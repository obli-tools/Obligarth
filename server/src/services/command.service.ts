import { db } from '../db';
import { logger } from '../utils/logger';
import { getIO } from '../socket';
import { AppError } from '../middleware/errorHandler';
import { SocketEvents } from '@obliance/shared';
import type { Command, CommandAck, CommandType, CommandPriority } from '@obliance/shared';

// Sync-wait map for callers that need to block on the agent's ack for a
// specific command (waitForResult).
const pendingWaiters = new Map<string, (payload: { status: string; result: any }) => void>();

/** Values of the PG enum command_type (isKnownCommandType). */
let knownTypes: { at: number; set: Set<string> } | null = null;

/**
 * Command types of the features this server no longer has: remote sessions
 * and tunnels (shell, RDP, ObliReach, VM console), ObliReach install, SSH
 * bastion jumps, file explorer, live process list, custom sections, privacy
 * password. They stay values of the PG enum command_type (the schema is
 * unchanged) but are never queued: isKnownCommandType answers false and
 * enqueue refuses them.
 */
const RETIRED_COMMAND_TYPES: ReadonlySet<string> = new Set([
  'open_remote_tunnel', 'close_remote_tunnel', 'list_wts_sessions', 'open_vm_console', 'close_vm_console',
  'install_oblireach',
  'ssh_jump_grant', 'ssh_jump_revoke',
  'list_directory', 'create_directory', 'rename_file', 'delete_file', 'download_file', 'upload_file',
  'list_processes', 'kill_process',
  'start_custom_section', 'stop_custom_section', 'resize_custom_section',
  'set_privacy_password', 'change_privacy_password', 'remove_privacy_password', 'verify_privacy_password',
]);

/** Commands a device in privacy mode refuses (the agent enforces it too):
 *  the routes refuse them up front instead of queuing a command that fails. */
export const PRIVACY_BLOCKED_COMMANDS: ReadonlySet<string> = new Set(['run_script']);

/**
 * Command-payload fields that are credentials meant for the AGENT only: the
 * API key carried by `reconfigure_agent` and, in rows written before remote
 * access and the privacy password were removed, the relay key, the URL that
 * embeds it and the privacy unlock token. They stay in command_queue (the
 * agent reads the raw row) but are stripped from every user-facing view.
 */
const COMMAND_SECRET_KEYS = new Set(['sessionToken', 'serverWsUrl', 'unlockToken', 'apiKey', 'viewerToken']);

/** Copy of a command payload with agent-only secrets removed (never mutates). */
export function redactCommandPayload(payload: unknown): Record<string, unknown> {
  if (typeof payload === 'string') {
    // jsonb comes back parsed from pg; a legacy text value may not.
    try {
      const parsed = JSON.parse(payload);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return redactCommandPayload(parsed);
    } catch { /* not JSON — cannot carry a keyed secret */ }
    return payload as unknown as Record<string, unknown>;
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return (payload ?? {}) as Record<string, unknown>;
  }
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
    if (COMMAND_SECRET_KEYS.has(key)) continue;
    out[key] = value;
  }
  return out;
}

/** Copy of a command RESULT with the same agent-only secrets removed (the
 *  unlock token a verify_privacy_password answer carried included). */
export function redactCommandResult(result: unknown): Record<string, unknown> {
  return redactCommandPayload(result);
}

class CommandService {
  rowToCommand(row: any): Command {
    // Compute duration from timestamps if not in result
    let durationMs: number | null = null;
    if (row.result?.duration != null) {
      durationMs = row.result.duration;
    } else if (row.sent_at && row.finished_at) {
      durationMs = new Date(row.finished_at).getTime() - new Date(row.sent_at).getTime();
    }
    return {
      id: row.id,
      deviceId: row.device_id,
      tenantId: row.tenant_id,
      type: row.type,
      // User-facing view (REST + COMMAND_* socket events): agent-only secrets
      // (COMMAND_SECRET_KEYS) are stripped. The agent never reads this — it
      // gets raw command_queue rows.
      payload: redactCommandPayload(row.payload || {}),
      status: row.status,
      priority: row.priority,
      sentAt: row.sent_at,
      ackedAt: row.acked_at,
      finishedAt: row.finished_at,
      expiresAt: row.expires_at,
      // Agent-only secrets of a result too — rows written before they were
      // kept out of command_queue included.
      result: redactCommandResult(row.result || {}),
      retryCount: row.retry_count,
      maxRetries: row.max_retries,
      sourceType: row.source_type,
      sourceId: row.source_id,
      createdBy: row.created_by,
      createdByName: row.created_by_name ?? null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      durationMs,
    };
  }

  async enqueue(data: {
    deviceId: number;
    tenantId: number;
    type: CommandType;
    payload?: Record<string, any>;
    priority?: CommandPriority;
    maxRetries?: number;
    expiresInSeconds?: number;
    sourceType?: string;
    sourceId?: string;
    createdBy?: number;
  }): Promise<Command> {
    // A removed feature's command is never queued, whoever asks (a raw
    // command, a batch, an approval, a scenario node).
    if (RETIRED_COMMAND_TYPES.has(data.type)) {
      throw new AppError(400, `Command type '${data.type}' is no longer supported`);
    }

    // Agent updates wait for their device (no expiry) and exist at most once
    // per device: agentUpdateRollout owns them, whatever the caller. A
    // scenario's update keeps the node's timeout; when an update is already
    // outstanding for the device, the scenario node is answered right away
    // (the device gets that one — its outcome belongs to whoever queued it),
    // otherwise the run would wait for an ack that never comes.
    if (data.type === 'update_agent') {
      const { agentUpdateRollout, isScenarioSource } = await import('./agentUpdateRollout.service');
      const { command, created } = await agentUpdateRollout.enqueue({
        deviceId: data.deviceId,
        tenantId: data.tenantId,
        createdBy: data.createdBy,
        priority: data.priority,
        sourceType: data.sourceType,
        sourceId: data.sourceId,
        expiresInSeconds: data.expiresInSeconds,
      });
      if (!created && isScenarioSource(data.sourceType) && data.sourceId) {
        const origin = { id: command.id, source_type: data.sourceType, source_id: data.sourceId };
        // After the executor returned (the engine parks on awaitsAck first).
        setImmediate(() => {
          this.notifyEngine(origin, 0,
            `An agent update is already queued for this device (command ${command.id}): not queued twice`, null)
            .catch(() => { /* logged inside */ });
        });
      }
      return command;
    }

    const expiresAt = data.expiresInSeconds
      ? new Date(Date.now() + data.expiresInSeconds * 1000)
      : null;

    const payload = data.payload || {};

    const [row] = await db('command_queue').insert({
      device_id: data.deviceId,
      tenant_id: data.tenantId,
      type: data.type,
      payload: JSON.stringify(payload),
      status: 'pending',
      priority: data.priority || 'normal',
      max_retries: data.maxRetries || 0,
      expires_at: expiresAt,
      source_type: data.sourceType,
      source_id: data.sourceId,
      created_by: data.createdBy,
    }).returning('*');

    const cmd = this.rowToCommand(row);

    // Notify via socket that there's a new pending command
    try {
      const io = getIO();
      io.to(`tenant:${data.tenantId}:admin`).emit(SocketEvents.COMMAND_UPDATED, cmd);
    } catch {}

    return cmd;
  }

  /**
   * Wait for a specific command to be acked, for a caller that needs the
   * agent's result immediately. Resolves on terminal ack, rejects on timeout.
   */
  waitForResult(commandId: string, timeoutMs = 10000): Promise<{ status: string; result: any }> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingWaiters.delete(commandId);
        reject(new Error('Timed out waiting for agent response'));
      }, timeoutMs);
      pendingWaiters.set(commandId, (payload) => {
        clearTimeout(timer);
        pendingWaiters.delete(commandId);
        resolve(payload);
      });
    });
  }

  async processAcks(deviceId: number, tenantId: number, acks: CommandAck[]) {
    if (!acks?.length) return;

    // UUID v4 pattern — synthetic agent IDs (e.g. periodic scan commands) may
    // not be valid UUIDs and would cause a PostgreSQL "invalid input syntax for
    // type uuid" error.  Skip non-UUID IDs gracefully; they won't match any
    // command_queue row anyway.
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    for (const ack of acks) {
      if (!UUID_RE.test(ack.commandId)) continue;

      // What is stored and broadcast never carries an agent-only secret: the
      // sync waiter below gets the raw result, nothing else does.
      const storedResult = JSON.stringify(redactCommandResult(ack.result || {}));
      const updates: any = {
        status: ack.status,
        acked_at: new Date(),
        updated_at: new Date(),
        result: storedResult,
      };

      const isTerminal = ['success', 'failure', 'timeout'].includes(ack.status);
      if (isTerminal) updates.finished_at = new Date();

      // Sync waiters (waitForResult) resolve as soon as the terminal ack is
      // received.
      if (isTerminal) {
        const waiter = pendingWaiters.get(ack.commandId);
        if (waiter) waiter({ status: ack.status, result: ack.result });
      }

      const affected = await db('command_queue')
        .where({ id: ack.commandId, device_id: deviceId })
        .update(updates);

      // If no row was updated, this is a synthetic/periodic command from the agent.
      // Insert it into command_queue so it appears in task history (only for terminal acks).
      // EXCEPT high-frequency polling commands (e.g. live Hyper-V VM
      // enumeration pushed every few seconds while an operator watches the
      // Hyper-V view) — persisting those would flood task history.
      const NOISY_EPHEMERAL = new Set(['hyperv_list_vms', 'hyperv_console_thumbnail', 'veeam_list_jobs']);
      if (affected === 0 && isTerminal && ack.commandType && !NOISY_EPHEMERAL.has(ack.commandType)) {
        try {
          const now = new Date();
          await db('command_queue').insert({
            id: ack.commandId,
            device_id: deviceId,
            tenant_id: tenantId,
            type: ack.commandType,
            payload: storedResult,
            status: ack.status,
            priority: 'normal',
            created_at: now,
            sent_at: now,
            acked_at: now,
            ...(isTerminal ? { finished_at: now } : {}),
            result: storedResult,
          });
        } catch { /* ignore dupes or missing enum */ }
      }

      // Emit update and keep row for script_execution linkage below
      let row: any;
      try {
        row = await db('command_queue').where({ id: ack.commandId }).first();
        // Internal disk-health probes are not user-facing commands — don't push
        // them onto the admin command feed (fleet-wide socket churn).
        if (row && row.source_type !== 'disk_health_probe') {
          const io = getIO();
          const cmd = this.rowToCommand(row);
          io.to(`tenant:${tenantId}`).emit(SocketEvents.COMMAND_UPDATED, cmd);
          if (isTerminal) {
            io.to(`tenant:${tenantId}`).emit(SocketEvents.COMMAND_RESULT, cmd);
          }
        }
      } catch {}

      // When install_update(s) starts running, mark the update(s) as "installing"
      if (!isTerminal && ack.status === 'ack_running' && row && (row.type === 'install_update' || row.type === 'install_updates')) {
        try {
          const payload = typeof row.payload === 'string' ? JSON.parse(row.payload) : (row.payload || {});
          const uids: string[] = row.type === 'install_updates'
            ? (payload.updateUids ?? [])
            : (payload.updateUid ? [payload.updateUid] : []);
          if (uids.length) {
            await db('device_updates')
              .whereIn('update_uid', uids)
              .where({ device_id: deviceId })
              .update({ status: 'installing', updated_at: new Date() });
          }
        } catch (updateErr) {
          logger.error(updateErr, 'Failed to update device_updates status to installing from ack_running');
        }
      }

      // When install_update(s) finishes, reflect the outcome in device_updates
      if (isTerminal && row && (row.type === 'install_update' || row.type === 'install_updates')) {
        try {
          const payload = typeof row.payload === 'string' ? JSON.parse(row.payload) : (row.payload || {});
          const uids: string[] = row.type === 'install_updates'
            ? (payload.updateUids ?? [])
            : (payload.updateUid ? [payload.updateUid] : []);
          if (uids.length) {
            await db('device_updates')
              .whereIn('update_uid', uids)
              .where({ device_id: deviceId })
              .update({
                status: ack.status === 'success' ? 'installed' : 'failed',
                installed_at: ack.status === 'success' ? new Date() : null,
                install_error: ack.status !== 'success'
                  ? ((ack.result as any)?.error ?? 'Installation failed')
                  : null,
                updated_at: new Date(),
              });
          }
        } catch (updateErr) {
          logger.error(updateErr, 'Failed to update device_updates status from install_update(s) ack');
        }
      }

      // ── Native disk-health probe result (diskHealthCollector) ────────────
      // Server-dispatched SMART probe — no script_execution / schedule row, so
      // it bypasses the metric-script path above. Parse the JSON `disks`
      // payload straight into the snapshot.
      if (isTerminal && row && row.source_type === 'disk_health_probe') {
        if (ack.status === 'success') {
          try {
            const probeResult = ack.result as any;
            const rawOut = String(probeResult?.stdout ?? '').trim();
            const jsonStr = rawOut.startsWith('{')
              ? rawOut
              : (rawOut.split(/\r?\n/).map((l: string) => l.trim()).filter(Boolean).pop() ?? '');
            if (jsonStr.startsWith('{')) {
              const obj = JSON.parse(jsonStr);
              if (Array.isArray(obj?.disks) && obj.disks.length) {
                const { diskHealthService } = await import('./diskHealth.service');
                await diskHealthService.saveFromScript(deviceId, tenantId, obj.disks);
              }
            }
          } catch (probeErr) {
            logger.error(probeErr, 'Failed to process disk_health_probe result');
          }
        }
        // Internal probe — never keep it in command history (fleet-wide churn).
        try { await db('command_queue').where({ id: ack.commandId }).delete(); } catch { /* best-effort */ }
      }

      // Update linked script execution when the command is terminal
      if (isTerminal && row && row.source_type === 'script_execution' && row.source_id) {
        try {
          const result = ack.result as any;
          const execStatus =
            ack.status === 'success' ? 'success' :
            ack.status === 'timeout' ? 'timeout' : 'failure';

          await db('script_executions').where({ id: row.source_id }).update({
            status: execStatus,
            exit_code: result?.exitCode ?? null,
            stdout: result?.stdout ?? null,
            stderr: result?.stderr ?? null,
            started_at: result?.duration != null
              ? new Date(Date.now() - (result.duration as number))
              : new Date(),
            finished_at: new Date(),
          });

          // Notify the UI so the automation history / batch list refreshes
          // without requiring a manual reload.
          try {
            const execRow = await db('script_executions').where({ id: row.source_id }).first();
            if (execRow) {
              getIO().to(`tenant:${tenantId}`).emit(SocketEvents.EXECUTION_UPDATED, {
                id: execRow.id,
                batchId: execRow.batch_id ?? null,
                scheduleId: execRow.schedule_id ?? null,
                scriptId: execRow.script_id ?? null,
                deviceId: execRow.device_id,
                status: execStatus,
                exitCode: result?.exitCode ?? null,
                startedAt: execRow.started_at,
                finishedAt: execRow.finished_at,
              });
            }
          } catch {}

          // ── Custom metrics: if the executed script has purpose='metric',
          // parse stdout and upsert the custom metric row for this device.
          try {
            const exec0 = await db('script_executions').where({ id: row.source_id }).first();
            if (exec0?.script_id && exec0?.schedule_id) {
              const script = await db('scripts').where({ id: exec0.script_id }).first();
              if (script?.purpose === 'metric') {
                const schedule = await db('script_schedules').where({ id: exec0.schedule_id }).first();
                if (schedule) {
                  const { customMetricService, parseMetricStdout } = await import('./customMetric.service');
                  if (execStatus === 'success') {
                    const parsed = parseMetricStdout(result?.stdout ?? '');
                    if (parsed) {
                      await customMetricService.upsert({
                        deviceId,
                        scheduleId: schedule.id,
                        tenantId,
                        scheduleName: schedule.name,
                        parsed,
                      });
                    } else {
                      await customMetricService.markError({
                        deviceId, scheduleId: schedule.id, tenantId, scheduleName: schedule.name,
                      });
                    }
                    // Disk health (SMART): a metric script may ALSO emit a
                    // structured `disks` array in its JSON output. If so, persist
                    // the per-disk snapshot and evaluate health alerts. Purely
                    // additive — plain metric scripts have no `disks` key.
                    try {
                      const raw = String(result?.stdout ?? '').trim();
                      const jsonStr = raw.startsWith('{')
                        ? raw
                        : (raw.split(/\r?\n/).map((l: string) => l.trim()).filter(Boolean).pop() ?? '');
                      if (jsonStr.startsWith('{')) {
                        const obj = JSON.parse(jsonStr);
                        if (Array.isArray(obj?.disks) && obj.disks.length) {
                          const { diskHealthService } = await import('./diskHealth.service');
                          await diskHealthService.saveFromScript(deviceId, tenantId, obj.disks);
                        }
                      }
                    } catch { /* not a SMART payload — ignore */ }
                  } else {
                    await customMetricService.markError({
                      deviceId, scheduleId: schedule.id, tenantId, scheduleName: schedule.name,
                    });
                  }
                }
              }
            }
          } catch (metricErr) {
            logger.error(metricErr, 'Failed to process custom metric from script execution');
          }

          // ── Schedule Assert Pass: alert / recovery ──────────────────────
          try {
            const exec = await db('script_executions').where({ id: row.source_id }).first();
            if (exec?.schedule_id) {
              const schedule = await db('script_schedules').where({ id: exec.schedule_id }).first();
              if (schedule?.assert_pass) {
                const device = await db('devices').where({ id: deviceId }).first();
                if (execStatus === 'failure' || execStatus === 'timeout') {
                  // Check if there's already an active alert for the same schedule (notify_once dedup)
                  let alreadyAlerting = false;
                  if (schedule.notify_once && device?.schedule_alert) {
                    const existing = typeof device.schedule_alert === 'string'
                      ? JSON.parse(device.schedule_alert)
                      : device.schedule_alert;
                    alreadyAlerting = existing?.scheduleId === schedule.id;
                  }

                  // Set schedule alert on the device (always update, even if dedup)
                  const alertData = {
                    scheduleId: schedule.id,
                    scheduleName: schedule.name,
                    exitCode: result?.exitCode ?? -1,
                    stderr: (result?.stderr ?? result?.error ?? '').slice(0, 2000),
                    failedAt: new Date().toISOString(),
                  };
                  await db('devices').where({ id: deviceId }).update({
                    schedule_alert: JSON.stringify(alertData),
                    updated_at: new Date(),
                  });
                  // Send alert notification (skip if notify_once and alert already active)
                  if (!alreadyAlerting) {
                    try {
                      const { notificationService } = await import('./notification.service');
                      const deviceName = device?.display_name || device?.hostname || `Device #${deviceId}`;
                      const msg = `Schedule "${schedule.name}" failed on ${deviceName} (exit code ${alertData.exitCode})`;
                      const detail = alertData.stderr ? `\n${alertData.stderr.slice(0, 500)}` : '';
                      await notificationService.sendForAgent(deviceId, device?.tenant_id, 'warning', msg + detail);
                    } catch {}
                  }
                  // Emit socket event
                  try {
                    const { getIO } = await import('../socket');
                    const { SocketEvents } = await import('@obliance/shared');
                    getIO().to(`tenant:${device?.tenant_id}`).emit(SocketEvents.DEVICE_UPDATED, {
                      id: deviceId, scheduleAlert: alertData,
                    });
                  } catch {}
                } else if (execStatus === 'success' && device?.schedule_alert) {
                  // Check if this is the same schedule that set the alert
                  const currentAlert = typeof device.schedule_alert === 'string'
                    ? JSON.parse(device.schedule_alert)
                    : device.schedule_alert;
                  if (currentAlert?.scheduleId === schedule.id) {
                    // Clear the alert — recovery
                    await db('devices').where({ id: deviceId }).update({
                      schedule_alert: null,
                      updated_at: new Date(),
                    });
                    // Send recovery notification
                    try {
                      const { notificationService } = await import('./notification.service');
                      const deviceName = device?.display_name || device?.hostname || `Device #${deviceId}`;
                      const msg = `Schedule "${schedule.name}" recovered on ${deviceName}`;
                      await notificationService.sendForAgent(deviceId, device?.tenant_id, 'online', msg);
                    } catch {}
                    // Emit socket event
                    try {
                      const { getIO } = await import('../socket');
                      const { SocketEvents } = await import('@obliance/shared');
                      getIO().to(`tenant:${device?.tenant_id}`).emit(SocketEvents.DEVICE_UPDATED, {
                        id: deviceId, scheduleAlert: null,
                      });
                    } catch {}
                  }
                }
              }
            }
          } catch (alertErr) {
            logger.error(alertErr, 'Failed to process schedule assert_pass');
          }

          // ── Automation notifications (schedule batch complete) ──────────
          // If this script execution belongs to a schedule, check whether
          // the whole batch has now reached a terminal state — and if so,
          // dispatch aggregated notifications to the bound channels.
          try {
            const exec = await db('script_executions').where({ id: row.source_id }).first();
            if (exec?.schedule_id && exec?.batch_id) {
              const batch = await db('script_executions')
                .where({ batch_id: exec.batch_id });
              const allTerminal = batch.every((e: any) =>
                ['success', 'failure', 'timeout', 'cancelled', 'skipped'].includes(e.status),
              );
              if (allTerminal) {
                const schedule = await db('script_schedules').where({ id: exec.schedule_id }).first();
                if (schedule?.notification_channels) {
                  const bindings = typeof schedule.notification_channels === 'string'
                    ? JSON.parse(schedule.notification_channels)
                    : schedule.notification_channels;
                  if (Array.isArray(bindings) && bindings.length > 0) {
                    const successCount = batch.filter((e: any) => e.status === 'success').length;
                    const failedExecs = batch.filter((e: any) => e.status === 'failure' || e.status === 'timeout');
                    const failureCount = failedExecs.length;
                    const failedDeviceIds = failedExecs.map((e: any) => e.device_id);
                    const failedDevices = failedDeviceIds.length > 0
                      ? await db('devices').whereIn('id', failedDeviceIds).select('id', 'hostname', 'display_name')
                      : [];
                    const failedNames = failedDevices.map((d: any) => d.display_name || d.hostname || `#${d.id}`);

                    // notify_once dedup: if the PREVIOUS batch of this same
                    // schedule already had failures, suppress this one — the
                    // admin was paged on the first transition into failure
                    // and doesn't want the same alert every minute until it
                    // recovers. We only block the notification when both
                    // batches share the same failure state (fail→fail); the
                    // recovery case (fail→ok) still flows through so the
                    // operator sees the problem cleared.
                    let skipNotification = false;
                    if (schedule.notify_once) {
                      // Find the previous batch_id for this schedule (most
                      // recently finished, excluding the current one).
                      const prevBatchIdRow = await db('script_executions')
                        .where({ schedule_id: exec.schedule_id })
                        .whereNot({ batch_id: exec.batch_id })
                        .whereNotNull('batch_id')
                        .whereNotNull('finished_at')
                        .orderBy('finished_at', 'desc')
                        .first('batch_id');
                      if (prevBatchIdRow?.batch_id) {
                        const prevBatch = await db('script_executions')
                          .where({ batch_id: prevBatchIdRow.batch_id });
                        const prevHadFailure = prevBatch.some((e: any) =>
                          e.status === 'failure' || e.status === 'timeout',
                        );
                        const currHasFailure = failureCount > 0;
                        if (prevHadFailure && currHasFailure) skipNotification = true;
                      }
                    }

                    if (!skipNotification) {
                      const { automationNotificationService } = await import('./automationNotification.service');
                      await automationNotificationService.notify(tenantId, bindings, {
                        automationType: 'schedule',
                        automationName: schedule.name,
                        successCount,
                        failureCount,
                        totalCount: batch.length,
                        failedDeviceNames: failedNames,
                      });
                    }
                  }
                }
              }
            }
          } catch (notifyErr) {
            logger.error(notifyErr, 'Failed to dispatch schedule batch notifications');
          }
        } catch (execErr) {
          logger.error(execErr, 'Failed to update script_execution from ack');
        }
      }

      // ── Scenario step orchestration (v1 — linear engine) ────────────────
      if (isTerminal && row && row.source_type?.startsWith('scenario_step_')) {
        try {
          const result = ack.result as any;
          const { scenarioService } = await import('./scenario.service');
          await scenarioService.handleScenarioCommandAck(
            row.id,
            row.source_type,
            row.source_id,
            result?.exitCode ?? (ack.status === 'success' ? 0 : -1),
            result?.stdout ?? '',
            result?.stderr ?? result?.error ?? '',
          );
        } catch (scenarioErr) {
          logger.error(scenarioErr, 'Failed to process scenario step ack');
        }
      }

      // ── Scenario node orchestration (v2 — graph engine) ─────────────────
      // run_script / run_command nodes register their nodeRunId as
      // command source_id with source_type='scenario_node'. The graph
      // engine resumes the run from that node based on the exit code.
      if (isTerminal && row && row.source_type === 'scenario_node') {
        try {
          const result = ack.result as any;
          const { scenarioGraphService } = await import('./scenarioGraph.service');
          await scenarioGraphService.handleNodeCommandAck(
            row.source_id,
            result?.exitCode ?? (ack.status === 'success' ? 0 : -1),
            result?.stdout ?? '',
            result?.stderr ?? result?.error ?? '',
          );
        } catch (graphErr) {
          logger.error(graphErr, 'Failed to process scenario v2 node ack');
        }
      }
    }
  }

  async getCommands(tenantId: number, filters?: { deviceId?: number; status?: string; page?: number; limit?: number }) {
    const limit = filters?.limit ?? 50;
    const page = filters?.page ?? 1;

    let baseQ = db('command_queue').where({ 'command_queue.tenant_id': tenantId });
    if (filters?.deviceId) baseQ = baseQ.where({ 'command_queue.device_id': filters.deviceId });
    if (filters?.status) baseQ = baseQ.where({ 'command_queue.status': filters.status });

    const countResult = await baseQ.clone().count('command_queue.id as count').first();
    const total = parseInt(String((countResult as any)?.count ?? 0));

    let q = baseQ
      .select('command_queue.*', db.raw("COALESCE(u.display_name, u.username, u.email) as created_by_name"))
      .leftJoin('users as u', 'command_queue.created_by', 'u.id')
      .orderBy('command_queue.created_at', 'desc');

    if (limit > 0) {
      q = q.limit(limit).offset((page - 1) * limit);
    }

    const rows = await q;
    return { items: rows.map(this.rowToCommand.bind(this)), total };
  }

  /** Cancels a command still WAITING (pending). Returns the number of rows
   *  cancelled: 0 when it was already delivered / finished (the caller
   *  reports it instead of claiming success). */
  async cancelCommand(id: string, tenantId: number): Promise<number> {
    const now = new Date();
    const rows = await db('command_queue')
      .where({ id, tenant_id: tenantId, status: 'pending' })
      .update({ status: 'cancelled', finished_at: now, updated_at: now })
      .returning('*');
    // Open pages (device header "update pending", tasks tab) follow the change.
    for (const row of rows) {
      try { getIO().to(`tenant:${row.tenant_id}`).emit(SocketEvents.COMMAND_UPDATED, this.rowToCommand(row)); } catch {}
      // A scenario's agent update: the run must not wait for it forever.
      if (row.type === 'update_agent') {
        await this.notifyEngine(row, -1, null, 'Agent update cancelled by an administrator');
      }
    }
    return rows.length;
  }

  /** Reports a command's outcome to the scenario engine that queued it
   *  (v2 node: source_type 'scenario_node'; v1 step: 'scenario_step_*'),
   *  for outcomes that do not come from an agent ack (timeout, skip,
   *  inferred success, cancel). No-op for other sources. Never throws. */
  async notifyEngine(row: { id: string; source_type?: string | null; source_id?: string | null }, exitCode: number, stdout: string | null, stderr: string | null): Promise<void> {
    try {
      if (row.source_type === 'scenario_node' && row.source_id) {
        const { scenarioGraphService } = await import('./scenarioGraph.service');
        await scenarioGraphService.handleNodeCommandAck(row.source_id, exitCode, stdout, stderr);
      } else if (typeof row.source_type === 'string' && row.source_type.startsWith('scenario_step_') && row.source_id) {
        const { scenarioService } = await import('./scenario.service');
        await scenarioService.handleScenarioCommandAck(row.id, row.source_type, row.source_id, exitCode, stdout ?? '', stderr ?? '');
      }
    } catch (engineErr) {
      logger.error({ engineErr, commandId: row.id, sourceType: row.source_type }, 'Failed to notify engine of command outcome');
    }
  }

  /** A command type the database knows (PG enum command_type) and that is
   *  not retired (RETIRED_COMMAND_TYPES). Unknown types are refused at the
   *  API edge — before a restriction could file an approval for an action
   *  string that means something else to an executor. Cached (the enum only
   *  grows through migrations). */
  async isKnownCommandType(type: unknown): Promise<boolean> {
    if (typeof type !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(type)) return false;
    if (RETIRED_COMMAND_TYPES.has(type)) return false;
    if (!knownTypes || Date.now() - knownTypes.at > 10 * 60_000) {
      const r = await db.raw(
        `SELECT e.enumlabel AS v FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'command_type'`,
      );
      const rows = (Array.isArray(r) ? r : r?.rows ?? []) as Array<{ v: string }>;
      knownTypes = { at: Date.now(), set: new Set(rows.map((x) => x.v)) };
    }
    return knownTypes.set.has(type);
  }

  // Expire timed-out commands. Crucially, when a v2 scenario node's
  // command times out, we MUST notify the engine so the run advances
  // (or fails) — otherwise the scenario_runs row stays 'running'
  // forever and the editor shows a permanently-pulsing ring with no
  // stdout/stderr. The cleanup runs every minute; expired commands
  // tied to scenario nodes get a synthetic ack with exitCode=-1.
  async startCleanupJob() {
    setInterval(() => { this.sweepExpired().catch(() => { /* logged inside */ }); }, 60_000); // every minute
  }

  /** One pass of the cleanup job (also called directly by tests). */
  async sweepExpired(): Promise<void> {
    // Agent updates have their own pass (agentUpdateRollout.sweep): success
    // when the device reports the target version (the ack is often lost
    // with the old agent process), handed out again when never confirmed,
    // timeout otherwise — a waiting one never expires (it waits for its
    // device), except a scenario's.
    try {
      const { agentUpdateRollout } = await import('./agentUpdateRollout.service');
      const n = await agentUpdateRollout.sweep();
      if (n.confirmed + n.redelivered + n.timedOut > 0) logger.info(n, 'Agent updates swept');
    } catch (err) {
      logger.error(err, 'Error sweeping agent updates');
    }
    try {
      const expired = await db('command_queue')
        .where('expires_at', '<', new Date())
        .whereIn('status', ['pending', 'sent'])
        .whereNot('type', 'update_agent')
        .update({ status: 'timeout', finished_at: new Date(), updated_at: new Date() })
        .returning('*');

      if (expired.length > 0) {
        logger.info({ count: expired.length }, 'Commands expired');
      }

      // For each expired scenario-node command, push a timeout ack
      // into the v2 engine so the run advances/fails. We also do
      // this for v1 scenario_step commands so legacy step-based
      // scenarios surface timeouts in their UI too.
      for (const cmd of expired) {
        await this.notifyEngine(cmd, -1, null, 'Command timed out — agent never acknowledged within the configured timeout window.');
      }
    } catch (err) {
      logger.error(err, 'Error in command cleanup job');
    }
  }
}

export const commandService = new CommandService();
