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
 * password, script executions, OS updates, compliance checks, software
 * compliance, network discovery, Hyper-V, Veeam. They stay values of the PG
 * enum command_type (the schema is unchanged) but are never queued:
 * isKnownCommandType answers false and enqueue refuses them.
 */
const RETIRED_COMMAND_TYPES: ReadonlySet<string> = new Set([
  'open_remote_tunnel', 'close_remote_tunnel', 'list_wts_sessions', 'open_vm_console', 'close_vm_console',
  'install_oblireach',
  'ssh_jump_grant', 'ssh_jump_revoke',
  'list_directory', 'create_directory', 'rename_file', 'delete_file', 'download_file', 'upload_file',
  'list_processes', 'kill_process',
  'start_custom_section', 'stop_custom_section', 'resize_custom_section',
  'set_privacy_password', 'change_privacy_password', 'remove_privacy_password', 'verify_privacy_password',
  'cancel_script',
  'scan_updates', 'install_update', 'install_updates',
  'check_compliance', 'remediate_rule',
  'check_software_compliance', 'install_software', 'uninstall_software',
  'scan_network',
  'hyperv_list_vms', 'hyperv_control', 'hyperv_console_thumbnail', 'install_vm_console',
  'veeam_list_jobs', 'veeam_control',
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
    // command, a batch, an approval).
    if (RETIRED_COMMAND_TYPES.has(data.type)) {
      throw new AppError(400, `Command type '${data.type}' is no longer supported`);
    }

    // Agent updates wait for their device (no expiry) and exist at most once
    // per device: agentUpdateRollout owns them, whatever the caller (an
    // update already outstanding for the device is returned as is).
    if (data.type === 'update_agent') {
      const { agentUpdateRollout } = await import('./agentUpdateRollout.service');
      const { command } = await agentUpdateRollout.enqueue({
        deviceId: data.deviceId,
        tenantId: data.tenantId,
        createdBy: data.createdBy,
        priority: data.priority,
        sourceType: data.sourceType,
        sourceId: data.sourceId,
      });
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
      if (affected === 0 && isTerminal && ack.commandType) {
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

      // Emit update and keep row for the disk-health probe below
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

      // ── Native disk-health probe result (diskHealthCollector) ────────────
      // Server-dispatched SMART probe: parse the JSON `disks` payload
      // straight into the snapshot.
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
    }
    return rows.length;
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

  // Expire timed-out commands. The cleanup runs every minute.
  async startCleanupJob() {
    setInterval(() => { this.sweepExpired().catch(() => { /* logged inside */ }); }, 60_000); // every minute
  }

  /** One pass of the cleanup job (also called directly by tests). */
  async sweepExpired(): Promise<void> {
    // Agent updates have their own pass (agentUpdateRollout.sweep): success
    // when the device reports the target version (the ack is often lost
    // with the old agent process), handed out again when never confirmed,
    // timeout otherwise — a waiting one never expires (it waits for its
    // device).
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
        .update({ status: 'timeout', finished_at: new Date(), updated_at: new Date() });

      if (expired > 0) {
        logger.info({ count: expired }, 'Commands expired');
      }
    } catch (err) {
      logger.error(err, 'Error in command cleanup job');
    }
  }
}

export const commandService = new CommandService();
