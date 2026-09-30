import { Router } from 'express';
import { commandService, PRIVACY_BLOCKED_COMMANDS } from '../services/command.service';
import { getAgentVersion } from '../services/device.service';
import { agentHub } from '../services/agentHub.service';
import { permissionService } from '../services/permission.service';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import type { CommandType, CommandPriority } from '@obliance/shared';

const router = Router();

// Command types whose payload can trigger arbitrary code execution on the
// agent (custom install scripts, attacker-chosen msi URLs), or that only a
// platform administrator may start (agent update): forbidden on this generic
// endpoint for non-admins — and so is cancelling them.
const ADMIN_ONLY_COMMANDS: CommandType[] = [
  'install_software',
  'uninstall_software',
  'check_software_compliance',
  // Force-applying an agent update is an admin-only operation.
  'update_agent',
];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// POST /api/commands — enqueue a command for a device (try immediate delivery first)
router.post('/', async (req, res, next) => {
  try {
    const { deviceId, type, payload = {}, priority = 'normal' } = req.body as {
      deviceId: number;
      type: CommandType;
      payload?: Record<string, any>;
      priority?: CommandPriority;
    };

    if (!deviceId || !type) {
      return res.status(400).json({ error: 'deviceId and type are required' });
    }
    // Only the command types the database knows: an arbitrary string must
    // not reach a restriction / approval (whose executor dispatches on it).
    if (!(await commandService.isKnownCommandType(type))) {
      return res.status(400).json({ error: `Unknown command type '${String(type)}'` });
    }

    // Verify device belongs to tenant
    const device = await db('devices').where({ id: deviceId, tenant_id: req.tenantId! }).first();
    if (!device) return res.status(404).json({ error: 'Device not found' });

    // Legacy-agent compatibility gate. The Go 1.20 build that runs on
    // Server 2008 R2 / 2012 lacks the software-compliance and privacy-mode
    // handlers — queuing these commands would silently hang forever. Refuse
    // at the edge so the caller gets a clear error instead of a ghost command.
    const LEGACY_INCOMPATIBLE: string[] = [
      'install_software', 'uninstall_software', 'check_software_compliance',
      'enable_privacy_mode',
      // The legacy Go 1.20 agent has no self-update path (no MSI, deployed
      // via sc create) — it explicitly rejects update_agent. Refuse here so
      // the admin gets a clear error instead of a ghost command.
      'update_agent',
    ];
    if (device.agent_flavor === 'legacy' && LEGACY_INCOMPATIBLE.includes(type)) {
      return next(new AppError(409,
        `Command "${type}" is not supported on the legacy agent (Go 1.20 / Server 2008 R2). Upgrade the agent or use a compatible action.`));
    }
    // An agent update waits for its device (no expiry): never for a device
    // that will not get it (not approved, suspended, being uninstalled).
    if (type === 'update_agent' && (device.approval_status !== 'approved' || ['suspended', 'pending_uninstall'].includes(device.status))) {
      return next(new AppError(409, 'The agent of a device that is not approved, suspended or being uninstalled cannot be updated.'));
    }

    // A privacy password set on the device: the raw disable_privacy_mode is
    // refused (the agent does not check the password on it) — privacy mode is
    // then lifted on the device itself.
    if (type === 'disable_privacy_mode' && device.privacy_password_set) {
      return next(new AppError(423, 'A privacy password is set on this device — privacy mode can only be disabled on the device'));
    }

    // Permission check — non-admins need write access to the device.
    //
    // ADMIN_ONLY_COMMANDS (above) are forbidden on this generic endpoint for
    // non-admins. Non-admins must instead use the dedicated routes
    // (/software-compliance/check, /remediate) which resolve entries
    // server-side from admin-curated lists — the payload is never taken from
    // the client. Admins keep direct access here for debug and manual
    // orchestration.
    if (req.session.role !== 'admin') {
      if (ADMIN_ONLY_COMMANDS.includes(type)) {
        return next(new AppError(403,
          `Command type '${type}' must be invoked via the dedicated /api/software-compliance/* routes`));
      }

      // Determine required capability based on command type
      const POWER_COMMANDS = ['reboot', 'shutdown', 'sleep', 'restart_agent', 'uninstall_agent'];

      let requiredCap = 'execute'; // default for scripts, scans, etc.
      if (POWER_COMMANDS.includes(type)) requiredCap = 'power';

      const allowed = await permissionService.canUseCapability(req.session.userId!, deviceId, false, requiredCap);
      if (!allowed) return next(new AppError(403, `Capability '${requiredCap}' not permitted for your team`));
    }

    // A device in privacy mode refuses the privacy-blocked commands (even
    // from an admin): refused here rather than queued to fail.
    if (device.privacy_mode_enabled && PRIVACY_BLOCKED_COMMANDS.has(type)) {
      return next(new AppError(423, `Privacy mode is active on this device — '${type}' is blocked`));
    }

    let effectivePayload = payload;

    // Force-update: stamp the server's current agent version into the payload
    // when the caller didn't supply one, so the agent applies exactly the
    // build this server ships (the agent falls back to GET /api/agent/version
    // only if even this is missing).
    if (type === 'update_agent' && !effectivePayload?.version) {
      const ver = getAgentVersion();
      if (!ver) {
        return next(new AppError(409, 'Cannot determine the latest agent version (agent/VERSION missing).'));
      }
      effectivePayload = { ...effectivePayload, version: ver };
    }

    // ── Action restriction gate ───────────────────────────────────────────
    // Consults the tenant's per-action restriction map (configured under
    // /admin/users → Restrictions). If the action is "sensitive", we require
    // a valid TOTP code (sent as `twoFactorCode`, moved to req.stepUpProof by
    // captureStepUpProof); if "restricted", we
    // queue a pending approval instead of executing.
    const { applyRestriction } = await import('../services/restriction.service');
    const { commandCarriesSecret, scrubSecrets } = await import('../services/approvalSecrets');
    const { fields } = await import('../services/approvalDescribe');
    // A command whose type carries a secret (the fields its module declared,
    // registerSecretCommandFields) asks a fresh code at the 'restricted'
    // level — decided by the TYPE, never by the names of the payload fields
    // (a junk `token` key is simply dropped from the approval by
    // approvalService.create).
    const approvalParams = scrubSecrets((effectivePayload ?? {}) as Record<string, unknown>).clean;
    const shownParams = Object.keys(approvalParams).length ? ` (${fields(approvalParams)})` : '';
    const approved = await applyRestriction(res, {
      req,
      actionKey: `command.${type}`,
      deviceIds: [deviceId],
      carriesSecret: commandCarriesSecret(type, effectivePayload),
      approvalRequestType: 'batch_command',
      approvalDescription: `${type} on ${device.hostname}${shownParams}`,
      approvalPayload: { action: type, deviceIds: [deviceId], params: approvalParams },
    });
    if (!approved) return;

    // Agent update: queued without expiry (delivered when the device comes
    // back), at most one per device, paced by the rollout — see
    // services/agentUpdateRollout.service.ts. Handed over the live channel
    // right away when the device holds one and the rollout allows it.
    if (type === 'update_agent') {
      const { agentUpdateRollout, AGENT_REACHABLE_STATUSES } = await import('../services/agentUpdateRollout.service');
      const { command, created } = await agentUpdateRollout.enqueue({
        deviceId,
        tenantId: device.tenant_id,
        createdBy: req.session?.userId,
        priority: priority as CommandPriority,
      });
      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'command.update_agent', {
          deviceId,
          resourceType: 'command',
          resourcePath: command.id,
          details: { hostname: device.hostname, priority, alreadyQueued: !created },
        });
      } catch {}
      if (command.status === 'pending') await agentUpdateRollout.deliverNow(deviceId);
      const fresh = await db('command_queue').where({ id: command.id }).first();
      const out = fresh ? commandService.rowToCommand(fresh) : command;
      return res.json({
        data: {
          ...out,
          // 'sent': handed to the agent; 'queued': waits for the device's next
          // contact / its rollout slot (or for the device to come back online);
          // 'skipped': closed, the agent already runs the current version.
          delivery: out.status === 'pending' ? 'queued' : out.status === 'cancelled' ? 'skipped' : 'sent',
          alreadyQueued: !created,
          deviceOnline: AGENT_REACHABLE_STATUSES.includes(device.status),
        },
      });
    }

    const cmd = await commandService.enqueue({
      deviceId,
      tenantId: req.tenantId!,
      type,
      payload: effectivePayload,
      priority: priority as CommandPriority,
      expiresInSeconds: 300,
      createdBy: req.session?.userId,
    });

    // Audit every user-initiated command so the security tab shows who
    // triggered what on which machine (reboot / shutdown / scripts / etc).
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, `command.${type}`, {
        deviceId,
        resourceType: 'command',
        resourcePath: cmd.id,
        details: { hostname: device.hostname, priority },
      });
    } catch {}

    // Try immediate delivery via WebSocket command channel.
    // If the push succeeds the agent will execute and ack via WS, so mark
    // the command as 'sent' now to prevent re-delivery on the next HTTP push.
    const pushed = agentHub.push(deviceId, {
      type: 'command',
      id: cmd.id,
      commandType: type,
      payload: effectivePayload,
    });
    if (pushed) {
      try {
        await db('command_queue')
          .where({ id: cmd.id })
          .update({ status: 'sent', sent_at: new Date(), updated_at: new Date() });
      } catch { /* non-fatal — command will be re-delivered via HTTP push */ }
    }

    res.json({ data: cmd });
  } catch (err) { next(err); }
});

router.get('/', async (req, res, next) => {
  try {
    const { deviceId, status, page, limit } = req.query as any;

    // Non-admins: if deviceId specified, check read access; otherwise filter to visible devices
    if (req.session.role !== 'admin' && deviceId) {
      const canRead = await permissionService.canReadDevice(req.session.userId!, parseInt(deviceId), false);
      if (!canRead) return next(new AppError(403, 'Insufficient permissions'));
    }

    const result = await commandService.getCommands(req.tenantId!, {
      deviceId: deviceId ? parseInt(deviceId) : undefined,
      status,
      page: page ? parseInt(page) : undefined,
      limit: limit ? parseInt(limit) : undefined,
    });

    // Filter results to visible devices for non-admins
    if (req.session.role !== 'admin') {
      const visible = await permissionService.getVisibleDeviceIds(req.session.userId!, false);
      if (visible !== 'all') {
        const visibleSet = new Set(visible);
        const filtered = result.items.filter((c: any) => visibleSet.has(c.deviceId));
        return res.json({ data: { items: filtered, total: filtered.length } });
      }
    }

    res.json({ data: result });
  } catch (err) { next(err); }
});

// DELETE /api/commands/:id — cancel a command still waiting (pending).
// 409 when it was already delivered or finished (nothing was cancelled).
// Cancelling an admin-only command (agent update…) is admin-only too:
// otherwise a team member could silently undo what only an administrator —
// possibly with a second approver — may start. Audited.
router.delete('/:id', async (req, res, next) => {
  try {
    if (!UUID_RE.test(String(req.params.id))) return next(new AppError(404, 'Command not found'));
    const cmd = await db('command_queue').where({ id: req.params.id, tenant_id: req.tenantId! }).first();
    if (!cmd) return next(new AppError(404, 'Command not found'));
    if (req.session.role !== 'admin') {
      if (ADMIN_ONLY_COMMANDS.includes(cmd.type)) {
        return next(new AppError(403, `Only an administrator can cancel a '${cmd.type}' command`));
      }
      const canWrite = await permissionService.canWriteDevice(req.session.userId!, cmd.device_id, false);
      if (!canWrite) return next(new AppError(403, 'Insufficient permissions'));
    }
    const cancelled = await commandService.cancelCommand(req.params.id, req.tenantId!);
    if (!cancelled) {
      const now = await db('command_queue').where({ id: req.params.id }).first('status');
      return res.status(409).json({
        error: 'This command was already delivered to the agent or has finished: it can no longer be cancelled.',
        code: 'not_pending',
        status: now?.status ?? null,
      });
    }
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'command.cancel', {
        deviceId: cmd.device_id,
        resourceType: 'command',
        resourcePath: cmd.id,
        details: { type: cmd.type },
      });
    } catch {}
    res.status(204).send();
  } catch (err) { next(err); }
});

export default router;
