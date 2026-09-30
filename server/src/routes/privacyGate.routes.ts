import { Router, type Request } from 'express';
import { requireRole } from '../middleware/rbac';
import { commandService } from '../services/command.service';
import { agentHub } from '../services/agentHub.service';
import { privacyGateService } from '../services/privacyGate.service';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { isMasterTenant } from '@obliance/shared';
import { permissionService } from '../services/permission.service';

const router = Router({ mergeParams: true });

// Rate-limit password attempts per (user, device). Simple in-memory.
const attempts = new Map<string, { count: number; resetAt: number; blockedAudited?: boolean }>();
const RATE_MAX = 5;
const RATE_WINDOW_MS = 60_000;

function checkRateLimit(userId: number, deviceId: number): boolean {
  const k = `${userId}:${deviceId}`;
  const now = Date.now();
  const e = attempts.get(k);
  if (!e || now > e.resetAt) {
    attempts.set(k, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return true;
  }
  if (e.count >= RATE_MAX) return false;
  e.count++;
  return true;
}

/** True the first time this (user, device) window refuses an attempt: the
 *  refusal is audited once per window, not once per hammered request. */
function firstRefusalOfWindow(userId: number, deviceId: number): boolean {
  const e = attempts.get(`${userId}:${deviceId}`);
  if (!e || e.blockedAudited) return false;
  e.blockedAudited = true;
  return true;
}

/**
 * The unlock features and the capability each one needs: the capability of
 * the action the unlock opens (remote sessions and chat 'remote', the file
 * explorer 'files', scripts and processes 'execute': command.routes.ts).
 */
const UNLOCK_FEATURE_CAPABILITY: Readonly<Record<string, string>> = {
  remote: 'remote',
  chat: 'remote',
  files: 'files',
  scripts: 'execute',
  processes: 'execute',
};

type UnlockFailure = 'incorrect_password' | 'rate_limited' | 'forbidden' | 'agent_offline' | 'agent_no_answer';

/** A failed unlock attempt, audited in the DEVICE's tenant. Never the password. */
async function auditUnlockFailure(
  req: Request, device: { id: number; tenant_id: number }, feature: string,
  reason: UnlockFailure, agentError?: unknown,
  action: 'privacy.unlock_failed' | 'privacy.disable_failed' = 'privacy.unlock_failed',
): Promise<void> {
  try {
    const { auditService } = await import('../services/audit.service');
    await auditService.logReqAs(req, device.tenant_id, action, {
      deviceId: device.id, resourceType: 'device', resourcePath: String(device.id),
      details: {
        feature, reason,
        ...(typeof agentError === 'string' && agentError ? { agentError: agentError.slice(0, 200) } : {}),
      },
    });
  } catch { /* audit never breaks the request */ }
}

/**
 * Dispatch a privacy-gate command to the agent and wait synchronously for
 * the result. Passwords are attached to the payload but NEVER written to
 * the DB command_queue row — we strip them before enqueue.
 */
async function sendPrivacyCommand(
  deviceId: number,
  tenantId: number,
  type: string,
  payload: Record<string, any>,
  userId: number,
): Promise<{ status: string; result: any }> {
  if (!agentHub.isConnected(deviceId)) {
    throw new AppError(503, 'Agent is offline');
  }

  // Create a queue row WITHOUT the secret fields so plaintext never persists.
  const redactedPayload = { ...payload };
  delete redactedPayload.password;
  delete redactedPayload.oldPassword;
  delete redactedPayload.newPassword;

  const cmd = await commandService.enqueue({
    deviceId,
    tenantId,
    type: type as any,
    payload: redactedPayload,
    priority: 'high',
    expiresInSeconds: 30,
    createdBy: userId,
  });

  // Push the FULL payload (with secrets) via the live WS channel. It is not
  // persisted — the WS frame is in memory only, TLS-encrypted in flight.
  const pushed = agentHub.push(deviceId, {
    type: 'command',
    id: cmd.id,
    commandType: type,
    payload,
  });
  if (!pushed) throw new AppError(503, 'Agent push channel failed');

  return commandService.waitForResult(cmd.id, 15000);
}

// POST /api/devices/:id/privacy/password — set, change, or remove
router.post('/password', requireRole('admin'), async (req, res, next) => {
  try {
    const deviceId = parseInt((req.params as any).id);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;

    const device = await db('devices').where({ id: deviceId, tenant_id: tenantId }).first();
    if (!device) throw new AppError(404, 'Device not found');

    const { action, password, newPassword } = req.body as {
      action: 'set' | 'change' | 'remove';
      password: string;
      newPassword?: string;
    };

    if (!action || !password) throw new AppError(400, 'action and password are required');

    // UI-level check: block when privacy is ON. The agent enforces this too.
    if (device.privacy_mode_enabled) {
      throw new AppError(409, 'Cannot modify privacy password while privacy mode is active');
    }

    let type: string;
    let payload: Record<string, any>;
    if (action === 'set') {
      type = 'set_privacy_password';
      payload = { password };
    } else if (action === 'change') {
      if (!newPassword) throw new AppError(400, 'newPassword required');
      type = 'change_privacy_password';
      payload = { oldPassword: password, newPassword };
    } else if (action === 'remove') {
      type = 'remove_privacy_password';
      payload = { password };
    } else {
      throw new AppError(400, 'Invalid action');
    }

    // Rate limit (wrong password abuse)
    if (!checkRateLimit(userId, deviceId)) {
      throw new AppError(429, 'Too many password attempts, retry in a minute');
    }

    const result = await sendPrivacyCommand(deviceId, tenantId, type, payload, userId);

    if (result.status !== 'success') {
      const err = result.result?.error || 'Operation failed';
      throw new AppError(400, err);
    }

    // Update the persistent "password set" flag on the device.
    const isSet = action !== 'remove';
    await db('devices').where({ id: deviceId }).update({
      privacy_password_set: isSet,
      privacy_password_set_at: isSet ? new Date() : null,
      updated_at: new Date(),
    });

    res.json({ data: { passwordSet: isSet } });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/privacy/unlock — verify password + create unlock session
//
// The device: the session's tenant, or any tenant for a platform admin on the
// master tenant (god view, like the device list): the web's device page and
// the Oblireach Desktop (single mode on the master tenant) show those devices.
// A non-admin must be a member of the device's tenant, see the device (team
// scope) and hold the capability of the feature unlocked (remote / chat:
// 'remote', files: 'files', scripts / processes: 'execute'); admins bypass.
// Failed attempts are audited (privacy.unlock_failed, device's tenant, never
// the password): wrong code, refused capability, rate limit (once per
// window), agent unreachable. The rate limit (5 / min per user and device)
// counts every attempt on a device the caller can see.
router.post('/unlock', async (req, res, next) => {
  try {
    const deviceId = Number((req.params as any).id);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    const isAdmin = req.session.role === 'admin';
    const { password, feature } = (req.body ?? {}) as { password?: unknown; feature?: unknown };

    if (!password || !feature || typeof password !== 'string' || typeof feature !== 'string') {
      throw new AppError(400, 'password and feature are required');
    }
    const capability = Object.prototype.hasOwnProperty.call(UNLOCK_FEATURE_CAPABILITY, feature)
      ? UNLOCK_FEATURE_CAPABILITY[feature] : undefined;
    if (!capability) throw new AppError(400, 'Unknown feature');
    if (!Number.isSafeInteger(deviceId) || deviceId <= 0 || deviceId > 2147483647) throw new AppError(404, 'Device not found');

    const q = db('devices').where({ id: deviceId });
    if (!(isAdmin && isMasterTenant(tenantId))) q.where({ tenant_id: tenantId });
    const device = await q.first();
    if (!device) throw new AppError(404, 'Device not found');

    // Visibility: a device the caller cannot see answers like one of another
    // tenant (no existence leak).
    if (!isAdmin) {
      const member = await db('user_tenants').where({ user_id: userId, tenant_id: device.tenant_id }).first('user_id');
      if (!member || !(await permissionService.canReadDevice(userId, deviceId, false))) {
        throw new AppError(404, 'Device not found');
      }
    }

    if (!checkRateLimit(userId, deviceId)) {
      if (firstRefusalOfWindow(userId, deviceId)) await auditUnlockFailure(req, device, feature, 'rate_limited');
      throw new AppError(429, 'Too many password attempts, retry in a minute');
    }

    if (!isAdmin && !(await permissionService.canUseCapability(userId, deviceId, false, capability))) {
      await auditUnlockFailure(req, device, feature, 'forbidden');
      throw new AppError(403, `Capability '${capability}' not permitted for your team`);
    }

    if (!device.privacy_password_set) throw new AppError(400, 'No privacy password is set on this device');

    let result: { status: string; result: any };
    try {
      result = await sendPrivacyCommand(
        deviceId,
        device.tenant_id,
        'verify_privacy_password',
        { password, feature },
        userId,
      );
    } catch (err) {
      const offline = err instanceof AppError && err.statusCode === 503;
      await auditUnlockFailure(req, device, feature, offline ? 'agent_offline' : 'agent_no_answer');
      throw err;
    }

    if (result.status !== 'success' || !result.result?.unlockToken) {
      await auditUnlockFailure(req, device, feature, 'incorrect_password', result.result?.error);
      throw new AppError(401, result.result?.error || 'Incorrect password');
    }

    privacyGateService.put(userId, deviceId, feature, result.result.unlockToken);
    const ttlSeconds: number = Number(result.result.ttlSeconds) || 900;
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReqAs(req, device.tenant_id, 'privacy.unlocked', {
        deviceId, resourceType: 'device', resourcePath: String(deviceId),
        details: { feature, ttlSeconds },
      });
    } catch {}
    res.json({ data: { unlocked: true, feature, ttlSeconds } });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/privacy/disable-with-password — disable privacy via password gate
//
// The same password check as /unlock, so the same rules (it must not be a way
// around them): the device with the REST rules (session's tenant; any tenant
// for an admin on the master tenant), a non-admin a member of that tenant who
// sees the device and holds 'execute' (the capability POST /api/commands asks
// for disable_privacy_mode); the tenant's restriction on
// command.disable_privacy_mode (the device's matrix too), like
// /privacy-mode/disable — the password never sits in an approval, so
// 'restricted' asks a fresh step-up instead (carriesSecret); the shared rate
// limit (5 / min per user and device); failed attempts audited
// (privacy.disable_failed, device's tenant, never the password).
router.post('/disable-with-password', async (req, res, next) => {
  try {
    const userId = req.session.userId!;
    const { password } = (req.body ?? {}) as { password?: unknown };
    if (!password || typeof password !== 'string') throw new AppError(400, 'password is required');

    const { resolveRequestDevice } = await import('../services/deviceScope.service');
    const access = await resolveRequestDevice(req, (req.params as any).id);
    if (!access.ok) throw new AppError(access.status, access.error);
    const device = access.device;
    const feature = '_disable_';

    if (!access.isAdmin && !(await permissionService.canUseCapability(userId, device.id, false, 'execute'))) {
      await auditUnlockFailure(req, device, feature, 'forbidden', undefined, 'privacy.disable_failed');
      throw new AppError(403, "Capability 'execute' not permitted for your team");
    }
    if (!device.privacy_password_set) throw new AppError(400, 'No privacy password is set on this device');

    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req, actionKey: 'command.disable_privacy_mode', deviceIds: [device.id],
      deviceTenantId: device.tenant_id,
      approvalRequestType: 'batch_command',
      approvalDescription: `Disable privacy mode on ${device.hostname}`,
      approvalPayload: { action: 'disable_privacy_mode', deviceIds: [device.id] },
      carriesSecret: true,
    });
    if (!approved) return;

    if (!checkRateLimit(userId, device.id)) {
      if (firstRefusalOfWindow(userId, device.id)) {
        await auditUnlockFailure(req, device, feature, 'rate_limited', undefined, 'privacy.disable_failed');
      }
      throw new AppError(429, 'Too many password attempts, retry in a minute');
    }

    // Verify first
    let verify: { status: string; result: any };
    try {
      verify = await sendPrivacyCommand(
        device.id,
        device.tenant_id,
        'verify_privacy_password',
        { password, feature },
        userId,
      );
    } catch (err) {
      const offline = err instanceof AppError && err.statusCode === 503;
      await auditUnlockFailure(req, device, feature, offline ? 'agent_offline' : 'agent_no_answer', undefined, 'privacy.disable_failed');
      throw err;
    }
    if (verify.status !== 'success') {
      await auditUnlockFailure(req, device, feature, 'incorrect_password', verify.result?.error, 'privacy.disable_failed');
      throw new AppError(401, verify.result?.error || 'Incorrect password');
    }

    // Password OK -> issue the real disable command (device's tenant).
    const cmd = await commandService.enqueue({
      deviceId: device.id,
      tenantId: device.tenant_id,
      type: 'disable_privacy_mode' as any,
      priority: 'high',
      expiresInSeconds: 60,
      createdBy: userId,
    });
    agentHub.push(device.id, { type: 'command', id: cmd.id, commandType: 'disable_privacy_mode', payload: {} });
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReqAs(req, device.tenant_id, 'command.disable_privacy_mode', {
        deviceId: device.id, resourceType: 'command', resourcePath: cmd.id,
        details: { hostname: device.hostname, via: 'password' },
      });
    } catch {}
    res.json({ data: { success: true, commandId: cmd.id } });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/privacy/unlocks — list my active unlock sessions for this device
router.get('/unlocks', async (req, res, next) => {
  try {
    const deviceId = parseInt((req.params as any).id);
    const userId = req.session.userId!;
    res.json({ data: privacyGateService.list(userId, deviceId) });
  } catch (err) { next(err); }
});

export default router;
