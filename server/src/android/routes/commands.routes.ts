// The commands of the channel amapi in the console (section 11.5; lot AN-D). Since lot AN-D they live in the queue
// (mdm_commands, platform 'android'): the routes of the queue (/api/apple/devices/:id/commands, /api/apple/commands/:id/
// cancel and /relaunch, integration §8.12) hand an amapi device or an Android command to the handlers below
// (registerQueueChannel), and /api/android keeps the same routes. Behind devices.manage, the device's team scope and the
// capability of each type (deviceAccess.ts, §22.8), and the restriction of the tenant's matrix (mdm.reboot,
// mdm.lost_mode_disable, mdm.clear_app_data, floor 'sensitive'; 'restricted': a request for approval android_action).
//   GET  /devices/:id/commands        the commands of a device: type, state, age, operation, error (never a secret)
//   POST /devices/:id/commands        a command that is not guarded (REBOOT, STOP_LOST_MODE, CLEAR_APP_DATA); the
//                                     guarded ones go through /api/guard/actions (409 guardedActionRequired)
//   POST /commands/:id/cancel         cancellation (guarded commands: through the action)
//   POST /commands/:id/retry          a new command of the same type for a command in error (not guarded); the queue
//                                     route …/relaunch does the same for an Android command
//   POST /commands/:id/release        a command held by the last-resort cap, released once the freeze is lifted
// Header Idempotency-Key: a request replayed with the same key returns the same commands.
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { audit } from '../../audit';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { registerQueueChannel } from '../../mdm/registry/queueChannels';
import { applyRestriction } from '../../services/restriction.service';
import { ANDROID_COMMANDS, isAndroidCommandType } from '../commands/catalog';
import { AndroidCommandError, cancelAndroidCommand } from '../commands/bus';
import { ANDROID_ACTION_APPROVAL, consoleType, enqueueConsoleCommand } from '../commands/console';
import { commands, readCommand } from '../commands/store';
import { releaseHeldCommand } from '../commands/submit';
import { toRouteError } from './enterprise.routes';
import { ANDROID_COMMAND_CAPABILITY, ANDROID_COMMAND_RESTRICTION, androidDeviceOf } from './deviceAccess';

/** The body of /api/android (type) or of the queue route (requestType). */
const CreateBody = z.object({
  type: z.string().max(32).optional(), requestType: z.string().max(32).optional(), params: z.record(z.unknown()).optional(),
  reason: z.string().trim().max(500).optional(), ticket: z.string().trim().max(100).optional(),
}).strict();
const UUID = z.string().uuid();
const KEY = /^[A-Za-z0-9_.:-]{8,200}$/;

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function routeError(err: unknown): unknown {
  if (err instanceof AndroidCommandError) return new AppError(err.status, err.message, err.code);
  return toRouteError(err);
}

/** One command as the console sees it (never secret_enc, never the body of a command). */
const dto = (r: Record<string, unknown>) => ({
  id: r.id, type: r.request_type, state: r.state, submitState: r.submit_state, holdReason: r.hold_reason, rejectCode: r.reject_code,
  errorCode: r.amapi_error_code, origin: r.origin, guarded: r.guard_action_uuid !== null, operation: r.amapi_operation ? String(r.amapi_operation).split('/').pop() : null,
  createdAt: r.created_at, deliveredAt: r.delivered_at, completedAt: r.completed_at, expiresAt: r.expires_at,
});

/** A command of the request's tenant and its device, with the capability its type needs there (review AN-A2): 404
 *  for a command of another tenant or of a device the caller does not see, 403 without the capability. */
async function ownCommand(req: Request, commandId: string): Promise<void> {
  const row = await readCommand(db, Number(req.tenantId), commandId);
  if (!row) throw new AppError(404, 'Not found', 'notFound');
  await androidDeviceOf(req, Number(row.device_id), isAndroidCommandType(row.request_type) ? ANDROID_COMMAND_CAPABILITY[row.request_type] : 'mdm:wipe');
}

/** POST …/devices/:id/commands for an amapi device (the device already resolved for the caller). */
export async function createAndroidCommandFor(req: Request, res: Response, deviceId: number): Promise<void> {
  // The device first (404 whatever the request says), then the type, the capability of the type on this device (403)
  // and the restriction of the tenant's matrix (step-up; 'restricted': a second approver): the order of the Apple route.
  const parsed = CreateBody.safeParse(req.body ?? {});
  const raw = parsed.success ? parsed.data.type ?? parsed.data.requestType : undefined;
  if (!parsed.success || !raw || !isAndroidCommandType(raw)) throw new AppError(400, 'Invalid input', 'invalidInput');
  if (ANDROID_COMMANDS[raw].guarded) throw new AppError(409, 'This command is requested through a guarded action', 'guardedActionRequired');
  const type = consoleType(raw)!;
  await androidDeviceOf(req, deviceId, ANDROID_COMMAND_CAPABILITY[type]);
  const key = req.get('Idempotency-Key');
  if (key !== undefined && !KEY.test(key)) throw new AppError(400, 'Invalid Idempotency-Key', 'invalidInput');
  const tenantId = Number(req.tenantId);
  const userId = Number(req.session.userId);
  const restrictionKey = ANDROID_COMMAND_RESTRICTION[type];
  if (restrictionKey && !(await applyRestriction(res, {
    req, actionKey: restrictionKey, deviceIds: [deviceId], approvalRequestType: ANDROID_ACTION_APPROVAL,
    approvalDescription: `${type} on 1 Android device`,
    approvalPayload: { action: 'android.command', type, deviceIds: [deviceId], params: parsed.data.params ?? {}, reason: parsed.data.reason ?? null },
  }))) return;
  try {
    const ctx = await audit.fromRequest(req, tenantId);
    const r = await asTenant(tenantId, { type: 'user', userId }, () => db.transaction((trx) => enqueueConsoleCommand(trx, {
      tenantId, type, deviceIds: [deviceId], params: parsed.data.params, userId, origin: 'console', auditCtx: ctx,
      ...(parsed.data.reason ? { reason: parsed.data.reason } : {}), ...(key ? { idempotencyKey: `console:${key}` } : {}),
    })));
    const refusal = r.refused[0];
    if (refusal) {
      if (refusal.code === 'commandAlreadyPending') throw new AppError(409, 'A command of this type is already pending for this device', 'commandAlreadyPending');
      if (refusal.code === 'not_found') throw new AppError(404, 'Not found', 'notFound');
      throw new AppError(409, 'The device does not take this command', refusal.code);
    }
    res.status(r.replayed ? 200 : 201).json({ success: true, data: { commandId: r.byDevice.get(deviceId), batchId: r.batchId, replayed: r.replayed > 0 } });
  } catch (err) { throw routeError(err); }
}

/** POST …/commands/:id/cancel for an Android command. */
export async function cancelAndroidCommandFor(req: Request, res: Response, commandId: string): Promise<void> {
  const id = UUID.safeParse(commandId);
  if (!id.success) throw new AppError(404, 'Not found', 'notFound');
  await ownCommand(req, id.data);
  const tenantId = Number(req.tenantId);
  try {
    const r = await cancelAndroidCommand(tenantId, id.data, { actor: `u:${Number(req.session.userId)}`, auditCtx: await audit.fromRequest(req, tenantId) });
    res.json({ success: true, data: { result: r } });
  } catch (err) { throw routeError(err); }
}

/** POST …/commands/:id/retry (or the queue's …/relaunch) for an Android command in error: a new command of its type. */
export async function retryAndroidCommandFor(req: Request, res: Response, commandId: string): Promise<void> {
  const id = UUID.safeParse(commandId);
  if (!id.success) throw new AppError(404, 'Not found', 'notFound');
  await ownCommand(req, id.data);
  const tenantId = Number(req.tenantId);
  const userId = Number(req.session.userId);
  const row = await readCommand(db, tenantId, id.data);
  if (!row) throw new AppError(404, 'Not found', 'notFound');
  if (row.guard_action_uuid || !consoleType(row.request_type)) {
    throw new AppError(409, 'This command is requested through a guarded action', 'guardedActionRequired');
  }
  if (row.state !== 'error') throw new AppError(409, 'Only a command in error is retried', 'commandNotInError');
  const type = consoleType(row.request_type)!;
  const { passwordSealed: _p, ...params } = (typeof row.params === 'string' ? JSON.parse(row.params) : row.params ?? {}) as Record<string, unknown>;
  // A retry is a new command: the restriction of its type holds as for a first request.
  const restrictionKey = ANDROID_COMMAND_RESTRICTION[type];
  if (restrictionKey && !(await applyRestriction(res, {
    req, actionKey: restrictionKey, deviceIds: [Number(row.device_id)], approvalRequestType: ANDROID_ACTION_APPROVAL,
    approvalDescription: `${type} on 1 Android device`,
    approvalPayload: { action: 'android.command', type, deviceIds: [Number(row.device_id)], params, reason: null },
  }))) return;
  try {
    const ctx = await audit.fromRequest(req, tenantId);
    const r = await asTenant(tenantId, { type: 'user', userId }, () => db.transaction((trx) => enqueueConsoleCommand(trx, {
      tenantId, type, deviceIds: [Number(row.device_id)], params, userId, origin: 'console', auditCtx: ctx,
    })));
    if (r.refused[0]) throw new AppError(409, 'The device does not take this command', r.refused[0].code);
    res.status(201).json({ success: true, data: { commandId: r.commandIds[0] } });
  } catch (err) { throw routeError(err); }
}

let channelRegistered = false;

/** The queue routes hand the amapi devices and the Android commands to these handlers. */
export function registerAndroidQueueChannel(): void {
  if (channelRegistered) return;
  channelRegistered = true;
  registerQueueChannel({
    channel: 'amapi', platform: 'android',
    create: (req, res, deviceId) => createAndroidCommandFor(req, res, deviceId),
    cancel: (req, res, commandId) => cancelAndroidCommandFor(req, res, commandId),
    relaunch: (req, res, commandId) => retryAndroidCommandFor(req, res, commandId),
  });
}

export function createAndroidCommandsRouter(): Router {
  const router = Router();
  const capability = requireTenantCapability('devices.manage');

  router.get('/devices/:id/commands', capability, wrap(async (req, res) => {
    const deviceId = await androidDeviceOf(req, req.params.id);
    const rows = await commands(db).where({ 'c.tenant_id': Number(req.tenantId), 't.device_id': deviceId }).orderBy('c.created_at', 'desc').limit(200)
      .select('c.id', 'c.request_type', 't.state', 'c.submit_state', 't.hold_reason', 't.reject_code', 't.amapi_error_code', 'c.origin', 'c.guard_action_uuid',
        't.amapi_operation', 'c.created_at', 't.delivered_at', 't.completed_at', 'c.expires_at');
    res.json({ success: true, data: rows.map(dto) });
  }));

  router.post('/devices/:id/commands', capability, wrap(async (req, res) => {
    const deviceId = await androidDeviceOf(req, req.params.id);
    await createAndroidCommandFor(req, res, deviceId);
  }));

  router.post('/commands/:id/cancel', capability, wrap((req, res) => cancelAndroidCommandFor(req, res, req.params.id)));
  router.post('/commands/:id/retry', capability, wrap((req, res) => retryAndroidCommandFor(req, res, req.params.id)));

  router.post('/commands/:id/release', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const tenantId = Number(req.tenantId);
    await ownCommand(req, id.data);
    const r = await releaseHeldCommand(tenantId, id.data, { type: 'user', userId: Number(req.session.userId) });
    if (r === 'frozen') throw new AppError(423, 'The tenant is frozen', 'tenantFrozen');
    if (r === 'not_held') throw new AppError(409, 'This command is not held by the last-resort cap', 'commandNotHeld');
    res.json({ success: true, data: { result: r } });
  }));
  return router;
}
