// /api/android (tenant router: requireAuth, requireTenant), commands of the channel amapi (section 11.5). Not mounted:
// at the junction AN-P the routes of the queue (integration §8.12: /api/mdm/devices/:id/commands,
// /api/mdm/commands/:id/cancel, relaunch) gain the channel amapi and take these functions, with the checks of
// capabilities per device and of the restrictions matrix of those routes (mdm.reboot, mdm.lost_mode_disable,
// mdm.clear_app_data: restriction 'sensitive'). Until then this router is their shape, behind devices.manage.
//   GET  /devices/:id/commands        the commands of a device: type, state, age, operation, error (never a secret)
//   POST /devices/:id/commands        a command that is not guarded (REBOOT, STOP_LOST_MODE, CLEAR_APP_DATA); the
//                                     guarded ones go through /api/guard/actions (409 guardedActionRequired)
//   POST /commands/:id/cancel         cancellation (guarded commands: through the action)
//   POST /commands/:id/retry          a new command of the same type for a command in error (not guarded)
//   POST /commands/:id/release        a command held by the last-resort cap, released once the freeze is lifted
// Header Idempotency-Key: a request replayed with the same key returns the same commands.
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { audit } from '../../audit';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { ANDROID_COMMANDS, isAndroidCommandType } from '../commands/catalog';
import { AndroidCommandError, cancelAndroidCommand, enqueueAndroidCommands } from '../commands/bus';
import { releaseHeldCommand } from '../commands/submit';
import { toRouteError } from './enterprise.routes';

const CreateBody = z.object({ type: z.string().max(32), params: z.record(z.unknown()).optional(), reason: z.string().trim().max(500).optional() }).strict();
const UUID = z.string().uuid();
const KEY = /^[A-Za-z0-9_.:-]{8,200}$/;

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function routeError(err: unknown): unknown {
  if (err instanceof AndroidCommandError) return new AppError(err.status, err.message, err.code);
  return toRouteError(err);
}

const deviceIdOf = (req: Request): number => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id <= 0) throw new AppError(404, 'Not found', 'notFound');
  return id;
};

/** One command as the console sees it (never secret_enc, never the body of a command). */
const dto = (r: Record<string, unknown>) => ({
  id: r.id, type: r.request_type, state: r.state, submitState: r.submit_state, holdReason: r.hold_reason, rejectCode: r.reject_code,
  errorCode: r.amapi_error_code, origin: r.origin, guarded: r.guard_action_uuid !== null, operation: r.amapi_operation ? String(r.amapi_operation).split('/').pop() : null,
  createdAt: r.created_at, deliveredAt: r.delivered_at, completedAt: r.completed_at, expiresAt: r.expires_at,
});

export function createAndroidCommandsRouter(): Router {
  const router = Router();
  const capability = requireTenantCapability('devices.manage');

  router.get('/devices/:id/commands', capability, wrap(async (req, res) => {
    const deviceId = deviceIdOf(req);
    const rows = await db('android_commands').where({ device_id: deviceId }).orderBy('created_at', 'desc').limit(200)
      .select('id', 'request_type', 'state', 'submit_state', 'hold_reason', 'reject_code', 'amapi_error_code', 'origin', 'guard_action_uuid',
        'amapi_operation', 'created_at', 'delivered_at', 'completed_at', 'expires_at');
    res.json({ success: true, data: rows.map(dto) });
  }));

  router.post('/devices/:id/commands', capability, wrap(async (req, res) => {
    const deviceId = deviceIdOf(req);
    const parsed = CreateBody.safeParse(req.body);
    if (!parsed.success || !isAndroidCommandType(parsed.data.type)) throw new AppError(400, 'Invalid input', 'invalidInput');
    const type = parsed.data.type;
    if (ANDROID_COMMANDS[type].guarded) throw new AppError(409, 'This command is requested through a guarded action', 'guardedActionRequired');
    const key = req.get('Idempotency-Key');
    if (key !== undefined && !KEY.test(key)) throw new AppError(400, 'Invalid Idempotency-Key', 'invalidInput');
    const tenantId = Number(req.tenantId);
    const userId = Number(req.session.userId);
    try {
      const ctx = await audit.fromRequest(req, tenantId);
      const r = await asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
        const out = await enqueueAndroidCommands(trx, {
          tenantId, type, deviceIds: [deviceId], params: parsed.data.params, origin: 'console', actor: `u:${userId}`, requestedBy: userId,
          ...(parsed.data.reason ? { reason: parsed.data.reason } : {}), ...(key ? { idempotencyKey: `console:${key}` } : {}), auditCtx: ctx,
        });
        if (type === 'STOP_LOST_MODE' && out.byDevice.size && !out.replayed) {
          await trx('devices').where({ tenant_id: tenantId, id: deviceId, lost_mode_state: 'on' }).update({ lost_mode_state: 'disabling', lost_mode_changed_at: trx.fn.now() });
        }
        return out;
      }));
      const refusal = r.refused[0];
      if (refusal) {
        if (refusal.code === 'commandAlreadyPending') throw new AppError(409, 'A command of this type is already pending for this device', 'commandAlreadyPending');
        if (refusal.code === 'not_found') throw new AppError(404, 'Not found', 'notFound');
        throw new AppError(409, 'The device does not take this command', refusal.code);
      }
      res.status(r.replayed ? 200 : 201).json({ success: true, data: { commandId: r.byDevice.get(deviceId), batchId: r.batchId, replayed: r.replayed > 0 } });
    } catch (err) { throw routeError(err); }
  }));

  router.post('/commands/:id/cancel', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const tenantId = Number(req.tenantId);
    try {
      const r = await cancelAndroidCommand(tenantId, id.data, { actor: `u:${Number(req.session.userId)}`, auditCtx: await audit.fromRequest(req, tenantId) });
      res.json({ success: true, data: { result: r } });
    } catch (err) { throw routeError(err); }
  }));

  router.post('/commands/:id/retry', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const tenantId = Number(req.tenantId);
    const userId = Number(req.session.userId);
    try {
      const ctx = await audit.fromRequest(req, tenantId);
      const r = await asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
        const row = await trx('android_commands').where({ id: id.data }).first('device_id', 'request_type', 'params', 'state', 'guard_action_uuid') as
          { device_id: number; request_type: string; params: Record<string, unknown>; state: string; guard_action_uuid: string | null } | undefined;
        if (!row) throw new AppError(404, 'Not found', 'notFound');
        if (row.guard_action_uuid || !isAndroidCommandType(row.request_type) || ANDROID_COMMANDS[row.request_type].guarded) {
          throw new AppError(409, 'This command is requested through a guarded action', 'guardedActionRequired');
        }
        if (row.state !== 'error') throw new AppError(409, 'Only a command in error is retried', 'commandNotInError');
        const { passwordSealed: _p, ...params } = row.params ?? {};
        return enqueueAndroidCommands(trx, {
          tenantId, type: row.request_type, deviceIds: [Number(row.device_id)], params, origin: 'console', actor: `u:${userId}`, requestedBy: userId, auditCtx: ctx,
        });
      }));
      if (r.refused[0]) throw new AppError(409, 'The device does not take this command', r.refused[0].code);
      res.status(201).json({ success: true, data: { commandId: r.commandIds[0] } });
    } catch (err) { throw routeError(err); }
  }));

  router.post('/commands/:id/release', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const tenantId = Number(req.tenantId);
    const r = await releaseHeldCommand(tenantId, id.data, { type: 'user', userId: Number(req.session.userId) });
    if (r === 'frozen') throw new AppError(423, 'The tenant is frozen', 'tenantFrozen');
    if (r === 'not_held') throw new AppError(409, 'This command is not held by the last-resort cap', 'commandNotHeld');
    res.json({ success: true, data: { result: r } });
  }));
  return router;
}
