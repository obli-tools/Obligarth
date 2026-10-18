// /api/android (tenant router: requireAuth, requireTenant), enrollment (sections 10.2, 10.3, 10.4 step 5):
//   POST   /enrollment-tokens               creates a token of an Android profile; answers its payload once
//   GET    /enrollment-tokens/:id/payload   shows an active token again (step-up for a long token), audited
//   DELETE /enrollment-tokens/:id           revokes a token (deleted at Google, value destroyed), audited
//   POST   /devices/:id/approve             approves a device enrolled with a token that requires it
//   POST   /devices/:id/refuse              refuses it (its deletion: android.device_forget, lot AN-D)
// Capability: mdm.enrollment.manage once it exists (AN41, §22.8); devices.manage until then. Mounted at lot AN-A2.
// The value of a token is never logged: the payload is in the body of the answer only, with Cache-Control no-store.
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { audit } from '../../audit';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { checkSecondFactor, sendStepUpFailure } from '../../services/deviceKey/stepUpProof';
import { ApprovalError, approveAndroidDevice, refuseAndroidDevice } from '../enrollment/decisions';
import { createEnrollmentToken, revealEnrollmentToken, revokeEnrollmentToken, TokenError } from '../enrollment/tokens';
import { toRouteError } from './enterprise.routes';

const CreateBody = z.object({
  profileId: z.string().uuid(),
  endUserId: z.number().int().positive().optional(),
  expiresInSeconds: z.number().int().min(60).max(31_536_000).optional(),
}).strict();
const UUID = z.string().uuid();

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function routeError(err: unknown): unknown {
  if (err instanceof TokenError || err instanceof ApprovalError) return new AppError(err.status, err.message, err.code);
  return toRouteError(err);
}

export function createAndroidEnrollmentRouter(): Router {
  const router = Router();
  const capability = requireTenantCapability('devices.manage');

  router.post('/enrollment-tokens', capability, wrap(async (req, res) => {
    const parsed = CreateBody.safeParse(req.body);
    if (!parsed.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    const tenantId = Number(req.tenantId);
    const userId = Number(req.session.userId);
    try {
      const ctx = await audit.fromRequest(req, tenantId);
      const t = await createEnrollmentToken(tenantId, userId, parsed.data, ctx);
      res.setHeader('Cache-Control', 'no-store');
      res.status(201).json({ success: true, data: t });
    } catch (err) { throw routeError(err); }
  }));

  router.get('/enrollment-tokens/:id/payload', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const tenantId = Number(req.tenantId);
    const userId = Number(req.session.userId);
    const row = await db('android_enrollment_tokens').where({ id: id.data }).first('max_uses') as { max_uses: number | null } | undefined;
    if (!row) throw new AppError(404, 'Not found', 'notFound');
    if (row.max_uses === null) {
      const step = await checkSecondFactor(req, { actionKey: 'android.enrollment_token_reveal', allowTrustedIp: false, allowDevice: true });
      if (!step.ok) { sendStepUpFailure(res, step); return; }
    }
    try {
      const t = await revealEnrollmentToken(tenantId, userId, id.data, await audit.fromRequest(req, tenantId));
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, data: t });
    } catch (err) { throw routeError(err); }
  }));

  router.delete('/enrollment-tokens/:id', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const tenantId = Number(req.tenantId);
    try {
      const r = await revokeEnrollmentToken(tenantId, Number(req.session.userId), id.data, await audit.fromRequest(req, tenantId));
      res.json({ success: true, data: { result: r } });
    } catch (err) { throw routeError(err); }
  }));

  for (const [path, fn] of [['approve', approveAndroidDevice], ['refuse', refuseAndroidDevice]] as const) {
    router.post(`/devices/:id/${path}`, capability, wrap(async (req, res) => {
      const deviceId = Number(req.params.id);
      if (!Number.isSafeInteger(deviceId) || deviceId <= 0) throw new AppError(404, 'Not found', 'notFound');
      const tenantId = Number(req.tenantId);
      try {
        const r = await fn(tenantId, Number(req.session.userId), deviceId, await audit.fromRequest(req, tenantId));
        res.json({ success: true, data: { result: r } });
      } catch (err) { throw routeError(err); }
    }));
  }
  return router;
}
