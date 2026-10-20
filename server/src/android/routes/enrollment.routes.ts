// /api/android (tenant router: requireAuth, requireTenant), enrollment (sections 10.1 to 10.4 step 5):
//   GET    /enrollment-profiles             the Android profiles (?archived=1: all), their tokens and enrollment policy
//   GET    /enrollment-profiles/:id         one of them
//   POST   /enrollment-profiles             creates one (profile service of lot C1, Android checks; lot AN-C1)
//   PUT    /enrollment-profiles/:id         changes one (version + 1; the method never changes)
//   POST   /enrollment-profiles/:id/archive archives one (a kiosk profile with enrolled devices: 409), its tokens revoked
//   POST   /enrollment-tokens               creates a token of an Android profile; answers its payload once
//   GET    /enrollment-tokens/:id/payload   shows an active token again (step-up for a long token), audited
//   DELETE /enrollment-tokens/:id           revokes a token (deleted at Google, value destroyed), audited
//   POST   /devices/:id/approve             approves a device enrolled with a token that requires it
//   POST   /devices/:id/refuse              refuses it (its deletion: android.device_forget, lot AN-D)
// Capability: mdm.enrollment.manage (AN41, §22.8). Mounted under /api/android by routes/index.ts (lot AN-A2).
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
import {
  archiveAndroidProfile, checkAndroidProfileBody, createAndroidProfile, getAndroidProfile, listAndroidProfiles, updateAndroidProfile,
} from '../enrollment/profileService';
import { logger } from '../../utils/logger';
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
  const capability = requireTenantCapability('mdm.enrollment.manage');

  // ── Profiles (section 10.1, lot AN-C1) ──
  const profileId = (req: Request): string => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'enrollmentProfileNotFound');
    return id.data.toLowerCase();
  };
  const savedAudit = async (req: Request, tenantId: number, id: string, details: Record<string, unknown>) => audit.append({
    tenantId, action: 'android.enrollment_profile_saved', target: { type: 'enrollment_profile', id }, details: { profileId: id, ...details },
  }, await audit.fromRequest(req, tenantId));

  router.get('/enrollment-profiles', capability, wrap(async (req, res) => {
    res.json({ success: true, data: await listAndroidProfiles(db, Number(req.tenantId), req.query.archived === '1') });
  }));

  router.get('/enrollment-profiles/:id', capability, wrap(async (req, res) => {
    res.json({ success: true, data: await getAndroidProfile(db, Number(req.tenantId), profileId(req)) });
  }));

  router.post('/enrollment-profiles', capability, wrap(async (req, res) => {
    const tenantId = Number(req.tenantId);
    const p = checkAndroidProfileBody(req.body);
    const id = await db.transaction((trx) => createAndroidProfile(trx, tenantId, Number(req.session.userId), p));
    await savedAudit(req, tenantId, id, { created: true, method: p.method, ownership: p.ownership, version: 1 });
    res.status(201).json({ success: true, data: await getAndroidProfile(db, tenantId, id) });
  }));

  router.put('/enrollment-profiles/:id', capability, wrap(async (req, res) => {
    const tenantId = Number(req.tenantId);
    const id = profileId(req);
    // A profile out of reach names nothing, whatever the body (404 before any check of the body: rls-tenant §11.5).
    if (!(await db('enrollment_profiles').where({ tenant_id: tenantId, id, platform: 'android' }).first('id'))) {
      throw new AppError(404, 'Enrollment profile not found', 'enrollmentProfileNotFound');
    }
    const p = checkAndroidProfileBody(req.body);
    const version = await db.transaction((trx) => updateAndroidProfile(trx, tenantId, Number(req.session.userId), id, p));
    await savedAudit(req, tenantId, id, { method: p.method, ownership: p.ownership, version });
    res.json({ success: true, data: await getAndroidProfile(db, tenantId, id) });
  }));

  router.post('/enrollment-profiles/:id/archive', capability, wrap(async (req, res) => {
    const tenantId = Number(req.tenantId);
    const userId = Number(req.session.userId);
    const id = profileId(req);
    const r = await db.transaction((trx) => archiveAndroidProfile(trx, tenantId, userId, id));
    await savedAudit(req, tenantId, id, { archived: true, version: r.version, tokens: r.tokens.length });
    // An archived profile enrolls no new device: its active tokens are deleted at Google (each audited). A failure
    // leaves the token active, shown on the profile: the operator revokes it again.
    let revoked = 0;
    for (const t of r.tokens) {
      try {
        if (await revokeEnrollmentToken(tenantId, userId, t, await audit.fromRequest(req, tenantId)) === 'revoked') revoked++;
      } catch (err) {
        logger.warn({ android: { profileArchive: 'token_not_revoked', tenantId, code: (err as { code?: string; kind?: string })?.kind ?? 'error' } }, 'android: token of an archived profile not revoked');
      }
    }
    res.json({ success: true, data: { ...(await getAndroidProfile(db, tenantId, id)), tokensRevoked: revoked } });
  }));

  // ── Tokens (sections 10.2, 10.3) ──
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
      // A device of another tenant names nothing here (404, never a state of it: rls-tenant §11.5).
      if (!(await db('android_devices').where({ tenant_id: tenantId, device_id: deviceId }).first('device_id'))) throw new AppError(404, 'Not found', 'notFound');
      try {
        const r = await fn(tenantId, Number(req.session.userId), deviceId, await audit.fromRequest(req, tenantId));
        res.json({ success: true, data: { result: r } });
      } catch (err) { throw routeError(err); }
    }));
  }
  return router;
}
