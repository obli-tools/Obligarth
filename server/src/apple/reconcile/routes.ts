import { Router, type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import type { DeviceCapability } from '@obligarth/shared';
import { audit } from '../../audit';
import { config } from '../../config';
import { db } from '../../db';
import { userActor } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { parseRequestDeviceId, resolveRequestDevice } from '../../services/deviceScope.service';
import { permissionService } from '../../services/permission.service';
import { applyRestriction } from '../../services/restriction.service';
import { edgeActorOf } from '../actors';
import { RETIRE_MANUAL_ITEMS, retirementOf, tickRetirementItem } from '../devices/retire';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import { realtime } from '../realtime';
import { attachUnknownEnrollments, listUnknownEnrollments, releaseUnknownEnrollments, UNKNOWN_BATCH_MAX } from './unknown';

// =============================================================================
// Console API of the operations lot (docs: integration-apple-edge §13.1,
// §13.2, §13.3), mounted at /api/apple behind the session and the tenant:
//   GET  /enrollments/unknown             enrollments apple-edge holds that no record of the tenant holds
//                                         (mdm.enrollment.manage)
//   POST /enrollments/unknown/attach      attach them to an enrollment profile (the record is born with its
//                                         ownership): { profileId, enrollmentIds } (200 at most)
//   POST /enrollments/unknown/release     release them at apple-edge: { enrollmentIds }
//   GET  /devices/:id/retirement          the checklist of the device's last verified retirement
//   POST /devices/:id/retirement/manual   tick a manual point (mdm:remove): { item: apple_business | activation_lock }
//   POST /devices/:id/revoke-identity     stolen device (mdm:remove, restriction apple.device_identity_revoke,
//                                         a reason): apple.device_identity_revoked (critical, P2), the certificate
//                                         revoked at apple-edge ('compromised') and the enrollment released
// A device out of reach answers like an unknown one (404); an enrollment of another tenant is refused by its
// prefix (404). The calls to apple-edge happen outside any transaction.
// =============================================================================

const router = Router();
const manage = requireTenantCapability('mdm.enrollment.manage');

const keyOfUser = (req: Request): string => `u:${req.session?.userId ?? 'anonymous'}`;
/** Listing reads every enrollment of the tenant at apple-edge: 10 a minute and per user. */
const listLimiter = rateLimit({
  windowMs: 60_000, limit: 10, keyGenerator: keyOfUser, standardHeaders: true, legacyHeaders: false,
  handler: (_q, res) => { res.status(429).json({ success: false, error: 'Too many requests', code: 'rateLimited' }); },
});

function h(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };
}

function body<S extends z.ZodTypeAny>(schema: S, req: Request): z.infer<S> {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  return parsed.data;
}

function requireOn(): void {
  if (config.apple.mode !== 'on') throw new AppError(503, 'The Apple integration is turned off on this instance', 'appleIntegrationDisabled');
}

/** The device of a route, in the session's tenant (404 otherwise), with the capability asked and write access. */
async function deviceOf(req: Request, capability?: DeviceCapability): Promise<number> {
  const id = parseRequestDeviceId(req.params.id);
  if (id === null) throw new AppError(404, 'Device not found');
  const outcome = await resolveRequestDevice(req, id, capability ? { capability } : {});
  if (!outcome.ok) throw new AppError(outcome.status, outcome.error, outcome.status === 403 ? 'capabilityMissing' : undefined);
  if (Number(outcome.device.tenant_id) !== Number(req.tenantId)) throw new AppError(404, 'Device not found');
  if (capability && !outcome.isAdmin && !(await permissionService.canWriteDevice(req.session.userId!, id, false))) {
    throw new AppError(403, 'Insufficient permissions', 'capabilityMissing');
  }
  return id;
}

const Ids = z.array(z.string().min(1).max(200)).min(1).max(UNKNOWN_BATCH_MAX);
const AttachBody = z.object({ profileId: z.string().min(1).max(64), enrollmentIds: Ids }).strict();
const ReleaseBody = z.object({ enrollmentIds: Ids }).strict();
const ManualBody = z.object({ item: z.enum(RETIRE_MANUAL_ITEMS) }).strict();
const RevokeBody = z.object({ reason: z.string().trim().min(3).max(500), ticket: z.string().trim().max(100).optional() }).strict();

router.get('/enrollments/unknown', manage, listLimiter, h(async (req, res) => {
  requireOn();
  const items = await listUnknownEnrollments(req.tenantId!, userActor(req.session.userId!), req.header('X-Request-ID') ?? undefined);
  res.json({ data: items });
}));

router.post('/enrollments/unknown/attach', manage, h(async (req, res) => {
  requireOn();
  const b = body(AttachBody, req);
  const tenantId = req.tenantId!;
  const out = await attachUnknownEnrollments(tenantId, userActor(req.session.userId!), b);
  const attached = Object.values(out.results).filter((r) => r === 'attached').length;
  if (attached > 0) {
    await audit.append({
      tenantId, action: 'apple.enrollment_attached', target: { type: 'enrollment_profile', id: b.profileId.toLowerCase() },
      details: { attached, requested: b.enrollmentIds.length, deviceIds: out.deviceIds.slice(0, 200).join(',') },
    }, await audit.fromRequest(req, tenantId));
  }
  res.json({ data: out });
}));

router.post('/enrollments/unknown/release', manage, h(async (req, res) => {
  requireOn();
  const b = body(ReleaseBody, req);
  const tenantId = req.tenantId!;
  const out = await releaseUnknownEnrollments(tenantId, userActor(req.session.userId!), b);
  const released = Object.values(out.results).filter((r) => r === 'released').length;
  if (released > 0) {
    await audit.append({
      tenantId, action: 'apple.enrollment_released', target: { type: 'tenant', id: String(tenantId) },
      details: { released, requested: b.enrollmentIds.length },
    }, await audit.fromRequest(req, tenantId));
  }
  res.json({ data: out });
}));

router.get('/devices/:id/retirement', h(async (req, res) => {
  const id = await deviceOf(req);
  res.json({ data: await retirementOf(db, req.tenantId!, id) });
}));

router.post('/devices/:id/retirement/manual', h(async (req, res) => {
  const id = await deviceOf(req, 'mdm:remove');
  const b = body(ManualBody, req);
  const tenantId = req.tenantId!;
  const view = await retirementOf(db, tenantId, id);
  if (!view.startedAt) throw new AppError(409, 'No retirement was started for this device', 'retirementNotStarted');
  await db.transaction((trx) => tickRetirementItem(trx, tenantId, id, b.item, req.session.userId!));
  realtime.deviceChanged(tenantId, id);
  res.json({ data: await retirementOf(db, tenantId, id) });
}));

router.post('/devices/:id/revoke-identity', h(async (req, res) => {
  const id = await deviceOf(req, 'mdm:remove');           // out of reach: 404 before anything else
  requireOn();
  const b = body(RevokeBody, req);
  const tenantId = req.tenantId!;
  const facts = await db('apple_devices as a').join('tenants as t', 't.id', 'a.tenant_id')
    .where({ 'a.tenant_id': tenantId, 'a.device_id': id }).first('t.mdm_key', 'a.enrollment_id', 'a.cert_sha256') as
    { mdm_key: string | null; enrollment_id: string; cert_sha256: string | null } | undefined;
  if (!facts?.mdm_key || !facts.enrollment_id.startsWith(`${facts.mdm_key}_`)) throw new AppError(404, 'Device not found');
  const sha = facts.cert_sha256 ? String(facts.cert_sha256).trim().toLowerCase() : null;
  if (!sha || !/^[0-9a-f]{64}$/.test(sha)) throw new AppError(409, 'This device has no identity certificate to revoke', 'identityUnavailable');
  const approved = await applyRestriction(res, {
    req, actionKey: 'apple.device_identity_revoke', approvalDescription: `Revoke the identity of the device #${id}`,
  });
  if (!approved) return;
  const key = facts.mdm_key;
  const o = { actor: edgeActorOf(userActor(req.session.userId!)), requestId: req.header('X-Request-ID') ?? undefined };
  const result = await audit.withIntent({
    tenantId, action: 'apple.device_identity_revoked', target: { type: 'device', id: String(id) },
    details: { reason: b.reason, ...(b.ticket ? { ticket: b.ticket } : {}) },
  }, await audit.fromRequest(req, tenantId), async () => {
    try {
      await appleEdge.revokeCertificate(key, sha, 'compromised', o);
      let released = true;
      try {
        await appleEdge.releaseEnrollment(key, facts.enrollment_id, o);
      } catch (err) {
        if (isAppleEdgeError(err) && (err.code === 'enrollment_not_found' || err.status === 404)) released = false;
        else throw err;
      }
      return { revoked: true, released };
    } catch (err) {
      if (isAppleEdgeError(err)) throw new AppError(err.retryable ? 503 : 502, 'The device service did not revoke the identity', 'appleEdgeUnavailable');
      throw err;
    }
  }, { resultDetails: (r) => ({ released: r.released }) });
  realtime.deviceChanged(tenantId, id);
  res.json({ data: result });
}));

/** Mounted at /api/apple (routes/index.ts), after requireTenant. */
export function createAppleOperationsRouter(): Router {
  return router;
}
