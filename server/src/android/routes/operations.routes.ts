// Routes of the Android operation (lot AN-H1), mounted by routes/index.ts (junction AN-A2):
// /api/android (tenant router: requireAuth, requireTenant; capability of the integrations, devices.manage until
// mdm.integrations.manage exists, AN41):
//   POST /enterprise/unlink                   restricted request of the unlink (reason, step-up; a second approver)
//   POST /enterprise/unlink/force             restricted request to go on without the devices left (reason, step-up)
//   POST /enterprise/unlink/confirm-external  the enterprise in error confirmed unlinked from outside (step-up)
//   POST /enterprise/recheck                  an enterprise in error read again at Google (linked again if reachable)
//   GET  /enterprise/offboarding              the offboarding (steps, devices left, the client's guide once done)
//   POST /reconcile                           an extra reconciliation of the tenant (picked up within the minute)
//   GET  /devices/presumed-gone               the devices presumed gone (their forget: guarded action android.device_forget,
//                                             POST /api/guard/actions, never a route of this module)
//   GET  /deadlines                           the deadlines of the tenant (long tokens, backup administrators)
// /api/admin/android (master tenant, platform administrators):
//   GET  /quota                               quota of the project, last weekly recount and its gap
//   GET  /orphans?tenantId=                   orphan enterprises adoptable by a tenant (marker of its failed signup)
//   POST /orphans/adopt                       restricted request of the adoption (another platform administrator, step-up)
//   GET  /deadlines                           the deadline of the service account key
import { Router, type NextFunction, type Request, type Response } from 'express';
import { audit } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { checkSecondFactor, sendStepUpFailure } from '../../services/deviceKey/stepUpProof';
import { AdoptionError, listAdoptable, requestAdoption } from '../operations/adoption';
import { listAndroidDeadlines, platformKeyDeadline } from '../operations/deadlines';
import { listPresumedGone } from '../operations/forget';
import {
  confirmExternalUnlink, INTEGRATIONS_CAPABILITY, OffboardingError, readOffboarding, recheckEnterpriseAccess, requestForceUnlink, requestUnlink,
} from '../operations/offboarding';
import { readQuotaView } from '../operations/quota';
import { requestReconcile } from '../operations/reconcile';
import { masterPlatformAdmin } from './admin.routes';
import { toRouteError } from './enterprise.routes';

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

const asRouteError = (err: unknown): unknown => {
  if (err instanceof OffboardingError || err instanceof AdoptionError) return new AppError(err.status, err.message, err.code);
  return toRouteError(err);
};

/** Step-up of the requester (no trusted-IP shortcut); false when the answer was sent. */
async function stepUp(req: Request, res: Response, actionKey: string): Promise<boolean> {
  const step = await checkSecondFactor(req, { actionKey, allowTrustedIp: false, allowDevice: true });
  if (!step.ok) { sendStepUpFailure(res, step); return false; }
  return true;
}

export function createAndroidOperationsRouter(): Router {
  const router = Router();
  const capability = requireTenantCapability(INTEGRATIONS_CAPABILITY);
  const ids = (req: Request) => ({ tenantId: Number(req.tenantId), userId: Number(req.session.userId) });

  router.post('/enterprise/unlink', capability, wrap(async (req, res) => {
    if (!(await stepUp(req, res, 'android.enterprise_unlink'))) return;
    const { tenantId, userId } = ids(req);
    try {
      const approval = await requestUnlink(tenantId, userId, req.body ?? {}, await audit.fromRequest(req, tenantId), req);
      res.status(202).json({ success: true, data: { approvalId: approval.id, status: approval.status } });
    } catch (err) { throw asRouteError(err); }
  }));

  router.post('/enterprise/unlink/force', capability, wrap(async (req, res) => {
    if (!(await stepUp(req, res, 'android.enterprise_force_unlink'))) return;
    const { tenantId, userId } = ids(req);
    try {
      const approval = await requestForceUnlink(tenantId, userId, req.body ?? {}, await audit.fromRequest(req, tenantId), req);
      res.status(202).json({ success: true, data: { approvalId: approval.id, status: approval.status } });
    } catch (err) { throw asRouteError(err); }
  }));

  router.post('/enterprise/unlink/confirm-external', capability, wrap(async (req, res) => {
    if (!(await stepUp(req, res, 'android.enterprise_unlink'))) return;
    const { tenantId, userId } = ids(req);
    try {
      res.json({ success: true, data: { result: await confirmExternalUnlink(tenantId, userId, await audit.fromRequest(req, tenantId)) } });
    } catch (err) { throw asRouteError(err); }
  }));

  router.post('/enterprise/recheck', capability, wrap(async (req, res) => {
    try {
      res.json({ success: true, data: { result: await recheckEnterpriseAccess(Number(req.tenantId)) } });
    } catch (err) { throw asRouteError(err); }
  }));

  router.get('/enterprise/offboarding', capability, wrap(async (req, res) => {
    const { tenantId, userId } = ids(req);
    res.json({ success: true, data: await readOffboarding(tenantId, userId) });
  }));

  router.post('/reconcile', capability, wrap(async (req, res) => {
    const { tenantId, userId } = ids(req);
    const ok = await requestReconcile(tenantId, 'operator', { type: 'user', userId });
    if (!ok) throw new AppError(409, 'No linked Android enterprise', 'androidNotLinked');
    res.status(202).json({ success: true, data: { requested: true } });
  }));

  router.get('/devices/presumed-gone', capability, wrap(async (req, res) => {
    const { tenantId, userId } = ids(req);
    res.json({ success: true, data: await listPresumedGone(tenantId, userId) });
  }));

  router.get('/deadlines', capability, wrap(async (req, res) => {
    const { tenantId, userId } = ids(req);
    res.json({ success: true, data: await listAndroidDeadlines(tenantId, userId) });
  }));
  return router;
}

export function createAndroidOperationsAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  router.get('/quota', wrap(async (_req, res) => {
    res.json({ success: true, data: await readQuotaView() });
  }));

  router.get('/orphans', wrap(async (req, res) => {
    const tenantId = Number(req.query.tenantId);
    if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new AppError(400, 'tenantId required', 'invalidInput');
    try {
      res.json({ success: true, data: await listAdoptable(tenantId) });
    } catch (err) { throw asRouteError(err); }
  }));

  router.post('/orphans/adopt', wrap(async (req, res) => {
    if (!(await stepUp(req, res, 'android.enterprise_adopt'))) return;
    const body = (req.body ?? {}) as Record<string, unknown>;
    const tenantId = Number(body.tenantId);
    try {
      const approval = await requestAdoption(Number(req.session.userId), body, await audit.fromRequest(req, Number.isSafeInteger(tenantId) && tenantId > 0 ? tenantId : Number(req.tenantId)));
      res.status(202).json({ success: true, data: { approvalId: approval.id, status: approval.status } });
    } catch (err) { throw asRouteError(err); }
  }));

  router.get('/deadlines', wrap(async (_req, res) => {
    res.json({ success: true, data: await platformKeyDeadline() });
  }));
  return router;
}
