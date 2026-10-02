// Routes of the guard engine (docs: audit-durci §10.11), mounted by
// tenantRouter.use('/guard', …) behind requireAuth and requireTenant.
//   POST   /actions                 request (202 GuardOutcome)
//   POST   /actions/preview         level, delay, confirmation, quota (no effect)
//   GET    /actions?state=          members with devices.manage, approvals.review or audit.read
//   GET    /actions/:uuid           idem
//   POST   /actions/:uuid/cancel    §10.5
//   POST   /actions/:uuid/resume    §10.5 (approval request)
//   GET    /quota                   devices.manage
//   GET    /catalog                 the guarded actions, their floors and delays
//   POST   /freeze, /unfreeze       §10.7
//   GET    /settings, PUT /settings  §10.6
//   GET    /approvers, POST /approvers, DELETE /approvers/:id   §10.4
import { Router, type NextFunction, type Request, type Response } from 'express';
import {
  GUARD_BULK_THRESHOLD, OPEN_PENDING_ACTION_STATES, PENDING_ACTION_STATES, type GuardedActionInfo, type PendingActionState,
} from '@obligarth/shared';
import { db } from '../db';
import { globalViewScope } from '../middleware/dbContext';
import { AppError } from '../middleware/errorHandler';
import { requireTenantCapability } from '../middleware/rbac';
import { hasGlobalView } from '../services/deviceScope.service';
import { permissionService } from '../services/permission.service';
import { sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { asAppError } from './approvals';
import { quotaOf } from './cap';
import { guardedActionList } from './catalog';
import { GuardStepUpError, preview, request } from './engine';
import {
  cancelAction, freeze, listApprovers, requestDesignation, requestResume, requestSettings, requestUnfreeze, revokeDesignation,
} from './operations';
import { readSettings, settingsToDto } from './settings';
import { ACTION_COLUMNS, findAction, normaliseRow, toDto, toDtos } from './store';

/** Members who read the guarded actions: devices.manage, approvals.review or
 *  audit.read in the tenant, a designated approver; platform administrators. */
async function requireGuardReader(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    if (req.session.role === 'admin') { next(); return; }
    const userId = Number(req.session.userId);
    const tenantId = Number(req.tenantId);
    for (const cap of ['devices.manage', 'approvals.review', 'audit.read'] as const) {
      if (await permissionService.userHasTenantCapability(userId, tenantId, cap)) { next(); return; }
    }
    if (await db('tenant_approvers').where({ tenant_id: tenantId, user_id: userId }).whereNull('revoked_at').first('id')) { next(); return; }
    next(new AppError(403, 'Insufficient permissions'));
  } catch (err) {
    next(err);
  }
}

/** The errors of the engine: the step-up's own answer, an AppError, the
 *  approval engine's status, else the error handler. */
function fail(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof GuardStepUpError) { sendStepUpFailure(res, err.outcome); return; }
  const app = asAppError(err);
  next(app ?? err);
}

export function catalogInfo(): GuardedActionInfo[] {
  return guardedActionList().map((d) => ({
    key: d.key, label: d.label, family: d.family, singleFloor: d.singleFloor, singleStrictStepUp: d.singleStrictStepUp,
    bulkThreshold: d.bulkThreshold ?? GUARD_BULK_THRESHOLD, singleDelaySeconds: d.singleDelaySeconds, bulkDelaySeconds: d.bulkDelaySeconds,
    hourlyCap: d.hourlyCap, forbidWholeFleet: d.forbidWholeFleet, confirmation: d.confirmation,
  }));
}

export function createGuardRouter(): Router {
  const router = Router();

  router.post('/actions', async (req, res, next) => {
    try {
      res.status(202).json({ data: await request(req, req.body ?? {}) });
    } catch (err) { fail(err, res, next); }
  });

  router.post('/actions/preview', async (req, res, next) => {
    try {
      res.json({ data: await preview(req, req.body ?? {}) });
    } catch (err) { fail(err, res, next); }
  });

  router.get('/actions', requireGuardReader, globalViewScope('console.guard'), async (req, res, next) => {
    try {
      const raw = typeof req.query.state === 'string' ? req.query.state : '';
      const states: PendingActionState[] = raw === 'open' ? [...OPEN_PENDING_ACTION_STATES]
        : raw ? raw.split(',').filter((s): s is PendingActionState => (PENDING_ACTION_STATES as readonly string[]).includes(s)) : [];
      const limit = Math.min(200, Math.max(1, parseInt(String(req.query.limit ?? '100'), 10) || 100));
      const q = db('pending_actions').orderBy('created_at', 'desc').limit(limit).select(ACTION_COLUMNS);
      if (hasGlobalView(req)) {
        const filter = Number(req.query.tenantId);
        if (Number.isSafeInteger(filter) && filter > 0) q.where({ tenant_id: filter });
      } else {
        q.where({ tenant_id: req.tenantId! });
      }
      if (states.length) q.whereIn('state', states);
      const rows = (await q as Array<Record<string, unknown>>).map(normaliseRow);
      res.json({ data: await toDtos(rows) });
    } catch (err) { next(err); }
  });

  router.get('/actions/:uuid', requireGuardReader, globalViewScope('console.guard'), async (req, res, next) => {
    try {
      const row = await findAction(req.params.uuid, hasGlobalView(req) ? {} : { tenantId: req.tenantId! });
      if (!row) throw new AppError(404, 'Guarded action not found', 'notFound');
      res.json({ data: { ...(await toDto(row)), selection: row.selection, params: row.params, resultDetails: row.result } });
    } catch (err) { next(err); }
  });

  router.post('/actions/:uuid/cancel', async (req, res, next) => {
    try {
      res.json({ data: await cancelAction(req, req.params.uuid, req.body?.reason) });
    } catch (err) { fail(err, res, next); }
  });

  router.post('/actions/:uuid/resume', async (req, res, next) => {
    try {
      const approval = await requestResume(req, req.params.uuid);
      res.status(202).json({ data: { approvalId: approval.id, status: 'pending_approval', expiresAt: approval.expiresAt } });
    } catch (err) { fail(err, res, next); }
  });

  router.get('/quota', requireTenantCapability('devices.manage'), async (req, res, next) => {
    try {
      res.json({ data: await quotaOf(req.tenantId!) });
    } catch (err) { next(err); }
  });

  router.get('/catalog', (_req, res) => {
    res.json({ data: catalogInfo() });
  });

  router.post('/freeze', async (req, res, next) => {
    try {
      res.json({ data: await freeze(req, req.body ?? {}) });
    } catch (err) { fail(err, res, next); }
  });

  router.post('/unfreeze', async (req, res, next) => {
    try {
      const approval = await requestUnfreeze(req, req.body ?? {});
      res.status(202).json({ data: { approvalId: approval.id, status: 'pending_approval', expiresAt: approval.expiresAt } });
    } catch (err) { fail(err, res, next); }
  });

  router.get('/settings', async (req, res, next) => {
    try {
      res.json({ data: settingsToDto(await readSettings(req.tenantId!)) });
    } catch (err) { next(err); }
  });

  router.put('/settings', async (req, res, next) => {
    try {
      const approval = await requestSettings(req, req.body);
      if (!approval) { res.json({ data: settingsToDto(await readSettings(req.tenantId!)) }); return; }
      res.status(202).json({ data: { approvalId: approval.id, status: 'pending_approval', expiresAt: approval.expiresAt } });
    } catch (err) { fail(err, res, next); }
  });

  router.get('/approvers', requireGuardReader, async (req, res, next) => {
    try {
      res.json({ data: await listApprovers(req.tenantId!) });
    } catch (err) { next(err); }
  });

  router.post('/approvers', async (req, res, next) => {
    try {
      const approval = await requestDesignation(req, req.body);
      res.status(202).json({ data: { approvalId: approval.id, status: 'pending_approval', expiresAt: approval.expiresAt } });
    } catch (err) { fail(err, res, next); }
  });

  router.delete('/approvers/:id', async (req, res, next) => {
    try {
      await revokeDesignation(req, req.params.id);
      res.status(204).send();
    } catch (err) { fail(err, res, next); }
  });

  return router;
}
