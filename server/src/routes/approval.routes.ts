import { Router, type NextFunction, type Request, type Response } from 'express';
import { db } from '../db';
import { requireAuth } from '../middleware/auth';
import { ApprovalStepUpError, approvalService } from '../services/approval.service';
import { permissionService } from '../services/permission.service';
import { hasGlobalView } from '../services/deviceScope.service';
import { sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { AppError } from '../middleware/errorHandler';
import { globalViewScope } from '../middleware/dbContext';
import { audit } from '../audit';

const router = Router();

declare global {
  namespace Express {
    interface Request {
      /** requireApprovalAccess: 'review' (platform administrator, or holder of
       *  approvals.review in the tenant) or 'own' (the member's own requests). */
      approvalAccess?: 'review' | 'own';
    }
  }
}

/**
 * Access to the approvals (audit-durci §10.4): a platform administrator, or a
 * holder of approvals.review in the tenant, reviews the tenant's requests;
 * any other member of the tenant sees and cancels its own requests only.
 * Who may approve or deny a request is decided by the policy of its type
 * (approval.service, checkReviewer): a platform administrator for the
 * inherited types, the guard's examination policy for the guarded actions.
 */
export async function requireApprovalAccess(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    if (req.session.role === 'admin') { req.approvalAccess = 'review'; next(); return; }
    const tenantId = Number(req.tenantId);
    const userId = Number(req.session.userId);
    // A designated approver of the tenant (audit-durci §10.4) reviews too:
    // the designation is the right to examine the guard's requests.
    const reviewer = Number.isSafeInteger(tenantId) && tenantId > 0
      && (await permissionService.userHasTenantCapability(userId, tenantId, 'approvals.review')
        || !!(await db('tenant_approvers').where({ tenant_id: tenantId, user_id: userId }).whereNull('revoked_at').first('id')));
    req.approvalAccess = reviewer ? 'review' : 'own';
    next();
  } catch (err) {
    next(err);
  }
}

router.use(requireAuth, requireApprovalAccess);

/** An error of the approval service: its status and code, else the error handler. */
function serviceError(err: any, res: Response, next: NextFunction): void {
  if (err instanceof ApprovalStepUpError) { sendStepUpFailure(res, err.outcome); return; }
  if (err?.status) { next(new AppError(err.status, err.message, err.code)); return; }
  next(err);
}

// List pending (default) or all approvals: the tenant's for a reviewer (the
// master tenant's global view lists every tenant's: context 'platform'), the
// member's own requests otherwise.
router.get('/', globalViewScope('console.approvals'), async (req, res, next) => {
  try {
    const includeResolved = req.query.includeResolved === 'true';
    const limit = Math.min(200, Math.max(1, parseInt((req.query.limit as string) || '50', 10) || 50));
    const own = req.approvalAccess !== 'review';
    const items = await approvalService.list(req.tenantId!, {
      includeResolved, limit, globalView: hasGlobalView(req),
      ...(own ? { requesterId: Number(req.session.userId) } : {}),
    });
    res.json({ data: items });
  } catch (err) { next(err); }
});

// Approve a pending request. Body: { reason?: string } (and the reviewer's
// second-factor proof when the request's type asks one).
router.post('/:id/approve', async (req, res, next) => {
  try {
    if (req.approvalAccess !== 'review') throw new AppError(403, 'Insufficient permissions');
    const id = parseInt(req.params.id, 10);
    const approved = await approvalService.approve({
      tenantId: req.tenantId!,
      approvalId: id,
      reviewerId: req.session.userId!,
      reason: typeof req.body?.reason === 'string' ? req.body.reason : undefined,
      req,
    });
    res.json({ data: approved });
  } catch (err: any) {
    serviceError(err, res, next);
  }
});

// Deny a pending request. Body: { reason?: string }
router.post('/:id/deny', async (req, res, next) => {
  try {
    if (req.approvalAccess !== 'review') throw new AppError(403, 'Insufficient permissions');
    const id = parseInt(req.params.id, 10);
    const denied = await approvalService.deny({
      tenantId: req.tenantId!,
      approvalId: id,
      reviewerId: req.session.userId!,
      reason: typeof req.body?.reason === 'string' ? req.body.reason : undefined,
      auditCtx: await audit.fromRequest(req, req.tenantId!),
    });
    res.json({ data: denied });
  } catch (err: any) {
    serviceError(err, res, next);
  }
});

// Requester cancels their own pending request.
router.post('/:id/cancel', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const cancelled = await approvalService.cancel({
      tenantId: req.tenantId!,
      approvalId: id,
      userId: req.session.userId!,
      auditCtx: await audit.fromRequest(req, req.tenantId!),
    });
    res.json({ data: cancelled });
  } catch (err: any) {
    serviceError(err, res, next);
  }
});

export default router;
