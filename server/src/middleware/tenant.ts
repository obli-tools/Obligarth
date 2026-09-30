import type { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';
import { tenantService, noTenantAccessError } from '../services/tenant.service';

// Extend Express.Request to carry the resolved tenantId
declare global {
  namespace Express {
    interface Request {
      tenantId: number;
    }
  }
}

/** A session's tenant id, or null. */
function sessionTenantId(req: Request): number | null {
  const tid = Number(req.session?.currentTenantId);
  return Number.isInteger(tid) && tid > 0 ? tid : null;
}

/**
 * Resolves req.tenantId from the session.
 * Must be applied after requireAuth on all routes that operate on tenant-scoped data.
 *
 * Membership is re-checked on every request (cached a few seconds,
 * tenantService.isMemberCached): a session that is not a platform admin's
 * only acts in a tenant its user still belongs to. Removing a user from a
 * tenant ends its sessions too, but a session left on that tenant by any
 * other path (another server process, a membership removed in the database,
 * a request in flight that saved its session back) is refused here — 403,
 * never a silent switch to another tenant, which would apply the request to
 * that tenant's data. Platform admins have access to every tenant.
 */
export async function requireTenant(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    const tid = sessionTenantId(req);
    if (!tid) {
      next(new AppError(400, 'No tenant selected'));
      return;
    }
    if (req.session.role !== 'admin') {
      const userId = Number(req.session.userId);
      if (!Number.isInteger(userId) || userId <= 0 || !(await tenantService.isMemberCached(userId, tid))) {
        next(new AppError(403, 'Access denied to this tenant', 'tenantAccessRevoked'));
        return;
      }
    }
    req.tenantId = tid;
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * For routers that are NOT mounted under the tenant router (/api/profile,
 * /api/profile/2fa, /api/profile/device-keys): exposes the session's current
 * tenant as req.tenantId, so the restriction envelope
 * (`tenant.manage_profile`), the "Trust this IP" duration and the audit log
 * all see a tenant (P4). These routes act on the user's own account, so a
 * session without a tenant (pre-tenant sessions), or left on a tenant its
 * user no longer belongs to, is repaired the way /auth/me does: the first
 * tenant the user belongs to. An account without any tenant is refused
 * (403): it never gets the master tenant it is not a member of, and cannot
 * sign in either.
 */
export async function attachSessionTenant(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = Number(req.session?.userId);
    if (Number.isInteger(userId) && userId > 0) {
      let tid = sessionTenantId(req);
      if (tid && req.session.role !== 'admin' && !(await tenantService.isMemberCached(userId, tid))) tid = null;
      if (!tid) {
        tid = await tenantService.sessionTenantFor(userId, req.session.role);
        if (!tid) {
          next(noTenantAccessError());
          return;
        }
        req.session.currentTenantId = tid;
      }
      req.tenantId = tid;
    }
    next();
  } catch (err) {
    next(err);
  }
}
