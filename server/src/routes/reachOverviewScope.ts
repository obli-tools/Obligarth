import { MASTER_TENANT_ID } from '@obliance/shared';
import { AppError } from '../middleware/errorHandler';

/**
 * The tenants GET /reach/overview lists when the Oblireach Desktop asks for
 * them (?tenantId=<id> or ?tenantId=all, its multi-server mode): the union of
 * what the same user already gets today by POST /api/tenant/switch followed by
 * GET /reach/overview, never more.
 *
 *   - all: true  = the god view (every tenant), as after a switch to the
 *                  master tenant: platform admins only.
 *   - tenantIds  = those tenants only.
 */
export type OverviewScope = { all: true } | { all: false; tenantIds: number[] };

/** Lookups injected by the route (pure function: testable without a DB). */
export interface ScopeDeps {
  tenantExists(id: number): Promise<boolean>;
  userTenantIds(userId: number): Promise<number[]>;
}

export interface ScopeCtx {
  userId: number;
  /** req.session.role === 'admin' (a platform admin: may switch to any tenant). */
  isAdmin: boolean;
  /** The session's current tenant: what the overview already lists without the parameter. */
  currentTenantId: number;
}

const MAX_TENANT_ID = 2147483647;

/**
 * ?tenantId= of GET /reach/overview. null: absent (the legacy behaviour,
 * unchanged). Throws AppError (400 malformed, 404 unknown tenant for an
 * admin, 403 a tenant a non-admin has no access to: the switch route's text).
 *
 * Mirrors /api/tenant/switch (tenant.routes.ts): platform admins may reach any
 * tenant (the master one = the god view), other users only their own
 * (user_tenants) or the tenant their session is already on. A non-admin never
 * gets the god view, even on the master tenant (only its own devices).
 */
export async function resolveOverviewScope(raw: unknown, ctx: ScopeCtx, deps: ScopeDeps): Promise<OverviewScope | null> {
  if (raw === undefined || raw === '') return null;
  // One value only: an array (?tenantId=1&tenantId=2) or an object is refused.
  if (typeof raw !== 'string') throw new AppError(400, 'Invalid tenantId');
  const own = async (): Promise<number[]> => {
    const ids = (await deps.userTenantIds(ctx.userId)).map(Number).filter((n) => Number.isInteger(n) && n > 0);
    if (Number.isInteger(ctx.currentTenantId) && ctx.currentTenantId > 0) ids.push(ctx.currentTenantId);
    return [...new Set(ids)].sort((a, b) => a - b);
  };
  if (raw === 'all') {
    if (ctx.isAdmin) return { all: true };
    return { all: false, tenantIds: await own() };
  }
  if (!/^[1-9][0-9]{0,9}$/.test(raw)) throw new AppError(400, 'Invalid tenantId');
  const id = Number(raw);
  if (id > MAX_TENANT_ID) throw new AppError(400, 'Invalid tenantId');
  if (ctx.isAdmin) {
    if (!(await deps.tenantExists(id))) throw new AppError(404, 'Tenant not found');
    return id === MASTER_TENANT_ID ? { all: true } : { all: false, tenantIds: [id] };
  }
  if (!(await own()).includes(id)) throw new AppError(403, 'Access denied to this tenant');
  return { all: false, tenantIds: [id] };
}
