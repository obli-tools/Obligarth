import type { McpPerimeterMode, McpScope, TenantCapability } from '@obligarth/shared';
import { asTenant, userActor } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';

// =============================================================================
// Who calls the MCP server (docs: specs mcp-server §3.2 step 9, §3.3): the key
// says WHO (the human who owns it); what that human may do is worked out on
// every call, in each tenant, with the console's own functions. There is no
// session on /mcp: the caller travels explicitly to every tool, and every
// database access of a tool runs in asTenant(T, userActor(U)) for the tenant
// the tool names. Never a global view.
// =============================================================================

export interface McpKeyInfo {
  /** access_keys.id (uuid). */
  rowId: string;
  publicId: string;
  name: string;
  scopes: McpScope[];
  tenantMode: McpPerimeterMode;
  groupMode: McpPerimeterMode;
  deviceMode: McpPerimeterMode;
  ipAllow: string[];
  expiresAt: Date;
  credentialVersion: number;
}

export interface McpTarget {
  kind: 'tenant' | 'group' | 'device' | 'tenant_excluded';
  tenantId: number;
  refId: number | null;
}

export interface EffectiveTenant {
  id: number;
  name: string;
  /** The role in the tenant (permission set slug), or 'platform_admin' outside a membership. */
  role: string;
}

export interface EffectiveTenants {
  tenants: EffectiveTenant[];
  /** List mode only: listed tenants out of the perimeter now, with the reason (never a name). */
  outside: Array<{ tenantId: number; why: string }>;
}

export interface McpCaller {
  userId: number;
  username: string;
  isPlatformAdmin: boolean;
  isSso: boolean;
  key: McpKeyInfo;
  targets: McpTarget[];
  ip: string;
  requestId: string;
  /** Per JSON-RPC request memo (§4.4): the effective tenants are computed once per request, never across requests. */
  memo: { tenants?: Promise<EffectiveTenants> };
}

/** Rows of a kind of the key's perimeter in tenant T. */
export function targetIds(caller: Pick<McpCaller, 'targets'>, kind: 'group' | 'device', tenantId: number): number[] {
  return caller.targets.filter((t) => t.kind === kind && t.tenantId === tenantId && t.refId !== null).map((t) => Number(t.refId));
}

/** The effective tenants of the caller for this request (memoised on the caller object). */
export async function effectiveTenantsOf(caller: McpCaller): Promise<EffectiveTenants> {
  if (!caller.memo.tenants) {
    const { effectiveTenants } = await import('./perimeter');
    caller.memo.tenants = effectiveTenants(caller);
    caller.memo.tenants.catch(() => { caller.memo.tenants = undefined; });
  }
  return caller.memo.tenants;
}

/** A tenant outside the perimeter answers like an unknown one. */
export function tenantNotInPerimeter(): AppError {
  return new AppError(404, 'Tenant not found', 'tenantNotInPerimeter');
}

/**
 * Runs fn in tenant T as the human (§3.3): T must be in the effective tenants now; the database context is the
 * tenant's, actor u:<owner>. No implicit switch of anything.
 */
export async function withTenant<T>(caller: McpCaller, tenantId: number, fn: () => Promise<T>): Promise<T> {
  const t = Number(tenantId);
  if (!Number.isSafeInteger(t) || t <= 0) throw tenantNotInPerimeter();
  const eff = await effectiveTenantsOf(caller);
  if (!eff.tenants.some((x) => x.id === t)) throw tenantNotInPerimeter();
  return asTenant(t, userActor(caller.userId), fn);
}

/** The tenant capability the human holds in T (a platform administrator passes, as rbac.ts). */
export async function holdsTenantCapability(caller: Pick<McpCaller, 'userId' | 'isPlatformAdmin'>, tenantId: number,
  capability: TenantCapability): Promise<boolean> {
  if (caller.isPlatformAdmin) return true;
  return permissionService.userHasTenantCapability(caller.userId, tenantId, capability);
}

/**
 * The scope is on the key, and the human meets its tenant need in T now (§1.3). Inside withTenant. `need`:
 * 'membership' (already proven by the effective tenants) or a tenant capability.
 */
export async function requireScope(caller: McpCaller, tenantId: number, scope: McpScope,
  need: 'membership' | TenantCapability = 'membership'): Promise<void> {
  if (!caller.key.scopes.includes(scope)) {
    throw new AppError(403, `This access key does not carry the scope ${scope}`, 'scopeNotOnKey', { scope });
  }
  if (need !== 'membership' && !(await holdsTenantCapability(caller, tenantId, need))) {
    throw new AppError(403, `Capability '${need}' not held in this tenant`, 'capabilityMissing', { capability: need });
  }
}
