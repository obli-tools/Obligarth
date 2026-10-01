import type { Request } from 'express';
import { knownTenantCapabilities } from '@obligarth/shared';
import { db } from '../db';
import { switchToIdentity } from '../db/context';
import { AppError } from '../middleware/errorHandler';

// ── Scope of `users.manage` (P1, docs/mobile/device-bound-2fa.md §6.0) ─────
//
// /api/users is gated by the tenant capability `users.manage`. Password,
// 2FA, activity and deletion act on the GLOBAL account, so a holder that is
// not a platform admin may only act on an account it fully dominates:
//   - never a platform admin (users.role = 'admin');
//   - a member of the caller's current tenant;
//   - in EVERY tenant the account belongs to:
//       · a tenant administrator (user_tenants.role = 'admin') only if the
//         caller is tenant administrator there too;
//       · otherwise the caller holds `users.manage` there AND every
//         capability of the account's permission set there (taking over an
//         account must never widen the caller's rights).
// Platform admins (session role 'admin') may target anyone.
//
// The same rules are re-run by the approval executor (approval.service.ts)
// as the REQUESTER, because rights may change while a request waits.
//
// Database context (rls-tenant §8.2): the checks read the GLOBAL account and
// ALL its memberships (a tenant context would only show the current
// tenant's rows, and a check that does not see a membership would pass):
// every read of this file runs in the identity context, the caller's actor
// kept. The writes that follow are made by the callers, in identity too.

export type ScopeActor = { userId: number; isPlatformAdmin: boolean; tenantId: number };
export type ManagedTarget = {
  id: number; username: string; role: string; is_active: boolean; foreign_source: string | null;
};
export type TenantAssignment = { tenantId: number; role: string };

export function actorFromReq(req: Request): ScopeActor {
  return {
    userId: Number(req.session.userId),
    isPlatformAdmin: req.session.role === 'admin',
    tenantId: Number((req as any).tenantId),
  };
}

/** Pre-091 tenant role 'member' is the 'user' permission set (migration 091
 *  backfilled it; the tenant panel kept writing it — an orphan slug gives no
 *  capability at all). */
export function normaliseTenantRole(role: unknown): string {
  const r = String(role ?? '').trim();
  return r === '' || r === 'member' ? 'user' : r;
}

type Caps = { all: true } | { all: false; set: Set<string> };

/** Capabilities of a tenant role. Stored values outside the shared
 *  vocabulary grant nothing (userHasTenantCapability), so they are not
 *  compared either. */
async function capsOfRole(role: string): Promise<Caps | null> {
  if (role === 'admin') return { all: true };
  const row = await db('permission_sets').where({ slug: role }).first('capabilities') as { capabilities: unknown } | undefined;
  if (!row) return null; // unknown slug: no capability (userHasTenantCapability)
  return { all: false, set: new Set<string>(knownTenantCapabilities(row.capabilities)) };
}

async function membershipRole(userId: number, tenantId: number): Promise<string | null> {
  const row = await db('user_tenants').where({ user_id: userId, tenant_id: tenantId }).first('role') as { role: string } | undefined;
  return row ? normaliseTenantRole(row.role) : null;
}

/**
 * Can `actor` (not a platform admin) manage an account whose role in
 * `tenantId` is `targetRole`? Returns the refusal text, or null when allowed.
 */
async function refusalFor(actor: ScopeActor, tenantId: number, targetRole: string): Promise<string | null> {
  const callerRole = await membershipRole(actor.userId, tenantId);
  if (callerRole === 'admin') return null; // tenant admin: every capability there
  if (targetRole === 'admin') {
    return "Only an administrator of each of this user's tenants can manage a tenant administrator";
  }
  const callerCaps = callerRole ? await capsOfRole(callerRole) : null;
  if (callerCaps?.all) return null;
  if (!callerCaps || !callerCaps.set.has('users.manage')) {
    return 'This user also belongs to a tenant where you cannot manage users';
  }
  const targetCaps = await capsOfRole(targetRole);
  if (targetCaps?.all) return 'This user has permissions you do not hold';
  for (const cap of targetCaps?.set ?? []) {
    if (!callerCaps.set.has(cap)) return 'This user has permissions you do not hold';
  }
  return null;
}

export const userScope = {
  /** Write access (password / 2FA reset, edit, enable/disable, delete,
   *  tenant access). Throws 400 / 403 / 404 (AppError). */
  async assertManageableTarget(actor: ScopeActor, targetId: number): Promise<ManagedTarget> {
    return switchToIdentity(() => assertManageableTargetIn(actor, targetId));
  },

  /** Read access (GET /users/:id, /:id/tenants, /:id/teams): every account
   *  for a platform admin; members of the current tenant otherwise — the
   *  master tenant included: its tenant administrators who are not platform
   *  admins get no global view (GET /users lists the same population). 404
   *  outside. */
  async assertReadableTarget(actor: ScopeActor, targetId: number): Promise<void> {
    if (!Number.isInteger(targetId) || targetId <= 0) throw new AppError(400, 'Invalid user id');
    if (actor.isPlatformAdmin) return;
    const member = await switchToIdentity(() => db('user_tenants').where({ user_id: targetId, tenant_id: actor.tenantId }).first('user_id'));
    if (!member) throw new AppError(404, 'User not found');
  },

  /**
   * Resolves PUT /users/:id/tenants into the full list of memberships to
   * store. Platform admin: the list as sent ('member' read as 'user').
   * Other managers: only the CURRENT tenant's row may change (add a role,
   * change it, or remove it); every other membership is kept as it is —
   * absent from the list or repeated unchanged, never altered.
   */
  async resolveTenantAssignments(actor: ScopeActor, targetId: number, assignments: unknown): Promise<TenantAssignment[]> {
    return switchToIdentity(() => resolveTenantAssignmentsIn(actor, targetId, assignments));
  },

  /**
   * May `actor` (not a platform admin) give `role` in `tenantId`? The tenant
   * administrator role only by a tenant administrator there; a permission set
   * only if the caller holds every capability of it there (granting must
   * never widen the caller's rights). Throws 400 (unknown role) or 403.
   */
  async assertGrantableRole(actor: ScopeActor, tenantId: number, role: string): Promise<void> {
    return switchToIdentity(() => assertGrantableRoleIn(actor, tenantId, role));
  },

};

async function assertManageableTargetIn(actor: ScopeActor, targetId: number): Promise<ManagedTarget> {
  if (!Number.isInteger(targetId) || targetId <= 0) throw new AppError(400, 'Invalid user id');
  const target = await db('users').where({ id: targetId })
    .first('id', 'username', 'role', 'is_active', 'foreign_source') as ManagedTarget | undefined;
  if (!target) throw new AppError(404, 'User not found');
  if (actor.isPlatformAdmin) return target;
  // Outside the current tenant, an account answers like an unknown one
  // (404) before anything else is said about it (a platform admin, say).
  const rows = await db('user_tenants').where({ user_id: targetId }).select('tenant_id', 'role') as Array<{ tenant_id: number; role: string }>;
  if (!rows.some((r) => Number(r.tenant_id) === actor.tenantId)) throw new AppError(404, 'User not found');
  if (target.role === 'admin') {
    throw new AppError(403, 'Only a platform administrator can manage an administrator account');
  }
  for (const r of rows) {
    const refusal = await refusalFor(actor, Number(r.tenant_id), normaliseTenantRole(r.role));
    if (refusal) throw new AppError(403, refusal);
  }
  return target;
}

async function resolveTenantAssignmentsIn(actor: ScopeActor, targetId: number, assignments: unknown): Promise<TenantAssignment[]> {
  if (!Array.isArray(assignments)) throw new AppError(400, 'assignments must be an array');
  const wanted: TenantAssignment[] = [];
  const seen = new Set<number>();
  for (const a of assignments as Array<{ tenantId?: unknown; role?: unknown }>) {
    const tenantId = Number(a?.tenantId);
    if (!Number.isInteger(tenantId) || tenantId <= 0) throw new AppError(400, 'Invalid tenant id');
    if (seen.has(tenantId)) throw new AppError(400, 'Duplicate tenant in assignments');
    seen.add(tenantId);
    wanted.push({ tenantId, role: normaliseTenantRole(a?.role) });
  }
  if (actor.isPlatformAdmin) return wanted;

  if (targetId === actor.userId) throw new AppError(403, 'You cannot change your own tenant access');
  await assertManageableTargetIn(actor, targetId); // member of the current tenant, dominated everywhere

  const current = (await db('user_tenants').where({ user_id: targetId }).select('tenant_id', 'role') as Array<{ tenant_id: number; role: string }>)
    .map((r) => ({ tenantId: Number(r.tenant_id), role: normaliseTenantRole(r.role) }));
  const kept = current.filter((r) => r.tenantId !== actor.tenantId);
  for (const w of wanted) {
    if (w.tenantId === actor.tenantId) continue;
    const same = kept.find((k) => k.tenantId === w.tenantId);
    if (!same || same.role !== w.role) throw new AppError(403, 'You can only change access to the current tenant');
  }

  const next = wanted.find((w) => w.tenantId === actor.tenantId);
  if (next) await assertGrantableRoleIn(actor, actor.tenantId, next.role);
  return next ? [...kept, next] : kept;
}

async function assertGrantableRoleIn(actor: ScopeActor, tenantId: number, role: string): Promise<void> {
  if (actor.isPlatformAdmin) return;
  if (role === 'admin') {
    if ((await membershipRole(actor.userId, tenantId)) !== 'admin') {
      throw new AppError(403, 'Only a tenant administrator can grant the tenant administrator role');
    }
    return;
  }
  if (!(await capsOfRole(role))) throw new AppError(400, `Unknown role: ${role}`);
  const refusal = await refusalFor(actor, tenantId, role);
  if (refusal) throw new AppError(403, 'You can only grant a role whose permissions you hold');
}

/** Admin MFA reset: removes every local second factor, lifts the code lock
 *  (§6.8), drops the IP trusts that rested on the removed factor and revokes
 *  the account's phone keys ('totp_reset', §6.7). `byUserId`: the
 *  administrator (the approval requester when executed from an approval).
 *  `ctx.req` (the administrator's request) or, from an approval,
 *  `ctx.auditTenantId`: the revocation is audited under the administrator,
 *  in their tenant (never under the target user / the master tenant). */
export async function resetSecondFactors(
  userId: number,
  byUserId?: number,
  ctx: { req?: Request; auditTenantId?: number | null } = {},
): Promise<boolean> {
  // Another account's factors, code lock and trusts: the identity context.
  return switchToIdentity(() => resetSecondFactorsIn(userId, byUserId, ctx));
}

async function resetSecondFactorsIn(
  userId: number,
  byUserId: number | undefined,
  ctx: { req?: Request; auditTenantId?: number | null },
): Promise<boolean> {
  const count = await db('users').where({ id: userId }).update({
    totp_secret_enc: null,
    totp_secret: null,          // inherited clear column (emptied by the vault's backfill)
    totp_enabled: false,
    email_otp_enabled: false,
    updated_at: new Date(),
  });
  if (!count) return false;
  const { clearCodeThrottle } = await import('./deviceKey/stepUpProof');
  await clearCodeThrottle(userId);
  const { tfaTrustService } = await import('./tfaTrust.service');
  await tfaTrustService.revokeAllForUser(userId);
  try {
    const { deviceKeyService } = await import('./deviceKey/deviceKey.service');
    await deviceKeyService.revokeAllForUser(userId, 'totp_reset', {
      byUserId: byUserId ?? null, req: ctx.req, auditTenantId: ctx.auditTenantId ?? null,
    });
  } catch { /* the credential-version trigger remains the safety net */ }
  return true;
}
