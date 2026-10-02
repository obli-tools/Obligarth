import type { Request } from 'express';
import type { Knex } from 'knex';
import type { User } from '@obligarth/shared';
import { db } from '../db';
import { switchToIdentity, userActor } from '../db/context';
import { audit as journal, type AuditEntryInput, type AuditWriteContext } from '../audit';
import { currentApprovalIds } from './approvalContext';
import { AppError } from '../middleware/errorHandler';
import { userService } from './user.service';
import { userScope, type ScopeActor } from './userScope.service';
import { createUserSchema, updateUserSchema, type UpdateUserInput } from '../validators/user.schema';

// ── Create / update / delete a user account (tenant.manage_users) ──────────
//
// ONE implementation for the direct route (users.controller.ts) and for an
// approved request (approval.service.ts, executed AS THE REQUESTER when a
// second administrator approves it). Every rule is (re-)checked here at
// execution time — rights, scope and accounts may have changed while the
// request waited:
//  - P1 scope (userScope.assertManageableTarget): a manager that is not a
//    platform admin only acts on an account it dominates, and an account it
//    creates joins its tenant with a role it can grant (newAccountTenant);
//  - only a platform admin creates an administrator or changes a platform
//    role; SSO (Obligate) accounts are managed from Obligate; the last
//    active administrator is never demoted, disabled or deleted; one's own
//    account is never deleted.
// `ctx.req`: the caller's request (audit with its tenant and IP). Without it
// (approval): audited as `actor.userId` in `ctx.auditTenantId`, flagged
// `viaApproval`.
// Database context (rls-tenant §8.2): accounts and memberships are identity
// rows, read and written in the identity context (the caller's actor kept),
// after the P1 checks; the audit goes to the caller's tenant.

export type UserAdminCtx = { req?: Request; auditTenantId?: number };

/** The chain and context of an account change: the request's tenant, or
 *  (approval) the approval's tenant as the requester, naming the approval. */
async function auditTarget(actor: ScopeActor, ctx: UserAdminCtx): Promise<{ tenantId: number; wctx: AuditWriteContext; viaApproval: boolean }> {
  if (ctx.req) {
    const tenantId = Number(ctx.req.tenantId) || actor.tenantId;
    return { tenantId, wctx: await journal.fromRequest(ctx.req, tenantId), viaApproval: false };
  }
  const tenantId = ctx.auditTenantId ?? actor.tenantId;
  return { tenantId, wctx: await journal.fromDbActor(userActor(actor.userId), tenantId), viaApproval: true };
}

function accountEntry(tenantId: number, action: string, targetId: number, details: Record<string, unknown>, viaApproval: boolean): AuditEntryInput {
  return {
    tenantId, action, target: { type: 'user', id: String(targetId) },
    approvalIds: viaApproval ? currentApprovalIds() : undefined,
    details: viaApproval ? { ...details, viaApproval: true } : details,
  };
}

/** P3 / P4: a standard or protective account change, after the fact; never
 *  throws (the writer spools a failure). */
async function audit(actor: ScopeActor, ctx: UserAdminCtx, action: string, targetId: number, details: Record<string, unknown>): Promise<void> {
  try {
    const t = await auditTarget(actor, ctx);
    await journal.append(accountEntry(t.tenantId, action, targetId, details, t.viaApproval), t.wctx);
  } catch { /* the writer logged it */ }
}

/** P1: the entry in the transaction of the change (critical when asked). */
async function auditInTx(trx: Knex.Transaction, actor: ScopeActor, ctx: UserAdminCtx, action: string, targetId: number,
  details: Record<string, unknown>, critical: boolean): Promise<void> {
  const t = await auditTarget(actor, ctx);
  await journal.appendInTx(trx, accountEntry(t.tenantId, action, targetId, details, t.viaApproval), t.wctx,
    critical ? { criticality: 'critical' } : {});
}

/** P2: a critical account change (the intent before `fn`). */
async function withAccountIntent<T>(actor: ScopeActor, ctx: UserAdminCtx, action: string, targetId: number,
  details: Record<string, unknown>, fn: () => Promise<T>): Promise<T> {
  const t = await auditTarget(actor, ctx);
  return journal.withIntent(accountEntry(t.tenantId, action, targetId, details, t.viaApproval), t.wctx, fn);
}

async function otherActiveAdmins(exceptId: number): Promise<number> {
  const row = await switchToIdentity(() => db('users').where({ role: 'admin', is_active: true }).whereNot({ id: exceptId })
    .count('* as n').first()) as { n: string | number } | undefined;
  return Number(row?.n ?? 0);
}

/** Same comparison as the sign-in and the `users.username` unique index. */
export async function usernameTaken(username: string): Promise<boolean> {
  const row = await switchToIdentity(() => db('users').where({ username }).first('id'));
  return !!row;
}

/** Tenant role a new account receives in its creator's tenant. */
export const NEW_ACCOUNT_TENANT_ROLE = 'user';

/**
 * The tenant a new account joins: a creator that is not a platform
 * administrator (a tenant administrator, or a holder of users.manage) can
 * only see and manage the members of its tenant, so the account joins it,
 * with the role NEW_ACCOUNT_TENANT_ROLE, which the creator must be able to
 * grant (userScope.assertGrantableRole). A platform administrator assigns
 * the tenants afterwards (PUT /api/users/:id/tenants): null.
 */
export async function newAccountTenant(actor: ScopeActor): Promise<number | null> {
  if (actor.isPlatformAdmin) return null;
  if (!Number.isInteger(actor.tenantId) || actor.tenantId <= 0) throw new AppError(400, 'No tenant selected');
  await userScope.assertGrantableRole(actor, actor.tenantId, NEW_ACCOUNT_TENANT_ROLE);
  return actor.tenantId;
}

/**
 * New local account. `passwordHash` is a bcrypt hash (utils/crypto
 * hashPassword): an approval only ever keeps the hash, never the password.
 * Created by a manager that is not a platform administrator, the account
 * joins the manager's tenant in the same transaction (newAccountTenant):
 * without it, it was invisible to its creator and could not sign in.
 */
export async function createUserAccount(
  actor: ScopeActor,
  input: { username?: unknown; displayName?: unknown; role?: unknown },
  passwordHash: string,
  ctx: UserAdminCtx = {},
): Promise<User> {
  const parsed = createUserSchema.omit({ password: true }).safeParse({
    username: input.username,
    displayName: input.displayName,
    role: input.role,
  });
  if (!parsed.success) throw new AppError(400, `Invalid user: ${parsed.error.errors.map((e) => e.message).join('; ')}`);
  const data = parsed.data;
  if (data.role === 'admin' && !actor.isPlatformAdmin) {
    throw new AppError(403, 'Only a platform administrator can create an administrator account');
  }
  if (typeof passwordHash !== 'string' || passwordHash.length < 20) {
    throw new AppError(400, 'The request carries no password hash — redo the creation');
  }
  const tenantId = await newAccountTenant(actor);
  if (await usernameTaken(data.username)) throw new AppError(409, 'Username already exists');
  let user: User;
  try {
    user = await switchToIdentity(() => db.transaction(async (trx) => {
      const created = await userService.createWithPasswordHash({
        username: data.username,
        passwordHash,
        displayName: data.displayName ?? null,
        role: data.role ?? 'user',
      }, trx);
      if (tenantId !== null) {
        await trx('user_tenants').insert({ user_id: created.id, tenant_id: tenantId, role: NEW_ACCOUNT_TENANT_ROLE });
      }
      // P1, last statement: an administrator account is critical (§3.4).
      await auditInTx(trx, actor, ctx, 'user.created', created.id, {
        username: created.username,
        role: created.role,
        ...(tenantId !== null ? { tenantId, tenantRole: NEW_ACCOUNT_TENANT_ROLE } : {}),
      }, created.role === 'admin');
      return created;
    }));
  } catch (err) {
    if (err instanceof Error && /unique/i.test(err.message)) throw new AppError(409, 'Username already exists');
    throw err;
  }
  return user;
}

/** Edit (display name, platform role, active). */
export async function updateUserAccount(
  actor: ScopeActor,
  targetId: number,
  input: unknown,
  ctx: UserAdminCtx = {},
): Promise<User> {
  const parsed = updateUserSchema.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(400, `Invalid change: ${parsed.error.errors.map((e) => e.message).join('; ')}`);
  const data: UpdateUserInput = parsed.data;
  const scoped = await userScope.assertManageableTarget(actor, targetId);
  if (data.role !== undefined && data.role !== scoped.role && !actor.isPlatformAdmin) {
    throw new AppError(403, 'Only a platform administrator can change a user role');
  }
  if (scoped.foreign_source === 'obligate') {
    throw new AppError(400, 'Cannot modify SSO user — manage from Obligate');
  }
  // The last active administrator is never demoted nor disabled.
  if ((data.role === 'user' || data.isActive === false) && scoped.role === 'admin') {
    if ((await otherActiveAdmins(targetId)) === 0) throw new AppError(400, 'Cannot remove the last active admin');
  }

  const roleChanged = data.role !== undefined && data.role !== scoped.role;
  const detailsBefore = { username: scoped.username, before: { role: scoped.role, isActive: scoped.is_active } };
  // A platform role change is critical (P2): the intent before the change.
  // The intent names every change of the request (AUD-A6-R10: a role change
  // and a deactivation in one PUT left the deactivation out of the entry).
  const after = { role: data.role, ...(data.isActive !== undefined ? { isActive: data.isActive } : {}) };
  const user = roleChanged
    ? await withAccountIntent(actor, ctx, 'user.role_changed', targetId, { ...detailsBefore, after },
      () => switchToIdentity(() => userService.update(targetId, data)))
    : await switchToIdentity(() => userService.update(targetId, data));
  if (!user) throw new AppError(404, 'User not found');
  // P6: the session guard caches is_active / role for a few seconds; a
  // deactivated user's sessions (and a demoted admin's, whose session still
  // says 'admin') must die now.
  const { forgetSessionUser } = await import('../middleware/sessionUserGuard');
  forgetSessionUser(targetId);
  const demoted = scoped.role === 'admin' && user.role !== 'admin';
  if (data.isActive === false || demoted) {
    const { killSessionsForUser } = await import('./userSessions.service');
    await killSessionsForUser(targetId, data.isActive === false ? 'user_disabled' : 'role_demoted');
    if (data.isActive === false) {
      const { tfaTrustService } = await import('./tfaTrust.service');
      await switchToIdentity(() => tfaTrustService.revokeAllForUser(targetId));
      // P6 / §6.7: a disabled account's phone keys are revoked.
      try {
        const { deviceKeyService } = await import('./deviceKey/deviceKey.service');
        await deviceKeyService.revokeAllForUser(targetId, 'user_disabled', {
          byUserId: actor.userId, req: ctx.req, auditTenantId: ctx.req ? undefined : (ctx.auditTenantId ?? actor.tenantId),
        });
      } catch { /* trigger */ }
    }
  }
  if (!roleChanged) {
    // A deactivation is protective (P4), any other change standard (P3).
    const deactivated = data.isActive === false && scoped.is_active;
    await audit(actor, ctx, deactivated ? 'user.deactivated' : 'user.updated', targetId, {
      username: user.username,
      before: { role: scoped.role, isActive: scoped.is_active },
      after: { role: user.role, isActive: user.isActive },
    });
  }
  return user;
}

/** Deletion (never one's own account, never the last administrator). */
export async function deleteUserAccount(actor: ScopeActor, targetId: number, ctx: UserAdminCtx = {}): Promise<void> {
  if (targetId === actor.userId) throw new AppError(400, 'Cannot delete your own account');
  const scoped = await userScope.assertManageableTarget(actor, targetId);
  if (scoped.foreign_source === 'obligate') {
    throw new AppError(400, 'Cannot delete SSO user — manage from Obligate');
  }
  if (scoped.role === 'admin' && (await otherActiveAdmins(targetId)) === 0) {
    throw new AppError(400, 'Cannot delete the last admin');
  }
  const deleted = await switchToIdentity(() => userService.delete(targetId));
  if (!deleted) throw new AppError(404, 'User not found');
  // P6: a deleted user's sessions would keep their role (admin bypasses).
  const { forgetSessionUser } = await import('../middleware/sessionUserGuard');
  forgetSessionUser(targetId);
  const { killSessionsForUser } = await import('./userSessions.service');
  await killSessionsForUser(targetId, 'user_deleted');
  await audit(actor, ctx, 'user.deleted', targetId, { username: scoped.username });
}
