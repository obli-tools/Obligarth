import type { Request } from 'express';
import type { User } from '@obliance/shared';
import { db } from '../db';
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
//    platform admin only acts on an account it dominates;
//  - only a platform admin creates an administrator or changes a platform
//    role; SSO (Obligate) accounts are managed from Obligate; the last
//    active administrator is never demoted, disabled or deleted; one's own
//    account is never deleted.
// `ctx.req`: the caller's request (audit with its tenant and IP). Without it
// (approval): audited as `actor.userId` in `ctx.auditTenantId`, flagged
// `viaApproval`.

export type UserAdminCtx = { req?: Request; auditTenantId?: number };

async function audit(actor: ScopeActor, ctx: UserAdminCtx, action: string, targetId: number, details: Record<string, unknown>): Promise<void> {
  try {
    const { auditService } = await import('./audit.service');
    if (ctx.req) {
      await auditService.logReq(ctx.req, action, { resourceType: 'user', resourcePath: String(targetId), details });
    } else {
      await auditService.log({
        tenantId: ctx.auditTenantId ?? actor.tenantId,
        userId: actor.userId,
        action,
        resourceType: 'user',
        resourcePath: String(targetId),
        details: { ...details, viaApproval: true },
      });
    }
  } catch { /* the audit never breaks the action */ }
}

async function otherActiveAdmins(exceptId: number): Promise<number> {
  const row = await db('users').where({ role: 'admin', is_active: true }).whereNot({ id: exceptId })
    .count('* as n').first() as { n: string | number } | undefined;
  return Number(row?.n ?? 0);
}

/** Same comparison as the sign-in and the `users.username` unique index. */
export async function usernameTaken(username: string): Promise<boolean> {
  const row = await db('users').where({ username }).first('id');
  return !!row;
}

/**
 * New local account. `passwordHash` is a bcrypt hash (utils/crypto
 * hashPassword): an approval only ever keeps the hash, never the password.
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
  if (await usernameTaken(data.username)) throw new AppError(409, 'Username already exists');
  let user: User;
  try {
    user = await userService.createWithPasswordHash({
      username: data.username,
      passwordHash,
      displayName: data.displayName ?? null,
      role: data.role ?? 'user',
    });
  } catch (err) {
    if (err instanceof Error && /unique/i.test(err.message)) throw new AppError(409, 'Username already exists');
    throw err;
  }
  await audit(actor, ctx, 'user.created', user.id, { username: user.username, role: user.role });
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

  const user = await userService.update(targetId, data);
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
      await tfaTrustService.revokeAllForUser(targetId);
      // P6 / §6.7: a disabled account's phone keys are revoked.
      try {
        const { deviceKeyService } = await import('./deviceKey/deviceKey.service');
        await deviceKeyService.revokeAllForUser(targetId, 'user_disabled', {
          byUserId: actor.userId, req: ctx.req, auditTenantId: ctx.req ? undefined : (ctx.auditTenantId ?? actor.tenantId),
        });
      } catch { /* trigger */ }
    }
  }
  const roleChanged = data.role !== undefined && data.role !== scoped.role;
  await audit(actor, ctx, roleChanged ? 'user.role_changed' : 'user.updated', targetId, {
    username: user.username,
    before: { role: scoped.role, isActive: scoped.is_active },
    after: { role: user.role, isActive: user.isActive },
  });
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
  const deleted = await userService.delete(targetId);
  if (!deleted) throw new AppError(404, 'User not found');
  // P6: a deleted user's sessions would keep their role (admin bypasses).
  const { forgetSessionUser } = await import('../middleware/sessionUserGuard');
  forgetSessionUser(targetId);
  const { killSessionsForUser } = await import('./userSessions.service');
  await killSessionsForUser(targetId, 'user_deleted');
  await audit(actor, ctx, 'user.deleted', targetId, { username: scoped.username });
}
