import type { Request, Response, NextFunction } from 'express';
import { userService } from '../services/user.service';
import { teamService } from '../services/team.service';
import { AppError } from '../middleware/errorHandler';
import { userScope, actorFromReq, resetSecondFactors } from '../services/userScope.service';
import {
  createUserAccount, updateUserAccount, deleteUserAccount, usernameTaken, newAccountTenant, NEW_ACCOUNT_TENANT_ROLE,
} from '../services/userAdmin.service';
import { hashPassword } from '../utils/crypto';
import { db } from '../db';
import { switchToIdentity } from '../db/context';
import { globalViewRead } from '../middleware/dbContext';
import { isMasterTenant } from '@obligarth/shared';
import type {
  CreateUserInput,
  UpdateUserInput,
  ChangePasswordInput,
} from '../validators/user.schema';

// ── P1: scope of `users.manage` ─────────────────────────────────────────────
// (docs/mobile/device-bound-2fa.md §6.0). The rules live in
// services/userScope.service.ts (shared with the approval executor): a holder
// that is not a platform admin (req.session.role !== 'admin') may only act on
// an account it fully dominates — never a platform admin, a member of the
// current tenant, and in EVERY tenant of the account: tenant admin only if
// the caller is tenant admin there, otherwise `users.manage` + every
// capability of the account's permission set there. It may never change a
// platform role, and may only change the current tenant's membership row.
// Password and 2FA resets of one's own account go through the profile
// (current password / current code), never through here.
//
// Database contexts (rls-tenant §8.2): a manager that is not a platform
// admin reads in the tenant context (the tenant's members); a platform admin
// reads every account in the identity context; every write to an account or
// a membership runs in the identity context, after the P1 checks.

function isPlatformAdmin(req: Request): boolean {
  return req.session.role === 'admin';
}

async function auditUserAction(req: Request, action: string, targetId: number, details: Record<string, unknown>): Promise<void> {
  try {
    const { auditService } = await import('../services/audit.service');
    await auditService.logReq(req, action, { resourceType: 'user', resourcePath: String(targetId), details });
  } catch {}
}

export const usersController = {
  // GET /api/users
  //
  // A platform admin on the default tenant (id=1) gets the "god view":
  // every user across the install — needed to bootstrap memberships,
  // audit access, etc. Anyone else — on a customer workspace, or a
  // tenant administrator of the default tenant who is not a platform
  // admin — only lists the users that actually have access to the current
  // tenant (i.e. own a row in `user_tenants` for it). This makes the
  // /admin/users page double as a "who can see this tenant?" glance card
  // and stops a Contoso admin from accidentally browsing ACME users.
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = Number(req.tenantId);
      if (!Number.isInteger(tenantId) || tenantId <= 0) throw new AppError(400, 'No tenant selected');
      const scopeAll = isPlatformAdmin(req) && isMasterTenant(tenantId);
      const users = scopeAll ? await switchToIdentity(() => userService.getAll(null)) : await userService.getAll(tenantId);
      res.json({ success: true, data: users });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/users/:id
  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      // Members of the current tenant; every account for a platform admin
      // (userScope.assertReadableTarget).
      await userScope.assertReadableTarget(actorFromReq(req), id);
      const user = isPlatformAdmin(req) ? await switchToIdentity(() => userService.getById(id)) : await userService.getById(id);
      if (!user) throw new AppError(404, 'User not found');
      res.json({ success: true, data: user });
    } catch (err) {
      next(err);
    }
  },

  // POST /api/users
  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = req.body as CreateUserInput;
      // P1: creating a platform admin is a platform-role change.
      if (data?.role === 'admin' && !isPlatformAdmin(req)) {
        throw new AppError(403, 'Only a platform administrator can create an administrator account');
      }
      if (await usernameTaken(data.username)) throw new AppError(409, 'Username already exists');
      // Outside the platform administrators, the account joins the
      // manager's tenant: refused now (role it cannot grant) rather than
      // after a second administrator approved it (checked again then).
      const joinsTenant = await newAccountTenant(actorFromReq(req));
      // The password is hashed NOW: at the 'restricted' level the approval
      // keeps only this bcrypt hash, in its sealed part (never returned by
      // the API, wiped once resolved) — never the password (approvalSecrets).
      const passwordHash = await hashPassword(data.password);
      const { applyRestriction } = await import('../services/restriction.service');
      const access = joinsTenant !== null
        ? `; tenant access: ${await (await import('../services/approvalDescribe')).tenantLabel(joinsTenant)} as "${NEW_ACCOUNT_TENANT_ROLE}"`
        : '';
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_users',
        approvalRequestType: 'batch_command',
        approvalDescription: `Create user "${data.username}" — display name: ${data.displayName ? `"${data.displayName}"` : 'none'}; platform role: ${data.role === 'admin' ? 'ADMINISTRATOR' : 'user'}${access}; password: set by the requester (never shown)`,
        approvalPayload: {
          action: 'user_create',
          body: { username: data.username, displayName: data.displayName ?? null, role: data.role ?? 'user' },
        },
        approvalSealed: { passwordHash },
      });
      if (!gated) return;

      // Same path as an approved creation (services/userAdmin.service.ts).
      const user = await createUserAccount(actorFromReq(req), data, passwordHash, { req });
      res.status(201).json({ success: true, data: user });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('unique')) {
        next(new AppError(409, 'Username already exists'));
      } else {
        next(err);
      }
    }
  },

  // PUT /api/users/:id
  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const data = req.body as UpdateUserInput;
      // P1: target scope, then platform role changes are admin-only (the
      // edit form always sends the current role: only a CHANGE is refused).
      const scoped = await userScope.assertManageableTarget(actorFromReq(req), id);
      if (data.role !== undefined && data.role !== scoped.role && !isPlatformAdmin(req)) {
        throw new AppError(403, 'Only a platform administrator can change a user role');
      }
      // Refused now rather than after a second administrator approved it
      // (updateUserAccount checks it again at execution).
      if (scoped.foreign_source === 'obligate') {
        throw new AppError(400, 'Cannot modify SSO user — manage from Obligate');
      }

      // The approval keeps the validated fields only, and says what changes
      // (the reviewer approves THIS, the executor applies exactly these).
      const body: Record<string, unknown> = {};
      for (const k of ['username', 'displayName', 'role', 'isActive'] as const) {
        if (data[k] !== undefined) body[k] = data[k];
      }
      const { change } = await import('../services/approvalDescribe');
      const cur = await switchToIdentity(() => db('users').where({ id }).first('username', 'display_name', 'role', 'is_active')) as
        { username: string; display_name: string | null; role: string; is_active: boolean } | undefined;
      const changes = [
        'username' in body ? change('username', cur?.username, body.username) : null,
        'displayName' in body ? change('display name', cur?.display_name ?? null, body.displayName) : null,
        'role' in body ? change('PLATFORM ROLE', cur?.role, body.role) : null,
        'isActive' in body ? change('active', cur?.is_active, body.isActive) : null,
      ].filter(Boolean);
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_users',
        approvalRequestType: 'batch_command',
        approvalDescription: `Update user "${scoped.username}" (#${id}) — ${changes.join('; ') || 'no change'}`,
        approvalPayload: { action: 'user_update', userId: id, body },
      });
      if (!gated) return;

      // Same path as an approved edit (services/userAdmin.service.ts): SSO
      // accounts refused, last active admin kept, sessions of a disabled or
      // demoted account killed (P6), audited.
      const user = await updateUserAccount(actorFromReq(req), id, data, { req });
      res.json({ success: true, data: user });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('unique')) {
        next(new AppError(409, 'Username already exists'));
      } else {
        next(err);
      }
    }
  },

  // PUT /api/users/:id/password
  async changePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      // One's own password changes through the profile (current password).
      if (id === req.session.userId) {
        throw new AppError(400, 'Use your profile to change your own password');
      }
      // P1: a non-admin manager may only reset an account it dominates.
      const target = await userScope.assertManageableTarget(actorFromReq(req), id);

      // Block password changes for SSO users
      if (target.foreign_source === 'obligate') {
        throw new AppError(400, 'Cannot modify SSO user — manage from Obligate');
      }

      // P1: through the tenant.manage_users envelope. A password must never
      // sit in an approval payload, and nothing could execute such an
      // approval: at the 'restricted' level a fresh step-up is asked instead
      // of a second administrator — always a code / the phone, never the
      // trusted-IP shortcut (the second person is replaced by a FRESH factor,
      // as for every secret-carrying action, restriction.service).
      const { restrictionService, applyRestriction } = await import('../services/restriction.service');
      const level = await restrictionService.getLevelFor({ tenantId: req.tenantId!, actionKey: 'tenant.manage_users' });
      if (level === 'restricted') {
        const { checkSecondFactor, sendStepUpFailure } = await import('../services/deviceKey/stepUpProof');
        const step = await checkSecondFactor(req, { actionKey: 'tenant.manage_users', allowTrustedIp: false, allowDevice: true });
        if (!step.ok) { sendStepUpFailure(res, step); return; }
      } else {
        const gated = await applyRestriction(res, { req, actionKey: 'tenant.manage_users' });
        if (!gated) return;
      }

      const data = req.body as ChangePasswordInput;
      const success = await switchToIdentity(() => userService.changePassword(id, data.password));
      if (!success) throw new AppError(404, 'User not found');
      // §6.7: the account's phone keys die with the old password (trigger = safety net).
      try {
        const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
        await deviceKeyService.revokeAllForUser(id, 'password_reset', { byUserId: req.session.userId, req });
      } catch { /* trigger */ }
      await auditUserAction(req, 'user.password_reset_admin', id, { username: target.username });
      res.json({ success: true, message: 'Password changed' });
    } catch (err) {
      next(err);
    }
  },

  // DELETE /api/users/:id
  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      if (id === req.session.userId) {
        throw new AppError(400, 'Cannot delete your own account');
      }
      // P1: a non-admin manager may only delete an account it dominates.
      const target = await userScope.assertManageableTarget(actorFromReq(req), id);
      // Refused now rather than after a second administrator approved it
      // (deleteUserAccount checks it again at execution).
      if (target.foreign_source === 'obligate') {
        throw new AppError(400, 'Cannot delete SSO user — manage from Obligate');
      }
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_users',
        approvalRequestType: 'batch_command',
        approvalDescription: `Delete user ${target.username} (#${id})`,
        approvalPayload: { action: 'user_delete', userId: id },
      });
      if (!gated) return;

      // Same path as an approved deletion (services/userAdmin.service.ts).
      await deleteUserAccount(actorFromReq(req), id, { req });
      res.json({ success: true, message: 'User deleted' });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/users/:id/teams
  async getTeams(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const actor = actorFromReq(req);
      await userScope.assertReadableTarget(actor, id);
      // Teams are tenant rows: every tenant's in the global view, the
      // current tenant's otherwise.
      let teams = await globalViewRead(req, () => teamService.getUserTeams(id));
      // A manager that is not a platform admin only sees the current
      // tenant's teams (the master tenant included: no global view for a
      // tenant administrator there).
      if (!actor.isPlatformAdmin) {
        teams = teams.filter((tm) => Number(tm.tenantId) === actor.tenantId);
      }
      res.json({ success: true, data: teams });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/users/:id/tenants
  async getTenants(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const actor = actorFromReq(req);
      await userScope.assertReadableTarget(actor, id);
      let assignments = actor.isPlatformAdmin
        ? await switchToIdentity(() => userService.getUserTenantAssignments(id))
        : await userService.getUserTenantAssignments(id);
      // A manager that is not a platform admin sees (and may change) only
      // the current tenant's row: other tenants are neither listed nor
      // named. PUT /:id/tenants keeps the rows it does not send.
      if (!actor.isPlatformAdmin) {
        assignments = assignments.filter((a) => Number(a.tenantId) === actor.tenantId);
      }
      res.json({ success: true, data: assignments });
    } catch (err) {
      next(err);
    }
  },

  // DELETE /api/users/:id/2fa  — admin resets all MFA for a locked-out user
  async resetMfa(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      // One's own 2FA is managed from the profile with a current code (P2):
      // this route must not be a way around it.
      if (id === req.session.userId) {
        throw new AppError(400, 'Use your profile to manage your own two-factor authentication');
      }
      // P1: a non-admin manager may only reset an account it dominates.
      const target = await userScope.assertManageableTarget(actorFromReq(req), id);

      // At the 'restricted' level the approval is EXECUTED once a second
      // administrator approves it (approval.service _executeUserAction,
      // which re-checks this scope as the requester).
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_users',
        approvalRequestType: 'batch_command',
        approvalDescription: `Reset the two-factor authentication of user ${target.username} (#${id})`,
        approvalPayload: { action: 'user_2fa_reset', userId: id },
      });
      if (!gated) return;

      // Removes the factors, lifts the code lock (§6.8) and the IP trusts
      // that rested on the removed factor.
      if (!(await resetSecondFactors(id, req.session.userId, { req }))) throw new AppError(404, 'User not found');
      await auditUserAction(req, 'user.2fa_reset', id, { username: target.username });
      res.json({ success: true, message: 'MFA reset successfully' });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/users/:id/device-keys — the account's active phone keys
  // (docs/mobile/device-bound-2fa.md §6.5). Same population as the resets
  // (P1: a non-admin manager only sees accounts it dominates).
  async listDeviceKeys(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      await userScope.assertManageableTarget(actorFromReq(req), id);
      const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
      res.json({ success: true, data: await deviceKeyService.list(id, null) });
    } catch (err) {
      next(err);
    }
  },

  // DELETE /api/users/:id/device-keys/:keyId  and  DELETE /api/users/:id/device-keys
  // Revocation by an administrator ('admin', revoked_by = the caller): the
  // phone's sessions die, the account's trusted IPs are dropped (§6.7).
  // Through the tenant.manage_users envelope; at the 'restricted' level the
  // approval is EXECUTED once a second administrator approves it.
  async revokeDeviceKeys(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const keyId = req.params.keyId as string | undefined;
      // One's own phones are managed from the profile (no step-up there, [D8b]).
      if (id === req.session.userId) {
        throw new AppError(400, 'Use your profile to manage your own phones');
      }
      const target = await userScope.assertManageableTarget(actorFromReq(req), id);
      const { isUuid } = await import('../services/deviceKey/payload');
      if (keyId !== undefined && !isUuid(keyId)) throw new AppError(404, 'Not found');

      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_users',
        approvalRequestType: 'batch_command',
        approvalDescription: keyId
          ? `Revoke a validation phone of user ${target.username} (#${id})`
          : `Revoke every validation phone of user ${target.username} (#${id})`,
        approvalPayload: { action: 'user_device_keys_revoke', userId: id, ...(keyId ? { keyId } : {}) },
      });
      if (!gated) return;

      const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
      const opts = { byUserId: req.session.userId, req };
      const done = keyId
        ? await deviceKeyService.revoke([keyId], 'admin', { ...opts, ownerId: id })
        : await deviceKeyService.revokeAllForUser(id, 'admin', opts);
      if (keyId && done.length === 0) throw new AppError(404, 'Not found');
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  },

  // PUT /api/users/:id/tenants
  // Body: { assignments: [{ tenantId: number, role: 'admin' | <permission set slug> }] }
  // ('member', the pre-091 name of the 'user' set, is read as 'user'.)
  async setTenants(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      // P1: tenant memberships are the tenant-level role. A manager that is
      // not a platform admin may only change the CURRENT tenant's row, of an
      // account it dominates other than itself (tenant admin rows only as a
      // tenant admin), and may only grant a role whose permissions it holds.
      // Rows of other tenants are kept as they are. Checked first: an
      // account outside the manager's reach answers 404, whatever it is.
      const actor = actorFromReq(req);
      const assignments = await userScope.resolveTenantAssignments(actor, id, (req.body as { assignments?: unknown })?.assignments);
      const targetUser = await switchToIdentity(() => userService.getById(id));
      if (!targetUser) throw new AppError(404, 'User not found');
      if (targetUser.foreignSource === 'obligate') {
        throw new AppError(400, 'Cannot modify SSO user tenant access — manage from Obligate');
      }

      // The requested rows (tenant id + role only): the executor re-resolves
      // them as the requester when the request is approved. The description
      // lists the resulting access.
      const requested = ((req.body as { assignments?: unknown }).assignments as Array<{ tenantId?: unknown; role?: unknown }>)
        .map((a) => ({ tenantId: Number(a?.tenantId), role: String(a?.role ?? '') }));
      const { tenantLabel } = await import('../services/approvalDescribe');
      const access: string[] = [];
      for (const a of assignments) access.push(`${await tenantLabel(a.tenantId)}: ${a.role}`);
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_users',
        approvalRequestType: 'batch_command',
        approvalDescription: `Change the tenant access of user "${targetUser.username}" (#${id}) → ${access.join('; ') || 'no tenant at all'}`,
        approvalPayload: { action: 'user_tenants_set', userId: id, assignments: requested },
      });
      if (!gated) return;

      await userService.setUserTenantAssignments(id, assignments);
      await auditUserAction(req, 'user.tenants_changed', id, { username: targetUser.username, assignments });
      res.json({ success: true, message: 'Tenant assignments updated' });
    } catch (err) {
      next(err);
    }
  },
};
