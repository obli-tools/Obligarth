import type { Knex } from 'knex';
import { db } from '../db';
import { switchToIdentity, switchToTenant } from '../db/context';
import { hashPassword } from '../utils/crypto';
import { forgetTenantMemberships } from './tenant.service';
import { AppError } from '../middleware/errorHandler';
import { forgetSessionUser } from '../middleware/sessionUserGuard';
import type { User, UserRole, UserTenantAssignment } from '@obligarth/shared';
import { logger } from '../utils/logger';

/** A DELETE of users refused by a foreign key (23503 foreign_key_violation): another row still references it. */
export function isUserReferenceViolation(err: unknown): boolean {
  return !!err && typeof err === 'object' && (err as { code?: unknown }).code === '23503';
}

interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  display_name: string | null;
  role: string;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
}

function rowToUser(row: UserRow): User {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    role: row.role as UserRole,
    isActive: row.is_active,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
    email: (row as any).email ?? null,
    preferences: (row as any).preferences ?? {},
    preferredLanguage: (row as any).preferred_language ?? 'en',
    enrollmentVersion: (row as any).enrollment_version ?? 0,
    totpEnabled: (row as any).totp_enabled ?? false,
    emailOtpEnabled: (row as any).email_otp_enabled ?? false,
    foreignSource: (row as any).foreign_source ?? null,
    foreignId: (row as any).foreign_id ?? null,
    foreignSourceUrl: (row as any).foreign_source_url ?? null,
    hasPassword: (row as any).has_password ?? true,
    avatar: (row as any).avatar ?? null,
  };
}

export const userService = {
  /** List users. When `tenantId` is provided, restrict to users that have
   *  a membership row in `user_tenants` for that tenant — used by the
   *  /admin/users page for every caller outside the global view (so a
   *  Contoso admin doesn't see ACME users by accident). Pass `null` /
   *  undefined to get every user: the global view, for a platform admin on
   *  the master tenant only (usersController.list). */
  async getAll(tenantId?: number | null): Promise<User[]> {
    const q = db<UserRow>('users').orderBy('users.username').select('users.*');
    if (tenantId != null) {
      q.join('user_tenants', 'user_tenants.user_id', 'users.id')
        .where('user_tenants.tenant_id', tenantId)
        .groupBy('users.id'); // dedupe: a user may have multiple rows in user_tenants if joined multiple ways
    }
    const rows = await q;
    return rows.map(rowToUser);
  },

  async getById(id: number): Promise<User | null> {
    const row = await db<UserRow>('users').where({ id }).first();
    return row ? rowToUser(row) : null;
  },

  async create(data: {
    username: string;
    password: string;
    displayName?: string | null;
    role?: UserRole;
  }): Promise<User> {
    const passwordHash = await hashPassword(data.password);
    return this.createWithPasswordHash({ ...data, passwordHash });
  },

  /** Same, from a bcrypt hash computed beforehand (utils/crypto
   *  hashPassword): an approved creation only ever kept the hash. `trx`: the
   *  transaction of a caller that writes more with the account. */
  async createWithPasswordHash(data: {
    username: string;
    passwordHash: string;
    displayName?: string | null;
    role?: UserRole;
  }, trx?: Knex.Transaction): Promise<User> {
    const [row] = await (trx ?? db)<UserRow>('users')
      .insert({
        username: data.username,
        password_hash: data.passwordHash,
        display_name: data.displayName || null,
        role: data.role || 'user',
      })
      .returning('*');

    return rowToUser(row);
  },

  async update(id: number, data: {
    /** A new sign-in name (validated by updateUserSchema; the unique index refuses a name in use). */
    username?: string;
    displayName?: string | null;
    role?: UserRole;
    isActive?: boolean;
  }): Promise<User | null> {
    const updateData: Record<string, unknown> = { updated_at: new Date() };
    // The rename the edit form and its approval announce is applied (it used
    // to be dropped silently while the request answered 200).
    if (data.username !== undefined) updateData.username = data.username;
    if (data.displayName !== undefined) updateData.display_name = data.displayName;
    if (data.role !== undefined) updateData.role = data.role;
    if (data.isActive !== undefined) updateData.is_active = data.isActive;

    let row: UserRow | undefined;
    try {
      [row] = await db<UserRow>('users')
        .where({ id })
        .update(updateData)
        .returning('*');
    } catch (err) {
      // A name taken in the meantime (an approved edit runs later than its
      // request): a clear refusal, never a raw SQL error.
      if (data.username !== undefined && (err as { code?: string })?.code === '23505') {
        throw new AppError(409, 'Username already exists');
      }
      throw err;
    }
    // The open sessions of a renamed account pick the new name up on their
    // next request (sessionUserGuard keeps session.username in step).
    if (row && data.username !== undefined) forgetSessionUser(id);

    return row ? rowToUser(row) : null;
  },

  async changePassword(id: number, newPassword: string): Promise<boolean> {
    const passwordHash = await hashPassword(newPassword);
    const count = await db('users')
      .where({ id })
      .update({ password_hash: passwordHash, updated_at: new Date() });
    return count > 0;
  },

  /** Deletes the account. A row still referencing it through a foreign key without ON DELETE answers 409
   *  userHasDependencies (review F047), never a 500: the account stays as it was. */
  async delete(id: number): Promise<boolean> {
    try {
      const count = await db('users').where({ id }).del();
      return count > 0;
    } catch (err) {
      if (isUserReferenceViolation(err)) {
        logger.warn({ userId: id, constraint: String((err as { constraint?: unknown }).constraint ?? '').slice(0, 120) },
          'user not deleted: still referenced');
        throw new AppError(409, 'This account is still referenced by other records: disable it instead, or remove what refers to it first', 'userHasDependencies');
      }
      throw err;
    }
  },

  /** Returns all tenants with this user's membership status and role. */
  async getUserTenantAssignments(userId: number): Promise<UserTenantAssignment[]> {
    const rows = await db('tenants as t')
      .leftJoin('user_tenants as ut', function () {
        this.on('ut.tenant_id', '=', 't.id').andOnVal('ut.user_id', '=', userId);
      })
      .select(
        't.id as tenantId',
        't.name as tenantName',
        't.slug as tenantSlug',
        db.raw('(ut.user_id IS NOT NULL) as is_member'),
        // 'user' is the default non-admin permission set. 'member' is its
        // pre-091 name (migration 091 backfilled it): reported as 'user'.
        db.raw("COALESCE(ut.role, 'user') as role"),
      )
      .orderBy('t.name');

    return rows.map((r) => ({
      tenantId: r.tenantId,
      tenantName: r.tenantName,
      tenantSlug: r.tenantSlug,
      isMember: Boolean(r.is_member),
      role: (r.role === 'member' ? 'user' : r.role) as UserTenantAssignment['role'],
    }));
  },

  /**
   * Bulk-replaces all tenant memberships for a user. Teams are mono-tenant:
   * the user's memberships of the teams of every tenant it no longer belongs
   * to go too (a team membership left behind kept its device grants), as
   * tenantService.removeUser and the Obligate reconciliation do. When a
   * tenant was removed, the user's sessions end: one may sit on that tenant.
   */
  async setUserTenantAssignments(
    userId: number,
    assignments: { tenantId: number; role: string }[],
  ): Promise<void> {
    const kept = [...new Set(assignments.map((a) => Number(a.tenantId)))];
    let removed: number[] = [];
    // Memberships: identity rows (identity context, after the caller's P1
    // checks). Team memberships: rows of each tenant, purged below in that
    // tenant's context.
    await switchToIdentity(() => db.transaction(async (trx) => {
      const before = (await trx('user_tenants').where({ user_id: userId }).pluck('tenant_id') as number[]).map(Number);
      removed = before.filter((t) => !kept.includes(t));
      await trx('user_tenants').where({ user_id: userId }).del();
      if (assignments.length > 0) {
        await trx('user_tenants').insert(
          // user_tenants has no created_at column (001 / 091): inserting one
          // made every save fail with a 500.
          assignments.map((a) => ({
            user_id: userId,
            tenant_id: a.tenantId,
            // Never store the orphan pre-091 slug 'member' (no capability).
            role: a.role === 'member' || !a.role ? 'user' : a.role,
          })),
        );
      }
    }));
    for (const tenantId of removed) {
      await switchToTenant(tenantId, () => db('team_memberships').where({ user_id: userId, tenant_id: tenantId }).del());
    }
    forgetTenantMemberships(userId);
    if (removed.length > 0) {
      const { killSessionsForUser } = await import('./userSessions.service');
      await killSessionsForUser(userId, 'tenant_access_removed');
    }
  },
};
