import type { Knex } from 'knex';
import { db } from '../db';
import { hashPassword } from '../utils/crypto';
import { forgetTenantMemberships } from './tenant.service';
import type { User, UserRole, UserTenantAssignment } from '@obligarth/shared';

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
    displayName?: string | null;
    role?: UserRole;
    isActive?: boolean;
  }): Promise<User | null> {
    const updateData: Record<string, unknown> = { updated_at: new Date() };
    if (data.displayName !== undefined) updateData.display_name = data.displayName;
    if (data.role !== undefined) updateData.role = data.role;
    if (data.isActive !== undefined) updateData.is_active = data.isActive;

    const [row] = await db<UserRow>('users')
      .where({ id })
      .update(updateData)
      .returning('*');

    return row ? rowToUser(row) : null;
  },

  async changePassword(id: number, newPassword: string): Promise<boolean> {
    const passwordHash = await hashPassword(newPassword);
    const count = await db('users')
      .where({ id })
      .update({ password_hash: passwordHash, updated_at: new Date() });
    return count > 0;
  },

  async delete(id: number): Promise<boolean> {
    const count = await db('users').where({ id }).del();
    return count > 0;
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
    let removedTenants = 0;
    await db.transaction(async (trx) => {
      const before = (await trx('user_tenants').where({ user_id: userId }).pluck('tenant_id') as number[]).map(Number);
      removedTenants = before.filter((t) => !kept.includes(t)).length;
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
      const outside = trx('user_teams').select('id');
      if (kept.length > 0) outside.whereNotIn('tenant_id', kept);
      await trx('team_memberships').where({ user_id: userId }).whereIn('team_id', outside).del();
    });
    forgetTenantMemberships(userId);
    if (removedTenants > 0) {
      const { killSessionsForUser } = await import('./userSessions.service');
      await killSessionsForUser(userId, 'tenant_access_removed');
    }
  },
};
