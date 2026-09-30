import { performance } from 'node:perf_hooks';
import type { Request } from 'express';
import { db } from '../db';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import type { Tenant, TenantWithRole } from '@obligarth/shared';
import { AppError } from '../middleware/errorHandler';
import { clientIp } from '../utils/clientIp';
import { normaliseTenantRole } from './userScope.service';

interface TenantRow {
  id: number;
  name: string;
  slug: string;
  two_step_approval?: boolean;
  created_at: Date;
  updated_at: Date;
}

interface UserRow {
  id: number;
  username: string;
  display_name: string | null;
  role: string;
  is_active: boolean;
  email: string | null;
}

function rowToTenant(row: TenantRow): Tenant {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    twoStepApproval: !!row.two_step_approval,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

// Tables whose `target_tenant_ids` (int[]) name the tenants a master-owned row
// is fanned out to. The module that owns such a table registers it
// (registerTenantFanoutTable): deleting a tenant strips its id from every
// registered table.
const IDENT_RE = /^[a-z_][a-z0-9_]*$/;
const fanoutTables: string[] = [];

export function registerTenantFanoutTable(table: string): void {
  // Inlined in the SQL of delete(): an identifier only.
  if (!IDENT_RE.test(table)) throw new Error(`Invalid fan-out table name: ${table}`);
  if (fanoutTables.includes(table)) throw new Error(`Fan-out table '${table}' registered twice`);
  fanoutTables.push(table);
}

// ── Membership of a session's tenant ────────────────────────────────────────
// requireTenant (middleware/tenant.ts) re-checks on every request that a
// session which is not a platform admin's still belongs to its tenant: a
// removal from a tenant ends that tenant's access at once, whatever path
// removed the row. The answer is cached a few seconds per user and tenant;
// every path of this process that changes a membership drops the user's
// entries (forgetTenantMemberships, also run by killSessionsForUser), so the
// delay only covers changes made outside this process.

const MEMBERSHIP_TTL_MS = 5_000;
const MEMBERSHIP_MAX_USERS = 10_000;
const membershipCache = new Map<number, Map<number, { at: number; member: boolean }>>();

/** Drops the cached tenant memberships of a user. */
export function forgetTenantMemberships(userId: number): void {
  membershipCache.delete(Number(userId));
}

/** Refusal of a sign-in or a session for an account without any tenant:
 *  such an account never gets the master tenant it is not a member of. */
export function noTenantAccessError(): AppError {
  return new AppError(403, 'This account has no access to any tenant. Ask an administrator to grant it access.', 'noTenantAccess');
}

/** A sign-in refused for that reason (password, second factor or SSO),
 *  audited in the master tenant: the platform's own log, as the account has
 *  no tenant. Returns the error to answer with. */
export async function refuseSignInWithoutTenant(
  req: Request,
  user: { id: number; username: string },
  via: string,
): Promise<AppError> {
  try {
    const { auditService } = await import('./audit.service');
    await auditService.log({
      tenantId: MASTER_TENANT_ID,
      userId: user.id,
      action: 'auth.login_refused',
      resourceType: 'user',
      resourcePath: String(user.id),
      details: { username: user.username, reason: 'no_tenant', via },
      ipAddress: clientIp(req) || undefined,
    });
  } catch { /* the audit never breaks the answer */ }
  return noTenantAccessError();
}

export const tenantService = {
  async getAll(): Promise<Tenant[]> {
    const rows = await db('tenants').select<TenantRow[]>('*').orderBy('id');
    return rows.map(rowToTenant);
  },

  async getById(id: number): Promise<Tenant | null> {
    const row = await db('tenants').where({ id }).first<TenantRow>();
    return row ? rowToTenant(row) : null;
  },

  async getBySlug(slug: string): Promise<Tenant | null> {
    const row = await db('tenants').where({ slug }).first<TenantRow>();
    return row ? rowToTenant(row) : null;
  },

  async create(data: { name: string; slug: string }): Promise<Tenant> {
    const [row] = await db('tenants')
      .insert({ name: data.name, slug: data.slug })
      .returning('*');
    return rowToTenant(row as TenantRow);
  },

  async update(id: number, data: { name?: string; slug?: string; twoStepApproval?: boolean }): Promise<Tenant | null> {
    const patch: any = { updated_at: db.fn.now() };
    if (data.name !== undefined) patch.name = data.name;
    if (data.slug !== undefined) patch.slug = data.slug;
    if (data.twoStepApproval !== undefined) patch.two_step_approval = data.twoStepApproval;
    const [row] = await db('tenants').where({ id }).update(patch).returning('*');
    return row ? rowToTenant(row as TenantRow) : null;
  },

  async delete(id: number): Promise<void> {
    // Strip the tenant id from any master-owned fan-out array before
    // dropping the row (registerTenantFanoutTable). Without this, the rows
    // that targeted this tenant would carry a dangling id forever — and the
    // cross-tenant read scope would perform a wasted `id = ANY(...)` test
    // against the dead value. CASCADE on tenant_id covers the owner side;
    // the array side is application-level and has to be cleaned explicitly.
    await db.transaction(async (trx) => {
      for (const table of fanoutTables) {
        const has = await trx.schema.hasColumn(table, 'target_tenant_ids');
        if (!has) continue;
        await trx.raw(
          `UPDATE ${table}
              SET target_tenant_ids = NULLIF(array_remove(target_tenant_ids, ?), '{}')::int[]
            WHERE ? = ANY(target_tenant_ids)`,
          [id, id],
        );
      }
      await trx('tenants').where({ id }).delete();
    });
  },

  /** Returns the first tenant accessible by userId (lowest id). */
  async getFirstTenantForUser(userId: number): Promise<Tenant | null> {
    const row = await db('tenants')
      .join('user_tenants', 'tenants.id', 'user_tenants.tenant_id')
      .where('user_tenants.user_id', userId)
      .orderBy('tenants.id')
      .first<TenantRow & { role: string }>('tenants.*');
    return row ? rowToTenant(row) : null;
  },

  /** Returns all tenants accessible by userId, with tenant-level role. */
  async getTenantsForUser(userId: number): Promise<TenantWithRole[]> {
    const rows = await db('tenants')
      .join('user_tenants', 'tenants.id', 'user_tenants.tenant_id')
      .where('user_tenants.user_id', userId)
      .orderBy('tenants.id')
      .select<(TenantRow & { role: string })[]>('tenants.*', 'user_tenants.role');
    return rows.map((r) => ({ ...rowToTenant(r), role: r.role as 'admin' | 'member' }));
  },

  /** Check if user has access to a specific tenant. */
  async userHasAccess(userId: number, tenantId: number): Promise<boolean> {
    const row = await db('user_tenants')
      .where({ user_id: userId, tenant_id: tenantId })
      .first('user_id');
    return !!row;
  },

  /** userHasAccess, cached a few seconds (see "Membership of a session's
   *  tenant" above). */
  async isMemberCached(userId: number, tenantId: number): Promise<boolean> {
    const now = performance.now();
    let perUser = membershipCache.get(userId);
    const hit = perUser?.get(tenantId);
    if (hit && now - hit.at < MEMBERSHIP_TTL_MS) return hit.member;
    if (!perUser) {
      if (membershipCache.size >= MEMBERSHIP_MAX_USERS) membershipCache.clear();
      perUser = new Map();
      membershipCache.set(userId, perUser);
    }
    const member = await this.userHasAccess(userId, tenantId);
    // Stored in the map taken BEFORE the query: a forgetTenantMemberships()
    // run meanwhile dropped that map, so an answer read before a change is
    // never served after it.
    perUser.set(tenantId, { at: now, member });
    return member;
  },

  /**
   * The tenant a session of this user starts on (sign-in, or a session to
   * repair): the first tenant it belongs to. A platform admin without any
   * membership row (implicit access to every tenant, as the SSO sign-in
   * leaves it) starts on the master tenant. Anyone else without a tenant
   * gets null, never the master tenant: the caller refuses the session.
   */
  async sessionTenantFor(userId: number, platformRole: string | null | undefined): Promise<number | null> {
    const first = await this.getFirstTenantForUser(userId);
    if (first) return first.id;
    return platformRole === 'admin' ? MASTER_TENANT_ID : null;
  },

  /**
   * A tenant role as stored in user_tenants.role: 'admin' (tenant
   * administrator) or the slug of a permission set. 'member' (the pre-091
   * name of the 'user' set) and a missing role are read as 'user': an orphan
   * slug grants no capability at all. Throws 400 for a slug that names no
   * permission set.
   */
  async resolveTenantRole(role: unknown): Promise<string> {
    if (role != null && typeof role !== 'string') throw new AppError(400, 'Invalid role');
    const slug = normaliseTenantRole(role);
    if (slug === 'admin') return slug;
    const set = await db('permission_sets').where({ slug }).first('id');
    if (!set) throw new AppError(400, `Unknown role: ${slug}`);
    return slug;
  },

  async getMembers(tenantId: number): Promise<(UserRow & { tenantRole: string })[]> {
    return db('users')
      .join('user_tenants', 'users.id', 'user_tenants.user_id')
      .where('user_tenants.tenant_id', tenantId)
      .select<(UserRow & { tenantRole: string })[]>(
        'users.id',
        'users.username',
        'users.display_name',
        'users.role',
        'users.is_active',
        'users.email',
        db.raw('user_tenants.role as "tenantRole"'),
      )
      .orderBy('users.username');
  },

  /** Adds a membership (or changes its role). `role`: see resolveTenantRole
   *  ('user' when none is given). */
  async addUser(tenantId: number, userId: number, role?: unknown): Promise<void> {
    const slug = await this.resolveTenantRole(role);
    await db('user_tenants')
      .insert({ tenant_id: tenantId, user_id: userId, role: slug })
      .onConflict(['user_id', 'tenant_id'])
      .merge({ role: slug });
    forgetTenantMemberships(userId);
  },

  /** Removes a membership. Returns false when there was none. */
  async removeUser(tenantId: number, userId: number): Promise<boolean> {
    // The user's teams of that tenant go too (teams are mono-tenant): a team
    // membership left behind kept its device grants and capabilities on the
    // tenant's devices. Same rule as the Obligate callback's tenant
    // reconciliation.
    let removed = 0;
    await db.transaction(async (trx) => {
      const teamIds = await trx('team_memberships')
        .join('user_teams', 'user_teams.id', 'team_memberships.team_id')
        .where({ 'team_memberships.user_id': userId, 'user_teams.tenant_id': tenantId })
        .pluck('team_memberships.team_id') as number[];
      if (teamIds.length > 0) {
        await trx('team_memberships').where({ user_id: userId }).whereIn('team_id', teamIds).delete();
      }
      removed = await trx('user_tenants').where({ tenant_id: tenantId, user_id: userId }).delete();
    });
    forgetTenantMemberships(userId);
    if (removed > 0) {
      // An open session may sit on that tenant: the user's sessions end (the
      // next sign-in lands on a tenant it still belongs to), as the Obligate
      // reconciliation does.
      const { killSessionsForUser } = await import('./userSessions.service');
      await killSessionsForUser(userId, 'tenant_access_removed');
    }
    return removed > 0;
  },

  /** Changes the role of a membership. `role`: see resolveTenantRole. */
  async updateUserRole(tenantId: number, userId: number, role: unknown): Promise<void> {
    const slug = await this.resolveTenantRole(role);
    await db('user_tenants')
      .where({ tenant_id: tenantId, user_id: userId })
      .update({ role: slug });
  },
};
