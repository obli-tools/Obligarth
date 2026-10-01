import { performance } from 'node:perf_hooks';
import type { Request } from 'express';
import { db } from '../db';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import type { Tenant, TenantWithRole } from '@obligarth/shared';
import { AppError } from '../middleware/errorHandler';
import { clientIp } from '../utils/clientIp';
import { normaliseTenantRole } from './userScope.service';
import { currentDbContext, switchToIdentity, switchToNone, switchToTenant, type DbActor } from '../db/context';
import { vault } from '../vault';
import { audit, type AuditWriteContext } from '../audit';

// Database contexts (rls-tenant §6.6, §8.2): the registry is read in the
// caller's context (each sees the tenants it may: its own memberships, every
// tenant for a platform administrator); a tenant's own settings are written
// in its context; memberships are written in the identity context, after the
// application's checks; creation and deletion go through the definer
// functions obligarth.tenant_create / obligarth.tenant_delete, which require
// an active platform administrator as the actor (context 'none').

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
// is fanned out to are of the RLS class `tenant_shared` (rls-tenant §5.1):
// obligarth.tenant_delete strips the deleted tenant's id from every table of
// that class, found in the classification registry (the former
// registerTenantFanoutTable registry is gone).

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

/** The user of the current database context (the platform administrator
 *  who creates or deletes a tenant). */
function actorUserId(): number | null {
  const actor = currentDbContext()?.actor;
  return actor?.type === 'user' ? actor.userId : null;
}

/** The audit context of a tenant change: the request's, else the current
 *  database context's actor. */
async function auditContextOf(given: AuditWriteContext | undefined, chainTenantId: number, ip?: string): Promise<AuditWriteContext> {
  if (given) return given;
  const actor: DbActor = currentDbContext()?.actor ?? { type: 'anonymous', name: 'unscoped' };
  return audit.fromDbActor(actor, chainTenantId, { ip });
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

  /** A new tenant starts with the recommended restrictions matrix
   *  (defaultRestrictions: the core's and the registered modules'), like
   *  the master tenant the seed creates; the column default ('{}') would
   *  leave it with no restriction at all. Through obligarth.tenant_create
   *  (rls-tenant §6.6; specs README §5), in one transaction, context 'none'
   *  of the caller, who must be an active platform administrator (refused by
   *  the database otherwise). Its first data key is created by the vault in
   *  the same transaction (coffre-secrets §6.2: no valid tenant lacks one);
   *  the apple-edge integration adds its provisioning (lot B). */
  async create(data: { name: string; slug: string }, opts: { ipAddress?: string; auditCtx?: AuditWriteContext } = {}): Promise<Tenant> {
    const { defaultRestrictions } = await import('./restriction.service');
    const ctx = await auditContextOf(opts.auditCtx, MASTER_TENANT_ID, opts.ipAddress);
    return switchToNone(() => db.transaction(async (trx) => {
      const { rows } = await trx.raw('SELECT obligarth.tenant_create(?, ?, ?::jsonb) AS id',
        [data.name, data.slug, JSON.stringify(defaultRestrictions())]) as { rows: Array<{ id: number }> };
      const id = Number(rows[0].id);
      await vault.createTenantKey(trx, id);
      const row = await trx('tenants').where({ id }).first() as TenantRow;
      // P1, last statement of the transaction (audit-durci §4.6): no tenant
      // without its entry, no entry without its tenant.
      await audit.appendInTx(trx, {
        tenantId: MASTER_TENANT_ID, action: 'tenant.created', onBehalfOf: id,
        target: { type: 'tenant', id: String(id) }, details: { slug: row.slug, name: row.name },
      }, ctx);
      return rowToTenant(row);
    }));
  },

  /** Settings of a tenant, written in its own context. The slug is fixed at
   *  creation (join key with Obligate, R11): a different slug is refused. */
  /** The change and its tenant.updated entry (P1, the tenant's chain) in one
   *  transaction; no entry when nothing changes. */
  async update(id: number, data: { name?: string; slug?: string; twoStepApproval?: boolean },
    opts: { auditCtx?: AuditWriteContext } = {}): Promise<Tenant | null> {
    return switchToTenant(id, async () => {
      const ctx = await auditContextOf(opts.auditCtx, id);
      return db.transaction(async (trx) => {
        const current = await trx('tenants').where({ id }).forUpdate().first() as TenantRow | undefined;
        if (!current) return null;
        if (data.slug !== undefined && data.slug !== current.slug) {
          throw new AppError(400, 'The slug of a tenant cannot be changed', 'tenantSlugImmutable');
        }
        const patch: any = { updated_at: trx.fn.now() };
        const changes: Record<string, unknown> = {};
        if (data.name !== undefined) {
          patch.name = data.name;
          if (data.name !== current.name) changes.name = { from: current.name, to: data.name };
        }
        if (data.twoStepApproval !== undefined) {
          patch.two_step_approval = data.twoStepApproval;
          if (data.twoStepApproval !== !!current.two_step_approval) {
            changes.twoStepApproval = { from: !!current.two_step_approval, to: data.twoStepApproval };
          }
        }
        const [row] = await trx('tenants').where({ id }).update(patch).returning('*');
        if (row && Object.keys(changes).length) {
          await audit.appendInTx(trx, {
            tenantId: id, action: 'tenant.updated', onBehalfOf: id === MASTER_TENANT_ID ? undefined : id,
            target: { type: 'tenant', id: String(id) }, details: changes,
          }, ctx);
        }
        return row ? rowToTenant(row as TenantRow) : null;
      });
    });
  },

  /** Hard deletion through obligarth.tenant_delete (temporary measure until
   *  the tenant lifecycle specification: specs README §5): one transaction,
   *  context 'none' of the caller, an active platform administrator. The
   *  vault first crypto-shreds the tenant's data keys (coffre-secrets §6.5,
   *  V7: the foreign key of data_keys is RESTRICT, tenant_delete fails
   *  without it); the function then strips the tenant's id from the
   *  `target_tenant_ids` of every table of the class tenant_shared and
   *  deletes the row (the foreign keys cascade); it refuses the master
   *  tenant. The entries vault.dek_destroyed and tenant.deleted (master
   *  tenant) come last (review COF-RC2): written once the transaction
   *  commits until the hardened journal (lot A6) writes them in it. */
  async delete(id: number, opts: { ipAddress?: string; auditCtx?: AuditWriteContext } = {}): Promise<void> {
    const userId = actorUserId();
    const ctx = await auditContextOf(opts.auditCtx, MASTER_TENANT_ID, opts.ipAddress);
    await switchToNone(() => db.transaction(async (trx) => {
      const tenant = await trx('tenants').where({ id }).first('id', 'slug') as { id: number; slug: string } | undefined;
      const { auditEntry } = await vault.shredTenantKeys(trx, id, { userId }, { audit: 'return' });
      await trx.raw('SELECT obligarth.tenant_delete(?)', [id]);
      // vault.dek_destroyed and tenant.deleted last (COF-RC2, AUD-RC8), P1:
      // the head of the master chain is not held during the cascade.
      await audit.appendManyInTx(trx, [
        ...(auditEntry ? [{
          tenantId: MASTER_TENANT_ID, action: auditEntry.action, onBehalfOf: id,
          target: { type: 'tenant', id: String(id) }, details: auditEntry.details,
        }] : []),
        {
          tenantId: MASTER_TENANT_ID, action: 'tenant.deleted', onBehalfOf: id,
          target: { type: 'tenant', id: String(id) }, details: { slug: tenant?.slug ?? null },
        },
      ], ctx);
    }));
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

  /** Members of a tenant (platform administrators' tenant panel): identity
   *  context, after the route's check. */
  async getMembers(tenantId: number): Promise<(UserRow & { tenantRole: string })[]> {
    return switchToIdentity(() => db('users')
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
      .orderBy('users.username'));
  },

  /** Adds a membership (or changes its role). `role`: see resolveTenantRole
   *  ('user' when none is given). Identity context, after the route's
   *  checks. */
  async addUser(tenantId: number, userId: number, role?: unknown): Promise<void> {
    const slug = await this.resolveTenantRole(role);
    await switchToIdentity(() => db('user_tenants')
      .insert({ tenant_id: tenantId, user_id: userId, role: slug })
      .onConflict(['user_id', 'tenant_id'])
      .merge({ role: slug }));
    forgetTenantMemberships(userId);
  },

  /** Removes a membership. Returns false when there was none. */
  async removeUser(tenantId: number, userId: number): Promise<boolean> {
    // The user's teams of that tenant go too (teams are mono-tenant): a team
    // membership left behind kept its device grants and capabilities on the
    // tenant's devices. Same rule as the Obligate callback's tenant
    // reconciliation.
    // Team memberships are tenant rows (context of that tenant), the
    // membership itself an identity row: two transactions, the teams first.
    let removed = 0;
    await switchToTenant(tenantId, () => db.transaction(async (trx) => {
      await trx('team_memberships')
        .where({ user_id: userId, tenant_id: tenantId })
        .whereIn('team_id', trx('user_teams').where({ tenant_id: tenantId }).select('id'))
        .delete();
    }));
    await switchToIdentity(async () => {
      removed = await db('user_tenants').where({ tenant_id: tenantId, user_id: userId }).delete();
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
    await switchToIdentity(() => db('user_tenants')
      .where({ tenant_id: tenantId, user_id: userId })
      .update({ role: slug }));
  },
};
