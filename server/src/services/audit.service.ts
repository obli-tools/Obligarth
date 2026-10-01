import { clientIp as resolveClientIp } from '../utils/clientIp';
import type { Knex } from 'knex';
import { db } from '../db';
import type { Request } from 'express';
import { isMasterTenant } from '@obligarth/shared';
import { asTenant, contextMode, countContextMissing, currentDbContext, type DbActor } from '../db/context';
import { logger } from '../utils/logger';
import { userLabels } from './userLabels.service';

/**
 * An entry is written in the database context of ITS tenant, as the current
 * actor (rls-tenant §5.3.5, §8.2): a platform event filed under the master
 * tenant from a sign-in, an action of the MSP filed in the client's tenant
 * (logReqAs), all with the actor of the caller's context. Without a context
 * (a defect): logged, and written only while DB_CONTEXT_MODE=audit.
 */
async function inEntryTenant(tenantId: number, fn: () => Promise<unknown>): Promise<void> {
  const ctx = currentDbContext();
  if (ctx?.kind === 'tenant' && ctx.tenantId === tenantId) { await fn(); return; }
  let actor: DbActor;
  if (ctx) {
    actor = ctx.actor;
  } else {
    countContextMissing();
    logger.warn({ code: 'DB_CONTEXT_MISSING', stack: new Error('audit entry').stack }, 'database query without context');
    if (contextMode() !== 'audit') throw new Error('audit entry without a database context');
    actor = { type: 'anonymous', name: 'unscoped' };
  }
  await asTenant(tenantId, actor, fn);
}

export interface AuditLogEntry {
  tenantId: number;
  userId?: number;
  deviceId?: number;
  action: string;
  resourceType?: string;
  resourcePath?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
}

export interface AuditLogRow {
  id: number;
  tenantId: number;
  /** Tenant display name. Always populated (the join is unconditional);
   *  the UI consumes it on master view to render a per-row tenant chip
   *  + tenant filter dropdown. */
  tenantName: string | null;
  userId: number | null;
  username: string | null;
  deviceId: number | null;
  deviceName: string | null;
  action: string;
  resourceType: string | null;
  resourcePath: string | null;
  /** Display name resolved from the owning table when possible
   *  (e.g. `device_groups.name` for `resource_type='group'`). `null` when
   *  the entity has been deleted, or when the resource_type doesn't
   *  map to a nameable table (commands, files, sessions, etc.). The
   *  raw `resourceType:resourcePath` pair stays available so the UI
   *  can always fall back to it for debugging. */
  resourceName: string | null;
  details: Record<string, unknown> | null;
  ipAddress: string | null;
  createdAt: string;
}

function rowToAudit(r: any): AuditLogRow {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    tenantName: r.tenant_name ?? null,
    userId: r.user_id,
    username: r.username ?? null,
    deviceId: r.device_id,
    deviceName: r.device_name ?? null,
    action: r.action,
    resourceType: r.resource_type,
    resourcePath: r.resource_path,
    resourceName: r.resource_name ?? null,
    details: typeof r.details === 'string' ? JSON.parse(r.details) : r.details,
    ipAddress: r.ip_address,
    createdAt: r.created_at,
  };
}

// ── Resource names ──────────────────────────────────────────────────────────
// The owner of a `resource_type` names its resources: `column` of `table`
// whose id is the row's resource_path. The core registers its own below; a
// module registers its types (registerAuditResourceName) — removing the
// module removes the subquery on its table.
//
// A name is only resolved within the tenant of the entry (`tenant`): an
// entry that cites the id of another tenant's resource (resource_path is
// free text) shows no name, so a tenant's log never names what another
// tenant owns. The same goes for the device of an entry (device_id).
//   - { column: c }              the row's own tenant column (tenant_id by
//                                default; `id` for the tenants table);
//   - { membership: t, key: k }  a global row (users) named only when it
//                                belongs to the entry's tenant through the
//                                membership table t (t.k = the row's id,
//                                t.tenant_id = the entry's tenant).

export type AuditNameTenant = { column: string } | { membership: string; key: string };

const IDENT_RE = /^[a-z_][a-z0-9_]*$/;
const RESOURCE_TYPE_RE = /^[a-z][a-z0-9_]*$/;
const resourceNames: Array<{ resourceType: string; table: string; column: string; tenant: AuditNameTenant }> = [];

export function registerAuditResourceName(
  resourceType: string,
  table: string,
  column = 'name',
  tenant: AuditNameTenant = { column: 'tenant_id' },
): void {
  // Inlined in the SQL below: identifiers and the type literal are checked.
  const idents = 'column' in tenant ? [tenant.column] : [tenant.membership, tenant.key];
  if (!RESOURCE_TYPE_RE.test(resourceType) || ![table, column, ...idents].every((i) => IDENT_RE.test(i))) {
    throw new Error(`Invalid audit resource name source: ${resourceType} → ${table}.${column}`);
  }
  if (resourceNames.some((r) => r.resourceType === resourceType)) {
    throw new Error(`Audit resource type '${resourceType}' registered twice`);
  }
  resourceNames.push({ resourceType, table, column, tenant });
}

registerAuditResourceName('team', 'user_teams');
registerAuditResourceName('user', 'users', 'username', { membership: 'user_tenants', key: 'user_id' });
registerAuditResourceName('group', 'device_groups');
registerAuditResourceName('tenant', 'tenants', 'name', { column: 'id' });

/** Resolves the human-readable name for an audit row's resource via
 *  correlated subqueries.
 *
 *  A first cut used N LEFT JOINs gated by `resource_type`. That broke:
 *  PostgreSQL doesn't reliably short-circuit `AND` inside an `ON`
 *  clause, so `al.resource_path::int` ended up evaluating for every
 *  row regardless of `resource_type`, and any non-numeric
 *  `resource_path` (file paths under `resource_type='file'`, etc.)
 *  threw "invalid input syntax for type integer" — the whole SELECT
 *  failed and the page went red. Subqueries dodge the issue: each
 *  branch is only executed when the WHERE predicate is true, and we
 *  compare `id::text = resource_path` (cast the PK, not the path).
 *  With LIMIT 100 + indexed PK lookups this stays cheap. The types are
 *  distinct, so at most one branch names a row. Each branch only names a
 *  row of the entry's tenant (see "Resource names" above). */
function resourceNameSelect() {
  if (!resourceNames.length) return db.raw('NULL::text as resource_name');
  const inTenant = (r: (typeof resourceNames)[number]) => ('column' in r.tenant
    ? `${r.table}.${r.tenant.column} = al.tenant_id`
    : `EXISTS (SELECT 1 FROM ${r.tenant.membership} m WHERE m.${r.tenant.key} = ${r.table}.id AND m.tenant_id = al.tenant_id)`);
  const branches = resourceNames.map((r) =>
    `(SELECT ${r.column} FROM ${r.table} WHERE al.resource_type = '${r.resourceType}' AND ${r.table}.id::text = al.resource_path AND ${inTenant(r)})`);
  return db.raw(`
  COALESCE(
    ${branches.join(',\n    ')}
  ) as resource_name
`);
}

/** The device named by an entry, only when it is in the entry's tenant
 *  (see "Resource names" above). */
function deviceOfEntryTenant(this: Knex.JoinClause): void {
  this.on('d.id', '=', 'al.device_id').andOn('d.tenant_id', '=', 'al.tenant_id');
}

function clientIpFromReq(req: Request | undefined): string | undefined {
  if (!req) return undefined;
  // Through OUR proxies only (utils/clientIp.ts), never the left-most XFF value.
  return resolveClientIp(req) || undefined;
}

export const auditService = {
  /** Write a raw audit entry. Never throws — logging must not break the
   *  request that's trying to be audited. */
  async log(entry: AuditLogEntry): Promise<void> {
    try {
      await inEntryTenant(entry.tenantId, () => db('audit_logs').insert({
        tenant_id: entry.tenantId,
        user_id: entry.userId ?? null,
        device_id: entry.deviceId ?? null,
        action: entry.action,
        resource_type: entry.resourceType ?? null,
        resource_path: entry.resourcePath ?? null,
        details: entry.details ? JSON.stringify(entry.details) : null,
        ip_address: entry.ipAddress ?? null,
      }));
    } catch (err) {
      // Audit logging must never break the calling request (until PLT-12
      // makes it blocking for the critical actions), but a lost entry is
      // logged, never swallowed.
      logger.warn({ err, action: entry.action, tenantId: entry.tenantId }, 'audit entry not written');
    }
  },

  /** Convenience helper for route handlers — pulls tenantId/userId/ip from req. */
  async logReq(
    req: Request,
    action: string,
    extras: Partial<Omit<AuditLogEntry, 'action' | 'tenantId' | 'userId' | 'ipAddress'>> = {},
  ): Promise<void> {
    const tenantId = (req as any).tenantId as number | undefined;
    const userId = (req.session as any)?.userId as number | undefined;
    if (!tenantId) return; // can't audit without a tenant scope
    await this.log({
      tenantId,
      userId,
      action,
      ipAddress: clientIpFromReq(req),
      ...extras,
    });
  },

  /** As logReq, but filed in `tenantId` (a master-tenant action that touched
   *  another tenant's devices leaves a trace in that tenant's own log). */
  async logReqAs(
    req: Request,
    tenantId: number,
    action: string,
    extras: Partial<Omit<AuditLogEntry, 'action' | 'tenantId' | 'userId' | 'ipAddress'>> = {},
  ): Promise<void> {
    const userId = (req.session as any)?.userId as number | undefined;
    await this.log({
      tenantId,
      userId,
      action,
      ipAddress: clientIpFromReq(req),
      ...extras,
    });
  },

  async getByDevice(deviceId: number, tenantId: number, limit = 50): Promise<AuditLogRow[]> {
    const rows = await db('audit_logs as al')
      .leftJoin('devices as d', deviceOfEntryTenant)
      .where({ 'al.device_id': deviceId, 'al.tenant_id': tenantId })
      .select(
        'al.*',
        db.raw('COALESCE(d.display_name, d.hostname) as device_name'),
        resourceNameSelect(),
      )
      .orderBy('al.created_at', 'desc')
      .limit(limit);
    return withAuthorNames(rows);
  },

  /** Tenant-wide list with filters + pagination. */
  async list(params: {
    tenantId: number;
    action?: string;          // exact or prefix match (e.g. "user." matches all user actions)
    userId?: number;
    deviceId?: number;
    resourceType?: string;
    search?: string;          // match against resource_path or details text
    since?: Date;
    until?: Date;
    limit?: number;
    offset?: number;
    /** Master-only narrow filter — pick one tenant within the god
     *  view. Silently dropped for non-master callers (they're already
     *  scoped to their own tenant; allowing this would let them peek
     *  at other tenants' logs by ID). */
    filterTenantId?: number;
  }): Promise<{ items: AuditLogRow[]; total: number }> {
    const page = Math.max(0, params.offset ?? 0);
    const limit = Math.min(500, Math.max(1, params.limit ?? 100));

    // Master tenant gets the cross-tenant audit feed (essential for a
    // platform admin investigating an incident across customers).
    const isMaster = isMasterTenant(params.tenantId);
    const base = db('audit_logs as al')
      .leftJoin('users as u', 'u.id', 'al.user_id')
      .leftJoin('devices as d', deviceOfEntryTenant)
      // Always join `tenants` so master rows carry a tenant name column;
      // child tenants get the join too but ignore it.
      .leftJoin('tenants as ten', 'ten.id', 'al.tenant_id');
    if (!isMaster) base.where({ 'al.tenant_id': params.tenantId });
    // Narrow filter — master only (non-master is already scoped above).
    if (isMaster && Number.isFinite(params.filterTenantId)) {
      base.where('al.tenant_id', params.filterTenantId);
    }

    if (params.action) {
      if (params.action.endsWith('.')) {
        base.where('al.action', 'like', `${params.action}%`);
      } else {
        base.where('al.action', params.action);
      }
    }
    if (params.userId) base.where('al.user_id', params.userId);
    if (params.deviceId) base.where('al.device_id', params.deviceId);
    if (params.resourceType) base.where('al.resource_type', params.resourceType);
    if (params.since) base.where('al.created_at', '>=', params.since);
    if (params.until) base.where('al.created_at', '<=', params.until);
    if (params.search) {
      const q = `%${params.search}%`;
      base.where((b) => {
        b.where('al.resource_path', 'like', q)
         .orWhereRaw('details::text ILIKE ?', [q])
         .orWhere('u.username', 'like', q);
      });
    }

    const countRes = await base.clone().count<{ c: string }[]>({ c: 'al.id' });
    const total = parseInt((countRes[0] as any)?.c || '0', 10);

    const rows = await base
      .select(
        'al.*',
        db.raw('COALESCE(d.display_name, d.hostname) as device_name'),
        'ten.name as tenant_name',
        resourceNameSelect(),
      )
      .orderBy('al.created_at', 'desc')
      .limit(limit)
      .offset(page);

    return { items: await withAuthorNames(rows), total };
  },
};

/** The rows with their authors' names (obligarth.user_labels: an MSP
 *  administrator who acted in the tenant is named, an account of another
 *  client never). */
async function withAuthorNames(rows: any[]): Promise<AuditLogRow[]> {
  const labels = await userLabels(rows.map((r) => r.user_id).filter((id) => id != null));
  return rows.map((r) => rowToAudit({ ...r, username: r.user_id != null ? labels.get(Number(r.user_id))?.username ?? null : null }));
}
