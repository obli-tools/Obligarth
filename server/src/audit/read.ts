// Reading the journal (docs: audit-durci §9): in the database context of the
// request, so the row level security keeps every reader to what they may
// read: the chain of the session's tenant ('tenant'), or every chain from the
// master tenant's global view ('platform', platform administrators only:
// globalViewScope). Names are resolved in the entry's tenant only (E14):
// resources (registerAuditResourceName), devices (tenant_id, device_id of the
// entry), authors (obligarth.user_labels: the reader's tenants' members and
// the platform administrators, never another client's accounts).
import type { Knex } from 'knex';
import type {
  AuditActorSide, AuditChainStatus, AuditCriticality, AuditEntryDetailDto, AuditEntryDto, AuditOutcome, AuditSealDto,
  AuditVerificationDto,
} from '@obligarth/shared';
import { db } from '../db';
import { userLabels } from '../services/userLabels.service';

// ── Resource names (E14: resolved in the entry's tenant only) ───────────────
// The owner of a `resource_type` names its resources: `column` of `table`
// whose id is the entry's resource_path. A name is only resolved within the
// tenant of the entry: an entry that cites another tenant's resource shows no
// name, so a tenant's log never names what another tenant owns.
//   - { column: c }              the row's own tenant column (tenant_id by
//                                default; `id` for the tenants table);
//   - { membership: t, key: k }  a global row (users) named only when it
//                                belongs to the entry's tenant through t.

export type AuditNameTenant = { column: string } | { membership: string; key: string };

const IDENT_RE = /^[a-z_][a-z0-9_]*$/;
const RESOURCE_TYPE_RE = /^[a-z][a-z0-9_]*$/;
const resourceNames: Array<{ resourceType: string; table: string; column: string; tenant: AuditNameTenant }> = [];

export function registerAuditResourceName(
  resourceType: string, table: string, column = 'name', tenant: AuditNameTenant = { column: 'tenant_id' },
): void {
  const idents = 'column' in tenant ? [tenant.column] : [tenant.membership, tenant.key];
  if (!RESOURCE_TYPE_RE.test(resourceType) || ![table, column, ...idents].every((i) => IDENT_RE.test(i))) {
    throw new Error(`Invalid audit resource name source: ${resourceType} → ${table}.${column}`);
  }
  if (resourceNames.some((r) => r.resourceType === resourceType)) throw new Error(`Audit resource type '${resourceType}' registered twice`);
  resourceNames.push({ resourceType, table, column, tenant });
}

registerAuditResourceName('team', 'user_teams');
registerAuditResourceName('user', 'users', 'username', { membership: 'user_tenants', key: 'user_id' });
registerAuditResourceName('group', 'device_groups');
registerAuditResourceName('tenant', 'tenants', 'name', { column: 'id' });

/** Correlated subqueries (each branch evaluated only for its type, comparing
 *  id::text to resource_path), one row of the entry's tenant at most. */
function resourceNameSelect(): Knex.Raw {
  if (!resourceNames.length) return db.raw('NULL::text as resource_name');
  const inTenant = (r: (typeof resourceNames)[number]) => ('column' in r.tenant
    ? `${r.table}.${r.tenant.column} = al.tenant_id`
    : `EXISTS (SELECT 1 FROM ${r.tenant.membership} m WHERE m.${r.tenant.key} = ${r.table}.id AND m.tenant_id = al.tenant_id)`);
  const branches = resourceNames.map((r) =>
    `(SELECT ${r.column} FROM ${r.table} WHERE al.resource_type = '${r.resourceType}' AND ${r.table}.id::text = al.resource_path AND ${inTenant(r)})`);
  return db.raw(`COALESCE(${branches.join(', ')}) as resource_name`);
}

function deviceOfEntryTenant(this: Knex.JoinClause): void {
  this.on('d.id', '=', 'al.device_id').andOn('d.tenant_id', '=', 'al.tenant_id');
}

// ── Rows ────────────────────────────────────────────────────────────────────

const iso = (d: unknown): string => (d instanceof Date ? d : new Date(String(d))).toISOString();
const hex = (b: unknown): string => (Buffer.isBuffer(b) ? b.toString('hex') : '');

function parseJson(v: unknown): Record<string, unknown> | null {
  if (v === null || v === undefined) return null;
  if (typeof v === 'object') return v as Record<string, unknown>;
  try { return JSON.parse(String(v)) as Record<string, unknown>; } catch { return null; }
}

/** The DTO of a row (with its author's current display name). */
export function rowToDto(r: any, labels: Map<number, { username: string; displayName: string | null }>): AuditEntryDto {
  const userId = r.user_id != null ? Number(r.user_id) : null;
  const label = r.actor_label ?? (userId != null ? labels.get(userId)?.username ?? null : null);
  let late = false;
  if (typeof r.body === 'string' && r.body.includes('"late"')) {
    try { late = (JSON.parse(r.body) as { late?: unknown }).late === true; } catch { late = false; }
  }
  return {
    id: Number(r.id),
    uuid: String(r.uuid),
    tenantId: Number(r.tenant_id),
    tenantName: r.tenant_name ?? null,
    chainSeq: Number(r.chain_seq),
    occurredAt: iso(r.occurred_at),
    recordedAt: iso(r.created_at),
    action: r.action,
    outcome: r.outcome as AuditOutcome,
    criticality: r.criticality as AuditCriticality,
    actor: {
      type: r.actor_type,
      ref: r.actor_ref,
      label,
      displayName: userId != null ? labels.get(userId)?.displayName ?? null : null,
      side: r.actor_side as AuditActorSide,
      role: (() => { try { return (JSON.parse(String(r.body)) as { actor?: { role?: string } }).actor?.role ?? null; } catch { return null; } })(),
      homeTenantId: r.actor_home_tenant_id != null ? Number(r.actor_home_tenant_id) : null,
    },
    onBehalfOfTenantId: r.on_behalf_of_tenant_id != null ? Number(r.on_behalf_of_tenant_id) : null,
    deviceId: r.device_id != null ? Number(r.device_id) : null,
    deviceName: r.device_name ?? null,
    resourceType: r.resource_type ?? null,
    resourcePath: r.resource_path ?? null,
    resourceName: r.resource_name ?? null,
    targetCount: r.target_count != null ? Number(r.target_count) : null,
    details: parseJson(r.details),
    reason: r.reason ?? null,
    ticket: r.ticket ?? null,
    approvalIds: Array.isArray(r.approval_ids) ? r.approval_ids.map(Number) : [],
    ipAddress: r.ip_address ?? null,
    userAgent: r.user_agent ?? null,
    requestId: r.request_id ?? null,
    legacy: r.is_legacy === true,
    late,
    userId,
    username: label,
    createdAt: iso(r.created_at),
  };
}

async function withLabels(rows: any[]): Promise<AuditEntryDto[]> {
  const labels = await userLabels(rows.map((r) => r.user_id).filter((id) => id != null));
  return rows.map((r) => rowToDto(r, labels));
}

// ── List ────────────────────────────────────────────────────────────────────

export interface ListParams {
  /** The chain read: a tenant, or every chain readable in the context (global view). */
  tenantId: number | null;
  action?: string;
  userId?: number;
  actorSide?: AuditActorSide;
  outcome?: AuditOutcome;
  criticality?: AuditCriticality;
  deviceId?: number;
  resourceType?: string;
  search?: string;
  since?: Date;
  until?: Date;
  beforeSeq?: number;
  limit?: number;
  offset?: number;
}

/** `%`, `_` and the escape character itself, for a LIKE pattern (ESCAPE '!'). */
export function likeEscape(s: string): string {
  return s.replace(/[!%_]/g, (c) => `!${c}`);
}

function filtered(p: ListParams): Knex.QueryBuilder {
  const q = db('audit_logs as al');
  if (p.tenantId !== null) q.where('al.tenant_id', p.tenantId);
  if (p.action) {
    if (p.action.endsWith('.')) q.whereRaw("al.action LIKE ? ESCAPE '!'", [`${likeEscape(p.action)}%`]);
    else q.where('al.action', p.action);
  }
  if (p.userId) q.where('al.user_id', p.userId);
  if (p.actorSide) q.where('al.actor_side', p.actorSide);
  if (p.outcome) q.where('al.outcome', p.outcome);
  if (p.criticality) q.where('al.criticality', p.criticality);
  if (p.deviceId) q.where('al.device_id', p.deviceId);
  if (p.resourceType) q.where('al.resource_type', p.resourceType);
  if (p.since) q.where('al.created_at', '>=', p.since);
  if (p.until) q.where('al.created_at', '<=', p.until);
  if (p.beforeSeq && p.tenantId !== null) q.where('al.chain_seq', '<', p.beforeSeq);
  if (p.search) {
    const pattern = `%${likeEscape(p.search.slice(0, 100))}%`;
    q.where((b) => {
      b.whereRaw("al.resource_path ILIKE ? ESCAPE '!'", [pattern])
        .orWhereRaw("al.actor_label ILIKE ? ESCAPE '!'", [pattern])
        .orWhereRaw("al.details::text ILIKE ? ESCAPE '!'", [pattern]);
    });
  }
  return q;
}

export async function listEntries(p: ListParams): Promise<{ items: AuditEntryDto[]; total: number; nextBeforeSeq: number | null }> {
  const limit = Math.min(500, Math.max(1, Math.trunc(p.limit ?? 100)));
  const offset = Math.min(10_000, Math.max(0, Math.trunc(p.offset ?? 0)));
  const countRes = await filtered(p).count<{ c: string }[]>({ c: '*' });
  const total = Number((countRes[0] as { c?: string } | undefined)?.c ?? 0);
  const q = filtered(p)
    .leftJoin('devices as d', deviceOfEntryTenant)
    .leftJoin('tenants as ten', 'ten.id', 'al.tenant_id')
    .select('al.*', db.raw('COALESCE(d.display_name, d.hostname) as device_name'), 'ten.name as tenant_name', resourceNameSelect())
    .limit(limit)
    .offset(p.beforeSeq ? 0 : offset);
  if (p.tenantId !== null) q.orderBy('al.chain_seq', 'desc');
  else q.orderBy([{ column: 'al.created_at', order: 'desc' }, { column: 'al.id', order: 'desc' }]);
  const rows = await q;
  const items = await withLabels(rows);
  const nextBeforeSeq = p.tenantId !== null && items.length === limit ? items[items.length - 1].chainSeq : null;
  return { items, total, nextBeforeSeq };
}

/** Actions present in the scope (filter of the console). */
export async function distinctActions(tenantId: number | null): Promise<string[]> {
  const q = db('audit_logs').distinct('action').orderBy('action', 'asc');
  if (tenantId !== null) q.where({ tenant_id: tenantId });
  return (await q).map((r: { action: string }) => r.action);
}

/** Device timeline (config_change): the entries of a device in its tenant. */
export async function entriesOfDevice(deviceId: number, tenantId: number, limit = 50): Promise<AuditEntryDto[]> {
  const rows = await db('audit_logs as al')
    .leftJoin('devices as d', deviceOfEntryTenant)
    .where({ 'al.device_id': deviceId, 'al.tenant_id': tenantId })
    .select('al.*', db.raw('COALESCE(d.display_name, d.hostname) as device_name'), resourceNameSelect())
    .orderBy('al.chain_seq', 'desc')
    .limit(limit);
  return withLabels(rows);
}

// ── Seals ───────────────────────────────────────────────────────────────────

type SealJoin = {
  seal_seq: string | number; sealed_at: Date; leaf_count: number; merkle_root: Buffer; prev_seal_hash: Buffer; seal_hash: Buffer;
  key_id: string; signature: Buffer; tsa_status: 'ok' | 'disabled' | 'failed'; tsa_gen_time: Date | null;
  leaf_index?: number; chain_seq?: string | number; chain_hash?: Buffer; proof?: Buffer[];
};

export function sealToDto(s: SealJoin): AuditSealDto {
  return {
    seq: Number(s.seal_seq),
    sealedAt: iso(s.sealed_at),
    leaves: Number(s.leaf_count),
    root: hex(s.merkle_root),
    prev: hex(s.prev_seal_hash),
    hash: hex(s.seal_hash),
    keyId: s.key_id,
    signature: hex(s.signature),
    tsa: { status: s.tsa_status, genTime: s.tsa_gen_time ? iso(s.tsa_gen_time) : null },
    leaf: s.chain_seq !== undefined && s.chain_seq !== null ? {
      index: Number(s.leaf_index), seq: Number(s.chain_seq), hash: hex(s.chain_hash),
      proof: (s.proof ?? []).map((p) => Buffer.from(p).toString('hex')),
    } : null,
  };
}

const SEAL_COLUMNS = ['s.seal_seq', 's.sealed_at', 's.leaf_count', 's.merkle_root', 's.prev_seal_hash', 's.seal_hash', 's.key_id',
  's.signature', 's.tsa_status', 's.tsa_gen_time'];

/** The first seal whose leaf of `tenantId` covers `seq`, with its proof. */
export async function coveringSeal(tenantId: number, seq: number): Promise<AuditSealDto | null> {
  const r = await db('audit_seal_leaves as l').join('audit_seals as s', 's.id', 'l.seal_id')
    .where('l.tenant_id', tenantId).andWhere('l.chain_seq', '>=', seq)
    .orderBy([{ column: 'l.chain_seq', order: 'asc' }, { column: 's.seal_seq', order: 'asc' }])
    .first(...SEAL_COLUMNS, 'l.leaf_index', 'l.chain_seq', 'l.chain_hash', 'l.proof') as SealJoin | undefined;
  return r ? sealToDto(r) : null;
}

/** Seals whose leaf of the tenant falls in [fromSeq, toSeq], plus the first
 *  one after toSeq (it covers the last entries). Without a tenant (global
 *  view, no filter): the seals alone. */
export async function sealsOf(tenantId: number | null, fromSeq = 1, toSeq?: number, limit = 200): Promise<AuditSealDto[]> {
  if (tenantId === null) {
    const rows = await db('audit_seals as s').orderBy('s.seal_seq', 'desc').limit(limit).select(...SEAL_COLUMNS) as SealJoin[];
    return rows.map(sealToDto);
  }
  const q = db('audit_seal_leaves as l').join('audit_seals as s', 's.id', 'l.seal_id')
    .where('l.tenant_id', tenantId).andWhere('l.chain_seq', '>=', fromSeq)
    .orderBy('s.seal_seq', 'asc').limit(limit)
    .select(...SEAL_COLUMNS, 'l.leaf_index', 'l.chain_seq', 'l.chain_hash', 'l.proof');
  if (toSeq !== undefined) q.andWhere('l.chain_seq', '<=', toSeq);
  const rows = await q as SealJoin[];
  if (toSeq !== undefined) {
    const after = await db('audit_seal_leaves as l').join('audit_seals as s', 's.id', 'l.seal_id')
      .where('l.tenant_id', tenantId).andWhere('l.chain_seq', '>', toSeq)
      .orderBy('l.chain_seq', 'asc').first(...SEAL_COLUMNS, 'l.leaf_index', 'l.chain_seq', 'l.chain_hash', 'l.proof') as SealJoin | undefined;
    if (after && !rows.some((r) => Number(r.seal_seq) === Number(after.seal_seq))) rows.push(after);
  }
  return rows.map(sealToDto);
}

// ── Detail, status, verifications ───────────────────────────────────────────

export async function entryDetail(uuid: string, tenantId: number | null): Promise<AuditEntryDetailDto | null> {
  const q = db('audit_logs as al')
    .leftJoin('devices as d', deviceOfEntryTenant)
    .leftJoin('tenants as ten', 'ten.id', 'al.tenant_id')
    .where('al.uuid', uuid)
    .select('al.*', db.raw('COALESCE(d.display_name, d.hostname) as device_name'), 'ten.name as tenant_name', resourceNameSelect());
  if (tenantId !== null) q.andWhere('al.tenant_id', tenantId);
  const row = await q.first();
  if (!row) return null;
  const [dto] = await withLabels([row]);
  return {
    ...dto,
    body: String(row.body),
    prevHash: hex(row.prev_hash),
    hash: hex(row.hash),
    seal: await coveringSeal(Number(row.tenant_id), Number(row.chain_seq)),
  };
}

export async function chainStatus(tenantId: number): Promise<AuditChainStatus> {
  const head = await db('audit_chain_heads').where({ tenant_id: tenantId }).first('last_seq', 'last_hash', 'last_appended_at') as
    { last_seq: string | number; last_hash: Buffer; last_appended_at: Date | null } | undefined;
  const anchor = await db('audit_chain_anchors').where({ tenant_id: tenantId }).first('anchor_seq', 'anchor_hash', 'purged_at') as
    { anchor_seq: string | number; anchor_hash: Buffer; purged_at: Date } | undefined;
  const ret = await db('audit_retention').where({ tenant_id: tenantId }).first() as Record<string, any> | undefined;
  const inForce = Number((await db.raw('SELECT obligarth.audit_retention_months(?) AS m', [tenantId]) as { rows: Array<{ m: number }> }).rows[0]?.m ?? 12);
  const seal = await db('audit_seal_leaves as l').join('audit_seals as s', 's.id', 'l.seal_id')
    .where('l.tenant_id', tenantId).orderBy('s.seal_seq', 'desc')
    .first('s.seal_seq', 's.sealed_at', 'l.chain_seq', 's.tsa_status') as
    { seal_seq: string | number; sealed_at: Date; chain_seq: string | number; tsa_status: 'ok' | 'disabled' | 'failed' } | undefined;
  const ver = await db('audit_verifications').where({ tenant_id: tenantId }).orderBy('id', 'desc')
    .first('started_at', 'kind', 'status', 'entries') as { started_at: Date; kind: string; status: 'running' | 'ok' | 'broken' | 'error'; entries: string | number } | undefined;
  return {
    tenantId,
    head: head ? { seq: Number(head.last_seq), hash: hex(head.last_hash), appendedAt: head.last_appended_at ? iso(head.last_appended_at) : null } : null,
    anchor: anchor ? { seq: Number(anchor.anchor_seq), hash: hex(anchor.anchor_hash), purgedAt: iso(anchor.purged_at) } : null,
    retention: {
      months: Number(ret?.months ?? 12),
      effectiveMonths: inForce,
      pendingMonths: ret?.pending_months != null && ret?.pending_effective_at && new Date(ret.pending_effective_at).getTime() > Date.now()
        ? Number(ret.pending_months) : null,
      pendingEffectiveAt: ret?.pending_effective_at && new Date(ret.pending_effective_at).getTime() > Date.now() ? iso(ret.pending_effective_at) : null,
      justification: ret?.justification ?? null,
      legalHoldUntil: ret?.legal_hold_until && new Date(ret.legal_hold_until).getTime() > Date.now() ? iso(ret.legal_hold_until) : null,
      legalHoldReason: ret?.legal_hold_until && new Date(ret.legal_hold_until).getTime() > Date.now() ? ret.legal_hold_reason ?? null : null,
    },
    lastSeal: seal ? { seq: Number(seal.seal_seq), sealedAt: iso(seal.sealed_at), coveredSeq: Number(seal.chain_seq), tsaStatus: seal.tsa_status } : null,
    lastVerification: ver ? { at: iso(ver.started_at), kind: ver.kind, status: ver.status, entries: Number(ver.entries) } : null,
  };
}

export async function verificationsOf(tenantId: number, limit = 20): Promise<AuditVerificationDto[]> {
  const rows = await db('audit_verifications').where({ tenant_id: tenantId }).orderBy('id', 'desc')
    .limit(Math.min(200, Math.max(1, limit))) as Array<Record<string, any>>;
  return rows.map((r) => ({
    id: Number(r.id),
    tenantId: Number(r.tenant_id),
    kind: r.kind,
    status: r.status,
    fromSeq: r.from_seq != null ? Number(r.from_seq) : null,
    toSeq: r.to_seq != null ? Number(r.to_seq) : null,
    entries: Number(r.entries),
    seals: Number(r.seals),
    problem: parseJson(r.problem),
    startedAt: iso(r.started_at),
    finishedAt: r.finished_at ? iso(r.finished_at) : null,
  }));
}
