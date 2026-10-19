import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { withTenantTransaction } from '../../db/tenantContext';
import { logger } from '../../utils/logger';
import { edgeActorOf } from '../actors';
import { raiseCountedInTx, raiseMasterInTx, resolveInTx, resolveMasterInTx } from '../alerts/service';
import { deviceEvents } from '../devices/events';
import { sendUnenrollCleanup } from '../devices/jobs';
import { onUnenrolled } from '../devices/lifecycle';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import type { EdgeEnrollment, EdgeTenantInfo } from '../edge/wire';
import { reconcileAdeServers } from '../integrations/ade';
import { applyPushActivation } from '../integrations/push';
import { appleMetrics } from '../metrics';
import { realtime } from '../realtime';
import { upsertMirror, recordDeviceCaDeadline, type EdgeMirrorState } from '../tenants/registry';

// =============================================================================
// Reconciliation of one tenant with apple-edge (docs: integration-apple-edge
// §13.1; apple-edge §5.9; modele DM25), run by apple-edge.reconcile-tenant and
// by apple-edge.restore-check. Every call to apple-edge happens between two
// transactions (T-1), in the tenant's context only:
//   1. tenant: getTenant → mirror (state, freeze, active and verify-only CAs),
//      platform alerts (tenant.edge_missing, platform.tenant_load_failed);
//   2. enrollments: an incremental pass (seen since the last successful
//      reconciliation minus 30 minutes) or a full pass (at start, after a
//      restore, each night):
//        - enabled at apple-edge, unknown to the brain: no record (DM25: the
//          ownership is never guessed); the aggregated alert
//          enrollment.unknown_session, the operator attaches the enrollment to
//          an enrollment profile or releases it (unknown.ts);
//        - known, another certificate created after the record's Authenticate:
//          a new cycle the brain cannot open without its enrollment session
//          (the session's ownership is never guessed either): the record leaves
//          management ('superseded') and the enrollment is counted unknown, to
//          be attached or released (gap noted in the specification);
//        - a record under management whose enrollment is disabled or missing at
//          apple-edge (full pass only): onUnenrolled('disabled_in_edge');
//        - a more recent last_seen_at at apple-edge: the maximum copied.
//      An enrollment with an event still waiting in the outbox is left to the
//      consumer (the event will say it);
//   3. integrations: the ADE mirror (reconcileAdeServers) and the active push
//      certificate (applyPushActivation, matched by edge_cert_id);
//   4. tenant_apple_edge.last_synced_at, obligarth_apple_reconcile_fixes_total.
// Never a device identifier in a log, an alert or a metric (T-5).
// =============================================================================

/** The incremental pass looks this far before the last successful reconciliation. */
export const INCREMENTAL_OVERLAP_MS = 30 * 60_000;
const PAGE = 500;
const ENROLLMENT_ID_RE = /^[a-km-np-z2-9]{16}_[A-Za-z0-9._-]{1,128}$/;
const MANAGED = new Set(['enrolling', 'awaiting_configuration', 'enrolled']);

export type ReconcileFixKind = 'tenant_mirror' | 'unknown_enrollment' | 'superseded' | 'disabled_in_edge' | 'last_seen'
  | 'ade_mirror' | 'push_mirror' | 'missing_in_edge';

export type ReconcileCounts = Partial<Record<ReconcileFixKind, number>>;

export interface ReconcileOptions {
  full: boolean;
  actor: DbActor;
  requestId?: string;
  signal?: AbortSignal;
}

export interface ReconcileResult {
  outcome: 'done' | 'skipped' | 'missing' | 'not_live';
  full: boolean;
  enrollments: number;
  unknown: number;
  fixes: ReconcileCounts;
}

function add(c: ReconcileCounts, kind: ReconcileFixKind, n = 1): void {
  if (n > 0) c[kind] = (c[kind] ?? 0) + n;
}

const time = (v: unknown): number => (v instanceof Date ? v.getTime() : v ? new Date(String(v)).getTime() : Number.NaN);

/** The enrollments of the tenant with an event not yet consumed (the outbox, read through the guarded function
 *  obligarth.edge_outbox_pending_enrollments: the key of the tenant of the context, or a job's, INT-B1-R9 B). */
export async function pendingEnrollments(key: string): Promise<Set<string>> {
  try {
    const r = await db.raw('SELECT e AS enrollment_id FROM obligarth.edge_outbox_pending_enrollments(?) e', [key]) as
      { rows: Array<{ enrollment_id: string }> };
    return new Set(r.rows.map((x) => String(x.enrollment_id)));
  } catch (err) {
    const code = (err as { code?: unknown })?.code;
    if (code === '42P01' || code === '3F000') return new Set();      // no outbox in this database (a test bench)
    throw err;
  }
}

/** Every enrollment of the tenant at apple-edge (all pages), device channel only. */
export async function listAll(key: string, seenSince: Date | null, o: ReconcileOptions): Promise<EdgeEnrollment[]> {
  const out: EdgeEnrollment[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < 10_000; i++) {
    o.signal?.throwIfAborted();
    const page = await appleEdge.listEnrollments(key, { cursor, limit: PAGE, ...(seenSince ? { seenSince } : {}) },
      { actor: edgeActorOf(o.actor), requestId: o.requestId, signal: o.signal });
    for (const e of page.items) {
      if (!e.enrollment_id.startsWith(`${key}_`) || e.enrollment_id.includes(':') || !ENROLLMENT_ID_RE.test(e.enrollment_id)) continue;
      out.push(e);
    }
    if (!page.nextCursor || page.items.length === 0) break;
    cursor = page.nextCursor;
  }
  return out;
}

interface RecordRow {
  device_id: number;
  enrollment_id: string;
  cert_sha256: string | null;
  authenticated_at: Date;
  enrollment_state: string;
  last_checkin_at: Date | null;
}

/** 1. The tenant's mirror from getTenant. */
async function mirrorTenant(tenantId: number, info: EdgeTenantInfo, o: ReconcileOptions, c: ReconcileCounts): Promise<void> {
  const active = info.cas.find((x) => x.status === 'active') ?? null;
  const state: EdgeMirrorState = info.load_failed ? 'load_failed'
    : (['active', 'suspended', 'retiring', 'retired'].includes(info.state) ? info.state : 'error') as EdgeMirrorState;
  await withTenantTransaction(tenantId, o.actor, async (trx) => {
    const before = await trx('tenant_apple_edge').where({ tenant_id: tenantId }).first('edge_state', 'commands_frozen', 'ca_id') as
      { edge_state: string; commands_frozen: boolean; ca_id: string | null } | undefined;
    const changed = !before || before.edge_state !== state || before.commands_frozen !== info.commands_frozen
      || (active && String(before.ca_id ?? '') !== active.id);
    await upsertMirror(trx, tenantId, {
      edge_state: state, ...(changed ? { edge_state_at: new Date() } : {}), commands_frozen: info.commands_frozen,
      ...(active ? { ca: active } : {}),
      verify_only: info.cas.filter((x) => x.status === 'verify_only').map((x) => ({ id: x.id, sha256: x.sha256, not_after: x.not_after })),
    });
    if (active) await recordDeviceCaDeadline(trx, tenantId, active);
    if (changed) add(c, 'tenant_mirror');
    const name = await tenantName(trx, tenantId);
    await resolveMasterInTx(trx, 'tenant.edge_missing', tenantId, o.actor, tenantId);
    if (info.load_failed) {
      await raiseMasterInTx(trx, 'platform.tenant_load_failed', { discriminant: tenantId, params: { tenantName: name } }, o.actor, tenantId);
    } else {
      await resolveMasterInTx(trx, 'platform.tenant_load_failed', tenantId, o.actor, tenantId);
    }
  });
}

async function tenantName(q: Knex | Knex.Transaction, tenantId: number): Promise<string> {
  const row = await q('tenants').where({ id: tenantId }).first('name') as { name: string } | undefined;
  return row?.name ?? `#${tenantId}`;
}

/** The tenant is unknown at apple-edge: mirror 'missing', tenant.edge_missing. */
export async function markEdgeMissing(tenantId: number, actor: DbActor): Promise<void> {
  await withTenantTransaction(tenantId, actor, async (trx) => {
    await upsertMirror(trx, tenantId, { edge_state: 'missing', edge_state_at: new Date(), last_error_code: 'tenant_not_found' });
    await raiseMasterInTx(trx, 'tenant.edge_missing', { discriminant: tenantId, params: { tenantName: await tenantName(trx, tenantId) } }, actor, tenantId);
  });
}

/** 3. The active push certificate of apple-edge in the push mirror. */
async function mirrorPush(tenantId: number, info: EdgeTenantInfo, o: ReconcileOptions, c: ReconcileCounts): Promise<void> {
  const active = info.push_certificates.find((p) => p.state === 'active' && p.topic && p.not_after);
  if (!active || !active.topic || !active.not_after) return;
  const topic = active.topic;
  const notAfter = new Date(active.not_after);
  if (Number.isNaN(notAfter.getTime()) || !topic.startsWith('com.apple.mgmt.')) return;
  const certId = /^[0-9a-f-]{36}$/i.test(active.id) ? active.id.toLowerCase() : null;
  const changed = await withTenantTransaction(tenantId, o.actor, async (trx) => {
    const current = await trx('tenant_apple_push').where({ tenant_id: tenantId, state: 'active' }).first('id', 'topic', 'not_after', 'edge_cert_id') as
      { id: string; topic: string | null; not_after: Date | null; edge_cert_id: string | null } | undefined;
    if (current && current.topic === topic && time(current.not_after) === notAfter.getTime()
      && (!certId || !current.edge_cert_id || current.edge_cert_id === certId)) return false;
    const preferred = certId ? await trx('tenant_apple_push').where({ tenant_id: tenantId, edge_cert_id: certId }).first('id') as { id: string } | undefined : undefined;
    const at = active.activated_at ? new Date(active.activated_at) : new Date();
    const r = await applyPushActivation(trx, tenantId, { topic, certSha256: null, notAfter }, Number.isNaN(at.getTime()) ? new Date() : at,
      preferred ? { preferredId: preferred.id } : { importRow: true });
    if (r && certId) {
      await trx('tenant_apple_push').where({ tenant_id: tenantId, state: 'active' }).whereNull('edge_cert_id').update({ edge_cert_id: certId });
    }
    return r !== null;
  });
  if (changed) {
    add(c, 'push_mirror');
    realtime.integrationChanged(tenantId, 'push', 'deadlines');
  }
}

/** Raises (or raises the count of) enrollment.unknown_session to at least `n` (§13.1, aggregated alert). */
export async function raiseUnknownAtLeast(trx: Knex.Transaction, tenantId: number, n: number): Promise<number> {
  if (n <= 0) return 0;
  const open = await trx('live_alerts').where({ tenant_id: tenantId, stable_key: 'apple:enrollment.unknown_session' }).whereNull('resolved_at')
    .orderBy('id', 'desc').first('i18n_params') as { i18n_params: Record<string, unknown> | null } | undefined;
  const current = Number(open?.i18n_params?.count ?? 0);
  const increment = n - (Number.isFinite(current) ? current : 0);
  if (increment <= 0) return 0;
  await raiseCountedInTx(trx, tenantId, 'enrollment.unknown_session', { at: new Date(), eventId: randomUUID(), increment },
    { navigateTo: '/device-enrollment' });
  return increment;
}

/** 2. The enrollments of the tenant against its records. */
async function reconcileEnrollments(tenantId: number, key: string, since: Date | null, o: ReconcileOptions, c: ReconcileCounts):
  Promise<{ enrollments: number; unknown: number }> {
  const listedAt = new Date();
  const list = await listAll(key, o.full ? null : since, o);
  const pending = await pendingEnrollments(key);
  const records = await asTenant(tenantId, o.actor, () => db('apple_devices as a')
    .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where('a.tenant_id', tenantId)
    .select('a.device_id', 'a.enrollment_id', 'a.cert_sha256', 'a.authenticated_at', 'd.enrollment_state', 'd.last_checkin_at')) as RecordRow[];
  const byEnrollment = new Map(records.map((r) => [String(r.enrollment_id), r]));
  const seen = new Set<string>();
  let unknown = 0;
  const superseded: number[] = [];
  const disabled: number[] = [];
  const lastSeen: Array<{ deviceId: number; at: Date }> = [];
  for (const e of list) {
    seen.add(e.enrollment_id);
    if (pending.has(e.enrollment_id)) continue;                         // the consumer will say it
    const r = byEnrollment.get(e.enrollment_id);
    if (!r) {
      if (e.enabled) unknown += 1;
      continue;
    }
    const certNow = e.cert_sha256 ? e.cert_sha256.toLowerCase() : null;
    const certRec = r.cert_sha256 ? String(r.cert_sha256).trim().toLowerCase() : null;
    const created = time(e.created_at);
    if (e.enabled && certNow && certRec && certNow !== certRec && created > time(r.authenticated_at)) {
      if (MANAGED.has(r.enrollment_state)) superseded.push(Number(r.device_id));
      unknown += 1;
      continue;
    }
    if (!e.enabled && o.full && MANAGED.has(r.enrollment_state) && time(r.authenticated_at) < listedAt.getTime()) {
      disabled.push(Number(r.device_id));
      continue;
    }
    const seenAt = time(e.last_seen_at);
    if (e.enabled && Number.isFinite(seenAt) && (r.last_checkin_at === null || seenAt > time(r.last_checkin_at))) {
      lastSeen.push({ deviceId: Number(r.device_id), at: new Date(seenAt) });
    }
  }
  // A record under management whose enrollment apple-edge no longer holds (full pass: the whole list was read).
  if (o.full) {
    for (const r of records) {
      if (seen.has(String(r.enrollment_id)) || pending.has(String(r.enrollment_id))) continue;
      if (MANAGED.has(r.enrollment_state) && time(r.authenticated_at) < listedAt.getTime()) disabled.push(Number(r.device_id));
    }
  }

  const changedDevices: number[] = [];
  const now = new Date();
  if (superseded.length > 0 || disabled.length > 0 || unknown > 0 || lastSeen.length > 0) {
    await withTenantTransaction(tenantId, o.actor, async (trx) => {
      const departures: Array<[number, 'superseded' | 'disabled_in_edge']> = [
        ...superseded.map((d): [number, 'superseded'] => [d, 'superseded']),
        ...disabled.map((d): [number, 'disabled_in_edge'] => [d, 'disabled_in_edge']),
      ];
      for (const [deviceId, reason] of departures.sort((a, b) => a[0] - b[0])) {
        const rec = records.find((x) => Number(x.device_id) === deviceId) as RecordRow;
        const r = await onUnenrolled(trx, tenantId, String(rec.enrollment_id), reason, now, randomUUID());
        if (r.outcome !== 'unenrolled') continue;
        const left = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).first('unenrolled_at') as { unenrolled_at: Date | null } | undefined;
        await deviceEvents.add(trx, tenantId, deviceId, 'released', now, null, { reason, source: 'reconcile' });
        await sendUnenrollCleanup(trx, tenantId, deviceId, left?.unenrolled_at ? new Date(left.unenrolled_at) : now);
        add(c, reason);
        changedDevices.push(deviceId);
      }
      if (lastSeen.length > 0) {
        const ids = lastSeen.map((x) => x.deviceId);
        const ats = lastSeen.map((x) => x.at.toISOString());
        const res = await trx.raw(`
          WITH s AS (SELECT * FROM unnest(?::int[], ?::timestamptz[]) AS u(device_id, seen)),
               l AS (SELECT d.id, s.seen FROM obligarth.devices d JOIN s ON s.device_id = d.id
                      WHERE d.tenant_id = ? AND (d.last_checkin_at IS NULL OR d.last_checkin_at < s.seen)
                      ORDER BY d.id FOR NO KEY UPDATE OF d)
          UPDATE obligarth.devices d SET last_checkin_at = l.seen FROM l WHERE d.id = l.id AND d.tenant_id = ?
          RETURNING d.id`, [ids, ats, tenantId, tenantId]) as { rows: unknown[] };
        add(c, 'last_seen', res.rows.length);
      }
      if (unknown > 0) {
        // Counted as a correction only when the alert learns of more of them (a later pass finds them again).
        add(c, 'unknown_enrollment', await raiseUnknownAtLeast(trx, tenantId, unknown));
      } else if (o.full) {
        // A full pass found none: the aggregated alert has nothing left to attach or release.
        await resolveInTx(trx, tenantId, 'enrollment.unknown_session');
      }
    });
  } else if (o.full) {
    await withTenantTransaction(tenantId, o.actor, (trx) => resolveInTx(trx, tenantId, 'enrollment.unknown_session'));
  }
  if (changedDevices.length > 0) realtime.deviceChanged(tenantId, ...changedDevices);
  return { enrollments: list.length, unknown };
}

/**
 * One tenant reconciled. `full`: the full pass of the enrollments. Errors of apple-edge propagate (the job retries),
 * except tenant_not_found (mirror 'missing', alert) and tenant_not_live (retired at apple-edge).
 */
export async function reconcileTenant(tenantId: number, o: ReconcileOptions): Promise<ReconcileResult> {
  const startedAt = new Date();
  const fixes: ReconcileCounts = {};
  const t = await asTenant(tenantId, o.actor, () => db('tenants as t').leftJoin('tenant_apple_edge as m', 'm.tenant_id', 't.id')
    .where('t.id', tenantId).first('t.mdm_key', 'm.last_synced_at', 'm.edge_state')) as
    { mdm_key: string | null; last_synced_at: Date | null; edge_state: string | null } | undefined;
  if (!t?.mdm_key) return { outcome: 'skipped', full: o.full, enrollments: 0, unknown: 0, fixes };
  const key = t.mdm_key;
  const opts = { actor: edgeActorOf(o.actor), requestId: o.requestId, signal: o.signal };

  // 1. The tenant.
  let info: EdgeTenantInfo;
  try {
    info = await appleEdge.getTenant(key, opts);
  } catch (err) {
    if (isAppleEdgeError(err) && err.code === 'tenant_not_found') {
      await markEdgeMissing(tenantId, o.actor);
      add(fixes, 'tenant_mirror');
      return { outcome: 'missing', full: o.full, enrollments: 0, unknown: 0, fixes };
    }
    throw err;
  }
  await mirrorTenant(tenantId, info, o, fixes);
  if (info.state === 'retired') return { outcome: 'not_live', full: o.full, enrollments: 0, unknown: 0, fixes };

  // 2. The enrollments.
  const since = !o.full && t.last_synced_at ? new Date(new Date(t.last_synced_at).getTime() - INCREMENTAL_OVERLAP_MS) : null;
  const full = o.full || since === null;
  const e = await reconcileEnrollments(tenantId, key, since, { ...o, full }, fixes);

  // 3. The integrations.
  try {
    // In the tenant's context: a job's handler runs outside of it (integration of lot C: the mirror read nothing and
    // its insert was refused by the row level security, so the job failed whenever the tenant had an ADE server).
    const ade = await asTenant(tenantId, o.actor, () => reconcileAdeServers(tenantId, key, o.actor));
    add(fixes, 'ade_mirror', ade.updated + ade.added + ade.removed);
    if (ade.updated + ade.added + ade.removed > 0) realtime.integrationChanged(tenantId, 'ade');
  } catch (err) {
    if (!isAppleEdgeError(err)) throw err;
    logger.warn({ tenantId, code: err.code }, 'reconciliation: ADE servers not read');
  }
  await mirrorPush(tenantId, info, o, fixes);

  // 4. The mark and the metrics.
  await withTenantTransaction(tenantId, o.actor, (trx) => upsertMirror(trx, tenantId, { last_synced_at: startedAt, last_error_code: null }));
  for (const [kind, n] of Object.entries(fixes)) appleMetrics.reconcileFix(kind, n as number);
  return { outcome: 'done', full, enrollments: e.enrollments, unknown: e.unknown, fixes };
}

/** apple-edge's tenants against the brain's (reconcile-all, first step): orphans and missing keys. */
export async function compareTenants(actor: DbActor, o: { requestId?: string; signal?: AbortSignal }):
  Promise<{ withKey: number[]; orphans: number; missing: number }> {
  const edge: Array<{ key: string; external_ref: string; state: string }> = [];
  let cursor: string | undefined;
  for (let i = 0; i < 1_000; i++) {
    const page = await appleEdge.listTenants({ cursor, limit: 500 }, { actor: edgeActorOf(actor), requestId: o.requestId, signal: o.signal });
    edge.push(...page.items);
    if (!page.nextCursor || page.items.length === 0) break;
    cursor = page.nextCursor;
  }
  const brain = await db('tenants').select('id', 'uuid', 'mdm_key').orderBy('id') as Array<{ id: number; uuid: string; mdm_key: string | null }>;
  const keys = new Set(brain.map((b) => b.mdm_key).filter((k): k is string => !!k));
  const refs = new Set(brain.map((b) => String(b.uuid).toLowerCase()));
  const edgeKeys = new Set(edge.map((x) => x.key));
  let orphans = 0;
  for (const x of edge) {
    if (keys.has(x.key) || refs.has(String(x.external_ref).toLowerCase()) || x.state === 'retired') continue;
    if (!/^[a-km-np-z2-9]{16}$/.test(x.key)) continue;
    orphans += 1;
    await withTenantTransaction(MASTER_TENANT_ID, actor, (trx) => raiseMasterInTx(trx, 'platform.edge_orphan',
      { discriminant: x.key, params: { key: x.key } }, actor, MASTER_TENANT_ID));
  }
  const withKey: number[] = [];
  let missing = 0;
  for (const b of brain) {
    if (!b.mdm_key) continue;
    if (!edgeKeys.has(b.mdm_key)) {
      missing += 1;
      await markEdgeMissing(Number(b.id), actor);
      continue;
    }
    withKey.push(Number(b.id));
  }
  return { withKey, orphans, missing };
}
