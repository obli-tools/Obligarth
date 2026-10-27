import type { Knex } from 'knex';
import {
  SocketEvents, dirtyReasonsMeet, smartGroupGuardDecision, validateRule,
  type RuleNode, type SmartGroupChangedEvent, type SmartGroupState,
} from '@obligarth/shared';
import { db } from '../../db';
import { withTenantTransaction } from '../../db/tenantContext';
import type { DbActor } from '../../db/context';
import type { JobContext } from '../../jobs';
import { getIO } from '../../socket';
import { logger } from '../../utils/logger';
import { raiseInTx } from '../../apple/alerts/service';
import { retryOnDeadlock } from '../policies/jobs';
import { requestDeviceResolution } from '../policies/triggers';
import { loadRulePrivacy, type RulePrivacy } from '../rules/facts';
import { computeMembers, previewRule, readsPrivacy, type MembershipChange } from './smartGroupService';

// =============================================================================
// Incremental computation of the dynamic groups (P0-5 T5, §4.3; D4, D9). In the tenant's context (RLS: one tenant).
//   - evaluateTenant (queue mdm.groups.evaluate, jobs.ts): the devices marked by the triggers (smart_group_dirty,
//     migration p05_smart_group_marking), by slices of 500, each slice in its own transaction:
//       1. dequeued: DELETE … RETURNING of the oldest markings nobody holds (FOR UPDATE SKIP LOCKED); a slice that
//          fails rolls back with its dequeue (the markings come back);
//       2. the groups active or held of the tenant whose families (rule_fields) meet the reasons of the slice ('new'
//          meets them all), their rows held (FOR NO KEY UPDATE, in id order: a change of the rule holds its row FOR
//          UPDATE, so a computation never mixes two rules; the counters are written by the slice);
//       3. each active group computed again on the devices of the slice whose reasons meet its families
//          (computeMembers: entries, exits, journal cause 'inventory'; never a device out of management, D9);
//       4. the mass guard (D4) for a group an assignment targets: beyond max(25, 10 % of the managed devices)
//          entries and exits within the hour, nothing is written (the computation runs under a savepoint, rolled
//          back), the group goes to 'held' with its pending changes, alert smart_group.mass_change;
//       5. the devices whose membership of a targeted group changed are resolved again (requestDeviceResolution in
//          the slice's transaction: the tenant's beyond 50);
//       6. once committed: SMART_GROUP_CHANGED { smartGroupIds } to the tenant's room (identifiers only).
//     A held group is not computed: its pending changes are counted again once at the end of the run when a slice
//     met it. A group in error (its rule names a deleted static group, or the catalog no longer validates it) is
//     frozen. A stored rule the catalog no longer validates puts its group in error (rule_invalid) instead of failing
//     the queue.
//   - recomputeGroups (the hourly schedule, jobs.ts): the full computation of groups, each in its own transaction,
//     with the same guard for a targeted group.
// Never writes a row of devices and never takes the configuration lock (P0-5 §11); a slice chosen as the victim of a
// deadlock is played again alone (retryOnDeadlock).
// =============================================================================

/** Devices of a slice. */
export const DIRTY_SLICE = 500;

/** A run of the queue that dequeued more than this many slices yields: what is left is for the next job. */
const MAX_SLICES_PER_RUN = 400;

/** What a run reads once for all its slices (lazily: only when a group needs it). */
export interface EvaluationRun {
  tenantId: number;
  now: Date;
  /** The tenant's privacy context (compile.ts), loaded by the first group whose rule reads it. */
  privacy: RulePrivacy | null;
  /** The managed devices of the tenant (the mass guard), counted by the first targeted group. */
  managed: number | null;
  /** Held groups a slice met: their pending changes are counted again at the end of the run. */
  heldTouched: Set<number>;
}

export const newRun = (tenantId: number, now = new Date()): EvaluationRun =>
  ({ tenantId, now, privacy: null, managed: null, heldTouched: new Set() });

interface EvalGroup {
  id: number;
  name: string;
  rule: unknown;
  ruleVersion: number;
  families: string[];
  state: Extract<SmartGroupState, 'active' | 'held'>;
  windowStart: Date | null;
  windowChanges: number;
  memberCount: number;
  targeted: boolean;
}

/** The outcome of the computation of one group. */
export interface GroupOutcome {
  change: MembershipChange | null;
  /** Put in held by the mass guard (nothing written). */
  held: boolean;
  /** Put in error: its stored rule is no longer valid. */
  invalid: boolean;
}

const asObject = (v: unknown): unknown => (typeof v === 'string' ? JSON.parse(v) : v);
const pgIntArray = (ids: readonly number[]): string => `{${ids.map(Number).filter((n) => Number.isSafeInteger(n)).join(',')}}`;
const pgTextArray = (v: readonly string[]): string => `{${v.map((s) => `"${s.replace(/["\\]/g, '')}"`).join(',')}}`;

/** The groups whose families meet reasons, the groups of a list (one array binding each). The only text lockGroups adds. */
const MEET_SQL = ' AND g.rule_fields && ?::text[]';
const IDS_SQL = ' AND g.id = ANY(?::integer[])';

/** The groups of the tenant to compute (active and held; `reasons` given: those whose families meet them), their rows
 *  held for the computation, in id order. */
async function lockGroups(trx: Knex.Transaction, tenantId: number, reasons: readonly string[] | null, ids?: readonly number[]): Promise<EvalGroup[]> {
  const meet = reasons && !reasons.includes('new');
  const meetSql = meet ? MEET_SQL : '';
  const idsSql = ids ? IDS_SQL : '';
  const res = await trx.raw(`
    SELECT g.id, g.name, g.rule, g.rule_version, g.rule_fields, g.state, g.guard_window_start, g.guard_window_changes, g.member_count,
           EXISTS (SELECT 1 FROM assignments a
                    WHERE a.tenant_id = g.tenant_id AND a.target_scope = 'smart_group' AND a.target_id = g.id) AS targeted
      FROM smart_groups g
     WHERE g.tenant_id = ?::integer AND g.state IN ('active', 'held')${meetSql}${idsSql}
     ORDER BY g.id
       FOR NO KEY UPDATE OF g`, [tenantId, ...(meet ? [pgTextArray(reasons)] : []), ...(ids ? [pgIntArray(ids)] : [])]) as {
    rows: Array<{ id: number; name: string; rule: unknown; rule_version: number; rule_fields: string[] | null; state: 'active' | 'held';
      guard_window_start: Date | null; guard_window_changes: number; member_count: number; targeted: boolean }>;
  };
  return res.rows.map((r) => ({
    id: Number(r.id), name: r.name, rule: asObject(r.rule), ruleVersion: Number(r.rule_version), families: r.rule_fields ?? [],
    state: r.state, windowStart: r.guard_window_start ? new Date(r.guard_window_start) : null,
    windowChanges: Number(r.guard_window_changes), memberCount: Number(r.member_count), targeted: r.targeted === true,
  }));
}

/** The managed devices of the tenant (D4: the base of the mass guard), counted once per run. */
async function managedOf(trx: Knex.Transaction, run: EvaluationRun): Promise<number> {
  if (run.managed === null) {
    const r = await trx('devices').where({ tenant_id: run.tenantId }).whereNot('enrollment_state', 'unenrolled')
      .count<{ n: string }[]>('id as n').first();
    run.managed = Number(r?.n ?? 0);
  }
  return run.managed;
}

/** The tenant's privacy context, loaded once per run by the first rule that reads it. */
async function privacyOf(trx: Knex.Transaction, run: EvaluationRun, rule: RuleNode): Promise<RulePrivacy | undefined> {
  if (!readsPrivacy(rule)) return undefined;
  if (run.privacy === null) run.privacy = await loadRulePrivacy(trx, [run.tenantId]);
  return run.privacy;
}

/** The stop of a computation the mass guard refuses: rolls its savepoint back. */
class HeldByGuard extends Error {
  readonly change: MembershipChange;
  readonly limit: number;
  constructor(change: MembershipChange, limit: number) {
    super('held by the mass guard');
    this.change = change;
    this.limit = limit;
  }
}

/** A stored rule the catalog no longer validates: the group goes to error (rule_invalid), alert smart_group.rule_invalid. */
async function putInError(trx: Knex.Transaction, tenantId: number, g: EvalGroup): Promise<void> {
  await trx('smart_groups').where({ tenant_id: tenantId, id: g.id })
    .update({ state: 'error', state_reason: 'rule_invalid', state_since: trx.fn.now(), pending_added: 0, pending_removed: 0 });
  await raiseInTx(trx, tenantId, 'smart_group.rule_invalid', {
    discriminant: g.id, params: { name: g.name.slice(0, 200), smartGroupId: g.id }, navigateTo: `/groups/smart/${g.id}`,
  });
  logger.warn({ tenantId, smartGroupId: g.id }, 'dynamic group put in error: its stored rule is no longer valid');
}

/** The pending changes of a held group (its whole rule against its members), written on its row. */
async function writePending(trx: Knex.Transaction, run: EvaluationRun, g: { id: number; rule: RuleNode }): Promise<{ added: number; removed: number }> {
  const p = await previewRule(trx, run.tenantId, g.rule, g.id, null, await privacyOf(trx, run, g.rule));
  const out = { added: Number(p.added ?? 0), removed: Number(p.removed ?? 0) };
  await trx('smart_groups').where({ tenant_id: run.tenantId, id: g.id }).update({ pending_added: out.added, pending_removed: out.removed });
  return out;
}

/**
 * Computes a group again (its row held by the caller), on `deviceIds` (a slice) or the whole tenant, with the mass
 * guard for a targeted group. Writes the members, the journal (cause 'inventory'), member_count, computed_at and the
 * guard's window; or, beyond the guard, nothing but 'held', its pending changes and the alert.
 */
export async function computeGroup(trx: Knex.Transaction, run: EvaluationRun, g: EvalGroup, deviceIds?: readonly number[]): Promise<GroupOutcome> {
  const rule = g.rule as RuleNode;
  if (validateRule(rule).length > 0) {
    await putInError(trx, run.tenantId, g);
    return { change: null, held: false, invalid: true };
  }
  const opts = { deviceIds, now: run.now, privacy: await privacyOf(trx, run, rule) };
  const counters = (c: MembershipChange): Record<string, unknown> => ({
    member_count: deviceIds ? trx.raw('GREATEST(0, member_count + ?::integer)', [c.added.length - c.removed.length]) : c.total,
    computed_at: trx.fn.now(),
  });
  if (!g.targeted) {
    const change = await computeMembers(trx, run.tenantId, g.id, rule, 'inventory', opts);
    if (!deviceIds || change.added.length || change.removed.length) {
      await trx('smart_groups').where({ tenant_id: run.tenantId, id: g.id }).update(counters(change));
    }
    return { change, held: false, invalid: false };
  }
  const managed = await managedOf(trx, run);
  try {
    const change = await trx.transaction(async (sp) => {
      const c = await computeMembers(sp, run.tenantId, g.id, rule, 'inventory', opts);
      const n = c.added.length + c.removed.length;
      const d = smartGroupGuardDecision({ windowStart: g.windowStart, windowChanges: g.windowChanges, changes: n, managed, now: run.now });
      if (d.hold) throw new HeldByGuard(c, d.limit);
      if (n > 0 || !deviceIds) {
        await sp('smart_groups').where({ tenant_id: run.tenantId, id: g.id }).update({
          ...counters(c), ...(n > 0 ? { guard_window_start: d.windowStart, guard_window_changes: d.windowChanges } : {}),
        });
        g.windowStart = n > 0 ? d.windowStart : g.windowStart;
        g.windowChanges = n > 0 ? d.windowChanges : g.windowChanges;
      }
      return c;
    });
    return { change, held: false, invalid: false };
  } catch (err) {
    if (!(err instanceof HeldByGuard)) throw err;
    await trx('smart_groups').where({ tenant_id: run.tenantId, id: g.id })
      .update({ state: 'held', state_reason: 'mass_change', state_since: trx.fn.now() });
    // The pending changes on the group's row (counted again while it stays held; the alert names the group only).
    await writePending(trx, run, { id: g.id, rule });
    await raiseInTx(trx, run.tenantId, 'smart_group.mass_change', {
      discriminant: g.id, navigateTo: `/groups/smart/${g.id}`,
      params: { name: g.name.slice(0, 200), smartGroupId: g.id, limit: err.limit },
    });
    logger.warn({ tenantId: run.tenantId, smartGroupId: g.id, changes: err.change.added.length + err.change.removed.length, limit: err.limit },
      'dynamic group held by the mass guard');
    g.state = 'held';
    run.heldTouched.delete(g.id);
    return { change: null, held: true, invalid: false };
  }
}

/** The outcome of a slice. */
export interface SliceOutcome {
  /** Devices dequeued. */
  devices: number;
  /** Groups whose members changed. */
  changed: number[];
  /** Groups held by the guard in this slice. */
  held: number[];
  /** Devices whose membership of a targeted group changed (resolved again). */
  resolved: number;
}

/** A marking dequeued. */
export interface MarkedDevice {
  deviceId: number;
  reasons: string[];
}

/**
 * Dequeues the oldest `limit` markings of the tenant nobody holds (FOR UPDATE SKIP LOCKED: never waits on a trigger
 * writing a marking, nor on another slice), in `trx`: they are gone once it commits, back if it rolls back. A marking
 * written meanwhile for one of these devices waits for `trx`, then marks it again.
 */
export async function dequeueMarked(trx: Knex.Transaction, tenantId: number, limit = DIRTY_SLICE): Promise<MarkedDevice[]> {
  const res = await trx.raw(`
    DELETE FROM smart_group_dirty d
     USING (SELECT s.tenant_id, s.device_id FROM smart_group_dirty s
             WHERE s.tenant_id = ?::integer
             ORDER BY s.queued_at, s.device_id
             LIMIT ?::integer
               FOR UPDATE SKIP LOCKED) x
     WHERE d.tenant_id = x.tenant_id AND d.device_id = x.device_id
    RETURNING d.device_id, d.reasons`, [tenantId, limit]) as { rows: Array<{ device_id: number; reasons: string[] }> };
  return res.rows.map((r) => ({ deviceId: Number(r.device_id), reasons: r.reasons ?? [] }));
}

/** One slice of the queue, in `trx` (the tenant's context): null when nothing was left to dequeue. */
export async function evaluateSlice(trx: Knex.Transaction, run: EvaluationRun, limit = DIRTY_SLICE): Promise<SliceOutcome | null> {
  const dirty = await dequeueMarked(trx, run.tenantId, limit);
  if (dirty.length === 0) return null;
  const union = [...new Set(dirty.flatMap((d) => d.reasons))];
  const out: SliceOutcome = { devices: dirty.length, changed: [], held: [], resolved: 0 };
  const resolve = new Set<number>();
  for (const g of await lockGroups(trx, run.tenantId, union)) {
    const ids = dirty.filter((d) => dirtyReasonsMeet(d.reasons, g.families)).map((d) => d.deviceId);
    if (ids.length === 0) continue;
    if (g.state === 'held') { run.heldTouched.add(g.id); continue; }
    const r = await computeGroup(trx, run, g, ids);
    if (r.held) { out.held.push(g.id); continue; }
    if (!r.change || (r.change.added.length === 0 && r.change.removed.length === 0)) continue;
    out.changed.push(g.id);
    if (g.targeted) for (const id of [...r.change.added, ...r.change.removed]) resolve.add(id);
  }
  // What applies to a device follows its targeted groups (P0-5 T6: the resolution reads them).
  if (resolve.size > 0) {
    await requestDeviceResolution(trx, run.tenantId, [...resolve]);
    out.resolved = resolve.size;
  }
  return out;
}

/** SMART_GROUP_CHANGED to the tenant's room (identifiers only); never throws. */
export function emitGroupsChanged(tenantId: number, smartGroupIds: number[]): void {
  if (!smartGroupIds.length) return;
  const event: SmartGroupChangedEvent = { smartGroupIds: [...new Set(smartGroupIds)].sort((a, b) => a - b) };
  try {
    getIO().to(`tenant:${tenantId}`).emit(SocketEvents.SMART_GROUP_CHANGED, event);
  } catch { /* no Socket.io in this process */ }
}

/** The pending changes of the held groups a run met, counted again (one transaction). */
async function refreshHeld(ctx: Pick<JobContext<unknown>, 'withTenant'>, run: EvaluationRun): Promise<number> {
  if (run.heldTouched.size === 0) return 0;
  const ids = [...run.heldTouched];
  run.heldTouched.clear();
  return retryOnDeadlock(() => ctx.withTenant(async (trx) => {
    let n = 0;
    for (const g of await lockGroups(trx, run.tenantId, null, ids)) {
      if (g.state !== 'held' || validateRule(g.rule).length > 0) continue;
      await writePending(trx, run, { id: g.id, rule: g.rule as RuleNode });
      n++;
    }
    return n;
  }));
}

/** The outcome of a run of the queue. */
export interface EvaluationOutcome {
  slices: number;
  devices: number;
  changed: number[];
  held: number[];
  resolved: number;
  /** The run yielded with markings left (MAX_SLICES_PER_RUN). */
  more: boolean;
}

/**
 * The markings of the tenant, slice after slice, until none is left (or MAX_SLICES_PER_RUN: the caller sends the
 * next job). Each slice in its own transaction (ctx.withTenant), announced once committed.
 */
export async function evaluateTenant(ctx: Pick<JobContext<unknown>, 'withTenant' | 'throwIfAborted'>, tenantId: number,
  opts: { sliceSize?: number; maxSlices?: number } = {}): Promise<EvaluationOutcome> {
  const run = newRun(tenantId);
  const out: EvaluationOutcome = { slices: 0, devices: 0, changed: [], held: [], resolved: 0, more: false };
  const max = opts.maxSlices ?? MAX_SLICES_PER_RUN;
  for (;;) {
    ctx.throwIfAborted();
    if (out.slices >= max) { out.more = true; break; }
    run.now = new Date();
    const s = await retryOnDeadlock(() => ctx.withTenant((trx) => evaluateSlice(trx, run, opts.sliceSize ?? DIRTY_SLICE)));
    if (!s) break;
    out.slices++;
    out.devices += s.devices;
    out.held.push(...s.held);
    out.resolved += s.resolved;
    out.changed.push(...s.changed);
    emitGroupsChanged(tenantId, s.changed);
  }
  await refreshHeld(ctx, run);
  out.changed = [...new Set(out.changed)].sort((a, b) => a - b);
  return out;
}

/** Which groups the schedule computes in full: those that read a temporal field (never targeted: D2), or all of them
 *  (the nightly pass against the drift). */
export type RecomputeScope = 'temporal' | 'all';

/** The outcome of a full computation of groups. */
export interface RecomputeOutcome {
  groups: number;
  changed: number[];
  held: number[];
  pendingRefreshed: number;
}

/**
 * The full computation of the active groups of the tenant `scope` selects, each in its own transaction of the tenant
 * (as `actor`), with the guard for a targeted group; the pending changes of the held groups counted again. In the
 * tenant's database context (forEachTenant of the schedule).
 */
export async function recomputeGroups(tenantId: number, actor: DbActor, scope: RecomputeScope): Promise<RecomputeOutcome> {
  const tx = <T>(fn: (trx: Knex.Transaction) => Promise<T>): Promise<T> => retryOnDeadlock(() => withTenantTransaction(tenantId, actor, fn));
  const rows = await db('smart_groups').where({ tenant_id: tenantId }).whereIn('state', ['active', 'held'])
    .orderBy('id').select('id', 'state', 'rule_fields') as Array<{ id: number; state: string; rule_fields: string[] | null }>;
  const out: RecomputeOutcome = { groups: 0, changed: [], held: [], pendingRefreshed: 0 };
  const run = newRun(tenantId);
  for (const row of rows) {
    const id = Number(row.id);
    if (row.state === 'held') { run.heldTouched.add(id); continue; }
    if (scope === 'temporal' && !(row.rule_fields ?? []).includes('temporal')) continue;
    run.now = new Date();
    const r = await tx(async (trx) => {
      const [g] = await lockGroups(trx, tenantId, null, [id]);
      // Changed meanwhile (held, in error, deleted), or targeted while it reads a temporal field: left alone.
      if (!g || g.state !== 'active' || (scope === 'temporal' && g.targeted)) return null;
      const outcome = await computeGroup(trx, run, g);
      const moved = outcome.change ? [...outcome.change.added, ...outcome.change.removed] : [];
      if (g.targeted && moved.length > 0) await requestDeviceResolution(trx, tenantId, moved);
      return outcome;
    });
    if (!r) continue;
    out.groups++;
    if (r.held) out.held.push(id);
    else if (r.change && (r.change.added.length || r.change.removed.length)) out.changed.push(id);
  }
  emitGroupsChanged(tenantId, out.changed);
  out.pendingRefreshed = await refreshHeld({ withTenant: tx }, run);
  return out;
}
