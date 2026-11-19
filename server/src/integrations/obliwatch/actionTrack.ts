import type { Knex } from 'knex';
import type { ObliwatchAction, ObliwatchActionResult, ObliwatchActionState } from '@obligarth/shared';
import { OBLIWATCH_ACTION_FINAL_STATES } from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../../audit';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { guardedActionDef } from '../../guard';
import { actionEntry, executionContext } from '../../guard/executor';
import { cancelJob } from '../../guard/jobs';
import { findAction } from '../../guard/store';
import { lateCancelOf } from '../../guard/types';
import { mdmCommands } from '../../apple/commands';
import { cancelAndroidCommand } from '../../android/commands/bus';
import { logger } from '../../utils/logger';
import { requestActionResultsInTx } from './actionResults';
import { OBLIWATCH_ACTOR } from './config';
import { obliwatchActionsClosed } from './actionGate';

// =============================================================================
// The life of an action request of Obliwatch (brief GTH-04, GTH-05; lot L5): what the request became, read from what
// executes it, and each transition recorded (owner decision Q-L5a: no approval; the machine is accepted → executing →
// done | failed | refused | expired | cancelled, 'awaiting_approval' and 'approved' never used).
//   - a guarded action (path 'guard': lock, lost mode on) follows its pending_actions row (scheduled or paused:
//     accepted; executing: executing; refused, failed, cancelled, expired as such), then once dispatched the command of
//     its device: Apple and AMAPI in mdm_command_targets (mdm_commands.guard_action_uuid), the bridge agent in
//     legacy_agent_commands;
//   - a command of the queue (path 'command': lost mode off, location, sound) follows its target in
//     mdm_command_targets.
// A target acknowledged: done; error: failed; rejected: refused; expired: expired; cancelled: cancelled; still open:
// executing. A request still open 24 hours after it was made expires, and what it would still send to the device is
// withdrawn first (a guarded action not started is cancelled, a dispatched one gets the late cancellation of the guard
// engine; a command of the queue is cancelled), so that an expired request never acts later.
// Each transition, in ONE transaction of the tenant: the row (state, seq + 1, result, code; closed_at for a final
// state), its event (the outbox of GTH-05, actionResults.ts), the critical entry obliwatch.action.<verb> (prefix
// [Obliwatch, incident <ref>, requested by <user>]), and the drain job asked. Called by the minute step for the open
// requests of each tenant, and by GET /action-requests/:id for the one read (the poller of Obliwatch sees it at once).
// The result never holds a coordinate: device_location reads horizontal_accuracy of its position only (accuracy bucket).
// The gate (actionGate.ts: the switch and the tenant's consent to the actions) is checked again: closed, the open
// requests are withdrawn as at the expiry and closed 'cancelled' with integration_off or consent_revoked
// (closeOpenRequests: the consent route at once, the minute step, the cleanup step of modules/obliwatch.ts while the
// switch is off).
// =============================================================================

export const REQUEST_TTL_MS = 24 * 3600_000;

let clock: () => number = () => Date.now();
/** Tests: a simulated clock (the 24 hours of a request). */
export function _setActionTrackClockForTests(now: (() => number) | null): void { clock = now ?? (() => Date.now()); }
export const trackNow = (): number => clock();

export const REQUEST_COLUMNS = [
  'id', 'tenant_id', 'device_id', 'device_uuid', 'action', 'channel', 'path', 'state', 'seq', 'requested_by', 'requester_label', 'azp',
  'reason', 'incident_ref', 'pending_action_uuid', 'command_id', 'result', 'code', 'expires_at', 'created_at', 'updated_at', 'closed_at',
] as const;

export interface RequestRow {
  id: string; tenant_id: number; device_id: number; device_uuid: string; action: ObliwatchAction; channel: string; path: 'guard' | 'command';
  state: ObliwatchActionState; seq: number; requested_by: number; requester_label: string | null; azp: string; reason: string;
  incident_ref: string; pending_action_uuid: string | null; command_id: string | null; result: ObliwatchActionResult | null;
  code: string | null; expires_at: Date; created_at: Date; updated_at: Date; closed_at: Date | null;
}

export const isFinal = (s: string): boolean => (OBLIWATCH_ACTION_FINAL_STATES as readonly string[]).includes(s);

/** The prefix of every entry and of the guarded action's reason: who asked, for which incident. */
export function prefixOf(r: Pick<RequestRow, 'incident_ref' | 'requester_label'>): string {
  return `[Obliwatch, incident ${r.incident_ref}, requested by ${r.requester_label ?? 'unknown'}]`;
}

const VERB: Record<string, string> = {
  accepted: 'requested', executing: 'executing', done: 'executed', failed: 'failed', refused: 'refused', expired: 'expired', cancelled: 'cancelled',
};
const OUTCOME: Record<string, 'requested' | 'success' | 'failure' | 'denied' | 'cancelled'> = {
  accepted: 'requested', executing: 'requested', done: 'success', failed: 'failure', refused: 'denied', expired: 'failure', cancelled: 'cancelled',
};

/** The critical entry of a step of a request (in the caller's transaction: no step without its entry). */
export async function auditStepInTx(trx: Knex.Transaction, r: RequestRow, state: ObliwatchActionState, ctx: AuditWriteContext,
  extra: Record<string, unknown> = {}): Promise<void> {
  await audit.appendInTx(trx, {
    tenantId: r.tenant_id, action: `obliwatch.action.${VERB[state] ?? state}`, outcome: OUTCOME[state] ?? 'success',
    target: { type: 'device', id: String(r.device_id), device: Number(r.device_id) },
    reason: `${prefixOf(r)} ${r.reason}`.slice(0, 1000),
    links: { ...(r.pending_action_uuid ? { action: r.pending_action_uuid } : {}), ...(r.command_id ? { command: r.command_id } : {}) },
    details: {
      requestId: r.id, action: r.action, state, channel: r.channel, path: r.path, incidentRef: r.incident_ref,
      requestedBy: { userId: Number(r.requested_by), label: r.requester_label }, azp: r.azp, ...extra,
    },
  }, ctx);
}

/** The event of a transition (the outbox of the results) and the drain job asked; in the caller's transaction. */
export async function recordEventInTx(trx: Knex.Transaction, r: Pick<RequestRow, 'tenant_id' | 'id'>, seq: number, state: ObliwatchActionState,
  result: ObliwatchActionResult, at: Date): Promise<void> {
  await trx('obliwatch_action_events').insert({ tenant_id: r.tenant_id, request_id: r.id, seq, status: state, at, result: JSON.stringify(result) });
  await requestActionResultsInTx(trx, r.tenant_id);
}

const jobCtx = (): AuditWriteContext => audit.fromJob({ name: 'integrations.obliwatch.action-track', requestId: `obliwatch-action-track-${Date.now()}` });

// ── Observation ──────────────────────────────────────────────────────────────────────────────────────────────

interface Observed { state: ObliwatchActionState; code?: string }

/** The state a target of a command means for the request. */
function ofTarget(t: { state: string; reject_code?: string | null; last_status?: string | null } | undefined): Observed {
  if (!t) return { state: 'executing' };
  switch (t.state) {
    case 'acknowledged': return { state: 'done' };
    case 'error': return { state: 'failed', code: (t.last_status ?? 'device_error').slice(0, 64) };
    case 'rejected': return { state: 'refused', code: (t.reject_code ?? 'rejected').slice(0, 64) };
    case 'expired': return { state: 'expired', code: 'command_expired' };
    case 'cancelled': return { state: 'cancelled', code: (t.reject_code ?? 'command_cancelled').slice(0, 64) };
    default: return { state: 'executing' };
  }
}

async function targetOfCommand(q: Knex | Knex.Transaction, r: RequestRow): Promise<Observed> {
  const t = await q('mdm_command_targets').where({ tenant_id: r.tenant_id, command_id: r.command_id, device_id: r.device_id })
    .first('state', 'reject_code', 'last_status') as { state: string; reject_code: string | null; last_status: string | null } | undefined;
  return t ? ofTarget(t) : { state: 'failed', code: 'command_missing' };
}

async function targetOfGuarded(q: Knex | Knex.Transaction, r: RequestRow): Promise<Observed | null> {
  if (r.channel === 'legacy_agent') {
    const t = await q('legacy_agent_commands').where({ tenant_id: r.tenant_id, guard_action_uuid: String(r.pending_action_uuid).toLowerCase(), device_id: r.device_id })
      .orderBy('created_at', 'desc').first('state', 'result_code') as { state: string; result_code: string | null } | undefined;
    return t ? ofTarget({ state: t.state, reject_code: t.result_code, last_status: t.result_code }) : null;
  }
  const t = await q('mdm_command_targets as t').join('mdm_commands as c', function j() { this.on('c.id', '=', 't.command_id').andOn('c.tenant_id', '=', 't.tenant_id'); })
    .where({ 'c.tenant_id': r.tenant_id, 'c.guard_action_uuid': r.pending_action_uuid, 't.device_id': r.device_id })
    .orderBy('c.created_at', 'desc').first('t.state', 't.reject_code', 't.last_status') as { state: string; reject_code: string | null; last_status: string | null } | undefined;
  return t ? ofTarget(t) : null;
}

const firstCode = (result: unknown): string | undefined => {
  const o = (result ?? {}) as { code?: unknown; failures?: Array<{ code?: unknown }>; setAside?: Array<{ code?: unknown }> };
  const c = o.failures?.[0]?.code ?? o.setAside?.[0]?.code ?? o.code;
  return typeof c === 'string' && c ? c.slice(0, 64) : undefined;
};

/** What the request is now, from what executes it (no write). */
export async function observe(q: Knex | Knex.Transaction, r: RequestRow): Promise<Observed> {
  if (r.path === 'command') return targetOfCommand(q, r);
  const pa = await q('pending_actions').where({ tenant_id: r.tenant_id, uuid: r.pending_action_uuid }).first('state', 'result') as
    { state: string; result: unknown } | undefined;
  if (!pa) return { state: 'failed', code: 'action_missing' };
  const result = typeof pa.result === 'string' ? (() => { try { return JSON.parse(pa.result as string); } catch { return null; } })() : pa.result;
  switch (pa.state) {
    case 'scheduled': case 'paused': case 'awaiting_approval': return { state: 'accepted' };
    case 'executing': return { state: 'executing' };
    case 'refused': return { state: 'refused', code: firstCode(result) ?? 'refused' };
    case 'failed': return { state: 'failed', code: firstCode(result) ?? 'execution_failed' };
    case 'cancelled': return { state: 'cancelled', code: 'action_cancelled' };
    case 'expired': return { state: 'expired', code: 'action_expired' };
    case 'done': case 'partial': {
      const t = await targetOfGuarded(q, r);
      if (t) return t;
      // Dispatched with no command found for the device: the execution set it aside.
      return firstCode(result) ? { state: 'refused', code: firstCode(result) } : { state: 'done' };
    }
    default: return { state: 'executing' };
  }
}

/** The bucket of a horizontal accuracy in metres (null: unknown). */
export function accuracyBucketOf(m: number | null | undefined): ObliwatchActionResult['accuracyBucket'] | undefined {
  if (m === null || m === undefined || !Number.isFinite(Number(m)) || Number(m) < 0) return undefined;
  const v = Number(m);
  return v < 100 ? '<100m' : v <= 1000 ? '100m-1km' : '>1km';
}

/** The result of a request in `state`: never a coordinate (horizontal_accuracy only, for a location). */
export async function resultOf(q: Knex | Knex.Transaction, r: RequestRow, state: ObliwatchActionState, code?: string): Promise<ObliwatchActionResult> {
  const out: ObliwatchActionResult = { action: r.action, ...(code ? { code } : {}) };
  if (r.action === 'device_location' && state === 'done' && r.command_id) {
    const p = await q('lost_mode_locations').where({ tenant_id: r.tenant_id, device_id: r.device_id, command_id: r.command_id })
      .orderBy('observed_at', 'desc').first('horizontal_accuracy') as { horizontal_accuracy: number | string | null } | undefined;
    out.locationObtained = !!p;
    const b = p ? accuracyBucketOf(p.horizontal_accuracy === null ? null : Number(p.horizontal_accuracy)) : undefined;
    if (b) out.accuracyBucket = b;
  }
  return out;
}

// ── Transitions ──────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Moves the request to `to` in ONE transaction of the tenant (row locked; nothing when it changed meanwhile: `seq` is
 * the one read). Returns the new row, or null.
 */
export async function transition(tenantId: number, id: string, seq: number, to: Observed, ctx: AuditWriteContext = jobCtx(),
  extra: Record<string, unknown> = {}): Promise<RequestRow | null> {
  return asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction(async (trx) => {
    const cur = await trx('obliwatch_action_requests').where({ tenant_id: tenantId, id }).forUpdate().first(REQUEST_COLUMNS) as RequestRow | undefined;
    if (!cur || cur.seq !== seq || isFinal(cur.state) || cur.state === to.state) return null;
    const result = await resultOf(trx, cur, to.state, to.code);
    const at = new Date();
    const next = cur.seq + 1;
    await trx('obliwatch_action_requests').where({ tenant_id: tenantId, id }).update({
      state: to.state, seq: next, result: JSON.stringify(result), code: to.code ?? null, updated_at: at, ...(isFinal(to.state) ? { closed_at: at } : {}),
    });
    const row: RequestRow = { ...cur, state: to.state, seq: next, result, code: to.code ?? null, updated_at: at };
    await recordEventInTx(trx, row, next, to.state, result, at);
    await auditStepInTx(trx, row, to.state, ctx, { ...(to.code ? { code: to.code } : {}), ...extra });
    return row;
  }));
}

// ── Withdrawal (expiry) ──────────────────────────────────────────────────────────────────────────────────────

const LATE_STATES = new Set(['executing', 'done', 'partial']);

/**
 * What an expired request would still send is withdrawn (best effort, logged): a guarded action not started is
 * cancelled; one dispatched gets the late cancellation of the guard engine (its mark under the row lock, then the
 * withdrawal of its commands not delivered); a command of the queue is cancelled. Returns what was done.
 */
async function withdraw(r: RequestRow, reason = 'Obliwatch request expired (no answer within 24 hours)'): Promise<string> {
  const tenantId = r.tenant_id;
  try {
    if (r.path === 'command') {
      if (r.channel === 'amapi') await cancelAndroidCommand(tenantId, String(r.command_id), { actor: 'i:obliwatch' });
      else await asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction((trx) => mdmCommands.cancel(trx, tenantId, String(r.command_id), [r.device_id], 'i:obliwatch')));
      return 'command_cancelled';
    }
    const uuid = String(r.pending_action_uuid);
    const def = (await asTenant(tenantId, OBLIWATCH_ACTOR, () => findAction(uuid, { tenantId })))?.action_key;
    const d = def ? guardedActionDef(def) : undefined;
    const marked = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction(async (trx) => {
      const cur = await findAction(uuid, { trx, forUpdate: true, tenantId });
      if (!cur) return null;
      if (cur.state === 'scheduled' || cur.state === 'paused') {
        const now = new Date();
        await trx('pending_actions').where({ id: cur.id }).update({
          state: 'cancelled', cancelled_at: now, cancelled_by: cur.requested_by, cancel_reason: reason, updated_at: now,
        });
        await audit.appendInTx(trx, actionEntry(cur, 'guard.action_cancelled', {
          outcome: 'cancelled', reason, details: { from: cur.state, cancelledBy: cur.requested_by, via: 'obliwatch' },
        }), jobCtx());
        return { kind: 'cancelled' as const, row: cur };
      }
      if (!LATE_STATES.has(cur.state) || !d?.cancelAfterDispatch || Array.isArray((cur.result as { cancellation?: unknown } | null)?.cancellation)) {
        return { kind: 'none' as const, row: cur };
      }
      const mark = lateCancelOf(cur.result) ?? { at: new Date().toISOString(), by: cur.requested_by, reason };
      await trx('pending_actions').where({ id: cur.id })
        .update({ result: JSON.stringify({ ...(cur.result ?? { done: 0, failed: 0, skipped: 0 }), lateCancel: mark }), updated_at: new Date() });
      return { kind: 'late' as const, row: cur };
    }));
    if (!marked) return 'action_missing';
    if (marked.kind === 'cancelled') {
      if (marked.row.job_id) await cancelJob(marked.row.job_id);
      return 'action_cancelled';
    }
    if (marked.kind === 'none' || !d?.cancelAfterDispatch) return 'nothing_to_withdraw';
    const res = await asTenant(tenantId, OBLIWATCH_ACTOR, () => d.cancelAfterDispatch!(executionContext(marked.row, marked.row.target_device_ids,
      { requestId: `obliwatch-expire-${r.id}`, actor: 'i:obliwatch' })));
    const cancellation = [...res.entries()].map(([id, outcome]) => ({ id, outcome }));
    await asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction(async (trx) => {
      const cur = await findAction(uuid, { trx, forUpdate: true, tenantId });
      if (!cur) return;
      await trx('pending_actions').where({ id: cur.id }).update({
        result: JSON.stringify({ ...(cur.result ?? { done: 0, failed: 0, skipped: 0 }), lateCancel: lateCancelOf(cur.result), cancellation }), updated_at: new Date(),
      });
      await audit.appendInTx(trx, actionEntry(cur, 'guard.action_cancelled', {
        outcome: 'cancelled', reason, details: { from: cur.state, late: true, cancelledBy: cur.requested_by, via: 'obliwatch' },
      }), jobCtx());
    }));
    return 'late_cancelled';
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, requestId: r.id }, 'obliwatch actions: withdrawal of an expired request not completed');
    return 'withdrawal_incomplete';
  }
}

// ── Tracking ─────────────────────────────────────────────────────────────────────────────────────────────────

/** One open request brought up to date (expiry included). Returns the row as it is now. */
export async function trackRequest(r: RequestRow): Promise<RequestRow> {
  if (isFinal(r.state)) return r;
  let row = r;
  const seen = await asTenant(r.tenant_id, OBLIWATCH_ACTOR, () => observe(db, r));
  if (seen.state !== row.state) {
    // An intermediate step is recorded too (accepted → executing → done: two transitions, two results).
    if (row.state === 'accepted' && isFinal(seen.state) && seen.state !== 'refused' && seen.state !== 'cancelled' && seen.state !== 'expired') {
      row = (await transition(row.tenant_id, row.id, row.seq, { state: 'executing' })) ?? row;
    }
    row = (await transition(row.tenant_id, row.id, row.seq, seen)) ?? row;
  }
  if (!isFinal(row.state) && clock() > new Date(row.expires_at).getTime()) {
    const withdrawal = await withdraw(row);
    // What the device answered meanwhile wins (read again after the withdrawal).
    const again = await asTenant(row.tenant_id, OBLIWATCH_ACTOR, () => observe(db, row));
    const to: Observed = isFinal(again.state) && again.state !== 'cancelled' ? again : { state: 'expired', code: 'no_answer_24h' };
    row = (await transition(row.tenant_id, row.id, row.seq, to, jobCtx(), { withdrawal })) ?? row;
  }
  return row;
}

// ── The gate closed: the open requests withdrawn ─────────────────────────────────────────────────────────────

const CLOSED_REASON: Record<'integration_off' | 'consent_revoked', string> = {
  integration_off: 'Obliwatch request withdrawn: the integration was turned off',
  consent_revoked: 'Obliwatch request withdrawn: the tenant withdrew its consent to the actions',
};

/**
 * One open request whose gate closed (the switch off, or the consent to the actions withdrawn: actionGate.ts): what it
 * would still send is withdrawn, as at the expiry, then it is closed 'cancelled' with the code (integration_off,
 * consent_revoked), unless the device answered meanwhile (that answer wins). The guard engine's executor refuses the
 * guarded action of such a request anyway (revalidate), so a withdrawal not completed here never lets it run.
 */
export async function closeRequest(r: RequestRow, code: 'integration_off' | 'consent_revoked', ctx: AuditWriteContext = jobCtx()): Promise<RequestRow> {
  if (isFinal(r.state)) return r;
  const withdrawal = await withdraw(r, CLOSED_REASON[code]);
  const again = await asTenant(r.tenant_id, OBLIWATCH_ACTOR, () => observe(db, r));
  let row = r;
  if (again.state !== row.state && row.state === 'accepted' && isFinal(again.state) && again.state !== 'refused' && again.state !== 'cancelled' && again.state !== 'expired') {
    row = (await transition(row.tenant_id, row.id, row.seq, { state: 'executing' }, ctx)) ?? row;
  }
  const to: Observed = isFinal(again.state) && again.state !== 'cancelled' ? again : { state: 'cancelled', code };
  return (await transition(row.tenant_id, row.id, row.seq, to, ctx, { withdrawal, closedBecause: code })) ?? row;
}

/** Every open request of a tenant closed (the consent to the actions withdrawn: consent.ts; the switch off: the
 *  cleanup step of modules/obliwatch.ts). Never throws. Returns the number closed. */
export async function closeOpenRequests(tenantId: number, code: 'integration_off' | 'consent_revoked', ctx: AuditWriteContext = jobCtx()): Promise<number> {
  let closed = 0;
  try {
    const rows = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db('obliwatch_action_requests').where({ tenant_id: tenantId })
      .whereIn('state', ['accepted', 'executing']).orderBy('created_at').limit(500).select(REQUEST_COLUMNS)) as RequestRow[];
    for (const r of rows) {
      try {
        const now = await closeRequest(r, code, ctx);
        if (isFinal(now.state)) closed++;
      } catch (err) {
        logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, requestId: r.id }, 'obliwatch actions: request not withdrawn (next minute)');
      }
    }
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, tenantId }, 'obliwatch actions: withdrawal failed (next minute)');
  }
  return closed;
}

/** The open requests of a tenant (minute step). Never throws: a failure is logged, the next minute tries again. A
 *  gate closed meanwhile (actionGate.ts) closes them instead of tracking them. */
export async function trackTenant(tenantId: number): Promise<number> {
  let changed = 0;
  try {
    const rows = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db('obliwatch_action_requests').where({ tenant_id: tenantId })
      .whereIn('state', ['accepted', 'executing']).orderBy('created_at').limit(500).select(REQUEST_COLUMNS)) as RequestRow[];
    if (!rows.length) return 0;
    const closed = await asTenant(tenantId, OBLIWATCH_ACTOR, () => obliwatchActionsClosed(db, tenantId));
    if (closed) return closeOpenRequests(tenantId, closed);
    for (const r of rows) {
      try {
        const now = await trackRequest(r);
        if (now.seq !== r.seq) changed++;
      } catch (err) {
        logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, requestId: r.id }, 'obliwatch actions: request not tracked (next minute)');
      }
    }
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, tenantId }, 'obliwatch actions: tracking failed (next minute)');
  }
  return changed;
}
