import type { Knex } from 'knex';
import { z } from 'zod';
import { OBLIWATCH_SLUG_RE } from '@obligarth/shared';
import { audit } from '../../audit';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { defaultRuntime } from '../../jobs';
import type { JobContext, JobHandle, JobResult } from '../../jobs/types';
import { logger } from '../../utils/logger';
import type { CallFailure } from './client';
import { OBLIWATCH_ACTOR, obliwatchIntegrationEnabled } from './config';
import { obliwatchClient } from './push';

// =============================================================================
// The push of the results of the action requests to Obliwatch (brief GTH-05; lot L5): one row of
// obliwatch_action_events per transition of a request (written by actionTrack.ts in the transaction of the transition),
// sent by the drain job integrations.obliwatch.action-result of the tenant (stately, one queued per tenant) to
// POST {obliwatch}/api/ingest/v1/action-results {results: [{uuid, status, at, seq, result}]}, in the order they were
// written (a row waits while an earlier one of its request is in backoff), 100 per request, with a fresh delegation
// token per HTTP request (client.ts, the pattern of the push of lot L3). The row carries the retries, as L3:
//   - a 2xx: the whole batch sent;
//   - 400, 413 or 422 (the batch is invalid: a resend cannot change the answer): dead at once;
//   - anything else (network, Obligate, 401, 403, 404 — Obliwatch had not built the route when this was written —, 429,
//     5xx): attempts + 1, next attempt after a backoff of 30 s doubling to one hour (never before Retry-After, 6 hours at
//     most), one per batch; a row queued more than 72 hours ago is dead. A 404 is logged at debug level only (the route
//     not built yet is a known state, not an incident: no log flood while it lasts).
// A dead letter is journaled obliwatch.action.result_dead (counts only). The consent 'actions' of the tenant withdrawn:
// what waits is skipped (consent_off), never sent. Never a coordinate: `result` is {action, code?, locationObtained?,
// accuracyBucket?} (actionTrack.ts builds it, from horizontal_accuracy only).
// =============================================================================

export const ACTION_RESULT_QUEUE = 'integrations.obliwatch.action-result';
export const ActionResultJobPayload = z.object({ tenantId: z.number().int().positive() }).strict();
export type ActionResultPayload = z.infer<typeof ActionResultJobPayload>;

const DEAD_AFTER_MS = 72 * 3600_000;
const MAX_BACKOFF_S = 3600;
const MAX_RETRY_AFTER_S = 6 * 3600;
const BATCH = 100;
const MAX_ROUNDS = 20;
const INVALID = new Set([400, 413, 422]);

let clock: () => number = () => Date.now();
/** Tests: a simulated clock (the 72 hours of the dead letter). */
export function _setActionResultClockForTests(now: (() => number) | null): void { clock = now ?? (() => Date.now()); }

let job: JobHandle<ActionResultPayload> | null = null;
export function bindActionResultJob(h: JobHandle<ActionResultPayload>): void { job = h; }
export const actionResultSingletonKey = (tenantId: number): string => `obliwatch-action-result:t:${tenantId}`;

type Nested = Knex.Transaction & { parentTransaction?: Knex.Transaction; executionPromise?: Promise<unknown> };

/**
 * The drain job of the tenant asked in `trx` (in a savepoint: a send that fails never takes the transition with it; the
 * minute step sends it). Absorbed by a job already waiting, it is asked again once the outermost transaction committed.
 */
export async function requestActionResultsInTx(trx: Knex.Transaction, tenantId: number): Promise<void> {
  const h = job;
  if (!h || !defaultRuntime.isStarted()) return;
  const opts = { singletonKey: actionResultSingletonKey(tenantId), tenantId };
  let id: string | null = null;
  try {
    id = await trx.transaction((sp) => h.sendInTx(sp, { tenantId }, opts));
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) } }, 'obliwatch action results: job not asked (the minute step will)');
  }
  if (id !== null) return;
  let outer = trx as Nested;
  for (let depth = 0; depth < 16 && outer.parentTransaction; depth++) outer = outer.parentTransaction as Nested;
  outer.executionPromise?.then(() => h.send({ tenantId }, opts), () => undefined)
    .catch((err) => logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) } }, 'obliwatch action results: not asked again after the commit'));
}

type Row = {
  id: string | number; request_id: string; seq: number; status: string; at: Date | string; result: Record<string, unknown> | null;
  created_at: Date | string; attempts: number;
};

/** One item of POST /api/ingest/v1/action-results, built field by field (never anything but the whitelist). */
export function resultItemOf(r: Pick<Row, 'request_id' | 'seq' | 'status' | 'at' | 'result'>): Record<string, unknown> {
  const src = (r.result && typeof r.result === 'object' ? r.result : {}) as Record<string, unknown>;
  const result: Record<string, unknown> = { action: typeof src.action === 'string' ? src.action : null };
  if (typeof src.code === 'string' && src.code) result.code = src.code.slice(0, 64);
  if (typeof src.locationObtained === 'boolean') result.locationObtained = src.locationObtained;
  if (src.accuracyBucket === '<100m' || src.accuracyBucket === '100m-1km' || src.accuracyBucket === '>1km') result.accuracyBucket = src.accuracyBucket;
  return { uuid: String(r.request_id).toLowerCase(), status: r.status, at: new Date(r.at).toISOString(), seq: Number(r.seq), result };
}

const inTx = <T>(tenantId: number, fn: (trx: Knex.Transaction) => Promise<T>): Promise<T> =>
  asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction(fn));

const dueBound = (now: number) => db.raw('greatest(now(), ?::timestamptz)', [new Date(now)]);

async function dueRows(tenantId: number, limit: number, now: number): Promise<Row[]> {
  return asTenant(tenantId, OBLIWATCH_ACTOR, () => db('obliwatch_action_events as e')
    .where({ 'e.tenant_id': tenantId, 'e.push_state': 'pending' }).where('e.next_attempt_at', '<=', dueBound(now))
    .whereNotExists(db('obliwatch_action_events as p').select(db.raw('1'))
      .whereRaw('p.tenant_id = e.tenant_id AND p.request_id = e.request_id AND p.seq < e.seq')
      .where('p.push_state', 'pending').where('p.next_attempt_at', '>', dueBound(now)))
    .orderBy('e.id', 'asc').limit(limit)
    .select('e.id', 'e.request_id', 'e.seq', 'e.status', 'e.at', 'e.result', 'e.created_at', 'e.attempts')) as Promise<Row[]>;
}

function backoffSeconds(attempts: number, retryAfter: number | null): number {
  const base = Math.min(MAX_BACKOFF_S, 30 * 2 ** Math.max(0, Math.min(attempts - 1, 12)));
  const jittered = Math.round(base * (0.8 + Math.random() * 0.4));
  return Math.max(Math.min(jittered, MAX_BACKOFF_S), Math.min(retryAfter ?? 0, MAX_RETRY_AFTER_S), 1);
}

const idsOf = (rows: Array<Pick<Row, 'id'>>): string[] => rows.map((r) => String(r.id));

async function markDead(trx: Knex.Transaction, tenantId: number, rows: Row[], code: string, error: string | null): Promise<void> {
  if (!rows.length) return;
  await trx('obliwatch_action_events').where({ tenant_id: tenantId, push_state: 'pending' }).whereIn('id', idsOf(rows))
    .update({ push_state: 'dead', result_code: code.slice(0, 40), ...(error ? { last_error: error.slice(0, 300) } : {}) });
  await audit.appendInTx(trx, {
    tenantId, action: 'obliwatch.action.result_dead', outcome: 'failure', target: { type: 'tenant', id: String(tenantId) },
    details: { count: rows.length, code: code.slice(0, 40), requests: [...new Set(rows.map((r) => String(r.request_id)))].slice(0, 20) },
  }, audit.fromJob({ name: ACTION_RESULT_QUEUE, requestId: `obliwatch-action-result-${tenantId}` }), { onFailure: 'spool' });
}

async function markFailed(trx: Knex.Transaction, tenantId: number, rows: Row[], f: CallFailure, now: number): Promise<number> {
  const old = rows.filter((r) => now - new Date(r.created_at).getTime() > DEAD_AFTER_MS);
  const retry = rows.filter((r) => !old.includes(r));
  if (retry.length) {
    const attempts = Math.max(...retry.map((r) => Number(r.attempts) || 0)) + 1;
    await trx('obliwatch_action_events').where({ tenant_id: tenantId, push_state: 'pending' }).whereIn('id', idsOf(retry)).update({
      attempts: trx.raw('attempts + 1'), next_attempt_at: new Date(now + backoffSeconds(attempts, f.retryAfterSeconds) * 1000),
      last_error: f.error.slice(0, 300),
    });
  }
  await markDead(trx, tenantId, old, 'expired_72h', f.error);
  return old.length;
}

async function tenantOf(tenantId: number): Promise<{ slug: string | null; actions: boolean }> {
  return asTenant(tenantId, OBLIWATCH_ACTOR, async () => {
    const t = await db('tenants').where({ id: tenantId }).first('slug') as { slug?: string } | undefined;
    const c = await db('tenant_obliwatch_settings').where({ tenant_id: tenantId }).first('actions_enabled') as { actions_enabled?: boolean } | undefined;
    return { slug: t?.slug ?? null, actions: c?.actions_enabled === true };
  });
}

async function skipAllPending(tenantId: number, code: string): Promise<number> {
  return inTx(tenantId, async (trx) => Number(await trx('obliwatch_action_events').where({ tenant_id: tenantId, push_state: 'pending' })
    .update({ push_state: 'skipped', result_code: code })));
}

export interface ActionResultDrain { sent: number; skipped: number; dead: number; retried: number; rounds: number }

/** Sends the due results of a tenant (the job's work; the tests call it directly). Throws only on a database error. */
export async function drainActionResults(tenantId: number, signal: AbortSignal = new AbortController().signal): Promise<ActionResultDrain> {
  const out: ActionResultDrain = { sent: 0, skipped: 0, dead: 0, retried: 0, rounds: 0 };
  if (!obliwatchIntegrationEnabled()) return out;
  for (let round = 0; round < MAX_ROUNDS && !signal.aborted; round++) {
    const t = await tenantOf(tenantId);
    if (!t.actions) { out.skipped += await skipAllPending(tenantId, 'consent_off'); break; }
    const now = clock();
    const rows = await dueRows(tenantId, BATCH, now);
    if (rows.length === 0) break;
    out.rounds++;
    const expired = rows.filter((r) => now - new Date(r.created_at).getTime() > DEAD_AFTER_MS);
    if (expired.length) { await inTx(tenantId, (trx) => markDead(trx, tenantId, expired, 'expired_72h', null)); out.dead += expired.length; }
    const live = rows.filter((r) => !expired.includes(r));
    if (live.length === 0) continue;
    const slug = t.slug && OBLIWATCH_SLUG_RE.test(t.slug) ? t.slug : null;
    const sent = slug ? await obliwatchClient.postActionResults(slug, live.map(resultItemOf))
      : { ok: false as const, error: 'tenant slug incompatible with Obliwatch', status: null, retryAfterSeconds: null };
    if (!sent.ok) {
      if (sent.status !== null && INVALID.has(sent.status)) {
        await inTx(tenantId, (trx) => markDead(trx, tenantId, live, `rejected_${sent.status}`, sent.error));
        out.dead += live.length;
        continue;
      }
      const dead = await inTx(tenantId, (trx) => markFailed(trx, tenantId, live, sent, now));
      out.dead += dead;
      out.retried += live.length - dead;
      const log = { tenantId, rows: live.length, status: sent.status, error: sent.error };
      // The route not built yet at Obliwatch: a known state, retried quietly (no log flood).
      if (sent.status === 404) logger.debug(log, 'obliwatch action results: route not available (retried later)');
      else logger.warn(log, 'obliwatch action results: batch not sent (retried later)');
      break;
    }
    const at = new Date(clock());
    await inTx(tenantId, (trx) => trx('obliwatch_action_events').where({ tenant_id: tenantId, push_state: 'pending' }).whereIn('id', idsOf(live))
      .update({ push_state: 'sent', pushed_at: at, result_code: 'accepted', last_error: null }));
    out.sent += live.length;
    if (rows.length < BATCH) break;
  }
  return out;
}

export async function runActionResultJob(ctx: JobContext<ActionResultPayload>): Promise<JobResult> {
  const r = await drainActionResults(ctx.tenantId as number, ctx.signal);
  return { output: { sent: r.sent, skipped: r.skipped, dead: r.dead, retried: r.retried, rounds: r.rounds } };
}

/** The minute step: the tenants with due results asked again (a send absorbed by a running job, a retry that came due). */
export async function requestDueActionResults(tenantIds: number[]): Promise<number> {
  const h = job;
  if (!h) return 0;
  let asked = 0;
  const now = clock();
  for (const tenantId of tenantIds) {
    const due = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db('obliwatch_action_events')
      .where({ tenant_id: tenantId, push_state: 'pending' }).where('next_attempt_at', '<=', dueBound(now)).first('id'));
    if (!due) continue;
    await h.send({ tenantId }, { singletonKey: actionResultSingletonKey(tenantId), tenantId });
    asked++;
  }
  return asked;
}

/** Hourly: results ended 30 days ago (dead: 90 days) and requests closed 90 days ago removed (their events with them). */
export async function purgeActionRows(tenantId: number): Promise<number> {
  const now = clock();
  return inTx(tenantId, async (trx) => {
    const events = await trx('obliwatch_action_events').where({ tenant_id: tenantId })
      .where((q) => q.where((a) => a.whereIn('push_state', ['sent', 'skipped']).where('created_at', '<', new Date(now - 30 * 86_400_000)))
        .orWhere((a) => a.where('push_state', 'dead').where('created_at', '<', new Date(now - 90 * 86_400_000))))
      .delete();
    const requests = await trx('obliwatch_action_requests').where({ tenant_id: tenantId }).whereNotNull('closed_at')
      .where('closed_at', '<', new Date(now - 90 * 86_400_000)).delete();
    return Number(events) + Number(requests);
  });
}
