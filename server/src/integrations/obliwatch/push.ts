import type { Knex } from 'knex';
import { z } from 'zod';
import { OBLIWATCH_RULE_IDS, OBLIWATCH_SLUG_RE, type ObliwatchPushStatus, type ObliwatchRuleId } from '@obligarth/shared';
import { audit } from '../../audit';
import { db } from '../../db';
import { asIdentity, asTenant } from '../../db/context';
import type { JobContext, JobResult } from '../../jobs/types';
import { raiseInTx, resolveInTx } from '../../apple/alerts/service';
import { appConfigService } from '../../services/appConfig.service';
import { obligateService } from '../../services/obligate.service';
import { dropIdentifierKeys } from '../../privacy/mask';
import { logger } from '../../utils/logger';
import { ObliwatchClient, type CallFailure, type IngestResult, type ProducerConfig } from './client';
import { OBLIWATCH_ACTOR, obliwatchIntegrationEnabled } from './config';
import { deviceViewsOf } from './devices';
import { RULES, osLabel } from './rules';
import { pushSingletonKey, reconcileSignalState, type PushPayload } from './signals';

// =============================================================================
// The push of the D-MOB-* signals to Obliwatch (brief GTH-01; plan L3): the drain job integrations.obliwatch.push of a
// tenant (stately, one queued per tenant) sends the due transitions of device_signal_transitions, in the order they were
// written (a transition waits while an earlier one of its (device, rule) is in backoff), in batches of 500 at most
// (the producer-config's maxBatch), minIntervalSec apart, to POST /api/ingest/v1/alerts with a fresh token per request
// (client.ts); the consent is read again before each round. The row carries the retries, never the job:
//   - accepted (created, deduped, duplicate, suppressed): sent;
//   - rejected module_disabled / source_not_allowed, module 'mobile' off, a rule prefix disabled by producer-config,
//     the push consent withdrawn: skipped (never retried, as Obliwatch asks);
//   - rejected validation / asset_tenant_mismatch: dead at once (a resend cannot change the answer);
//   - any failure of the request (network, Obligate, 5xx, 429, 401/403 of a configuration not done yet): attempts + 1,
//     next attempt after an exponential backoff (30 s doubling, one hour at most, a jitter), and never before the
//     Retry-After Obliwatch asked; a transition queued more than 72 hours ago is dead.
// A dead letter raises the tenant alert obliwatch.push_dead (count of the dead letters, resolved once none is left)
// and is journaled obliwatch.push.dead (counts and rules only). The minute step of the module asks the job of every
// tenant with due transitions (a send absorbed by a running job, a retry that came due) and purges the rows ended for
// 30 days (dead: 90 days).
// What is sent is built here, field by field, from the transition (its whitelisted details) and the read API's view of
// the device (deviceViewsOf: hostname, os, end user's UPN else address): never a serial number, IMEI, UDID, phone number, MAC
// nor a coordinate; dropIdentifierKeys is applied to each item as the last line; never srcIp (source 'mobile').
// =============================================================================

export const PUSH_QUEUE = 'integrations.obliwatch.push';
export const PushJobPayload = z.object({ tenantId: z.number().int().positive(), reconcile: z.boolean().optional() }).strict();

/** 72 hours: a transition queued longer is a dead letter (brief GTH-01, criterion 4). */
export const DEAD_AFTER_MS = 72 * 3600_000;
const MAX_BACKOFF_S = 3600;
const MAX_RETRY_AFTER_S = 6 * 3600;
const MAX_ROUNDS = 10;
const BATCH = 500;

let clock: () => number = () => Date.now();
/** Tests: a simulated clock (the 72 hours of the dead letter). */
export function _setPushClockForTests(now: (() => number) | null): void { clock = now ?? (() => Date.now()); }

/** The client of the instance: Obligate's settings and connected apps, read in the identity context of i:obliwatch. */
export const obliwatchClient = new ObliwatchClient(async () => {
  const raw = await asIdentity(OBLIWATCH_ACTOR, () => appConfigService.getObligateRaw());
  return {
    obligate: raw.url && raw.apiKey ? { url: raw.url, apiKey: raw.apiKey } : null,
    connectedApps: async () => (await asIdentity(OBLIWATCH_ACTOR, () => obligateService.getConnectedApps()))
      .map((a) => a as { appType?: string; baseUrl?: string }),
  };
});

type Row = {
  id: string | number; device_id: number; device_uuid: string; rule_id: string; seq: number; state: string; severity: string;
  details: Record<string, unknown> | null; occurred_at: Date | string; created_at: Date | string; attempts: number;
};

const eventIdOf = (r: Pick<Row, 'device_uuid' | 'rule_id' | 'seq'>): string => `obligarth:${String(r.device_uuid).toLowerCase()}:${r.rule_id}:${Number(r.seq)}`;

const strings = (v: unknown, max: number, len: number): string[] =>
  (Array.isArray(v) ? v : []).filter((x): x is string => typeof x === 'string' && x.length > 0).map((x) => x.slice(0, len)).slice(0, max);

/** The whitelisted details of the brief (§5.1: platform, ownership, managementMode, reasonCodes, posture, risks, state). */
function detailsOf(r: Row): Record<string, unknown> {
  const d = (r.details && typeof r.details === 'object' ? r.details : {}) as Record<string, unknown>;
  const s = (v: unknown, n: number): string | null => (typeof v === 'string' && v ? v.slice(0, n) : null);
  const out: Record<string, unknown> = {
    platform: s(d.platform, 20), ownership: s(d.ownership, 30), managementMode: s(d.managementMode, 40),
    reasonCodes: strings(d.reasonCodes, 20, 40), state: r.state === 'cleared' ? 'cleared' : 'active',
  };
  if ('posture' in d) out.posture = s(d.posture, 40);
  if ('risks' in d) out.risks = d.risks === null ? null : strings(d.risks, 20, 60);
  return out;
}

/** One item of POST /api/ingest/v1/alerts (Obliwatch's AlertInputSchema), built field by field. */
export function alertOf(r: Row, view: { hostname: string | null; platform: string; osVersion: string | null; primaryUpn: string | null } | undefined): Record<string, unknown> {
  const ruleId = r.rule_id as ObliwatchRuleId;
  const def = RULES[ruleId];
  const uuid = String(r.device_uuid).toLowerCase();
  const asset: Record<string, unknown> = { deviceUuid: uuid, externalId: uuid };
  const details = detailsOf(r);
  if (view?.hostname) asset.hostname = view.hostname.slice(0, 255);
  const os = osLabel(view?.platform ?? String(details.platform ?? ''), view?.osVersion ?? null);
  if (os) asset.os = os;
  const item: Record<string, unknown> = {
    eventId: eventIdOf(r),
    occurredAt: new Date(r.occurred_at).toISOString(),
    source: 'mobile',
    ruleId,
    ruleTitle: def?.title ?? ruleId,
    severity: r.severity,
    ...(def?.mitre && r.state === 'active' ? { mitre: def.mitre } : {}),
    asset,
    // The end user's UPN, else their address (lot L4: the primaryUpn of the read API, devices.ts upnOf).
    ...(view?.primaryUpn ? { user: { upn: view.primaryUpn.slice(0, 320) } } : {}),
    details,
  };
  return dropIdentifierKeys(item);
}

// ── Row updates ──────────────────────────────────────────────────────────────────────────────────────────

const idsOf = (rows: Array<Pick<Row, 'id'>>): string[] => rows.map((r) => String(r.id));

function backoffSeconds(attempts: number, retryAfter: number | null): number {
  const base = Math.min(MAX_BACKOFF_S, 30 * 2 ** Math.max(0, Math.min(attempts - 1, 12)));
  const jittered = Math.round(base * (0.8 + Math.random() * 0.4));
  return Math.max(Math.min(jittered, MAX_BACKOFF_S), Math.min(retryAfter ?? 0, MAX_RETRY_AFTER_S), 1);
}

async function markSent(trx: Knex.Transaction, tenantId: number, ids: string[], code: string, at: Date): Promise<void> {
  if (!ids.length) return;
  await trx('device_signal_transitions').where({ tenant_id: tenantId, push_state: 'pending' }).whereIn('id', ids)
    .update({ push_state: 'sent', pushed_at: at, result_code: code.slice(0, 40), last_error: null });
}

async function markSkipped(trx: Knex.Transaction, tenantId: number, ids: string[], code: string): Promise<void> {
  if (!ids.length) return;
  await trx('device_signal_transitions').where({ tenant_id: tenantId, push_state: 'pending' }).whereIn('id', ids)
    .update({ push_state: 'skipped', result_code: code.slice(0, 40) });
}

/** Dead letters: written, journaled, alerted (in one transaction of the tenant). */
async function markDead(trx: Knex.Transaction, tenantId: number, rows: Row[], code: string, error: string | null): Promise<void> {
  if (!rows.length) return;
  await trx('device_signal_transitions').where({ tenant_id: tenantId, push_state: 'pending' }).whereIn('id', idsOf(rows))
    .update({ push_state: 'dead', result_code: code.slice(0, 40), ...(error ? { last_error: error.slice(0, 300) } : {}) });
  const total = Number((await trx('device_signal_transitions').where({ tenant_id: tenantId, push_state: 'dead' }).count('* as n').first() as { n: string } | undefined)?.n ?? 0);
  const rules = [...new Set(rows.map((r) => r.rule_id))].sort().slice(0, 10);
  await audit.appendInTx(trx, {
    tenantId, action: 'obliwatch.push.dead', outcome: 'failure',
    target: { type: 'tenant', id: String(tenantId) },
    details: { count: rows.length, total, rules, code: code.slice(0, 40), transitionIds: idsOf(rows).slice(0, 20) },
  }, audit.fromJob({ name: PUSH_QUEUE, requestId: `obliwatch-push-${tenantId}` }), { onFailure: 'spool' });
  await raiseInTx(trx, tenantId, 'obliwatch.push_dead', { params: { count: total }, navigateTo: '/integrations' });
}

/** A failed request: the rows of the batch retried later, or dead after 72 hours. ONE next attempt for the whole batch
 *  (a jitter per row could send a 'cleared' before the 'active' it closes; dueRows keeps the order of the sequences). */
async function markFailed(trx: Knex.Transaction, tenantId: number, rows: Row[], f: CallFailure, now: number): Promise<number> {
  const old = rows.filter((r) => now - new Date(r.created_at).getTime() > DEAD_AFTER_MS);
  const retry = rows.filter((r) => !old.includes(r));
  if (retry.length) {
    const attempts = Math.max(...retry.map((r) => Number(r.attempts) || 0)) + 1;
    await trx('device_signal_transitions').where({ tenant_id: tenantId, push_state: 'pending' }).whereIn('id', idsOf(retry)).update({
      attempts: trx.raw('attempts + 1'), next_attempt_at: new Date(now + backoffSeconds(attempts, f.retryAfterSeconds) * 1000),
      last_error: f.error.slice(0, 300),
    });
  }
  await markDead(trx, tenantId, old, 'expired_72h', f.error);
  return old.length;
}

const ACCEPTED = new Set(['created', 'deduped', 'duplicate', 'suppressed']);
const SKIP_CODES = new Set(['module_disabled', 'source_not_allowed']);

// ── The job ─────────────────────────────────────────────────────────────────────────────────────────────

async function tenantOf(tenantId: number): Promise<{ slug: string | null; push: boolean }> {
  return asTenant(tenantId, OBLIWATCH_ACTOR, async () => {
    const t = await db('tenants').where({ id: tenantId }).first('slug') as { slug?: string } | undefined;
    const c = await db('tenant_obliwatch_settings').where({ tenant_id: tenantId }).first('push_enabled') as { push_enabled?: boolean } | undefined;
    return { slug: t?.slug ?? null, push: c?.push_enabled === true };
  });
}

const sleep = (ms: number, signal: AbortSignal): Promise<void> => new Promise((resolve) => {
  if (signal.aborted) { resolve(); return; }
  const t = setTimeout(resolve, ms);
  signal.addEventListener('abort', () => { clearTimeout(t); resolve(); }, { once: true });
});

/** The bound of a due row: the database's clock (next_attempt_at is written with now()), or the simulated one when later. */
const dueBound = (now: number) => db.raw('greatest(now(), ?::timestamptz)', [new Date(now)]);

/**
 * The due rows, in the order they were written (id: the sequences of a (device, rule) in order). A row waits while an
 * earlier transition of its (device, rule) is still pending and not due (in backoff): Obliwatch ingests in the order
 * of the request, and a 'cleared' sent before its 'active' would leave a signal open.
 */
async function dueRows(tenantId: number, limit: number, now: number): Promise<Row[]> {
  return asTenant(tenantId, OBLIWATCH_ACTOR, () => db('device_signal_transitions as t')
    .where({ 't.tenant_id': tenantId, 't.push_state': 'pending' }).where('t.next_attempt_at', '<=', dueBound(now))
    .whereNotExists(db('device_signal_transitions as p').select(db.raw('1'))
      .whereRaw('p.tenant_id = t.tenant_id AND p.device_id = t.device_id AND p.rule_id = t.rule_id AND p.seq < t.seq')
      .where('p.push_state', 'pending').where('p.next_attempt_at', '>', dueBound(now)))
    .orderBy('t.id', 'asc').limit(limit)
    .select('t.id', 't.device_id', 't.device_uuid', 't.rule_id', 't.seq', 't.state', 't.severity', 't.details', 't.occurred_at', 't.created_at',
      't.attempts')) as Promise<Row[]>;
}

/** Every pending transition of the tenant skipped (consent withdrawn, module off): never sent. */
async function skipAllPending(tenantId: number, code: string): Promise<number> {
  const ids = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db('device_signal_transitions')
    .where({ tenant_id: tenantId, push_state: 'pending' }).limit(10_000).pluck('id')) as Array<string | number>;
  if (ids.length) await inTx(tenantId, (trx) => markSkipped(trx, tenantId, ids.map(String), code));
  return ids.length;
}

const inTx = <T>(tenantId: number, fn: (trx: Knex.Transaction) => Promise<T>): Promise<T> =>
  asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction(fn));

export interface DrainResult { sent: number; skipped: number; dead: number; retried: number; rounds: number }

/** Sends the due transitions of a tenant (the job's work; the tests call it directly). Throws only on a database error. */
export async function drainTenant(tenantId: number, signal: AbortSignal = new AbortController().signal): Promise<DrainResult> {
  const out: DrainResult = { sent: 0, skipped: 0, dead: 0, retried: 0, rounds: 0 };
  if (!obliwatchIntegrationEnabled()) return out;
  const t = await tenantOf(tenantId);
  if (!t.push) {
    // The consent was withdrawn: what waits is never sent.
    out.skipped += await skipAllPending(tenantId, 'consent_off');
    return out;
  }
  let batch = BATCH;
  let interval = 10;
  for (let round = 0; round < MAX_ROUNDS && !signal.aborted; round++) {
    // The consent read again before each round after the first: a withdrawal stops a drain that is running.
    if (round > 0 && !(await tenantOf(tenantId)).push) {
      out.skipped += await skipAllPending(tenantId, 'consent_off');
      break;
    }
    const now = clock();
    const rows = await dueRows(tenantId, batch, now);
    if (rows.length === 0) break;
    out.rounds++;
    const unknownRule = rows.filter((r) => !(OBLIWATCH_RULE_IDS as readonly string[]).includes(r.rule_id));
    if (unknownRule.length) await inTx(tenantId, (trx) => markDead(trx, tenantId, unknownRule, 'unknown_rule', null));
    const candidates = rows.filter((r) => !unknownRule.includes(r));
    // Queued more than 72 hours ago and due again: its window is over.
    const expired = candidates.filter((r) => now - new Date(r.created_at).getTime() > DEAD_AFTER_MS);
    if (expired.length) { await inTx(tenantId, (trx) => markDead(trx, tenantId, expired, 'expired_72h', null)); out.dead += expired.length; }
    let live = candidates.filter((r) => !expired.includes(r));
    if (live.length === 0) continue;
    const slug = t.slug && OBLIWATCH_SLUG_RE.test(t.slug) ? t.slug : null;
    const fail = async (f: CallFailure): Promise<void> => {
      const dead = await inTx(tenantId, (trx) => markFailed(trx, tenantId, live, f, now));
      out.dead += dead;
      out.retried += live.length - dead;
      logger.warn({ tenantId, rows: live.length, status: f.status, error: f.error }, 'obliwatch push: batch not sent (retried later)');
    };
    if (!slug) { await fail({ ok: false, error: 'tenant slug incompatible with Obliwatch', status: null, retryAfterSeconds: null }); break; }
    const cfg = await obliwatchClient.producerConfig(slug);
    if (!cfg.ok) { await fail(cfg); break; }
    const config: ProducerConfig = cfg.config;
    batch = Math.max(1, Math.min(BATCH, config.maxBatch));
    interval = config.minIntervalSec;
    if (config.modules.mobile === false) {
      // The module 'mobile' is off for this tenant at Obliwatch: nothing of it is sent (brief GTH-01).
      out.skipped += await skipAllPending(tenantId, 'module_disabled');
      break;
    }
    const disabled = live.filter((r) => config.ruleIdPrefixesDisabled.some((p) => p && r.rule_id.startsWith(p)));
    if (disabled.length) {
      await inTx(tenantId, (trx) => markSkipped(trx, tenantId, idsOf(disabled), 'rule_disabled'));
      out.skipped += disabled.length;
      live = live.filter((r) => !disabled.includes(r));
    }
    if (live.length === 0) continue;
    // Obliwatch's maxBatch, from the first round too (the rows were read before the producer-config): the rest waits for
    // the next round, in order.
    let cut = false;
    if (live.length > batch) { live = live.slice(0, batch); cut = true; }
    const views = await asTenant(tenantId, OBLIWATCH_ACTOR, () => deviceViewsOf(tenantId, live.map((r) => Number(r.device_id))));
    const alerts = live.map((r) => alertOf(r, views.get(Number(r.device_id))));
    const sent = await obliwatchClient.postAlerts(slug, alerts);
    if (!sent.ok) { await fail(sent); break; }
    const byEvent = new Map<string, IngestResult>(sent.results.map((x) => [x.eventId, x]));
    const at = new Date(clock());
    await inTx(tenantId, async (trx) => {
      const accepted: Record<string, string[]> = {};
      const skipped: Record<string, string[]> = {};
      const dead: Row[] = [];
      const missing: Row[] = [];
      for (const r of live) {
        const x = byEvent.get(eventIdOf(r));
        if (!x) { missing.push(r); continue; }
        if (ACCEPTED.has(x.status)) (accepted[x.status] ??= []).push(String(r.id));
        else if (x.status === 'rejected' && x.code && SKIP_CODES.has(x.code)) (skipped[x.code] ??= []).push(String(r.id));
        else dead.push(r);
      }
      for (const [code, ids] of Object.entries(accepted)) { await markSent(trx, tenantId, ids, code, at); out.sent += ids.length; }
      for (const [code, ids] of Object.entries(skipped)) { await markSkipped(trx, tenantId, ids, code); out.skipped += ids.length; }
      if (dead.length) {
        const code = byEvent.get(eventIdOf(dead[0]))?.code ?? 'rejected';
        await markDead(trx, tenantId, dead, `rejected_${code}`, null);
        out.dead += dead.length;
      }
      // An item without a result (an answer cut short): retried like a failed request.
      if (missing.length) {
        out.dead += await markFailed(trx, tenantId, missing, { ok: false, error: 'no result for the item', status: null, retryAfterSeconds: null }, at.getTime());
      }
    });
    if (rows.length < batch && !cut) break;
    await sleep(Math.max(0, interval) * 1000, signal);
  }
  return out;
}

export async function runPushJob(ctx: JobContext<z.infer<typeof PushJobPayload>>): Promise<JobResult> {
  if (ctx.payload.reconcile) {
    // The second pass after the push turned on (signals.ts requestReconcileInTx): never a drain (its own singleton key:
    // two drains of a tenant never run side by side); the transitions it writes ask the drain job as usual.
    const n = await reconcileSignalState(ctx.tenantId as number);
    return { output: { reconciled: n } };
  }
  const r = await drainTenant(ctx.tenantId as number, ctx.signal);
  return { output: { sent: r.sent, skipped: r.skipped, dead: r.dead, retried: r.retried, rounds: r.rounds } };
}

// ── Minute step: due transitions, purge ─────────────────────────────────────────────────────────────────

/** The tenants with due transitions, asked again (the job is stately per tenant: a waiting one absorbs it). */
export async function requestDuePushes(send: (payload: PushPayload, opts: { singletonKey: string; tenantId: number }) => Promise<unknown>,
  tenantIds: number[]): Promise<number> {
  let asked = 0;
  const now = new Date(clock());
  for (const tenantId of tenantIds) {
    const due = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db('device_signal_transitions')
      .where({ tenant_id: tenantId, push_state: 'pending' }).where('next_attempt_at', '<=', dueBound(now.getTime())).first('id'));
    if (!due) continue;
    await send({ tenantId }, { singletonKey: pushSingletonKey(tenantId), tenantId });
    asked++;
  }
  return asked;
}

/** Rows ended 30 days ago (dead: 90 days) removed; the alert resolved when no dead letter is left. */
export async function purgeTransitions(tenantId: number): Promise<number> {
  const now = clock();
  return inTx(tenantId, async (trx) => {
    const n = await trx('device_signal_transitions').where({ tenant_id: tenantId })
      .where((q) => q.where((a) => a.whereIn('push_state', ['sent', 'skipped']).where('created_at', '<', new Date(now - 30 * 86_400_000)))
        .orWhere((a) => a.where('push_state', 'dead').where('created_at', '<', new Date(now - 90 * 86_400_000))))
      .delete();
    if (n > 0) await resolveIfNoDead(trx, tenantId);
    return Number(n);
  });
}

async function resolveIfNoDead(trx: Knex.Transaction, tenantId: number): Promise<void> {
  const dead = await trx('device_signal_transitions').where({ tenant_id: tenantId, push_state: 'dead' }).first('id');
  if (!dead) await resolveInTx(trx, tenantId, 'obliwatch.push_dead');
}

// ── Console ────────────────────────────────────────────────────────────────────────────────────────────

/** The state of the push of the tenant (the caller's database context: the tenant's). Counts and dates only. */
export async function pushStatusOf(q: Knex | Knex.Transaction, tenantId: number): Promise<ObliwatchPushStatus> {
  const counts = await q('device_signal_transitions').where({ tenant_id: tenantId }).whereIn('push_state', ['pending', 'dead'])
    .groupBy('push_state').select('push_state').count('* as n') as Array<{ push_state: string; n: string | number }>;
  const n = (s: string) => Number(counts.find((c) => c.push_state === s)?.n ?? 0);
  const last = await q('device_signal_transitions').where({ tenant_id: tenantId, push_state: 'sent' }).max('pushed_at as at').first() as { at: Date | string | null } | undefined;
  const err = n('pending') > 0
    ? await q('device_signal_transitions').where({ tenant_id: tenantId, push_state: 'pending' }).whereNotNull('last_error')
      .orderBy('id', 'desc').first('last_error') as { last_error: string | null } | undefined
    : undefined;
  return {
    pending: n('pending'), dead: n('dead'),
    lastSentAt: last?.at ? new Date(last.at).toISOString() : null,
    lastError: err?.last_error ? String(err.last_error).slice(0, 300) : null,
  };
}

/** The push consent withdrawn (consent.ts, in its transaction): what waits and the dead letters are never sent
 *  (skipped, consent_off), and the alert of the dead letters resolved (nothing is left to act on). */
export async function withdrawPushInTx(trx: Knex.Transaction, tenantId: number): Promise<number> {
  const n = await trx('device_signal_transitions').where({ tenant_id: tenantId }).whereIn('push_state', ['pending', 'dead'])
    .update({ push_state: 'skipped', result_code: 'consent_off' });
  await resolveInTx(trx, tenantId, 'obliwatch.push_dead');
  return Number(n);
}

/** The dead letters of the tenant put back in the queue (a new window of 72 hours); in the caller's transaction. */
export async function requeueDeadInTx(trx: Knex.Transaction, tenantId: number): Promise<number> {
  const rows = await trx('device_signal_transitions').where({ tenant_id: tenantId, push_state: 'dead' })
    .update({ push_state: 'pending', attempts: 0, next_attempt_at: trx.fn.now(), created_at: trx.fn.now(), result_code: null })
    .returning('id') as unknown[];
  await resolveIfNoDead(trx, tenantId);
  return rows.length;
}
