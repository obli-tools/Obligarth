// Application of the Android notifications of one tenant (job android.inbox-drain, context of the tenant, actor
// j:android.inbox-drain). A pass takes at most 200 pending events whose next attempt is due, sorted by (occurred_at,
// id), and applies them one by one, each in its savepoint, in one transaction per slice of 50 (5 s budget per slice).
// The audit entries of the handlers are written at the end of the slice. Failures: attempts + 1, next attempt after
// 10 s, 1 min, 5 min, 30 min; the fifth failure is a dead letter (platform alert). A MissingPrerequisite is retried
// without counting a failure for 30 minutes. Unknown type: skipped. A payload refused by its schema, or a resource
// name of another enterprise than the event's (tenant_mismatch, security alert): dead letter at once.
import type { Knex } from 'knex';
import { audit } from '../../audit';
import type { AuditEntryInput } from '../../audit/types';
import type { DbActor } from '../../db/context';
import { withTenantTransaction } from '../../db/tenantContext';
import { logger } from '../../utils/logger';
import { raiseAndroidPlatformAlert } from '../alerts';
import { enterpriseOfResource } from '../gateway/names';
import { androidMetrics } from '../metrics';
import { androidEventHandler, MissingPrerequisite, type AndroidInboxEvent } from './handlers';
import type { AndroidEventType } from './schemas';

export const DRAIN_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.inbox-drain' }) as DbActor;
export const PASS_MAX = 200;
export const SLICE = 50;
const SLICE_BUDGET_MS = 5_000;
export const MAX_ATTEMPTS = 5;
export const RETRY_DELAYS_S: readonly number[] = [10, 60, 300, 1_800];
const PREREQUISITE_WINDOW_MS = 30 * 60_000;
const PREREQUISITE_RETRY_S = 30;

interface InboxRow {
  id: string;
  message_id: string;
  event_type: string;
  enterprise_name: string;
  resource_name: string | null;
  published_at: Date;
  occurred_at: Date;
  payload: unknown;
  attempts: number;
  received_at: Date;
}

export interface DrainResult { applied: number; skipped: number; retried: number; dead: number; remaining: boolean }

type Outcome = { state: 'applied' } | { state: 'skipped'; error: string } | { state: 'dead'; error: string }
  | { state: 'retry'; error: string; delayS: number; count: boolean };

function errCode(err: unknown): string {
  const e = err as { code?: unknown; name?: unknown };
  const c = typeof e?.code === 'string' ? e.code : typeof e?.name === 'string' ? e.name : 'error';
  return c.replace(/[^A-Za-z0-9_.:-]/g, '').slice(0, 64) || 'error';
}

/** Applies the due events of `tenantId`. */
export async function drainTenantInbox(tenantId: number, o: { actor?: DbActor; requestId?: string } = {}): Promise<DrainResult> {
  const actor = o.actor ?? DRAIN_ACTOR;
  const result: DrainResult = { applied: 0, skipped: 0, retried: 0, dead: 0, remaining: false };
  const auditCtx = audit.fromJob({ name: 'android.inbox-drain', requestId: o.requestId ?? `android-drain-${tenantId}` });
  let taken = 0;
  while (taken < PASS_MAX) {
    const effects: Array<() => void | Promise<void>> = [];
    const deadAlerts: string[] = [];
    const n = await withTenantTransaction(tenantId, actor, async (trx) => {
      const rows = await trx('android_inbox')
        .where({ state: 'pending' }).where('next_attempt_at', '<=', trx.fn.now())
        .orderBy([{ column: 'occurred_at' }, { column: 'id' }])
        .limit(Math.min(SLICE, PASS_MAX - taken)).forUpdate().skipLocked()
        .select<InboxRow[]>('id', 'message_id', 'event_type', 'enterprise_name', 'resource_name', 'published_at', 'occurred_at',
          'payload', 'attempts', 'received_at');
      if (!rows.length) return 0;
      const enterprises = await trx('android_enterprises').whereIn('enterprise_name', [...new Set(rows.map((r) => r.enterprise_name))])
        .whereIn('state', ['linked', 'unlinking', 'error']).select<{ id: number; enterprise_name: string; test_message_at: Date | null }[]>(
          'id', 'enterprise_name', 'test_message_at');
      const byName = new Map(enterprises.map((e) => [e.enterprise_name, e]));
      const audits: AuditEntryInput[] = [];
      const started = Date.now();
      let done = 0;
      for (const row of rows) {
        if (Date.now() - started > SLICE_BUDGET_MS) break;
        done += 1;
        const outcome = await applyOne(trx, tenantId, row, byName.get(row.enterprise_name)?.id ?? null, effects, audits);
        await record(trx, row, outcome);
        androidMetrics.event(row.event_type, outcome.state);
        if (outcome.state === 'applied') result.applied += 1;
        else if (outcome.state === 'skipped') result.skipped += 1;
        else if (outcome.state === 'retry') result.retried += 1;
        else { result.dead += 1; deadAlerts.push(outcome.error); androidMetrics.deadLetter(); }
      }
      // RR-5: the first event of an enterprise proves its link to the topic.
      for (const e of enterprises) {
        if (!e.test_message_at) await trx('android_enterprises').where({ id: e.id }).whereNull('test_message_at').update({ test_message_at: trx.fn.now() });
      }
      if (audits.length) await audit.appendManyInTx(trx, audits, auditCtx);
      return done;
    });
    for (const fx of effects) {
      try { await fx(); } catch (err) { logger.warn({ err: errCode(err), tenantId }, 'android: afterCommit effect failed'); }
    }
    for (const code of deadAlerts) {
      void raiseAndroidPlatformAlert('android.inbox_dead_letter', { tenantId, code }, `t${tenantId}`);
      if (code === 'tenant_mismatch') void raiseAndroidPlatformAlert('android.ownership_violation', { tenantId, reason: 'tenant_mismatch' });
    }
    if (n === 0) break;
    taken += n;
  }
  if (taken >= PASS_MAX) result.remaining = true;
  return result;
}

async function applyOne(trx: Knex.Transaction, tenantId: number, row: InboxRow, enterpriseId: number | null,
  effects: Array<() => void | Promise<void>>, audits: AuditEntryInput[]): Promise<Outcome> {
  const handler = androidEventHandler(row.event_type);
  if (!handler) return { state: 'skipped', error: 'unknown_type' };
  if (enterpriseId === null) return { state: 'skipped', error: 'enterprise_not_linked' };
  if (row.resource_name !== null && enterpriseOfResource(row.resource_name) !== row.enterprise_name) {
    return { state: 'dead', error: 'tenant_mismatch' };
  }
  const parsed = handler.payload.safeParse(row.payload);
  if (!parsed.success) return { state: 'dead', error: 'invalid_payload' };
  // Every resource name of the payload must belong to the event's enterprise (A-T3).
  if (!namesBelong(parsed.data, row.enterprise_name)) return { state: 'dead', error: 'tenant_mismatch' };
  const myEffects: Array<() => void | Promise<void>> = [];
  const myAudits: AuditEntryInput[] = [];
  const event: AndroidInboxEvent<unknown> = {
    id: Number(row.id), messageId: row.message_id, type: row.event_type as AndroidEventType, enterpriseName: row.enterprise_name,
    resourceName: row.resource_name, publishedAt: row.published_at, occurredAt: row.occurred_at, payload: parsed.data,
    attempts: row.attempts, receivedAt: row.received_at,
  };
  try {
    await trx.transaction(async (sp) => {
      await handler.handle({
        event, tenantId, enterpriseId, trx: sp,
        log: logger.child({ inboxId: Number(row.id), type: row.event_type, tenantId }),
        afterCommit: (fn) => { myEffects.push(fn); },
        audit: (entry) => { myAudits.push(entry); },
      });
    });
  } catch (err) {
    if (err instanceof MissingPrerequisite && Date.now() - new Date(row.received_at).getTime() < PREREQUISITE_WINDOW_MS) {
      return { state: 'retry', error: 'missing_prerequisite', delayS: PREREQUISITE_RETRY_S, count: false };
    }
    const attempts = row.attempts + 1;
    if (attempts >= MAX_ATTEMPTS) return { state: 'dead', error: errCode(err) };
    return { state: 'retry', error: errCode(err), delayS: RETRY_DELAYS_S[attempts - 1] ?? 1_800, count: true };
  }
  effects.push(...myEffects);
  audits.push(...myAudits);
  return { state: 'applied' };
}

/**
 * Does every enterprises/... name of the payload (strings only) name `enterprise`? A payload nested deeper than
 * NAMES_MAX_DEPTH (far beyond any AMAPI resource) is refused rather than left unchecked.
 */
const NAMES_MAX_DEPTH = 16;
function namesBelong(payload: unknown, enterprise: string, depth = 0): boolean {
  if (payload === null || payload === undefined) return true;
  if (depth > NAMES_MAX_DEPTH) return typeof payload !== 'object' && typeof payload !== 'string';
  if (typeof payload === 'string') {
    const head = enterpriseOfResource(payload);
    return head === null || head === enterprise;
  }
  if (Array.isArray(payload)) return payload.every((v) => namesBelong(v, enterprise, depth + 1));
  if (typeof payload === 'object') return Object.values(payload as Record<string, unknown>).every((v) => namesBelong(v, enterprise, depth + 1));
  return true;
}

async function record(trx: Knex.Transaction, row: InboxRow, o: Outcome): Promise<void> {
  const q = trx('android_inbox').where({ id: row.id });
  if (o.state === 'applied') {
    await q.update({ state: 'applied', applied_at: trx.fn.now(), last_error: null });
  } else if (o.state === 'skipped') {
    await q.update({ state: 'skipped', applied_at: trx.fn.now(), last_error: o.error });
  } else if (o.state === 'dead') {
    await q.update({ state: 'dead', attempts: row.attempts + 1, last_error: o.error });
  } else {
    await q.update({
      attempts: o.count ? row.attempts + 1 : row.attempts, last_error: o.error,
      next_attempt_at: trx.raw("now() + make_interval(secs => ?)", [o.delayS]),
    });
  }
}
