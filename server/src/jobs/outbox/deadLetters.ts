import { db } from '../../db';
import { asNone, type DbActor } from '../../db/context';
import { audit } from '../../audit';
import { logger } from '../../utils/logger';
import {
  applyEvent, CONSUMER_ACTOR, EventScope, tenantIdsOfKeys, type EventCollector, type OutboxRow,
} from './apply';
import { outboxConsumer, runEffects } from './consumer';

// =============================================================================
// Dead letters of the apple-edge outbox (docs: file-durable §4.4, §7.4, §8.5):
// the state of the queue (counts only, no tenant data), the redrive of a dead
// letter through the same registry (one transaction, the same checks, the
// consumer's own context and actor: a handler behaves as it does in a batch),
// the purge of the expired ones (job apple-edge.dead-letters-purge). The list
// and the detail are read by the administration routes in the context
// 'platform' under the administrator's grant (admin.routes.ts); the discard
// goes through obligarth.outbox_dead_letter_discard() (migration outbox_admin).
// =============================================================================

/** Counts of the administration (context 'none' of the monitor's actor: technical tables, no tenant data). */
const COUNTS_ACTOR: DbActor = { type: 'job', name: 'apple-edge.outbox-monitor' };

export interface OutboxLag {
  /** apple_edge.outbox present and usable. */
  table: boolean;
  pending: number;
  retrying: number;
  oldestPendingSeconds: number | null;
}

/** The lag of the queue (file-durable §7.8): events not consumed, outside and inside their attempts. */
export async function outboxLag(actor: DbActor = COUNTS_ACTOR): Promise<OutboxLag> {
  return asNone(actor, async () => {
    const t = await db.raw(`
      SELECT COALESCE((SELECT has_schema_privilege(n.oid, 'USAGE') AND has_table_privilege(c.oid, 'SELECT')
                         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'apple_edge' AND c.relname = 'outbox'), false) AS ok`) as { rows: Array<{ ok: boolean }> };
    if (t.rows[0]?.ok !== true) return { table: false, pending: 0, retrying: 0, oldestPendingSeconds: null };
    const res = await db.raw(`
      SELECT count(*) FILTER (WHERE a.event_id IS NULL)::int     AS pending,
             count(*) FILTER (WHERE a.event_id IS NOT NULL)::int AS retrying,
             extract(epoch FROM now() - min(o.occurred_at) FILTER (WHERE a.event_id IS NULL))::float8 AS oldest
        FROM apple_edge.outbox o
        LEFT JOIN obligarth.apple_edge_inbox_attempts a ON a.event_id = o.event_id
       WHERE o.consumed_at IS NULL`) as { rows: Array<{ pending: number; retrying: number; oldest: number | null }> };
    const r = res.rows[0];
    return {
      table: true,
      pending: Number(r?.pending ?? 0),
      retrying: Number(r?.retrying ?? 0),
      oldestPendingSeconds: r?.oldest === null || r?.oldest === undefined ? null : Math.max(0, Math.round(Number(r.oldest))),
    };
  });
}

/** Dead letters per reason (every tenant: counts only). */
export async function deadLetterCountsByReason(actor: DbActor = COUNTS_ACTOR): Promise<Record<string, number>> {
  return asNone(actor, async () => {
    const res = await db.raw(`SELECT reason, count(*)::int AS n FROM obligarth.apple_edge_dead_letters GROUP BY reason ORDER BY reason`) as
      { rows: Array<{ reason: string; n: number }> };
    return Object.fromEntries(res.rows.map((r) => [r.reason, Number(r.n)]));
  });
}

/** Dead letters written after `since` (the monitor's new dead letters). */
export async function deadLettersSince(since: Date, actor: DbActor = COUNTS_ACTOR): Promise<number> {
  return asNone(actor, async () => {
    const res = await db.raw('SELECT count(*)::int AS n FROM obligarth.apple_edge_dead_letters WHERE dead_lettered_at > ?', [since]) as
      { rows: Array<{ n: number }> };
    return Number(res.rows[0]?.n ?? 0);
  });
}

/** The overview of GET /api/admin/outbox (also in GET /api/admin/jobs). */
export async function outboxOverview() {
  const [lag, byReason] = await Promise.all([outboxLag(), deadLetterCountsByReason()]);
  const st = outboxConsumer.status();
  return {
    consumer: st.state,
    listening: st.listening,
    batchSize: st.batchSize,
    lastLoopAt: st.lastLoopAt ? new Date(st.lastLoopAt).toISOString() : null,
    lastSuccessAt: st.lastSuccessAt ? new Date(st.lastSuccessAt).toISOString() : null,
    table: lag.table,
    pending: lag.table ? lag.pending : null,
    retrying: lag.table ? lag.retrying : null,
    oldestPendingSeconds: lag.oldestPendingSeconds,
    deadLetters: Object.values(byReason).reduce((n, x) => n + x, 0),
    deadLettersByReason: byReason,
  };
}

/** Purge of the dead letters past their retention, 1 000 at a time (in the job's context 'none'). */
export async function purgeDeadLetters(days: number, signal?: AbortSignal): Promise<number> {
  let total = 0;
  for (;;) {
    if (signal?.aborted) break;
    const res = await db.raw(`
      DELETE FROM obligarth.apple_edge_dead_letters
       WHERE event_id IN (SELECT event_id FROM obligarth.apple_edge_dead_letters
                           WHERE dead_lettered_at < now() - make_interval(days => ?) LIMIT 1000)`, [days]) as { rowCount?: number };
    const n = Number(res.rowCount ?? 0);
    total += n;
    if (n < 1000) break;
  }
  return total;
}

export type RedriveResult =
  | { found: false }
  | { found: true; outcome: 'applied' | 'failed'; code?: string; type: string; reason: string; tenantId: number | null };

/** Applies a dead letter again (file-durable §7.4, "Rejeu"): same registry, same checks, tenant resolved
 *  again, one transaction of the consumer; the row stays (redriven_at, redrive_outcome, redriven_by). */
export async function redriveDeadLetter(eventId: string, userId: number): Promise<RedriveResult> {
  const collector: EventCollector = { effects: [], audits: [] };
  const out = await asNone(CONSUMER_ACTOR, () => db.transaction(async (trx): Promise<RedriveResult> => {
    await trx.raw("SET LOCAL statement_timeout = '30s'");
    const res = await trx.raw(`
      SELECT seq::text AS seq, event_id::text AS event_id, schema_version, scope, tenant_key, type, enrollment_id,
             command_uuid, request_id, occurred_at, payload, reason
        FROM obligarth.apple_edge_dead_letters WHERE event_id = ? FOR UPDATE`, [eventId]) as
      { rows: Array<OutboxRow & { reason: string }> };
    const row = res.rows[0];
    if (!row) return { found: false };
    const tenants = await tenantIdsOfKeys(trx, row.tenant_key ? [row.tenant_key] : []);
    const scope = new EventScope(trx, CONSUMER_ACTOR);
    const { outcome, tenantId } = await applyEvent(trx, row, {
      priorAttempts: 0,
      resolveTenant: async (key) => tenants.get(key) ?? null,
      redrive: true,
      collector,
      scope,
    });
    // The consumer's context again for the audit entries and the dead letter's row.
    await scope.toNone();
    const applied = outcome.kind === 'applied';
    if (applied && collector.audits.length > 0) {
      await audit.appendManyInTx(trx, collector.audits, audit.fromJob({ name: 'apple-edge.outbox-consumer', requestId: `redrive-${eventId}` }),
        { onFailure: 'spool' });
    }
    await trx.raw(`UPDATE obligarth.apple_edge_dead_letters
                      SET redriven_at = now(), redrive_outcome = ?, redriven_by = ?
                    WHERE event_id = ?`, [applied ? 'applied' : 'failed', userId, eventId]);
    const code = outcome.kind === 'applied' ? undefined : outcome.kind === 'retry' ? outcome.code : outcome.reason === 'handler_error' || outcome.reason === 'permanent_error' ? outcome.code : outcome.reason;
    return { found: true, outcome: applied ? 'applied' : 'failed', ...(code ? { code } : {}), type: row.type, reason: row.reason, tenantId };
  }));
  if (out.found && out.outcome === 'applied') await runEffects(collector.effects);
  if (out.found) logger.info({ eventId, outcome: out.outcome, code: out.found && out.outcome === 'failed' ? out.code : undefined }, 'outbox dead letter redriven');
  return out;
}
