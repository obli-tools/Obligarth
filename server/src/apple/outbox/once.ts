import type { Knex } from 'knex';

// =============================================================================
// One-time effects of an outbox event (docs: integration-apple-edge §7.2, G-4,
// G-7): an audit entry of an event that changes no state the brain keeps (a
// security event, a conflict between tenants, a transfer). The outbox
// delivers at least once and an event whose consumed_at was reset is applied
// again: such an entry is written the first time only. The marker is a key of
// job_once (class technical, file-durable §4.3), written in the event's
// savepoint (rolled back with it), kept 90 days (the longest outbox retention
// of apple-edge, EDGE_OUTBOX_RETENTION), purged by jobs.housekeeping. The
// effects of an event that changes a state (a record, a target, a mirror) are
// written by the transition itself, never twice; an alert is deduplicated by
// its stable key (and its count by the event's time: alerts/service.ts).
// =============================================================================

/** Life of a marker: an event older than that is no longer in the outbox (EDGE_OUTBOX_RETENTION ≤ 90 days). */
const MARKER_TTL_DAYS = 90;
const EFFECT_RE = /^[a-z][a-z0-9_.]{0,40}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** True the first time the event `eventId` produces `effect` (in ctx.trx, the event's savepoint); false when a
 *  previous application of the same event already did. */
export async function firstTimeFor(trx: Knex.Transaction, eventId: string, effect: string): Promise<boolean> {
  if (!UUID_RE.test(eventId) || !EFFECT_RE.test(effect)) throw new Error('outbox marker: invalid event id or effect');
  const res = await trx.raw(`
    INSERT INTO obligarth.job_once (key, queue, state, lease_until, done_at, expires_at)
    VALUES (?, 'apple-edge.outbox-consumer', 'done', now(), now(), now() + make_interval(days => ?))
    ON CONFLICT (key) DO NOTHING
    RETURNING key`, [`outbox:${eventId.toLowerCase()}:${effect}`, MARKER_TTL_DAYS]) as { rows: unknown[] };
  return res.rows.length > 0;
}
