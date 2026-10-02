// =============================================================================
// Metrics of the outbox consumer (docs: file-durable §8.3): in-process
// counters of the consumer, gauges of the monitor (apple-edge.outbox-monitor),
// handed to the observability work (FND-14) by jobs.metricsSnapshot(). No
// tenant label; the event types are those of apple-edge's catalogue (a bounded
// set: past 200 distinct types, the rest is counted as 'other').
// =============================================================================

export type OutboxEventOutcome = 'applied' | 'retry' | 'dead_letter';

/** obligarth_outbox_batch_duration_seconds buckets. */
export const BATCH_BUCKETS_S = [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30] as const;
const MAX_TYPES = 200;

const events = new Map<string, number>();
const deadLetters = new Map<string, number>();
const batch = { buckets: BATCH_BUCKETS_S.map(() => 0), sum: 0, count: 0 };
const gauges = { pending: null as number | null, retrying: null as number | null, oldestPendingSeconds: null as number | null };
let consumerUp = 0;

const typeLabel = (type: string): string => {
  const known = new Set([...events.keys()].map((k) => k.slice(0, k.lastIndexOf('|'))));
  return known.has(type) || known.size < MAX_TYPES ? type : 'other';
};

export const outboxMetrics = {
  event(type: string, outcome: OutboxEventOutcome): void {
    const k = `${typeLabel(String(type).slice(0, 64))}|${outcome}`;
    events.set(k, (events.get(k) ?? 0) + 1);
  },
  deadLetter(reason: string): void {
    deadLetters.set(reason, (deadLetters.get(reason) ?? 0) + 1);
  },
  batch(durationMs: number): void {
    const s = Math.max(0, durationMs) / 1000;
    BATCH_BUCKETS_S.forEach((le, i) => { if (s <= le) batch.buckets[i] += 1; });
    batch.sum += s;
    batch.count += 1;
  },
  lag(v: { pending: number; retrying: number; oldestPendingSeconds: number | null }): void {
    gauges.pending = v.pending;
    gauges.retrying = v.retrying;
    gauges.oldestPendingSeconds = v.oldestPendingSeconds;
  },
  setConsumerUp(up: boolean): void {
    consumerUp = up ? 1 : 0;
  },
  snapshot() {
    return {
      /** obligarth_outbox_events_total{type, outcome} */
      events: [...events.entries()].map(([k, value]) => {
        const i = k.lastIndexOf('|');
        return { type: k.slice(0, i), outcome: k.slice(i + 1) as OutboxEventOutcome, value };
      }),
      /** obligarth_outbox_dead_letters_total{reason} */
      deadLetters: [...deadLetters.entries()].map(([reason, value]) => ({ reason, value })),
      /** obligarth_outbox_batch_duration_seconds */
      batchDuration: { buckets: BATCH_BUCKETS_S.map((le, i) => ({ le, count: batch.buckets[i] })), sum: batch.sum, count: batch.count },
      /** obligarth_outbox_pending, obligarth_outbox_retrying, obligarth_outbox_oldest_pending_seconds */
      pending: gauges.pending,
      retrying: gauges.retrying,
      oldestPendingSeconds: gauges.oldestPendingSeconds,
      /** obligarth_outbox_consumer_up */
      consumerUp,
    };
  },
};

export type OutboxMetricsSnapshot = ReturnType<typeof outboxMetrics.snapshot>;
