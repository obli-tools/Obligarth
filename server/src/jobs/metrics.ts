// =============================================================================
// Metrics of the jobs: in-process counters of the execution envelope, and the
// snapshot handed to the observability work (FND-14), which publishes it. No
// tenant label (cardinality, and no client name in the metrics).
// =============================================================================

export type RunOutcome = 'completed' | 'retry' | 'failed' | 'invalid' | 'skipped';

/** obligarth_job_run_duration_seconds buckets. */
export const DURATION_BUCKETS_S = [0.05, 0.25, 1, 5, 15, 60, 300, 900] as const;

interface Histogram { buckets: number[]; sum: number; count: number }

const runs = new Map<string, number>();
const durations = new Map<string, Histogram>();

export const jobMetrics = {
  /** One run of `queue`, its outcome and duration (absent for the runs that
   *  never reached the handler). */
  run(queue: string, outcome: RunOutcome, durationMs?: number): void {
    const k = `${queue}|${outcome}`;
    runs.set(k, (runs.get(k) ?? 0) + 1);
    if (durationMs === undefined || !Number.isFinite(durationMs)) return;
    const s = Math.max(0, durationMs) / 1000;
    let h = durations.get(queue);
    if (!h) { h = { buckets: DURATION_BUCKETS_S.map(() => 0), sum: 0, count: 0 }; durations.set(queue, h); }
    DURATION_BUCKETS_S.forEach((le, i) => { if (s <= le) h!.buckets[i] += 1; });
    h.sum += s;
    h.count += 1;
  },

  /** obligarth_job_runs_total{queue, outcome}. */
  runCounters(): Array<{ queue: string; outcome: RunOutcome; value: number }> {
    return [...runs.entries()].map(([k, value]) => {
      const i = k.lastIndexOf('|');
      return { queue: k.slice(0, i), outcome: k.slice(i + 1) as RunOutcome, value };
    });
  },

  /** obligarth_job_run_duration_seconds{queue} (cumulative buckets). */
  durationHistograms(): Array<{ queue: string; buckets: Array<{ le: number; count: number }>; sum: number; count: number }> {
    return [...durations.entries()].map(([queue, h]) => ({
      queue,
      buckets: DURATION_BUCKETS_S.map((le, i) => ({ le, count: h.buckets[i] })),
      sum: h.sum,
      count: h.count,
    }));
  },
};

/** What jobs.metricsSnapshot() returns (names: file-durable §8.3). */
export interface JobsMetricsSnapshot {
  generatedAt: string;
  /** obligarth_job_runs_total{queue, outcome} */
  runs: Array<{ queue: string; outcome: RunOutcome; value: number }>;
  /** obligarth_job_run_duration_seconds{queue} */
  durations: Array<{ queue: string; buckets: Array<{ le: number; count: number }>; sum: number; count: number }>;
  /** obligarth_job_queue_ready / _deferred / _active / _failed{queue} */
  queues: Array<{ queue: string; ready: number; deferred: number; active: number; failed: number }>;
  /** obligarth_job_oldest_ready_seconds{queue} */
  oldestReady: Array<{ queue: string; seconds: number }>;
  /** obligarth_job_dead_letters{source} */
  deadLetters: Array<{ source: string; count: number }>;
  /** obligarth_job_schedule_last_success_timestamp_seconds{queue} */
  scheduleLastSuccess: Array<{ queue: string; timestampSeconds: number }>;
  /** obligarth_job_heartbeat_age_seconds (null: never beaten) */
  heartbeatAgeSeconds: number | null;
}
