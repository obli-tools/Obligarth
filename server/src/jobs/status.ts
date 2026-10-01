import { db } from '../db';

// =============================================================================
// job_status: the last run of each queue ('' key), and of each tenant for the
// fan-outs that track it ('t:<tenant id>'). Written by the execution envelope
// only (never by a handler), at the start and at the end of each tracked run;
// read by the admin API, the health route and the monitor. Platform table, no
// tenant data: ids, timestamps, error codes (rls-tenant §5.7, RLS-RC10).
// Runs in the caller's database context (the run's 'none').
// =============================================================================

export interface JobStatusRow {
  queue: string;
  key: string;
  lastJobId: string | null;
  lastStartedAt: Date | null;
  lastSucceededAt: Date | null;
  lastFailedAt: Date | null;
  lastErrorCode: string | null;
  consecutiveFailures: number;
  lastDurationMs: number | null;
  succeededCount: number;
  failedCount: number;
  updatedAt: Date;
}

type Raw = { rows: Array<Record<string, unknown>> };

const date = (v: unknown): Date | null => (v instanceof Date ? v : v ? new Date(String(v)) : null);

function toRow(r: Record<string, unknown>): JobStatusRow {
  return {
    queue: String(r.queue),
    key: String(r.key ?? ''),
    lastJobId: (r.last_job_id as string | null) ?? null,
    lastStartedAt: date(r.last_started_at),
    lastSucceededAt: date(r.last_succeeded_at),
    lastFailedAt: date(r.last_failed_at),
    lastErrorCode: (r.last_error_code as string | null) ?? null,
    consecutiveFailures: Number(r.consecutive_failures ?? 0),
    lastDurationMs: r.last_duration_ms === null || r.last_duration_ms === undefined ? null : Number(r.last_duration_ms),
    succeededCount: Number(r.succeeded_count ?? 0),
    failedCount: Number(r.failed_count ?? 0),
    updatedAt: date(r.updated_at) ?? new Date(0),
  };
}

const clampMs = (ms: number): number => Math.max(0, Math.min(2_147_483_647, Math.round(ms)));

export const jobStatus = {
  async started(queue: string, key: string, jobId: string): Promise<void> {
    await db.raw(
      `INSERT INTO job_status (queue, key, last_job_id, last_started_at, updated_at)
       VALUES (?, ?, ?, now(), now())
       ON CONFLICT (queue, key) DO UPDATE
          SET last_job_id = EXCLUDED.last_job_id, last_started_at = now(), updated_at = now()`,
      [queue, key, jobId],
    );
  },

  async succeeded(queue: string, key: string, durationMs: number): Promise<void> {
    await db.raw(
      `INSERT INTO job_status (queue, key, last_succeeded_at, consecutive_failures, last_duration_ms, succeeded_count, updated_at)
       VALUES (?, ?, now(), 0, ?, 1, now())
       ON CONFLICT (queue, key) DO UPDATE
          SET last_succeeded_at = now(), consecutive_failures = 0, last_duration_ms = EXCLUDED.last_duration_ms,
              succeeded_count = job_status.succeeded_count + 1, updated_at = now()`,
      [queue, key, clampMs(durationMs)],
    );
  },

  /** Returns the consecutive failures, this one included. */
  async failed(queue: string, key: string, code: string, durationMs: number): Promise<number> {
    const res = await db.raw(
      `INSERT INTO job_status (queue, key, last_failed_at, last_error_code, consecutive_failures, last_duration_ms, failed_count, updated_at)
       VALUES (?, ?, now(), ?, 1, ?, 1, now())
       ON CONFLICT (queue, key) DO UPDATE
          SET last_failed_at = now(), last_error_code = EXCLUDED.last_error_code,
              consecutive_failures = job_status.consecutive_failures + 1, last_duration_ms = EXCLUDED.last_duration_ms,
              failed_count = job_status.failed_count + 1, updated_at = now()
       RETURNING consecutive_failures`,
      [queue, key, code.slice(0, 64), clampMs(durationMs)],
    ) as Raw;
    return Number(res.rows[0]?.consecutive_failures ?? 0);
  },

  /** Every row ('' keys first), or those of some queues. */
  async list(queues?: readonly string[]): Promise<JobStatusRow[]> {
    const q = db('job_status').select('*').orderBy([{ column: 'queue' }, { column: 'key' }]);
    if (queues) q.whereIn('queue', [...queues]);
    return (await q as Array<Record<string, unknown>>).map(toRow);
  },

  async get(queue: string, key = ''): Promise<JobStatusRow | null> {
    const row = await db('job_status').where({ queue, key }).first() as Record<string, unknown> | undefined;
    return row ? toRow(row) : null;
  },

  /** jobs.housekeeping: rows of queues no longer registered, untouched for
   *  `days` days. */
  async purgeRetired(registered: readonly string[], days: number): Promise<number> {
    const q = db('job_status').where('updated_at', '<', db.raw('now() - make_interval(days => ?)', [days]));
    if (registered.length) q.whereNotIn('queue', [...registered]);
    return q.delete();
  },
};
