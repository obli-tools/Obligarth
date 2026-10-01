import { AppError } from '../middleware/errorHandler';
import { PGBOSS_SCHEMA_VERSION, PGBOSS_VERSION } from './boss';
import { DEAD_LETTER_QUEUE, QUEUE_NAME_RE } from './registry';
import type { JobsRuntime } from './runtime';
import { jobStatus, type JobStatusRow } from './status';

// =============================================================================
// Administration of the jobs (platform administrators of the master tenant,
// admin.routes.ts; an approved 'jobs_manage' request, core.jobs.ts): the
// overview, the jobs of a queue, the shared dead letters, a manual run, a
// cancel, a redrive, a discard. Reads of pgboss.job are bounded (ORDER BY
// created_on DESC LIMIT); a payload is ids only (registry rule 6).
// =============================================================================

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type JobListState = 'queued' | 'active' | 'failed' | 'completed' | 'cancelled';
const STATES: Record<JobListState, string[]> = {
  queued: ['created', 'retry'],
  active: ['active'],
  failed: ['failed'],
  completed: ['completed'],
  cancelled: ['cancelled'],
};

export function isJobListState(s: unknown): s is JobListState {
  return typeof s === 'string' && Object.prototype.hasOwnProperty.call(STATES, s);
}

/** A queue name the API may name: a registered or retired job queue, or
 *  the dead letters; never pg-boss's internal queues. */
export function isQueueName(name: unknown): name is string {
  return typeof name === 'string' && (name === DEAD_LETTER_QUEUE || (QUEUE_NAME_RE.test(name) && name.length <= 64));
}

const iso = (d: unknown): string | null => (d instanceof Date ? d.toISOString() : d ? new Date(String(d)).toISOString() : null);

function statusOut(s: JobStatusRow | undefined) {
  return s
    ? {
      lastStartedAt: iso(s.lastStartedAt), lastSucceededAt: iso(s.lastSucceededAt), lastFailedAt: iso(s.lastFailedAt),
      lastErrorCode: s.lastErrorCode, consecutiveFailures: s.consecutiveFailures, lastDurationMs: s.lastDurationMs,
    }
    : null;
}

export function createJobsAdmin(runtime: JobsRuntime) {
  const boss = () => {
    if (!runtime.isStarted()) throw new AppError(503, 'Background jobs are not started', 'jobsNotStarted');
    return runtime.bossOrThrow();
  };
  const sql = async (text: string, values: unknown[]) => (await boss().getDb().executeSql(text, values)).rows as Array<Record<string, unknown>>;

  return {
    /** GET /api/admin/jobs */
    async overview() {
      const b = boss();
      const [queues, status, deadLetters] = await Promise.all([b.getQueues(), jobStatus.list(), runtime.deadLetterCounts()]);
      const byQueue = new Map(status.filter((s) => s.key === '').map((s) => [s.queue, s]));
      const tenantRows = status.filter((s) => s.key !== '');
      const registered = new Map(runtime.registry.list().map((d) => [d.name, d]));
      const names = [...new Set([...registered.keys(), ...queues.map((q) => q.name)])]
        .filter((n) => n !== DEAD_LETTER_QUEUE && !n.startsWith('__pgboss'))
        .sort();
      const counts = new Map(queues.map((q) => [q.name, q]));
      return {
        mode: runtime.mode(),
        workers: runtime.workersStarted(),
        pgBoss: { version: PGBOSS_VERSION, schemaVersion: PGBOSS_SCHEMA_VERSION },
        queues: names.map((name) => {
          const def = registered.get(name);
          const q = counts.get(name);
          const tenants = tenantRows.filter((s) => s.queue === name);
          return {
            name,
            registered: !!def,
            module: def?.module ?? name.split('.')[0],
            scope: def?.scope ?? null,
            description: def?.description ?? null,
            policy: def?.policy ?? q?.policy ?? null,
            schedule: def?.schedule ? { cron: def.schedule.cron, tz: def.schedule.tz, missed: def.schedule.missed } : null,
            manualRun: def?.manualRun ?? false,
            redrivable: def?.redrivable ?? true,
            counts: q
              ? { ready: Number(q.readyCount), deferred: Number(q.deferredCount), active: Number(q.activeCount), failed: Number(q.failedCount) }
              : { ready: 0, deferred: 0, active: 0, failed: 0 },
            status: statusOut(byQueue.get(name)),
            ...(def?.trackStatus === 'tenant'
              ? { tenants: { tracked: tenants.length, failing: tenants.filter((s) => s.consecutiveFailures > 0).length } }
              : {}),
          };
        }),
        deadLetters: {
          total: deadLetters.reduce((n, d) => n + d.count, 0),
          bySource: Object.fromEntries(deadLetters.map((d) => [d.source, d.count])),
        },
        // The apple-edge outbox consumer arrives with the integration (lot B).
        outbox: { consumer: 'disabled', pending: null, retrying: null, oldestPendingSeconds: null, deadLetters: null },
      };
    },

    /** GET /api/admin/jobs/:queue/jobs */
    async listJobs(queue: string, state: JobListState | null, limit: number) {
      if (!isQueueName(queue)) throw new AppError(404, 'Queue not found', 'queueNotFound');
      if (!(await boss().getQueue(queue))) throw new AppError(404, 'Queue not found', 'queueNotFound');
      const states = state ? STATES[state] : null;
      const rows = await sql(
        `SELECT id, name, state, created_on, started_on, completed_on, retry_count, singleton_key, data, output
           FROM pgboss.job
          WHERE name = $1 ${states ? 'AND state = ANY($3::pgboss.job_state[])' : ''}
          ORDER BY created_on DESC
          LIMIT $2`,
        states ? [queue, limit, states] : [queue, limit],
      );
      return rows.map((r) => ({
        id: r.id, state: r.state, createdOn: iso(r.created_on), startedOn: iso(r.started_on), completedOn: iso(r.completed_on),
        retryCount: Number(r.retry_count), singletonKey: r.singleton_key ?? null, data: r.data ?? null, output: r.output ?? null,
      }));
    },

    /** GET /api/admin/jobs/dead-letters */
    async listDeadLetters(source: string | null, limit: number) {
      if (source !== null && !isQueueName(source)) throw new AppError(400, 'Invalid source queue', 'invalidQueue');
      const rows = await sql(
        `SELECT id, source_name, source_id, source_retry_count, source_output, data, created_on
           FROM pgboss.job
          WHERE name = $1 ${source !== null ? 'AND source_name = $3' : ''}
          ORDER BY created_on DESC
          LIMIT $2`,
        source !== null ? [DEAD_LETTER_QUEUE, limit, source] : [DEAD_LETTER_QUEUE, limit],
      );
      return rows.map((r) => ({
        id: r.id, sourceName: r.source_name ?? null, sourceId: r.source_id ?? null,
        sourceRetryCount: r.source_retry_count === null || r.source_retry_count === undefined ? null : Number(r.source_retry_count),
        sourceOutput: r.source_output ?? null, data: r.data ?? null, createdOn: iso(r.created_on),
      }));
    },

    /** POST /api/admin/jobs/:queue/run: one run now, through the same
     *  (empty) key as the schedule: null when a run is queued or active. */
    async runNow(queue: string): Promise<{ jobId: string | null }> {
      const def = isQueueName(queue) ? runtime.registry.get(queue) : undefined;
      if (!def) throw new AppError(404, 'Queue not found', 'queueNotFound');
      if (!def.manualRun || def.scope !== 'platform') throw new AppError(409, 'This job cannot be run by hand', 'jobNotManual');
      boss();
      const jobId = await runtime.sendJob(def, def.schedule?.data ?? {}, {}, null);
      if (jobId) runtime.wake(def.name);
      return { jobId };
    },

    /** POST /api/admin/jobs/:queue/jobs/:id/cancel: a job queued or
     *  deferred (never one running). */
    async cancelJob(queue: string, id: string): Promise<void> {
      if (!isQueueName(queue) || queue === DEAD_LETTER_QUEUE || !UUID_RE.test(id)) throw new AppError(404, 'Job not found', 'jobNotFound');
      const rows = await sql('SELECT state FROM pgboss.job WHERE name = $1 AND id = $2', [queue, id]);
      if (rows.length === 0) throw new AppError(404, 'Job not found', 'jobNotFound');
      if (!['created', 'retry'].includes(String(rows[0].state))) {
        throw new AppError(409, 'Only a queued or deferred job can be cancelled', 'jobNotCancellable');
      }
      await boss().cancel(queue, id);
    },

    /** POST /api/admin/jobs/dead-letters/redrive: back to their source
     *  queue (100 at most per call); refused (409) for a queue declared
     *  redrivable: false (destructive actions). */
    async redrive(input: { ids?: string[]; source?: string }): Promise<{ moved: number; sources: string[] }> {
      const ids = input.ids;
      const source = input.source;
      if (ids === undefined && source === undefined) throw new AppError(400, 'Give the ids or the source queue to redrive', 'redriveTargetMissing');
      if (ids !== undefined && (!Array.isArray(ids) || ids.length === 0 || ids.length > 100 || !ids.every((x) => typeof x === 'string' && UUID_RE.test(x)))) {
        throw new AppError(400, 'ids: 1 to 100 job ids', 'invalidIds');
      }
      if (source !== undefined && (!isQueueName(source) || source === DEAD_LETTER_QUEUE)) throw new AppError(400, 'Invalid source queue', 'invalidQueue');
      const found = await sql(
        `SELECT DISTINCT COALESCE(source_name, '') AS source FROM pgboss.job
          WHERE name = $1 ${ids ? 'AND id = ANY($2::uuid[])' : ''} ${source !== undefined ? `AND source_name = $${ids ? 3 : 2}` : ''}`,
        [DEAD_LETTER_QUEUE, ...(ids ? [ids] : []), ...(source !== undefined ? [source] : [])],
      );
      const sources = found.map((r) => String(r.source));
      if (sources.length === 0) return { moved: 0, sources: [] };
      for (const s of sources) {
        if (runtime.registry.get(s)?.redrivable === false) {
          throw new AppError(409, `Jobs of ${s} are never redriven (destructive action)`, 'notRedrivable');
        }
      }
      const moved = await boss().redrive(DEAD_LETTER_QUEUE, {
        ...(ids ? { ids } : {}), ...(source !== undefined ? { sourceName: source } : {}), limit: 100,
      });
      for (const s of sources) runtime.wake(s);
      return { moved, sources };
    },

    /** DELETE /api/admin/jobs/dead-letters/:id */
    async discard(id: string): Promise<{ sourceName: string | null; sourceId: string | null }> {
      if (!UUID_RE.test(id)) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
      const rows = await sql('SELECT source_name, source_id FROM pgboss.job WHERE name = $1 AND id = $2', [DEAD_LETTER_QUEUE, id]);
      if (rows.length === 0) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
      await boss().deleteJob(DEAD_LETTER_QUEUE, id);
      return { sourceName: (rows[0].source_name as string | null) ?? null, sourceId: (rows[0].source_id as string | null) ?? null };
    },
  };
}

export type JobsAdmin = ReturnType<typeof createJobsAdmin>;
