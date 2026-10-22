import { randomUUID } from 'node:crypto';
import pg from 'pg';
import type { Knex } from 'knex';
import type { z } from 'zod';
import { config } from '../config';
import { asNone, currentDbContext } from '../db/context';
import { logger } from '../utils/logger';
import {
  createBoss, knexDb, PGBOSS_SCHEMA_VERSION, PGBOSS_VERSION,
  type BossOptions, type Clock, type PgBoss, type QueueResult, type SendOptions,
} from './boss';
import { JobError, safeErr } from './errors';
import { DEAD_LETTER_QUEUE, JobRegistry, QUEUE_NAME_RE, SINGLETON_KEY_RE } from './registry';
import { jobMetrics, type JobsMetricsSnapshot } from './metrics';
import { jobStatus } from './status';
import { runJobs } from './wrapper';
import type { JobDefinition, JobHandle, JobsMode, RegisteredJob, SendJobOptions, SendManyOptions } from './types';

// =============================================================================
// Runtime of the jobs: the pg-boss instance and its life (start, workers,
// stop), the synchronisation of the registry with the database (queues,
// schedules, sends at start), and the sends of the handles. index.ts drives
// the default runtime (jobs/index.ts); tests may build their own.
//
// Modes (JOBS_MODE): all runs jobs and schedules; api never runs a job nor a
// cron pass (replica serving the API: queues created, schedules untouched);
// paused keeps everything queued (restore, incident): maintenance runs,
// nothing executes, /health/jobs answers 503.
// =============================================================================

/** Queues created with the wrong policy by an earlier version (until 0.1.5, the policy of these jobs depended on
 *  APPLE_EDGE_MODE and OUTBOX_CONSUMER: standard when off, exclusive when on). Their jobs are probes and catch-ups
 *  re-sent by their schedule: a queue with another policy is deleted and recreated instead of refusing to start. */
const RECREATED_ON_POLICY_CHANGE = new Set(['apple-edge.provision-all', 'apple-edge.health', 'apple-edge.outbox-monitor']);

/** A start that must stop the server (exit code 1), with a message for the
 *  operator. */
export class JobsStartError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JobsStartError';
  }
}

export interface JobsStartOptions {
  mode?: JobsMode;
  /** Tests: another database than DATABASE_URL. */
  connectionString?: string;
  poolMax?: number;
  listenNotify?: boolean;
  stopTimeoutMs?: number;
  /** Tests only, never read from the environment. */
  clock?: Clock;
  spies?: boolean;
  intervals?: BossOptions['intervals'];
}

/** Largest serialized payload of a job. */
export const MAX_PAYLOAD_BYTES = 8 * 1024;
/** Retention of the shared dead letter queue (jobs never started). */
const DEAD_LETTER_RETENTION_SECONDS = 30 * 86_400;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Cache of the oldest-ready reading (metrics). */
const OLDEST_READY_CACHE_MS = 30_000;
/** Jobs written by one statement of a grouped send (sendManyInTx). */
const SEND_MANY_BATCH = 1000;

type QueueOptionsWanted = {
  policy: string;
  retryLimit: number;
  retryDelay: number;
  retryBackoff: boolean;
  retryDelayMax: number | null;
  expireInSeconds: number;
  retentionSeconds: number;
  deleteAfterSeconds: number;
  heartbeatSeconds: number | null;
  deadLetter: string | null;
  warningQueueSize: number;
  notify: boolean;
};

function queueOptions(def: RegisteredJob): QueueOptionsWanted {
  return {
    policy: def.policy,
    retryLimit: def.retry.limit,
    retryDelay: def.retry.delaySeconds,
    retryBackoff: def.retry.backoff,
    retryDelayMax: def.retry.backoff && def.retry.maxDelaySeconds !== undefined ? def.retry.maxDelaySeconds : null,
    expireInSeconds: def.timeoutSeconds,
    retentionSeconds: def.keepPendingSeconds,
    deleteAfterSeconds: def.keepFinishedSeconds,
    heartbeatSeconds: def.heartbeatSeconds,
    deadLetter: def.deadLetter ? DEAD_LETTER_QUEUE : null,
    warningQueueSize: def.warningQueueSize,
    notify: def.notify,
  };
}

/** The modifiable options of `have` that differ from `want` (empty: none). */
function changedOptions(have: QueueResult, want: QueueOptionsWanted): Record<string, unknown> {
  const norm = (v: unknown): unknown => (v === undefined ? null : v);
  const keys = [
    'retryLimit', 'retryDelay', 'retryBackoff', 'retryDelayMax', 'expireInSeconds', 'retentionSeconds',
    'deleteAfterSeconds', 'heartbeatSeconds', 'deadLetter', 'warningQueueSize', 'notify',
  ] as const;
  const changed = keys.filter((k) => norm((have as unknown as Record<string, unknown>)[k]) !== norm(want[k]));
  if (changed.length === 0) return {};
  // The retry options travel together (pg-boss checks retryDelayMax against retryBackoff).
  const out: Record<string, unknown> = {
    retryLimit: want.retryLimit, retryDelay: want.retryDelay, retryBackoff: want.retryBackoff, retryDelayMax: want.retryDelayMax,
  };
  for (const k of changed) out[k] = want[k];
  return out;
}

function createOptions(want: QueueOptionsWanted): Record<string, unknown> {
  const o: Record<string, unknown> = { ...want };
  for (const k of ['retryDelayMax', 'heartbeatSeconds', 'deadLetter'] as const) if (o[k] === null) delete o[k];
  return o;
}

export class JobsRuntime {
  readonly registry = new JobRegistry();
  private boss: PgBoss | null = null;
  private state: 'idle' | 'starting' | 'started' | 'stopping' | 'stopped' = 'idle';
  private workersRunning = false;
  private runMode: JobsMode = config.jobs.mode;
  private stopTimeoutMs = config.jobs.stopTimeoutMs;
  private stopping: Promise<void> | null = null;
  private oldestReadyCache: { at: number; rows: Array<{ queue: string; seconds: number }> } | null = null;
  /** The work id of each queue's workers (pg-boss), to wake them. */
  private readonly workIds = new Map<string, string>();
  startedAt: Date | null = null;

  /** Declares a job (before the start); returns its handle. */
  register<S extends z.ZodTypeAny>(def: JobDefinition<S>): JobHandle<z.infer<S>> {
    const job = this.registry.register(def as unknown as JobDefinition<z.ZodTypeAny>);
    return {
      name: job.name,
      send: (payload, opts) => this.sendJob(job, payload, opts ?? {}, null),
      sendInTx: (trx, payload, opts) => this.sendJob(job, payload, opts ?? {}, trx),
      sendManyInTx: (trx, items) => this.sendJobs(job, items, trx),
      cancel: async (jobId) => { await this.bossOrThrow().cancel(job.name, jobId); },
    };
  }

  mode(): JobsMode {
    return this.runMode;
  }

  /** pg-boss started: sends accepted. */
  isStarted(): boolean {
    return (this.state === 'started' || this.state === 'stopping') && this.boss !== null;
  }

  workersStarted(): boolean {
    return this.workersRunning;
  }

  /** The pg-boss instance (admin, health, metrics); JobError before the start. */
  bossOrThrow(): PgBoss {
    if (!this.boss || !this.isStarted()) throw new JobError('jobs_not_started', 'the job runtime is not started');
    return this.boss;
  }

  // ── Start ──────────────────────────────────────────────────────────────────

  /** pg-boss started (installation or migration of the schema pgboss),
   *  queues and schedules synchronised, sends at start. Throws
   *  JobsStartError (or a database error): the server must not start. */
  async start(opts: JobsStartOptions = {}): Promise<void> {
    if (this.state !== 'idle') throw new Error('the job runtime was already started');
    this.state = 'starting';
    this.registry.freeze();
    this.runMode = opts.mode ?? config.jobs.mode;
    this.stopTimeoutMs = opts.stopTimeoutMs ?? config.jobs.stopTimeoutMs;
    const connectionString = opts.connectionString ?? config.databaseUrl;
    try {
      await checkPgbossSchema(connectionString);
      const boss = createBoss({
        connectionString,
        mode: this.runMode,
        poolMax: opts.poolMax ?? config.jobs.poolMax,
        listenNotify: opts.listenNotify ?? config.jobs.listenNotify,
        clock: opts.clock,
        spies: opts.spies,
        intervals: opts.intervals,
      });
      this.boss = boss;
      await boss.start();
      const installed = await boss.schemaVersion();
      if (installed !== PGBOSS_SCHEMA_VERSION) {
        throw new JobsStartError(`schema pgboss at version ${installed}, expected ${PGBOSS_SCHEMA_VERSION} (pg-boss ${PGBOSS_VERSION})`);
      }
      await this.syncQueues(boss);
      if (this.runMode !== 'api') await this.syncSchedules(boss);
      this.state = 'started';
      this.startedAt = new Date();
      if (this.runMode === 'all') await this.sendAtStart();
      logger.info({ mode: this.runMode, queues: this.registry.list().length, pgBoss: PGBOSS_VERSION, schema: PGBOSS_SCHEMA_VERSION },
        'background jobs started');
    } catch (err) {
      const boss = this.boss;
      this.boss = null;
      this.state = 'stopped';
      if (boss) await boss.stop({ graceful: false }).catch(() => undefined);
      throw err;
    }
  }

  private async syncQueues(boss: PgBoss): Promise<void> {
    if (!(await boss.getQueue(DEAD_LETTER_QUEUE))) {
      await boss.createQueue(DEAD_LETTER_QUEUE, { policy: 'standard', retentionSeconds: DEAD_LETTER_RETENTION_SECONDS });
    }
    const conflicts: string[] = [];
    for (const def of this.registry.list()) {
      const want = queueOptions(def);
      const have = await boss.getQueue(def.name);
      if (!have) {
        await boss.createQueue(def.name, createOptions(want));
        continue;
      }
      if ((have.policy ?? 'standard') !== def.policy && RECREATED_ON_POLICY_CHANGE.has(def.name)) {
        // Only idempotent jobs re-sent by their schedule: their queue is recreated, its jobs dropped.
        await boss.deleteQueue(def.name);
        await boss.createQueue(def.name, createOptions(want));
        logger.warn({ queue: def.name, from: have.policy ?? 'standard', to: def.policy },
          'job queue recreated with the policy of this server (its pending jobs were dropped)');
        continue;
      }
      if ((have.policy ?? 'standard') !== def.policy) {
        conflicts.push(`queue ${def.name}: policy "${have.policy}" in the database, "${def.policy}" in this server — a policy never ` +
          'changes in place: register the job under a new queue name (…-v2), the old queue is then reported as unknown');
        continue;
      }
      const changed = changedOptions(have, want);
      if (Object.keys(changed).length > 0) {
        await boss.updateQueue(def.name, changed);
        logger.info({ queue: def.name, changed: Object.keys(changed) }, 'job queue options updated');
      }
    }
    if (conflicts.length) throw new JobsStartError(conflicts.join('; '));
    const known = new Set(this.registry.list().map((d) => d.name));
    for (const q of await boss.getQueues()) {
      if (known.has(q.name) || q.name === DEAD_LETTER_QUEUE || q.name.startsWith('__pgboss')) continue;
      logger.warn({ queue: q.name, queued: q.queuedCount, active: q.activeCount },
        'job queue in the database but not registered: kept (its jobs stay visible in the admin API)');
    }
  }

  private async syncSchedules(boss: PgBoss): Promise<void> {
    for (const def of this.registry.list()) {
      if (!def.schedule) continue;
      // No singletonKey: the scheduled occurrences, the start and the manual
      // runs share the empty key, so the policy's unique index (name, key)
      // keeps them from running together.
      await boss.schedule(def.name, def.schedule.cron, def.schedule.data, { tz: def.schedule.tz, missed: def.schedule.missed });
    }
    for (const s of await boss.getSchedules()) {
      const def = this.registry.get(s.name);
      if (def?.schedule || !QUEUE_NAME_RE.test(s.name)) continue;
      await boss.unschedule(s.name, s.key);
      logger.info({ queue: s.name, cron: s.cron }, 'schedule of a job no longer scheduled: removed');
    }
  }

  private async sendAtStart(): Promise<void> {
    for (const def of this.registry.list()) {
      if (!def.runAtStart) continue;
      // Same (empty) key as the scheduled occurrences: no effect when a run
      // of the queue is already queued or active (exclusive, stately).
      const id = await this.sendJob(def, def.schedule?.data ?? {}, {}, null);
      logger.debug({ queue: def.name, jobId: id }, id ? 'job sent at start' : 'job at start: one already queued or active');
    }
  }

  /** Workers of every job (mode all only), after Socket.io: handlers emit
   *  real-time events. */
  async startWorkers(): Promise<void> {
    if (this.runMode !== 'all' || this.workersRunning) return;
    const boss = this.bossOrThrow();
    for (const def of this.registry.list()) {
      // One job per fetch (a disposition per job, no batch held by a slow
      // job). A worker waits its polling interval between two fetches, even
      // after a fetch that found a job: through a backlog it fetches
      // continuously instead (burst) while the queue's cached ready count
      // shows more than one job ready.
      const options = {
        batchSize: 1,
        perJobResults: true,
        pollingIntervalSeconds: def.pollSeconds,
        burstWhenReadyExceeds: 1,
        localConcurrency: def.concurrency.local,
        ...(def.concurrency.perTenant !== null ? { groupConcurrency: def.concurrency.perTenant } : {}),
      } as const;
      this.workIds.set(def.name, await boss.work<unknown>(def.name, options, (jobs) => runJobs(def, jobs)));
    }
    this.workersRunning = true;
    logger.info({ queues: this.registry.list().length }, 'background job workers started');
  }

  /** Wakes this instance's workers of `queue` (a job sent by hand should not
   *  wait for the next poll); the workers of another instance poll as usual. */
  wake(queue: string): void {
    const id = this.workIds.get(queue);
    if (id && this.boss && this.workersRunning) this.boss.notifyWorker(id);
  }

  // ── Stop ───────────────────────────────────────────────────────────────────

  /** Idempotent. pg-boss stops gracefully: running handlers get
   *  stopTimeoutMs to finish, then their jobs are failed (retried later)
   *  and their signal aborted. */
  async stop(): Promise<void> {
    if (this.stopping) return this.stopping;
    const boss = this.boss;
    if (!boss) {
      this.state = this.state === 'idle' ? 'idle' : 'stopped';
      return;
    }
    this.state = 'stopping';
    this.stopping = (async () => {
      try {
        await boss.stop({ graceful: true, timeout: this.stopTimeoutMs });
      } catch (err) {
        logger.warn({ err: safeErr(err) }, 'background jobs: stop error');
      } finally {
        this.boss = null;
        this.workersRunning = false;
        this.workIds.clear();
        this.state = 'stopped';
        logger.info('background jobs stopped');
      }
    })();
    return this.stopping;
  }

  // ── Sends ──────────────────────────────────────────────────────────────────

  async sendJob(def: RegisteredJob, payload: unknown, opts: SendJobOptions, trx: Knex.Transaction | null): Promise<string | null> {
    const boss = this.bossOrThrow();
    const parsed = def.payload.safeParse(payload);
    if (!parsed.success) throw new JobError('invalid_payload', `payload of ${def.name} refused by its schema`, false);
    const data = parsed.data as Record<string, unknown>;
    if (Buffer.byteLength(JSON.stringify(data), 'utf8') > MAX_PAYLOAD_BYTES) {
      throw new JobError('payload_too_large', `payload of ${def.name} over ${MAX_PAYLOAD_BYTES} bytes`, false);
    }
    const bad = (message: string): never => { throw new JobError('invalid_send_options', `${def.name}: ${message}`, false); };
    const options: SendOptions = {};
    if (opts.id !== undefined) {
      if (typeof opts.id !== 'string' || !UUID_RE.test(opts.id)) bad('id must be a lower-case UUID');
      options.id = opts.id;
    }
    if (opts.singletonKey !== undefined) {
      if (typeof opts.singletonKey !== 'string' || !SINGLETON_KEY_RE.test(opts.singletonKey)) bad('invalid singletonKey');
      options.singletonKey = opts.singletonKey;
    }
    if (opts.startAfter !== undefined) {
      if (opts.startAfter instanceof Date) {
        if (Number.isNaN(opts.startAfter.getTime())) bad('invalid startAfter date');
        options.startAfter = opts.startAfter;
      } else if (typeof opts.startAfter === 'number' && Number.isFinite(opts.startAfter) && opts.startAfter >= 0) {
        options.startAfter = Math.round(opts.startAfter);
      } else bad('startAfter must be a Date or a number of seconds');
    }
    if (opts.priority !== undefined) {
      if (!Number.isInteger(opts.priority)) bad('priority must be an integer');
      options.priority = opts.priority;
    }
    const payloadTenant = typeof data.tenantId === 'number' ? data.tenantId : null;
    if (opts.tenantId !== undefined) {
      if (!Number.isSafeInteger(opts.tenantId) || opts.tenantId <= 0) bad('tenantId must be a positive integer');
      if (payloadTenant !== null && payloadTenant !== opts.tenantId) bad('tenantId differs from payload.tenantId');
    }
    const groupTenant = opts.tenantId ?? payloadTenant;
    if (groupTenant !== null && def.concurrency.perTenant !== null) options.group = { id: `t:${groupTenant}` };
    if (trx) options.db = knexDb(trx);
    if (opts.debounceSeconds !== undefined || opts.throttleSeconds !== undefined) {
      if (opts.debounceSeconds !== undefined && opts.throttleSeconds !== undefined) bad('debounceSeconds or throttleSeconds, not both');
      if (!options.singletonKey) bad('debounce and throttle need a singletonKey');
      const seconds = opts.debounceSeconds ?? opts.throttleSeconds!;
      if (!Number.isInteger(seconds) || seconds < 1 || seconds > 86_400) bad('debounce / throttle window: 1 to 86400 seconds');
      const key = options.singletonKey!;
      const sendOptions = { ...options };
      delete sendOptions.singletonKey;
      return opts.debounceSeconds !== undefined
        ? boss.sendDebounced(def.name, data, sendOptions, seconds, key)
        : boss.sendThrottled(def.name, data, sendOptions, seconds, key);
    }
    return boss.send(def.name, data, options);
  }

  /**
   * Several jobs of one queue in the caller's transaction, a thousand per statement (pg-boss insert: the statement
   * of send, which takes the retries, the expiry, the retention and the policy from the queue, and ends in ON
   * CONFLICT DO NOTHING). Same controls as sendJob on each payload; the options of a grouped send are the
   * singletonKey and the tenant. Answers one entry per job, in order: its id, or null when the queue's policy (or
   * a key given twice) absorbed it.
   */
  async sendJobs(def: RegisteredJob, items: ReadonlyArray<{ payload: unknown; opts?: SendManyOptions }>, trx: Knex.Transaction): Promise<Array<string | null>> {
    const boss = this.bossOrThrow();
    const bad = (message: string): never => { throw new JobError('invalid_send_options', `${def.name}: ${message}`, false); };
    const jobs: Array<{ id: string; data: Record<string, unknown>; singletonKey?: string; group?: { id: string } }> = [];
    for (const item of items) {
      const parsed = def.payload.safeParse(item.payload);
      if (!parsed.success) throw new JobError('invalid_payload', `payload of ${def.name} refused by its schema`, false);
      const data = parsed.data as Record<string, unknown>;
      if (Buffer.byteLength(JSON.stringify(data), 'utf8') > MAX_PAYLOAD_BYTES) {
        throw new JobError('payload_too_large', `payload of ${def.name} over ${MAX_PAYLOAD_BYTES} bytes`, false);
      }
      const opts = item.opts ?? {};
      const job: (typeof jobs)[number] = { id: randomUUID(), data };
      if (opts.singletonKey !== undefined) {
        if (typeof opts.singletonKey !== 'string' || !SINGLETON_KEY_RE.test(opts.singletonKey)) bad('invalid singletonKey');
        job.singletonKey = opts.singletonKey;
      }
      const payloadTenant = typeof data.tenantId === 'number' ? data.tenantId : null;
      if (opts.tenantId !== undefined) {
        if (!Number.isSafeInteger(opts.tenantId) || opts.tenantId <= 0) bad('tenantId must be a positive integer');
        if (payloadTenant !== null && payloadTenant !== opts.tenantId) bad('tenantId differs from payload.tenantId');
      }
      const groupTenant = opts.tenantId ?? payloadTenant;
      if (groupTenant !== null && def.concurrency.perTenant !== null) job.group = { id: `t:${groupTenant}` };
      jobs.push(job);
    }
    const out: Array<string | null> = [];
    const database = knexDb(trx);
    for (let i = 0; i < jobs.length; i += SEND_MANY_BATCH) {
      const slice = jobs.slice(i, i + SEND_MANY_BATCH);
      const inserted = new Set(await boss.insert(def.name, slice, { db: database, returnId: true }) ?? []);
      for (const job of slice) out.push(inserted.has(job.id) ? job.id : null);
    }
    return out;
  }

  // ── Observability ──────────────────────────────────────────────────────────

  /** Age of the oldest ready job of each queue (cached 30 s): a read of
   *  pgboss.job (name, state, start_after), covered by the drift check of
   *  the version upgrade procedure. */
  async oldestReady(): Promise<Array<{ queue: string; seconds: number }>> {
    const now = Date.now();
    if (this.oldestReadyCache && now - this.oldestReadyCache.at < OLDEST_READY_CACHE_MS) return this.oldestReadyCache.rows;
    const boss = this.bossOrThrow();
    const { rows } = await boss.getDb().executeSql(
      `SELECT name, extract(epoch FROM now() - min(start_after))::float8 AS seconds
         FROM pgboss.job
        WHERE state IN ('created', 'retry') AND start_after <= now() AND name NOT LIKE '\\_\\_pgboss%' AND name <> $1
        GROUP BY name`,
      [DEAD_LETTER_QUEUE],
    );
    const out = (rows as Array<{ name: string; seconds: number }>).map((r) => ({ queue: r.name, seconds: Math.max(0, Number(r.seconds) || 0) }));
    this.oldestReadyCache = { at: now, rows: out };
    return out;
  }

  /** Dead letters waiting in jobs.dead-letter, per source queue. */
  async deadLetterCounts(): Promise<Array<{ source: string; count: number }>> {
    const boss = this.bossOrThrow();
    const { rows } = await boss.getDb().executeSql(
      `SELECT COALESCE(source_name, '') AS source, count(*)::int AS n FROM pgboss.job
        WHERE name = $1 AND state IN ('created', 'retry') GROUP BY 1 ORDER BY 1`,
      [DEAD_LETTER_QUEUE],
    );
    return (rows as Array<{ source: string; n: number }>).map((r) => ({ source: r.source, count: Number(r.n) }));
  }

  /** The values of file-durable §8.3, for the observability work (FND-14). */
  async metricsSnapshot(): Promise<JobsMetricsSnapshot> {
    const read = async (): Promise<JobsMetricsSnapshot> => {
      const boss = this.isStarted() ? this.boss : null;
      const queues = boss ? await boss.getQueues() : [];
      const status = await jobStatus.list();
      const heartbeat = status.find((s) => s.queue === 'jobs.heartbeat' && s.key === '');
      const scheduled = new Set(this.registry.list().filter((d) => d.schedule).map((d) => d.name));
      return {
        generatedAt: new Date().toISOString(),
        runs: jobMetrics.runCounters(),
        durations: jobMetrics.durationHistograms(),
        queues: queues
          .filter((q) => !q.name.startsWith('__pgboss'))
          .map((q) => ({ queue: q.name, ready: Number(q.readyCount), deferred: Number(q.deferredCount), active: Number(q.activeCount), failed: Number(q.failedCount) })),
        oldestReady: boss ? await this.oldestReady() : [],
        deadLetters: boss ? await this.deadLetterCounts() : [],
        scheduleLastSuccess: status
          .filter((s) => s.key === '' && scheduled.has(s.queue) && s.lastSucceededAt)
          .map((s) => ({ queue: s.queue, timestampSeconds: Math.floor(s.lastSucceededAt!.getTime() / 1000) })),
        heartbeatAgeSeconds: heartbeat?.lastSucceededAt ? Math.max(0, Math.round((Date.now() - heartbeat.lastSucceededAt.getTime()) / 1000)) : null,
      };
    };
    // job_status is read in the caller's database context; a caller without
    // one (a background collector) gets the jobs' own.
    return currentDbContext() ? read() : asNone({ type: 'job', name: 'jobs.metrics' }, read);
  }
}

/** Before pg-boss starts: the schema exists, the runtime role owns it (pg-boss
 *  creates partitions and rebuilds its indexes as it runs), and it is not
 *  newer than this server's pg-boss (an image rolled back on a newer schema
 *  must not run). */
async function checkPgbossSchema(connectionString: string): Promise<void> {
  const client = new pg.Client({ connectionString, application_name: 'obligarth-jobs-check' });
  await client.connect();
  try {
    // The catalog only, first: a schema of another owner may not even be
    // usable by the runtime role.
    const { rows } = await client.query(`
      SELECT current_user AS me,
             COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false) AS superuser,
             (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'pgboss') AS owner`);
    const r = rows[0] as { me: string; superuser: boolean; owner: string | null };
    if (r.owner === null) {
      throw new JobsStartError('schema pgboss missing: run server-migrate (its bootstrap creates it, owned by the runtime role)');
    }
    if (r.owner !== r.me && !r.superuser) {
      throw new JobsStartError(`schema pgboss is owned by ${r.owner}, not by the runtime role ${r.me}: run server-migrate, ` +
        `which moves it (and every object in it) to the runtime role`);
    }
    const installed = await client.query(`SELECT to_regclass('pgboss.version') IS NOT NULL AS installed`);
    if (installed.rows[0]?.installed) {
      const v = await client.query('SELECT version FROM pgboss.version');
      const version = Number(v.rows[0]?.version);
      if (Number.isFinite(version) && version > PGBOSS_SCHEMA_VERSION) {
        throw new JobsStartError(`pgboss schema ${version} is newer than this server (${PGBOSS_SCHEMA_VERSION}, pg-boss ${PGBOSS_VERSION}): ` +
          'start a newer server, or roll the database back with the rollback plan of pg-boss');
      }
    }
  } finally {
    await client.end().catch(() => undefined);
  }
}
