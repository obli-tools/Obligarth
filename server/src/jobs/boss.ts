import { PgBoss, fromKnex } from 'pg-boss';      // the only import of pg-boss in the code base
import type {
  Clock, Db, Job, JobResult as BossJobResult, JobWithMetadata, Queue, QueueResult, Schedule, SendOptions,
  UpdateQueueOptions, WorkOptions,
} from 'pg-boss';
import type { Knex } from 'knex';
import { logger } from '../utils/logger';
import { isPoolClosedError, safeErr } from './errors';
import type { JobsMode } from './types';

// =============================================================================
// The pg-boss instance. Only this file imports pg-boss: the rest of the code
// goes through the registry (registerJob), so that a version upgrade, or a
// replacement of pg-boss, touches one layer (docs: file-durable F4).
// =============================================================================

/** Schema version of the pinned pg-boss (its package.json "pgboss.schema"). */
export const PGBOSS_SCHEMA_VERSION = 43;
/** The pinned version (server/package.json, exact). */
export const PGBOSS_VERSION = '12.35.1';
/** The schema pg-boss lives in, created by the bootstrap of server-migrate
 *  and owned by the runtime role. */
export const PGBOSS_SCHEMA = 'pgboss';

export type {
  Clock, Db, Job, BossJobResult, JobWithMetadata, Queue, QueueResult, Schedule, SendOptions, UpdateQueueOptions,
  WorkOptions,
};
export { PgBoss };

export interface BossOptions {
  connectionString: string;
  mode: JobsMode;
  poolMax: number;
  listenNotify: boolean;
  /** Tests only: a pg-boss TestClock (time shared with the database). */
  clock?: Clock;
  /** Tests only: job spies. */
  spies?: boolean;
  /** Tests only: shorter cron pass, maintenance and cache intervals. */
  intervals?: Partial<Record<
    'cronMonitorIntervalSeconds' | 'cronWorkerIntervalSeconds' | 'superviseIntervalSeconds'
    | 'maintenanceIntervalSeconds' | 'monitorIntervalSeconds' | 'queueCacheIntervalSeconds' | 'clockMonitorIntervalSeconds',
    number>>;
}

/** What a pg-boss warning may log: its data without the values of a slow
 *  query (they can be a job's payload or output). */
function warningData(data: unknown): unknown {
  if (!data || typeof data !== 'object') return data;
  const { values: _values, sql, ...rest } = data as Record<string, unknown>;
  return typeof sql === 'string' ? { ...rest, sql: sql.replace(/\s+/g, ' ').slice(0, 200) } : rest;
}

/** Supervision pass (expiry of silent or expired jobs, queue statistics)
 *  and queue cache every 15 s instead of 60: a worker bursts through a
 *  backlog (burstWhenReadyExceeds, runtime.ts) once the cached ready count
 *  shows it, and a job whose process died is retried sooner. A few
 *  statements every 15 s; the retention deletions stay daily. */
const SUPERVISE_INTERVAL_SECONDS = 15;

export function createBoss(o: BossOptions): PgBoss {
  const boss = new PgBoss({
    superviseIntervalSeconds: SUPERVISE_INTERVAL_SECONDS,
    monitorIntervalSeconds: SUPERVISE_INTERVAL_SECONDS,
    queueCacheIntervalSeconds: SUPERVISE_INTERVAL_SECONDS,
    connectionString: o.connectionString,
    schema: PGBOSS_SCHEMA,
    application_name: 'obligarth-jobs',
    max: o.poolMax,                           // JOBS_DB_POOL_MAX, default 10
    createSchema: false,                      // F2: the bootstrap of server-migrate creates the schema
    migrate: true,                            // F3: pg-boss installs and migrates its own objects
    schedule: o.mode === 'all',               // cron pass only where jobs run
    supervise: o.mode !== 'api',              // maintenance (expiry, retention, deletion)
    useListenNotify: o.listenNotify,          // JOBS_LISTEN_NOTIFY, default true
    persistWarnings: false,
    ...(o.clock ? { clock: o.clock } : {}),
    ...(o.spies ? { __test__enableSpies: true } : {}),
    ...(o.intervals ?? {}),
  });
  // An 'error' event without listener would throw and stop the process.
  boss.on('error', (err) => {
    if (isPoolClosedError(err)) logger.warn({ err: safeErr(err) }, 'pg-boss: late completion after the stop');
    else logger.error({ err: safeErr(err) }, 'pg-boss error');
  });
  // Warnings carry { message, data } (slow query, backlog, clock skew,
  // invalid schedule…): the values of a slow query are dropped.
  boss.on('warning', (w) => logger.warn({ data: warningData(w?.data) }, `pg-boss warning: ${String(w?.message ?? '').slice(0, 300)}`));
  return boss;
}

/** The caller's Knex transaction, as a pg-boss database (sendInTx): the job
 *  is written by the transaction, savepoints included. */
export function knexDb(trx: Knex.Transaction): Db {
  return fromKnex(trx as unknown as Parameters<typeof fromKnex>[0]);
}
