import type { Knex } from 'knex';
import type { Logger } from 'pino';
import type { z } from 'zod';
import type { DbActor } from '../db/context';
import type { JobsMode } from './config';

export type { JobsMode };

export type JobScope = 'platform' | 'tenant';
export type JobPolicy = 'standard' | 'exclusive' | 'stately' | 'singleton' | 'short' | 'key_strict_fifo';

export interface JobSchedule {
  /** 5-field cron expression (minute hour day-of-month month day-of-week). */
  cron: string;
  /** IANA time zone; default 'UTC'. Business schedules only: maintenance stays in UTC. */
  tz?: string;
  /** Occurrences missed while no instance ran: 'once' sends one job, 'skip' none.
   *  Default: 'once' when the period is one hour or more, else 'skip'. */
  missed?: 'skip' | 'once';
  /** Payload of the scheduled jobs, validated against the job's schema at registration. */
  data?: Record<string, unknown>;
}

export interface JobRetry {
  /** Retries after the first attempt (pg-boss retryLimit). */
  limit: number;
  /** First delay, seconds (pg-boss retryDelay). */
  delaySeconds: number;
  /** Exponential delay with jitter (pg-boss retryBackoff). */
  backoff: boolean;
  /** Ceiling of the exponential delay, seconds (pg-boss retryDelayMax). */
  maxDelaySeconds?: number;
}

export interface JobDefinition<S extends z.ZodTypeAny> {
  /** Queue name: `<module>.<name>[.<name>…]` (registry.ts). */
  name: string;
  scope: JobScope;
  /** One English line, shown by the admin API. */
  description: string;
  /** z.object({...}).strict(); a 'tenant' job has tenantId: z.number().int().positive(). */
  payload: S;
  /** Default: 'exclusive' with a schedule, else 'standard'. Immutable once the queue exists. */
  policy?: JobPolicy;
  retry?: Partial<JobRetry>;
  /** pg-boss expireInSeconds: an attempt still active after this delay is failed (and retried). Default 300, max 86400. */
  timeoutSeconds?: number;
  /** pg-boss heartbeatSeconds (>= 10, < timeoutSeconds): recommended when timeoutSeconds > 300. */
  heartbeatSeconds?: number;
  /** pg-boss deleteAfterSeconds (finished jobs). */
  keepFinishedSeconds?: number;
  /** pg-boss retentionSeconds (jobs never started). */
  keepPendingSeconds?: number;
  schedule?: JobSchedule;
  /** One send at each start (mode all); requires 'exclusive' or 'stately'. */
  runAtStart?: boolean;
  /** Worker polling interval, seconds (pg-boss pollingIntervalSeconds, >= 0.5). */
  pollSeconds?: number;
  /** Wake the workers with NOTIFY (interactive queues). */
  notify?: boolean;
  /** local: workers of this instance (localConcurrency); perTenant: soft cap per tenant (groupConcurrency). */
  concurrency?: { local?: number; perTenant?: number };
  /** Copy terminally failed jobs to jobs.dead-letter. Default: true without schedule, false with one. */
  deadLetter?: boolean;
  /** May be redriven from the dead letters by an administrator. Default true; false for destructive actions. */
  redrivable?: boolean;
  /** Write job_status: 'queue' (one row), 'tenant' (one row per tenant), 'none'. Default 'queue' with a schedule, else 'none'. */
  trackStatus?: 'queue' | 'tenant' | 'none';
  /** Consecutive failures that raise an alert (scheduled jobs). Default 3. */
  alertAfterFailures?: number;
  /** An administrator may trigger a run from the admin API. Default: true with a schedule. */
  manualRun?: boolean;
  /** Field names that look secret but were reviewed as harmless (registry rule 6). */
  reviewedFieldNames?: string[];
  handler: (ctx: JobContext<z.infer<S>>) => Promise<JobResult | void>;
}

export interface JobContext<P> {
  readonly name: string;
  readonly jobId: string;
  /** 1 for the first attempt. */
  readonly attempt: number;
  readonly isLastAttempt: boolean;
  readonly payload: P;
  /** payload.tenantId of a 'tenant' job, checked to exist before the handler runs; null otherwise. */
  readonly tenantId: number | null;
  /** Aborted when the attempt expires or the instance stops. */
  readonly signal: AbortSignal;
  /** 'job:<queue>': audit details, X-Obligarth-Actor towards apple-edge. */
  readonly actor: `job:${string}`;
  /** The database actor of the run ({ type: 'job', name: <queue> }, token j:<queue>). */
  readonly dbActor: DbActor;
  /** 'job-<jobId>': X-Request-ID towards apple-edge, request_id of the logs. */
  readonly requestId: string;
  /** Child logger: { job, jobId, attempt, tenantId }. Never log the payload of an outbox event. */
  readonly log: Logger;
  readonly db: Knex;
  throwIfAborted(): void;
  /** Transaction in the job's tenant (database context 'tenant'). Throws for a 'platform' job. */
  withTenant<T>(fn: (trx: Knex.Transaction) => Promise<T>): Promise<T>;
  /** fn in the job's tenant database context, without a transaction (each
   *  statement its own lease): for work that also waits on something else
   *  (a renderer, the network) and must not hold a transaction open. Throws
   *  for a 'platform' job. */
  inTenant<T>(fn: () => Promise<T>): Promise<T>;
  /** Side effect done at least once, never twice (job_once). */
  once(key: string, ttlSeconds: number, effect: () => Promise<void>): Promise<'done' | 'skipped'>;
  /** pg_try_advisory_xact_lock on hashtext('job:' + key), inside trx. */
  tryLock(trx: Knex.Transaction, key: string): Promise<boolean>;
}

/** Small, non-personal summary stored as the job's output (strings of 200 characters at most). */
export interface JobResult {
  output?: Record<string, string | number | boolean | null>;
}

export interface SendJobOptions {
  /** UUID: a second send with the same id returns null (idempotent send; window = retention of the job). */
  id?: string;
  /** Deduplication key, acted on by the queue's policy. */
  singletonKey?: string;
  /** Date, or seconds from now. */
  startAfter?: Date | number;
  /** Higher runs first. 0 by default; 10 for jobs a user is waiting for. */
  priority?: number;
  /** Fairness group 't:<id>'. Must equal payload.tenantId when both exist. */
  tenantId?: number;
  /** sendDebounced: one job per key per window, the last payload wins (requires singletonKey). */
  debounceSeconds?: number;
  /** sendThrottled: at most one job per key per window, later sends dropped (requires singletonKey). */
  throttleSeconds?: number;
}

/** What a grouped send accepts for each job (sendManyInTx). */
export type SendManyOptions = Pick<SendJobOptions, 'singletonKey' | 'tenantId'>;

export interface JobHandle<P> {
  readonly name: string;
  /** Returns the job id, or null when deduplicated (id, policy, singletonKey). */
  send(payload: P, opts?: SendJobOptions): Promise<string | null>;
  /** Same, inside the caller's Knex transaction: the job exists if and only if trx commits. */
  sendInTx(trx: Knex.Transaction, payload: P, opts?: SendJobOptions): Promise<string | null>;
  /**
   * Several jobs of this queue in one statement per thousand, inside the caller's Knex transaction (a tenant-wide
   * pass that asks one job per device). Each entry answers like sendInTx, in the order given: the job id, or null
   * when deduplicated (policy, singletonKey, a key given twice in the list). Options: singletonKey and tenantId only.
   */
  sendManyInTx(trx: Knex.Transaction, items: ReadonlyArray<{ payload: P; opts?: SendManyOptions }>): Promise<Array<string | null>>;
  /** Cancels a job not yet finished (no effect on a finished one). */
  cancel(jobId: string): Promise<void>;
}

/** A definition once registered: every default resolved. */
export interface RegisteredJob {
  readonly name: string;
  readonly module: string;
  readonly scope: JobScope;
  readonly description: string;
  readonly payload: z.ZodTypeAny;
  readonly policy: JobPolicy;
  readonly retry: JobRetry;
  readonly timeoutSeconds: number;
  readonly heartbeatSeconds: number | null;
  readonly keepFinishedSeconds: number;
  readonly keepPendingSeconds: number;
  readonly schedule: (Required<Pick<JobSchedule, 'cron' | 'tz' | 'missed'>> & { data: Record<string, unknown> }) | null;
  readonly runAtStart: boolean;
  readonly pollSeconds: number;
  readonly notify: boolean;
  readonly concurrency: { local: number; perTenant: number | null };
  readonly deadLetter: boolean;
  readonly redrivable: boolean;
  readonly trackStatus: 'queue' | 'tenant' | 'none';
  readonly alertAfterFailures: number;
  readonly manualRun: boolean;
  readonly warningQueueSize: number;
  readonly handler: (ctx: JobContext<any>) => Promise<JobResult | void>;
}
