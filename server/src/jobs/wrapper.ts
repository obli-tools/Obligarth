import type { Knex } from 'knex';
import { db } from '../db';
import { asTenant, runWithDbContext, type DbActor, type DbContext } from '../db/context';
import { withTenantTransaction } from '../db/tenantContext';
import { logger } from '../utils/logger';
import { jobAlerts } from './alerts';
import type { BossJobResult, Job } from './boss';
import { JobError, PermanentJobError, safeErr, sanitizeError } from './errors';
import { jobMetrics } from './metrics';
import { runOnce } from './once';
import { jobStatus } from './status';
import { tenantIsLive } from './tenant';
import type { JobContext, JobResult, RegisteredJob } from './types';

// =============================================================================
// Execution envelope: the handler pg-boss calls for every job is this one. It
// runs the job in its own database context ('none', actor j:<queue>), checks
// the payload and the tenant, writes job_status, counts, alerts, and RETURNS
// a disposition instead of letting an exception reach pg-boss (perJobResults):
//   completed   the output is a small summary (scalars, 200 characters);
//   failed      retried by the queue's policy, then copied to the dead
//               letters when the queue has them;
//   deadletter  straight to the dead letters, no retry spent (invalid
//               payload, PermanentJobError, permanent database error).
// Only { code, message } of an error is stored (sanitizeError): never a
// stack nor a value of a database error. An exception of the envelope itself
// never escapes: logged, and the disposition computed is returned.
// =============================================================================

const OUTPUT_KEY_RE = /^[A-Za-z][A-Za-z0-9_]{0,40}$/;
const OUTPUT_MAX_KEYS = 20;
/** The envelope gives up an attempt one second before pg-boss would expire
 *  it: the attempt then fails with { code: 'timeout' } (retried by the
 *  policy), instead of pg-boss storing its own error object, stack included.
 *  pg-boss times the attempt from the moment it hands the job over, so the
 *  envelope's deadline starts there as well (runJobs): the work before the
 *  handler (tenant check, status write) counts, and a slow database there
 *  can never let pg-boss's timer settle the job first. */
const DEADLINE_MARGIN_MS = 1_000;

/** `work`, or a retryable JobError('timeout') once `signal` aborts. The
 *  handler itself cannot be stopped: it sees its signal aborted. */
function withinDeadline<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(new JobError('timeout', 'attempt timed out'));
    if (signal.aborted) { onAbort(); return; }
    signal.addEventListener('abort', onAbort, { once: true });
    work.then(
      (v) => { signal.removeEventListener('abort', onAbort); resolve(v); },
      (e) => { signal.removeEventListener('abort', onAbort); reject(e); },
    );
  });
}

/** The output a job may store: scalar values, strings of 200 characters. */
export function clampOutput(output: unknown): Record<string, string | number | boolean | null> | null {
  if (!output || typeof output !== 'object' || Array.isArray(output)) return null;
  const out: Record<string, string | number | boolean | null> = {};
  for (const [k, v] of Object.entries(output as Record<string, unknown>).slice(0, OUTPUT_MAX_KEYS)) {
    if (!OUTPUT_KEY_RE.test(k)) continue;
    if (v === null || typeof v === 'boolean') out[k] = v;
    else if (typeof v === 'number') out[k] = Number.isFinite(v) ? v : null;
    else if (typeof v === 'string') out[k] = v.slice(0, 200);
  }
  return out;
}

const logStatusError = (err: unknown): void => { logger.warn({ err: safeErr(err) }, 'job_status not written'); };

function buildContext(
  def: RegisteredJob, job: Job<unknown>, payload: unknown, tenantId: number | null, attempt: number, actor: DbActor,
  signal: AbortSignal,
): JobContext<unknown> {
  const requireTenant = (): number => {
    if (tenantId === null) throw new PermanentJobError('tenant_context_refused', 'a tenant context is reserved to tenant jobs');
    return tenantId;
  };
  return {
    name: def.name,
    jobId: job.id,
    attempt,
    isLastAttempt: attempt > def.retry.limit,
    payload,
    tenantId,
    signal,
    actor: `job:${def.name}`,
    dbActor: actor,
    requestId: `job-${job.id}`,
    log: logger.child({ job: def.name, jobId: job.id, attempt, tenantId }),
    db,
    throwIfAborted(): void {
      if (signal?.aborted) throw new JobError('aborted', 'attempt aborted');
    },
    async withTenant<T>(fn: (trx: Knex.Transaction) => Promise<T>): Promise<T> {
      return withTenantTransaction(requireTenant(), actor, fn);
    },
    async inTenant<T>(fn: () => Promise<T>): Promise<T> {
      return asTenant(requireTenant(), actor, fn);
    },
    once(key: string, ttlSeconds: number, effect: () => Promise<void>): Promise<'done' | 'skipped'> {
      return runOnce(def.name, key, ttlSeconds, effect);
    },
    async tryLock(trx: Knex.Transaction, key: string): Promise<boolean> {
      const res = await trx.raw('SELECT pg_try_advisory_xact_lock(hashtext(?)) AS ok', [`job:${key}`]) as { rows: Array<{ ok: boolean }> };
      return res.rows[0]?.ok === true;
    },
  };
}

async function runOne(def: RegisteredJob, job: Job<unknown>, actor: DbActor, deadline: AbortSignal): Promise<BossJobResult> {
  const started = Date.now();
  const attempt = (Number(job.retryCount) || 0) + 1;
  const retryLimit = def.retry.limit;
  const parsed = def.payload.safeParse(job.data);
  if (!parsed.success) {
    jobMetrics.run(def.name, 'invalid');
    logger.error({ job: def.name, jobId: job.id, attempt, code: 'invalid_payload' }, 'job payload refused by its schema: dead letter');
    return { id: job.id, status: 'deadletter', output: { code: 'invalid_payload', message: 'payload rejected by the schema', attempt } };
  }
  let tenantId: number | null = null;
  if (def.scope === 'tenant') {
    tenantId = (parsed.data as { tenantId: number }).tenantId;
    if (!(await tenantIsLive(tenantId))) {
      jobMetrics.run(def.name, 'skipped');
      logger.info({ job: def.name, jobId: job.id, tenantId }, 'job skipped: its tenant is gone');
      return { id: job.id, status: 'completed', output: { skipped: 'tenant_gone' } };
    }
  }
  const statusKey = def.trackStatus === 'tenant' && tenantId !== null ? `t:${tenantId}` : '';
  if (def.trackStatus !== 'none') await jobStatus.started(def.name, statusKey, job.id).catch(logStatusError);
  // The attempt's signal: pg-boss's (expiry, shutdown) or the envelope's
  // deadline (started by runJobs), whichever comes first.
  const signal = job.signal ? AbortSignal.any([job.signal, deadline]) : deadline;
  const ctx = buildContext(def, job, parsed.data, tenantId, attempt, actor, signal);
  try {
    // Past the deadline already (slow database above): the handler never starts.
    if (deadline.aborted) throw new JobError('timeout', 'attempt timed out');
    const result = await withinDeadline(Promise.resolve().then(() => def.handler(ctx)), deadline) as JobResult | void;
    const durationMs = Date.now() - started;
    if (def.trackStatus !== 'none') await jobStatus.succeeded(def.name, statusKey, durationMs).catch(logStatusError);
    jobMetrics.run(def.name, 'completed', durationMs);
    ctx.log.debug({ durationMs }, 'job completed');
    return { id: job.id, status: 'completed', output: clampOutput(result ? result.output : null) };
  } catch (err) {
    const s = sanitizeError(err);
    const durationMs = Date.now() - started;
    const willRetry = s.retryable && attempt <= retryLimit;
    ctx.log[willRetry ? 'warn' : 'error']({ err: safeErr(err), code: s.code, attempt, durationMs }, 'job attempt failed');
    if (def.trackStatus !== 'none') {
      const failures = await jobStatus.failed(def.name, statusKey, s.code, durationMs).catch((e) => { logStatusError(e); return 0; });
      if (failures === def.alertAfterFailures) await jobAlerts.failing(actor, def.name, failures, s.code);
    }
    jobMetrics.run(def.name, willRetry ? 'retry' : 'failed', durationMs);
    return { id: job.id, status: s.retryable ? 'failed' : 'deadletter', output: { code: s.code, message: s.message, attempt } };
  }
}

/** The handler given to pg-boss for `def` (batchSize 1, perJobResults). */
export async function runJobs(def: RegisteredJob, jobs: Array<Job<unknown>>): Promise<BossJobResult[]> {
  const actor: DbActor = { type: 'job', name: def.name };
  const out: BossJobResult[] = [];
  for (const job of jobs) {
    // From the hand-over, like pg-boss's own timer (DEADLINE_MARGIN_MS).
    const deadline = AbortSignal.timeout(Math.max(1_000, def.timeoutSeconds * 1000 - DEADLINE_MARGIN_MS));
    const ctx: DbContext = { kind: 'none', tenantId: null, actor, grantId: null, origin: 'job', requestId: `job-${job.id}` };
    try {
      out.push(await withinDeadline(runWithDbContext(ctx, () => runOne(def, job, actor, deadline)), deadline));
    } catch (err) {
      if (err instanceof JobError && err.code === 'timeout') {
        // The deadline passed before the run settled: retryable, as a handler
        // that runs too long. The run logs, counts and records it as it ends.
        out.push({ id: job.id, status: 'failed', output: { code: 'timeout', message: 'attempt timed out', attempt: (Number(job.retryCount) || 0) + 1 } });
        continue;
      }
      logger.error({ err: safeErr(err), job: def.name, jobId: job.id }, 'job envelope failed');
      out.push({ id: job.id, status: 'failed', output: { code: 'internal_error', message: 'internal error' } });
    }
  }
  return out;
}
