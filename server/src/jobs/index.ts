import type { z } from 'zod';
import { createJobsHealth } from './health';
import { JobsRuntime, JobsStartError, type JobsStartOptions } from './runtime';
import { outboxConsumer, startOutboxConsumer } from './outbox/consumer';
import { freezeOutboxHandlers } from './outbox/handlers';
import { outboxMetrics } from './outbox/metrics';
import type { JobDefinition, JobHandle } from './types';

// =============================================================================
// Durable background jobs (pg-boss, schema pgboss): the only entry point of
// the rest of the code. A module declares its jobs with registerJob (before
// the start, no I/O) and keeps the handle to send them; index.ts drives the
// lifecycle (jobs.start, jobs.startWorkers, jobs.stop). Periodic and deferred
// work goes through here, never through a timer of the process. The consumer
// of the apple-edge outbox (outbox/, lot 2 of the durable queue) lives with
// the jobs: its handlers are registered before jobs.start(), its loop starts
// with the workers and stops first (its batch finishes while pg-boss runs).
// =============================================================================

/** The runtime of this process. */
export const defaultRuntime = new JobsRuntime();
const health = createJobsHealth(defaultRuntime, { outbox: () => outboxConsumer.status() });

/** Declares a job of a module (before jobs.start()); returns its handle. */
export function registerJob<S extends z.ZodTypeAny>(def: JobDefinition<S>): JobHandle<z.infer<S>> {
  return defaultRuntime.register(def);
}

export const jobs = {
  /** pg-boss started, queues and schedules synchronised; throws: fatal. The
   *  registries (jobs, outbox handlers) are frozen. */
  start: (opts?: JobsStartOptions): Promise<void> => {
    freezeOutboxHandlers();
    return defaultRuntime.start(opts);
  },
  /** Workers (mode all), after Socket.io; then the outbox consumer
   *  (OUTBOX_CONSUMER). */
  startWorkers: async (): Promise<void> => {
    await defaultRuntime.startWorkers();
    await startOutboxConsumer(defaultRuntime.mode());
  },
  /** Graceful stop: the outbox consumer finishes its batch, then pg-boss
   *  (JOBS_STOP_TIMEOUT_MS). Idempotent. */
  stop: async (): Promise<void> => {
    await outboxConsumer.stop();
    await defaultRuntime.stop();
  },
  mode: () => defaultRuntime.mode(),
  /** Healthy for GET /health/jobs (cached 10 s). */
  health: (): Promise<boolean> => health.check(),
  /** The Express handler of GET /health/jobs. */
  healthHandler: () => health.handler(),
  /** The values handed to the observability work (FND-14). */
  metricsSnapshot: async () => ({ ...(await defaultRuntime.metricsSnapshot()), outbox: outboxMetrics.snapshot() }),
};

export { jobIdFor, jitterSeconds } from './ids';
export { registerOutboxHandler } from './outbox/handlers';
export type { OutboxEvent, OutboxHandlerContext, OutboxHandlerDefinition, OutboxScope } from './outbox/handlers';
export { JobError, PermanentJobError, sanitizeError, safeErr } from './errors';
export { JobsStartError };
export type { JobsStartOptions };
export type {
  JobContext, JobDefinition, JobHandle, JobPolicy, JobResult, JobRetry, JobSchedule, JobScope, JobsMode, SendJobOptions,
} from './types';
