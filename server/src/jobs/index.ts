import type { z } from 'zod';
import { createJobsHealth } from './health';
import { JobsRuntime, JobsStartError, type JobsStartOptions } from './runtime';
import type { JobDefinition, JobHandle } from './types';

// =============================================================================
// Durable background jobs (pg-boss, schema pgboss): the only entry point of
// the rest of the code. A module declares its jobs with registerJob (before
// the start, no I/O) and keeps the handle to send them; index.ts drives the
// lifecycle (jobs.start, jobs.startWorkers, jobs.stop). Periodic and deferred
// work goes through here, never through a timer of the process.
// =============================================================================

/** The runtime of this process. */
export const defaultRuntime = new JobsRuntime();
const health = createJobsHealth(defaultRuntime);

/** Declares a job of a module (before jobs.start()); returns its handle. */
export function registerJob<S extends z.ZodTypeAny>(def: JobDefinition<S>): JobHandle<z.infer<S>> {
  return defaultRuntime.register(def);
}

export const jobs = {
  /** pg-boss started, queues and schedules synchronised; throws: fatal. */
  start: (opts?: JobsStartOptions): Promise<void> => defaultRuntime.start(opts),
  /** Workers (mode all), after Socket.io. */
  startWorkers: (): Promise<void> => defaultRuntime.startWorkers(),
  /** Graceful stop (JOBS_STOP_TIMEOUT_MS). Idempotent. */
  stop: (): Promise<void> => defaultRuntime.stop(),
  mode: () => defaultRuntime.mode(),
  /** Healthy for GET /health/jobs (cached 10 s). */
  health: (): Promise<boolean> => health.check(),
  /** The Express handler of GET /health/jobs. */
  healthHandler: () => health.handler(),
  /** The values handed to the observability work (FND-14). */
  metricsSnapshot: () => defaultRuntime.metricsSnapshot(),
};

export { jobIdFor, jitterSeconds } from './ids';
export { JobError, PermanentJobError, sanitizeError, safeErr } from './errors';
export { JobsStartError };
export type { JobsStartOptions };
export type {
  JobContext, JobDefinition, JobHandle, JobPolicy, JobResult, JobRetry, JobSchedule, JobScope, JobsMode, SendJobOptions,
} from './types';
