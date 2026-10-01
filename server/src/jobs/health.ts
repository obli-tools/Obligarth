import type { Request, Response } from 'express';
import { config } from '../config';
import { logger } from '../utils/logger';
import { safeErr } from './errors';
import type { JobsRuntime } from './runtime';
import { jobStatus } from './status';

// =============================================================================
// GET /health/jobs (public, no detail): the "heartbeat of the scheduler",
// watched from outside the instance (Obliview, OBL-05). 200 {"status":"ok"}
// when pg-boss runs, the mode is not 'paused' and, in mode 'all', the
// jobs.heartbeat queue succeeded less than JOBS_HEALTH_MAX_HEARTBEAT_AGE_S
// ago (the cron pass and the workers both work); 503 {"status":"degraded"}
// otherwise. Result cached 10 s, a 200 never past the moment its heartbeat
// gets too old: the 503 comes at most JOBS_HEALTH_MAX_HEARTBEAT_AGE_S after
// the last heartbeat (180 s), not 10 s later.
// =============================================================================

const CACHE_MS = 10_000;
const HEARTBEAT_QUEUE = 'jobs.heartbeat';

export interface JobsHealthOptions {
  /** Largest age of the heartbeat, in seconds (JOBS_HEALTH_MAX_HEARTBEAT_AGE_S). */
  maxAgeS?: () => number;
  /** The queue whose last success is the heartbeat (jobs.heartbeat; tests). */
  heartbeatQueue?: string;
}

export function createJobsHealth(runtime: JobsRuntime, opts: JobsHealthOptions = {}) {
  const maxAgeS = opts.maxAgeS ?? (() => config.jobs.healthMaxHeartbeatAgeS);
  const heartbeatQueue = opts.heartbeatQueue ?? HEARTBEAT_QUEUE;
  let cache: { ok: boolean; until: number } | null = null;

  /** Healthy, and until when that answer may be served from the cache. */
  async function evaluate(now: number): Promise<{ ok: boolean; until: number }> {
    const until = now + CACHE_MS;
    if (!runtime.isStarted()) return { ok: false, until };
    const mode = runtime.mode();
    if (mode === 'paused') return { ok: false, until };
    if (mode === 'api') return { ok: true, until };
    if (!runtime.workersStarted()) return { ok: false, until };
    const beat = await jobStatus.get(heartbeatQueue, '');
    if (!beat?.lastSucceededAt) return { ok: false, until };
    const deadline = beat.lastSucceededAt.getTime() + maxAgeS() * 1000;
    return now < deadline ? { ok: true, until: Math.min(until, deadline) } : { ok: false, until };
  }

  /** Healthy? (cached 10 s at most, see above) */
  async function check(): Promise<boolean> {
    const now = Date.now();
    if (cache && now < cache.until) return cache.ok;
    let result: { ok: boolean; until: number };
    try {
      result = await evaluate(now);
    } catch (err) {
      logger.warn({ err: safeErr(err) }, 'jobs health check failed');
      result = { ok: false, until: now + CACHE_MS };
    }
    cache = result;
    return result.ok;
  }

  return {
    check,
    /** Drops the cached result (tests, mode changes). */
    reset(): void {
      cache = null;
    },
    /** The Express handler of GET /health/jobs. */
    handler() {
      return async (_req: Request, res: Response): Promise<void> => {
        const ok = await check();
        res.setHeader('Cache-Control', 'no-store');
        res.status(ok ? 200 : 503).json({ status: ok ? 'ok' : 'degraded' });
      };
    },
  };
}
