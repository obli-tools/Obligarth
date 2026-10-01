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
// otherwise. Result cached 10 s.
// =============================================================================

const CACHE_MS = 10_000;

export function createJobsHealth(runtime: JobsRuntime, maxAgeS: () => number = () => config.jobs.healthMaxHeartbeatAgeS) {
  let cache: { at: number; ok: boolean } | null = null;

  async function evaluate(): Promise<boolean> {
    if (!runtime.isStarted()) return false;
    const mode = runtime.mode();
    if (mode === 'paused') return false;
    if (mode === 'api') return true;
    if (!runtime.workersStarted()) return false;
    const beat = await jobStatus.get('jobs.heartbeat', '');
    if (!beat?.lastSucceededAt) return false;
    return Date.now() - beat.lastSucceededAt.getTime() < maxAgeS() * 1000;
  }

  /** Healthy? (cached 10 s) */
  async function check(): Promise<boolean> {
    const now = Date.now();
    if (cache && now - cache.at < CACHE_MS) return cache.ok;
    let ok = false;
    try {
      ok = await evaluate();
    } catch (err) {
      logger.warn({ err: safeErr(err) }, 'jobs health check failed');
      ok = false;
    }
    cache = { at: now, ok };
    return ok;
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
