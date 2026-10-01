// =============================================================================
// Background jobs: environment (JOBS_*), parsed once and checked at start
// (config.ts startupConfigErrors). An invalid value is refused in every
// environment, development included: a typo must never silently change how
// the jobs run (or stop them).
// =============================================================================

export type JobsMode = 'all' | 'api' | 'paused';

export interface JobsConfig {
  /** all (default): run jobs and schedules; api: never run jobs (replica
   *  serving the API); paused: keep jobs queued without running them (after
   *  a database restore, during an incident). */
  mode: JobsMode;
  /** pg-boss pool (JOBS_DB_POOL_MAX, 2 to 50, default 10). */
  poolMax: number;
  /** Wake the workers of the notify queues by LISTEN/NOTIFY (one dedicated
   *  connection; JOBS_LISTEN_NOTIFY, default true). */
  listenNotify: boolean;
  /** Graceful stop of pg-boss (JOBS_STOP_TIMEOUT_MS, 1000 to 20000, default
   *  15000): inside the 25 s exit budget of the server. */
  stopTimeoutMs: number;
  /** /health/jobs: largest age of the last heartbeat success
   *  (JOBS_HEALTH_MAX_HEARTBEAT_AGE_S, 90 to 3600, default 180). */
  healthMaxHeartbeatAgeS: number;
}

export const JOBS_DEFAULTS: Readonly<JobsConfig> = Object.freeze({
  mode: 'all',
  poolMax: 10,
  listenNotify: true,
  stopTimeoutMs: 15_000,
  healthMaxHeartbeatAgeS: 180,
});

type Env = Record<string, string | undefined>;

function intIn(env: Env, name: string, min: number, max: number, fallback: number, errors: string[]): number {
  const raw = (env[name] ?? '').trim();
  if (raw === '') return fallback;
  if (!/^[0-9]+$/.test(raw) || Number(raw) < min || Number(raw) > max) {
    errors.push(`${name} must be an integer between ${min} and ${max} (${fallback} by default).`);
    return fallback;
  }
  return Number(raw);
}

/** The jobs settings of `env`, and why some are refused (empty: none). */
export function readJobsConfig(env: Env = process.env): { config: JobsConfig; errors: string[] } {
  const errors: string[] = [];
  const modeRaw = (env.JOBS_MODE ?? '').trim();
  let mode: JobsMode = JOBS_DEFAULTS.mode;
  if (modeRaw === 'all' || modeRaw === 'api' || modeRaw === 'paused') mode = modeRaw;
  else if (modeRaw !== '') errors.push('JOBS_MODE must be "all" (the default), "api" or "paused".');

  const notifyRaw = (env.JOBS_LISTEN_NOTIFY ?? '').trim();
  let listenNotify = JOBS_DEFAULTS.listenNotify;
  if (notifyRaw === 'true' || notifyRaw === 'false') listenNotify = notifyRaw === 'true';
  else if (notifyRaw !== '') errors.push('JOBS_LISTEN_NOTIFY must be "true" (the default) or "false".');

  const config: JobsConfig = {
    mode,
    poolMax: intIn(env, 'JOBS_DB_POOL_MAX', 2, 50, JOBS_DEFAULTS.poolMax, errors),
    listenNotify,
    stopTimeoutMs: intIn(env, 'JOBS_STOP_TIMEOUT_MS', 1_000, 20_000, JOBS_DEFAULTS.stopTimeoutMs, errors),
    healthMaxHeartbeatAgeS: intIn(env, 'JOBS_HEALTH_MAX_HEARTBEAT_AGE_S', 90, 3_600, JOBS_DEFAULTS.healthMaxHeartbeatAgeS, errors),
  };
  return { config, errors };
}
