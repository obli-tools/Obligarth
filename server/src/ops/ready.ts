import type { Request, Response } from 'express';

// =============================================================================
// GET /health/ready (P0-13 T8; public, relayed by the console's nginx like /health and /health/jobs, no detail):
// 200 {"status":"ok"} when every readiness check of the instance passes, 503 {"status":"degraded"} otherwise. The
// checks are registered by the modules (registerReadinessCheck): the core's (modules/ops.ts) are the database, its
// schema (no migration of this image missing), the vault, apple-edge when APPLE_EDGE_MODE=on, the backups when
// BACKUP_EXPECTED=true (P0-13 T9, ops/backups.ts). Each check has 3 s; one that throws or does not answer fails, with a fixed code
// (never a message: the detail is for GET /api/admin/ops/status, platform administrators). The answer is cached
// 10 s, like /health/jobs. Self-contained (unit tests): no import of the server.
// =============================================================================

export interface ReadinessOutcome {
  ok: boolean;
  /** A short fixed code ([a-z_]), for the status of the platform; never a message nor a value. */
  code?: string;
}

export type ReadinessCheckFn = () => Promise<boolean | ReadinessOutcome> | boolean | ReadinessOutcome;

export interface ReadinessCheck {
  name: string;
  run: ReadinessCheckFn;
}

export interface ReadinessResult {
  ok: boolean;
  checkedAt: string;
  checks: Array<{ name: string; ok: boolean; code: string | null }>;
}

const CHECK_NAME_RE = /^[a-z][a-z0-9_.-]{0,40}$/;
const CODE_RE = /^[a-z][a-z0-9_]{0,40}$/;
const CACHE_MS = 10_000;
const CHECK_TIMEOUT_MS = 3_000;

const registered: ReadinessCheck[] = [];

/** Declares a readiness check of a module (at registration time; no I/O). A name registered twice throws. */
export function registerReadinessCheck(name: string, run: ReadinessCheckFn): void {
  if (!CHECK_NAME_RE.test(name)) throw new Error(`readiness check ${JSON.stringify(name)}: invalid name`);
  if (registered.some((c) => c.name === name)) throw new Error(`readiness check ${name} registered twice`);
  registered.push({ name, run });
}

export function registeredReadinessChecks(): ReadonlyArray<ReadinessCheck> {
  return registered;
}

async function runCheck(c: ReadinessCheck, timeoutMs: number): Promise<{ name: string; ok: boolean; code: string | null }> {
  let timer: NodeJS.Timeout | undefined;
  try {
    const out = await Promise.race([
      Promise.resolve().then(() => c.run()),
      new Promise<'timeout'>((resolve) => { timer = setTimeout(() => resolve('timeout'), timeoutMs); }),
    ]);
    if (out === 'timeout') return { name: c.name, ok: false, code: 'timeout' };
    if (typeof out === 'boolean') return { name: c.name, ok: out, code: out ? null : 'failed' };
    const ok = out?.ok === true;
    const code = typeof out?.code === 'string' && CODE_RE.test(out.code) ? out.code : ok ? null : 'failed';
    return { name: c.name, ok, code };
  } catch {
    return { name: c.name, ok: false, code: 'error' };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export interface ReadinessOptions {
  /** The checks to run (default: the registered ones). */
  checks?: () => ReadonlyArray<ReadinessCheck>;
  cacheMs?: number;
  timeoutMs?: number;
  now?: () => number;
}

export function createReadiness(opts: ReadinessOptions = {}) {
  const checks = opts.checks ?? registeredReadinessChecks;
  const cacheMs = opts.cacheMs ?? CACHE_MS;
  const timeoutMs = opts.timeoutMs ?? CHECK_TIMEOUT_MS;
  const now = opts.now ?? Date.now;
  let cache: { until: number; result: ReadinessResult } | null = null;
  let inflight: Promise<ReadinessResult> | null = null;

  /** Every check, now (in parallel). No check registered: ready. */
  async function evaluate(): Promise<ReadinessResult> {
    const list = [...checks()];
    const results = await Promise.all(list.map((c) => runCheck(c, timeoutMs)));
    return { ok: results.every((r) => r.ok), checkedAt: new Date(now()).toISOString(), checks: results };
  }

  /** The result, from the cache when it is younger than cacheMs (concurrent callers share one evaluation). */
  async function result(fresh = false): Promise<ReadinessResult> {
    const t = now();
    if (!fresh && cache && t < cache.until) return cache.result;
    if (!inflight) {
      inflight = evaluate()
        .then((r) => { cache = { until: now() + cacheMs, result: r }; return r; })
        .finally(() => { inflight = null; });
    }
    return inflight;
  }

  return {
    result,
    /** Ready? (cached) */
    check: async (): Promise<boolean> => (await result()).ok,
    reset(): void {
      cache = null;
    },
    /** The Express handler of GET /health/ready. */
    handler() {
      return async (_req: Request, res: Response): Promise<void> => {
        let ok = false;
        try {
          ok = (await result()).ok;
        } catch {
          ok = false;
        }
        res.setHeader('Cache-Control', 'no-store');
        res.status(ok ? 200 : 503).json({ status: ok ? 'ok' : 'degraded' });
      };
    },
  };
}

/** The readiness of this process (GET /health/ready, the ops status, ops.watch). */
export const readiness = createReadiness();
