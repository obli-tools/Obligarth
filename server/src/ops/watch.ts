import { MASTER_TENANT_ID } from '@obligarth/shared';
import { asTenant } from '../db/context';
import { JobError } from '../jobs/errors';
import { liveAlertService } from '../services/liveAlert.service';
import { logger } from '../utils/logger';
import type { JobContext, JobResult } from '../jobs/types';
import { readiness } from './ready';

// =============================================================================
// ops.watch (P0-13 T8; platform job, every 5 minutes, modules/ops.ts): the watch of the instance, alerts of the
// master tenant (live alerts, stable keys: the alert engine keeps one unread alert per key). Each check of the
// registry runs on its own (one that throws does not stop the others; the run fails afterwards). The core's:
//   readiness   the checks of GET /health/ready, evaluated afresh: from the second run in a row not ready, every
//               run raises the critical alert ops:not-ready (one unread alert per key), naming the failing checks
//               (fixed names, never a value); a write that fails fails the check.
// The backups add theirs with P0-13 T9 (ops.backup_stale, ops.wal_stale, ops.disk_low, ops.restore_drill_due).
// =============================================================================

export type OpsWatchCheck = (ctx: JobContext<unknown>) => Promise<Record<string, string | number | boolean | null> | void>;

const CHECK_NAME_RE = /^[a-z][a-z0-9_]{0,30}$/;
const checks: Array<{ name: string; run: OpsWatchCheck }> = [];

/** Declares a check of ops.watch (at registration time). A name registered twice throws. */
export function registerOpsWatchCheck(name: string, run: OpsWatchCheck): void {
  if (!CHECK_NAME_RE.test(name)) throw new Error(`ops.watch check ${JSON.stringify(name)}: invalid name`);
  if (checks.some((c) => c.name === name)) throw new Error(`ops.watch check ${name} registered twice`);
  checks.push({ name, run });
}

/** Consecutive runs that found the instance not ready (this process; ops.watch is exclusive). */
let notReadyStreak = 0;

/** The critical alert ops:not-ready of the master tenant (deduplicated on an unread alert of the key); unlike
 *  raiseJobAlert, a write that fails throws. */
async function raiseNotReady(ctx: JobContext<unknown>, failing: string[]): Promise<void> {
  logger.error({ alert: 'ops:not-ready', severity: 'critical' }, 'job alert: Instance not ready');
  await asTenant(MASTER_TENANT_ID, ctx.dbActor, () => liveAlertService.add(MASTER_TENANT_ID, {
    severity: 'critical',
    title: 'Instance not ready',
    message: `GET /health/ready answers 503 for 10 minutes or more. Failing checks: ${failing.join(', ')}.`.slice(0, 500),
    navigateTo: null,
    stableKey: 'ops:not-ready',
  }));
}

/** The readiness check of ops.watch. */
export async function watchReadiness(ctx: JobContext<unknown>): Promise<Record<string, string | number | boolean | null>> {
  const r = await readiness.result(true);
  if (r.ok) {
    notReadyStreak = 0;
    return { ready: true };
  }
  notReadyStreak += 1;
  const failing = r.checks.filter((c) => !c.ok).map((c) => c.name);
  if (notReadyStreak >= 2) {
    // Every run from the second on: the engine keeps one unread alert per key, so an alert read (or lost) while
    // the instance stays not ready is raised again. A write that fails fails the check (and the run).
    await raiseNotReady(ctx, failing);
  }
  return { ready: false, failing: failing.join(',').slice(0, 200), streak: notReadyStreak };
}

/** The handler of ops.watch. */
export async function runOpsWatch(ctx: JobContext<unknown>): Promise<JobResult> {
  const output: Record<string, string | number | boolean | null> = {};
  let failed = 0;
  for (const c of checks) {
    ctx.throwIfAborted();
    try {
      const r = await c.run(ctx);
      if (r) for (const [k, v] of Object.entries(r)) output[`${c.name}_${k}`.slice(0, 40)] = v;
    } catch (err) {
      failed++;
      ctx.log.warn({ check: c.name, code: (err as { code?: unknown })?.code ?? null }, 'ops.watch: check failed');
    }
  }
  if (failed > 0) throw new JobError('partial_failure', `${failed} check(s) of ops.watch failed`);
  return { output };
}

/** Tests only. */
export function resetOpsWatchForTests(): void {
  notReadyStreak = 0;
}
