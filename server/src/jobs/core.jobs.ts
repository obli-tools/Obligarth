import { z } from 'zod';
import { isMasterTenant } from '@obligarth/shared';
import { db } from '../db';
import { asIdentity } from '../db/context';
import { purgePlatformGrants } from '../db/platformAccess';
import { forEachTenant } from '../db/tenantContext';
import { AppError } from '../middleware/errorHandler';
import { approvalService, refuse, registerApprovalExecutor, requirePlatformAdmin, withAuditAs } from '../services/approval.service';
import { liveAlertService } from '../services/liveAlert.service';
import { notificationService } from '../services/notification.service';
import { tfaTrustService } from '../services/tfaTrust.service';
import { createJobsAdmin } from './admin';
import { performJobsOp, type JobsManageOp } from './admin.routes';
import { jobAlerts } from './alerts';
import { JobError } from './errors';
import { defaultRuntime, registerJob } from './index';
import { purgeExpiredOnce } from './once';
import { DEAD_LETTER_QUEUE, SCHEDULED_POLL_SECONDS } from './registry';
import { jobStatus } from './status';
import type { JobContext, JobResult } from './types';

// =============================================================================
// The core's durable jobs (docs: file-durable §10.3 and annex B): the jobs
// module's own (heartbeat, monitor, housekeeping), two-step approvals, phone
// keys, second-factor trusts, live alerts, the notification log, the dead
// identity rows (reset tokens, step-up throttles), the journal of the
// cross-tenant read grants; and the approval executor of the jobs
// administration.
// Schedules in UTC, off the hour; the daily ones between 02:00 and 05:00, five
// minutes apart at least. index.ts calls registerCoreJobs() before the start.
// =============================================================================

const empty = z.object({}).strict();

/** Live alerts and resolved ones are kept 90 days once read or resolved. */
const LIVE_ALERT_RETENTION_DAYS = 90;
/** notification_log rows (one per send) are kept 30 days. */
const NOTIFICATION_LOG_RETENTION_DAYS = 30;
/** Rows per slice of the purges below (file-durable motif M8). */
const PURGE_SLICE_ROWS = 500;
/** job_status rows of a queue no longer registered: 30 days. */
const RETIRED_STATUS_DAYS = 30;
/** jobs.monitor: a scheduled job is stale after two periods and 10 min without success. */
const STALE_MARGIN_MS = 10 * 60_000;

/** Tenant by tenant (forEachTenant, each tenant in its own context): a
 *  tenant that fails does not stop the others; the run fails afterwards. */
async function eachTenant(ctx: JobContext<unknown>, step: (tenantId: number) => Promise<number>): Promise<JobResult> {
  let rows = 0;
  const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    rows += await step(tenantId);
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
  return { output: { tenants: ok, rows } };
}

/** Runs `slice` until it deletes fewer rows than PURGE_SLICE_ROWS (each
 *  slice one statement: idempotent, the next one starts from the database). */
async function drainSlices(ctx: JobContext<unknown>, slice: () => Promise<number>): Promise<number> {
  let total = 0;
  for (;;) {
    ctx.throwIfAborted();
    const n = await slice();
    total += n;
    if (n < PURGE_SLICE_ROWS) return total;
  }
}

// ── Dead identity rows (identity context) ─────────────────────────────────

/** password_reset_tokens used or expired more than a day ago (a token is
 *  valid 1 h and single use: such a row can never be redeemed). */
async function purgeResetTokensSlice(): Promise<number> {
  const r = await db.raw(
    `DELETE FROM password_reset_tokens WHERE id IN (
       SELECT id FROM password_reset_tokens
        WHERE (used_at IS NOT NULL AND used_at < now() - interval '1 day')
           OR expires_at < now() - interval '1 day'
        ORDER BY id LIMIT ?)`,
    [PURGE_SLICE_ROWS],
  ) as { rowCount: number | null };
  return Number(r.rowCount ?? 0);
}

/** step_up_throttle rows whose every window ended more than a day ago and
 *  that are not locked: deleting one is the same as the fresh row the next
 *  failure would create (services/deviceKey/stepUpProof.ts: 15-min and 24-h
 *  windows, 24-h enrolment lock, notice at most once per 24 h). A 'code' row
 *  locked until a full sign-in is never deleted. The conditions are written
 *  twice on purpose: the inner ones choose the slice, the outer ones are
 *  checked again on the row as it is when the DELETE reaches it, so a failure
 *  counted meanwhile (the row is live again) is never erased. */
async function purgeStepUpThrottleSlice(): Promise<number> {
  const r = await db.raw(
    `DELETE FROM step_up_throttle
      WHERE NOT locked
        AND (locked_until IS NULL OR locked_until < now() - interval '1 day')
        AND (window_start IS NULL OR window_start < now() - interval '1 day')
        AND (day_start    IS NULL OR day_start    < now() - interval '2 days')
        AND (notified_at  IS NULL OR notified_at  < now() - interval '2 days')
        AND (user_id, kind) IN (
          SELECT user_id, kind FROM step_up_throttle
           WHERE NOT locked
             AND (locked_until IS NULL OR locked_until < now() - interval '1 day')
             AND (window_start IS NULL OR window_start < now() - interval '1 day')
             AND (day_start    IS NULL OR day_start    < now() - interval '2 days')
             AND (notified_at  IS NULL OR notified_at  < now() - interval '2 days')
           ORDER BY user_id, kind LIMIT ?)`,
    [PURGE_SLICE_ROWS],
  ) as { rowCount: number | null };
  return Number(r.rowCount ?? 0);
}

// ── jobs.monitor ──────────────────────────────────────────────────────────

/** Consecutive monitor runs that found each queue over its warning size. */
const backlogStreaks = new Map<string, number>();

async function monitor(ctx: JobContext<unknown>): Promise<JobResult> {
  const boss = defaultRuntime.bossOrThrow();
  const defs = defaultRuntime.registry.list();
  const queues = new Map((await boss.getQueues()).map((q) => [q.name, q]));
  const status = await jobStatus.list();
  const statusOf = (queue: string) => status.find((s) => s.queue === queue && s.key === '');

  // Queues behind: ready jobs over the warning size at two checks in a row.
  let backlog = 0;
  for (const def of defs) {
    const ready = Number(queues.get(def.name)?.readyCount ?? 0);
    const streak = ready > def.warningQueueSize ? (backlogStreaks.get(def.name) ?? 0) + 1 : 0;
    backlogStreaks.set(def.name, streak);
    if (streak >= 2) backlog++;
    if (streak === 2) await jobAlerts.backlog(ctx.dbActor, def.name, ready);
  }

  // Scheduled jobs without success for two periods and 10 minutes (from
  // the last success, or from the schedule's creation for a job that never
  // succeeded, and never before this instance started: a downtime is the
  // external probe's to report): the second occurrence after it is more
  // than 10 min old. Not the monitor itself: this run is its proof.
  let stale = 0;
  const schedules = new Map((await boss.getSchedules()).filter((s) => s.key === '').map((s) => [s.name, s]));
  const startedAt = defaultRuntime.startedAt?.getTime() ?? Date.now();
  for (const def of defs) {
    if (!def.schedule || def.name === ctx.name) continue;
    const last = statusOf(def.name)?.lastSucceededAt ?? schedules.get(def.name)?.createdOn ?? null;
    if (!last) continue;
    const ref = Math.max(new Date(last).getTime(), startedAt);
    const next = boss.previewSchedule(def.schedule.cron, { tz: def.schedule.tz, from: new Date(ref), count: 2 });
    if (next.length === 2 && next[1].getTime() + STALE_MARGIN_MS < Date.now()) {
      stale++;
      await jobAlerts.stale(ctx.dbActor, def.name);
    }
  }

  // New dead letters: created since the START of the previous completed run
  // (one created while that run was counting is counted twice rather than
  // never; the alert is deduplicated).
  const prev = await boss.getDb().executeSql(
    `SELECT max(started_on) AS since FROM pgboss.job WHERE name = $1 AND state = 'completed' AND id <> $2`,
    [ctx.name, ctx.jobId],
  );
  const prevStart = (prev.rows[0] as { since: Date | string | null } | undefined)?.since ?? null;
  const since = prevStart !== null
    ? new Date(prevStart)
    : statusOf(ctx.name)?.lastSucceededAt ?? new Date(Date.now() - 2 * STALE_MARGIN_MS);
  const { rows } = await boss.getDb().executeSql(
    'SELECT count(*)::int AS n FROM pgboss.job WHERE name = $1 AND created_on > $2',
    [DEAD_LETTER_QUEUE, since],
  );
  const newDeadLetters = Number((rows[0] as { n: number } | undefined)?.n ?? 0);
  if (newDeadLetters > 0) await jobAlerts.deadLetters(ctx.dbActor, newDeadLetters);
  return { output: { backlog, stale, newDeadLetters } };
}

// ── Administration: approved 'jobs_manage' requests ─────────────────────────

const JobsOpPayload = z.discriminatedUnion('op', [
  z.object({ op: z.literal('run'), queue: z.string().max(64) }),
  z.object({ op: z.literal('cancel'), queue: z.string().max(64), jobId: z.string().max(64) }),
  z.object({ op: z.literal('redrive'), ids: z.array(z.string().max(64)).max(100).optional(), source: z.string().max(64).optional() }),
  z.object({ op: z.literal('discard'), id: z.string().max(64) }),
]);

let registered = false;

export function registerCoreJobs(): void {
  if (registered) return;
  registered = true;

  // ── The jobs module's own ─────────────────────────────────────────────────
  registerJob({
    name: 'jobs.heartbeat',
    scope: 'platform',
    description: 'Does nothing: its status proves that the cron pass and the workers run (GET /health/jobs)',
    payload: empty,
    schedule: { cron: '* * * * *' },
    // At start too: /health/jobs is green as soon as the workers run.
    runAtStart: true,
    retry: { limit: 0 },
    timeoutSeconds: 60,
    // Run as soon as the cron pass sends it (woken by NOTIFY, polled every
    // 2 s without it): its success follows the occurrence closely, so
    // /health/jobs turns 503 at most JOBS_HEALTH_MAX_HEARTBEAT_AGE_S after
    // the last occurrence sent.
    notify: true,
    pollSeconds: 2,
    handler: async () => undefined,
  });

  registerJob({
    name: 'jobs.monitor',
    scope: 'platform',
    description: 'Queues behind, scheduled jobs without success, new dead letters: alerts of the master tenant',
    payload: empty,
    schedule: { cron: '*/5 * * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    retry: { limit: 0 },
    timeoutSeconds: 120,
    handler: monitor,
  });

  registerJob({
    name: 'jobs.housekeeping',
    scope: 'platform',
    description: 'Purge the expired job_once keys and the job_status rows of retired queues',
    payload: empty,
    schedule: { cron: '45 3 * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    timeoutSeconds: 300,
    handler: async () => {
      const once = await purgeExpiredOnce();
      const status = await jobStatus.purgeRetired(defaultRuntime.registry.list().map((d) => d.name), RETIRED_STATUS_DAYS);
      return { output: { once, status } };
    },
  });

  // ── Two-step approvals ────────────────────────────────────────────────────
  registerJob({
    name: 'core.approvals.expire',
    scope: 'platform',
    description: 'Expire the pending two-step approvals past their deadline',
    payload: empty,
    schedule: { cron: '* * * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    runAtStart: true,
    retry: { limit: 0 },
    timeoutSeconds: 60,
    keepFinishedSeconds: 86_400,
    handler: (ctx) => eachTenant(ctx, (tenantId) => approvalService.sweepExpired(tenantId, { actor: ctx.actor, jobId: ctx.jobId })),
  });

  // ── Phone keys (device-bound 2FA §6.9), in the identity context ──────────
  registerJob({
    name: 'core.device-keys.sweep-challenges',
    scope: 'platform',
    description: 'Delete the phone-key challenges expired for more than 7 days',
    payload: empty,
    schedule: { cron: '17 * * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    timeoutSeconds: 120,
    handler: async (ctx) => {
      const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
      const deleted = await asIdentity(ctx.dbActor, () => deviceKeyService.sweepChallenges());
      return { output: { deleted } };
    },
  });

  // Daily, at a fixed hour (no longer at each start): stale keys, Google's
  // revocation list (only while the feature is on). An occurrence missed
  // while the server was down runs once at the next start.
  registerJob({
    name: 'core.device-keys.daily',
    scope: 'platform',
    description: 'Revoke the phone keys unused for 180 days, refresh the attestation revocation list',
    payload: empty,
    schedule: { cron: '40 2 * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    timeoutSeconds: 600,
    handler: async (ctx) => {
      const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
      const r = await asIdentity(ctx.dbActor, () => deviceKeyService.runDailyTasks());
      return { output: { skipped: r.skipped, staleRevoked: r.staleRevoked, statusRefreshed: r.statusRefreshed, attestationRevoked: r.attestationRevoked } };
    },
  });

  // ── Second-factor trusts (identity context) ──────────────────────────────
  registerJob({
    name: 'core.tfa-trust.sweep',
    scope: 'platform',
    description: 'Delete the expired second-factor trusts',
    payload: empty,
    schedule: { cron: '7 * * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    timeoutSeconds: 120,
    handler: async (ctx) => ({ output: { deleted: await asIdentity(ctx.dbActor, () => tfaTrustService.sweepExpired()) } }),
  });

  // ── Live alerts: read or resolved ones, after 90 days ─────────────────────
  registerJob({
    name: 'core.live-alerts.purge',
    scope: 'platform',
    description: 'Delete the live alerts read or resolved more than 90 days ago',
    payload: empty,
    schedule: { cron: '15 3 * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    timeoutSeconds: 300,
    handler: (ctx) => eachTenant(ctx, (tenantId) => liveAlertService.purgeOld(LIVE_ALERT_RETENTION_DAYS, tenantId)),
  });

  // ── Notification log: 30 days ─────────────────────────────────────────────
  registerJob({
    name: 'core.notification-log.purge',
    scope: 'platform',
    description: 'Delete the notification log rows older than 30 days',
    payload: empty,
    schedule: { cron: '10 3 * * *' },
    timeoutSeconds: 600,
    heartbeatSeconds: 60,
    // A daily job: woken by NOTIFY (a run asked by hand starts at once), polled once a minute at rest.
    notify: true,
    pollSeconds: 60,
    handler: (ctx) => eachTenant(ctx, (tenantId) => {
      const olderThan = new Date(Date.now() - NOTIFICATION_LOG_RETENTION_DAYS * 86_400_000);
      return drainSlices(ctx, () => notificationService.purgeLogSlice(tenantId, olderThan, PURGE_SLICE_ROWS));
    }),
  });

  // ── Dead identity rows: reset tokens, step-up throttles (identity context)
  registerJob({
    name: 'core.identity-rows.purge',
    scope: 'platform',
    description: 'Delete the password reset tokens used or expired for a day, and the step-up throttles whose windows all ended',
    payload: empty,
    schedule: { cron: '25 3 * * *' },
    timeoutSeconds: 300,
    notify: true,
    pollSeconds: 60,
    handler: async (ctx) => asIdentity(ctx.dbActor, async () => {
      const resetTokens = await drainSlices(ctx, purgeResetTokensSlice);
      const stepUpThrottles = await drainSlices(ctx, purgeStepUpThrottleSlice);
      return { output: { resetTokens, stepUpThrottles } };
    }),
  });

  // ── Journal of the cross-tenant read grants (rls-tenant §6.2) ─────────────
  registerJob({
    name: 'core.platform-grants.purge',
    scope: 'platform',
    description: 'Purge the journal of the cross-tenant read grants (PLATFORM_GRANT_RETENTION_DAYS)',
    payload: empty,
    schedule: { cron: '30 3 * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    timeoutSeconds: 300,
    handler: async () => ({ output: { deleted: await purgePlatformGrants() } }),
  });

  // ── Administration of the jobs: an approved request ('restricted' level of
  //    jobs.manage), executed as the requester, who must still be an active
  //    platform administrator, from the master tenant.
  const admin = createJobsAdmin(defaultRuntime);
  registerApprovalExecutor('jobs_manage', async ({ tenantId, requesterId, payload }) => {
    await requirePlatformAdmin(requesterId);
    if (!isMasterTenant(tenantId)) refuse('Background jobs are administered from the master tenant only');
    const parsed = JobsOpPayload.safeParse(payload);
    if (!parsed.success) refuse('Invalid background job request');
    try {
      await performJobsOp(admin, parsed.data as JobsManageOp,
        (action, extras, fn, resultDetails) => withAuditAs(tenantId, requesterId, action, extras, fn, resultDetails));
    } catch (err) {
      if (err instanceof AppError || err instanceof JobError) refuse(err.message);
      throw err;
    }
  });
}
