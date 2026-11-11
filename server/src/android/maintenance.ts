// android.maintenance (platform job, every minute, AN39): one query (android_maintenance_due) finds the tenants with
// work, and only those are touched:
//   - due inbox events (retries): the tenant's android.inbox-drain is sent;
//   - signups: consuming for more than 10 minutes → failed (interrupted) and tenant alert; requested or url_issued
//     past their hour → expired;
//   - purges: payload emptied 24 h after application, applied and skipped rows deleted after 7 days, dead letters after
//     30 days, destructive counter after 2 hours, finished signups after 30 days.
// Weekly (Monday 04:00 UTC): the check of the project's enterprises (AN51) and the recount of the quota (AN49).
// Lot AN-H1 (operation): android_operations_due() finds the tenants whose reconciliation is due (daily slot, or asked),
// whose devices presumed gone reach 270 days (the forget runs in the reconciliation), whose offboarding has a step due,
// or whose operation rows are to purge (400 days); hourly: the quota of the project and the purge of the idle rate
// buckets; daily (from 04:10 UTC): the age of the service account key. The periodic checks run at the first pass once
// their slot is past (review F026); the weekly one is due while no recount was recorded since Monday 04:00 UTC. A
// failure for one tenant never stops the sweep of the others.
import { db } from '../db';
import { logger } from '../utils/logger';
import { asNone, asTenant } from '../db/context';
import { raiseAndroidTenantAlert } from './alerts';
import { checkProjectEnterprises, MAINTENANCE_ACTOR } from './enterprises/orphans';
import { expireEnrollmentTokens } from './enrollment/tokens';
import { expireSigninSessions } from './signin/flow';
import type { AndroidGateway } from './gateway/types';
import { resubmitStaleCommands, resumeHeldCommands, sweepResetPasswordSecrets } from './commands/submit';
import { expireKioskExits } from './kiosk/exits';
import { checkKeyDeadline } from './operations/deadlines';
import { purgeIdleBuckets } from './gateway/limiter';
import { checkProjectQuota, recountQuota, type QuotaLevel, type QuotaRecount } from './operations/quota';

type DrainWaker = (tenantId: number) => Promise<unknown>;
let wakeDrain: DrainWaker = async () => undefined;
export function setMaintenanceDrainWaker(fn: DrainWaker): void { wakeDrain = fn; }
/** android.tokens-recover of a tenant (AN50 recovery and garbage collection at Google: network, hence a job). */
let recoverTokens: DrainWaker = async () => undefined;
export function setTokenRecoverySender(fn: DrainWaker): void { recoverTokens = fn; }
/** android.operations-poll of a tenant (lot AN-D1: operations to read, commands to expire: network, hence a job). */
let pollOperations: DrainWaker = async () => undefined;
export function setOperationsPollSender(fn: DrainWaker): void { pollOperations = fn; }
/** android.app-metadata of a tenant (lot AN-E1: metadata of its Android apps read at Google again: network, hence a job). */
let refreshApps: DrainWaker = async () => undefined;
export function setAppMetadataSender(fn: DrainWaker): void { refreshApps = fn; }
/** android.reconcile-tenant of a tenant (lot AN-H1: devices.list and the forgets: network, hence a job). */
let reconcileTenantJob: DrainWaker = async () => undefined;
export function setReconcileSender(fn: DrainWaker): void { reconcileTenantJob = fn; }
/** android.offboard-tenant of a tenant (lot AN-H1: a step due again, or waiting for the devices left). */
let offboardTenantJob: DrainWaker = async () => undefined;
export function setOffboardingSender(fn: DrainWaker): void { offboardTenantJob = fn; }

export interface MaintenanceResult {
  drains: number; interrupted: number; expired: number; purged: number; orphans: number | null; tokensExpired: number;
  /** Lot AN-D1: tenants whose commands were followed up (polls sent, submissions sent again, held resumed, secrets swept). */
  commands: number;
  /** Lot AN-F2: sign-in sessions past their end marked expired (old failed or expired ones purged). */
  signins: number;
  /** Lot AN-E1: tenants whose Android apps' metadata were sent to android.app-metadata. */
  apps: number;
  /** Lot AN-G1: tenants whose kiosk exits past their end (or of devices that left management) were ended. */
  kiosk: number;
  /** Lot AN-H1: reconciliations sent (due, asked, forgets due), offboarding steps sent, tenants purged. */
  reconciles: number;
  offboardings: number;
  operationsPurged: number;
  /** Hourly: the level of the quota of the project (null: not this run). Weekly: the recount (null: not this run). */
  quota: QuotaLevel | null;
  recount: QuotaRecount | null;
  /** Daily: the status of the service account key deadline (null: not this run, or no key). */
  key: string | null;
}

export async function runAndroidMaintenance(o: { now?: Date; gateway?: AndroidGateway; weekly?: boolean; hourly?: boolean; daily?: boolean } = {}): Promise<MaintenanceResult> {
  const now = o.now ?? new Date();
  const out: MaintenanceResult = {
    drains: 0, interrupted: 0, expired: 0, purged: 0, orphans: null, tokensExpired: 0, signins: 0, commands: 0, apps: 0, kiosk: 0,
    reconciles: 0, offboardings: 0, operationsPurged: 0, quota: null, recount: null, key: null,
  };
  // What is due, in one statement of the context none (file-durable L3, lot AN-A2: the run of every minute costs one
  // round trip when nothing is due, whatever the number of sweeps).
  const all = await asNone(MAINTENANCE_ACTOR, async () => {
    const r = await db.raw(`SELECT
      (SELECT COALESCE(json_agg(x), '[]') FROM obligarth.android_maintenance_due() x) AS maintenance,
      (SELECT COALESCE(json_agg(x.tenant_id), '[]') FROM obligarth.android_enrollment_due() x) AS tokens,
      (SELECT COALESCE(json_agg(x.tenant_id), '[]') FROM obligarth.android_signin_due() x) AS signins,
      (SELECT COALESCE(json_agg(x), '[]') FROM obligarth.android_commands_due() x) AS commands,
      (SELECT COALESCE(json_agg(x.tenant_id), '[]') FROM obligarth.android_apps_due() x) AS apps,
      (SELECT COALESCE(json_agg(x.tenant_id), '[]') FROM obligarth.android_kiosk_due() x) AS kiosk,
      (SELECT COALESCE(json_agg(x), '[]') FROM obligarth.android_operations_due() x) AS operations`) as { rows: Array<Record<string, unknown>> };
    return r.rows[0] ?? {};
  });
  const list = <T>(v: unknown): T[] => (Array.isArray(v) ? v : typeof v === 'string' ? JSON.parse(v) : []) as T[];
  const ids = (v: unknown): number[] => list<number | string>(v).map(Number);
  const due = list<{ tenant_id: number; inbox_due: boolean; signups_due: boolean; purge_due: boolean }>(all.maintenance);
  for (const t of due) await isolated('maintenance', t.tenant_id, async () => {
    if (t.inbox_due) { await wakeDrain(t.tenant_id); out.drains += 1; }
    if (t.signups_due) {
      const r = await asTenant(t.tenant_id, MAINTENANCE_ACTOR, () => db.transaction(async (trx) => {
        const interrupted = await trx('android_signups').where({ state: 'consuming' })
          .where('consuming_at', '<', trx.raw("now() - interval '10 minutes'"))
          .update({ state: 'failed', failure_code: 'interrupted' });
        const expired = await trx('android_signups').whereIn('state', ['requested', 'url_issued'])
          .where('expires_at', '<=', trx.fn.now())
          .update({ state: 'expired', failure_code: 'expired' });
        return { interrupted, expired };
      }));
      out.interrupted += r.interrupted;
      out.expired += r.expired;
      if (r.interrupted) void raiseAndroidTenantAlert(t.tenant_id, 'android.signup_interrupted', { count: r.interrupted });
    }
    if (t.purge_due) {
      out.purged += await asTenant(t.tenant_id, MAINTENANCE_ACTOR, () => db.transaction(async (trx) => {
        let n = await trx('android_inbox').whereIn('state', ['applied', 'skipped']).whereNotNull('payload')
          .where('applied_at', '<', trx.raw("now() - interval '24 hours'")).update({ payload: null });
        n += await trx('android_inbox').whereIn('state', ['applied', 'skipped'])
          .where('applied_at', '<', trx.raw("now() - interval '7 days'")).delete();
        n += await trx('android_inbox').where({ state: 'dead' })
          .where('received_at', '<', trx.raw("now() - interval '30 days'")).delete();
        n += await trx('android_destructive_events').where('at', '<', trx.raw("now() - interval '2 hours'")).delete();
        n += await trx('android_signups').whereIn('state', ['completed', 'failed', 'expired', 'cancelled'])
          .where('created_at', '<', trx.raw("now() - interval '30 days'")).delete();
        return n;
      }));
    }
  });
  // Enrollment tokens (lot AN-C1b): active ones past their end expire here (their value destroyed); interrupted
  // creations (creating for 15 minutes and more) go to android.tokens-recover.
  const tokenDue = ids(all.tokens);
  for (const tenantId of tokenDue) await isolated('tokens', tenantId, async () => {
    out.tokensExpired += await expireEnrollmentTokens(tenantId, MAINTENANCE_ACTOR);
    const stale = await asTenant(tenantId, MAINTENANCE_ACTOR, () => db('android_enrollment_tokens').where({ state: 'creating' })
      .where('created_at', '<', db.raw("now() - interval '15 minutes'")).first('id'));
    if (stale) await recoverTokens(tenantId);
  });
  // Sign-in sessions (lot AN-F2): past their end without a token → expired; failed and expired ones purged after 30 days.
  const signinDue = ids(all.signins);
  for (const tenantId of signinDue) await isolated('signins', tenantId, async () => { out.signins += await expireSigninSessions(tenantId, MAINTENANCE_ACTOR); });
  // Commands (lot AN-D1, section 11.3): operations to poll and commands past their end (android.operations-poll),
  // submissions lost or interrupted (their job again), held commands to resume, reset-password secrets to sweep.
  const commandDue = list<{ tenant_id: number; submit_due: boolean; poll_due: boolean; expire_due: boolean; resume_due: boolean; secrets_due: boolean }>(all.commands);
  for (const t of commandDue) await isolated('commands', Number(t.tenant_id), async () => {
    const tenantId = Number(t.tenant_id);
    if (t.poll_due || t.expire_due) await pollOperations(tenantId);
    if (t.submit_due) await resubmitStaleCommands(tenantId, MAINTENANCE_ACTOR);
    if (t.resume_due) await resumeHeldCommands(tenantId, MAINTENANCE_ACTOR);
    if (t.secrets_due) await sweepResetPasswordSecrets(tenantId, MAINTENANCE_ACTOR);
    out.commands += 1;
  });
  // Apps (lot AN-E1, section 9.6): metadata a day old or never read (android.app-metadata, once a day at most per app).
  const appsDue = ids(all.apps);
  for (const tenantId of appsDue) await isolated('apps', tenantId, async () => { await refreshApps(tenantId); out.apps += 1; });
  // Kiosk exits (lot AN-G1, section 9.7): those past their end whose job was lost, those of devices that left.
  const kioskDue = ids(all.kiosk);
  for (const tenantId of kioskDue) await isolated('kiosk', tenantId, async () => { await expireKioskExits(tenantId, MAINTENANCE_ACTOR); out.kiosk += 1; });
  // Operation (lot AN-H1): reconciliations, forgets at 270 days, offboarding steps, purge of the operation rows.
  const opsDue = list<{ tenant_id: number; reconcile_due: boolean; forget_due: boolean; offboarding_due: boolean; purge_due: boolean }>(all.operations);
  for (const t of opsDue) {
    const tenantId = Number(t.tenant_id);
    // A send that fails (queue unavailable) never stops the sweep of the other tenants: the next minute tries again.
    try {
      if (t.reconcile_due || t.forget_due) { await reconcileTenantJob(tenantId); out.reconciles += 1; }
      if (t.offboarding_due) { await offboardTenantJob(tenantId); out.offboardings += 1; }
    } catch (err) {
      logger.warn({ android: { maintenance: 'operations', tenantId, code: (err as { code?: string })?.code ?? 'error' } }, 'android: operation job not sent');
    }
    if (t.purge_due) await isolated('operations-purge', tenantId, async () => {
      await asTenant(tenantId, MAINTENANCE_ACTOR, () => db.transaction(async (trx) => {
        await trx('android_presumed_gone').whereNot('state', 'open').where('ended_at', '<', trx.raw("now() - interval '400 days'")).delete();
        await trx('android_offboardings').whereNotNull('finished_at').where('finished_at', '<', trx.raw("now() - interval '400 days'")).delete();
      }));
      out.operationsPurged += 1;
    });
  }
  // Review F027: the rate buckets of resources (k:<action>:<enterprise>:<resource>) not touched for an hour are full
  // again, hence the same as an absent row: deleted, so the table does not grow with every token, device and policy.
  // Review F026: the periodic checks run once their slot is past and they did not run since, not only at the exact
  // minute (a restart or a long pass at that minute skipped them for an hour, a day or a week, without a trace). Each
  // one is isolated (its failure is logged and never skips the others) and marked done only after a success; a failed
  // one is tried again after PERIODIC_RETRY_MS, not every minute.
  const forced = (v: boolean | undefined) => v !== undefined;
  await periodic('rate-buckets', o.hourly, hourKey(now), now, async () => { await asNone(MAINTENANCE_ACTOR, () => purgeIdleBuckets()); });
  await periodic('hourly', o.hourly, hourKey(now), now, async () => { out.quota = (await checkProjectQuota()).level; });
  const dailySlotPast = now.getUTCHours() * 60 + now.getUTCMinutes() >= 4 * 60 + 10;
  if (forced(o.daily) || dailySlotPast) {
    await periodic('daily', o.daily, dayKey(now), now, async () => { out.key = (await checkKeyDeadline(now))?.status ?? null; });
  }
  // The weekly mark is durable: the last recount (android_quota_recounts) older than the last Monday 04:00 UTC.
  const slotKey = lastWeeklySlot(now).toISOString();
  let weekly = o.weekly;
  if (weekly === undefined) {
    try {
      weekly = retryAllowed('weekly', now) && await weeklyDue(now);
    } catch (err) {
      periodicFailed('weekly', now, err);
      weekly = false;
    }
  }
  if (weekly && o.weekly === undefined && o.gateway?.mode === 'off') lastPeriodic.set('weekly', slotKey);
  if (weekly && o.gateway?.mode !== 'off') {
    try {
      out.recount = await recountQuota();
      if (o.weekly === undefined) { lastPeriodic.set('weekly', slotKey); periodicRetryAt.delete('weekly'); }
    } catch (err) {
      periodicFailed('weekly', now, err);
    }
    try {
      out.orphans = (await checkProjectEnterprises(o.gateway)).length;
    } catch (err) {
      logger.warn({ android: { maintenance: 'orphans', kind: (err as { kind?: string })?.kind ?? 'error' } }, 'android: weekly check of the project enterprises failed');
    }
  }
  return out;
}

/** A failed periodic check is tried again after this delay (not at every minute). */
const PERIODIC_RETRY_MS = 10 * 60_000;
const periodicRetryAt = new Map<string, number>();
const retryAllowed = (name: string, now: Date): boolean => (periodicRetryAt.get(name) ?? 0) <= now.getTime();
function periodicFailed(name: string, now: Date, err: unknown): void {
  periodicRetryAt.set(name, now.getTime() + PERIODIC_RETRY_MS);
  logger.warn({ android: { maintenance: name, code: (err as { code?: string })?.code ?? (err as { kind?: string })?.kind ?? 'error' } },
    'android: periodic check failed, tried again later');
}

/**
 * One periodic check: run when forced (`force` true), skipped when forced off (false), otherwise once per period key;
 * marked done only after a success. Its failure is logged and never thrown (the other checks of the pass still run).
 */
export async function periodic(name: string, force: boolean | undefined, key: string, now: Date, fn: () => Promise<void>): Promise<void> {
  if (force === false) return;
  if (force === undefined && (lastPeriodic.get(name) === key || !retryAllowed(name, now))) return;
  try {
    await fn();
    if (force === undefined) { lastPeriodic.set(name, key); periodicRetryAt.delete(name); }
  } catch (err) {
    if (force === undefined) periodicFailed(name, now, err);
    else logger.warn({ android: { maintenance: name, code: (err as { code?: string })?.code ?? 'error' } }, 'android: periodic check failed');
  }
}

/** Test hook: forgets the in-process marks of the periodic checks. */
export function resetPeriodicMarks(): void { lastPeriodic.clear(); periodicRetryAt.clear(); }

/** One tenant's sweep: its failure is logged and never stops the sweep of the other tenants (the next minute tries again). */
async function isolated(sweep: string, tenantId: number, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    logger.warn({ android: { maintenance: sweep, tenantId, code: (err as { code?: string })?.code ?? (err as { kind?: string })?.kind ?? 'error' } },
      'android: maintenance of a tenant failed');
  }
}

const hourKey = (d: Date): string => d.toISOString().slice(0, 13);
const dayKey = (d: Date): string => d.toISOString().slice(0, 10);
/** The last period each in-process check succeeded for (a restart runs it once more: the checks are idempotent). */
const lastPeriodic = new Map<string, string>();

/** The last Monday 04:00 UTC at or before `now`. Pure (unit tests). */
export function lastWeeklySlot(now: Date): Date {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 4, 0));
  d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7));
  if (d.getTime() > now.getTime()) d.setUTCDate(d.getUTCDate() - 7);
  return d;
}

/** Due when no recount was recorded since the last weekly slot; read once per slot by this process once settled. */
async function weeklyDue(now: Date): Promise<boolean> {
  const slot = lastWeeklySlot(now);
  if (lastPeriodic.get('weekly') === slot.toISOString()) return false;
  const last = await asNone(MAINTENANCE_ACTOR, () => db('android_quota_recounts').max<{ at: Date | null }[]>('counted_at as at'));
  const at = last[0]?.at ? new Date(last[0].at) : null;
  const due = !at || at.getTime() < slot.getTime();
  if (!due) lastPeriodic.set('weekly', slot.toISOString());   // done for this slot: not read again until the next one
  return due;
}
