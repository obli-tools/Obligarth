// android.maintenance (platform job, every minute, AN39): one query (android_maintenance_due) finds the tenants with
// work, and only those are touched:
//   - due inbox events (retries): the tenant's android.inbox-drain is sent;
//   - signups: consuming for more than 10 minutes → failed (interrupted) and tenant alert; requested or url_issued
//     past their hour → expired;
//   - purges: payload emptied 24 h after application, applied and skipped rows deleted after 7 days, dead letters after
//     30 days, destructive counter after 2 hours, finished signups after 30 days.
// Weekly (Monday 04:00 UTC): the check of the project's enterprises (AN51).
import { db } from '../db';
import { asNone, asTenant } from '../db/context';
import { raiseAndroidTenantAlert } from './alerts';
import { checkProjectEnterprises, MAINTENANCE_ACTOR } from './enterprises/orphans';
import { expireEnrollmentTokens } from './enrollment/tokens';
import type { AndroidGateway } from './gateway/types';
import { resubmitStaleCommands, resumeHeldCommands, sweepResetPasswordSecrets } from './commands/submit';

type DrainWaker = (tenantId: number) => Promise<unknown>;
let wakeDrain: DrainWaker = async () => undefined;
export function setMaintenanceDrainWaker(fn: DrainWaker): void { wakeDrain = fn; }
/** android.tokens-recover of a tenant (AN50 recovery and garbage collection at Google: network, hence a job). */
let recoverTokens: DrainWaker = async () => undefined;
export function setTokenRecoverySender(fn: DrainWaker): void { recoverTokens = fn; }
/** android.operations-poll of a tenant (lot AN-D1: operations to read, commands to expire: network, hence a job). */
let pollOperations: DrainWaker = async () => undefined;
export function setOperationsPollSender(fn: DrainWaker): void { pollOperations = fn; }

export interface MaintenanceResult {
  drains: number; interrupted: number; expired: number; purged: number; orphans: number | null; tokensExpired: number;
  /** Lot AN-D1: tenants whose commands were followed up (polls sent, submissions sent again, held resumed, secrets swept). */
  commands: number;
}

export async function runAndroidMaintenance(o: { now?: Date; gateway?: AndroidGateway; weekly?: boolean } = {}): Promise<MaintenanceResult> {
  const now = o.now ?? new Date();
  const out: MaintenanceResult = { drains: 0, interrupted: 0, expired: 0, purged: 0, orphans: null, tokensExpired: 0, commands: 0 };
  const due = await asNone(MAINTENANCE_ACTOR, async () => {
    const r = await db.raw('SELECT tenant_id, inbox_due, signups_due, purge_due FROM obligarth.android_maintenance_due()') as
      { rows: Array<{ tenant_id: number; inbox_due: boolean; signups_due: boolean; purge_due: boolean }> };
    return r.rows;
  });
  for (const t of due) {
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
        n += await trx('android_enrollment_tokens').whereIn('state', ['used', 'expired', 'revoked', 'failed'])
          .where('ended_at', '<', trx.raw("now() - interval '90 days'")).delete();
        n += await trx('android_signups').whereIn('state', ['completed', 'failed', 'expired', 'cancelled'])
          .where('created_at', '<', trx.raw("now() - interval '30 days'")).delete();
        return n;
      }));
    }
  }
  // Enrollment tokens (lot AN-C1b): active ones past their end expire here (their value destroyed); interrupted
  // creations (creating for 15 minutes and more) go to android.tokens-recover.
  const tokenDue = await asNone(MAINTENANCE_ACTOR, async () => {
    const r = await db.raw('SELECT tenant_id FROM obligarth.android_enrollment_due()') as { rows: Array<{ tenant_id: number }> };
    return r.rows.map((x) => Number(x.tenant_id));
  });
  for (const tenantId of tokenDue) {
    out.tokensExpired += await expireEnrollmentTokens(tenantId, MAINTENANCE_ACTOR);
    const stale = await asTenant(tenantId, MAINTENANCE_ACTOR, () => db('android_enrollment_tokens').where({ state: 'creating' })
      .where('created_at', '<', db.raw("now() - interval '15 minutes'")).first('id'));
    if (stale) await recoverTokens(tenantId);
  }
  // Commands (lot AN-D1, section 11.3): operations to poll and commands past their end (android.operations-poll),
  // submissions lost or interrupted (their job again), held commands to resume, reset-password secrets to sweep.
  const commandDue = await asNone(MAINTENANCE_ACTOR, async () => {
    const r = await db.raw('SELECT tenant_id, submit_due, poll_due, expire_due, resume_due, secrets_due FROM obligarth.android_commands_due()') as
      { rows: Array<{ tenant_id: number; submit_due: boolean; poll_due: boolean; expire_due: boolean; resume_due: boolean; secrets_due: boolean }> };
    return r.rows;
  });
  for (const t of commandDue) {
    const tenantId = Number(t.tenant_id);
    if (t.poll_due || t.expire_due) await pollOperations(tenantId);
    if (t.submit_due) await resubmitStaleCommands(tenantId, MAINTENANCE_ACTOR);
    if (t.resume_due) await resumeHeldCommands(tenantId, MAINTENANCE_ACTOR);
    if (t.secrets_due) await sweepResetPasswordSecrets(tenantId, MAINTENANCE_ACTOR);
    out.commands += 1;
  }
  const weekly = o.weekly ?? (now.getUTCDay() === 1 && now.getUTCHours() === 4 && now.getUTCMinutes() === 0);
  if (weekly && o.gateway?.mode !== 'off') {
    out.orphans = (await checkProjectEnterprises(o.gateway)).length;
  }
  return out;
}
