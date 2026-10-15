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
import type { AndroidGateway } from './gateway/types';

type DrainWaker = (tenantId: number) => Promise<unknown>;
let wakeDrain: DrainWaker = async () => undefined;
export function setMaintenanceDrainWaker(fn: DrainWaker): void { wakeDrain = fn; }

export interface MaintenanceResult { drains: number; interrupted: number; expired: number; purged: number; orphans: number | null }

export async function runAndroidMaintenance(o: { now?: Date; gateway?: AndroidGateway; weekly?: boolean } = {}): Promise<MaintenanceResult> {
  const now = o.now ?? new Date();
  const out: MaintenanceResult = { drains: 0, interrupted: 0, expired: 0, purged: 0, orphans: null };
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
        n += await trx('android_signups').whereIn('state', ['completed', 'failed', 'expired', 'cancelled'])
          .where('created_at', '<', trx.raw("now() - interval '30 days'")).delete();
        return n;
      }));
    }
  }
  const weekly = o.weekly ?? (now.getUTCDay() === 1 && now.getUTCHours() === 4 && now.getUTCMinutes() === 0);
  if (weekly && o.gateway?.mode !== 'off') {
    out.orphans = (await checkProjectEnterprises(o.gateway)).length;
  }
  return out;
}
