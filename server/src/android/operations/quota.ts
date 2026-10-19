// Quota of the project (lot AN-H1; android-amapi §13.3, §22.5, AN49): the quota Google grants a project is shared by
// every tenant of the instance.
//   - Hourly (android.maintenance): android_project_device_count() (all tenants, a number only) against
//     androidProjectDeviceQuota (platform setting: setProjectQuotaReader at the junction AN-A2, shared/src/settings
//     being an existing file); platform alerts android.quota_warning at 80 % and android.quota_exhausted at 100 %,
//     resolved below the thresholds. A long token already issued can still enroll: the instance counts and alerts.
//   - Weekly (Monday, android.maintenance): the recount. The reconciliation of each tenant records the devices Google
//     lists, without those silent for more than 270 days (AMAPI-R3); android_quota_census() sums them for the linked
//     tenants counted within 8 days; the gap with the instance's own count is kept in android_quota_recounts and shown
//     on « Platform > Android » (readQuotaView).
// Context 'none' of the maintenance; counts only, never a tenant datum.
import { ANDROID_QUOTA_WARNING_PERCENT, type AndroidQuotaView } from '@obligarth/shared';
import { db } from '../../db';
import { asNone } from '../../db/context';
import { raiseAndroidPlatformAlert, resolveAndroidPlatformAlert } from '../alerts';
import { MAINTENANCE_ACTOR } from '../enterprises/orphans';

let readQuota: () => Promise<number | null> = async () => null;
/** androidProjectDeviceQuota (platform setting, junction AN-A2); null: no quota known, nothing alerted. */
export function setProjectQuotaReader(fn: () => Promise<number | null>): void { readQuota = fn; }

export type QuotaLevel = 'none' | 'ok' | 'warning' | 'exhausted';

/** The level of a count against a quota. Pure (unit tests). */
export function quotaLevel(count: number, quota: number | null): QuotaLevel {
  if (quota === null || !Number.isFinite(quota) || quota < 0) return 'none';
  if (count >= quota) return 'exhausted';
  if (count * 100 >= quota * ANDROID_QUOTA_WARNING_PERCENT) return 'warning';
  return 'ok';
}

/** The hourly check: alerts raised or resolved. */
export async function checkProjectQuota(): Promise<{ count: number; quota: number | null; level: QuotaLevel }> {
  const quota = await readQuota();
  const count = await asNone(MAINTENANCE_ACTOR, async () => {
    const r = await db.raw('SELECT obligarth.android_project_device_count() AS n') as { rows: Array<{ n: number }> };
    return Number(r.rows[0]?.n ?? 0);
  });
  const level = quotaLevel(count, quota);
  if (level === 'exhausted') await raiseAndroidPlatformAlert('android.quota_exhausted', { count, quota: Number(quota) }, 'project');
  else await resolveAndroidPlatformAlert('android.quota_exhausted', 'project');
  if (level === 'warning') await raiseAndroidPlatformAlert('android.quota_warning', { count, quota: Number(quota) }, 'project');
  else if (level !== 'exhausted') await resolveAndroidPlatformAlert('android.quota_warning', 'project');
  return { count, quota, level };
}

export interface QuotaRecount { instanceCount: number; googleCount: number; staleExcluded: number; gap: number; tenantsLinked: number; tenantsCounted: number }

/** The weekly recount (AN49): one row of android_quota_recounts; rows older than 400 days purged. */
export async function recountQuota(): Promise<QuotaRecount> {
  return asNone(MAINTENANCE_ACTOR, async () => {
    const r = await db.raw('SELECT instance_count, google_count, stale_excluded, tenants_linked, tenants_counted FROM obligarth.android_quota_census()') as
      { rows: Array<{ instance_count: number; google_count: number; stale_excluded: number; tenants_linked: number; tenants_counted: number }> };
    const c = r.rows[0];
    const out: QuotaRecount = {
      instanceCount: Number(c.instance_count), googleCount: Number(c.google_count), staleExcluded: Number(c.stale_excluded),
      gap: Number(c.google_count) - Number(c.instance_count), tenantsLinked: Number(c.tenants_linked), tenantsCounted: Number(c.tenants_counted),
    };
    await db('android_quota_recounts').insert({
      instance_count: out.instanceCount, google_count: out.googleCount, stale_excluded: out.staleExcluded, gap: out.gap,
      tenants_linked: out.tenantsLinked, tenants_counted: out.tenantsCounted,
    });
    await db('android_quota_recounts').where('counted_at', '<', db.raw("now() - interval '400 days'")).delete();
    return out;
  });
}

/** The quota view of « Platform > Android » (platform administrator of the master tenant; counts only). */
export async function readQuotaView(): Promise<AndroidQuotaView> {
  const quota = await readQuota();
  return asNone(MAINTENANCE_ACTOR, async () => {
    const r = await db.raw('SELECT obligarth.android_project_device_count() AS n') as { rows: Array<{ n: number }> };
    const count = Number(r.rows[0]?.n ?? 0);
    const last = await db('android_quota_recounts').orderBy('id', 'desc').first() as Record<string, any> | undefined;
    return {
      quota, count, percent: quota ? Math.round((count * 1000) / quota) / 10 : null,
      lastRecount: last ? {
        at: new Date(last.counted_at).toISOString(), instanceCount: Number(last.instance_count), googleCount: Number(last.google_count),
        staleExcluded: Number(last.stale_excluded), gap: Number(last.gap), tenantsCounted: Number(last.tenants_counted), tenantsLinked: Number(last.tenants_linked),
      } : null,
    };
  });
}
