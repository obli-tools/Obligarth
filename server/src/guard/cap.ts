// The hourly cap of destructive actions (docs: audit-durci §10.6): the
// family device_destruction only (MVP). Targets engaged: target_count of the
// actions scheduled, executing, done or partial of the family whose
// COALESCE(executed_at, execute_after) falls within [now − 60 min,
// now + 60 min]. Read in the tenant's database context.
// An action of one channel (legacy_agent, the Android-only keys: decision of
// the owners of 20/10/2026, PONT-R-RV3) also has a cap of its channel: the
// tenant's percent and minimum on the channel's fleet, the targets engaged
// being the devices of that channel among those of the counted actions.
import type { Knex } from 'knex';
import type { GuardQuota } from '@obligarth/shared';
import { db } from '../db';
import { fleetSizeOf, guardedActionList } from './catalog';
import { capAllows, hourlyCap } from './policy';
import { readSettings } from './settings';
import type { GuardedActionDef, ManagementChannel } from './types';

export const CAPPED_FAMILY = 'device_destruction';
const COUNTED_STATES = ['scheduled', 'executing', 'done', 'partial'];

/** The size of the tenant's active fleet, or of its devices of one channel (0 without a provider). */
export async function fleetSize(tenantId: number, channel?: ManagementChannel): Promise<number> {
  const provider = fleetSizeOf();
  if (!provider) return 0;
  const n = Number(await (channel ? provider(tenantId, channel) : provider(tenantId)));
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

/** The quota of the tenant now, or of its devices of one channel (`channel`); `excludeUuid`: an action counted in
 *  `used` that is being re-checked itself (its own targets are added by the caller). */
export async function quotaOf(tenantId: number, o: { trx?: Knex.Transaction; excludeUuid?: string; channel?: ManagementChannel } = {}): Promise<GuardQuota> {
  const q = o.trx ?? db;
  const settings = await readSettings(tenantId, o.trx);
  const cap = hourlyCap(await fleetSize(tenantId, o.channel), settings.hourly_cap_percent, settings.hourly_cap_min);
  const params: Array<string | number | string[]> = [tenantId, CAPPED_FAMILY, COUNTED_STATES];
  let exclude = '';
  if (o.excludeUuid) { exclude = ' AND a.uuid <> ?'; params.push(o.excludeUuid); }
  // A channel: its devices among the targets of the counted actions (whatever their key, a shared one included). A
  // target whose record is gone since (device.delete after an erase: review of lot D-2010) still counts, for every
  // channel its action acts on: the deletion of records never gives back room in a channel's cap.
  const res = await (o.channel
    ? q.raw(
      `SELECT count(*)::integer AS used,
              min(COALESCE(a.executed_at, a.execute_after)) AS oldest
         FROM pending_actions a
        CROSS JOIN LATERAL unnest(a.target_device_ids) AS t(device_id)
         LEFT JOIN devices d ON d.tenant_id = a.tenant_id AND d.id = t.device_id
        WHERE a.tenant_id = ? AND a.family = ? AND a.state = ANY (?::text[])
          AND COALESCE(a.executed_at, a.execute_after) BETWEEN now() - interval '60 minutes' AND now() + interval '60 minutes'${exclude}
          AND (d.management_channel = ? OR (d.id IS NULL AND a.action_key = ANY (?::text[])))`,
      [...params, o.channel, keysOfChannel(o.channel)],
    )
    : q.raw(
      `SELECT COALESCE(sum(a.target_count), 0)::integer AS used,
              min(COALESCE(a.executed_at, a.execute_after)) AS oldest
         FROM pending_actions a
        WHERE a.tenant_id = ? AND a.family = ? AND a.state = ANY (?::text[])
          AND COALESCE(a.executed_at, a.execute_after) BETWEEN now() - interval '60 minutes' AND now() + interval '60 minutes'${exclude}`,
      params,
    )
  ) as { rows: Array<{ used: number; oldest: Date | string | null }> };
  const used = Number(res.rows[0]?.used ?? 0);
  const oldest = res.rows[0]?.oldest ? new Date(res.rows[0].oldest) : null;
  // The oldest action counted leaves the window 60 minutes after its instant.
  const resetsAt = oldest ? new Date(oldest.getTime() + 60 * 60_000).toISOString() : null;
  return { cap, used, remaining: Math.max(0, cap - used), resetsAt };
}

/** The keys of the guarded actions that act on a channel (declared channels, or every one when none is declared). */
function keysOfChannel(channel: ManagementChannel): string[] {
  return guardedActionList().filter((d) => !d.channels || d.channels.includes(channel)).map((d) => d.key);
}

/** The one channel of an action of one channel only (PONT-R-RV3), or null (several channels, or every one). */
export function ownChannelOf(def: Pick<GuardedActionDef<any>, 'channels'>): ManagementChannel | null {
  return def.channels && def.channels.length === 1 ? def.channels[0] : null;
}

/** The quota an action of the capped family would exceed with `count` more targets: the tenant's, then for an
 *  action of one channel that channel's; null when both allow it (or the action has no cap). */
export async function capExceeded(def: Pick<GuardedActionDef<any>, 'hourlyCap' | 'channels'>, tenantId: number, count: number,
  o: { trx?: Knex.Transaction; excludeUuid?: string } = {}): Promise<{ quota: GuardQuota; channel: ManagementChannel | null } | null> {
  if (!def.hourlyCap) return null;
  const quota = await quotaOf(tenantId, o);
  if (!capAllows(quota.cap, quota.used, count)) return { quota, channel: null };
  const channel = ownChannelOf(def);
  if (!channel) return null;
  const own = await quotaOf(tenantId, { ...o, channel });
  return capAllows(own.cap, own.used, count) ? null : { quota: own, channel };
}
