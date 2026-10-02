// The hourly cap of destructive actions (docs: audit-durci §10.6): the
// family device_destruction only (MVP). Targets engaged: target_count of the
// actions scheduled, executing, done or partial of the family whose
// COALESCE(executed_at, execute_after) falls within [now − 60 min,
// now + 60 min]. Read in the tenant's database context.
import type { Knex } from 'knex';
import type { GuardQuota } from '@obligarth/shared';
import { db } from '../db';
import { fleetSizeOf } from './catalog';
import { hourlyCap } from './policy';
import { readSettings } from './settings';

export const CAPPED_FAMILY = 'device_destruction';
const COUNTED_STATES = ['scheduled', 'executing', 'done', 'partial'];

/** The size of the tenant's active fleet (0 without a provider). */
export async function fleetSize(tenantId: number): Promise<number> {
  const provider = fleetSizeOf();
  if (!provider) return 0;
  const n = Number(await provider(tenantId));
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

/** The quota of the tenant now; `excludeUuid`: an action counted in `used`
 *  that is being re-checked itself (its own targets are added by the caller). */
export async function quotaOf(tenantId: number, o: { trx?: Knex.Transaction; excludeUuid?: string } = {}): Promise<GuardQuota> {
  const q = o.trx ?? db;
  const settings = await readSettings(tenantId, o.trx);
  const cap = hourlyCap(await fleetSize(tenantId), settings.hourly_cap_percent, settings.hourly_cap_min);
  const params: Array<string | number | string[]> = [tenantId, CAPPED_FAMILY, COUNTED_STATES];
  let exclude = '';
  if (o.excludeUuid) { exclude = ' AND a.uuid <> ?'; params.push(o.excludeUuid); }
  const res = await q.raw(
    `SELECT COALESCE(sum(a.target_count), 0)::integer AS used,
            min(COALESCE(a.executed_at, a.execute_after)) AS oldest
       FROM pending_actions a
      WHERE a.tenant_id = ? AND a.family = ? AND a.state = ANY (?::text[])
        AND COALESCE(a.executed_at, a.execute_after) BETWEEN now() - interval '60 minutes' AND now() + interval '60 minutes'${exclude}`,
    params,
  ) as { rows: Array<{ used: number; oldest: Date | string | null }> };
  const used = Number(res.rows[0]?.used ?? 0);
  const oldest = res.rows[0]?.oldest ? new Date(res.rows[0].oldest) : null;
  // The oldest action counted leaves the window 60 minutes after its instant.
  const resetsAt = oldest ? new Date(oldest.getTime() + 60 * 60_000).toISOString() : null;
  return { cap, used, remaining: Math.max(0, cap - used), resetsAt };
}
