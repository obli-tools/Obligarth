import type { Knex } from 'knex';
import { PUBLISH_APPROVAL_THRESHOLDS } from '@obligarth/shared';

// =============================================================================
// What the changes of the configuration written without a second approver
// touched, per tenant, over the last hour (docs: modele-donnees-mdm §7.12,
// DM23; review of lot B5b, MDM-B5b-C7; decision of the owners of 15/10/2026).
// The thresholds of DM23 were evaluated change by change: 60 devices assigned
// in 7 batches of 9, each one below them, a second factor each. They now bear
// on the devices this change touches together with those of the changes of the
// window (distinct devices, the removals apart): beyond them, the change asks
// a second approver (reason 'cumulative'). A change approved by a second
// administrator is not counted: it was looked at. Written under the lock of the
// tenant's configuration, in the transaction of the change; the rows older
// than the window are deleted there.
// =============================================================================

const WINDOW_MINUTES = PUBLISH_APPROVAL_THRESHOLDS.cumulativeWindowMinutes;

/** Devices kept per row (a direct change stays below 25 touched devices; a bound for the others). */
const MAX_IDS = 1000;

/** The kinds of change (mdm_change_ledger_kind_check; the governed changes of the dynamic groups: P0-5 T7). */
export type LedgerKind = 'version' | 'assignments' | 'group_move' | 'group_delete' | 'device_move'
  | 'smart_group_rule' | 'smart_group_delete' | 'smart_group_release' | 'device_facts';

export interface RecentChanges {
  devices: Set<number>;
  removals: Set<number>;
}

/** The devices touched (and those with a removal) by the direct changes of the tenant within the window. */
export async function recentlyTouched(q: Knex | Knex.Transaction, tenantId: number): Promise<RecentChanges> {
  const rows = await q('mdm_change_ledger').where({ tenant_id: tenantId })
    .whereRaw('recorded_at > now() - make_interval(mins => ?)', [WINDOW_MINUTES])
    .select('device_ids', 'removal_device_ids') as Array<{ device_ids: number[] | null; removal_device_ids: number[] | null }>;
  const out: RecentChanges = { devices: new Set(), removals: new Set() };
  for (const r of rows) {
    for (const d of r.device_ids ?? []) out.devices.add(Number(d));
    for (const d of r.removal_device_ids ?? []) out.removals.add(Number(d));
  }
  return out;
}

/** A change written without a second approver, in `trx` (which holds the lock of the tenant's configuration). */
export async function recordDirectChange(trx: Knex.Transaction, tenantId: number, kind: LedgerKind,
  touched: { deviceIds: number[]; removalDeviceIds: number[] }): Promise<void> {
  await trx('mdm_change_ledger').where({ tenant_id: tenantId })
    .whereRaw('recorded_at <= now() - make_interval(mins => ?)', [WINDOW_MINUTES]).del();
  if (!touched.deviceIds.length && !touched.removalDeviceIds.length) return;
  await trx('mdm_change_ledger').insert({
    tenant_id: tenantId, kind,
    device_ids: [...new Set(touched.deviceIds)].slice(0, MAX_IDS),
    removal_device_ids: [...new Set(touched.removalDeviceIds)].slice(0, MAX_IDS),
  });
}
