import type { Knex } from 'knex';
import { requestEndUserResolution } from '../policies/triggers';

// =============================================================================
// Retention rules of the data model (docs: modele-donnees-mdm §5.5, EX-17,
// DM19), handed to the generic retention (CNF-04: jobs privacy.retention-all
// and privacy.retention-tenant, modules/privacy.ts), tenant by tenant, in
// slices (motif M8). Each rule purges at most `limit` rows of one tenant per
// call, in the caller's transaction and the tenant's context, and returns how
// many it removed (the caller loops while a slice is full).
//   - end_users.departed: an end user departed for 90 days (the device ↔
//     employee link becomes NULL, composite keys ON DELETE SET NULL; the
//     devices that lose their end user are resolved again: the variables
//     {{user.…}} of their policies no longer have a value, §7.12);
//   - device_status_history: 90 days;
//   - lost_mode_locations: purge_at (62 days at most, by constraint).
// The record of a device past its retention_until is NOT one of these rules:
// a record is deleted only after its enrollments were purged at apple-edge
// (integration §13.3), which no generic caller can do. The retention job
// lists the records due (devicesDueForPurge), purges each one at apple-edge
// (apple/retention.ts, purgeDeviceInEdge) outside any transaction, then
// deletes the purged ones (deleteDueDeviceRecords); a failure postpones the
// record to the next run. The commands of the queue and the other tables of
// the integration: apple/retention.ts.
// =============================================================================

export interface MdmRetentionRule {
  name: string;
  description: string;
  /** Purges at most `limit` rows of `tenantId` that are due at `now`; returns the number removed. */
  purge(trx: Knex.Transaction, tenantId: number, now: Date, limit: number): Promise<number>;
}

/** Days the device ↔ employee link of a departed end user is kept (conception §10.4). */
export const DEPARTED_END_USER_DAYS = 90;
/** Days of the DDM status history (integration §4.9). */
export const STATUS_HISTORY_DAYS = 90;
/** Days a lost-mode position is kept, Apple and Android alike (lost_mode_locations_purge_cap allows 62). */
export const LOST_MODE_LOCATION_DAYS = 30;

const days = (n: number) => n * 86_400_000;

/** The records due for purge (out of management, retention_until passed), by id, after `afterId`: the
 *  caller purges them with the purger of their channel before deleteDueDeviceRecords. `afterId` is the last id
 *  of the previous slice of the same run: a record the caller postponed is not listed again before the next run.
 *  `channel`: the records of that management channel only. */
export async function devicesDueForPurge(trx: Knex | Knex.Transaction, tenantId: number, now: Date, limit: number,
  afterId = 0, channel?: string): Promise<number[]> {
  const q = trx('devices').where({ tenant_id: tenantId, enrollment_state: 'unenrolled' })
    .whereNotNull('retention_until').where('retention_until', '<=', now)
    .where('id', '>', afterId);
  if (channel !== undefined) q.where('management_channel', channel);
  return (await q.orderBy('id', 'asc').limit(limit).pluck('id') as number[]).map(Number);
}

/** The management channels of the records due for purge (privacy.retention-tenant runs the purger of each). */
export async function channelsDueForPurge(trx: Knex | Knex.Transaction, tenantId: number, now: Date): Promise<string[]> {
  return (await trx('devices').where({ tenant_id: tenantId, enrollment_state: 'unenrolled' })
    .whereNotNull('retention_until').where('retention_until', '<=', now)
    .distinct('management_channel').pluck('management_channel') as string[]).map(String).sort();
}

/** Deletes those of `ids` that are still due at `now` (same predicate as devicesDueForPurge: a record that
 *  came back under management meanwhile is left alone). PRECONDITION: the caller purged every enrollment of
 *  each record at apple-edge (integration §13.3); never call it with a record that was not. Cascades to the
 *  satellite, episodes, inventory, statuses, effective state and artifacts. Returns the number deleted. */
export async function deleteDueDeviceRecords(trx: Knex.Transaction, tenantId: number, now: Date, ids: readonly number[]): Promise<number> {
  if (ids.length === 0) return 0;
  return trx('devices').where({ tenant_id: tenantId, enrollment_state: 'unenrolled' })
    .whereNotNull('retention_until').where('retention_until', '<=', now)
    .whereIn('id', ids).del();
}

export const mdmRetentionRules: readonly MdmRetentionRule[] = Object.freeze([
  {
    name: 'end_users.departed',
    description: `End users departed for ${DEPARTED_END_USER_DAYS} days`,
    async purge(trx, tenantId, now, limit) {
      const cutoff = new Date(now.getTime() - days(DEPARTED_END_USER_DAYS));
      const ids = await trx('end_users').where({ tenant_id: tenantId, status: 'departed' }).where('departed_at', '<=', cutoff)
        .orderBy('departed_at', 'asc').limit(limit).pluck('id') as number[];
      if (!ids.length) return 0;
      // Before the link goes: the devices of these end users, resolved again by a job of this transaction.
      await requestEndUserResolution(trx, tenantId, ids.map(Number));
      return trx('end_users').where({ tenant_id: tenantId }).whereIn('id', ids).del();
    },
  },
  {
    name: 'device_status_history',
    description: `DDM status history older than ${STATUS_HISTORY_DAYS} days`,
    async purge(trx, tenantId, now, limit) {
      const cutoff = new Date(now.getTime() - days(STATUS_HISTORY_DAYS));
      const ids = await trx('device_status_history').where({ tenant_id: tenantId }).where('observed_at', '<', cutoff)
        .orderBy('observed_at', 'asc').limit(limit).pluck('id') as string[];
      return ids.length ? trx('device_status_history').where({ tenant_id: tenantId }).whereIn('id', ids).del() : 0;
    },
  },
  {
    name: 'lost_mode_locations',
    description: 'Locations of the lost mode past their purge date',
    async purge(trx, tenantId, now, limit) {
      const ids = await trx('lost_mode_locations').where({ tenant_id: tenantId }).where('purge_at', '<=', now)
        .orderBy('purge_at', 'asc').limit(limit).pluck('id') as string[];
      return ids.length ? trx('lost_mode_locations').where({ tenant_id: tenantId }).whereIn('id', ids).del() : 0;
    },
  },
]);
