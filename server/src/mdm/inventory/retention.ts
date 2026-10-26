import type { Knex } from 'knex';
import { requestEndUserResolution } from '../policies/triggers';
import { OWNERSHIPS } from '@obligarth/shared';
import { retentionCutoff, retentionDays, unenrolledRetentionDays } from '../../privacy/retention';
import { ICON_FAILED_DAYS } from './pngIcon';

// =============================================================================
// Retention rules of the data model (docs: modele-donnees-mdm §5.5, EX-17,
// DM19), handed to the generic retention (CNF-04: jobs privacy.retention-all
// and privacy.retention-tenant, modules/privacy.ts), tenant by tenant, in
// slices (motif M8). Each rule purges at most `limit` rows of one tenant per
// call, in the caller's transaction and the tenant's context, and returns how
// many it removed (the caller loops while a slice is full). The durations are
// the tenant's categories (P0-13 T4, CNF-04: privacy/retention.ts, read at
// each slice; the defaults of RETENTION_CATEGORIES when it set none):
//   - end_users.departed: an end user departed for departed_end_user_days (90
//     by default; the device ↔ employee link becomes NULL, composite keys ON
//     DELETE SET NULL; the devices that lose their end user are resolved
//     again: the variables {{user.…}} of their policies no longer have a
//     value, §7.12);
//   - device_status_history: status_history_days (90 by default);
//   - lost_mode_locations: past their purge_at (62 days at most, by
//     constraint), or observed more than lost_mode_location_days ago (30 by
//     default): a decrease applies to the positions already stored; their
//     purge_at follows a change of lost_mode_location_days, an increase as a
//     decrease (realignLostModePurgeDates, run before the rules);
//   - app_icons: a lease unanswered for 7 days (a failure of a device is
//     kept 30 days: it is not asked again meanwhile); an icon (or its
//     absence) whose app no device of the tenant has, untouched for 90 days.
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

/** Days an icon lease (app_icons 'pending') is kept unanswered; days an icon outlives the last device that had its app
 *  (stored or none, by its updated_at: a device sending it again moves it). */
export const ICON_LEASE_DAYS = 7;
export const ICON_ORPHAN_DAYS = 90;

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

/** One slice of the records out of management whose date of purge no longer follows the tenant's retention of their
 *  ownership (P0-13 T4, CNF-04: unenrolled_*_days changed since their departure; a decrease past its date, an increase
 *  at once): retention_until = unenrolled_at + the days in force, as unenrollCleanup computes it (exact days of 24
 *  hours; a date within a second of it is left alone: those computed in milliseconds before P0-13). At most `limit`
 *  rows of the tenant, in `trx` (its context); returns how many were moved. Run before the records due are listed, so
 *  that every purge uses the value in force. A tenant that never set its retention keeps the dates of its defaults:
 *  nothing to align. */
export async function realignRetentionDates(trx: Knex.Transaction, tenantId: number, limit: number): Promise<number> {
  if (!(await trx('tenant_retention_policies').where({ tenant_id: tenantId }).first('tenant_id'))) return 0;
  let moved = 0;
  for (const ownership of OWNERSHIPS) {
    if (moved >= limit) break;
    const days = Math.min(365, Math.max(30, await unenrolledRetentionDays(trx, tenantId, ownership)));
    const ids = await trx('devices').where({ tenant_id: tenantId, enrollment_state: 'unenrolled', ownership })
      .whereNotNull('unenrolled_at').whereNotNull('retention_until')
      .whereRaw("abs(extract(epoch FROM retention_until - (unenrolled_at + make_interval(hours => ?)))) > 1", [days * 24])
      .orderBy('id', 'asc').limit(limit - moved).pluck('id') as number[];
    if (!ids.length) continue;
    moved += await trx('devices').where({ tenant_id: tenantId, enrollment_state: 'unenrolled', ownership }).whereIn('id', ids)
      .update({ retention_until: trx.raw('unenrolled_at + make_interval(hours => ?)', [days * 24]), updated_at: new Date() });
  }
  return moved;
}

/** One slice of the positions in lost mode whose date of purge no longer follows the tenant's lost_mode_location_days
 *  (P0-13 T4, CNF-04: changed since their reception; an increase at once, a decrease past its date): purge_at =
 *  received_at + the days in force, the expression of lostModePurgeAt at the insertion, so that a position stored before
 *  an increase is kept as long as the value in force says (and the CHECK lost_mode_locations_purge_cap, 62 days at most,
 *  holds: the range of the category). A date within a second of it is left alone (those computed in milliseconds before
 *  P0-13). At most `limit` rows of the tenant, in `trx` (its context); returns how many were moved. Run before the rules
 *  (a position kept by an increase is not purged by its former date). A tenant that never set its retention keeps the
 *  dates of its defaults: nothing to align. */
export async function realignLostModePurgeDates(trx: Knex.Transaction, tenantId: number, limit: number): Promise<number> {
  if (!(await trx('tenant_retention_policies').where({ tenant_id: tenantId }).first('tenant_id'))) return 0;
  const kept = Math.min(62, Math.max(1, await retentionDays(trx, tenantId, 'lost_mode_location_days')));
  const ids = await trx('lost_mode_locations').where({ tenant_id: tenantId })
    .whereRaw('abs(extract(epoch FROM purge_at - (received_at + make_interval(days => ?)))) > 1', [kept])
    .orderBy('id', 'asc').limit(limit).pluck('id') as string[];
  if (!ids.length) return 0;
  return trx('lost_mode_locations').where({ tenant_id: tenantId }).whereIn('id', ids)
    .update({ purge_at: trx.raw('received_at + make_interval(days => ?)', [kept]) });
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
    description: 'End users departed for the days of the tenant (departed_end_user_days)',
    async purge(trx, tenantId, now, limit) {
      const cutoff = await retentionCutoff(trx, tenantId, 'departed_end_user_days', now);
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
    description: 'DDM status history older than the days of the tenant (status_history_days)',
    async purge(trx, tenantId, now, limit) {
      const cutoff = await retentionCutoff(trx, tenantId, 'status_history_days', now);
      const ids = await trx('device_status_history').where({ tenant_id: tenantId }).where('observed_at', '<', cutoff)
        .orderBy('observed_at', 'asc').limit(limit).pluck('id') as string[];
      return ids.length ? trx('device_status_history').where({ tenant_id: tenantId }).whereIn('id', ids).del() : 0;
    },
  },
  {
    name: 'lost_mode_locations',
    description: 'Locations of the lost mode past their purge date, or older than the days of the tenant (lost_mode_location_days)',
    async purge(trx, tenantId, now, limit) {
      const cutoff = await retentionCutoff(trx, tenantId, 'lost_mode_location_days', now);
      const ids = await trx('lost_mode_locations').where({ tenant_id: tenantId })
        .where((w) => w.where('purge_at', '<=', now).orWhere('observed_at', '<', cutoff))
        .orderBy('purge_at', 'asc').limit(limit).pluck('id') as string[];
      return ids.length ? trx('lost_mode_locations').where({ tenant_id: tenantId }).whereIn('id', ids).del() : 0;
    },
  },
  {
    name: 'app_icons',
    description: `App icons: leases unanswered for ${ICON_LEASE_DAYS} days, icons of apps no device of the tenant has had for ${ICON_ORPHAN_DAYS} days`,
    async purge(trx, tenantId, now, limit) {
      const leaseCutoff = new Date(now.getTime() - days(ICON_LEASE_DAYS));
      const orphanCutoff = new Date(now.getTime() - days(ICON_ORPHAN_DAYS));
      const failedCutoff = new Date(now.getTime() - days(ICON_FAILED_DAYS));
      const res = await trx.raw(`
        DELETE FROM app_icons ic USING (
          SELECT c.tenant_id, c.platform_family, c.identifier FROM app_icons c
           WHERE c.tenant_id = :tenantId
             AND ((c.state = 'pending' AND (c.requested_at IS NULL OR c.requested_at < :leaseCutoff)
                   AND (c.failed_at IS NULL OR c.failed_at < :failedCutoff))
               OR (c.state IN ('stored', 'none') AND c.updated_at < :orphanCutoff
                   AND NOT EXISTS (SELECT 1 FROM device_apps da WHERE da.tenant_id = c.tenant_id AND da.identifier = c.identifier)))
           LIMIT :limit) due
         WHERE ic.tenant_id = due.tenant_id AND ic.platform_family = due.platform_family AND ic.identifier = due.identifier`,
      { tenantId, leaseCutoff, orphanCutoff, failedCutoff, limit }) as { rowCount: number | null };
      return Number(res.rowCount ?? 0);
    },
  },
]);
