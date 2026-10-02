import type { Knex } from 'knex';

// =============================================================================
// Retention rules of the data model (docs: modele-donnees-mdm §5.5, EX-17,
// DM19), handed to the generic retention of the privacy specification (CNF-04:
// files privacy.retention-all and privacy.retention-tenant, tenant by tenant,
// in slices: motif M8). Each rule purges at most `limit` rows of one tenant
// per call, in the caller's transaction and the tenant's context, and returns
// how many it removed (the caller loops until 0).
//   - devices.records: a record past its retention_until; the caller purges
//     its enrollments at apple-edge first (appleDevices.purgeInEdge,
//     integration §13.3), outside any transaction, and postpones the deletion
//     when that fails; deleting the record cascades to its satellite,
//     episodes, inventory, statuses, effective state and artifacts;
//   - end_users.departed: an end user departed for 90 days (the device ↔
//     employee link becomes NULL, composite keys ON DELETE SET NULL);
//   - device_status_history: 90 days;
//   - lost_mode_locations: purge_at (62 days at most, by constraint).
// The commands keep the queue's retention (6 months, integration §4.9); DM19
// proposes 30 days for the origin 'inventory', left to CNF-04.
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

const days = (n: number) => n * 86_400_000;

/** The records due for purge (retention_until passed, out of management), oldest first: the caller purges
 *  them at apple-edge before mdmRetentionRules' devices.records deletes them. */
export async function devicesDueForPurge(trx: Knex | Knex.Transaction, tenantId: number, now: Date, limit: number): Promise<number[]> {
  return (await trx('devices').where({ tenant_id: tenantId, enrollment_state: 'unenrolled' })
    .whereNotNull('retention_until').where('retention_until', '<=', now)
    .orderBy('retention_until', 'asc').limit(limit).pluck('id') as number[]).map(Number);
}

export const mdmRetentionRules: readonly MdmRetentionRule[] = Object.freeze([
  {
    name: 'devices.records',
    description: 'Records of devices out of management past their retention (after the purge at apple-edge)',
    async purge(trx, tenantId, now, limit) {
      const ids = await devicesDueForPurge(trx, tenantId, now, limit);
      if (ids.length === 0) return 0;
      return trx('devices').where({ tenant_id: tenantId, enrollment_state: 'unenrolled' }).whereIn('id', ids).del();
    },
  },
  {
    name: 'end_users.departed',
    description: `End users departed for ${DEPARTED_END_USER_DAYS} days`,
    async purge(trx, tenantId, now, limit) {
      const cutoff = new Date(now.getTime() - days(DEPARTED_END_USER_DAYS));
      const ids = await trx('end_users').where({ tenant_id: tenantId, status: 'departed' }).where('departed_at', '<=', cutoff)
        .orderBy('departed_at', 'asc').limit(limit).pluck('id') as number[];
      return ids.length ? trx('end_users').where({ tenant_id: tenantId }).whereIn('id', ids).del() : 0;
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
