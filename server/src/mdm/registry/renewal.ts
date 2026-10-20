import type { Knex } from 'knex';

// =============================================================================
// Renewal of a record a new enrollment cycle takes by an unverified serial number (decision MDM-B2-R12, option A,
// 15/10/2026; modele-donnees-mdm §4.5): a device that only announced the serial number of a record out of management
// whose identifier is released takes nothing of that record's configuration: the group of its own profile, no direct
// assignment (policies and apps), lost mode off and no position of the previous cycle. One function for every
// channel: apple_mdm (apple/devices/lifecycle.ts, onAuthenticate) and amapi (android-amapi §10.4 step 6(a), lot AN-C1).
// In the caller's transaction (tenant context); the caller writes the returned columns with its own.
// =============================================================================

export interface RenewedRecord {
  /** Columns of devices the renewal sets (the caller adds them to its update). */
  columns: { group_id: number | null; lost_mode_state: 'off'; lost_mode_changed_at: null };
  /** Direct assignments and positions of the lost mode removed. */
  assignments: number;
  locations: number;
}

export async function renewRecordForNewCycle(trx: Knex.Transaction, tenantId: number, deviceId: number, groupId: number | null): Promise<RenewedRecord> {
  const assignments = await trx('assignments').where({ tenant_id: tenantId, target_scope: 'device', target_id: deviceId }).del();
  const locations = await trx('lost_mode_locations').where({ tenant_id: tenantId, device_id: deviceId }).del();
  return {
    columns: { group_id: groupId, lost_mode_state: 'off', lost_mode_changed_at: null },
    assignments: Number(assignments), locations: Number(locations),
  };
}
