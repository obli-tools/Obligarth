import type { Knex } from 'knex';
import type { Ownership } from '@obligarth/shared';
import { unenrolledRetentionDays } from '../../privacy/retention';

// =============================================================================
// After a device left management (docs: modele-donnees-mdm §5.5, §10.4: the
// writes of the integration's job devices.unenroll-cleanup): the date the
// record is purged, its effective state and its artifacts deleted, its
// configuration and compliance states back to 'unknown'. The record itself,
// its satellite, its episodes and its inventory stay until retention_until;
// the retention purges them after the purge at apple-edge (§5.5, integration
// §13.3). In the caller's transaction and the tenant's context.
// =============================================================================

/** Bounds of the retention after a departure from management (conception §10.4; the ranges of the categories
 *  unenrolled_*_days of RETENTION_CATEGORIES, checked again here). */
export const RETENTION_DAYS_MIN = 30;
export const RETENTION_DAYS_MAX = 365;

/**
 * The cleanup of a device out of management: retention_until = unenrolled_at + the days of the tenant's retention
 * category of its ownership (P0-13 T4, CNF-04: unenrolled_corporate_days, unenrolled_corporate_personal_days,
 * unenrolled_personal_days; 30 to 365, the defaults 90, 90 and 30 of before). null when the device is not in the tenant or still under
 * management (nothing written).
 */
export async function unenrollCleanup(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<{ retentionUntil: Date } | null> {
  const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).forUpdate()
    .first('enrollment_state', 'unenrolled_at', 'ownership') as
    { enrollment_state: string; unenrolled_at: Date | null; ownership: Ownership } | undefined;
  if (!d || d.enrollment_state !== 'unenrolled' || !d.unenrolled_at) return null;
  const kept = await unenrolledRetentionDays(trx, tenantId, d.ownership);
  const days = Math.min(RETENTION_DAYS_MAX, Math.max(RETENTION_DAYS_MIN, Math.floor(kept)));
  await trx('device_effective_settings').where({ tenant_id: tenantId, device_id: deviceId }).del();
  await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId }).del();
  // In SQL (days of 24 hours, the microseconds of unenrolled_at kept): the same date realignRetentionDates
  // (mdm/inventory/retention.ts) computes when the tenant's retention changes.
  const [row] = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update({
    retention_until: trx.raw('unenrolled_at + make_interval(hours => ?)', [days * 24]), config_state: 'unknown',
    compliance_state: 'unknown', compliance_reasons: '[]', compliance_evaluated_at: null, updated_at: new Date(),
  }).returning('retention_until') as Array<{ retention_until: Date }>;
  return { retentionUntil: new Date(row.retention_until) };
}
