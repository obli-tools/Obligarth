import type { Knex } from 'knex';
import type { NanoEnrollType, Ownership } from '@obligarth/shared';
import { privacyRulesFor } from '../../apple/devices/privacy';

// =============================================================================
// After a device left management (docs: modele-donnees-mdm §5.5, §10.4: the
// writes of the integration's job devices.unenroll-cleanup): the date the
// record is purged, its effective state and its artifacts deleted, its
// configuration and compliance states back to 'unknown'. The record itself,
// its satellite, its episodes and its inventory stay until retention_until;
// the retention purges them after the purge at apple-edge (§5.5, integration
// §13.3). In the caller's transaction and the tenant's context.
// =============================================================================

/** Bounds of the retention after a departure from management (conception §10.4). */
export const RETENTION_DAYS_MIN = 30;
export const RETENTION_DAYS_MAX = 365;

/**
 * The cleanup of a device out of management: retention_until = unenrolled_at + the retention days of the
 * privacy rules of its ownership (30 to 365). null when the device is not in the tenant or still under
 * management (nothing written).
 */
export async function unenrollCleanup(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<{ retentionUntil: Date } | null> {
  const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).forUpdate()
    .first('enrollment_state', 'unenrolled_at', 'ownership', 'management_mode') as
    { enrollment_state: string; unenrolled_at: Date | null; ownership: Ownership; management_mode: string } | undefined;
  if (!d || d.enrollment_state !== 'unenrolled' || !d.unenrolled_at) return null;
  const type: NanoEnrollType = d.management_mode === 'user_enrollment' ? 'User Enrollment (Device)' : 'Device';
  const rules = await privacyRulesFor(trx, tenantId, d.ownership, type);
  const days = Math.min(RETENTION_DAYS_MAX, Math.max(RETENTION_DAYS_MIN, Math.floor(rules.retentionDaysAfterUnenroll)));
  const retentionUntil = new Date(new Date(d.unenrolled_at).getTime() + days * 86_400_000);
  await trx('device_effective_settings').where({ tenant_id: tenantId, device_id: deviceId }).del();
  await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId }).del();
  await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update({
    retention_until: retentionUntil, config_state: 'unknown', compliance_state: 'unknown', compliance_reasons: '[]',
    compliance_evaluated_at: null, updated_at: new Date(),
  });
  return { retentionUntil };
}
