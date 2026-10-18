// Exit of an Android device from management (lot AN-H1; android-amapi §13.1, §22.5, AN36): the satellite released with
// the precise Android reason (android_devices.release_reason has no closed list), the record of devices unenrolled with
// the core reason, its enrollment episode closed, its open presumed-gone mark ended. The core CHECKs
// (devices_unenroll_reason_check, device_enrollments_end_reason_check) do not know missing_in_provider nor
// presumed_gone before their widening, part 3b of the migrations, written on the final CHECKs of lot C at the junction
// AN-A2/AN-C1 (an existing table): until then coreUnenrollReason() maps them on the closest existing reason
// (disabled_in_edge, which section 13.1 proposes to rename missing_in_provider). The junction replaces the mapping by
// the identity once 3b is applied.
import type { Knex } from 'knex';
import type { AndroidReleaseReason } from '@obligarth/shared/dist/android/operations.js';

/** Core reasons known by the CHECKs of main (devices and device_enrollments). */
type CoreReason = 'superseded' | 'removed_by_command' | 'disabled_in_edge' | 'retired';

let widened = false;
/** Junction AN-A2/AN-C1 (part 3b applied): the core CHECKs know missing_in_provider and presumed_gone. */
export function setCoreReasonsWidened(v: boolean): void { widened = v; }

/** The reason written in devices.unenroll_reason and device_enrollments.end_reason for an Android release reason. */
export function coreUnenrollReason(r: AndroidReleaseReason): string {
  if (widened && (r === 'missing_in_provider' || r === 'presumed_gone')) return r;
  const map: Record<AndroidReleaseReason, CoreReason> = {
    superseded: 'superseded',
    removed_by_command: 'removed_by_command',
    missing_in_provider: 'disabled_in_edge',
    presumed_gone: 'disabled_in_edge',
    forgotten: 'retired',
    offboarding: 'retired',
  };
  return map[r];
}

/**
 * Takes a device out of management in `trx` (tenant context of the caller). Idempotent: a device already released
 * changes nothing (false). The caller audits and deletes the AMAPI resource or the policy as its rule says.
 */
export async function exitManagement(trx: Knex.Transaction, tenantId: number, deviceId: number, reason: AndroidReleaseReason): Promise<boolean> {
  const now = new Date();
  const n = await trx('android_devices').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('released_at')
    .update({ released_at: now, release_reason: reason, updated_at: now });
  if (!n) return false;
  const core = coreUnenrollReason(reason);
  await trx('devices').where({ tenant_id: tenantId, id: deviceId }).whereNot('enrollment_state', 'unenrolled').update({
    enrollment_state: 'unenrolled', enrollment_state_at: now, unenrolled_at: now, unenroll_reason: core, updated_at: now,
  });
  await trx('device_enrollments').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('ended_at')
    .update({ ended_at: now, end_reason: core });
  await trx('android_presumed_gone').where({ tenant_id: tenantId, device_id: deviceId, state: 'open' })
    .update({ state: reason === 'presumed_gone' || reason === 'forgotten' ? 'forgotten' : 'cleared', ended_at: now });
  return true;
}
