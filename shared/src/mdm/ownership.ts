// =============================================================================
// The ownership of a device locks its management mode (docs: modele-donnees-mdm
// §4.3, DM4; conception §3.2, REQ-01). Mirror of the SQL function
// obligarth.ownership_allows (migration mdm_model_expand), which the CHECK
// devices_ownership_mode_check applies: both change together (the testbed
// compares the two truth tables).
// =============================================================================
import type { EnrollmentClass, EnrollmentMethod, ManagementMode, Ownership } from './enums';

const isAndroidMethod = (m: string): boolean => m.startsWith('android_');

/**
 * May a device of `ownership`, enrolled by `method`, be managed in `mode`? Unknown values (and null) are
 * never allowed. Personal: User Enrollment by account only (or an Android personal work profile);
 * corporate-personal (COPE): device mode by ADE, Apple Configurator or migration only, never OTA;
 * corporate: device mode by any Apple method, or the Android fully managed and dedicated modes.
 */
export function ownershipAllows(ownership: Ownership | string | null | undefined,
  method: EnrollmentMethod | string | null | undefined, mode: ManagementMode | string | null | undefined): boolean {
  if (typeof ownership !== 'string' || typeof method !== 'string' || typeof mode !== 'string') return false;
  switch (ownership) {
    case 'personal':
      return (mode === 'user_enrollment' && method === 'byod_account')
        || (mode === 'work_profile_personal' && isAndroidMethod(method));
    case 'corporate_personal':
      return (mode === 'device' && ['ade', 'configurator', 'migration'].includes(method))
        || (mode === 'work_profile_corporate' && isAndroidMethod(method));
    case 'corporate':
      return (mode === 'device' && ['ade', 'configurator', 'ota', 'account_device', 'migration'].includes(method))
        || (['fully_managed', 'dedicated'].includes(mode) && isAndroidMethod(method));
    default:
      return false;
  }
}

/** The Apple enrollment methods an ownership allows (in the order of the profiles' forms). */
export function allowedMethods(ownership: Ownership): EnrollmentMethod[] {
  switch (ownership) {
    case 'personal': return ['byod_account'];
    case 'corporate_personal': return ['ade', 'configurator', 'migration'];
    case 'corporate': return ['ade', 'ota', 'configurator', 'account_device', 'migration'];
    default: return [];
  }
}

/** The Apple management mode of a NanoMDM enrollment type ('Device' → device, 'User Enrollment (Device)' →
 *  user_enrollment); null for any other channel (user channels, Shared iPad: v1). */
export function appleModeOfNanoType(nanoType: string | null | undefined): ManagementMode | null {
  if (nanoType === 'Device') return 'device';
  if (nanoType === 'User Enrollment (Device)') return 'user_enrollment';
  return null;
}

/** Enrollment class of the availability of a setting (§4.2): supervised device, unsupervised device, user. */
export function enrollmentClassOf(mode: ManagementMode | string, supervised: boolean): EnrollmentClass {
  if (mode === 'user_enrollment') return 'user';
  return supervised ? 'supervised' : 'device';
}

/** Methods that supervise the device from the start (ADE, Apple Configurator, migration). */
export function methodSupervises(method: EnrollmentMethod | string): boolean {
  return method === 'ade' || method === 'configurator' || method === 'migration';
}
