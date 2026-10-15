// =============================================================================
// Availability of an Android setting for a device, shared by the server's
// compilation and by the editor of the console: the first reason that applies,
// in this order:
//   1 schema_unknown               field absent from the current catalog
//   2 platform_unsupported         Android key on an Apple device (and the
//                                  reverse, decided by the Apple side)
//   3 management_mode_unsupported  field without effect in the device's mode
//   4 os_too_old                   API level below the known minimum (detail:
//                                  the minimum)
//   5 ownership_forbidden          product rule on the ownership
//   6 variable_unresolved          variable without a value for the device
//   7 license_unavailable          never under managed Google Play (kept for
//                                  the order shared with Apple)
// An unknown API level (before the first status report) makes nothing
// unavailable for the reason 4, and a field whose minimum is not known never
// is: Google reports API_LEVEL as a non-compliance.
// Imported by direct path until the shared index exports it.
// =============================================================================

export const ANDROID_UNAVAILABLE_REASONS = [
  'schema_unknown', 'platform_unsupported', 'management_mode_unsupported', 'os_too_old', 'ownership_forbidden',
  'variable_unresolved', 'license_unavailable',
] as const;
export type AndroidUnavailableReason = typeof ANDROID_UNAVAILABLE_REASONS[number];

export type AndroidAvailability =
  | { status: 'available' }
  | { status: 'not_applicable'; reason: AndroidUnavailableReason; detail?: string };

/** The Android management modes (the values of devices.mode). */
export const ANDROID_MODES = ['fully_managed', 'dedicated', 'work_profile_corporate', 'work_profile_personal'] as const;
export type AndroidMode = typeof ANDROID_MODES[number];

/** What the catalog and the overlay know of a field (or of an app entry). */
export interface AndroidFieldSupport {
  /** The modes where the field has an effect; absent: every mode. */
  modes?: readonly AndroidMode[];
  /** Minimum API level, for every mode or by mode (the mode's wins). */
  minApi?: number;
  minApiByMode?: Partial<Record<AndroidMode, number>>;
}

export interface AndroidAvailabilityFacts {
  platform: string;
  mode: string;
  ownership: string;
  /** API level of the device; null until reported. */
  apiLevel: number | null;
}

export interface AndroidAvailabilityExtras {
  /** Product rule of the server's overlay for this value and this ownership. */
  ownershipForbidden?: boolean;
  /** A variable of the value without a value for this device (its name). */
  unresolvedVariable?: string | null;
}

const isAndroidMode = (m: string): m is AndroidMode => (ANDROID_MODES as readonly string[]).includes(m);

/** The availability of a field (`support` null: unknown to the catalog) for a device. */
export function availabilityAndroid(support: AndroidFieldSupport | null | undefined, facts: AndroidAvailabilityFacts,
  extras: AndroidAvailabilityExtras = {}): AndroidAvailability {
  if (!support) return { status: 'not_applicable', reason: 'schema_unknown' };
  if (facts.platform !== 'android' || !isAndroidMode(facts.mode)) return { status: 'not_applicable', reason: 'platform_unsupported' };
  if (support.modes && !support.modes.includes(facts.mode)) return { status: 'not_applicable', reason: 'management_mode_unsupported' };
  const min = support.minApiByMode?.[facts.mode] ?? support.minApi;
  if (typeof min === 'number' && typeof facts.apiLevel === 'number' && Number.isInteger(facts.apiLevel) && facts.apiLevel < min) {
    return { status: 'not_applicable', reason: 'os_too_old', detail: String(min) };
  }
  if (extras.ownershipForbidden) return { status: 'not_applicable', reason: 'ownership_forbidden' };
  if (extras.unresolvedVariable) return { status: 'not_applicable', reason: 'variable_unresolved', detail: extras.unresolvedVariable };
  return { status: 'available' };
}
