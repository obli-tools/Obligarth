// =============================================================================
// Availability of a setting for a device (docs: modele-donnees-mdm §7.8),
// shared by the resolver and the editor: the first reason that applies, in
// this order, at the level of the type then of the key:
//    1 schema_unknown              type absent from the current catalog
//    2 platform_unsupported        no support for the device's OS, or 'n/a'
//    3 enrollment_type_unsupported class of enrollment not allowed, or
//                                  userenrollment 'forbidden' in User Enrollment
//    4 supervision_required        supervision required, device not supervised
//    5 os_removed                  OS version ≥ removed
//    6 os_too_old                  OS version < introduced (detail: the minimum)
//    7 ownership_forbidden         product rule of the overlay
//    8 client_unsupported          declaration absent from the client capabilities
//    9 asset_not_supported         declaration that would need an asset (MVP)
//   10 variable_unresolved         variable without a value for the device
//   11 license_unavailable         app without an assignable licence
// An unknown OS version (before the first inventory) makes nothing
// unavailable for the reasons 5 and 6; unknown client capabilities nothing for
// the reason 8: the resolution is run again when they arrive.
// =============================================================================
import type { ManagementMode, Ownership, Platform } from '../enums';
import type { SettingAvailability } from '../effective';
import { enrollmentClassOf } from '../ownership';
import { versionNum } from '../states';
import { appleOsOfPlatform, type KeyOsSupport, type SchemaEntry, type SchemaKey } from './catalog';

export interface AvailabilityFacts {
  platform: Platform | string;
  osVersion: string | null;
  mode: ManagementMode | string;
  supervised: boolean;
  ownership: Ownership | string;
  /** Declaration types of management.client-capabilities; null (or absent): not reported yet. */
  declarationTypes?: readonly string[] | null;
}

export interface AvailabilityExtras {
  /** Product rule of the server's overlay: ownerships the type is never delivered to. */
  forbiddenOwnerships?: readonly string[];
  /** The declaration would need an asset (not delivered at the MVP). */
  requiresAsset?: boolean;
  /** A variable of the value without a value for this device (its name). */
  unresolvedVariable?: string | null;
  /** App without an assignable licence. */
  licenseUnavailable?: boolean;
}

/** The availability of a key (`key`, keyed types; null for the type as a whole) of `entry` for a device. */
export function availability(entry: SchemaEntry | null | undefined, key: SchemaKey | null | undefined,
  facts: AvailabilityFacts, extras: AvailabilityExtras = {}): SettingAvailability {
  // 1. Type absent from the current catalog.
  if (!entry) return { status: 'not_applicable', reason: 'schema_unknown' };
  // 2. Platform.
  const os = appleOsOfPlatform(facts.platform);
  const typeOs = os ? entry.os[os] : undefined;
  if (!os || !typeOs || typeOs.introduced === 'n/a') return { status: 'not_applicable', reason: 'platform_unsupported' };
  const keyOs: KeyOsSupport | undefined = key?.os?.[os];
  if (keyOs?.introduced === 'n/a') return { status: 'not_applicable', reason: 'platform_unsupported', detail: key!.name };
  const levels: KeyOsSupport[] = keyOs ? [typeOs, keyOs] : [typeOs];

  // 3. Class of enrollment, then 4. supervision.
  const cls = enrollmentClassOf(facts.mode, facts.supervised);
  for (const s of levels) {
    if (s.enrollments && !s.enrollments.includes(cls)) {
      // A declaration for supervised devices only, on an unsupervised device of device mode: what is missing is
      // the supervision, not another kind of enrollment.
      if (cls === 'device' && s.enrollments.includes('supervised')) return { status: 'not_applicable', reason: 'supervision_required' };
      return { status: 'not_applicable', reason: 'enrollment_type_unsupported' };
    }
    if (cls === 'user' && s.userEnrollment === 'forbidden') return { status: 'not_applicable', reason: 'enrollment_type_unsupported' };
  }
  for (const s of levels) {
    if (s.supervised === true && !facts.supervised) return { status: 'not_applicable', reason: 'supervision_required' };
  }

  // 5. Removed, 6. too old (an unknown version decides nothing).
  const v = versionNum(facts.osVersion);
  if (v !== null) {
    for (const s of levels) {
      const removed = s.removed ? versionNum(s.removed) : null;
      if (removed !== null && v >= removed) return { status: 'not_applicable', reason: 'os_removed', detail: s.removed };
    }
    for (const s of levels) {
      const introduced = s.introduced && s.introduced !== 'n/a' ? versionNum(s.introduced) : null;
      if (introduced !== null && v < introduced) return { status: 'not_applicable', reason: 'os_too_old', detail: s.introduced };
    }
  }

  // 7. Product rule (overlay).
  if (extras.forbiddenOwnerships?.includes(String(facts.ownership))) return { status: 'not_applicable', reason: 'ownership_forbidden' };
  // 8. Declaration the device does not announce.
  if (entry.family === 'declaration' && Array.isArray(facts.declarationTypes) && !facts.declarationTypes.includes(entry.type)) {
    return { status: 'not_applicable', reason: 'client_unsupported' };
  }
  // 9. Asset (MVP), 10. variable, 11. licence.
  if (extras.requiresAsset) return { status: 'not_applicable', reason: 'asset_not_supported' };
  if (extras.unresolvedVariable) return { status: 'not_applicable', reason: 'variable_unresolved', detail: extras.unresolvedVariable };
  if (extras.licenseUnavailable) return { status: 'not_applicable', reason: 'license_unavailable' };
  return { status: 'available' };
}

/** Is a type (or key) deprecated on the device's OS (shown by the editor, never a reason: still delivered)? */
export function deprecatedSince(entry: SchemaEntry | null | undefined, key: SchemaKey | null | undefined,
  platform: Platform | string): string | null {
  const os = appleOsOfPlatform(platform);
  if (!entry || !os) return null;
  return key?.os?.[os]?.deprecated ?? entry.os[os]?.deprecated ?? null;
}
