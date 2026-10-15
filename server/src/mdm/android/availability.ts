import {
  availabilityAndroid, type AndroidAvailability, type AndroidAvailabilityFacts, type AndroidFieldSupport,
} from '@obligarth/shared/dist/android/availability.js';
import { parseAndroidSettingKey } from '@obligarth/shared/dist/android/policy.js';
import { androidCatalog, type AndroidCatalogView } from './catalog';
import { fieldSupport, ownershipForbidden } from './overlay';

// =============================================================================
// Availability of an Android setting key for a device: the shared function
// fed with what the server's catalog and overlay know of the key. An app entry
// and an ONC network have the support of their field (applications,
// openNetworkConfiguration).
// Pure: the unit tests load it.
// =============================================================================

/** The support of a setting key: null when its field is unknown to the catalog (or the key is not Android's). */
export function settingSupport(settingKey: string, catalog: AndroidCatalogView = androidCatalog()): AndroidFieldSupport | null {
  const k = parseAndroidSettingKey(settingKey);
  if (!k) return null;
  const field = k.kind === 'app' ? 'applications' : k.kind === 'onc' ? 'openNetworkConfiguration' : k.field;
  return catalog.field(field) ? fieldSupport(field) : null;
}

/** The availability of a setting key, with the value it carries (product rules on the ownership). */
export function androidKeyAvailability(settingKey: string, value: unknown, facts: AndroidAvailabilityFacts,
  extras: { unresolvedVariable?: string | null } = {}, catalog: AndroidCatalogView = androidCatalog()): AndroidAvailability {
  const k = parseAndroidSettingKey(settingKey);
  const forbidden = k?.kind === 'field' ? ownershipForbidden(k.field, value, facts.ownership) : false;
  return availabilityAndroid(settingSupport(settingKey, catalog), facts, { ownershipForbidden: forbidden, unresolvedVariable: extras.unresolvedVariable ?? null });
}
