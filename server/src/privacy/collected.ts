import type { Knex } from 'knex';
import type { CollectedField, DeviceDetail, NanoEnrollType, Ownership } from '@obligarth/shared';
import { collectedFields, privacyRulesFor, type PrivacyRules } from '../apple/devices/privacy';
import { androidPrivacyRulesFor, legacyAgentPrivacyRulesFor } from './profiles';

// =============================================================================
// What the privacy rules collect of a device, by its channel (P0-13 T2; EX-19): DeviceDetail.privacy of the record
// (services/device.service.ts) and the visibility of the data the rule language may compare (P0-5 T1,
// mdm/rules/facts.ts). One function for both, so that a rule never compares a datum the record says is not kept.
// Reads in the caller's connection or transaction (the tenant's context).
// =============================================================================

type Q = Knex | Knex.Transaction;

/** The order of the fields in DeviceDetail.privacy (that of collectedFields). */
const COLLECTED_ORDER: readonly CollectedField[] = ['serialNumber', 'hardwareIds', 'deviceName', 'phoneNumber', 'network', 'allApps', 'allCertificates'];
const inOrder = (set: ReadonlySet<CollectedField>): CollectedField[] => COLLECTED_ORDER.filter((f) => set.has(f));

/** What a channel never reads, whatever the tenant's profile: Android Enterprise neither the device name, the phone
 *  number (v1) nor the certificates (android/inventory/privacy.ts); the bridge agent neither the phone number nor the
 *  certificates (legacyAgent/inventory.ts). Apple reads every field its rules ask for. */
const NOT_READ_BY_CHANNEL: Readonly<Record<string, readonly CollectedField[]>> = {
  amapi: ['deviceName', 'phoneNumber', 'allCertificates'],
  legacy_agent: ['phoneNumber', 'allCertificates'],
};

/** The NanoMDM enrollment type of a management mode (the Apple rules depend on it). */
export const nanoTypeOfMode = (mode: string): NanoEnrollType => (mode === 'user_enrollment' ? 'User Enrollment (Device)' : 'Device');

/**
 * DeviceDetail.privacy of a record, by its channel (what the notice and the record announce must be what is kept):
 *   - Apple: what the rules of its ownership collect (collectedFields of the resolved Apple rules);
 *   - Android Enterprise: the rules of the ingestion (androidPrivacyRulesFor): the serial number of a company device,
 *     the IMEI (hardware identifiers) and the network information where they allow them, the applications;
 *   - bridge agent (corporate only): the serial number always (PB13), the device name and the connection it reports,
 *     the IMEI and the full list of applications by the corporate profile (D14, legacyAgentPrivacyRulesFor).
 * notReadByChannel: NOT_READ_BY_CHANNEL, never in collected. `apple`: the Apple rules resolved for the record's
 * tenant, ownership and enrollment type.
 */
export async function recordPrivacy(q: Q, channel: string, tenantId: number, ownership: string | null, apple: PrivacyRules):
  Promise<DeviceDetail['privacy']> {
  const notRead = NOT_READ_BY_CHANNEL[channel] ?? [];
  const set = new Set<CollectedField>();
  if (channel === 'amapi') {
    const a = await androidPrivacyRulesFor(q, tenantId, ownership);
    if (ownership === 'corporate' || ownership === 'corporate_personal') set.add('serialNumber');
    if (a.imei) set.add('hardwareIds');
    if (a.networkInfo) set.add('network');
    if (a.installedApps === 'all') set.add('allApps');
  } else if (channel === 'legacy_agent') {
    const l = await legacyAgentPrivacyRulesFor(q, tenantId);
    for (const f of ['serialNumber', 'deviceName', 'network'] as const) set.add(f);
    if (l.imei) set.add('hardwareIds');
    if (l.installedApps === 'all') set.add('allApps');
  } else {
    for (const f of collectedFields(apple)) set.add(f);
  }
  for (const f of notRead) set.delete(f);
  return { collected: inOrder(set), notReadByChannel: inOrder(new Set(notRead)) };
}

/** The data the rule language may compare on a device of this tenant, channel, ownership and management mode
 *  (mdm/rules/facts.ts): the serial number when the record collects it AND the inventory list shows it (the list
 *  shows it by the Apple rules of the ownership, services/device.service.ts toSummary); every application when the
 *  record collects them all, else the managed ones only. */
export async function ruleVisibility(q: Q, tenantId: number, channel: string, ownership: string | null, mode: string):
  Promise<{ serialNumber: boolean; allApps: boolean }> {
  const apple = await privacyRulesFor(q, tenantId, (ownership as Ownership | null) ?? null, nanoTypeOfMode(mode));
  const { collected } = await recordPrivacy(q, channel, tenantId, ownership, apple);
  return { serialNumber: apple.storeSerialNumber && collected.includes('serialNumber'), allApps: collected.includes('allApps') };
}
