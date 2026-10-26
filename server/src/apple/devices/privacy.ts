import type { Knex } from 'knex';
import type { CollectedField, NanoEnrollType, Ownership } from '@obligarth/shared';

// =============================================================================
// Privacy rules of the collection (docs: integration-apple-edge §10.7, I20;
// modele-donnees-mdm §5.2, DM8): what the inventory commands ask a device for,
// and what the ingestors keep of the answer (refiltered at the ingestion: a
// key not asked but returned is not stored). Ten fields: the seven of the
// integration and the three the data model requests (certificates,
// storePhoneNumber, storeNetwork). A value not collected is ABSENT from the
// answers of the API, never null (EX-19).
// The default rules are those of conception §10.3, by ownership; they are
// reserved to the laboratory (integration §10.7): the privacy specification
// (CNF-02) replaces the resolver with the tenants' privacy profiles
// (privacy/profiles.ts, installed by registerPrivacyModule; P0-13 T1), which
// compose the same lists below and fall back to these rules for a tenant
// without a profile (equivalence tested by test:privacy).
// =============================================================================

export interface PrivacyRules {
  storeSerialNumber: boolean;
  storeHardwareIds: boolean;                 // IMEI, MEID, EID, MAC addresses
  storeDeviceName: boolean;
  installedApps: 'all' | 'managed_only';
  /** Keys of the DeviceInformation query (a key absent here is never asked). */
  deviceInformationQueries: string[];
  /** DDM status items the device may report (a status item absent here is not kept). */
  statusItems: string[];
  /** The default days of the record after its unenrollment; the tenant's retention applies (P0-13 T4: unenroll.ts). */
  retentionDaysAfterUnenroll: number;
  /** Requested by the data model (§5.2): */
  certificates: 'all' | 'managed_only';      // CertificateList ManagedOnly; personal and COPE: 'managed_only'
  storePhoneNumber: boolean;                 // PhoneNumber, ICCID, EID; corporate only by default
  storeNetwork: boolean;                     // carrier, roaming, Wi-Fi and Bluetooth MAC; personal: false
  /** Location of the device in lost mode (REQ-03; P0-13): never for a personal device. */
  lostModeLocation: boolean;
}

export interface PrivacyRulesResolver {
  rulesFor(trx: Knex | Knex.Transaction, tenantId: number, ownership: Ownership | null,
    enrollmentType: NanoEnrollType): Promise<PrivacyRules>;
}

/** DeviceInformation keys asked of every device (no personal data). */
export const BASE_QUERIES = [
  'OSVersion', 'BuildVersion', 'ProductName', 'Model', 'ModelName', 'ModelNumber', 'DeviceCapacity',
  'AvailableDeviceCapacity', 'IsSupervised', 'IsMDMLostModeEnabled', 'IsActivationLockEnabled',
  'IsDeviceLocatorServiceEnabled', 'IsCloudBackupEnabled', 'AwaitingConfiguration', 'BatteryLevel',
];
export const SERIAL_QUERIES = ['SerialNumber'];
export const UDID_QUERIES = ['UDID'];
export const HARDWARE_ID_QUERIES = ['IMEI', 'MEID'];
export const DEVICE_NAME_QUERIES = ['DeviceName'];
export const PHONE_QUERIES = ['PhoneNumber', 'ICCID', 'EID', 'ServiceSubscriptions'];
export const NETWORK_QUERIES = ['CurrentCarrierNetwork', 'SubscriberCarrierNetwork', 'IsRoaming', 'WiFiMAC', 'BluetoothMAC'];

/** DDM status items kept for every device (management, OS, compliance inputs). */
export const BASE_STATUS_ITEMS = [
  // management.push-token and mdm.push-magic never reach the brain (removed at the relay, apple-edge §5.7)
  'management.client-capabilities', 'management.declarations',
  'device.model.family', 'device.model.identifier', 'device.model.marketing-name',
  'device.operating-system.build-version', 'device.operating-system.family', 'device.operating-system.marketing-name',
  'device.operating-system.version', 'device.operating-system.supplemental.build-version',
  'device.operating-system.supplemental.extra-version',
  'passcode.is-compliant', 'passcode.is-present',
  'softwareupdate.install-reason', 'softwareupdate.install-state', 'softwareupdate.pending-version',
  'softwareupdate.failure-reason', 'softwareupdate.beta-enrollment',
  'app.managed.list', 'security.certificate.list',
];
export const SERIAL_STATUS_ITEMS = ['device.identifier.serial-number'];
export const UDID_STATUS_ITEMS = ['device.identifier.udid'];

/** The default rules of an ownership (conception §10.3; integration §10.7 and modele §5.2 tables). */
export function defaultPrivacyRules(ownership: Ownership | null, enrollmentType: NanoEnrollType): PrivacyRules {
  // Unknown ownership never happens for a record (DM25); the strictest rules apply to it.
  const o: Ownership = ownership ?? 'personal';
  const corporate = o === 'corporate';
  const personal = o === 'personal';
  const userEnrollment = enrollmentType === 'User Enrollment (Device)';
  const storeSerialNumber = !personal && !userEnrollment;
  const storeHardwareIds = !personal && !userEnrollment;
  const storeDeviceName = corporate;
  const storePhoneNumber = corporate;
  const storeNetwork = !personal;
  return {
    storeSerialNumber,
    storeHardwareIds,
    storeDeviceName,
    installedApps: corporate ? 'all' : 'managed_only',
    deviceInformationQueries: [
      ...BASE_QUERIES,
      ...(storeSerialNumber ? SERIAL_QUERIES : []),
      ...(userEnrollment ? [] : UDID_QUERIES),
      ...(storeHardwareIds ? HARDWARE_ID_QUERIES : []),
      ...(storeDeviceName ? DEVICE_NAME_QUERIES : []),
      ...(storePhoneNumber ? PHONE_QUERIES : []),
      ...(storeNetwork ? NETWORK_QUERIES : []),
    ],
    statusItems: [
      ...BASE_STATUS_ITEMS,
      ...(storeSerialNumber ? SERIAL_STATUS_ITEMS : []),
      ...(userEnrollment ? [] : UDID_STATUS_ITEMS),
    ],
    retentionDaysAfterUnenroll: personal ? 30 : 90,
    certificates: corporate ? 'all' : 'managed_only',
    storePhoneNumber,
    storeNetwork,
    lostModeLocation: !personal,
  };
}

const defaultResolver: PrivacyRulesResolver = {
  async rulesFor(_trx, _tenantId, ownership, enrollmentType) {
    return defaultPrivacyRules(ownership, enrollmentType);
  },
};

let resolver: PrivacyRulesResolver = defaultResolver;

/** The privacy specification (CNF-02) replaces the default resolver, before anything starts. */
export function setPrivacyRulesResolver(r: PrivacyRulesResolver): void {
  resolver = r;
}

/** Is the default resolver (laboratory rules) in place? */
export function usesDefaultPrivacyRules(): boolean {
  return resolver === defaultResolver;
}

/** The rules of a device of `tenantId` (in the caller's transaction or connection, in the tenant's context). */
export function privacyRulesFor(trx: Knex | Knex.Transaction, tenantId: number, ownership: Ownership | null,
  enrollmentType: NanoEnrollType): Promise<PrivacyRules> {
  return resolver.rulesFor(trx, tenantId, ownership, enrollmentType);
}

/** What the rules collect, for the record of a device (DeviceDetail.privacy.collected). */
export function collectedFields(rules: PrivacyRules): CollectedField[] {
  const out: CollectedField[] = [];
  if (rules.storeSerialNumber) out.push('serialNumber');
  if (rules.storeHardwareIds) out.push('hardwareIds');
  if (rules.storeDeviceName) out.push('deviceName');
  if (rules.storePhoneNumber) out.push('phoneNumber');
  if (rules.storeNetwork) out.push('network');
  if (rules.installedApps === 'all') out.push('allApps');
  if (rules.certificates === 'all') out.push('allCertificates');
  return out;
}
