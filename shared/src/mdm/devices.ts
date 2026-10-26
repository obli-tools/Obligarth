// =============================================================================
// MDM data model — views of the device registry, its episodes, its end users
// and its inventory (docs: modele-donnees-mdm §10.2). Fields the privacy rules
// do not collect are ABSENT (undefined), never null-filled (EX-19).
// =============================================================================
import type {
  ComplianceState, ConfigState, DeviceUsage, EndUserSource, EndUserStatus, EnrollmentMethod, EnrollmentState,
  EpisodeEndReason, IdentityState, LostModeState, ManagementChannel, ManagementMode, NanoEnrollType, Ownership, Platform,
  PushState, UnenrollReason,
} from './enums';
import type { ContactState } from './states';

/** A reason of non-compliance (MVP evaluator, §4.4; the Android evaluator, android/inventory/compliance.ts): no
 *  personal data in `detail`. */
export interface ComplianceReason {
  code: 'config_error' | 'passcode' | 'os_update_overdue' | 'stale' | 'supervision_required'
    | 'os_outdated' | 'amapi_noncompliant' | 'integrity_at_risk' | 'no_contact' | 'policy_not_applied' | 'management_disabled';
  detail?: Record<string, string | number | boolean | null>;
}

/** What the privacy rules of the device's ownership collect (DeviceDetail.privacy.collected). */
export type CollectedField = 'serialNumber' | 'hardwareIds' | 'deviceName' | 'phoneNumber' | 'network'
  | 'allApps' | 'allCertificates';

/** One row of the inventory list (GET /api/mdm/devices). */
export interface DeviceSummary {
  id: number; uuid: string; tenantId: number; tenantName?: string;
  label: string; displayName: string | null; groupId: number | null; groupName: string | null;
  platform: Platform; ownership: Ownership; enrollmentMethod: EnrollmentMethod; managementMode: ManagementMode;
  supervised: boolean; usage: DeviceUsage;
  enrollmentState: EnrollmentState; contactState: ContactState; lastCheckinAt: string | null;
  complianceState: ComplianceState; complianceReasons: ComplianceReason[]; configState: ConfigState;
  lostModeState: LostModeState;
  osVersion: string | null; model: string | null; modelName: string | null; serialNumber?: string | null;
  endUser: { id: number; displayName: string | null; email: string | null } | null;
  tags: string[]; enrolledAt: string | null;
  /** End of the warranty (asset data entered by an administrator, YYYY-MM-DD): the inventory's column (§11.3). */
  warrantyExpiry: string | null;
  /** Battery level, integer percent 0-100 (list only): Apple DeviceInformation or the bridge agent's status; absent
   *  without a source (AMAPI). */
  batteryLevel?: number | null;
}

/** What the record shows of DeviceInformation, refiltered with the privacy rules: a field not collected is ABSENT. */
export interface AppleDeviceInfoView {
  modelNumber?: string | null;
  cloudBackup?: boolean | null;
  /** storeNetwork */
  carrier?: string | null; subscriberCarrier?: string | null; roaming?: boolean | null;
  /** storePhoneNumber */
  phoneNumber?: string | null; iccid?: string | null; eid?: string | null;
  /** storeNetwork and storeHardwareIds */
  wifiMac?: string | null; bluetoothMac?: string | null;
}

/** The security posture of an Apple device: SecurityInfo, the DDM status items when they are more recent. */
export interface AppleDeviceSecurityView {
  passcodePresent: boolean | null;
  passcodeCompliant: boolean | null;
  passcodeCompliantWithProfiles: boolean | null;
  hardwareEncryptionCaps: number | null;
  /** macOS FileVault (absent when SecurityInfo does not report it). */
  fdeEnabled?: boolean | null;
  /** softwareupdate.pending-version (DDM): an OS update waits to be installed. */
  pendingOsVersion: string | null;
}

/** The Apple satellite, without its secrets nor the raw responses (identity_cert_pem, device_information). */
export interface AppleDeviceDetail {
  enrollmentType: NanoEnrollType; proof: 'none' | 'ade';
  certNotAfter: string | null; identityState: IdentityState;
  pushState: PushState;
  hasUnlockToken: boolean; activationLockEnabled: boolean | null; findMyEnabled: boolean | null;
  activationLockBypassEscrowed: boolean; ddmEnabled: boolean; imei?: string | null; udid?: string | null;
  lastInventory: { deviceInfo: string | null; securityInfo: string | null; apps: string | null;
                   profiles: string | null; certificates: string | null };
  info?: AppleDeviceInfoView;
  security?: AppleDeviceSecurityView;
}

/** The record of one device (GET /api/mdm/devices/:id). */
export interface DeviceDetail extends DeviceSummary {
  description: string | null; customFields: Record<string, unknown>;
  osBuild: string | null; deviceName?: string | null;
  storageCapacityBytes: number | null; storageAvailableBytes: number | null;
  unenrolledAt: string | null; unenrollReason: UnenrollReason | null;
  asset: { purchaseDate: string | null; warrantyExpiry: string | null; warrantyVendor: string | null;
           warrantyStatus: string | null; expectedLifetimeYears: number | null; lifecycleStatus: string | null };
  enrollmentProfileId: string | null;
  managementChannel: ManagementChannel;
  /** When the lost mode last changed state (an acknowledgement, the device's word, the user's exit). */
  lostModeChangedAt: string | null;
  /** Last known battery: Apple DeviceInformation (BatteryLevel) or the bridge agent's status; absent without one. */
  battery?: { level: number; charging: boolean | null; observedAt: string | null; source: 'apple' | 'agent' };
  apple?: AppleDeviceDetail;
  privacy: { collected: CollectedField[] };
}

/** One enrollment cycle of a device (device_enrollments). */
export interface EnrollmentEpisode {
  id: number; deviceId: number; channelEnrollmentId: string;
  enrollmentMethod: EnrollmentMethod; managementMode: ManagementMode; ownership: Ownership;
  enrollmentProfileId: string | null; enrollmentSessionId: string | null; endUserId: number | null;
  certSha256: string | null; startedAt: string; enrolledAt: string | null; endedAt: string | null;
  endReason: EpisodeEndReason | null;
}

/** An employee of the client (PLT-28): no account in Obligate nor in Obligarth. */
export interface EndUser {
  id: number; uuid: string; tenantId: number;
  externalId: string | null; email: string | null; displayName: string | null; managedAppleAccount: string | null;
  source: EndUserSource; status: EndUserStatus; departedAt: string | null;
  createdAt: string; updatedAt: string;
  /** Devices currently assigned (lists). */
  deviceCount?: number;
}

/** Report of a CSV import of end users, line by line (PLT-28). */
export interface EndUserImportReport {
  created: number; updated: number; unchanged: number; rejected: number;
  lines: Array<{ line: number; outcome: 'created' | 'updated' | 'unchanged' | 'rejected'; code?: string; id?: number }>;
}

/** An application of the inventory (device_apps). Unmanaged apps are absent when not collected. */
export interface DeviceAppView {
  identifier: string; name: string | null; version: string | null; shortVersion: string | null;
  managed: boolean; managementStatus: string | null; source: string;
  bundleSize: number | null; dynamicSize: number | null; hasConfiguration: boolean | null; isValidated: boolean | null;
  appId: number | null; firstSeenAt: string; lastSeenAt: string;
}

/** A configuration profile installed on an Apple device (ProfileList). */
export interface DeviceProfileView {
  payloadIdentifier: string; payloadUuid: string | null; displayName: string | null; organization: string | null;
  isManaged: boolean | null; isEncrypted: boolean | null; removalDisallowed: boolean | null;
  hasRemovalPasscode: boolean | null; payloadTypes: string[]; artifactKey: string | null;
  firstSeenAt: string; lastSeenAt: string;
}

/** A certificate of the device (CertificateList, DDM status); never the DER. */
export interface DeviceCertificateView {
  sha256: string; commonName: string | null; subject: string | null; issuer: string | null; serialHex: string | null;
  notBefore: string | null; notAfter: string | null; isIdentity: boolean; isMdmIdentity: boolean; source: string;
  firstSeenAt: string; lastSeenAt: string;
}

/** Counters of the facets of the inventory (GET /api/mdm/devices/facets). */
export interface DeviceFacets {
  platform: Array<{ value: string; count: number }>;
  ownership: Array<{ value: string; count: number }>;
  enrollmentState: Array<{ value: string; count: number }>;
  complianceState: Array<{ value: string; count: number }>;
  configState: Array<{ value: string; count: number }>;
  osVersion: Array<{ platform: string; value: string; count: number }>;
  model: Array<{ value: string; count: number }>;
  tag: Array<{ value: string; count: number }>;
  /** Devices whose lost mode is not off (enabling, on, disabling). */
  lostMode: number;
  /** Devices by contact (each tenant's mdmStaleAfterDays). */
  contact: Record<ContactState, number>;
  /** The same counters for the devices under management only (every state but unenrolled): the fleet counters above
   *  the list, whose tiles filter the "under management" tab. An unenrolled record keeps its lost mode and never
   *  checks in again: counted above, not here. */
  managed: {
    total: number;
    platform: Array<{ value: string; count: number }>;
    nonCompliant: number;
    lostMode: number;
    contact: Record<ContactState, number>;
  };
}

/** One position of a device in lost mode (lost_mode_locations; never for a personal device). */
export interface DeviceLocationPoint {
  latitude: number; longitude: number;
  horizontalAccuracy: number | null; altitude: number | null; speed: number | null; course: number | null;
  observedAt: string;
  /** apple_command: the answer to a DeviceLocation command; android_lost_mode: sent by an AMAPI device in lost mode. */
  source: 'apple_command' | 'android_lost_mode';
}

/** GET /api/mdm/devices/:id/locations: the last positions, or why there are none to read. */
export interface DeviceLocations {
  available: boolean;
  /** personal: never located; unenrolled: out of management; lostModeOff: positions exist only during the lost mode
   *  (SEC-05); capabilityMissing: the user may not use the lost mode on the device. */
  unavailable: 'personal' | 'unenrolled' | 'lostModeOff' | 'capabilityMissing' | null;
  points: DeviceLocationPoint[];
  /** Days a position is kept. */
  retentionDays: number;
}

/** The fleet of a tenant (dashboard, GET /api/mdm/fleet/summary): the devices under management. */
export interface MdmFleetSummary {
  /** Devices under management (every state but unenrolled). */
  total: number;
  enrolled: number; enrolling: number; awaitingConfiguration: number; unenrolling: number;
  compliant: number; nonCompliant: number; complianceUnknown: number;
  configErrors: number; configPending: number;
  contact: Record<ContactState, number>;
  /** Without contact for mdmStaleAfterDays days ('stale'), or never seen 24 h after the enrollment. */
  stale: number;
  lostMode: number;
  byPlatform: Partial<Record<Platform, number>>;
  byOwnership: Partial<Record<Ownership, number>>;
  staleAfterDays: number;
  deltas: { totalVsYesterday: number | null; enrolledVsYesterday: number | null;
            nonCompliantVsYesterday: number | null; staleVsYesterday: number | null };
}

/** One point of the fleet's daily or hourly series. */
export interface MdmFleetPoint {
  at: string; total: number; enrolled: number; enrolling: number; compliant: number; nonCompliant: number;
  configErrors: number; stale: number;
}
