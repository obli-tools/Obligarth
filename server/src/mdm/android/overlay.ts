import type { AndroidFieldSupport, AndroidMode } from '@obligarth/shared/dist/android/availability.js';

// =============================================================================
// Local overlay of the AMAPI Policy schema, versioned with the code: what the
// discovery document does not say, or not in a form a program reads.
//   - fields Obligarth reserves (the inventory is minimised by the privacy
//     rules, never by a policy; the policy's identity and version are
//     Google's), the reserved package (the companion app) and role;
//   - deprecated fields, refused at the write with their replacement;
//   - the settings that can wipe a device or hand its recovery to someone
//     (published at the restricted level, refused by the gateway under a
//     freeze);
//   - where a secret may stand (ONC passphrases, managed configurations);
//   - the modes where a field has an effect and the minimum API levels, kept
//     by hand from the field descriptions of the document (revision 20261014)
//     and the release notes; a field without a known minimum is never made
//     unavailable for its API level;
//   - the product rules on the ownership.
// =============================================================================

/** Top-level fields of Policy a fragment never sets. */
export const RESERVED_FIELDS: ReadonlySet<string> = new Set(['name', 'version', 'statusReportingSettings', 'usageLog']);

/** The companion app's package: never in a policy's applications (its entry is the compiler's, with the app). */
export const RESERVED_PACKAGES: ReadonlySet<string> = new Set(['tools.obli.obligarth.agent']);

/** App roles a policy never grants. */
export const RESERVED_ROLES: ReadonlySet<string> = new Set(['COMPANION_APP']);

/** Deprecated top-level fields and their replacement (null: no replacement, the field has no effect). */
export const DEPRECATED_FIELDS: Readonly<Record<string, string | null>> = {
  cameraDisabled: 'cameraAccess',
  passwordRequirements: 'passwordPolicies',
  usbFileTransferDisabled: 'deviceConnectivityManagement.usbDataAccess',
  usbMassStorageEnabled: 'deviceConnectivityManagement.usbDataAccess',
  complianceRules: 'policyEnforcementRules',
  unmuteMicrophoneDisabled: 'microphoneAccess',
  wifiConfigDisabled: 'deviceConnectivityManagement.configureWifi',
  wifiConfigsLockdownEnabled: 'deviceConnectivityManagement.configureWifi',
  tetheringConfigDisabled: 'deviceConnectivityManagement.tetheringSettings',
  autoTimeRequired: 'autoDateAndTimeZone',
  ensureVerifyAppsEnabled: 'advancedSecurityOverrides.googlePlayProtectVerifyApps',
  debuggingFeaturesAllowed: 'advancedSecurityOverrides.developerSettings',
  installUnknownSourcesAllowed: 'advancedSecurityOverrides.untrustedAppsPolicy',
  statusBarDisabled: 'kioskCustomization.statusBar',
  safeBootDisabled: null,
  androidDevicePolicyTracks: null,
  blockApplicationsEnabled: null,
};

/** Deprecated fields of an app entry and their replacement. */
export const DEPRECATED_APP_FIELDS: Readonly<Record<string, string | null>> = {
  lockTaskAllowed: 'roles[KIOSK]',
  extensionConfig: 'roles',
};

/** The settings that can wipe a device or give its recovery away, by field. */
export const WIPE_CAPABLE_FIELDS: ReadonlySet<string> = new Set([
  'policyEnforcementRules', 'passwordPolicies', 'frpAdminEmails', 'setupActions',
]);

/** JSON paths of a policy body the gateway looks at under a freeze (no schema validation there). */
export const WIPE_CAPABLE_PATHS: readonly string[] = [
  'policyEnforcementRules[].wipeAction', 'passwordPolicies[].maximumFailedPasswordsForWipe',
  'passwordRequirements.maximumFailedPasswordsForWipe', 'frpAdminEmails', 'setupActions',
];

/** maximumFailedPasswordsForWipe: accepted from 6 to 100; the tenant's floor (androidMinFailedPasswordsForWipe)
 *  defaults to 10 and is never below 6. 0 means no limit (no wipe). */
export const FAILED_PASSWORDS_FOR_WIPE = { min: 6, max: 100, defaultFloor: 10 } as const;
/** policyEnforcementRules: the wipe never comes before 14 days of non-compliance. */
export const MIN_WIPE_AFTER_DAYS = 14;
/** Limits of AMAPI on a policy. */
export const POLICY_LIMITS = { requiredForSetupApps: 5, minimumVersionCodeApps: 20, setupActions: 1, kioskApps: 1 } as const;

/** Where a secret reference may stand. ONC: keys holding a passphrase or a password, at any depth of
 *  openNetworkConfiguration; managed configurations: any value (hidden or secret properties of the app). */
export const ONC_SECRET_KEYS: Readonly<Record<string, string>> = {
  Passphrase: 'policy.wifi_password',
  Password: 'policy.eap_password',
  PSK: 'policy.vpn_shared_secret',
  // A client certificate with its private key (ONC Certificates[].PKCS12): the vault's, as for Apple.
  PKCS12: 'policy.pkcs12_identity',
};
export const APP_CONFIG_SECRET_PURPOSE = 'policy.app_config_secret';

const COMPANY: readonly AndroidMode[] = ['fully_managed', 'dedicated', 'work_profile_corporate'];
const DEVICE_OWNER: readonly AndroidMode[] = ['fully_managed', 'dedicated'];

/** Modes and minimum API levels of the top-level fields (the others: every mode, no known minimum). */
export const FIELD_SUPPORT: Readonly<Record<string, AndroidFieldSupport>> = {
  adjustVolumeDisabled: { modes: DEVICE_OWNER },
  autoDateAndTimeZone: { modes: COMPANY },
  backupService: { modes: DEVICE_OWNER, minApi: 26 },
  deviceRadioState: { modes: COMPANY },
  factoryResetDisabled: { modes: COMPANY },
  frpAdminEmails: { modes: COMPANY },
  keyguardDisabled: { modes: ['dedicated'] },
  kioskCustomLauncherEnabled: { modes: ['dedicated'] },
  kioskCustomization: { modes: ['dedicated'] },
  microphoneAccess: { modes: DEVICE_OWNER },
  networkResetDisabled: { modes: DEVICE_OWNER },
  personalUsagePolicies: { modes: ['work_profile_corporate'] },
  systemUpdate: { modes: COMPANY },
  assistContentPolicy: { minApi: 35 },
  credentialProviderPolicyDefault: { minApi: 34 },
  defaultApplicationSettings: { minApi: 36 },
  printingPolicy: { minApi: 28 },
  setUserIconDisabled: { minApi: 24 },
};

/** The support of a field known to the catalog (no entry: every mode, no known minimum). */
export function fieldSupport(field: string): AndroidFieldSupport {
  return Object.prototype.hasOwnProperty.call(FIELD_SUPPORT, field) ? FIELD_SUPPORT[field] : {};
}

/** Product rules on the ownership, by field and value: a company-owned device with a personal profile never has
 *  its factory reset disabled (the user keeps the way out of the organisation's hold). */
export function ownershipForbidden(field: string, value: unknown, ownership: string): boolean {
  if (field === 'factoryResetDisabled') return ownership === 'corporate_personal' && value === true;
  return false;
}

/** The overlay as plain data (for the fingerprint of the catalog). */
export function overlayFingerprintData(): Record<string, unknown> {
  return {
    reservedFields: [...RESERVED_FIELDS].sort(), reservedPackages: [...RESERVED_PACKAGES].sort(), reservedRoles: [...RESERVED_ROLES].sort(),
    deprecated: DEPRECATED_FIELDS, deprecatedApp: DEPRECATED_APP_FIELDS, wipe: [...WIPE_CAPABLE_FIELDS].sort(),
    wipeFloor: FAILED_PASSWORDS_FOR_WIPE, minWipeAfterDays: MIN_WIPE_AFTER_DAYS, limits: POLICY_LIMITS, onc: ONC_SECRET_KEYS,
    support: FIELD_SUPPORT,
  };
}
