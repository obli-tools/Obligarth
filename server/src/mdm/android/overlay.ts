import type { AndroidFieldSupport, AndroidMode } from '@obligarth/shared';

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

/** The settings that can wipe a device, destroy data on it or give its recovery away, by field. Besides the
 *  four of section 22.4: wipeDataFlags (WIPE_ESIMS: the eSIMs go irreversibly with any wipe, a compliance rule's
 *  included) and personalUsagePolicies when it disallows the private space (an existing one is removed with the
 *  user's data: description of PersonalUsagePolicies.privateSpacePolicy, revision 20261014). */
export const WIPE_CAPABLE_FIELDS: ReadonlySet<string> = new Set([
  'policyEnforcementRules', 'passwordPolicies', 'frpAdminEmails', 'setupActions', 'wipeDataFlags', 'personalUsagePolicies',
]);

/** The value of personalUsagePolicies.privateSpacePolicy that removes an existing private space. */
export const PRIVATE_SPACE_DISALLOWED = 'PRIVATE_SPACE_DISALLOWED';

/** JSON paths of a policy body the gateway looks at under a freeze (no schema validation there). */
export const WIPE_CAPABLE_PATHS: readonly string[] = [
  'policyEnforcementRules[].wipeAction', 'passwordPolicies[].maximumFailedPasswordsForWipe',
  'passwordRequirements.maximumFailedPasswordsForWipe', 'frpAdminEmails', 'setupActions', 'wipeDataFlags',
  `personalUsagePolicies.privateSpacePolicy=${PRIVATE_SPACE_DISALLOWED}`,
];

/** Does a policy body carry a wipe-capable setting (the closed list of JSON paths above; no schema validation)?
 *  The gateway's freeze lock asks it before any policies.patch. */
export function policyHasWipeSettings(p: Record<string, unknown> | null | undefined): boolean {
  if (!p || typeof p !== 'object') return false;
  const has = (o: unknown, k: string): boolean => !!o && typeof o === 'object' && (o as Record<string, unknown>)[k] !== undefined;
  const rules = p.policyEnforcementRules;
  if (Array.isArray(rules) && rules.some((r) => has(r, 'wipeAction'))) return true;
  const pp = p.passwordPolicies;
  if (Array.isArray(pp) && pp.some((r) => has(r, 'maximumFailedPasswordsForWipe'))) return true;
  if (has(p.passwordRequirements, 'maximumFailedPasswordsForWipe')) return true;
  if (p.frpAdminEmails !== undefined || p.setupActions !== undefined || p.wipeDataFlags !== undefined) return true;
  const pu = p.personalUsagePolicies;
  if (pu && typeof pu === 'object' && (pu as Record<string, unknown>).privateSpacePolicy === PRIVATE_SPACE_DISALLOWED) return true;
  return false;
}

/** maximumFailedPasswordsForWipe: accepted from 6 to 100; the tenant's floor (androidMinFailedPasswordsForWipe)
 *  defaults to 10 and is never below 6. 0 means no limit (no wipe). */
export const FAILED_PASSWORDS_FOR_WIPE = { min: 6, max: 100, defaultFloor: 10 } as const;
/** policyEnforcementRules: the wipe never comes before 14 days of non-compliance. */
export const MIN_WIPE_AFTER_DAYS = 14;
/** Limits of AMAPI on a policy. */
export const POLICY_LIMITS = { requiredForSetupApps: 5, minimumVersionCodeApps: 20, setupActions: 1, kioskApps: 1 } as const;

/** Where a secret reference may stand. ONC: keys holding a passphrase, a password, a one-time password, a key or a
 *  client certificate, at any depth of openNetworkConfiguration, never in clear (secret_expected); managed
 *  configurations: any value (hidden or secret properties of the app). null: the purpose depends on the object
 *  that holds the key (ONC_SECRET_PURPOSE_BY_PARENT); a secret key held elsewhere takes no secret at all. */
export const ONC_SECRET_KEYS: Readonly<Record<string, string | null>> = {
  Passphrase: 'policy.wifi_password',
  Password: null,
  PSK: 'policy.vpn_shared_secret',
  OTP: 'policy.vpn_otp',
  TLSAuthContents: 'policy.vpn_tls_auth',
  // A client certificate with its private key (ONC Certificates[].PKCS12): the vault's, as for Apple.
  PKCS12: 'policy.pkcs12_identity',
};
/** Purposes of a secret key of the ONC by the key of the object that holds it. */
export const ONC_SECRET_PURPOSE_BY_PARENT: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  Password: { EAP: 'policy.eap_password', OpenVPN: 'policy.vpn_password', L2TP: 'policy.vpn_password' },
};
const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
/** Is `key` a secret key of the ONC (a value in clear is refused there)? */
export function isOncSecretKey(key: string): boolean {
  return own(ONC_SECRET_KEYS, key);
}
/** The purpose of a secret at the ONC key `key` held by the object at key `parent` (null: no secret there). */
export function oncSecretPurpose(key: string, parent: string | null): string | null {
  if (!own(ONC_SECRET_KEYS, key)) return null;
  if (own(ONC_SECRET_PURPOSE_BY_PARENT, key)) {
    const byParent = ONC_SECRET_PURPOSE_BY_PARENT[key];
    return parent !== null && own(byParent, parent) ? byParent[parent] : null;
  }
  return ONC_SECRET_KEYS[key];
}
export const APP_CONFIG_SECRET_PURPOSE = 'policy.app_config_secret';
/** Secret slots of the policy outside the ONC and the managed configurations: the top-level field, the key of the
 *  object that holds the secret and the secret's key. A value in clear is refused there (secret_expected), as at the
 *  ONC's: the password of an APN (deviceConnectivityManagement.apnPolicy.apnSettings[].password). */
export const FIELD_SECRET_SLOTS: ReadonlyArray<{ field: string; parent: string; key: string; purpose: string }> = [
  { field: 'deviceConnectivityManagement', parent: 'apnSettings', key: 'password', purpose: 'policy.apn_password' },
];
/** The purpose of the secret slot at `key` held by the object at key `parent` under the top-level `field` (null:
 *  not a slot). */
export function fieldSecretPurpose(field: string, key: string, parent: string | null): string | null {
  const slot = FIELD_SECRET_SLOTS.find((s) => s.field === field && s.key === key && s.parent === parent);
  return slot ? slot.purpose : null;
}

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
    oncByParent: ONC_SECRET_PURPOSE_BY_PARENT, fieldSecrets: FIELD_SECRET_SLOTS, wipePaths: WIPE_CAPABLE_PATHS,
    support: FIELD_SUPPORT,
  };
}
