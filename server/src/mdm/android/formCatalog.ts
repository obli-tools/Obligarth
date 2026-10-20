import type { AndroidFormCatalogView, AndroidFormField, AndroidFormGroup, AndroidFormNode, AndroidMode } from '@obligarth/shared';
import { AMAPI_POLICY_SCHEMA } from './schema/amapiPolicySchema';
import type { AmapiSchemaNode } from './schemaTypes';
import {
  DEPRECATED_FIELDS, FIELD_SECRET_SLOTS, POLICY_LIMITS, RESERVED_FIELDS, WIPE_CAPABLE_FIELDS, fieldSupport,
} from './overlay';

// =============================================================================
// The catalog the policy editor of the console generates its forms from (lot AN-C2, android-amapi §12.1): the
// top-level fields of Policy that a fragment may set (the reserved ones left out, the apps edited apart), each with
// its schema as the discovery document gives it (types, formats, enumerations, deprecations; $ref resolved by the
// console in `schemas`), its group of intention, its modes and minimum API level, whether it can wipe a device and
// whether it holds a secret slot. The descriptions stay in the document (the catalog does not ship them): the console
// shows the name of the field and a translated help when it has one. Pure: computed once.
// =============================================================================

/** The group of intention of a field (the console lists the groups in ANDROID_FORM_GROUPS order). */
const GROUPS: Readonly<Record<string, AndroidFormGroup>> = {
  // Security of the device and of its data.
  advancedSecurityOverrides: 'security', encryptionPolicy: 'security', keyguardDisabled: 'security', keyguardDisabledFeatures: 'security',
  maximumTimeToLock: 'security', screenCaptureDisabled: 'security', choosePrivateKeyRules: 'security', privateKeySelectionEnabled: 'security',
  credentialsConfigDisabled: 'security', credentialProviderPolicyDefault: 'security', oncCertificateProviders: 'security',
  frpAdminEmails: 'security', factoryResetDisabled: 'security', safeBootDisabled: 'security', wipeDataFlags: 'security',
  debuggingFeaturesAllowed: 'security', ensureVerifyAppsEnabled: 'security', installUnknownSourcesAllowed: 'security',
  // Passwords.
  passwordPolicies: 'password', passwordRequirements: 'password',
  // Apps and their permissions.
  appAutoUpdatePolicy: 'apps', appFunctions: 'apps', defaultPermissionPolicy: 'apps', permissionGrants: 'apps', playStoreMode: 'apps',
  installAppsDisabled: 'apps', uninstallAppsDisabled: 'apps', blockApplicationsEnabled: 'apps', permittedAccessibilityServices: 'apps',
  permittedInputMethods: 'apps', persistentPreferredActivities: 'apps', defaultApplicationSettings: 'apps', autofillPolicy: 'apps',
  assistContentPolicy: 'apps', androidDevicePolicyTracks: 'apps',
  // Networks and connectivity.
  openNetworkConfiguration: 'network', alwaysOnVpnPackage: 'network', recommendedGlobalProxy: 'network', networkEscapeHatchEnabled: 'network',
  deviceConnectivityManagement: 'network', deviceRadioState: 'network', preferentialNetworkService: 'network', dataRoamingDisabled: 'network',
  mobileNetworksConfigDisabled: 'network', vpnConfigDisabled: 'network', wifiConfigDisabled: 'network', wifiConfigsLockdownEnabled: 'network',
  tetheringConfigDisabled: 'network', bluetoothConfigDisabled: 'network', bluetoothContactSharingDisabled: 'network', bluetoothDisabled: 'network',
  networkResetDisabled: 'network', outgoingBeamDisabled: 'network', cellBroadcastsConfigDisabled: 'network',
  // Restrictions of use.
  cameraAccess: 'restrictions', cameraDisabled: 'restrictions', microphoneAccess: 'restrictions', unmuteMicrophoneDisabled: 'restrictions',
  addUserDisabled: 'restrictions', removeUserDisabled: 'restrictions', modifyAccountsDisabled: 'restrictions',
  accountTypesWithManagementDisabled: 'restrictions', mountPhysicalMediaDisabled: 'restrictions', usbFileTransferDisabled: 'restrictions',
  usbMassStorageEnabled: 'restrictions', outgoingCallsDisabled: 'restrictions', smsDisabled: 'restrictions', shareLocationDisabled: 'restrictions',
  funDisabled: 'restrictions', createWindowsDisabled: 'restrictions', setUserIconDisabled: 'restrictions', setWallpaperDisabled: 'restrictions',
  adjustVolumeDisabled: 'restrictions', printingPolicy: 'restrictions', backupService: 'restrictions', locationMode: 'restrictions',
  // The device itself.
  autoDateAndTimeZone: 'device', autoTimeRequired: 'device', displaySettings: 'device', stayOnPluggedModes: 'device',
  deviceOwnerLockScreenInfo: 'device', shortSupportMessage: 'device', longSupportMessage: 'device', skipFirstUseHintsEnabled: 'device',
  enterpriseDisplayNameVisibility: 'device', setupActions: 'device', workAccountSetupConfig: 'device', minimumApiLevel: 'device',
  // Updates.
  systemUpdate: 'updates',
  // Dedicated devices.
  kioskCustomization: 'kiosk', kioskCustomLauncherEnabled: 'kiosk', statusBarDisabled: 'kiosk',
  // Work profile and personal use.
  personalUsagePolicies: 'personal', crossProfilePolicies: 'personal', crossDevicePolicies: 'personal',
  // Compliance.
  policyEnforcementRules: 'compliance', complianceRules: 'compliance',
};

/** Fields edited apart by the editor (the apps of the policy, section `applications`). */
const EDITED_APART: ReadonlySet<string> = new Set(['applications']);

/** Fields with a secret slot (a value in clear refused): ONC passphrases, APN password. */
const SECRET_FIELDS: ReadonlySet<string> = new Set(['openNetworkConfiguration', ...FIELD_SECRET_SLOTS.map((s) => s.field)]);

function toFormNode(n: AmapiSchemaNode): AndroidFormNode {
  const out: AndroidFormNode = {};
  if (n.type) out.type = n.type;
  if (n.$ref) out.$ref = n.$ref;
  if (n.format) out.format = n.format;
  if (n.enum) out.enum = [...n.enum];
  if (n.deprecatedValues?.length) out.deprecatedValues = [...n.deprecatedValues];
  if (n.deprecated) out.deprecated = true;
  if (n.items) out.items = toFormNode(n.items);
  if (n.properties) {
    out.properties = {};
    for (const [k, v] of Object.entries(n.properties)) if (!v.readOnly) out.properties[k] = toFormNode(v);
  }
  if (n.additionalProperties) out.additionalProperties = toFormNode(n.additionalProperties);
  return out;
}

let cached: AndroidFormCatalogView | null = null;

/** The form catalog of the pinned revision (GET /api/android/policy-catalog). */
export function androidFormCatalog(): AndroidFormCatalogView {
  if (cached) return cached;
  const catalog = AMAPI_POLICY_SCHEMA;
  const root = catalog.schemas[catalog.root];
  const fields: AndroidFormField[] = [];
  for (const name of Object.keys(root.properties ?? {}).sort()) {
    if (RESERVED_FIELDS.has(name) || EDITED_APART.has(name)) continue;
    const node = root.properties![name];
    if (node.readOnly) continue;
    const support = fieldSupport(name);
    const deprecated = Object.prototype.hasOwnProperty.call(DEPRECATED_FIELDS, name) || node.deprecated === true;
    fields.push({
      name,
      group: Object.prototype.hasOwnProperty.call(GROUPS, name) ? GROUPS[name] : 'other',
      node: toFormNode(node),
      deprecated,
      replacement: deprecated && Object.prototype.hasOwnProperty.call(DEPRECATED_FIELDS, name) ? DEPRECATED_FIELDS[name] : null,
      ...(support.modes ? { modes: [...support.modes] as AndroidMode[] } : {}),
      ...(support.minApi !== undefined ? { minApi: support.minApi } : {}),
      wipeCapable: WIPE_CAPABLE_FIELDS.has(name),
      secretSlots: SECRET_FIELDS.has(name),
    });
  }
  const schemas: Record<string, AndroidFormNode> = {};
  for (const [id, n] of Object.entries(catalog.schemas)) if (id !== catalog.root) schemas[id] = toFormNode(n);
  cached = {
    release: { revision: catalog.revision, sourceSha256: catalog.sourceSha256 },
    fields,
    schemas,
    limits: { requiredForSetupApps: POLICY_LIMITS.requiredForSetupApps, minimumVersionCodeApps: POLICY_LIMITS.minimumVersionCodeApps },
  };
  return cached;
}
