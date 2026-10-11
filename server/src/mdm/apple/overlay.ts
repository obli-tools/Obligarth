import type { Ownership } from '@obligarth/shared';

// =============================================================================
// Local overlay of the Apple schema (docs: modele-donnees-mdm §7.3), versioned
// with the code: what the schema does not say. The merge of a type whose keys
// Apple combines (restrictions: Obligarth delivers ONE resolved payload), the
// key naming the instance of a collection, the keys holding secrets (stored
// as references to the tenant's vault, purposes policy.*), the product rules,
// and the types offered at the MVP (the pilot's: the others stay visible and
// greyed, refused by the validation, until they are qualified).
// =============================================================================

export interface TypeOverlay {
  merge?: 'keyed' | 'collection' | 'atomic';
  /** Collection types: key whose value names the instance. */
  instanceKey?: string;
  /** Keys holding secrets (dotted path of the schema: dictionary keys, array elements by their subkey's
   *  name), with the tenant_secrets purpose. */
  secretKeys?: Record<string, string>;
  /** Product rule on top of Apple's: ownerships for which the type is never delivered. */
  forbiddenOwnerships?: Ownership[];
  /** Not offered at the MVP (editor hides it, validation refuses it). */
  disabled?: boolean;
}

const VPN_SECRET = 'policy.vpn_shared_secret';

export const APPLE_OVERLAY: Record<string, TypeOverlay> = {
  'com.apple.applicationaccess': { merge: 'keyed' },
  'com.apple.wifi.managed': { instanceKey: 'SSID_STR',
    secretKeys: { Password: 'policy.wifi_password', 'EAPClientConfiguration.UserPassword': 'policy.eap_password',
      ProxyPassword: 'policy.proxy_password' } },
  'com.apple.vpn.managed': { instanceKey: 'UserDefinedName',
    secretKeys: { 'VPN.AuthPassword': VPN_SECRET, 'IPSec.SharedSecret': VPN_SECRET, 'IPSec.XAuthPassword': VPN_SECRET,
      'PPP.AuthPassword': VPN_SECRET, 'IKEv2.Password': VPN_SECRET, 'IKEv2.AuthPassword': VPN_SECRET,
      'IKEv2.SharedSecret': VPN_SECRET, 'IKEv2.PPK': VPN_SECRET, 'TransparentProxy.Password': VPN_SECRET,
      'Proxies.HTTPProxyPassword': 'policy.proxy_password' } },
  'com.apple.security.pkcs12': { instanceKey: 'PayloadCertificateFileName',
    secretKeys: { Password: 'policy.pkcs12_password', PayloadContent: 'policy.pkcs12_identity' } },
  'com.apple.security.root': { instanceKey: 'PayloadCertificateFileName' },
  'com.apple.security.pkcs1': { instanceKey: 'PayloadCertificateFileName' },
  'com.apple.webcontent-filter': { instanceKey: 'UserDefinedName',
    secretKeys: { Password: 'policy.webfilter_password', 'URLFilterParameters.PIRAuthenticationToken': 'policy.webfilter_password' } },
  'com.apple.configuration.softwareupdate.enforcement.specific': { instanceKey: 'TargetOSVersion' },
  // A declaration never carries a secret at the MVP (secret_requires_asset): the beta programme tokens.
  'com.apple.configuration.softwareupdate.settings': {
    secretKeys: { 'Beta.OfferPrograms.Program.Token': 'policy.raw_secret', 'Beta.RequireProgram.Token': 'policy.raw_secret' } },
  // Settings items left for their qualification (CFG-08): per-app items (one artifact per item, not per app),
  // Shared iPad (v2), macOS only, superseded by a declaration, options of the activation lock.
  'setting.ApplicationAttributes': { disabled: true },
  'setting.ApplicationConfiguration': { disabled: true },
  'setting.DefaultApplications': { disabled: true },
  'setting.HostName': { disabled: true },
  'setting.MDMOptions': { disabled: true },
  'setting.MaximumResidentUsers': { disabled: true },
  'setting.PasscodeLockGracePeriod': { disabled: true },
  'setting.SharedDeviceConfiguration': { disabled: true },
  'setting.SoftwareUpdateSettings': { disabled: true },
  'setting.VoiceRoaming': { disabled: true },
};

/** The types of the pilot offered at the MVP (to be confirmed against the pilot's grid, D12), and the items of the
 *  Settings command (CFG-08) not disabled above. Any other type of the catalog stays greyed. */
export const MVP_TYPES: ReadonlySet<string> = new Set([
  'com.apple.configuration.passcode.settings',
  'com.apple.configuration.softwareupdate.enforcement.specific',
  'com.apple.configuration.softwareupdate.settings',
  'com.apple.applicationaccess',
  'com.apple.wifi.managed',
  'com.apple.app.lock',
  'com.apple.homescreenlayout',
  'com.apple.shareddeviceconfiguration',
  'com.apple.security.root',
  'com.apple.security.pkcs1',
  'com.apple.security.pkcs12',
  'com.apple.webcontent-filter',
  'com.apple.vpn.managed',
]);
