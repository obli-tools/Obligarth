// =============================================================================
// The Android section of a policy version and its setting keys, shared by the
// server's validation and compilation and by the editor of the console. The
// section carries a fragment of the AMAPI Policy resource (its top-level
// fields, minus those Obligarth reserves) and the apps of the policy itself;
// the resolution merges it key by key:
//   android:<field>          a top-level field of Policy
//   android:app[<package>]   one entry of applications[], by package name
//   android:onc[<GUID>]      one network of openNetworkConfiguration, by GUID
//                            (a Wi-Fi policy and a VPN policy do not replace
//                            each other)
// One AMAPI policy per device ('d-<device uuid>') and one per enrollment
// profile ('e-<profile uuid>'), delivered as the artifact 'amapi:policy'.
// Imported by direct path until the shared index exports it.
// =============================================================================
import type { JsonValue } from '../mdm/policyContent';

/** One entry of applications[] (an AMAPI ApplicationPolicy). */
export interface AndroidAppEntry {
  packageName: string;
  [field: string]: JsonValue;
}

/** policy_versions.content.sections.android. */
export interface AndroidPolicySection {
  /** Top-level fields of the AMAPI Policy resource. */
  fragment: Record<string, JsonValue>;
  /** Apps of the policy itself, merged by package name. */
  applications?: AndroidAppEntry[];
}

export const ANDROID_SETTING_PREFIX = 'android:';
export const AMAPI_ARTIFACT_KEY = 'amapi:policy';
export const AMAPI_CHANNEL = 'amapi';

/** A package name as Google Play accepts it (255 characters at most). */
export const ANDROID_PACKAGE_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;
export const ANDROID_PACKAGE_MAX = 255;
/** The GUID of an ONC network as the key of a setting (ONC allows any string; Obligarth keeps a safe subset). */
export const ANDROID_ONC_GUID_RE = /^[A-Za-z0-9._:{}-]{1,128}$/;
/** A top-level field name of Policy. */
const FIELD_RE = /^[a-z][A-Za-z0-9]{0,63}$/;

export const isAndroidPackage = (s: unknown): s is string =>
  typeof s === 'string' && s.length <= ANDROID_PACKAGE_MAX && ANDROID_PACKAGE_RE.test(s);

export const androidFieldKey = (field: string): string => `${ANDROID_SETTING_PREFIX}${field}`;
export const androidAppKey = (packageName: string): string => `${ANDROID_SETTING_PREFIX}app[${packageName}]`;
export const androidOncKey = (guid: string): string => `${ANDROID_SETTING_PREFIX}onc[${guid}]`;

export type AndroidSettingKey =
  | { kind: 'field'; field: string }
  | { kind: 'app'; packageName: string }
  | { kind: 'onc'; guid: string };

/** The parts of an Android setting key; null for anything else (an Apple key, a malformed one). */
export function parseAndroidSettingKey(key: string): AndroidSettingKey | null {
  if (typeof key !== 'string' || !key.startsWith(ANDROID_SETTING_PREFIX)) return null;
  const rest = key.slice(ANDROID_SETTING_PREFIX.length);
  const m = /^(app|onc)\[(.*)\]$/.exec(rest);
  if (m) {
    if (m[1] === 'app') return isAndroidPackage(m[2]) ? { kind: 'app', packageName: m[2] } : null;
    return ANDROID_ONC_GUID_RE.test(m[2]) ? { kind: 'onc', guid: m[2] } : null;
  }
  return FIELD_RE.test(rest) ? { kind: 'field', field: rest } : null;
}

/** Name of the AMAPI policy of a device, and of an enrollment profile. */
export const devicePolicyId = (deviceUuid: string): string => `d-${deviceUuid}`;
export const enrollmentPolicyId = (profileUuid: string): string => `e-${profileUuid}`;
