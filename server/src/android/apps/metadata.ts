// What the catalog keeps of an app read at Google (enterprises.applications.get, android-amapi §9.6; lot AN-E1):
// the title, the author, an HTTPS icon, the distribution channel, the minimum SDK, the managed configuration schema
// (bounded), the permissions and the tracks. Nothing else (descriptions, screenshots, prices, countries): Google's
// answer can be large and its text is not ours to store. The kind of an app (play, private, web) is derived from the
// distribution channel and the package, never taken from the client. Pure (unit tests: metadata.test.ts).
import {
  type AmapiApplication, type AmapiManagedProperty, ANDROID_WEB_APP_PREFIX, type AndroidAppKind,
} from '@obligarth/shared';

export const MANAGED_PROPERTY_TYPES = ['BOOL', 'STRING', 'INTEGER', 'CHOICE', 'MULTISELECT', 'HIDDEN', 'BUNDLE', 'BUNDLE_ARRAY'] as const;
export type ManagedPropertyType = typeof MANAGED_PROPERTY_TYPES[number];

export interface AndroidManagedProperty {
  key: string;
  type: ManagedPropertyType;
  title?: string;
  /** CHOICE and MULTISELECT: the values offered. */
  entries?: Array<{ name: string; value: string }>;
  nested?: AndroidManagedProperty[];
}

export interface AndroidAppMetadata {
  /** Version of this shape (a change of the minimization refreshes the metadata). */
  v: 1;
  languageCode: string;
  distributionChannel: string | null;
  minAndroidSdkVersion: number | null;
  /** null: unknown (not read yet, or too large to keep: the managed configuration then goes by the iframe only). */
  managedProperties: AndroidManagedProperty[] | null;
  managedPropertiesTruncated: boolean;
  permissions: string[];
  tracks: Array<{ trackId: string; trackAlias: string | null }>;
  /** An OEMConfig app (Knox Service Plugin, Zebra…): its configuration goes by the iframe only (CFG-11). */
  oemConfig: boolean;
}

export interface MinimizedApplication {
  title: string;
  author: string | null;
  iconUrl: string | null;
  metadata: AndroidAppMetadata;
}

/** OEMConfig apps known to this release (their schemas run to thousands of properties: iframe only). [NV] the list
 *  of OEMConfig apps of the managed Google Play is not published; extended at each finding. */
export const OEMCONFIG_PACKAGES: ReadonlySet<string> = new Set([
  'com.samsung.android.knox.kpu',            // Knox Service Plugin
  'com.zebra.oemconfig.common',              // Zebra OEMConfig (Android 11 and later)
  'com.zebra.oemconfig.release',             // Zebra OEMConfig (legacy)
  'com.honeywell.oemconfig',                 // Honeywell
]);

export const METADATA_LIMITS = {
  properties: 2000, depth: 8, entries: 500, text: 200, permissions: 500, tracks: 50, bytes: 512 * 1024,
} as const;

const clip = (s: unknown, n: number): string | null => (typeof s === 'string' && s.length > 0 ? s.slice(0, n) : null);
const KEY_RE = /^[A-Za-z0-9_.:\-]{1,200}$/;
const PERMISSION_RE = /^[A-Za-z][A-Za-z0-9_.]{0,254}$/;
const TRACK_RE = /^[A-Za-z0-9_-]{1,100}$/;
const LANG_RE = /^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$/;

/** An HTTPS URL of an image of Google, or null (anything else is dropped: never http, data: nor javascript:). */
export function safeIconUrl(u: unknown): string | null {
  if (typeof u !== 'string' || u.length > 1024) return null;
  try {
    const url = new URL(u);
    if (url.protocol !== 'https:' || url.username || url.password) return null;
    return url.toString();
  } catch {
    return null;
  }
}

function minimizeProperties(list: unknown, depth: number, budget: { n: number }): AndroidManagedProperty[] | null {
  if (!Array.isArray(list)) return [];
  if (depth > METADATA_LIMITS.depth) return null;
  const out: AndroidManagedProperty[] = [];
  for (const raw of list as AmapiManagedProperty[]) {
    if (!raw || typeof raw !== 'object') continue;
    if (++budget.n > METADATA_LIMITS.properties) return null;
    const key = typeof raw.key === 'string' && KEY_RE.test(raw.key) ? raw.key : null;
    const type = (MANAGED_PROPERTY_TYPES as readonly string[]).includes(String(raw.type)) ? raw.type as ManagedPropertyType : null;
    // A property without a usable key or type cannot be configured by JSON: the whole schema is unknown then.
    if (!key || !type) return null;
    const p: AndroidManagedProperty = { key, type };
    const title = clip(raw.title, METADATA_LIMITS.text);
    if (title) p.title = title;
    if (type === 'CHOICE' || type === 'MULTISELECT') {
      const entries = Array.isArray(raw.entries) ? raw.entries : [];
      if (entries.length > METADATA_LIMITS.entries) return null;
      p.entries = entries.filter((e) => e && typeof e.value === 'string').map((e) => ({
        name: clip(e.name, METADATA_LIMITS.text) ?? String(e.value).slice(0, METADATA_LIMITS.text), value: String(e.value).slice(0, 1024),
      }));
    }
    if (type === 'BUNDLE' || type === 'BUNDLE_ARRAY') {
      const nested = minimizeProperties(raw.nestedProperties, depth + 1, budget);
      if (nested === null) return null;
      p.nested = nested;
    }
    out.push(p);
  }
  return out;
}

/** The kind of an app as Google publishes it (null: the distribution channel is unknown). */
export function kindOf(packageName: string, distributionChannel: unknown): AndroidAppKind | null {
  if (packageName.startsWith(ANDROID_WEB_APP_PREFIX)) return 'web';
  if (distributionChannel === 'PUBLIC_GOOGLE_HOSTED') return 'play';
  if (distributionChannel === 'PRIVATE_GOOGLE_HOSTED' || distributionChannel === 'PRIVATE_SELF_HOSTED') return 'private';
  return null;
}

export function minimizeApplication(packageName: string, a: AmapiApplication, languageCode: string): MinimizedApplication {
  const budget = { n: 0 };
  let props = minimizeProperties(a.managedProperties, 0, budget);
  let truncated = props === null;
  const permissions = [...new Set((Array.isArray(a.permissions) ? a.permissions : [])
    .map((p) => (p && typeof p.permissionId === 'string' && PERMISSION_RE.test(p.permissionId) ? p.permissionId : null))
    .filter((p): p is string => p !== null))].sort().slice(0, METADATA_LIMITS.permissions);
  const tracks = (Array.isArray(a.appTracks) ? a.appTracks : [])
    .filter((t) => t && typeof t.trackId === 'string' && TRACK_RE.test(t.trackId))
    .slice(0, METADATA_LIMITS.tracks)
    .map((t) => ({ trackId: String(t.trackId), trackAlias: clip(t.trackAlias, METADATA_LIMITS.text) }));
  const metadata: AndroidAppMetadata = {
    v: 1,
    languageCode: LANG_RE.test(languageCode) ? languageCode : 'en',
    distributionChannel: clip(a.distributionChannel, 64),
    minAndroidSdkVersion: Number.isInteger(a.minAndroidSdkVersion) && Number(a.minAndroidSdkVersion) > 0 ? Number(a.minAndroidSdkVersion) : null,
    managedProperties: props,
    managedPropertiesTruncated: truncated,
    permissions,
    tracks,
    oemConfig: OEMCONFIG_PACKAGES.has(packageName),
  };
  if (Buffer.byteLength(JSON.stringify(metadata)) > METADATA_LIMITS.bytes) {
    props = null;
    truncated = true;
    metadata.managedProperties = null;
    metadata.managedPropertiesTruncated = true;
  }
  return {
    title: clip(a.title, 255) ?? packageName,
    author: clip(a.author, 255),
    iconUrl: safeIconUrl(a.iconUrl) ?? safeIconUrl(a.smallIconUrl),
    metadata,
  };
}

/** The metadata of a row of apps (jsonb), or null when absent or of another shape. */
export function metadataOf(raw: unknown): AndroidAppMetadata | null {
  const m = typeof raw === 'string' ? (() => { try { return JSON.parse(raw); } catch { return null; } })() : raw;
  if (!m || typeof m !== 'object' || (m as { v?: unknown }).v !== 1) return null;
  return m as AndroidAppMetadata;
}
