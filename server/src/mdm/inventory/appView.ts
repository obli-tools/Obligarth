import type { DeviceAppCategory } from '@obligarth/shared';

// =============================================================================
// What the console shows of an app of the inventory (GET /api/mdm/devices/:id/apps), pure (unit tests, npm run
// test:mdm). The columns of device_apps do not mean the same on both families: Apple stores Version
// (CFBundleVersion, the build) in `version` and ShortVersion (the marketing version) in `short_version`; Android,
// AMAPI and the bridge agent alike, stores versionName in `version` and versionCode in `short_version`.
// =============================================================================

export type PlatformFamily = 'apple' | 'android';

export const familyOf = (platform: string | null | undefined): PlatformFamily => (platform === 'android' ? 'android' : 'apple');

/** managed when the MDM manages it; else system (the device's flag; on macOS, Apple's own bundles); else user. */
export function categoryOf(a: { managed: boolean; isSystem: boolean | null; identifier: string; platform: string | null }): DeviceAppCategory {
  if (a.managed) return 'managed';
  if (a.isSystem === true) return 'system';
  if (a.platform === 'macos' && a.identifier.startsWith('com.apple.')) return 'system';
  return 'user';
}

/** The version shown and the build, by family. */
export function versionsOf(family: PlatformFamily, version: string | null, shortVersion: string | null):
  { displayVersion: string | null; build: string | null } {
  const v = version || null;
  const s = shortVersion || null;
  return family === 'apple' ? { displayVersion: s ?? v, build: v } : { displayVersion: v ?? s, build: s };
}

/** The catalog's icon when it is an https URL (never another scheme in an <img>). */
export function catalogIcon(url: unknown): string | null {
  if (typeof url !== 'string' || url.length > 1024) return null;
  try {
    return new URL(url).protocol === 'https:' ? url : null;
  } catch {
    return null;
  }
}
