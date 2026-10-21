// =============================================================================
// Android apps (android-amapi §9.6, §12.3; lot AN-E1), shared by the server
// and the console: the kinds of the catalog, the options of an assignment of
// an Android app (they become one ApplicationPolicy entry of the compiled
// policy, setting key android:app[<package>]), the screens of the managed
// Google Play iframes and the features each one opens, the pages allowed to
// host them, and the content security policy those pages need.
// Exported by the index of shared (junction AN-A2).
// =============================================================================
import type { JsonValue } from '../mdm/policyContent';

/** Kinds of an Android app of the catalog (apps.kind, already admitted by the model): public Play app, private app
 *  of the tenant's enterprise, web app published in the iframe. */
export const ANDROID_APP_KINDS = ['play', 'private', 'web'] as const;
export type AndroidAppKind = typeof ANDROID_APP_KINDS[number];

/** Google names the web apps it publishes for an enterprise under this prefix. */
export const ANDROID_WEB_APP_PREFIX = 'com.google.enterprise.webapp.';

/** Install types an assignment may set. CUSTOM (AMAPI SDK installation) is not offered in v1. */
export const ANDROID_INSTALL_TYPES = ['AVAILABLE', 'PREINSTALLED', 'FORCE_INSTALLED', 'REQUIRED_FOR_SETUP', 'BLOCKED', 'KIOSK'] as const;
export type AndroidInstallType = typeof ANDROID_INSTALL_TYPES[number];

export const ANDROID_AUTO_UPDATE_MODES = ['AUTO_UPDATE_DEFAULT', 'AUTO_UPDATE_POSTPONED', 'AUTO_UPDATE_HIGH_PRIORITY'] as const;
export const ANDROID_PERMISSION_POLICIES = ['PROMPT', 'GRANT', 'DENY'] as const;

/** The options of an assignment of an Android app (assignments.options), validated by the server (apps/appPolicy.ts). */
export interface AndroidAppOptions {
  installType?: AndroidInstallType;
  autoUpdateMode?: typeof ANDROID_AUTO_UPDATE_MODES[number];
  minimumVersionCode?: number;
  /** FORCE_INSTALLED and PREINSTALLED only: 0 (none) to 10,000 (lower first). */
  installPriority?: number;
  installConstraint?: Array<{ networkTypeConstraint?: string; chargingConstraint?: string; deviceIdleConstraint?: string }>;
  /** JSON validated against the app's managed properties; exclusive with managedConfigurationTemplate. */
  managedConfiguration?: Record<string, JsonValue>;
  /** Saved from the managed configurations iframe (mcmId, digits only). */
  managedConfigurationTemplate?: { templateId: string; configurationVariables?: Record<string, string> };
  permissionGrants?: Array<{ permission: string; policy: typeof ANDROID_PERMISSION_POLICIES[number] }>;
  defaultPermissionPolicy?: typeof ANDROID_PERMISSION_POLICIES[number];
  /** Tracks of the app (closed testing) the devices may receive, among the app's appTracks. */
  accessibleTrackIds?: string[];
}

/** Screens of the managed Google Play iframes and the features each opens. Never an empty list: Google opens every
 *  feature (zero-touch included) for a token without features. ZERO_TOUCH_CUSTOMER_MANAGEMENT belongs to lot AN-F2. */
export const ANDROID_IFRAME_SCREENS = {
  catalog: ['PLAY_SEARCH', 'PRIVATE_APPS', 'WEB_APPS'],
  play_search: ['PLAY_SEARCH'],
  private_apps: ['PRIVATE_APPS'],
  web_apps: ['WEB_APPS'],
  store_builder: ['STORE_BUILDER'],
  managed_config: ['MANAGED_CONFIGURATIONS'],
} as const;
export type AndroidIframeScreen = keyof typeof ANDROID_IFRAME_SCREENS;

/** Console pages allowed to host an iframe (parentFrameUrl = the console's public origin + one of these paths).
 *  The managed configurations iframe is hosted by the page of an app of the catalog, or by the Android section of
 *  a policy (the app's entry in it). */
export const ANDROID_IFRAME_PAGES: ReadonlyArray<{ screens: readonly AndroidIframeScreen[]; path: RegExp }> = [
  { screens: ['catalog', 'play_search', 'private_apps', 'web_apps', 'store_builder'], path: /^\/apps\/android$/ },
  { screens: ['managed_config'], path: /^\/apps\/android\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/managed-config$/ },
  { screens: ['managed_config'], path: /^\/policies\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/android\/managed-config$/ },
];

/** The sources the pages hosting an iframe add to their content security policy (AN22), and only them. */
export const ANDROID_FRAME_SOURCES = ['https://play.google.com', 'https://enterprise.google.com'] as const;
export const ANDROID_SCRIPT_SOURCES = ['https://apis.google.com'] as const;

/** URL of the iframe of a screen (the token is short-lived and goes nowhere else: never stored, never logged). */
export function androidIframeUrl(screen: AndroidIframeScreen, token: string, o: { locale?: string; packageName?: string; mcmId?: string } = {}): string {
  const q = new URLSearchParams({ token });
  if (o.locale) q.set('locale', o.locale);
  if (screen === 'managed_config') {
    if (o.packageName) q.set('packageName', o.packageName);
    if (o.mcmId) q.set('mcmId', o.mcmId);
    return `https://play.google.com/managed/mcm?${q.toString()}`;
  }
  q.set('mode', 'SELECT');
  return `https://play.google.com/work/embedded/search?${q.toString()}`;
}

// ── Console (lot AN-E) ─────────────────────────────────────────────────────────

/** Types of a managed property of an app (managedProperties of applications.get). */
export const ANDROID_MANAGED_PROPERTY_TYPES = ['BOOL', 'STRING', 'INTEGER', 'CHOICE', 'MULTISELECT', 'HIDDEN', 'BUNDLE', 'BUNDLE_ARRAY'] as const;
export type AndroidManagedPropertyType = typeof ANDROID_MANAGED_PROPERTY_TYPES[number];

/** A managed property of an app's schema, as the catalog keeps it (minimized and bounded by the server). */
export interface AndroidManagedPropertyView {
  key: string;
  type: AndroidManagedPropertyType;
  /** Google's text (the developer's), shown as text, never as HTML. */
  title?: string;
  /** CHOICE and MULTISELECT: the values offered. */
  entries?: Array<{ name: string; value: string }>;
  nested?: AndroidManagedPropertyView[];
}

/** What a route shows of an Android app of the catalog (never Google's whole answer). */
export interface AndroidAppView {
  id: number;
  uuid: string;
  kind: AndroidAppKind;
  packageName: string;
  name: string;
  publisher: string | null;
  iconUrl: string | null;
  /** How its managed configuration is set: a form generated from its schema, the iframe only, or not at all. */
  managedConfiguration: 'json' | 'iframe' | 'none';
  oemConfig: boolean;
  tracks: Array<{ trackId: string; trackAlias: string | null }>;
  permissions: string[];
  minAndroidSdkVersion: number | null;
  metadataRefreshedAt: string | null;
  unavailable: boolean;
}

/** GET /api/android/apps/:id: the app, its managed configuration schema and the number of its assignments. */
export interface AndroidAppDetail extends AndroidAppView {
  tenantId: number;
  managedProperties: AndroidManagedPropertyView[] | null;
  assignments: number;
}

/** POST /api/android/web-tokens: the URL of one iframe (carries a short-lived token: kept in memory only). */
export interface AndroidIframeTokenView {
  screen: AndroidIframeScreen;
  features: string[];
  iframeUrl: string;
  parentFrameUrl: string;
}

/** Events of the managed Google Play iframes the console listens to (gapi.iframes). [AR: names and payloads checked
 *  against Google's iframes at AN-B/AN-J.] */
export const ANDROID_IFRAME_EVENTS = {
  productSelect: 'onproductselect',
  configUpdated: 'onconfigupdated',
  configDeleted: 'onconfigdeleted',
} as const;

/** Google's library of embedded iframes (gapi), loaded by the pages hosting a managed Google Play iframe only. */
export const ANDROID_GAPI_URL = 'https://apis.google.com/js/api.js';

/** The zero-touch portal may send its frame through Google's sign-in (the customer's Google account) [NV: checked
 *  against the real portal at AN-J]: that page alone also admits accounts.google.com. */
export const ANDROID_ZERO_TOUCH_FRAME_SOURCES = [...ANDROID_FRAME_SOURCES, 'https://accounts.google.com'] as const;

/**
 * The content security policy of every page of the console (client/nginx.conf, map $obligarth_csp): it never lets a
 * third-party site frame the console (frame-ancestors, plus X-Frame-Options), lets the console frame itself only, and
 * refuses plugins and a foreign <base>. Scripts, styles, images and connections stay unrestricted (no default-src):
 * the pages hosting a Google iframe get androidFrameCsp(CONSOLE_BASE_CSP), Google's frames added to frame-src only.
 */
export const CONSOLE_BASE_CSP = "base-uri 'self'; object-src 'none'; frame-src 'self'; frame-ancestors 'self'";
