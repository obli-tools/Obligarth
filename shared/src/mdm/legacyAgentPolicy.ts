// =============================================================================
// Policies of the Android bridge agent (lot PONT-POL, agent 1.3.0): the section
// legacyAgent of a policy version, its setting keys (agent:*), the rules of its
// file paths, SSIDs, intents and Knox package lists, the device-administrator
// and Knox catalogues, and the vocabulary of the agent's compliance report.
// Pure, no import outside shared: the client, the server and the unit tests
// load it as is; the agent mirrors the rules (PathRules.kt, KioskModel.kt).
// =============================================================================

import type { JsonValue } from './policyContent';

/** The first agent that reads a policy (1.3.0): an older one never gets the key `policy` of its configuration. */
export const LEGACY_AGENT_POLICY_MIN_VERSION_CODE = 10300;
export const LEGACY_AGENT_POLICY_ARTIFACT_KEY = 'agent:policy';
/** policy.v on the wire. */
export const LEGACY_AGENT_POLICY_FORMAT = 1;
export const LEGACY_AGENT_SETTING_PREFIX = 'agent:';
export const LEGACY_AGENT_RESERVED_PACKAGE = 'tools.obli.obligarth.agent';
/** The pseudo item of the section in the issues and the sites of the secrets. */
export const LEGACY_AGENT_SECTION_ITEM = 'legacyAgent';
/** Seconds between two full reports of an agent that saw no change. */
export const LEGACY_AGENT_POLICY_REPORT_SECONDS = 21_600;

export const LEGACY_AGENT_POLICY_LIMITS = {
  files: 64, pathsPerFile: 4, wifi: 16, wifiRemove: 16, preferOver: 8, tiles: 48, certs: 8, knoxListItems: 64,
  pathMax: 240, pathSegments: 8, idRe: /^[a-z0-9][a-z0-9_-]{0,47}$/,
  /** The template text, and each file it renders for a device. */
  templateBytes: 32 * 1024,
  /** All the inline (rendered) files of one device. */
  inlineTotalBytes: 192 * 1024,
  pemBytes: 8 * 1024,
  storeFileBytes: 64 * 1024 * 1024,
  storeTenantBytes: 2 * 1024 * 1024 * 1024,
  /** Tile and logo images. */
  imageBytes: 256 * 1024,
  imagePixelsMax: 4096 * 4096,
  /** The canonical JSON of the compiled body of one device. */
  compiledBodyBytes: 384 * 1024,
  labelMax: 40, titleMax: 60, ssidMaxBytes: 32, pskMin: 8, pskMax: 63, eapFieldMax: 128,
  /** D15: 8 digits at least. */
  pinRe: /^[0-9]{8,12}$/,
  suspendMinutesMax: 240,
  reportItems: 200, reportDetail: 160, reportKeyMax: 160,
  pinIterations: 20_000,
  /** The custom fields of a device read by the templates ({{device.custom.<name>}}). */
  customKeyRe: /^[A-Za-z0-9_-]{1,64}$/,
} as const;

// ── Setting keys (one per inheritable unit) ──────────────────────────────────

export type AgentKeyFamily = 'file' | 'wifi' | 'wifi.remove' | 'kiosk' | 'dpm' | 'knox' | 'cert';

export const agentFileKey = (id: string): string => `agent:file[${id}]`;
export const agentWifiKey = (ssid: string): string => `agent:wifi[${ssid}]`;
export const agentWifiRemoveKey = (ssid: string): string => `agent:wifi.remove[${ssid}]`;
export const AGENT_KIOSK_KEY = 'agent:kiosk';
export const agentDpmKey = (field: string): string => `agent:dpm.${field}`;
export const agentKnoxKey = (field: string): string => `agent:knox.${field}`;
export const agentCertKey = (id: string): string => `agent:cert[${id}]`;
export const AGENT_WIPE_KEY = 'agent:dpm.maxFailedPasswordsForWipe';

/** The family and the instance (or field) of an agent setting key; null when it is not one. */
export function parseAgentKey(key: string): { family: AgentKeyFamily; instance?: string; field?: string } | null {
  if (typeof key !== 'string' || !key.startsWith(LEGACY_AGENT_SETTING_PREFIX)) return null;
  const rest = key.slice(LEGACY_AGENT_SETTING_PREFIX.length);
  if (rest === 'kiosk') return { family: 'kiosk' };
  const inst = /^(file|wifi\.remove|wifi|cert)\[(.+)\]$/s.exec(rest);
  if (inst) return { family: inst[1] as AgentKeyFamily, instance: inst[2] };
  const fld = /^(dpm|knox)\.([A-Za-z][A-Za-z0-9]{0,63})$/.exec(rest);
  if (fld) return { family: fld[1] as AgentKeyFamily, field: fld[2] };
  return null;
}

// ── Packages ─────────────────────────────────────────────────────────────────

const PACKAGE_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;

export const isAgentPackageName = (s: unknown): s is string => typeof s === 'string' && s.length <= 255 && PACKAGE_RE.test(s);

/** The agent's own package (or one of its sub-names). */
export const isOwnAgentPackage = (pkg: string): boolean =>
  pkg.toLowerCase() === LEGACY_AGENT_RESERVED_PACKAGE || pkg.toLowerCase().startsWith(`${LEGACY_AGENT_RESERVED_PACKAGE}.`);

/**
 * A package a Knox list of the section must not name (B9): the agent, the system ('android'), Knox itself, the
 * Settings app unless the section's kiosk is enabled (the kiosk's admin panel opens it), and, for disabledApps, the
 * packages the kiosk tiles launch.
 */
export function isReservedKnoxListPackage(pkg: string,
  ctx: { kioskEnabled: boolean; tilePackages: readonly string[]; list?: 'disabledApps' | 'uninstallBlocked' }): boolean {
  const p = pkg.toLowerCase();
  if (isOwnAgentPackage(p) || p === 'android') return true;
  if (p.startsWith('com.sec.enterprise.knox') || p.startsWith('com.samsung.android.knox')) return true;
  if (p === 'com.android.settings' && !ctx.kioskEnabled) return true;
  if ((ctx.list ?? 'disabledApps') === 'disabledApps' && ctx.tilePackages.some((t) => t.toLowerCase() === p)) return true;
  return false;
}

// ── File paths (§4.3; mirrored by the agent's PathRules.kt) ──────────────────

const SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,79}$/;

/**
 * A target path of a deposited file, relative to the external storage: '/' separators, 1 to 8 segments, 240
 * characters at most, each segment a plain name (never '.', '..', empty, nor a variable). Under Android/: the agent's
 * own data folder always; another app's data folder (Android/data/<package>/files/…) only with allowAppDataDir (D16);
 * anything else under Android/ (obb, media, another folder) is refused.
 */
export function isAgentFilePath(p: unknown, o: { allowAppDataDir?: boolean } = {}): boolean {
  if (typeof p !== 'string' || p.length === 0 || p.length > LEGACY_AGENT_POLICY_LIMITS.pathMax) return false;
  const segs = p.split('/');
  if (segs.length > LEGACY_AGENT_POLICY_LIMITS.pathSegments) return false;
  if (!segs.every((s) => SEGMENT_RE.test(s) && s !== '.' && s !== '..' && !s.endsWith('.') && !s.endsWith(' '))) return false;
  if (segs[0].toLowerCase() !== 'android') return true;
  // Android/ itself and anything but Android/data/<package>/… : refused (obb above all).
  if (segs.length < 2 || segs[1].toLowerCase() !== 'data') return false;
  const pkg = segs[2];
  if (pkg === undefined || !isAgentPackageName(pkg)) return false;
  if (isOwnAgentPackage(pkg)) return segs.length >= 4;
  return o.allowAppDataDir === true && segs.length >= 5 && segs[3] === 'files';
}

/** The key two paths collide on (the storage is case-insensitive). */
export const agentPathKey = (p: string): string => p.toLowerCase();

// ── SSIDs ────────────────────────────────────────────────────────────────────

function utf8Length(s: string): number {
  let n = 0;
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    n += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
  }
  return n;
}

/** An SSID: 1 to 32 UTF-8 bytes, printable, no square bracket (it is the instance of a setting key). */
export function isValidSsid(s: unknown): s is string {
  if (typeof s !== 'string' || s.length === 0) return false;
  const n = utf8Length(s);
  if (n < 1 || n > LEGACY_AGENT_POLICY_LIMITS.ssidMaxBytes) return false;
  return !/[\u0000-\u001f\u007f-\u009f[\]]/.test(s);
}

// ── Kiosk tiles: intents and URLs (B1; mirrored by the agent's KioskModel.kt) ──

/** An intent URI with its scheme prefix in lower case ('Intent://' → 'intent://'); null when it is not one. */
export function normalizeIntentUri(uri: unknown): string | null {
  if (typeof uri !== 'string' || uri.length === 0 || uri.length > 2048) return null;
  const m = /^intent:/i.exec(uri);
  if (!m) return null;
  return `intent:${uri.slice(m[0].length)}`;
}

/** A well-formed intent URI: intent:…#Intent;…;end. */
export function isIntentUriWellFormed(uri: unknown): boolean {
  const n = normalizeIntentUri(uri);
  return n !== null && n.includes('#Intent;') && n.endsWith(';end') && !/[\u0000-\u001f\u007f]/.test(n);
}

/**
 * Does an intent URI reach what a kiosk tile must never reach (case-insensitive)? The agent's package named anywhere
 * (component=, package=, a selector…), a selector at all (SEL;), launch flags (set by the agent only), a browser
 * fallback URL, and a file or content data scheme (in the scheme= extra or as the data before '#').
 */
export function isUnsafeIntentUri(uri: string): boolean {
  const u = uri.toLowerCase();
  if (u.includes(LEGACY_AGENT_RESERVED_PACKAGE)) return true;
  if (u.includes(';sel;') || u.includes('#intent;sel;')) return true;
  if (u.includes('launchflags=')) return true;
  if (u.includes('s.browser_fallback_url=')) return true;
  if (/[;#]scheme=(file|content)(;|$)/.test(u)) return true;
  const data = u.replace(/^intent:/, '').split('#')[0];
  if (/^(\/\/)?(file|content):/.test(data)) return true;
  return false;
}

/** A tile URL: http or https, at most 2048 characters. */
export function isAgentTileUrl(url: unknown): boolean {
  if (typeof url !== 'string' || url.length === 0 || url.length > 2048 || /[\u0000- \u007f]/.test(url)) return false;
  return /^https?:\/\/[^/\s]+/i.test(url);
}

// ── Catalogues ───────────────────────────────────────────────────────────────

export const AGENT_PASSWORD_QUALITIES = ['unspecified', 'something', 'numeric', 'numeric_complex', 'alphabetic', 'alphanumeric', 'complex'] as const;
export type AgentPasswordQuality = typeof AGENT_PASSWORD_QUALITIES[number];
export const AGENT_KEYGUARD_FEATURES = ['camera', 'notifications', 'unredacted_notifications', 'trust_agents', 'fingerprint'] as const;

export interface AgentDpmFieldSpec {
  field: string;
  type: 'bool' | 'int' | 'enum' | 'flags';
  min?: number;
  max?: number;
  values?: readonly string[];
  /** The value the agent restores when the key leaves the policy; null: nothing to restore (a check or a prompt). */
  undo: JsonValue;
  /** A setting that can erase the device: a second approver at publication, corporate devices only. */
  wipe?: true;
  corporateOnly?: true;
  /** Checked only, never set (requireEncryption). */
  complianceOnly?: true;
}

/** Device-administrator settings (API 24), §2.4. */
export const AGENT_DPM_FIELDS: readonly AgentDpmFieldSpec[] = [
  { field: 'cameraDisabled', type: 'bool', undo: false },
  { field: 'passwordQuality', type: 'enum', values: AGENT_PASSWORD_QUALITIES, undo: 'unspecified' },
  { field: 'passwordMinLength', type: 'int', min: 0, max: 16, undo: 0 },
  { field: 'passwordMinLetters', type: 'int', min: 0, max: 16, undo: 0 },
  { field: 'passwordMinNumeric', type: 'int', min: 0, max: 16, undo: 0 },
  { field: 'passwordMinSymbols', type: 'int', min: 0, max: 16, undo: 0 },
  { field: 'passwordHistoryLength', type: 'int', min: 0, max: 50, undo: 0 },
  { field: 'passwordExpirationDays', type: 'int', min: 0, max: 730, undo: 0 },
  { field: 'keyguardDisabledFeatures', type: 'flags', values: AGENT_KEYGUARD_FEATURES, undo: [] },
  { field: 'maxTimeToLockSeconds', type: 'int', min: 0, max: 3600, undo: 0 },
  { field: 'maxFailedPasswordsForWipe', type: 'int', min: 0, max: 30, undo: 0, wipe: true, corporateOnly: true },
  { field: 'requireEncryption', type: 'bool', undo: null, complianceOnly: true },
  { field: 'promptPasswordChange', type: 'bool', undo: null },
];
export type AgentDpmField = string;

export interface AgentKnoxFieldSpec { field: string; type: 'bool' | 'packages'; undo: JsonValue }

const KNOX_BOOLS = [
  'camera', 'microphone', 'bluetooth', 'nfc', 'cellularData', 'smsIncoming', 'smsOutgoing', 'mms', 'tethering', 'unknownSources',
  'clipboard', 'screenCapture', 'usbDebugging', 'usbMediaPlayer', 'mockLocation', 'factoryReset', 'airplaneMode', 'safeMode',
  'statusBarExpansion', 'settingsChanges', 'multiWindow', 'sdCard', 'otaUpgrade', 'wifiUserProfiles', 'appUninstall',
] as const;

/** Knox restrictions (licensed devices only), §2.5: true means allowed; the lists name packages. */
export const AGENT_KNOX_FIELDS: readonly AgentKnoxFieldSpec[] = [
  ...KNOX_BOOLS.map((field) => ({ field, type: 'bool' as const, undo: true })),
  { field: 'disabledApps', type: 'packages', undo: [] },
  { field: 'uninstallBlocked', type: 'packages', undo: [] },
];
export type AgentKnoxField = string;

export const agentDpmSpec = (field: string): AgentDpmFieldSpec | undefined => AGENT_DPM_FIELDS.find((f) => f.field === field);
export const agentKnoxSpec = (field: string): AgentKnoxFieldSpec | undefined => AGENT_KNOX_FIELDS.find((f) => f.field === field);

// ── The section (policy_versions.content.sections.legacyAgent) ──────────────

export type SecretSlot = { $secret: string } | { $secretValue: string };

export interface AgentImageRef { sha256: string; size: number; name: string }

export interface AgentFileItem {
  id: string;
  /** 1 to 4 target paths, the same content deposited to each (C8). */
  paths: string[];
  /** Default false: admits Android/data/<package>/files/… (C8, D16). */
  allowAppDataDir?: boolean;
  source:
    | { kind: 'store'; sha256: string; size: number; name: string }
    | { kind: 'template'; text: string; encoding: 'text' | 'json' };
  /** Default always (drift corrected). */
  overwrite?: 'always' | 'if_absent';
  /** Default keep. */
  onRemove?: 'keep' | 'delete';
  /** Default true. */
  mediaScan?: boolean;
}

export interface AgentWifiEap {
  identity: string;
  anonymousIdentity?: string | null;
  password: SecretSlot;
  phase2: 'mschapv2';
  caPem?: string | null;
  /** A store row of kind certificate, inlined when the policy is delivered. */
  caFile?: AgentImageRef | null;
  domainSuffixMatch?: string | null;
  /** Default false: a network without a CA only when this is set (not recommended, D6). */
  allowNoCa?: boolean;
}

export interface AgentWifiItem {
  ssid: string;
  hidden?: boolean;
  /** 0 to 100, default 40. */
  priority?: number;
  /** Default true. */
  autoConnect?: boolean;
  /** SSIDs (8 at most): switch to this network when connected to one of them (C2). */
  preferOver?: string[];
  security: 'wpa2_psk' | 'wpa2_eap_peap';
  psk?: SecretSlot;
  eap?: AgentWifiEap;
}

export type AgentTileAction =
  | { type: 'app'; package: string }
  | { type: 'url'; url: string; package?: string | null }
  | { type: 'intent'; uri: string };

export interface AgentTile {
  id: string;
  label: string;
  image?: AgentImageRef | null;
  launchOnStart?: boolean;
  action: AgentTileAction;
}

export interface AgentKioskHard {
  hideSystemBar?: boolean;
  disableStatusBarExpansion?: boolean;
  disableTaskManager?: boolean;
  blockKeys?: Array<'home' | 'recent' | 'back' | 'menu' | 'search'>;
  disableSettingsChanges?: boolean;
}

export interface AgentKiosk {
  enabled: boolean;
  title?: string | null;
  showDeviceName?: boolean;
  /** 2 to 5, default 3. */
  columns?: number;
  logo?: AgentImageRef | null;
  tiles: AgentTile[];
  /** Purpose policy.kiosk_pin. */
  exitPin: SecretSlot;
  hard?: AgentKioskHard;
}

export const AGENT_KIOSK_BLOCK_KEYS = ['home', 'recent', 'back', 'menu', 'search'] as const;

export interface AgentCertItem { id: string; name: string; pem: string }

export interface LegacyAgentPolicySection {
  files?: AgentFileItem[];
  wifi?: AgentWifiItem[];
  /** SSIDs to remove (Knox only). */
  wifiRemove?: string[];
  kiosk?: AgentKiosk | null;
  dpm?: Record<AgentDpmField, JsonValue>;
  knox?: Record<AgentKnoxField, JsonValue>;
  certs?: AgentCertItem[];
}

/** The purposes of the vault secrets of the section. */
export const AGENT_SECRET_PURPOSES = { wifi: 'policy.wifi_password', kioskPin: 'policy.kiosk_pin' } as const;

// ── The compliance report (§2.6, §8.4) ──────────────────────────────────────

export const AGENT_POLICY_ITEM_STATES = ['compliant', 'non_compliant', 'pending', 'pending_licence', 'unsupported', 'error'] as const;
export type AgentPolicyItemState = typeof AGENT_POLICY_ITEM_STATES[number];
export const AGENT_POLICY_REPORT_STATES = ['applied', 'partial', 'pending', 'error', 'none'] as const;
export type AgentPolicyReportState = typeof AGENT_POLICY_REPORT_STATES[number];

export const AGENT_POLICY_ITEM_CODES = [
  'ok', 'unchanged', 'applied', 'undone',
  'file_written', 'file_unchanged', 'file_present', 'file_deleted', 'permission_missing', 'path_forbidden',
  'download_failed', 'download_limited', 'hash_mismatch', 'storage_unavailable', 'io_error',
  'wifi_added', 'wifi_updated', 'wifi_disabled', 'wifi_foreign_profile', 'wifi_add_failed', 'wifi_removed', 'wifi_preferred',
  'admin_inactive', 'admin_policy_missing', 'password_insufficient', 'encryption_missing',
  'knox_required', 'knox_error', 'knox_refused', 'knox_method_missing', 'blocked_by_order',
  'home_not_default', 'kiosk_foreign_lockdown', 'kiosk_active', 'kiosk_suspended', 'kiosk_disabled', 'image_unreadable',
  'app_missing', 'intent_invalid',
  'cert_installed', 'policy_version_unsupported', 'invalid_item', 'undeliverable', 'internal',
  // Compile-time drops (body.dropped), reported by the agent as error/<code>; wipe_withheld as pending.
  'path_conflict', 'inline_too_large', 'template_too_large', 'invalid_json', 'wipe_without_password',
  'foreign_tenant_resource', 'wipe_withheld',
] as const;
export type AgentPolicyItemCode = typeof AGENT_POLICY_ITEM_CODES[number];
/** Any code the server stores (robustness: a future agent's code is shown as is). */
export const AGENT_POLICY_CODE_RE = /^[a-z_]{1,48}$/;

/** The drops of the compilation: the item leaves the body, the artifact stays deliverable. */
export const AGENT_POLICY_DROP_CODES = ['path_conflict', 'inline_too_large', 'template_too_large', 'invalid_json', 'wipe_without_password',
  'foreign_tenant_resource'] as const;
export type AgentPolicyDropCode = typeof AGENT_POLICY_DROP_CODES[number];

export interface AgentPolicyReportItem { key: string; state: AgentPolicyItemState; code: string; detail?: string }

/** The state of an agent's report from its items (the agent computes the same). */
export function agentReportStateOf(items: ReadonlyArray<Pick<AgentPolicyReportItem, 'state'>>, hasPolicy: boolean): AgentPolicyReportState {
  if (!hasPolicy) return 'none';
  if (items.some((i) => i.state === 'error')) return 'error';
  if (items.some((i) => i.state === 'non_compliant')) return 'partial';
  if (items.some((i) => i.state === 'pending')) return 'pending';
  return 'applied';
}

/** The human family of a key for the console ('file', 'wifi'…) and its instance, or the key itself. */
export function agentKeyLabelParts(key: string): { family: AgentKeyFamily | 'policy' | null; name: string } {
  if (key === LEGACY_AGENT_POLICY_ARTIFACT_KEY) return { family: 'policy', name: '' };
  const k = parseAgentKey(key);
  if (!k) return { family: null, name: key };
  return { family: k.family, name: k.instance ?? k.field ?? '' };
}
