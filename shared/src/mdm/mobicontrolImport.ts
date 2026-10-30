// =============================================================================
// Import of MobiControl kiosk templates and profiles into the section of the
// bridge agent (lot PONT-POL §12.2, §12.3). Pure, run in the browser and by
// the unit tests: the lockdown templates (JSON items or plain HTML), the
// lockdown payloads of the profiles export (menu items, flags, group paths),
// the tiles of a template, and the classification of the other payloads
// (restrictions, password, Wi-Fi) into a draft fragment. It returns plain data
// only (strings, numbers): the imported HTML is read with regular expressions
// and never handed to a DOM (B12). Masked values of the export become
// REQUIRED_INPUT, never a value.
// =============================================================================

import { isAgentPackageName, isUnsafeIntentUri, normalizeIntentUri, type AgentKioskHard, type AgentTileAction } from './legacyAgentPolicy';

/** A value the export masks: the operator types it in the console. */
export const REQUIRED_INPUT = '\u0000REQUIRED_INPUT\u0000';
/** The markers of a masked value in an export (the dialog may add its own). */
export const MOBICONTROL_MASK_MARKERS = ['«masqué»', '«masked»', '********'] as const;

export type MobiControlIssueCode = 'index_without_menu_item' | 'menu_item_not_in_template' | 'mobicontrol_target' | 'url_scheme_assumed'
  | 'intent_unsafe' | 'image_missing' | 'template_html_truncated' | 'unknown_action' | 'wifi_parent_review' | 'wifi_security_unsupported'
  | 'security_upgraded' | 'ssid_review' | 'wipe_threshold' | 'template_unreadable';

export interface MobiControlIssue { code: MobiControlIssueCode; tile?: string; detail?: string }

// ── Templates ────────────────────────────────────────────────────────────────

export interface MobiControlTemplate { referenceId: string | null; name: string; html: string; truncated: boolean }

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

/** The lockdown templates of picked files: a JSON item {"$type":"LockdownTemplateItem","Content",…} despite its .html
 *  extension, an array of them, or plain HTML. Escaped CRLF are unescaped. */
export function parseTemplates(files: ReadonlyArray<{ name: string; text: string }>): MobiControlTemplate[] {
  const out: MobiControlTemplate[] = [];
  const add = (referenceId: string | null, name: string, html: string): void => {
    const h = html.replace(/\\r\\n/g, '\n').replace(/\r\n/g, '\n');
    out.push({ referenceId, name: name.slice(0, 200), html: h, truncated: !/<\/html>/i.test(h) });
  };
  for (const f of files) {
    const t = f.text.replace(/^﻿/, '');
    let json: unknown = null;
    if (/^\s*[[{]/.test(t)) { try { json = JSON.parse(t); } catch { json = null; } }
    const items = Array.isArray(json) ? json : json ? [json] : [];
    const parsed = items.filter((x): x is Record<string, unknown> => !!x && typeof x === 'object' && typeof (x as Record<string, unknown>).Content === 'string');
    if (parsed.length) {
      for (const x of parsed) add(str(x.ReferenceId) || null, str(x.DisplayName) || str(x.Name) || f.name, str(x.Content));
    } else {
      add(/^([0-9a-f-]{36})\.html?$/i.exec(f.name)?.[1]?.toLowerCase() ?? null, f.name, t);
    }
  }
  return out;
}

// ── Lockdown payloads of the profiles export ─────────────────────────────────

export interface MobiControlMenuItem { displayName: string; programPath: string; programImage: string; launchOnStartup: boolean }

export interface MobiControlLockdown {
  profileName: string;
  groupPaths: string[];
  flags: { DisableStatusBarExpansion: boolean; HideSystemBar: boolean; DisableSettingsChanges: boolean; SamsungSoftBlocking: boolean; HardBlocking: boolean };
  menuItems: MobiControlMenuItem[];
  templateRef: string | null;
  templateName: string | null;
}

const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});

/** The payload values of a profile of the export. */
function payloadValues(profile: Record<string, unknown>): Record<string, unknown>[] {
  return asArray(obj(profile.payloads).PayloadValues).map(obj);
}

function profileName(profile: Record<string, unknown>): string {
  return (str(profile.name) || str(obj(profile.summary).Name) || '?').slice(0, 200);
}

function groupPathsOf(profile: Record<string, unknown>): string[] {
  return asArray(obj(profile.assignment).TargetDeviceGroups).map(obj).filter((g) => g.Excluded !== true)
    .map((g) => str(g.DeviceGroupPath)).filter(Boolean).slice(0, 100);
}

/** The lockdown payloads of a profiles export (JSON array): FormValue null and LegacyContract.Name AndroidSamsung_LockdownSection. */
export function lockdownPayloads(profiles: unknown): MobiControlLockdown[] {
  const out: MobiControlLockdown[] = [];
  for (const p of asArray(profiles).map(obj)) {
    for (const pv of payloadValues(p)) {
      const lc = obj(pv.LegacyContract);
      if (pv.FormValue !== null || lc.Name !== 'AndroidSamsung_LockdownSection') continue;
      const control = asArray(lc.Controls).map(obj)[0] ?? {};
      out.push({
        profileName: profileName(p), groupPaths: groupPathsOf(p),
        flags: {
          DisableStatusBarExpansion: lc.DisableStatusBarExpansion === true, HideSystemBar: lc.HideSystemBar === true,
          DisableSettingsChanges: lc.DisableSettingsChanges === true, SamsungSoftBlocking: lc.SamsungSoftBlocking === true,
          HardBlocking: lc.HardBlocking === true,
        },
        menuItems: asArray(control.MenuItems).map(obj).map((m) => ({
          displayName: str(m.DisplayName).slice(0, 200), programPath: str(m.ProgramPath).slice(0, 2048),
          programImage: str(m.ProgramImage).slice(0, 300), launchOnStartup: m.LaunchOnStartup === true,
        })),
        templateRef: str(control.TemplateFileReferenceId).toLowerCase() || null,
        templateName: str(control.TemplateName) || null,
      });
    }
  }
  return out;
}

// ── Tiles ────────────────────────────────────────────────────────────────────

export interface MobiControlTile {
  /** The MCLink index of the template. */
  index: number;
  label: string;
  /** null: to complete by the operator (an unknown or unsafe action, a template without its profile). */
  action: AgentTileAction | null;
  /** The name of the picked image file the tile uses, or null (the app's icon). */
  image: string | null;
  launchOnStart: boolean;
  issues: MobiControlIssueCode[];
}

export interface MobiControlKioskImport {
  tiles: MobiControlTile[];
  /** The picked image of the template's logo (<MCImg_logo…>), or null. */
  logo: string | null;
  showDeviceName: boolean;
  columns: number;
  issues: MobiControlIssue[];
}

/** The action of a MobiControl program path. */
export function actionOfProgramPath(path: string): { action: AgentTileAction | null; issue: MobiControlIssueCode | null } {
  const p = path.trim();
  const launch = /^launch:\/\/(.+)$/i.exec(p);
  if (launch) {
    const pkg = launch[1].replace(/\/+$/, '');
    if (!isAgentPackageName(pkg)) return { action: null, issue: 'unknown_action' };
    return { action: { type: 'app', package: pkg }, issue: pkg.toLowerCase().startsWith('net.soti.') ? 'mobicontrol_target' : null };
  }
  const browser = /^browsers?:\/\/(.+)$/i.exec(p);
  if (browser) return { action: { type: 'url', url: `https://${browser[1]}` }, issue: 'url_scheme_assumed' };
  const intent = normalizeIntentUri(p);
  if (intent) {
    if (isUnsafeIntentUri(intent)) return { action: null, issue: 'intent_unsafe' };
    return { action: { type: 'intent', uri: intent }, issue: null };
  }
  return { action: null, issue: 'unknown_action' };
}

/** The picked image a template or program image names: URL-decoded, case-insensitive, an '<8 hex>-' prefix ignored. */
export function matchImage(ref: string, images: readonly string[]): string | null {
  let name = ref;
  try { name = decodeURIComponent(ref); } catch { /* as is */ }
  name = name.split(/[\\/]/).pop() ?? name;
  const strip = (s: string): string => s.toLowerCase().replace(/^[0-9a-f]{8}-/, '');
  const want = strip(name);
  if (!want) return null;
  return images.find((i) => strip(i) === want) ?? images.find((i) => strip(i).replace(/\.[a-z0-9]+$/, '') === want.replace(/\.[a-z0-9]+$/, '')) ?? null;
}

/**
 * The tiles of a template: comments stripped, rows split on <div class="row">, each <li><a href="<MCLinkN>"><img
 * src="<MCImg_…>"> (a line break inside a tile tolerated) joined to MenuItems[N]. `menuItems` null: a template without
 * its profile (labels from nothing, actions to complete).
 */
export function tilesOf(html: string, menuItems: readonly MobiControlMenuItem[] | null, images: readonly string[] = []): MobiControlKioskImport {
  const issues: MobiControlIssue[] = [];
  const clean = html.replace(/<!--[\s\S]*?-->/g, '');
  if (!/<\/html>/i.test(html)) issues.push({ code: 'template_html_truncated' });
  const rows = clean.split(/<div\s+class\s*=\s*"row"\s*>/i);
  const tiles: MobiControlTile[] = [];
  const seen = new Set<number>();
  let columns = 0;
  const tileRe = /<li>\s*<a\s+href\s*=\s*"<MCLink(\d+)>"\s*>\s*<img\s+src\s*=\s*"<MCImg_([^>]*)>"/gis;
  for (const row of rows) {
    let inRow = 0;
    for (const m of row.matchAll(tileRe)) {
      const index = Number(m[1]);
      if (seen.has(index)) continue;
      seen.add(index);
      inRow++;
      const t: MobiControlTile = { index, label: '', action: null, image: null, launchOnStart: false, issues: [] };
      const item = menuItems ? menuItems[index] : undefined;
      if (menuItems && !item) t.issues.push('index_without_menu_item');
      if (item) {
        t.label = item.displayName.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 40);
        t.launchOnStart = item.launchOnStartup;
        const a = actionOfProgramPath(item.programPath);
        t.action = a.action;
        if (a.issue) t.issues.push(a.issue);
      }
      t.image = matchImage(m[2], images) ?? (item?.programImage ? matchImage(item.programImage, images) : null);
      if (!t.image) t.issues.push('image_missing');
      tiles.push(t);
    }
    columns = Math.max(columns, inRow);
  }
  if (menuItems) {
    menuItems.forEach((mi, i) => { if (!seen.has(i)) issues.push({ code: 'menu_item_not_in_template', tile: mi.displayName.slice(0, 40) }); });
  }
  const logoRef = /<img\s+[^>]*src\s*=\s*"<MCImg_(logo[^>]*)>"/i.exec(clean)?.[1] ?? null;
  return {
    tiles, logo: logoRef ? matchImage(logoRef, images) : null, showDeviceName: /%MCDEVICENAME%/i.test(clean),
    columns: Math.min(5, Math.max(2, columns || 3)), issues,
  };
}

/** The hard options of the kiosk from the lockdown flags. */
export function hardOfLockdown(flags: MobiControlLockdown['flags']): AgentKioskHard {
  const hard: AgentKioskHard = {};
  if (flags.DisableStatusBarExpansion) hard.disableStatusBarExpansion = true;
  if (flags.HideSystemBar) hard.hideSystemBar = true;
  if (flags.DisableSettingsChanges) hard.disableSettingsChanges = true;
  return hard;
}

// ── Other payloads: restrictions, password, Wi-Fi (§12.3) ───────────────────

export type MobiControlPayloadKind = 'restrictions' | 'authentication' | 'wifi' | 'certificates' | 'settings_manager' | 'lockdown' | 'other';

/** The kind of a payload by the root key of its FormValue (FormKey is masked in the exports). */
export function classifyPayload(pv: Record<string, unknown>): MobiControlPayloadKind {
  if (pv.FormValue === null && obj(pv.LegacyContract).Name === 'AndroidSamsung_LockdownSection') return 'lockdown';
  const keys = Object.keys(obj(pv.FormValue));
  if (keys.includes('FeatureControlContainer')) return 'restrictions';
  if (keys.includes('AuthenticationSection')) return 'authentication';
  if (keys.includes('WIFI')) return 'wifi';
  if (keys.includes('Certificates') && keys.length === 1) return 'certificates';
  if (keys.includes('General') && keys.includes('Display')) return 'settings_manager';
  return 'other';
}

/** The booleans of a FeatureControlContainer as dotted paths; a '…Children' node counts only when its parent is true. */
export function flattenFeatureControls(v: unknown, prefix = '', out: Map<string, boolean> = new Map(), depth = 0): Map<string, boolean> {
  if (depth > 12) return out;
  const o = obj(v);
  for (const [k, x] of Object.entries(o)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (typeof x === 'boolean') { out.set(path, x); continue; }
    if (x && typeof x === 'object' && !Array.isArray(x)) {
      if (k.endsWith('Children')) {
        const parent = o[k.slice(0, -'Children'.length)];
        if (parent !== true) continue;
      }
      flattenFeatureControls(x, path, out, depth + 1);
    }
  }
  return out;
}

/** MobiControl feature (last segment, or a dotted suffix) → Knox field (allowed = false when the feature is disabled). */
const FEATURE_MAP: ReadonlyArray<[RegExp, string]> = [
  [/(^|\.)DisableMicrophone$/i, 'microphone'], [/(^|\.)DisableNfc$/i, 'nfc'], [/(^|\.)DisableScreenCapture$/i, 'screenCapture'],
  [/(^|\.)DisableMockLocations?$/i, 'mockLocation'], [/(^|\.)DisableAirplaneMode$/i, 'airplaneMode'], [/(^|\.)DisableSafeMode$/i, 'safeMode'],
  [/(^|\.)DisableFactoryReset$/i, 'factoryReset'], [/(^|\.)DisableUsbMediaPlayer$/i, 'usbMediaPlayer'], [/(^|\.)BlockOsUpgrade$/i, 'otaUpgrade'],
  [/(^|\.)DisableUnknownSources$/i, 'unknownSources'], [/(^|\.)DisableMultiWindow$/i, 'multiWindow'],
  [/CellularNetwork\..*Disable.*Data$/i, 'cellularData'], [/(^|\.)DisableWifiProfiles$/i, 'wifiUserProfiles'],
  [/(^|\.)DisableBluetooth$/i, 'bluetooth'], [/TetheringAndPortableHotspot\./i, 'tethering'],
  [/Incoming.*Sms|Sms.*Incoming/i, 'smsIncoming'], [/Outgoing.*Sms|Sms.*Outgoing/i, 'smsOutgoing'], [/Mms/i, 'mms'],
  [/(^|\.)PreventUninstallApps$/i, 'appUninstall'], [/DataProtection\..*Clipboard/i, 'clipboard'],
];

export interface MobiControlWifiImport {
  ssid: string;
  security: 'wpa2_psk' | 'wpa2_eap_peap';
  identity: string | null;
  /** The CA the export names (its file name): the operator picks the uploaded certificate in the store. */
  caName: string | null;
  issues: MobiControlIssueCode[];
}

export interface MobiControlSettingsImport {
  knox: Record<string, boolean>;
  dpm: Record<string, string | number | boolean>;
  wifi: MobiControlWifiImport[];
  /** What the operator must type before publishing (the exit PIN, Wi-Fi secrets, masked values). */
  required: string[];
  unmapped: string[];
  issues: MobiControlIssue[];
}

const isMasked = (v: unknown, markers: readonly string[]): boolean => typeof v === 'string' && markers.some((m) => v.includes(m));

/** The first value of a key anywhere in an object (case-insensitive), depth-bounded. */
function findKey(v: unknown, re: RegExp, depth = 0): unknown {
  if (depth > 10 || !v || typeof v !== 'object') return undefined;
  if (Array.isArray(v)) { for (const x of v) { const r = findKey(x, re, depth + 1); if (r !== undefined) return r; } return undefined; }
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) if (re.test(k)) return x;
  for (const x of Object.values(v as Record<string, unknown>)) { const r = findKey(x, re, depth + 1); if (r !== undefined) return r; }
  return undefined;
}

const QUALITIES: Record<string, string> = {
  something: 'something', numeric: 'numeric', numericcomplex: 'numeric_complex', alphabetic: 'alphabetic', alphanumeric: 'alphanumeric',
  complex: 'complex',
};

/** "<n>####<Unit>" (Second, Minute, Hour) in seconds, or null. */
export function mobiControlDuration(v: unknown): number | null {
  const m = /^(\d{1,6})#+(Second|Minute|Hour)s?$/i.exec(str(v).trim());
  if (!m) return null;
  const n = Number(m[1]) * ({ second: 1, minute: 60, hour: 3600 } as Record<string, number>)[m[2].toLowerCase()];
  return Number.isFinite(n) ? n : null;
}

/** The restrictions, password and Wi-Fi of the payloads of one profile (or all profiles when `profile` is null). */
export function profileSettings(profiles: unknown, o: { profile?: string | null; maskMarkers?: readonly string[] } = {}): MobiControlSettingsImport {
  const markers = o.maskMarkers ?? MOBICONTROL_MASK_MARKERS;
  const out: MobiControlSettingsImport = { knox: {}, dpm: {}, wifi: [], required: [], unmapped: [], issues: [] };
  const certNames = new Map<string, string>();
  const chosen = asArray(profiles).map(obj).filter((p) => !o.profile || profileName(p) === o.profile);
  const values = chosen.flatMap(payloadValues);
  // The CA list first: a Wi-Fi payload names its CA by a row of it.
  for (const pv of values) {
    const list = findKey(obj(pv.FormValue).Certificates, /^CertificateList$/i);
    for (const row of asArray(list).map(obj)) {
      const id = str(row.RowTempData) || str(row.Id);
      const name = str(row.CertificateName);
      if (id && name) certNames.set(id, name.slice(0, 200));
    }
  }
  for (const pv of values) {
    const kind = classifyPayload(pv);
    const form = obj(pv.FormValue);
    if (kind === 'restrictions') {
      for (const [path, on] of flattenFeatureControls(form.FeatureControlContainer)) {
        if (!on) continue;
        if (/(^|\.)DisableCamera$/i.test(path)) { out.knox.camera = false; out.dpm.cameraDisabled = true; continue; }
        if (/(^|\.)Connectivity\.WiFi\.DisableWifi$/i.test(path) || /(^|\.)DisableWifi$/i.test(path)) {
          out.issues.push({ code: 'wifi_parent_review', detail: path.slice(0, 160) });
          continue;
        }
        const hit = FEATURE_MAP.find(([re]) => re.test(path));
        if (hit) out.knox[hit[1]] = false; else out.unmapped.push(path.slice(0, 160));
      }
    } else if (kind === 'authentication') {
      const auth = obj(form.AuthenticationSection);
      if (findKey(auth, /^AdministratorTab$/i) !== undefined) out.required.push('kiosk.exitPin');
      const policy = obj(findKey(auth, /^DevicePasswordPolicy$/i));
      if (findKey(policy, /^EnforceUserPasswordPolicy$/i) === true || findKey(auth, /^EnforceUserPasswordPolicy$/i) === true) {
        const q = findKey(policy, /Quality/i);
        if (isMasked(q, markers)) out.required.push('dpm.passwordQuality');
        else if (typeof q === 'string' && QUALITIES[q.toLowerCase().replace(/[^a-z]/g, '')]) out.dpm.passwordQuality = QUALITIES[q.toLowerCase().replace(/[^a-z]/g, '')];
        const len = findKey(policy, /Minimum.*Length|MinLength/i);
        if (isMasked(len, markers)) out.required.push('dpm.passwordMinLength');
        else if (Number.isInteger(Number(len)) && Number(len) >= 0 && Number(len) <= 16 && len !== null && len !== '') out.dpm.passwordMinLength = Number(len);
        const lock = mobiControlDuration(findKey(policy, /MaximumSettingTime/i));
        if (lock !== null) out.dpm.maxTimeToLockSeconds = Math.min(3600, lock);
        const failed = obj(findKey(policy, /^FailedAttemptsGroup$/i));
        const toggle = Object.values(failed).find((x) => typeof x === 'boolean');
        if (toggle === true) {
          const n = Object.values(failed).find((x) => typeof x === 'number' || /^\d+$/.test(str(x)));
          if (n !== undefined && Number(n) > 0) {
            out.dpm.maxFailedPasswordsForWipe = Math.min(30, Number(n));
            out.issues.push({ code: 'wipe_threshold' });
          }
        }
      }
    } else if (kind === 'wifi') {
      const w = obj(form.WIFI);
      const ssid = (str(findKey(w, /^NetworkName$|^SSID$/i)) || str(pv.PayloadDescription)).trim().slice(0, 32);
      const sec = str(findKey(w, /Security(Type)?$|^Encryption$/i));
      const issues: MobiControlIssueCode[] = ['ssid_review'];
      let security: MobiControlWifiImport['security'] | null = null;
      if (/^WPA2?Personal$/i.test(sec)) {
        security = 'wpa2_psk';
        if (/^WPAPersonal$/i.test(sec)) issues.push('security_upgraded');
        out.required.push(`wifi[${ssid}].psk`);
      } else if (/PEAP/i.test(sec) || /PEAP/i.test(str(findKey(w, /EapType|EAPMethod/i)))) {
        security = 'wpa2_eap_peap';
        out.required.push(`wifi[${ssid}].eap.password`);
      }
      if (!security) { out.issues.push({ code: 'wifi_security_unsupported', detail: ssid }); continue; }
      const identity = str(findKey(w, /^UserName$|^Identity$/i));
      const caRef = str(findKey(w, /Certificate(Ref|Id|Reference)?$/i));
      out.wifi.push({
        ssid, security, identity: identity && !isMasked(identity, markers) ? identity.slice(0, 128) : null,
        caName: caRef ? (certNames.get(caRef) ?? null) : null, issues,
      });
    }
  }
  out.required = [...new Set(out.required)];
  return out;
}

/** The profiles of the export that carry a lockdown payload (step 1 of the dialog). */
export function profilesWithLockdown(profiles: unknown): Array<{ profileName: string; groupPaths: string[] }> {
  return lockdownPayloads(profiles).map((l) => ({ profileName: l.profileName, groupPaths: l.groupPaths }));
}
