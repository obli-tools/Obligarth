import { X509Certificate } from 'node:crypto';
import {
  AGENT_DPM_FIELDS, AGENT_KIOSK_BLOCK_KEYS, AGENT_KNOX_FIELDS, AGENT_SECRET_PURPOSES, AGENT_WIPE_KEY, LEGACY_AGENT_POLICY_LIMITS as L,
  LEGACY_AGENT_SECTION_ITEM, agentPathKey, isAgentFilePath, isAgentPackageName, isAgentTemplateVariable, isAgentTileUrl,
  isIntentUriWellFormed, isOwnAgentPackage, isReservedKnoxListPackage, isSecretRef, isSecretValue, isUnsafeIntentUri, isValidSsid,
  normalizeIntentUri, variablesInString,
  type LegacyAgentPolicySection, type PolicyValidationCode,
} from '@obligarth/shared';

// =============================================================================
// Validation of the section legacyAgent of a policy version (lot PONT-POL §4),
// the bridge agent's: files deposited, Wi-Fi networks, the soft kiosk, the
// device-administrator and Knox restrictions, the CAs of the system store.
// Pure (it mirrors android/validate.ts): unknown keys and wrong types refused,
// variables only in the text of a file template ({{device.custom.<name>}}
// admitted there), secret slots as vault references or typed values (moved to
// the vault by the caller), the store files it references returned for the
// caller to check against the tenant's store (missingFiles), and the
// wipe-capable keys it sets (a second approver at publication).
// =============================================================================

export { LEGACY_AGENT_SECTION_ITEM };

export interface LegacyAgentValidationOptions {
  /** The floor of maxFailedPasswordsForWipe (the Android floor of the tenant). */
  minFailedPasswordsForWipe: number;
}

export interface LegacyAgentSecretSite {
  /** Tokens from the section ('wifi', 0, 'psk'). */
  tokens: Array<string | number>;
  path: string;
  purpose: string;
  kind: 'ref' | 'value';
  /** A reference's vault id (lower case). */
  id?: string;
}

export interface LegacyAgentStoreRef { path: string; sha256: string; size: number; kind: 'file' | 'image' | 'certificate' }

export interface LegacyAgentValidation {
  issues: Array<{ path: string; code: PolicyValidationCode }>;
  secrets: LegacyAgentSecretSite[];
  storeRefs: LegacyAgentStoreRef[];
  /** ['agent:dpm.maxFailedPasswordsForWipe'] when it is set above 0. */
  wipeRules: string[];
  /** The section holds what belongs to its tenant only (a secret, a store file, a CA file, a kiosk): never shared nor
   *  assigned to another tenant (B2). */
  tenantBound: boolean;
  /** The section normalised (intent prefixes in lower case); null when it has issues. */
  section: LegacyAgentPolicySection | null;
}

const SHA_RE = /^[0-9a-f]{64}$/;
const DOMAIN_RE = /^[A-Za-z0-9.-]{1,253}$/;
const MAX_ISSUES = 200;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const isBool = (v: unknown): v is boolean => typeof v === 'boolean';
const isInt = (v: unknown, min: number, max: number): v is number => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
const utf8Bytes = (s: string): number => Buffer.byteLength(s, 'utf8');
const hasControl = (s: string): boolean => /[\u0000-\u001f\u007f]/.test(s);

/** The text of a path from its tokens: 'wifi[0].eap.password'. */
function pathText(tokens: Array<string | number>): string {
  let out = '';
  for (const t of tokens) out += typeof t === 'number' ? `[${t}]` : out ? `.${t}` : t;
  return out;
}

/** One or more X.509 certificates in PEM, nothing else but whitespace around them. */
export function parsePemCertificates(pem: string): X509Certificate[] | null {
  if (typeof pem !== 'string' || pem.length === 0 || utf8Bytes(pem) > L.pemBytes) return null;
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks || blocks.length === 0 || blocks.length > 8) return null;
  if (pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim() !== '') return null;
  try {
    return blocks.map((b) => new X509Certificate(b));
  } catch {
    return null;
  }
}

/**
 * A JSON template (B8): every {{…}} token replaced by a unique sentinel string, the result must parse as JSON and each
 * sentinel must sit inside a string value only (never a bare token, never in a key).
 */
export function jsonTemplateHolds(text: string): boolean {
  let salt = 0;
  const sentinelOf = (n: number): string => `__OBG${salt}_${n}__`;
  while (text.includes(`__OBG${salt}_`)) salt++;
  const sentinels: string[] = [];
  const replaced = text.replace(/\{\{([^{}]*)\}\}/g, () => { const s = sentinelOf(sentinels.length); sentinels.push(s); return s; });
  let parsed: unknown;
  try { parsed = JSON.parse(replaced); } catch { return false; }
  const inValues = new Set<string>();
  let inKey = false;
  const walk = (v: unknown, depth: number): void => {
    if (depth > 64) return;
    if (typeof v === 'string') { for (const s of sentinels) if (v.includes(s)) inValues.add(s); return; }
    if (Array.isArray(v)) { v.forEach((x) => walk(x, depth + 1)); return; }
    if (isObj(v)) {
      for (const [k, x] of Object.entries(v)) {
        if (sentinels.some((s) => k.includes(s))) inKey = true;
        walk(x, depth + 1);
      }
    }
  };
  walk(parsed, 0);
  return !inKey && sentinels.every((s) => inValues.has(s));
}

class Ctx {
  readonly issues: LegacyAgentValidation['issues'] = [];
  readonly secrets: LegacyAgentSecretSite[] = [];
  readonly storeRefs: LegacyAgentStoreRef[] = [];
  tenantBound = false;
  add(tokens: Array<string | number>, code: PolicyValidationCode): void {
    if (this.issues.length < MAX_ISSUES) this.issues.push({ path: pathText(tokens), code });
  }
  /** Unknown keys of an object. */
  keys(o: Obj, allowed: readonly string[], at: Array<string | number>): void {
    for (const k of Object.keys(o)) if (!allowed.includes(k)) this.add([...at, k], 'unknown_key');
  }
}

/** A secret slot: a reference, or a typed value (`check` validates its format). */
function secretSlot(x: Ctx, v: unknown, at: Array<string | number>, purpose: string, check: (s: string) => PolicyValidationCode | null): void {
  x.tenantBound = true;
  if (isSecretRef(v)) { x.secrets.push({ tokens: at, path: pathText(at), purpose, kind: 'ref', id: v.$secret.toLowerCase() }); return; }
  if (isSecretValue(v)) {
    if (v.$secretValue.length === 0) { x.add(at, 'required'); return; }
    const bad = check(v.$secretValue);
    if (bad) { x.add(at, bad); return; }
    x.secrets.push({ tokens: at, path: pathText(at), purpose, kind: 'value' });
    return;
  }
  x.add(at, 'secret_expected');
}

const pskCheck = (s: string): PolicyValidationCode | null =>
  (/^[\x20-\x7e]{8,63}$/.test(s) || /^[0-9a-fA-F]{64}$/.test(s) ? null : 'psk_invalid');
const eapPasswordCheck = (s: string): PolicyValidationCode | null => (s.length <= L.eapFieldMax * 2 && !hasControl(s) ? null : 'out_of_range');
const pinCheck = (s: string): PolicyValidationCode | null => (L.pinRe.test(s) ? null : 'pin_invalid');

/** A reference to a row of the store: {sha256, size, name}. */
function storeRef(x: Ctx, v: unknown, at: Array<string | number>, kind: LegacyAgentStoreRef['kind'], maxBytes: number): void {
  if (!isObj(v)) { x.add(at, 'type_mismatch'); return; }
  x.keys(v, ['sha256', 'size', 'name'], at);
  if (typeof v.sha256 !== 'string' || !SHA_RE.test(v.sha256)) { x.add([...at, 'sha256'], 'invalid_content'); return; }
  if (!isInt(v.size, 1, maxBytes)) { x.add([...at, 'size'], 'out_of_range'); return; }
  if (typeof v.name !== 'string' || v.name.trim() === '' || v.name.length > 200 || hasControl(v.name)) { x.add([...at, 'name'], 'invalid_content'); return; }
  x.tenantBound = true;
  x.storeRefs.push({ path: pathText(at), sha256: v.sha256, size: v.size, kind });
}

/** No {{ anywhere but in the text of a file template (A5). */
function noVariables(x: Ctx, v: unknown, at: Array<string | number>, depth = 0): void {
  if (depth > 16) return;
  if (typeof v === 'string') { if (v.includes('{{')) x.add(at, 'variable_not_allowed'); return; }
  if (Array.isArray(v)) { v.forEach((e, i) => noVariables(x, e, [...at, i], depth + 1)); return; }
  if (isObj(v)) {
    for (const [k, e] of Object.entries(v)) {
      if (at.length >= 3 && at[0] === 'files' && at[2] === 'source' && k === 'text') continue;
      noVariables(x, e, [...at, k], depth + 1);
    }
  }
}

function validateFiles(x: Ctx, raw: unknown, seenPaths: Map<string, string>): void {
  if (!Array.isArray(raw)) { x.add(['files'], 'type_mismatch'); return; }
  if (raw.length > L.files) { x.add(['files'], 'too_many_files'); return; }
  const ids = new Set<string>();
  raw.forEach((f, i) => {
    const at: Array<string | number> = ['files', i];
    if (!isObj(f)) { x.add(at, 'type_mismatch'); return; }
    x.keys(f, ['id', 'paths', 'allowAppDataDir', 'source', 'overwrite', 'onRemove', 'mediaScan'], at);
    if (typeof f.id !== 'string' || !L.idRe.test(f.id)) x.add([...at, 'id'], 'invalid_content');
    else if (ids.has(f.id)) x.add([...at, 'id'], 'duplicate_value');
    else ids.add(f.id);
    if (f.allowAppDataDir !== undefined && !isBool(f.allowAppDataDir)) x.add([...at, 'allowAppDataDir'], 'type_mismatch');
    if (f.overwrite !== undefined && f.overwrite !== 'always' && f.overwrite !== 'if_absent') x.add([...at, 'overwrite'], 'out_of_range');
    if (f.onRemove !== undefined && f.onRemove !== 'keep' && f.onRemove !== 'delete') x.add([...at, 'onRemove'], 'out_of_range');
    if (f.mediaScan !== undefined && !isBool(f.mediaScan)) x.add([...at, 'mediaScan'], 'type_mismatch');
    if (!Array.isArray(f.paths) || f.paths.length < 1 || f.paths.length > L.pathsPerFile) x.add([...at, 'paths'], 'out_of_range');
    else {
      f.paths.forEach((p, j) => {
        if (!isAgentFilePath(p, { allowAppDataDir: f.allowAppDataDir === true })) { x.add([...at, 'paths', j], 'path_invalid'); return; }
        const key = agentPathKey(p as string);
        if (seenPaths.has(key)) x.add([...at, 'paths', j], 'duplicate_value'); else seenPaths.set(key, String(f.id));
      });
    }
    const s = f.source;
    if (!isObj(s)) { x.add([...at, 'source'], 'required'); return; }
    if (s.kind === 'store') {
      x.keys(s, ['kind', 'sha256', 'size', 'name'], [...at, 'source']);
      storeRef(x, { sha256: s.sha256, size: s.size, name: s.name }, [...at, 'source'], 'file', L.storeFileBytes);
    } else if (s.kind === 'template') {
      x.keys(s, ['kind', 'text', 'encoding'], [...at, 'source']);
      if (s.encoding !== 'text' && s.encoding !== 'json') x.add([...at, 'source', 'encoding'], 'out_of_range');
      if (typeof s.text !== 'string') { x.add([...at, 'source', 'text'], 'type_mismatch'); return; }
      if (utf8Bytes(s.text) > L.templateBytes) { x.add([...at, 'source', 'text'], 'template_too_large'); return; }
      if (variablesInString(s.text, isAgentTemplateVariable).unknown.length) { x.add([...at, 'source', 'text'], 'unknown_variable'); return; }
      if (s.encoding === 'json' && !jsonTemplateHolds(s.text)) x.add([...at, 'source', 'text'], 'invalid_content');
    } else x.add([...at, 'source', 'kind'], 'out_of_range');
  });
}

function validateWifi(x: Ctx, raw: unknown, removeList: unknown): void {
  const ssids = new Set<string>();
  if (raw !== undefined) {
    if (!Array.isArray(raw)) x.add(['wifi'], 'type_mismatch');
    else if (raw.length > L.wifi) x.add(['wifi'], 'too_many_networks');
    else raw.forEach((w, i) => {
      const at: Array<string | number> = ['wifi', i];
      if (!isObj(w)) { x.add(at, 'type_mismatch'); return; }
      x.keys(w, ['ssid', 'hidden', 'priority', 'autoConnect', 'preferOver', 'security', 'psk', 'eap'], at);
      if (!isValidSsid(w.ssid)) x.add([...at, 'ssid'], 'ssid_invalid');
      else if (ssids.has(w.ssid)) x.add([...at, 'ssid'], 'duplicate_value');
      else ssids.add(w.ssid);
      if (w.hidden !== undefined && !isBool(w.hidden)) x.add([...at, 'hidden'], 'type_mismatch');
      if (w.autoConnect !== undefined && !isBool(w.autoConnect)) x.add([...at, 'autoConnect'], 'type_mismatch');
      if (w.priority !== undefined && !isInt(w.priority, 0, 100)) x.add([...at, 'priority'], 'out_of_range');
      if (w.preferOver !== undefined) {
        if (!Array.isArray(w.preferOver) || w.preferOver.length > L.preferOver) x.add([...at, 'preferOver'], 'out_of_range');
        else {
          const seen = new Set<string>();
          w.preferOver.forEach((s, j) => {
            if (!isValidSsid(s)) x.add([...at, 'preferOver', j], 'ssid_invalid');
            else if (s === w.ssid || seen.has(s)) x.add([...at, 'preferOver', j], 'duplicate_value');
            else seen.add(s);
          });
        }
      }
      if (w.security === 'wpa2_psk') {
        if (w.eap !== undefined) x.add([...at, 'eap'], 'unknown_key');
        if (w.psk === undefined) x.add([...at, 'psk'], 'required');
        else secretSlot(x, w.psk, [...at, 'psk'], AGENT_SECRET_PURPOSES.wifi, pskCheck);
      } else if (w.security === 'wpa2_eap_peap') {
        if (w.psk !== undefined) x.add([...at, 'psk'], 'unknown_key');
        const e = w.eap;
        if (!isObj(e)) { x.add([...at, 'eap'], 'required'); return; }
        const ea = [...at, 'eap'];
        x.keys(e, ['identity', 'anonymousIdentity', 'password', 'phase2', 'caPem', 'caFile', 'domainSuffixMatch', 'allowNoCa'], ea);
        if (typeof e.identity !== 'string' || e.identity.length < 1 || e.identity.length > L.eapFieldMax || hasControl(e.identity)) x.add([...ea, 'identity'], 'required');
        if (e.anonymousIdentity !== undefined && e.anonymousIdentity !== null
          && (typeof e.anonymousIdentity !== 'string' || e.anonymousIdentity.length > L.eapFieldMax || hasControl(e.anonymousIdentity))) {
          x.add([...ea, 'anonymousIdentity'], 'out_of_range');
        }
        if (e.phase2 !== 'mschapv2') x.add([...ea, 'phase2'], 'out_of_range');
        if (e.password === undefined) x.add([...ea, 'password'], 'required');
        else secretSlot(x, e.password, [...ea, 'password'], AGENT_SECRET_PURPOSES.wifi, eapPasswordCheck);
        const hasPem = e.caPem !== undefined && e.caPem !== null;
        const hasFile = e.caFile !== undefined && e.caFile !== null;
        if (hasPem && hasFile) x.add([...ea, 'caFile'], 'duplicate_value');
        if (hasPem && (typeof e.caPem !== 'string' || !parsePemCertificates(e.caPem))) x.add([...ea, 'caPem'], 'certificate_invalid');
        if (hasFile) storeRef(x, e.caFile, [...ea, 'caFile'], 'certificate', L.pemBytes);
        if (e.allowNoCa !== undefined && !isBool(e.allowNoCa)) x.add([...ea, 'allowNoCa'], 'type_mismatch');
        if (!hasPem && !hasFile && e.allowNoCa !== true) x.add([...ea, 'caPem'], 'required');
        if (e.domainSuffixMatch !== undefined && e.domainSuffixMatch !== null
          && (typeof e.domainSuffixMatch !== 'string' || !DOMAIN_RE.test(e.domainSuffixMatch))) x.add([...ea, 'domainSuffixMatch'], 'out_of_range');
      } else x.add([...at, 'security'], 'out_of_range');
    });
  }
  if (removeList !== undefined) {
    if (!Array.isArray(removeList) || removeList.length > L.wifiRemove) x.add(['wifiRemove'], 'out_of_range');
    else {
      const seen = new Set<string>();
      removeList.forEach((s, j) => {
        if (!isValidSsid(s)) x.add(['wifiRemove', j], 'ssid_invalid');
        else if (ssids.has(s) || seen.has(s)) x.add(['wifiRemove', j], 'duplicate_value');
        else seen.add(s);
      });
    }
  }
}

function validateKiosk(x: Ctx, k: unknown): void {
  if (k === null) return;
  const at = ['kiosk'];
  if (!isObj(k)) { x.add(at, 'type_mismatch'); return; }
  x.keys(k, ['enabled', 'title', 'showDeviceName', 'columns', 'logo', 'tiles', 'exitPin', 'hard'], at);
  x.tenantBound = true;   // its exit PIN is a secret of the tenant
  if (!isBool(k.enabled)) x.add([...at, 'enabled'], 'required');
  if (k.title !== undefined && k.title !== null && (typeof k.title !== 'string' || k.title.length > L.titleMax || hasControl(k.title))) x.add([...at, 'title'], 'out_of_range');
  if (k.showDeviceName !== undefined && !isBool(k.showDeviceName)) x.add([...at, 'showDeviceName'], 'type_mismatch');
  if (k.columns !== undefined && !isInt(k.columns, 2, 5)) x.add([...at, 'columns'], 'out_of_range');
  if (k.logo !== undefined && k.logo !== null) storeRef(x, k.logo, [...at, 'logo'], 'image', L.imageBytes);
  if (k.exitPin === undefined) x.add([...at, 'exitPin'], 'required');
  else secretSlot(x, k.exitPin, [...at, 'exitPin'], AGENT_SECRET_PURPOSES.kioskPin, pinCheck);
  if (k.hard !== undefined) {
    const h = k.hard;
    if (!isObj(h)) x.add([...at, 'hard'], 'type_mismatch');
    else {
      x.keys(h, ['hideSystemBar', 'disableStatusBarExpansion', 'disableTaskManager', 'blockKeys', 'disableSettingsChanges'], [...at, 'hard']);
      for (const f of ['hideSystemBar', 'disableStatusBarExpansion', 'disableTaskManager', 'disableSettingsChanges']) {
        if (h[f] !== undefined && !isBool(h[f])) x.add([...at, 'hard', f], 'type_mismatch');
      }
      if (h.blockKeys !== undefined && (!Array.isArray(h.blockKeys) || h.blockKeys.length > AGENT_KIOSK_BLOCK_KEYS.length
        || h.blockKeys.some((b) => !(AGENT_KIOSK_BLOCK_KEYS as readonly unknown[]).includes(b)) || new Set(h.blockKeys).size !== h.blockKeys.length)) {
        x.add([...at, 'hard', 'blockKeys'], 'out_of_range');
      }
    }
  }
  if (!Array.isArray(k.tiles)) { x.add([...at, 'tiles'], 'required'); return; }
  if (k.tiles.length < 1 || k.tiles.length > L.tiles) { x.add([...at, 'tiles'], 'too_many_tiles'); return; }
  const ids = new Set<string>();
  k.tiles.forEach((t, i) => {
    const ta: Array<string | number> = [...at, 'tiles', i];
    if (!isObj(t)) { x.add(ta, 'type_mismatch'); return; }
    x.keys(t, ['id', 'label', 'image', 'launchOnStart', 'action'], ta);
    if (typeof t.id !== 'string' || !L.idRe.test(t.id)) x.add([...ta, 'id'], 'invalid_content');
    else if (ids.has(t.id)) x.add([...ta, 'id'], 'duplicate_value');
    else ids.add(t.id);
    if (typeof t.label !== 'string' || t.label.trim().length < 1 || t.label.length > L.labelMax || hasControl(t.label)) x.add([...ta, 'label'], 'tile_invalid');
    if (t.launchOnStart !== undefined && !isBool(t.launchOnStart)) x.add([...ta, 'launchOnStart'], 'type_mismatch');
    if (t.image !== undefined && t.image !== null) storeRef(x, t.image, [...ta, 'image'], 'image', L.imageBytes);
    const a = t.action;
    const aa = [...ta, 'action'];
    if (!isObj(a)) { x.add(aa, 'required'); return; }
    if (a.type === 'app') {
      x.keys(a, ['type', 'package'], aa);
      if (!isAgentPackageName(a.package)) x.add([...aa, 'package'], 'package_invalid');
      else if (isOwnAgentPackage(a.package)) x.add([...aa, 'package'], 'package_reserved');
    } else if (a.type === 'url') {
      x.keys(a, ['type', 'url', 'package'], aa);
      if (!isAgentTileUrl(a.url)) x.add([...aa, 'url'], 'url_invalid');
      if (a.package !== undefined && a.package !== null) {
        if (!isAgentPackageName(a.package)) x.add([...aa, 'package'], 'package_invalid');
        else if (isOwnAgentPackage(a.package)) x.add([...aa, 'package'], 'package_reserved');
      }
    } else if (a.type === 'intent') {
      x.keys(a, ['type', 'uri'], aa);
      const uri = normalizeIntentUri(a.uri);
      if (!uri || !isIntentUriWellFormed(uri) || isUnsafeIntentUri(uri)) x.add([...aa, 'uri'], 'intent_invalid');
    } else x.add([...aa, 'type'], 'out_of_range');
  });
}

function validateDpm(x: Ctx, d: unknown, o: LegacyAgentValidationOptions): string[] {
  if (!isObj(d)) { x.add(['dpm'], 'type_mismatch'); return []; }
  const wipe: string[] = [];
  for (const [field, v] of Object.entries(d)) {
    const at = ['dpm', field];
    const spec = AGENT_DPM_FIELDS.find((f) => f.field === field);
    if (!spec) { x.add(at, 'unknown_key'); continue; }
    if (spec.type === 'bool') { if (!isBool(v)) x.add(at, 'type_mismatch'); continue; }
    if (spec.type === 'enum') { if (typeof v !== 'string' || !spec.values!.includes(v)) x.add(at, 'out_of_range'); continue; }
    if (spec.type === 'flags') {
      if (!Array.isArray(v) || v.some((e) => typeof e !== 'string' || !spec.values!.includes(e)) || new Set(v).size !== v.length) x.add(at, 'out_of_range');
      continue;
    }
    if (typeof v !== 'number' || !Number.isInteger(v)) { x.add(at, 'type_mismatch'); continue; }
    if (v < spec.min! || v > spec.max!) { x.add(at, 'out_of_range'); continue; }
    if (spec.wipe && v > 0) {
      if (v < o.minFailedPasswordsForWipe) { x.add(at, 'wipe_threshold_too_low'); continue; }
      if (typeof d.passwordQuality !== 'string' || d.passwordQuality === 'unspecified') { x.add(at, 'wipe_without_password'); continue; }
      wipe.push(AGENT_WIPE_KEY);
    }
  }
  return wipe;
}

function validateKnox(x: Ctx, k: unknown, kiosk: unknown): void {
  if (!isObj(k)) { x.add(['knox'], 'type_mismatch'); return; }
  const kioskEnabled = isObj(kiosk) && kiosk.enabled === true;
  const tilePackages: string[] = [];
  if (isObj(kiosk) && Array.isArray(kiosk.tiles)) {
    for (const t of kiosk.tiles) {
      const a = isObj(t) && isObj(t.action) ? t.action : null;
      if (a && typeof a.package === 'string') tilePackages.push(a.package);
    }
  }
  for (const [field, v] of Object.entries(k)) {
    const at = ['knox', field];
    const spec = AGENT_KNOX_FIELDS.find((f) => f.field === field);
    if (!spec) { x.add(at, 'unknown_key'); continue; }
    if (spec.type === 'bool') { if (!isBool(v)) x.add(at, 'type_mismatch'); continue; }
    if (!Array.isArray(v) || v.length > L.knoxListItems) { x.add(at, 'out_of_range'); continue; }
    const seen = new Set<string>();
    v.forEach((p, j) => {
      if (!isAgentPackageName(p)) x.add([...at, j], 'package_invalid');
      else if (isReservedKnoxListPackage(p, { kioskEnabled, tilePackages, list: field as 'disabledApps' | 'uninstallBlocked' })) x.add([...at, j], 'package_reserved');
      else if (seen.has(p)) x.add([...at, j], 'duplicate_value');
      else seen.add(p);
    });
  }
}

function validateCerts(x: Ctx, c: unknown): void {
  if (!Array.isArray(c) || c.length > L.certs) { x.add(['certs'], 'out_of_range'); return; }
  const ids = new Set<string>();
  c.forEach((e, i) => {
    const at: Array<string | number> = ['certs', i];
    if (!isObj(e)) { x.add(at, 'type_mismatch'); return; }
    x.keys(e, ['id', 'name', 'pem'], at);
    if (typeof e.id !== 'string' || !L.idRe.test(e.id)) x.add([...at, 'id'], 'invalid_content');
    else if (ids.has(e.id)) x.add([...at, 'id'], 'duplicate_value');
    else ids.add(e.id);
    if (typeof e.name !== 'string' || e.name.trim() === '' || e.name.length > 100 || hasControl(e.name)) x.add([...at, 'name'], 'required');
    if (typeof e.pem !== 'string' || !parsePemCertificates(e.pem)) x.add([...at, 'pem'], 'certificate_invalid');
  });
}

/** Validates the section legacyAgent (pure). */
export function validateLegacyAgentSection(raw: unknown, o: LegacyAgentValidationOptions): LegacyAgentValidation {
  const x = new Ctx();
  const done = (wipeRules: string[]): LegacyAgentValidation => ({
    issues: x.issues, secrets: x.secrets, storeRefs: x.storeRefs, wipeRules, tenantBound: x.tenantBound,
    section: x.issues.length ? null : normalise(raw as LegacyAgentPolicySection),
  });
  if (!isObj(raw)) { x.add([], 'invalid_content'); return done([]); }
  x.keys(raw, ['files', 'wifi', 'wifiRemove', 'kiosk', 'dpm', 'knox', 'certs', 'confirmBenchLockout'], []);
  noVariables(x, raw, []);
  // Lot BANC (D16, §7.3): Knox usbDebugging=false cuts ADB, hence the bench station: never without an explicit
  // confirmation stored with the section. A policy published before keeps being delivered (the publication and the
  // delivery never validate again); the confirmation is asked at its next change.
  if (raw.confirmBenchLockout !== undefined && raw.confirmBenchLockout !== true) x.add(['confirmBenchLockout'], 'type_mismatch');
  if (isObj(raw.knox) && raw.knox.usbDebugging === false && raw.confirmBenchLockout !== true) x.add(['confirmBenchLockout'], 'required');
  const paths = new Map<string, string>();
  if (raw.files !== undefined) validateFiles(x, raw.files, paths);
  validateWifi(x, raw.wifi, raw.wifiRemove);
  if (raw.kiosk !== undefined) validateKiosk(x, raw.kiosk);
  const wipe = raw.dpm !== undefined ? validateDpm(x, raw.dpm, o) : [];
  if (raw.knox !== undefined) validateKnox(x, raw.knox, raw.kiosk);
  if (raw.certs !== undefined) validateCerts(x, raw.certs);
  return done(wipe);
}

/** The section with its intent URIs normalised (prefix in lower case). */
function normalise(s: LegacyAgentPolicySection): LegacyAgentPolicySection {
  const copy = JSON.parse(JSON.stringify(s)) as LegacyAgentPolicySection;
  for (const t of copy.kiosk?.tiles ?? []) {
    if (t.action?.type === 'intent') t.action.uri = normalizeIntentUri(t.action.uri) ?? t.action.uri;
  }
  return copy;
}

/** The node at a secret's tokens in a section: its parent and key. */
export function legacyAgentNodeAt(section: unknown, tokens: Array<string | number>): { parent: Record<string | number, unknown>; key: string | number } | null {
  let node: unknown = section;
  for (let i = 0; i < tokens.length - 1; i++) {
    if (!node || typeof node !== 'object') return null;
    node = (node as Record<string | number, unknown>)[tokens[i]];
  }
  if (!node || typeof node !== 'object') return null;
  return { parent: node as Record<string | number, unknown>, key: tokens[tokens.length - 1] };
}
