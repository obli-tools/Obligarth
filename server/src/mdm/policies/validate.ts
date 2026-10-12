import {
  POLICY_CONTENT_FORMAT, POLICY_MAX_CONTENT_BYTES, POLICY_MAX_ITEMS, POLICY_MAX_SECRET_VALUE_LENGTH, RAW_PROFILE_TYPE,
  SETTING_KEY_MAX, artifactOf, identifierFits, isSecretRef, isSecretValue, looksLikeSecretMarker, settingKeysOf, subkeyNamed,
  typedValueKind, variablesInString,
  type AppleItem, type JsonValue, type PolicyContentV1, type PolicyValidationCode, type PolicyValidationIssue,
  type PolicyVersionSummary, type SchemaFamily, type SchemaKey,
} from '@obligarth/shared';
import { canonicalJson } from '../../audit/canonical';
import type { AppleCatalogView } from '../apple/catalog';

// =============================================================================
// Validation of the content of a policy version (docs: modele-donnees-mdm
// §7.2, codes of §10.8), at every write of a draft and at the submission:
//   - format 1; 200 items per section at most; 512 KiB serialised at most;
//     unique item ids;
//   - a type of the catalog offered at the MVP (the raw profile only from its
//     import route, or kept as the draft already holds it), values conforming
//     to its schema (types, enumerations, bounds, required keys), unknown keys
//     refused;
//   - a tombstone only on a collection or atomic type, never with values;
//     two items never produce the same setting key; an artifact identifier
//     too long is refused here, never at the compilation;
//   - variables of the closed list only, in string values, never in the name
//     of a key;
//   - a secret key of the overlay holds a reference {"$secret": "<uuid>"} (or,
//     when a draft is saved, a value {"$secretValue": "…"} the server moves to
//     the vault before any storage) and nothing else; a reference elsewhere is
//     refused; a declaration carries neither a secret nor an asset (MVP).
// Pure: the existence of the referenced secrets is checked by the caller,
// which receives where they are.
// =============================================================================

export interface ValidateOptions {
  catalog: AppleCatalogView;
  /** The policy's uuid (identifier of a raw profile's artifact). */
  policyUuid: string;
  /** Saving a draft: {"$secretValue"} accepted at a secret key (the caller replaces it). */
  allowSecretValues: boolean;
  /** The import route of raw profiles (CFG-06), a stored content checked again: raw.profile accepted. */
  allowRawProfiles?: boolean;
  /** Saving a draft: the raw profiles it already holds (item id → rawProfileFingerprint of the stored item) are
   *  accepted as they are, never changed nor added by the editor. */
  keptRawProfiles?: ReadonlyMap<string, string>;
}

/** What identifies a stored raw profile item: the canonical JSON of the item (its note apart). */
export function rawProfileFingerprint(item: Pick<AppleItem, 'id' | 'type' | 'values'>): string {
  return canonicalJson({ id: item.id, type: item.type, values: item.values ?? {} });
}

/** The raw profiles of a stored content, by item id (ValidateOptions.keptRawProfiles). */
export function rawProfilesOf(content: PolicyContentV1 | null | undefined): Map<string, string> {
  const out = new Map<string, string>();
  for (const item of content?.sections?.apple?.items ?? []) {
    if (item?.type === RAW_PROFILE_TYPE && typeof item.id === 'string') out.set(item.id.toLowerCase(), rawProfileFingerprint(item));
  }
  return out;
}

/** A secret typed in, to move to the vault: where it is, and the purpose of its key. */
export interface SecretValueSite { itemId: string; path: Array<string | number>; purpose: string }
/** A reference to a tenant secret, where it is, and the purpose its key gives a secret (the overlay's; the typed
 *  values of a raw profile: policy.raw_secret). The secret referred to must have been stored for that purpose: the
 *  rendering reads it accordingly (review of lot B5b, MDM-B5b-C8). */
export interface SecretRefSite { itemId: string; path: string; id: string; purpose: string }

/** The purpose of the secrets the import of a raw profile moves to the vault. */
export const RAW_SECRET_PURPOSE = 'policy.raw_secret';
/** Nesting of the payloads of a raw profile: with the six levels above them, a reference stays within the 32
 *  levels the garbage collection of the vault reads (findSecretRefs; review of lot B5b, MDM-B5b-C9). */
export const RAW_PROFILE_MAX_DEPTH = 24;

export interface ValidationOutcome {
  issues: PolicyValidationIssue[];
  /** The content, normalised (known properties only, in a stable order); null when its shape is invalid. */
  content: PolicyContentV1 | null;
  secretValues: SecretValueSite[];
  secretRefs: SecretRefSite[];
  summary: PolicyVersionSummary;
}

const ITEM_PROPS = new Set(['id', 'type', 'instance', 'remove', 'values', 'note']);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_DEPTH = 32;
const MAX_ISSUES = 200;

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v) && typedValueKind(v) === null;

const pathText = (path: Array<string | number>): string => path.map(String).join('.');

/** Serialised size of a content, in bytes (the stored JSON). */
export function contentBytes(content: unknown): number {
  return Buffer.byteLength(JSON.stringify(content), 'utf8');
}

/** Is a value nested deeper than `max` levels (walked without recursion: nothing is serialised nor hashed before)? */
export function nestedDeeperThan(value: unknown, max: number): boolean {
  const stack: Array<{ v: unknown; depth: number }> = [{ v: value, depth: 0 }];
  while (stack.length) {
    const { v, depth } = stack.pop()!;
    if (v === null || typeof v !== 'object') continue;
    if (depth >= max) return true;
    for (const x of Array.isArray(v) ? v : Object.values(v as Record<string, unknown>)) {
      if (x !== null && typeof x === 'object') stack.push({ v: x, depth: depth + 1 });
    }
  }
  return false;
}

/** A variable is rendered in string values only: the name of a key that holds one is refused (S8). */
const templatedName = (name: string): boolean => name.includes('{{');

/** The markers of the typed values: a well-formed one is a value (typedValueKind), never a dictionary; seen as the
 *  key of a dictionary, it is a malformed typed value. */
const TYPED_MARKERS: ReadonlySet<string> = new Set(['$data', '$date', '$real', '$int']);

/** The code a dictionary key is refused with, null when it is an ordinary name. */
function badKeyName(name: string): PolicyValidationCode | null {
  if (templatedName(name)) return 'unknown_variable';
  if (TYPED_MARKERS.has(name)) return 'type_mismatch';
  return null;
}

class Collector {
  readonly issues: PolicyValidationIssue[] = [];
  readonly secretValues: SecretValueSite[] = [];
  readonly secretRefs: SecretRefSite[] = [];
  variables = 0;

  add(itemId: string | null, path: string, code: PolicyValidationCode): void {
    if (this.issues.length < MAX_ISSUES) this.issues.push({ itemId, path, code });
  }
}

interface ValueCtx {
  c: Collector;
  o: ValidateOptions;
  itemId: string;
  type: string;
  family: SchemaFamily;
}

function inRangeList(list: JsonValue[] | undefined, v: unknown): boolean {
  if (!list || list.length === 0) return true;
  return list.some((x) => x === v || (typeof x === 'number' && typeof v === 'number' && x === v));
}

function numericOf(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  const kind = typedValueKind(v);
  if (kind === 'real') return (v as { $real: number }).$real;
  if (kind === 'int') return Number((v as { $int: string }).$int);
  return null;
}

/** A value against its schema key (recursive). `path`: path in the item; `schemaPath`: the key names. */
function checkValue(x: ValueCtx, key: SchemaKey, value: unknown, path: Array<string | number>, schemaPath: string[], depth: number): void {
  const at = pathText(path);
  if (depth > MAX_DEPTH) { x.c.add(x.itemId, at, 'invalid_item'); return; }
  const purpose = x.o.catalog.secretPurpose(x.type, schemaPath.join('.'));
  if (purpose) {
    // A declaration never carries a secret at the MVP: assets come with step 3 of apple-edge.
    if (x.family === 'declaration') { x.c.add(x.itemId, at, 'secret_requires_asset'); return; }
    if (isSecretRef(value)) { x.c.secretRefs.push({ itemId: x.itemId, path: at, id: value.$secret, purpose }); return; }
    if (x.o.allowSecretValues && isSecretValue(value)) {
      if (value.$secretValue.length === 0 || value.$secretValue.length > POLICY_MAX_SECRET_VALUE_LENGTH) {
        x.c.add(x.itemId, at, 'out_of_range');
        return;
      }
      x.c.secretValues.push({ itemId: x.itemId, path: [...path], purpose });
      return;
    }
    x.c.add(x.itemId, at, 'secret_expected');
    return;
  }
  if (looksLikeSecretMarker(value)) { x.c.add(x.itemId, at, 'secret_not_allowed'); return; }
  if (key.assetReference && x.family === 'declaration') { x.c.add(x.itemId, at, 'asset_not_supported'); return; }

  switch (key.type) {
    case 'string': {
      if (typeof value !== 'string') { x.c.add(x.itemId, at, 'type_mismatch'); return; }
      const vars = variablesInString(value);
      if (vars.unknown.length) { x.c.add(x.itemId, at, 'unknown_variable'); return; }
      if (vars.known.length) { x.c.variables++; return; }   // rendered per device: the list and the format apply then
      if (!inRangeList(key.rangelist, value)) { x.c.add(x.itemId, at, 'out_of_range'); return; }
      if (key.format) {
        let ok = true;
        try { ok = new RegExp(key.format).test(value); } catch { ok = true; }
        if (!ok) x.c.add(x.itemId, at, 'out_of_range');
      }
      return;
    }
    case 'integer':
    case 'real': {
      const n = numericOf(value);
      const okType = key.type === 'integer'
        ? (typeof value === 'number' && Number.isInteger(value)) || typedValueKind(value) === 'int'
        : n !== null;
      if (!okType || n === null) { x.c.add(x.itemId, at, 'type_mismatch'); return; }
      if ((key.range?.min !== undefined && n < key.range.min) || (key.range?.max !== undefined && n > key.range.max)
        || !inRangeList(key.rangelist, n)) {
        x.c.add(x.itemId, at, 'out_of_range');
      }
      return;
    }
    case 'boolean':
      if (typeof value !== 'boolean') x.c.add(x.itemId, at, 'type_mismatch');
      return;
    case 'date':
      if (typedValueKind(value) !== 'date') x.c.add(x.itemId, at, 'type_mismatch');
      return;
    case 'data':
      if (typedValueKind(value) !== 'data') x.c.add(x.itemId, at, 'type_mismatch');
      return;
    case 'array': {
      if (!Array.isArray(value)) { x.c.add(x.itemId, at, 'type_mismatch'); return; }
      const element = key.subkeys?.[0];
      if (!element) return;
      value.forEach((v, i) => checkValue(x, element, v, [...path, i], [...schemaPath, element.name], depth + 1));
      return;
    }
    case 'dictionary': {
      if (!isPlainObject(value)) { x.c.add(x.itemId, at, 'type_mismatch'); return; }
      checkDictionary(x, key.subkeys, value, path, schemaPath, depth + 1);
      return;
    }
    case 'any':
    default:
      checkNoSecretInside(x, value, path, depth + 1);
  }
}

/** The keys of a dictionary (or of an item's values) against their schema. */
function checkDictionary(x: ValueCtx, subkeys: SchemaKey[] | undefined, obj: Record<string, unknown>,
  path: Array<string | number>, schemaPath: string[], depth: number, opts: { required?: boolean } = {}): void {
  for (const [k, v] of Object.entries(obj)) {
    const refused = badKeyName(k);
    if (refused) { x.c.add(x.itemId, pathText([...path, k]), refused); continue; }
    const sub = subkeyNamed(subkeys, k);
    if (!sub) {
      if (subkeys && subkeys.length) x.c.add(x.itemId, pathText([...path, k]), 'unknown_key');
      else checkNoSecretInside(x, v, [...path, k], depth + 1);
      continue;
    }
    checkValue(x, sub, v, [...path, k], [...schemaPath, k], depth);
  }
  if (opts.required !== false) {
    for (const sub of subkeys ?? []) {
      if (sub.required && sub.name !== 'ANY' && !Object.prototype.hasOwnProperty.call(obj, sub.name)) {
        x.c.add(x.itemId, pathText([...path, sub.name]), 'required');
      }
    }
  }
}

/** A value without a schema (type 'any', dictionary of unknown keys): no secret marker anywhere, no unknown
 *  variable, no variable in the name of a key, no number JSON cannot hold. */
function checkNoSecretInside(x: ValueCtx, value: unknown, path: Array<string | number>, depth: number): void {
  if (depth > MAX_DEPTH) { x.c.add(x.itemId, pathText(path), 'invalid_item'); return; }
  if (looksLikeSecretMarker(value)) { x.c.add(x.itemId, pathText(path), 'secret_not_allowed'); return; }
  if (typeof value === 'string') {
    const vars = variablesInString(value);
    if (vars.unknown.length) x.c.add(x.itemId, pathText(path), 'unknown_variable');
    else if (vars.known.length) x.c.variables++;
  } else if (typeof value === 'number') {
    if (!Number.isFinite(value)) x.c.add(x.itemId, pathText(path), 'type_mismatch');
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => checkNoSecretInside(x, v, [...path, i], depth + 1));
  } else if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      const refused = badKeyName(k);
      if (refused) x.c.add(x.itemId, pathText([...path, k]), refused);
      else checkNoSecretInside(x, v, [...path, k], depth + 1);
    }
  }
}

/** A raw profile (server-produced by its import route): displayName, originalIdentifier, payloads; references to
 *  the vault allowed anywhere (the import moved the secrets there), never a value typed in. */
function checkRawProfile(x: ValueCtx, values: Record<string, unknown>): void {
  const allowed = new Set(['displayName', 'originalIdentifier', 'payloads']);
  for (const k of Object.keys(values)) if (!allowed.has(k)) x.c.add(x.itemId, `values.${k}`, 'unknown_key');
  if (typeof values.displayName !== 'string' || values.displayName.length > 200) x.c.add(x.itemId, 'values.displayName', 'type_mismatch');
  if (typeof values.originalIdentifier !== 'string' || values.originalIdentifier.length > 255) x.c.add(x.itemId, 'values.originalIdentifier', 'type_mismatch');
  if (!Array.isArray(values.payloads) || values.payloads.length === 0 || values.payloads.length > 50
    || !values.payloads.every((p) => isPlainObject(p) && typeof p.PayloadType === 'string')) {
    x.c.add(x.itemId, 'values.payloads', 'type_mismatch');
    return;
  }
  const walk = (v: unknown, path: Array<string | number>, depth: number): void => {
    if (depth > RAW_PROFILE_MAX_DEPTH) { x.c.add(x.itemId, pathText(path), 'invalid_item'); return; }
    if (isSecretRef(v)) { x.c.secretRefs.push({ itemId: x.itemId, path: pathText(path), id: v.$secret, purpose: RAW_SECRET_PURPOSE }); return; }
    if (looksLikeSecretMarker(v)) { x.c.add(x.itemId, pathText(path), 'secret_not_allowed'); return; }
    if (typeof v === 'string') {
      const vars = variablesInString(v);
      if (vars.unknown.length) x.c.add(x.itemId, pathText(path), 'unknown_variable');
      else if (vars.known.length) x.c.variables++;
    } else if (typeof v === 'number') {
      if (!Number.isFinite(v)) x.c.add(x.itemId, pathText(path), 'type_mismatch');
    } else if (Array.isArray(v)) v.forEach((e, i) => walk(e, [...path, i], depth + 1));
    else if (isPlainObject(v)) {
      for (const [k, e] of Object.entries(v)) {
        const refused = badKeyName(k);
        if (refused) x.c.add(x.itemId, pathText([...path, k]), refused);
        else walk(e, [...path, k], depth + 1);
      }
    }
  };
  walk(values.payloads, ['values', 'payloads'], 0);
}

/** Is this raw profile item the one the draft already holds (same id, type and values)? */
function keptRawProfile(o: ValidateOptions, item: AppleItem): boolean {
  const stored = o.keptRawProfiles?.get(item.id);
  if (stored === undefined || item.remove || item.instance !== undefined) return false;
  try {
    return rawProfileFingerprint(item) === stored;
  } catch {
    return false;   // a value JSON cannot hold: not what is stored
  }
}

/** Validates (and normalises) the content of a version. */
export function validatePolicyContent(raw: unknown, o: ValidateOptions): ValidationOutcome {
  const c = new Collector();
  const summary: PolicyVersionSummary = { items: 0, removals: 0, types: {}, secretRefs: 0, variables: 0 };
  const done = (content: PolicyContentV1 | null): ValidationOutcome => {
    summary.secretRefs = c.secretRefs.length + c.secretValues.length;
    summary.variables = c.variables;
    return { issues: c.issues, content, secretValues: c.secretValues, secretRefs: c.secretRefs, summary };
  };
  if (!isPlainObject(raw)) { c.add(null, '', 'invalid_content'); return done(null); }
  // Before anything serialises or hashes the content: sections, items, values and their own nesting.
  if (nestedDeeperThan(raw, MAX_DEPTH + 8)) { c.add(null, '', 'invalid_content'); return done(null); }
  for (const k of Object.keys(raw)) if (k !== 'format' && k !== 'sections') c.add(null, k, 'invalid_content');
  if (raw.format !== POLICY_CONTENT_FORMAT) c.add(null, 'format', 'invalid_content');
  const sections = raw.sections;
  if (!isPlainObject(sections)) { c.add(null, 'sections', 'invalid_content'); return done(null); }
  for (const k of Object.keys(sections)) {
    // The android section (AMAPI fragment) is v1 (section 7.14).
    if (k !== 'apple') c.add(null, `sections.${k}`, 'invalid_content');
  }
  if (c.issues.length) return done(null);
  // A guard before anything heavy (the stored content is measured again once the secrets are replaced).
  if (contentBytes(raw) > 2 * POLICY_MAX_CONTENT_BYTES) { c.add(null, '', 'content_too_large'); return done(null); }

  const content: PolicyContentV1 = { format: 1, sections: {} };
  if (sections.apple === undefined) return done(content);
  const apple = sections.apple;
  if (!isPlainObject(apple) || Object.keys(apple).some((k) => k !== 'items') || !Array.isArray(apple.items)) {
    c.add(null, 'sections.apple', 'invalid_content');
    return done(null);
  }
  if (apple.items.length > POLICY_MAX_ITEMS) { c.add(null, 'sections.apple.items', 'too_many_items'); return done(null); }

  const items: AppleItem[] = [];
  const ids = new Set<string>();
  const settingKeys = new Map<string, string>();
  for (const [index, rawItem] of apple.items.entries()) {
    if (!isPlainObject(rawItem)) { c.add(null, `sections.apple.items.${index}`, 'invalid_item'); continue; }
    const itemId = typeof rawItem.id === 'string' && UUID_RE.test(rawItem.id) ? rawItem.id.toLowerCase() : null;
    if (!itemId) { c.add(null, `sections.apple.items.${index}.id`, 'invalid_item'); continue; }
    if (ids.has(itemId)) { c.add(itemId, 'id', 'duplicate_item_id'); continue; }
    ids.add(itemId);
    let bad = false;
    for (const k of Object.keys(rawItem)) if (!ITEM_PROPS.has(k)) { c.add(itemId, k, 'invalid_item'); bad = true; }
    const type = rawItem.type;
    if (typeof type !== 'string' || type.length === 0 || type.length > 128) { c.add(itemId, 'type', 'invalid_item'); continue; }
    if (rawItem.remove !== undefined && rawItem.remove !== true) { c.add(itemId, 'remove', 'invalid_item'); bad = true; }
    if (rawItem.values !== undefined && !isPlainObject(rawItem.values)) { c.add(itemId, 'values', 'invalid_item'); bad = true; }
    if (rawItem.remove === true && rawItem.values !== undefined) { c.add(itemId, 'values', 'invalid_item'); bad = true; }
    if (rawItem.instance !== undefined && typeof rawItem.instance !== 'string') { c.add(itemId, 'instance', 'invalid_instance'); bad = true; }
    if (rawItem.note !== undefined && (typeof rawItem.note !== 'string' || rawItem.note.length > 1000)) { c.add(itemId, 'note', 'invalid_item'); bad = true; }
    if (bad) continue;

    const isRaw = type === RAW_PROFILE_TYPE;
    const entry = o.catalog.entry(type);
    if (!entry) { c.add(itemId, 'type', 'unknown_type'); continue; }
    const d = o.catalog.descriptor(type)!;
    const item: AppleItem = { id: itemId, type };
    if (rawItem.instance !== undefined) item.instance = rawItem.instance as string;
    if (rawItem.remove === true) item.remove = true;
    if (rawItem.values !== undefined) item.values = rawItem.values as Record<string, JsonValue>;
    if (rawItem.note !== undefined) item.note = rawItem.note as string;
    // A raw profile comes from its import route only; the editor sends back, unchanged, the ones the draft holds.
    if (isRaw ? !(o.allowRawProfiles || keptRawProfile(o, item)) : !o.catalog.enabled(type)) {
      c.add(itemId, 'type', 'type_disabled');
      continue;
    }

    const keys = settingKeysOf(item, d);
    if ('error' in keys) {
      c.add(itemId, keys.error === 'remove_not_allowed' ? 'remove'
        : d.instanceKey && !item.remove ? `values.${d.instanceKey}` : 'instance', keys.error);
      continue;
    }
    // The values against the schema (a tombstone has none).
    if (!item.remove) {
      const x: ValueCtx = { c, o, itemId, type, family: entry.family };
      const values = (item.values ?? {}) as Record<string, unknown>;
      if (isRaw) checkRawProfile(x, values);
      // Keyed types resolve key by key: another policy may bring a required key, the compilation checks the result.
      else checkDictionary(x, entry.keys, values, ['values'], [], 1, { required: d.merge !== 'keyed' });
    }
    for (const part of keys.parts) {
      const at = part.key !== null ? `values.${part.key}` : 'type';
      const other = settingKeys.get(part.settingKey);
      if (other !== undefined) { c.add(itemId, at, 'duplicate_setting_key'); continue; }
      settingKeys.set(part.settingKey, itemId);
      const art = artifactOf(type, d, part.instance, { policyUuid: o.policyUuid, itemId });
      if (part.settingKey.length > SETTING_KEY_MAX || !identifierFits(art.channel, art.identifier)) {
        c.add(itemId, at, 'identifier_too_long');
      }
    }
    summary.items++;
    if (item.remove) summary.removals++;
    summary.types[type] = (summary.types[type] ?? 0) + 1;
    items.push(item);
  }
  content.sections.apple = { items };
  return done(c.issues.length ? null : content);
}

/** A content whose `$secretValue` markers (sites of validatePolicyContent) are replaced by references. */
export function withSecretRefs(content: PolicyContentV1, sites: Array<SecretValueSite & { id: string }>): PolicyContentV1 {
  const copy = JSON.parse(JSON.stringify(content)) as PolicyContentV1;
  const items = copy.sections.apple?.items ?? [];
  for (const s of sites) {
    const item = items.find((i) => i.id === s.itemId);
    if (!item) throw new Error('secret site of an unknown item');
    let node: unknown = item;
    for (let i = 0; i < s.path.length - 1; i++) node = (node as Record<string | number, unknown>)[s.path[i] as string];
    const last = s.path[s.path.length - 1];
    const parent = node as Record<string | number, unknown>;
    if (!isSecretValue(parent[last as string])) throw new Error('secret site without a secret value');
    parent[last as string] = { $secret: s.id };
  }
  return copy;
}

/** Does any `$secretValue` remain in a content (never stored)? */
export function hasSecretValue(v: unknown, depth = 0): boolean {
  if (depth > 64 || v === null || typeof v !== 'object') return false;
  if (Array.isArray(v)) return v.some((x) => hasSecretValue(x, depth + 1));
  if (Object.prototype.hasOwnProperty.call(v, '$secretValue')) return true;
  return Object.values(v as Record<string, unknown>).some((x) => hasSecretValue(x, depth + 1));
}

export { POLICY_MAX_CONTENT_BYTES };
