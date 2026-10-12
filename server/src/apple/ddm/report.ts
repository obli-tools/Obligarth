import { DECLARATION_FAMILIES, type DeclarationFamily } from './capabilities';

// =============================================================================
// Status reports of the devices (docs: integration-apple-edge §9.5, §9.6,
// annex C.6; apple-edge §5.7). A report is the JSON a device posts to the
// `status` endpoint: { "StatusItems": {…nested dictionaries…}, "Errors": […] }.
//   - sanitizeReport: what the relay stores. The push token and the push magic
//     the OS 27 report under StatusItems.mdm (and management) never reach the
//     database nor a log; a dictionary left empty is removed;
//   - flattenStatusItems: the nested dictionaries flattened into dotted paths
//     down to the name of a known item (device.operating-system.version…);
//     what is not a known item is ignored;
//   - declarationStatuses: the status of each declaration from
//     management.declarations (reasons bounded to 4 KiB);
//   - errorItems: the item names of the Errors, for a counter (no content);
//   - isStorableJson: what PostgreSQL's jsonb holds (no lone surrogate, a
//     bounded nesting): anything else is not a status report.
// Device data never size anything: every list and string is bounded here.
// Self-contained: the unit tests run under node --test.
// =============================================================================

/** Largest status report accepted (bytes of the JSON a device posted). */
export const MAX_REPORT_BYTES = 4 * 1024 * 1024;
/** reasons of a declaration status kept (bytes of their JSON). */
export const MAX_REASONS_BYTES = 4 * 1024;
const MAX_DEPTH = 12;
/** Nesting of a status report accepted (Apple's reports are a few levels deep). Neither JSON.stringify nor
 *  PostgreSQL's jsonb reads an unbounded one. */
export const MAX_REPORT_DEPTH = 32;
/** A lone surrogate is no Unicode character: PostgreSQL's jsonb refuses it, as it refuses U+0000. */
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const MAX_ITEMS = 500;
const MAX_STATUSES = 2000;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;
const ITEM_NAME_RE = /^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/;

/** Never stored, never logged (apple-edge §5.7): the push token and magic the OS 27 report as status items. */
const REDACTED: ReadonlyArray<[string, string]> = [['mdm', 'push-token'], ['mdm', 'push-magic'], ['management', 'push-token'], ['management', 'push-magic']];

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

export interface StatusReport {
  StatusItems: Record<string, unknown>;
  Errors: unknown[];
}

/**
 * The report as the relay stores it: StatusItems and Errors only, the push token and magic removed (and their
 * dictionary when it is left empty). null when the document is not a status report (not an object).
 */
export function sanitizeReport(raw: unknown): StatusReport | null {
  if (!isObject(raw)) return null;
  const items = isObject(raw.StatusItems) ? { ...raw.StatusItems } : {};
  for (const [group, key] of REDACTED) {
    const g = items[group];
    if (!isObject(g) || !(key in g)) continue;
    const rest = { ...g };
    delete rest[key];
    if (Object.keys(rest).length === 0) delete items[group];
    else items[group] = rest;
  }
  return { StatusItems: items, Errors: Array.isArray(raw.Errors) ? raw.Errors : [] };
}

/**
 * Can the document be stored as it is (jsonb)? No lone surrogate in a string or a key, MAX_REPORT_DEPTH levels at
 * most. The relay refuses anything else (400): stored, it would fail at the insertion at each attempt of the device.
 */
export function isStorableJson(v: unknown, depth = 0): boolean {
  if (typeof v === 'string') return !LONE_SURROGATE_RE.test(v);
  if (v === null || typeof v !== 'object') return true;
  if (depth >= MAX_REPORT_DEPTH) return false;
  if (Array.isArray(v)) {
    for (const x of v) if (!isStorableJson(x, depth + 1)) return false;
    return true;
  }
  for (const [k, x] of Object.entries(v)) if (LONE_SURROGATE_RE.test(k) || !isStorableJson(x, depth + 1)) return false;
  return true;
}

export interface FlatStatusItem {
  item: string;
  value: unknown;
}

/**
 * The status items of a report, flattened down to the names of `known`: a dictionary is walked until its dotted
 * path is a known item, whose value (scalar, list or dictionary) is taken whole. Anything else is ignored.
 */
export function flattenStatusItems(statusItems: unknown, known: ReadonlySet<string>): FlatStatusItem[] {
  const out: FlatStatusItem[] = [];
  const walk = (node: unknown, path: string, depth: number): void => {
    if (out.length >= MAX_ITEMS || depth > MAX_DEPTH || !isObject(node)) return;
    for (const [k, v] of Object.entries(node)) {
      if (out.length >= MAX_ITEMS) return;
      const p = path ? `${path}.${k}` : k;
      if (p.length > 128) continue;
      if (known.has(p)) {
        if (ITEM_NAME_RE.test(p)) out.push({ item: p, value: v });
      } else {
        walk(v, p, depth + 1);
      }
    }
  };
  walk(statusItems, '', 0);
  return out;
}

export interface DeclarationStatus {
  family: DeclarationFamily;
  identifier: string;
  serverToken: string | null;
  active: boolean | null;
  valid: 'valid' | 'invalid' | 'unknown' | null;
  /** The device's reasons (codes, descriptions), 4 KiB at most; null when absent or larger. */
  reasons: unknown[] | null;
}

const REPORT_FAMILY: Record<DeclarationFamily, string> = {
  activation: 'activations', asset: 'assets', configuration: 'configurations', management: 'management',
};

/** The statuses of management.declarations: one per identifier (the first one wins), 2 000 at most. */
export function declarationStatuses(value: unknown): DeclarationStatus[] {
  if (!isObject(value)) return [];
  const out: DeclarationStatus[] = [];
  const seen = new Set<string>();
  for (const family of DECLARATION_FAMILIES) {
    const list = value[REPORT_FAMILY[family]];
    if (!Array.isArray(list)) continue;
    for (const s of list) {
      if (out.length >= MAX_STATUSES) return out;
      if (!isObject(s) || typeof s.identifier !== 'string' || !IDENTIFIER_RE.test(s.identifier) || seen.has(s.identifier)) continue;
      seen.add(s.identifier);
      const token = typeof s['server-token'] === 'string' && s['server-token'].length <= 64 ? s['server-token'] : null;
      const valid = s.valid === 'valid' || s.valid === 'invalid' || s.valid === 'unknown' ? s.valid : null;
      let reasons: unknown[] | null = null;
      if (Array.isArray(s.reasons) && s.reasons.length > 0) {
        try {
          if (Buffer.byteLength(JSON.stringify(s.reasons), 'utf8') <= MAX_REASONS_BYTES) reasons = s.reasons;
        } catch { /* not serialisable: dropped */ }
      }
      out.push({ family, identifier: s.identifier, serverToken: token, active: typeof s.active === 'boolean' ? s.active : null, valid, reasons });
    }
  }
  return out;
}

/** The item names of the Errors of a report (StatusItem), for a counter: known names, 'other' otherwise. */
export function errorItems(errors: unknown, known: ReadonlySet<string>): string[] {
  if (!Array.isArray(errors)) return [];
  return errors.slice(0, MAX_ITEMS).map((e) => {
    const name = isObject(e) && typeof e.StatusItem === 'string' ? e.StatusItem : '';
    return known.has(name) ? name : 'other';
  });
}
