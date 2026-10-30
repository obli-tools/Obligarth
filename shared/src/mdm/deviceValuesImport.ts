// =============================================================================
// Import of per-device values for the templates of the bridge agent (lot
// PONT-POL §12.1): the parsers of a folder tree (one folder per device name
// holding a JSON file, the MobiControl file-sync export among others), of a
// CSV and of a JSON document. Pure, run in the browser and by the unit tests;
// no ICU: the text is strict UTF-8, else Windows-1252 through a built-in table.
// The values are customer data: never logged, only sent to the server.
// =============================================================================

export const DEVICE_VALUES_PARSE_LIMITS = {
  fileBytes: 64 * 1024, files: 5000, keysPerFile: 32, keyRe: /^[A-Za-z0-9_-]{1,64}$/, valueMax: 1000, deviceKeyMax: 200,
} as const;

export interface DeviceValuesRow {
  deviceKey: string;
  values: Record<string, string>;
  /** The relative path of its file, or the line of the CSV ("line 12"). */
  source: string;
}

export type DeviceValuesIssueCode = 'no_device_folder' | 'too_large' | 'not_utf8' | 'invalid_json' | 'not_an_object' | 'key_dropped'
  | 'value_dropped' | 'too_many_keys' | 'too_many_files' | 'no_device' | 'conflict' | 'empty' | 'bad_header';

export interface DeviceValuesIssue { source: string; code: DeviceValuesIssueCode; detail?: string }

export interface DeviceValuesParseResult {
  rows: DeviceValuesRow[];
  issues: DeviceValuesIssue[];
  /** Device keys with more than one candidate (several files or lines): the operator picks one. */
  conflicts: string[];
}

// ── Text ─────────────────────────────────────────────────────────────────────

/** 0x80 to 0x9F of Windows-1252 (the rest of the high half is Latin-1); undefined bytes map to U+FFFD. */
const CP1252_HIGH = [
  0x20ac, 0xfffd, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0xfffd, 0x017d, 0xfffd,
  0xfffd, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0xfffd, 0x017e, 0x0178,
];

/** Strict UTF-8 decoding; null at the first invalid sequence (overlong, surrogate, truncated). */
function strictUtf8(b: Uint8Array): string | null {
  let out = '';
  let i = 0;
  while (i < b.length) {
    const c = b[i];
    if (c < 0x80) { out += String.fromCharCode(c); i++; continue; }
    let need = 0;
    let cp = 0;
    let min = 0;
    if (c >= 0xc2 && c <= 0xdf) { need = 1; cp = c & 0x1f; min = 0x80; } else if (c >= 0xe0 && c <= 0xef) { need = 2; cp = c & 0x0f; min = 0x800; } else if (c >= 0xf0 && c <= 0xf4) { need = 3; cp = c & 0x07; min = 0x10000; } else return null;
    if (i + need >= b.length) return null;   // truncated sequence
    for (let k = 1; k <= need; k++) {
      const x = b[i + k];
      if (x === undefined || (x & 0xc0) !== 0x80) return null;
      cp = (cp << 6) | (x & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return null;
    out += String.fromCodePoint(cp);
    i += need + 1;
  }
  return out;
}

/** The text of a file: strict UTF-8 (BOM dropped), else Windows-1252 (the exports of some tools). */
export function decodeText(bytes: Uint8Array): { text: string; encoding: 'utf8' | 'cp1252' } {
  const start = bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  const body = start ? bytes.subarray(start) : bytes;
  const utf8 = strictUtf8(body);
  if (utf8 !== null) return { text: utf8, encoding: 'utf8' };
  let out = '';
  for (const c of body) out += String.fromCharCode(c >= 0x80 && c <= 0x9f ? CP1252_HIGH[c - 0x80] : c);
  return { text: out, encoding: 'cp1252' };
}

// ── Values ───────────────────────────────────────────────────────────────────

const clean = (s: string): string => s.replace(/[\u0000-\u001f\u007f]/g, '').trim();

/** A flat object of scalars into values (stringified, trimmed); bad keys and nested values reported. */
function valuesOf(obj: Record<string, unknown>, source: string, issues: DeviceValuesIssue[]): Record<string, string> | null {
  const L = DEVICE_VALUES_PARSE_LIMITS;
  const out: Record<string, string> = {};
  const keys = Object.keys(obj);
  if (keys.length > L.keysPerFile) { issues.push({ source, code: 'too_many_keys' }); return null; }
  for (const k of keys) {
    const v = obj[k];
    if (!L.keyRe.test(k)) { issues.push({ source, code: 'key_dropped', detail: k.slice(0, 64) }); continue; }
    if (v === null || v === undefined) continue;
    if (typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'boolean') { issues.push({ source, code: 'value_dropped', detail: k }); continue; }
    const s = clean(String(v));
    if (s.length > L.valueMax) { issues.push({ source, code: 'value_dropped', detail: k }); continue; }
    out[k] = s;
  }
  return out;
}

function finish(rows: DeviceValuesRow[], issues: DeviceValuesIssue[]): DeviceValuesParseResult {
  const count = new Map<string, number>();
  for (const r of rows) count.set(r.deviceKey.toLowerCase(), (count.get(r.deviceKey.toLowerCase()) ?? 0) + 1);
  const conflicts = [...new Set(rows.filter((r) => (count.get(r.deviceKey.toLowerCase()) ?? 0) > 1).map((r) => r.deviceKey))];
  for (const k of conflicts) issues.push({ source: k, code: 'conflict' });
  return { rows, issues, conflicts };
}

// ── Folder tree ──────────────────────────────────────────────────────────────

/** A glob of a file name ('*.json', 'conf_*.json'): * and ? only, case-insensitive. */
export function globToRegExp(glob: string): RegExp {
  const esc = glob.trim().slice(0, 100).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${esc}$`, 'i');
}

/**
 * A folder tree (webkitRelativePath of each picked file and its bytes): the device key is the name of the folder
 * that holds the file (a deeper file keeps its direct parent); name variants such as 'conf_store (7).json' are
 * matched by the glob like any other. A file at the top of the tree (no device folder) is reported.
 */
export function parseFolderTree(files: ReadonlyArray<{ relPath: string; bytes: Uint8Array }>, o: { glob?: string } = {}): DeviceValuesParseResult {
  const L = DEVICE_VALUES_PARSE_LIMITS;
  const re = globToRegExp(o.glob && o.glob.trim() ? o.glob : '*.json');
  const rows: DeviceValuesRow[] = [];
  const issues: DeviceValuesIssue[] = [];
  let taken = 0;
  for (const f of files) {
    const parts = f.relPath.split(/[\\/]/).filter((p) => p.length > 0);
    const name = parts[parts.length - 1] ?? '';
    if (!re.test(name)) continue;
    if (++taken > L.files) { issues.push({ source: f.relPath, code: 'too_many_files' }); break; }
    // The picked folder is parts[0]: a file directly inside it has no device folder.
    if (parts.length < 3) { issues.push({ source: f.relPath, code: 'no_device_folder' }); continue; }
    if (f.bytes.length > L.fileBytes) { issues.push({ source: f.relPath, code: 'too_large' }); continue; }
    const deviceKey = clean(parts[parts.length - 2]).slice(0, L.deviceKeyMax);
    if (!deviceKey) { issues.push({ source: f.relPath, code: 'no_device_folder' }); continue; }
    const { text } = decodeText(f.bytes);
    let json: unknown;
    try { json = JSON.parse(text); } catch { issues.push({ source: f.relPath, code: 'invalid_json' }); continue; }
    if (!json || typeof json !== 'object' || Array.isArray(json)) { issues.push({ source: f.relPath, code: 'not_an_object' }); continue; }
    const values = valuesOf(json as Record<string, unknown>, f.relPath, issues);
    if (!values) continue;
    if (Object.keys(values).length === 0) { issues.push({ source: f.relPath, code: 'empty' }); continue; }
    rows.push({ deviceKey, values, source: f.relPath });
  }
  return finish(rows, issues);
}

// ── CSV ──────────────────────────────────────────────────────────────────────

/** The cells of a CSV text (separator ',' or ';', detected on the header; quoted cells with "" escapes). */
export function csvCells(text: string, sep?: ',' | ';'): string[][] {
  const firstLine = text.split(/\r?\n/, 1)[0] ?? '';
  const s = sep ?? ((firstLine.split(';').length > firstLine.split(',').length) ? ';' : ',');
  const out: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else quoted = false; } else cell += ch;
      continue;
    }
    if (ch === '"' && cell.length === 0) quoted = true;
    else if (ch === s) { row.push(cell); cell = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); cell = '';
      if (row.some((c) => c.trim() !== '')) out.push(row);
      row = [];
    } else cell += ch;
  }
  row.push(cell);
  if (row.some((c) => c.trim() !== '')) out.push(row);
  return out;
}

/** A CSV whose header is device,<key1>,<key2>,…; an empty cell leaves its key out. */
export function parseCsvValues(text: string): DeviceValuesParseResult {
  const L = DEVICE_VALUES_PARSE_LIMITS;
  const cells = csvCells(text.replace(/^﻿/, ''));
  const rows: DeviceValuesRow[] = [];
  const issues: DeviceValuesIssue[] = [];
  if (cells.length === 0) return finish(rows, [{ source: 'line 1', code: 'empty' }]);
  const header = cells[0].map((h) => clean(h));
  if (header.length < 2) return finish(rows, [{ source: 'line 1', code: 'bad_header' }]);
  const keys = header.slice(1);
  keys.forEach((k) => { if (!L.keyRe.test(k)) issues.push({ source: 'line 1', code: 'key_dropped', detail: k.slice(0, 64) }); });
  for (let n = 1; n < cells.length; n++) {
    const source = `line ${n + 1}`;
    const line = cells[n];
    const deviceKey = clean(line[0] ?? '').slice(0, L.deviceKeyMax);
    if (!deviceKey) { issues.push({ source, code: 'no_device' }); continue; }
    const obj: Record<string, unknown> = {};
    keys.forEach((k, i) => { const v = line[i + 1]; if (L.keyRe.test(k) && v !== undefined && clean(v) !== '') obj[k] = v; });
    const values = valuesOf(obj, source, issues);
    if (!values || Object.keys(values).length === 0) { issues.push({ source, code: 'empty' }); continue; }
    rows.push({ deviceKey, values, source });
  }
  return finish(rows, issues);
}

// ── JSON ─────────────────────────────────────────────────────────────────────

/** [{ "device": "C0100042", "values": { "storeCode": "00042" } }] or { "C0100042": { "storeCode": "00042" } }. */
export function parseJsonValues(text: string): DeviceValuesParseResult {
  const L = DEVICE_VALUES_PARSE_LIMITS;
  const rows: DeviceValuesRow[] = [];
  const issues: DeviceValuesIssue[] = [];
  let json: unknown;
  try { json = JSON.parse(text.replace(/^﻿/, '')); } catch { return finish(rows, [{ source: 'json', code: 'invalid_json' }]); }
  const entries: Array<[string, unknown, string]> = [];
  if (Array.isArray(json)) {
    json.forEach((e, i) => {
      const o = e as { device?: unknown; values?: unknown } | null;
      entries.push([typeof o?.device === 'string' ? o.device : '', o?.values, `[${i}]`]);
    });
  } else if (json && typeof json === 'object') {
    for (const [k, v] of Object.entries(json as Record<string, unknown>)) entries.push([k, v, k.slice(0, 64)]);
  } else return finish(rows, [{ source: 'json', code: 'not_an_object' }]);
  for (const [key, v, source] of entries) {
    const deviceKey = clean(key).slice(0, L.deviceKeyMax);
    if (!deviceKey) { issues.push({ source, code: 'no_device' }); continue; }
    if (!v || typeof v !== 'object' || Array.isArray(v)) { issues.push({ source, code: 'not_an_object' }); continue; }
    const values = valuesOf(v as Record<string, unknown>, source, issues);
    if (!values || Object.keys(values).length === 0) { issues.push({ source, code: 'empty' }); continue; }
    rows.push({ deviceKey, values, source });
  }
  return finish(rows, issues);
}

/** Renames the keys of the rows (mapping old → new; an empty new name drops the key) and prefixes them. */
export function mapDeviceValueKeys(rows: DeviceValuesRow[], mapping: Record<string, string>, prefix = ''): DeviceValuesRow[] {
  return rows.map((r) => {
    const values: Record<string, string> = {};
    for (const [k, v] of Object.entries(r.values)) {
      const to = Object.prototype.hasOwnProperty.call(mapping, k) ? mapping[k] : k;
      if (!to) continue;
      const name = `${prefix}${to}`;
      if (DEVICE_VALUES_PARSE_LIMITS.keyRe.test(name)) values[name] = v;
    }
    return { ...r, values };
  });
}
