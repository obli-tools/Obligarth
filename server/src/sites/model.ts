import { createHash } from 'node:crypto';
import {
  SITE_LIMITS as L, SITE_RESERVED_KEYS, SITE_VALUE_KEY_RE, isSiteText,
  type SiteImportLine, type SiteImportResult, type SiteIssueCode, type SitesFromDevicesResult, type SiteWriteBody,
} from '@obligarth/shared';
import { canonicalJson } from '../audit/canonical';

// =============================================================================
// The rules of the sites (lot P1-SITE §2), pure: the check of a site, the reading of a CSV file, the plan of an import
// and the plan of the creation of the sites from the custom fields of the devices. No database, no I/O: the service
// (service.ts) reads what exists, asks for a plan, and writes it; the MCP authorization compares the digest of the plan
// it approved with the plan made again at approval. The values of a site are customer data: the plans name the keys
// that change, never their values.
// =============================================================================

const RESERVED: ReadonlySet<string> = new Set(SITE_RESERVED_KEYS);
const sha256 = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');

/** A site as the plans see it (the existing ones, read by the service). */
export interface SiteRow {
  id: string;
  code: string;
  name: string;
  city: string | null;
  contact: string | null;
  groupId: number | null;
  values: Record<string, string>;
  archived: boolean;
}

/** A text of a site, trimmed; null when blank. */
export const cleanSiteText = (v: unknown): string | null => {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  return s ? s : null;
};

/** The values of a site as stored: string values only (a number or a boolean as its text). */
export function siteValuesOf(v: unknown): Record<string, string> {
  let o: unknown = v;
  if (typeof v === 'string') { try { o = JSON.parse(v); } catch { return {}; } }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return {};
  const out: Record<string, string> = {};
  for (const [k, x] of Object.entries(o as Record<string, unknown>)) {
    if (typeof x === 'string') out[k] = x;
    else if (typeof x === 'number' || typeof x === 'boolean') out[k] = String(x);
  }
  return out;
}

/** The issues of a value key. */
export function valueKeyIssue(k: string): SiteIssueCode | null {
  if (!SITE_VALUE_KEY_RE.test(k)) return 'value_key_invalid';
  if (RESERVED.has(k.toLowerCase())) return 'value_key_reserved';
  return null;
}

/** The issues of the values of a site (keys, texts, count, and their size as stored: 50 values of 500 characters in a
 *  script of 3 or 4 UTF-8 bytes a character pass the 64 KiB of the table, refused here rather than by its CHECK);
 *  empty values are dropped by the caller. */
export function valuesIssues(values: Record<string, string>): SiteIssueCode[] {
  const out = new Set<SiteIssueCode>();
  const keys = Object.keys(values);
  if (keys.length > L.valuesMax) out.add('too_many_values');
  // jsonb's text form adds a space after each ':' and ',': counted with a margin of two bytes a pair.
  else if (Buffer.byteLength(JSON.stringify(values), 'utf8') + 2 * keys.length > L.valuesBytes) out.add('values_too_large');
  for (const k of keys) {
    const i = valueKeyIssue(k);
    if (i) out.add(i);
    const v = values[k];
    if (typeof v !== 'string' || v.length > L.valueMax || !isSiteText(v)) out.add('value_invalid');
  }
  return [...out];
}

/** The fields of a site once checked (POST / PATCH / upsert / import line): the issues, or the clean fields. */
export interface CleanSite {
  code?: string;
  name?: string;
  city?: string | null;
  contact?: string | null;
  groupId?: number | null;
  values?: Record<string, string>;
}

export function checkSite(b: SiteWriteBody, creating: boolean): { site: CleanSite; issues: SiteIssueCode[] } {
  const issues: SiteIssueCode[] = [];
  const site: CleanSite = {};
  if (b.code !== undefined || creating) {
    const c = cleanSiteText(b.code);
    if (!c) issues.push('code_missing');
    else if (c.length > L.codeMax || !isSiteText(c)) issues.push('code_invalid');
    else site.code = c;
  }
  if (b.name !== undefined || creating) {
    const n = cleanSiteText(b.name);
    if (!n) issues.push('name_missing');
    else if (n.length > L.nameMax || !isSiteText(n)) issues.push('name_invalid');
    else site.name = n;
  }
  if (b.city !== undefined) {
    const c = cleanSiteText(b.city);
    if (c !== null && (c.length > L.cityMax || !isSiteText(c))) issues.push('city_invalid');
    else site.city = c;
  }
  if (b.contact !== undefined) {
    const c = cleanSiteText(b.contact);
    if (c !== null && (c.length > L.contactMax || !isSiteText(c))) issues.push('contact_invalid');
    else site.contact = c;
  }
  if (b.groupId !== undefined) site.groupId = b.groupId;
  if (b.values !== undefined) {
    const values: Record<string, string> = {};
    for (const [k, v] of Object.entries(b.values ?? {})) {
      const t = typeof v === 'string' ? v.trim() : '';
      if (t) values[k] = t;
    }
    issues.push(...valuesIssues(values));
    site.values = values;
  }
  return { site, issues: [...new Set(issues)] };
}

// ── CSV ──────────────────────────────────────────────────────────────────────

/** The separator of a file: the one of ';' and ',' its header holds the more of (';' on a tie, the French export). */
export function separatorOf(header: string): ';' | ',' {
  const count = (c: string): number => { let n = 0; let quoted = false; for (const ch of header) { if (ch === '"') quoted = !quoted; else if (!quoted && ch === c) n++; } return n; };
  return count(',') > count(';') ? ',' : ';';
}

/** The records of a CSV text (RFC 4180: quoted fields, "" inside quotes, CRLF or LF; a UTF-8 BOM dropped), with the
 *  line each record starts on. Blank lines are skipped. */
export function parseCsv(text: string, sep?: ';' | ','): { sep: ';' | ','; records: Array<{ line: number; fields: string[] }> } {
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const firstLine = src.split(/\r?\n/, 1)[0] ?? '';
  const s = sep ?? separatorOf(firstLine);
  const records: Array<{ line: number; fields: string[] }> = [];
  let fields: string[] = [];
  let field = '';
  let quoted = false;
  let line = 1;
  let start = 1;
  let any = false;
  const end = (): void => {
    fields.push(field);
    if (any || fields.length > 1 || field !== '') records.push({ line: start, fields });
    fields = []; field = ''; any = false;
  };
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (quoted) {
      if (ch === '"') {
        if (src[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else {
        if (ch === '\n') line++;
        field += ch;
      }
      continue;
    }
    if (ch === '"' && field === '') { quoted = true; any = true; continue; }
    if (ch === s) { fields.push(field); field = ''; any = true; continue; }
    if (ch === '\r' && src[i + 1] === '\n') continue;
    if (ch === '\n' || ch === '\r') { end(); line++; start = line; continue; }
    field += ch;
  }
  if (field !== '' || fields.length || any) end();
  return { sep: s, records };
}

/** The roles of the columns of a header (case-blind): code (or codeMag), name (or nameMag), city (or ville), contact;
 *  every other column goes to the values. A column used as the code or the name that is not literally 'code' or
 *  'name' (codeMag, nameMag) goes to the values too, under its canonical key whatever the case of the header (CodeMag →
 *  codeMag), so that {{device.custom.codeMag}} finds it on the site (the variables are case-sensitive). */
export interface CsvColumns {
  code: number;
  name: number;
  city: number | null;
  contact: number | null;
  /** Index → key of the values. */
  values: Array<{ index: number; key: string }>;
  headers: string[];
}

export type ColumnsError = { error: 'header_missing' | 'code_column_missing' | 'name_column_missing' | 'duplicate_column' | 'column_invalid'; column?: string };

export function columnsOf(header: string[]): CsvColumns | ColumnsError {
  const headers = header.map((h) => h.trim());
  if (!headers.length || headers.every((h) => !h)) return { error: 'header_missing' };
  const lower = headers.map((h) => h.toLowerCase());
  const dup = lower.find((h, i) => h && lower.indexOf(h) !== i);
  if (dup) return { error: 'duplicate_column', column: headers[lower.indexOf(dup)] };
  const find = (...names: string[]): number => {
    for (const n of names) { const i = lower.indexOf(n.toLowerCase()); if (i >= 0) return i; }
    return -1;
  };
  const code = find('code', 'codeMag');
  if (code < 0) return { error: 'code_column_missing' };
  const name = find('name', 'nameMag');
  if (name < 0) return { error: 'name_column_missing' };
  const city = find('city', 'ville');
  const contact = find('contact');
  const values: CsvColumns['values'] = [];
  for (let i = 0; i < headers.length; i++) {
    const h = headers[i];
    if (!h) continue;
    if (i === city || i === contact) continue;
    if ((i === code && lower[i] === 'code') || (i === name && lower[i] === 'name')) continue;
    if (valueKeyIssue(h)) return { error: 'column_invalid', column: h };
    values.push({ index: i, key: i === code ? 'codeMag' : i === name ? 'nameMag' : h });
  }
  if (values.length > L.valuesMax) return { error: 'column_invalid', column: headers[values[L.valuesMax].index] };
  return { code, name, city: city < 0 ? null : city, contact: contact < 0 ? null : contact, values, headers };
}

// ── Plan of an import ────────────────────────────────────────────────────────

/** What an import line would write. */
export interface ImportWrite {
  kind: 'create' | 'update';
  /** The existing site (update). */
  id?: string;
  site: Required<Pick<CleanSite, 'code' | 'name'>> & { city?: string | null; contact?: string | null; values: Record<string, string> };
}

export interface ImportPlan { result: SiteImportResult; writes: ImportWrite[] }

/** The digest of a plan: its columns and lines (the codes, the actions, the fields that change), and, unlike the
 *  answer, the written values as a hash: an approval of a plan never applies other values than those it approved. */
function digestOf(result: Omit<SiteImportResult, 'digest'> | Omit<SitesFromDevicesResult, 'digest'>, writes: unknown): string {
  const { dryRun: _d, applied: _a, ...rest } = result as unknown as Record<string, unknown>;
  return sha256(canonicalJson({ rest, writes: sha256(canonicalJson(writes as never)) } as never));
}

/**
 * The plan of an import of a CSV text: each data line created, updated (only the fields it changes; an empty cell
 * keeps what the site has), unchanged, or refused with its issues (a code twice in the file refuses each of its lines,
 * an archived site is never written again by an import). `existing`: the sites of the tenant, archived ones included.
 * A file without a usable header throws { error } (answered 400 by the caller).
 */
export function planImport(csv: string, existing: SiteRow[], opts: { dryRun: boolean }): ImportPlan | ColumnsError {
  const { records } = parseCsv(csv);
  if (!records.length) return { error: 'header_missing' };
  const cols = columnsOf(records[0].fields);
  if ('error' in cols) return cols;
  const rows = records.slice(1);
  const byCode = new Map(existing.map((s) => [s.code.toLowerCase(), s]));
  const cell = (f: string[], i: number | null): string | null => (i === null ? null : cleanSiteText(f[i] ?? ''));
  const counts = new Map<string, number>();
  for (const r of rows) {
    const c = cell(r.fields, cols.code);
    if (c) counts.set(c.toLowerCase(), (counts.get(c.toLowerCase()) ?? 0) + 1);
  }
  const lines: SiteImportLine[] = [];
  const writes: ImportWrite[] = [];
  let room = L.perTenant - existing.length;
  for (const r of rows) {
    const issues: SiteIssueCode[] = [];
    const code = cell(r.fields, cols.code) ?? '';
    if (r.fields.length !== cols.headers.length) issues.push('columns_mismatch');
    const values: Record<string, string> = {};
    for (const v of cols.values) { const x = cell(r.fields, v.index); if (x !== null) values[v.key] = x; }
    const checked = checkSite({ code, name: cell(r.fields, cols.name) ?? '', city: cell(r.fields, cols.city), contact: cell(r.fields, cols.contact), values }, true);
    issues.push(...checked.issues);
    if (code && (counts.get(code.toLowerCase()) ?? 0) > 1) issues.push('duplicate_code');
    const prev = code ? byCode.get(code.toLowerCase()) : undefined;
    if (prev?.archived) issues.push('site_archived');
    if (!prev && !issues.length && room <= 0) issues.push('too_many_sites');
    if (issues.length) { lines.push({ line: r.line, code, action: 'error', changes: [], issues: [...new Set(issues)] }); continue; }
    const s = checked.site as Required<Pick<CleanSite, 'code' | 'name'>> & CleanSite;
    if (!prev) {
      room--;
      const site = { code: s.code, name: s.name, ...(s.city ? { city: s.city } : {}), ...(s.contact ? { contact: s.contact } : {}), values: s.values ?? {} };
      writes.push({ kind: 'create', site });
      lines.push({ line: r.line, code: s.code, action: 'create', changes: [], issues: [] });
      continue;
    }
    // An update: the fields the file gives that differ; the values merged (an empty cell keeps the site's value).
    const changes: string[] = [];
    if (s.name !== prev.name) changes.push('name');
    if (s.city && s.city !== prev.city) changes.push('city');
    if (s.contact && s.contact !== prev.contact) changes.push('contact');
    const merged = { ...prev.values };
    for (const [k, v] of Object.entries(s.values ?? {})) if (prev.values[k] !== v) { merged[k] = v; changes.push(`values.${k}`); }
    const mergedIssues = valuesIssues(merged).filter((i) => i === 'too_many_values' || i === 'values_too_large');
    if (mergedIssues.length) {
      lines.push({ line: r.line, code, action: 'error', changes: [], issues: mergedIssues });
      continue;
    }
    if (!changes.length) { lines.push({ line: r.line, code: prev.code, action: 'unchanged', changes: [], issues: [] }); continue; }
    writes.push({
      kind: 'update', id: prev.id,
      site: { code: prev.code, name: s.name, ...(s.city ? { city: s.city } : {}), ...(s.contact ? { contact: s.contact } : {}), values: merged },
    });
    lines.push({ line: r.line, code: prev.code, action: 'update', changes, issues: [] });
  }
  const base = {
    dryRun: opts.dryRun, applied: false,
    columns: {
      code: cols.headers[cols.code], name: cols.headers[cols.name], city: cols.city === null ? null : cols.headers[cols.city],
      contact: cols.contact === null ? null : cols.headers[cols.contact], values: cols.values.map((v) => v.key),
    },
    created: lines.filter((l) => l.action === 'create').length, updated: lines.filter((l) => l.action === 'update').length,
    unchanged: lines.filter((l) => l.action === 'unchanged').length, errors: lines.filter((l) => l.action === 'error').length,
    lines,
  };
  return { result: { ...base, digest: digestOf(base, writes) }, writes };
}

// ── Plan of the sites from the custom fields ─────────────────────────────────

/** A device as the plan from the custom fields reads it. */
export interface FieldsDevice {
  id: number;
  label: string;
  siteId: string | null;
  fields: Record<string, string>;
}

export interface FromDevicesKeys { code: string; name: string; values: string[] }

export interface FromDevicesPlan {
  result: SitesFromDevicesResult;
  /** Sites to create, or to complete (the value keys they lack: never a value they have overwritten). */
  writes: Array<{ kind: 'create' | 'update'; id?: string; site: { code: string; name: string; values: Record<string, string> } }>;
  /** Devices → the code of the site they join. */
  attach: Array<{ deviceId: number; code: string }>;
}

/** Does a value still fit in the stored size of the values of a site? */
const fits = (values: Record<string, string>, k: string, v: string): boolean => !valuesIssues({ ...values, [k]: v }).includes('values_too_large');

/** The most frequent value of a list (the first seen on a tie), and the distinct ones. */
function mostFrequent(values: string[]): { top: string | null; distinct: string[] } {
  const n = new Map<string, number>();
  for (const v of values) n.set(v, (n.get(v) ?? 0) + 1);
  let top: string | null = null;
  let best = 0;
  for (const [v, c] of n) if (c > best) { top = v; best = c; }
  return { top, distinct: [...n.keys()] };
}

/**
 * The plan of the sites made from the custom fields of the devices (§2.5 sites_from_devices): the devices grouped by
 * the value of their code field (case-blind; the case seen first kept), one site per code, named after the most frequent
 * value of the name field (the code when none), its values the code, name and value fields of its devices (the most
 * frequent value of each). An existing site keeps its name and its values; only the keys it lacks are added. A device
 * without a code field (or with a code a site cannot take) and on no site is listed, left as it is; a device already on another site
 * stays there (listed). Never a move of group.
 */
export function planFromDevices(devices: FieldsDevice[], existing: SiteRow[], keys: FromDevicesKeys, opts: { dryRun: boolean }): FromDevicesPlan {
  const byCode = new Map(existing.map((s) => [s.code.toLowerCase(), s]));
  const byId = new Map(existing.map((s) => [s.id, s]));
  const groups = new Map<string, { code: string; devices: FieldsDevice[] }>();
  const withoutField: SitesFromDevicesResult['withoutField'] = [];
  for (const d of devices) {
    const code = cleanSiteText(d.fields[keys.code]);
    if (!code || code.length > L.codeMax || !isSiteText(code)) {
      // Listed only when it is on no site (a device enrolled on a site has no field to read: nothing to do).
      if (!d.siteId) withoutField.push({ id: d.id, label: d.label });
      continue;
    }
    const k = code.toLowerCase();
    const g = groups.get(k) ?? { code: byCode.get(k)?.code ?? code, devices: [] };
    g.devices.push(d);
    groups.set(k, g);
  }
  const valueKeys = [...new Set([keys.code, keys.name, ...keys.values])].filter((k) => !valueKeyIssue(k));
  const sites: SitesFromDevicesResult['sites'] = [];
  const conflicts: SitesFromDevicesResult['conflicts'] = [];
  const onOtherSite: SitesFromDevicesResult['onOtherSite'] = [];
  const writes: FromDevicesPlan['writes'] = [];
  const attach: FromDevicesPlan['attach'] = [];
  let alreadyAttached = 0;
  let room = L.perTenant - existing.length;
  for (const [k, g] of [...groups.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
    const names = g.devices.map((d) => cleanSiteText(d.fields[keys.name])).filter((n): n is string => !!n && n.length <= L.nameMax && isSiteText(n));
    const name = mostFrequent(names);
    if (name.distinct.length > 1) conflicts.push({ code: g.code, names: name.distinct.slice(0, 10) });
    const values: Record<string, string> = {};
    for (const vk of valueKeys) {
      const all = g.devices.map((d) => cleanSiteText(d.fields[vk])).filter((v): v is string => !!v && v.length <= L.valueMax && isSiteText(v));
      const top = mostFrequent(all).top;
      if (top !== null && fits(values, vk, top)) values[vk] = top;
    }
    const prev = byCode.get(k);
    let action: 'create' | 'update' | 'unchanged' = 'unchanged';
    const changes: string[] = [];
    if (!prev) {
      if (room <= 0) { for (const d of g.devices) withoutField.push({ id: d.id, label: d.label }); continue; }
      room--;
      action = 'create';
      writes.push({ kind: 'create', site: { code: g.code, name: name.top ?? g.code, values } });
    } else if (!prev.archived) {
      const merged = { ...prev.values };
      for (const [vk, v] of Object.entries(values)) if (!(vk in prev.values) && Object.keys(merged).length < L.valuesMax && fits(merged, vk, v)) { merged[vk] = v; changes.push(`values.${vk}`); }
      if (changes.length) { action = 'update'; writes.push({ kind: 'update', id: prev.id, site: { code: prev.code, name: prev.name, values: merged } }); }
    }
    let n = 0;
    for (const d of g.devices) {
      if (prev?.archived) { onOtherSite.push({ id: d.id, label: d.label, siteCode: prev.code }); continue; }
      if (d.siteId && prev && d.siteId === prev.id) { alreadyAttached++; continue; }
      if (d.siteId) { onOtherSite.push({ id: d.id, label: d.label, siteCode: byId.get(d.siteId)?.code ?? '' }); continue; }
      attach.push({ deviceId: d.id, code: g.code });
      n++;
    }
    sites.push({ code: g.code, name: prev ? prev.name : (name.top ?? g.code), action: prev?.archived ? 'unchanged' : action, devices: n, changes });
  }
  const base = {
    dryRun: opts.dryRun, applied: false, keys: { code: keys.code, name: keys.name, values: keys.values },
    sites, attached: attach.length, alreadyAttached, withoutField, conflicts, onOtherSite,
  };
  return { result: { ...base, digest: digestOf(base, { writes, attach }) }, writes, attach };
}
