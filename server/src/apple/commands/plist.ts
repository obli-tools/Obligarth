import { createHash } from 'node:crypto';

// =============================================================================
// Property lists of the MDM commands (docs: integration-apple-edge §8.5,
// annex C.4): a deterministic XML writer, without dependency, and the small
// reader the secret scanner and the tests need.
//   - exact header (<?xml …?>, DOCTYPE, <plist version="1.0">), '\n' line
//     ends, tab indentation, the file ends with '</plist>\n';
//   - dictionary keys sorted by UTF-16 code units, escaped like text;
//   - string (&, <, > escaped; characters XML 1.0 forbids, lone surrogates,
//     U+FFFE and U+FFFF refused), boolean, integer (a safe integer number or
//     a bigint: any other number is refused), PlistReal, PlistDate (UTC, no
//     fraction), PlistData (standard base64 on one line), arrays and
//     dictionaries (<array/>, <dict/> when empty); null and undefined refused;
//   - a command: { Command: { RequestType, …params }, CommandUUID } with the
//     CommandUUID in upper case (apple-edge compares it byte for byte with
//     the command_uuid of the request: review INT-RC2), 4 MiB at most.
// The same value always gives the same bytes: plist_sha256 is the SHA-256 of
// the UTF-8 bytes, and a retried submission sends the very same command.
// Pure (no import of the server): the unit tests load it under node --test.
// =============================================================================

/** A <real>. */
export class PlistReal {
  readonly value: number;
  constructor(value: number) { this.value = value; }
}

/** A <date> (UTC, to the second). */
export class PlistDate {
  readonly value: Date;
  constructor(value: Date) { this.value = value; }
}

/** A <data> (bytes). */
export class PlistData {
  readonly value: Buffer;
  constructor(value: Buffer | Uint8Array) { this.value = Buffer.isBuffer(value) ? value : Buffer.from(value); }
}

export type PlistValue = string | number | bigint | boolean | PlistReal | PlistDate | PlistData | PlistValue[] | PlistDict;
export interface PlistDict { [key: string]: PlistValue }

export type PlistErrorCode = 'invalid_value' | 'too_large' | 'invalid_plist';

export class PlistError extends Error {
  readonly code: PlistErrorCode;
  constructor(code: PlistErrorCode, message: string) {
    super(message);
    this.name = 'PlistError';
    this.code = code;
  }
}

/** Largest command plist (apple-edge's own limit, queue.go MaxCommandBytes). */
export const MAX_COMMAND_BYTES = 4 * 1024 * 1024;

const HEADER = '<?xml version="1.0" encoding="UTF-8"?>\n'
  + '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
  + '<plist version="1.0">\n';
const FOOTER = '</plist>\n';

const UUID_RE = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
const REQUEST_TYPE_RE = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
/** Deepest nesting written or read. */
const MAX_DEPTH = 64;

/** Text as XML 1.0 allows it, with &, < and > escaped. Throws on a character XML forbids. */
export function escapeText(s: string): string {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new PlistError('invalid_value', 'a string holds a lone surrogate');
      i++;
      continue;
    }
    if (c >= 0xdc00 && c <= 0xdfff) throw new PlistError('invalid_value', 'a string holds a lone surrogate');
    if (c === 0x9 || c === 0xa || c === 0xd) continue;
    if (c < 0x20 || c === 0xfffe || c === 0xffff) throw new PlistError('invalid_value', 'a string holds a character XML 1.0 forbids');
  }
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function isPlainObject(v: unknown): v is PlistDict {
  if (v === null || typeof v !== 'object') return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function writeValue(v: PlistValue, depth: number, out: string[]): void {
  if (depth > MAX_DEPTH) throw new PlistError('invalid_value', 'the value is nested too deeply');
  const tabs = '\t'.repeat(depth);
  if (typeof v === 'string') { out.push(`${tabs}<string>${escapeText(v)}</string>\n`); return; }
  if (typeof v === 'boolean') { out.push(`${tabs}<${v ? 'true' : 'false'}/>\n`); return; }
  if (typeof v === 'bigint') { out.push(`${tabs}<integer>${v.toString(10)}</integer>\n`); return; }
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new PlistError('invalid_value', 'a number must be a safe integer (PlistReal for a real)');
    out.push(`${tabs}<integer>${Object.is(v, -0) ? '0' : String(v)}</integer>\n`);
    return;
  }
  if (v instanceof PlistReal) {
    if (typeof v.value !== 'number' || !Number.isFinite(v.value)) throw new PlistError('invalid_value', 'a real must be finite');
    out.push(`${tabs}<real>${Object.is(v.value, -0) ? '0' : String(v.value)}</real>\n`);
    return;
  }
  if (v instanceof PlistDate) {
    const t = v.value instanceof Date ? v.value.getTime() : NaN;
    if (!Number.isFinite(t)) throw new PlistError('invalid_value', 'an invalid date');
    out.push(`${tabs}<date>${new Date(Math.floor(t / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')}</date>\n`);
    return;
  }
  if (v instanceof PlistData) { out.push(`${tabs}<data>${v.value.toString('base64')}</data>\n`); return; }
  if (Array.isArray(v)) {
    if (v.length === 0) { out.push(`${tabs}<array/>\n`); return; }
    out.push(`${tabs}<array>\n`);
    for (const e of v) writeValue(e, depth + 1, out);
    out.push(`${tabs}</array>\n`);
    return;
  }
  if (isPlainObject(v)) {
    const keys = Object.keys(v).sort();
    if (keys.length === 0) { out.push(`${tabs}<dict/>\n`); return; }
    out.push(`${tabs}<dict>\n`);
    const inner = '\t'.repeat(depth + 1);
    for (const k of keys) {
      out.push(`${inner}<key>${escapeText(k)}</key>\n`);
      writeValue(v[k], depth + 1, out);
    }
    out.push(`${tabs}</dict>\n`);
    return;
  }
  throw new PlistError('invalid_value', v === null || v === undefined ? 'null and undefined have no plist form' : 'a value of an unsupported type');
}

/** The XML property list of a value (any root), deterministic. */
export function serializePlist(root: PlistValue): string {
  const out: string[] = [HEADER];
  writeValue(root, 0, out);
  out.push(FOOTER);
  return out.join('');
}

export interface CommandPlist {
  /** The exact text submitted. */
  plist: string;
  /** SHA-256 of its UTF-8 bytes (hex). */
  sha256: string;
  bytes: number;
}

/**
 * The plist of a command: { Command: { RequestType, …command }, CommandUUID } (§8.5). `command` is the Command
 * dictionary without its RequestType; the CommandUUID is written in upper case. Throws PlistError('too_large')
 * beyond 4 MiB.
 */
export function commandPlist(commandUuid: string, requestType: string, command: PlistDict): CommandPlist {
  if (!UUID_RE.test(commandUuid)) throw new PlistError('invalid_value', 'the CommandUUID is not a UUID');
  if (!REQUEST_TYPE_RE.test(requestType)) throw new PlistError('invalid_value', 'invalid RequestType');
  if (!isPlainObject(command)) throw new PlistError('invalid_value', 'the Command must be a dictionary');
  if (Object.prototype.hasOwnProperty.call(command, 'RequestType') && command.RequestType !== requestType) {
    throw new PlistError('invalid_value', 'the Command carries another RequestType');
  }
  const plist = serializePlist({ Command: { ...command, RequestType: requestType }, CommandUUID: commandUuid.toUpperCase() });
  const bytes = Buffer.byteLength(plist, 'utf8');
  if (bytes > MAX_COMMAND_BYTES) throw new PlistError('too_large', `the command plist exceeds ${MAX_COMMAND_BYTES} bytes`);
  return { plist, sha256: createHash('sha256').update(plist, 'utf8').digest('hex'), bytes };
}

/** A canonical text of a value (the plist of the value alone): two commands share one plist when it is equal. */
export function plistFingerprint(value: PlistValue): string {
  const out: string[] = [];
  writeValue(value, 0, out);
  return createHash('sha256').update(out.join(''), 'utf8').digest('hex');
}

/** A JSON value (parameters kept in mdm_commands.params) as a plist value: integers stay integers, any other
 *  number becomes a real; null is refused. */
export function plistFromJson(v: unknown, depth = 0): PlistValue {
  if (depth > MAX_DEPTH) throw new PlistError('invalid_value', 'the value is nested too deeply');
  if (typeof v === 'string' || typeof v === 'boolean') return v;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new PlistError('invalid_value', 'a number must be finite');
    return Number.isSafeInteger(v) ? v : new PlistReal(v);
  }
  if (Array.isArray(v)) return v.map((e) => plistFromJson(e, depth + 1));
  if (isPlainObject(v)) {
    const out: PlistDict = {};
    for (const [k, e] of Object.entries(v)) out[k] = plistFromJson(e, depth + 1);
    return out;
  }
  throw new PlistError('invalid_value', 'null has no plist form');
}

const TYPED_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/**
 * A typed JSON value as a plist value: like plistFromJson, plus the markers of the plist types JSON lacks
 * ({"$data": "<base64>"}, {"$date": "<RFC 3339>"}, {"$real": n}, {"$int": "<decimal>"}: the form the policies
 * store their values in, modele-donnees-mdm §7.2). A malformed marker is refused, never written as a dictionary.
 */
export function plistFromTypedJson(v: unknown, depth = 0): PlistValue {
  if (depth > MAX_DEPTH) throw new PlistError('invalid_value', 'the value is nested too deeply');
  if (Array.isArray(v)) return v.map((e) => plistFromTypedJson(e, depth + 1));
  if (isPlainObject(v)) {
    const keys = Object.keys(v);
    if (keys.length === 1 && keys[0].startsWith('$')) {
      const x = (v as Record<string, unknown>)[keys[0]];
      switch (keys[0]) {
        case '$data':
          if (typeof x !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(x) || x.length % 4 !== 0) throw new PlistError('invalid_value', 'a malformed data value');
          return new PlistData(Buffer.from(x, 'base64'));
        case '$date': {
          const t = typeof x === 'string' && TYPED_DATE_RE.test(x) ? Date.parse(x) : NaN;
          if (!Number.isFinite(t)) throw new PlistError('invalid_value', 'a malformed date value');
          return new PlistDate(new Date(t));
        }
        case '$real':
          if (typeof x !== 'number' || !Number.isFinite(x)) throw new PlistError('invalid_value', 'a malformed real value');
          return new PlistReal(x);
        case '$int':
          if (typeof x !== 'string' || !/^-?[0-9]{1,30}$/.test(x)) throw new PlistError('invalid_value', 'a malformed integer value');
          return Number.isSafeInteger(Number(x)) ? Number(x) : BigInt(x);
        default:
          throw new PlistError('invalid_value', 'an unknown typed value');
      }
    }
    const out: PlistDict = {};
    for (const [k, e] of Object.entries(v)) out[k] = plistFromTypedJson(e, depth + 1);
    return out;
  }
  return plistFromJson(v, depth);
}

// ── Reader ─────────────────────────────────────────────────────────────────────
// XML property lists only (what the brain writes, and the profiles a command
// carries as data); bounded like apple-edge's own examination (64 levels,
// 500 000 elements). Not a general XML parser: no entity declaration is read
// (a DOCTYPE with an internal subset is refused), no attribute but the
// plist's version.

const MAX_ELEMENTS = 500_000;

function unescapeText(s: string): string {
  if (!s.includes('&')) return s;
  return s.replace(/&(#x[0-9A-Fa-f]{1,6}|#[0-9]{1,7}|[A-Za-z]+);/g, (m, e: string) => {
    if (e === 'amp') return '&';
    if (e === 'lt') return '<';
    if (e === 'gt') return '>';
    if (e === 'quot') return '"';
    if (e === 'apos') return "'";
    if (e[0] === '#') {
      const code = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      if (Number.isFinite(code) && code > 0 && code <= 0x10ffff) return String.fromCodePoint(code);
    }
    throw new PlistError('invalid_plist', `unknown entity ${m.slice(0, 12)}`);
  });
}

interface Cursor { s: string; i: number; elements: number }

function skipSpace(c: Cursor): void {
  for (;;) {
    while (c.i < c.s.length && /\s/.test(c.s[c.i])) c.i++;
    if (c.s.startsWith('<!--', c.i)) {
      const end = c.s.indexOf('-->', c.i + 4);
      if (end < 0) throw new PlistError('invalid_plist', 'unterminated comment');
      c.i = end + 3;
      continue;
    }
    return;
  }
}

function readTag(c: Cursor): { name: string; closing: boolean; empty: boolean } {
  skipSpace(c);
  if (c.s[c.i] !== '<') throw new PlistError('invalid_plist', 'an element was expected');
  const end = c.s.indexOf('>', c.i);
  if (end < 0) throw new PlistError('invalid_plist', 'unterminated tag');
  let body = c.s.slice(c.i + 1, end).trim();
  c.i = end + 1;
  const closing = body.startsWith('/');
  if (closing) body = body.slice(1).trim();
  const empty = body.endsWith('/');
  if (empty) body = body.slice(0, -1).trim();
  const name = body.split(/\s/, 1)[0];
  if (!/^[a-z]{3,8}$/.test(name)) throw new PlistError('invalid_plist', 'unknown element');
  return { name, closing, empty };
}

function readText(c: Cursor, name: string): string {
  const close = `</${name}>`;
  const end = c.s.indexOf(close, c.i);
  if (end < 0) throw new PlistError('invalid_plist', `unterminated <${name}>`);
  const raw = c.s.slice(c.i, end);
  if (raw.includes('<')) throw new PlistError('invalid_plist', `markup inside <${name}>`);
  c.i = end + close.length;
  return unescapeText(raw);
}

function readValue(c: Cursor, depth: number, first?: { name: string; closing: boolean; empty: boolean }): PlistValue {
  if (depth > MAX_DEPTH) throw new PlistError('invalid_plist', 'the property list is nested too deeply');
  if (++c.elements > MAX_ELEMENTS) throw new PlistError('invalid_plist', 'the property list holds too many elements');
  const tag = first ?? readTag(c);
  if (tag.closing) throw new PlistError('invalid_plist', 'unexpected closing tag');
  switch (tag.name) {
    case 'true': if (!tag.empty) readText(c, 'true'); return true;
    case 'false': if (!tag.empty) readText(c, 'false'); return false;
    case 'string': return tag.empty ? '' : readText(c, 'string');
    case 'integer': {
      const t = (tag.empty ? '' : readText(c, 'integer')).trim();
      if (!/^[+-]?[0-9]{1,20}$/.test(t)) throw new PlistError('invalid_plist', 'invalid integer');
      const n = Number(t);
      return Number.isSafeInteger(n) ? n : BigInt(t);
    }
    case 'real': {
      const n = Number((tag.empty ? '' : readText(c, 'real')).trim());
      if (!Number.isFinite(n)) throw new PlistError('invalid_plist', 'invalid real');
      return new PlistReal(n);
    }
    case 'date': {
      const d = new Date((tag.empty ? '' : readText(c, 'date')).trim());
      if (Number.isNaN(d.getTime())) throw new PlistError('invalid_plist', 'invalid date');
      return new PlistDate(d);
    }
    case 'data': {
      const t = (tag.empty ? '' : readText(c, 'data')).replace(/\s+/g, '');
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(t)) throw new PlistError('invalid_plist', 'invalid data');
      return new PlistData(Buffer.from(t, 'base64'));
    }
    case 'array': {
      const out: PlistValue[] = [];
      if (tag.empty) return out;
      for (;;) {
        const next = readTag(c);
        if (next.closing) {
          if (next.name !== 'array') throw new PlistError('invalid_plist', 'mismatched closing tag');
          return out;
        }
        out.push(readValue(c, depth + 1, next));
      }
    }
    case 'dict': {
      const out: PlistDict = Object.create(null) as PlistDict;
      if (tag.empty) return { ...out };
      for (;;) {
        const k = readTag(c);
        if (k.closing) {
          if (k.name !== 'dict') throw new PlistError('invalid_plist', 'mismatched closing tag');
          return { ...out };
        }
        if (k.name !== 'key') throw new PlistError('invalid_plist', 'a <key> was expected');
        const key = k.empty ? '' : readText(c, 'key');
        out[key] = readValue(c, depth + 1);
      }
    }
    default:
      throw new PlistError('invalid_plist', 'unknown element');
  }
}

/** Does this text look like an XML property list (after a BOM and white space)? */
export function looksLikeXmlPlist(text: string): boolean {
  const t = text.replace(/^﻿/, '').trimStart();
  return t.startsWith('<?xml') || t.startsWith('<plist') || t.startsWith('<!DOCTYPE');
}

/** Reads an XML property list. Throws PlistError('invalid_plist'). */
export function parsePlist(text: string): PlistValue {
  const c: Cursor = { s: String(text).replace(/^﻿/, ''), i: 0, elements: 0 };
  skipSpace(c);
  if (c.s.startsWith('<?xml', c.i)) {
    const end = c.s.indexOf('?>', c.i);
    if (end < 0) throw new PlistError('invalid_plist', 'unterminated XML declaration');
    c.i = end + 2;
  }
  skipSpace(c);
  if (c.s.startsWith('<!DOCTYPE', c.i)) {
    const end = c.s.indexOf('>', c.i);
    const decl = end < 0 ? '' : c.s.slice(c.i, end);
    if (end < 0 || decl.includes('[')) throw new PlistError('invalid_plist', 'a DOCTYPE with declarations is refused');
    c.i = end + 1;
  }
  const open = readTag(c);
  if (open.name !== 'plist' || open.closing) throw new PlistError('invalid_plist', 'a <plist> root was expected');
  if (open.empty) throw new PlistError('invalid_plist', 'empty property list');
  const value = readValue(c, 0);
  const close = readTag(c);
  if (!close.closing || close.name !== 'plist') throw new PlistError('invalid_plist', 'the <plist> root is not closed');
  skipSpace(c);
  if (c.i < c.s.length) throw new PlistError('invalid_plist', 'content after the property list');
  return value;
}
