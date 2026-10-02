import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { combine, split } from 'shamir-secret-sharing';
import { KEY_BYTES, kekIdOf, parseKek } from './envelope';
import { readKekFile } from './kek';

// =============================================================================
// Escrow of the vault's keys (docs: coffre-secrets §9.2; V13)
// =============================================================================
//
// One bundle, a UTF-8 JSON text that never touches the disk:
//   { "v": 1, "created_at": "2026-10-01T10:00:00Z",
//     "keys": { "server_kek": "<base64>", "edge_kek": "<base64>" },
//     "extra": { "backup_passphrase": "<…>" },
//     "kek_ids": { "server": "<16 hex>", "edge": "<16 hex>" } }
// split by Shamir's secret sharing over GF(2^8) into 3 shares, any 2 of which
// rebuild it. The sharing itself is the published and audited library
// shamir-secret-sharing (Apache-2.0; audits by Cure53 and Zellic), pinned in
// server/package.json and loaded by the vault's CLI only: this module is
// imported by vault/cli.ts (escrow commands), never by the server.
//
// A share is printed text, copied by hand or printed, never a file:
//   OBLIGARTH-ESCROW v1
//   created 2026-10-01T10:00:00Z   threshold 2/3   share 1
//   server_kek_id 630dcd2966c43366   edge_kek_id 1f2e3d4c5b6a7980
//   MFRG GZDF MZTW Q2LK NNWG 23TP OBYX E43U
//   …
//   check 9f3a1c07
// The share bytes (the library's: one byte per byte of the bundle, then the
// share's x coordinate) in base32 (RFC 4648, no padding), groups of four,
// eight groups per line; `check` = 8 first hex characters of SHA-256 of the
// share bytes, which catches a copying error. The kek_ids are not secret:
// they tell which generation of keys a share belongs to. The library does
// not check what it rebuilds: the bundle is checked here (JSON, sizes, the
// kek_id of each key against the headers), and, given more shares than the
// threshold, every subset must rebuild the same bundle.
//
// Commands (vault/cli.ts; no database, no network):
//   escrow split --kek server=<file> [--kek edge=<file>] [--extra <name>=<file>]
//                [--threshold 2] [--shares 3]     shares on stdout
//   escrow combine --out-dir <dir>                shares on stdin; keys written
//                                                 to <dir>, never over a file
//   escrow verify --expect server=<kek_id> [--expect edge=<kek_id>]
//                                                 shares on stdin, nothing written
// Exit codes: 0; 2 shares refused, too few, inconsistent, or keys other than
// expected; 1 usage or file errors. Never a key, a share or a passphrase in a
// message or in the JSON result: kek_ids, names, numbers, counts.

export const ESCROW_HEADER = 'OBLIGARTH-ESCROW v1';
const KEK_NAMES = ['server', 'edge'] as const;
type KekName = (typeof KEK_NAMES)[number];
const EXTRA_NAME_RE = /^[a-z][a-z0-9_]{0,31}$/;
const EXTRA_MAX_BYTES = 1024;
const KEK_ID_RE = /^[0-9a-f]{16}$/;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export type EscrowErrorCode = 'usage' | 'io' | 'share_invalid' | 'too_few_shares' | 'inconsistent' | 'bundle_invalid' | 'kek_mismatch';

/** A refusal of the escrow commands; the message never carries a secret. */
export class EscrowError extends Error {
  readonly code: EscrowErrorCode;

  constructor(code: EscrowErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = 'EscrowError';
  }

  /** Exit code of the CLI: 1 usage and files, 2 shares and keys. */
  get exitCode(): number {
    return this.code === 'usage' || this.code === 'io' ? 1 : 2;
  }
}

/** What every share of one ceremony states in clear. */
export interface EscrowHeader {
  created: string;               // UTC, seconds: 2026-10-01T10:00:00Z
  threshold: number;
  shares: number;
  kekIds: { server: string; edge: string | null };
}

export interface ParsedShare extends EscrowHeader {
  number: number;
  bytes: Uint8Array;
}

/** The rebuilt bundle: keys are the caller's (fill(0) once written). */
export interface RebuiltBundle {
  created: string;
  kekIds: { server: string; edge: string | null };
  keys: { server: Buffer; edge: Buffer | null };
  extra: Record<string, string>;
  sharesUsed: number[];
}

// ── base32 (RFC 4648, no padding) ───────────────────────────────────────────

export function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

/** Decodes base32 (case-insensitive, blanks ignored); null for a character
 *  out of the alphabet, a length no encoder produces or non-zero padding
 *  bits (one writing only). */
export function base32Decode(text: string): Uint8Array | null {
  const t = text.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z2-7]*$/.test(t) || [1, 3, 6].includes(t.length % 8)) return null;
  const out = new Uint8Array(Math.floor((t.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let i = 0;
  for (const c of t) {
    value = (value << 5) | BASE32.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out[i++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  return value === 0 ? out : null;
}

const checkOf = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex').slice(0, 8);

// ── format of a share ───────────────────────────────────────────────────────

/** The printed text of a share. */
export function formatShare(header: EscrowHeader, number: number, bytes: Uint8Array): string {
  const groups = base32Encode(bytes).match(/.{1,4}/g) ?? [];
  const lines: string[] = [];
  for (let i = 0; i < groups.length; i += 8) lines.push(groups.slice(i, i + 8).join(' '));
  return [
    ESCROW_HEADER,
    `created ${header.created}   threshold ${header.threshold}/${header.shares}   share ${number}`,
    `server_kek_id ${header.kekIds.server}   edge_kek_id ${header.kekIds.edge ?? '-'}`,
    ...lines,
    `check ${checkOf(bytes)}`,
  ].join('\n');
}

/**
 * The shares found in a text (stdin of combine and verify): every block that
 * starts with the header line. A block that does not read (header, base32,
 * check line) is listed in `problems` by its share number when it has one,
 * never with its content.
 */
export function parseShares(text: string): { shares: ParsedShare[]; problems: string[] } {
  // A copy by hand: case, blanks and line breaks do not matter; characters do.
  const lines = String(text).split(/\r?\n/).map((l) => l.trim().replace(/\s+/g, ' '));
  const isHeader = (l: string | undefined) => (l ?? '').toUpperCase() === ESCROW_HEADER.toUpperCase();
  const shares: ParsedShare[] = [];
  const problems: string[] = [];
  let i = 0;
  let block = 0;
  while (i < lines.length) {
    if (!isHeader(lines[i])) { i++; continue; }
    block++;
    const start = i + 1;
    let end = start;
    while (end < lines.length && !isHeader(lines[end]) && !/^check /i.test(lines[end])) end++;
    const label = (n: number | null) => (n === null ? `block ${block}` : `share ${n}`);
    const h1 = /^created (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) threshold (\d)\/(\d) share (\d)$/i.exec(lines[start] ?? '');
    const h2 = /^server_kek_id ([0-9a-f]{16}) edge_kek_id ([0-9a-f]{16}|-)$/i.exec(lines[start + 1] ?? '');
    const number = h1 ? Number(h1[4]) : null;
    if (end >= lines.length || isHeader(lines[end])) {
      problems.push(`${label(number)}: no check line`);
      i = end;
      continue;
    }
    i = end + 1;
    const check = /^check ([0-9a-f]{8})$/i.exec(lines[end]);
    if (!h1 || !h2) { problems.push(`${label(number)}: header lines not readable`); continue; }
    if (!check) { problems.push(`${label(number)}: check line not readable`); continue; }
    const threshold = Number(h1[2]);
    const total = Number(h1[3]);
    if (!(threshold >= 2 && threshold <= total && number !== null && number >= 1 && number <= total)) {
      problems.push(`${label(number)}: threshold or share number out of range`);
      continue;
    }
    const data = lines.slice(start + 2, end).join('');
    const bytes = base32Decode(data);
    if (!bytes || bytes.length < 2) { problems.push(`${label(number)}: characters outside base32 or truncated`); continue; }
    if (checkOf(bytes) !== check[1].toLowerCase()) {
      bytes.fill(0);
      problems.push(`${label(number)}: check failed (copying error)`);
      continue;
    }
    shares.push({
      number, bytes, created: h1[1].toUpperCase(), threshold, shares: total,
      kekIds: { server: h2[1].toLowerCase(), edge: h2[2] === '-' ? null : h2[2].toLowerCase() },
    });
  }
  return { shares, problems };
}

// ── split ───────────────────────────────────────────────────────────────────

export interface SplitInput {
  keks: { server: { id: string; key: Buffer }; edge?: { id: string; key: Buffer } | null };
  extra?: Record<string, string>;
  threshold?: number;
  shares?: number;
  now?: Date;
}

/** The bundle split into printed shares (the bundle itself only in memory,
 *  zeroed once split). */
export async function splitBundle(input: SplitInput): Promise<{ header: EscrowHeader; shares: string[] }> {
  const threshold = input.threshold ?? 2;
  const total = input.shares ?? 3;
  if (!(Number.isInteger(threshold) && Number.isInteger(total) && threshold >= 2 && total >= threshold && total <= 9)) {
    throw new EscrowError('usage', 'escrow split: --threshold and --shares must be integers with 2 <= threshold <= shares <= 9');
  }
  const { server, edge } = input.keks;
  for (const [name, k] of [['server', server], ['edge', edge]] as const) {
    if (k && (!Buffer.isBuffer(k.key) || k.key.length !== KEY_BYTES || kekIdOf(k.key) !== k.id)) {
      throw new EscrowError('usage', `escrow split: the ${name} KEK is not a 32-byte key`);
    }
  }
  const extra: Record<string, string> = {};
  for (const [name, value] of Object.entries(input.extra ?? {})) {
    if (!EXTRA_NAME_RE.test(name)) throw new EscrowError('usage', `escrow split: invalid extra name ${JSON.stringify(name.slice(0, 40))}`);
    if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value) > EXTRA_MAX_BYTES || value.includes('\0')) {
      throw new EscrowError('usage', `escrow split: the extra ${name} is empty, too long or not text`);
    }
    extra[name] = value;
  }
  const created = (input.now ?? new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const header: EscrowHeader = { created, threshold, shares: total, kekIds: { server: server.id, edge: edge?.id ?? null } };
  const bundle: Record<string, unknown> = {
    v: 1,
    created_at: created,
    keys: { server_kek: server.key.toString('base64'), ...(edge ? { edge_kek: edge.key.toString('base64') } : {}) },
    extra,
    kek_ids: { server: server.id, ...(edge ? { edge: edge.id } : {}) },
  };
  const secret = Buffer.from(JSON.stringify(bundle), 'utf8');
  try {
    const parts = await split(new Uint8Array(secret.buffer, secret.byteOffset, secret.byteLength), total, threshold);
    // Each share must rebuild with any other one before anything is printed.
    const texts = parts.map((bytes, i) => formatShare(header, i + 1, bytes));
    const reparsed = parseShares(texts.join('\n\n'));
    if (reparsed.problems.length || reparsed.shares.length !== total) throw new Error('escrow split: self-check of the shares failed');
    const rebuilt = await combineShares(reparsed.shares);
    rebuilt.keys.server.fill(0);
    rebuilt.keys.edge?.fill(0);
    for (const p of [...parts, ...reparsed.shares.map((s) => s.bytes)]) p.fill(0);
    return { header, shares: texts };
  } finally {
    secret.fill(0);
  }
}

// ── combine ─────────────────────────────────────────────────────────────────

function* subsets<T>(items: T[], k: number, start = 0, acc: T[] = []): Generator<T[]> {
  if (acc.length === k) { yield [...acc]; return; }
  for (let i = start; i < items.length; i++) yield* subsets(items, k, i + 1, [...acc, items[i]]);
}

function keyFrom(b64: unknown): Buffer | null {
  if (typeof b64 !== 'string') return null;
  try {
    return parseKek(b64).key;
  } catch {
    return null;
  }
}

/** The bundle of a set of shares, checked against their headers. */
async function rebuildFrom(shares: ParsedShare[]): Promise<RebuiltBundle> {
  const bytes = await combine(shares.map((s) => s.bytes));
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Record<string, unknown>;
  } catch {
    throw new EscrowError('bundle_invalid', 'the shares do not rebuild a bundle (shares of different ceremonies, or a copying error)');
  } finally {
    bytes.fill(0);
  }
  const h = shares[0];
  const keys = (doc.keys ?? {}) as Record<string, unknown>;
  const ids = (doc.kek_ids ?? {}) as Record<string, unknown>;
  const server = keyFrom(keys.server_kek);
  const edge = keys.edge_kek === undefined ? null : keyFrom(keys.edge_kek);
  const extraIn = (doc.extra ?? {}) as Record<string, unknown>;
  const extraOk = typeof extraIn === 'object' && extraIn !== null && !Array.isArray(extraIn)
    && Object.entries(extraIn).every(([k, v]) => EXTRA_NAME_RE.test(k) && typeof v === 'string');
  const fail = () => {
    server?.fill(0);
    edge?.fill(0);
    return new EscrowError('bundle_invalid', 'the rebuilt bundle does not hold (keys, kek_ids or date other than the shares state)');
  };
  if (doc.v !== 1 || doc.created_at !== h.created || !server || (keys.edge_kek !== undefined && !edge) || !extraOk) throw fail();
  const serverId = kekIdOf(server);
  const edgeId = edge ? kekIdOf(edge) : null;
  if (serverId !== ids.server || serverId !== h.kekIds.server || (edgeId ?? undefined) !== ids.edge || edgeId !== h.kekIds.edge) throw fail();
  return {
    created: h.created, kekIds: { server: serverId, edge: edgeId }, keys: { server, edge },
    extra: Object.fromEntries(Object.entries(extraIn as Record<string, string>)), sharesUsed: shares.map((s) => s.number).sort((a, b) => a - b),
  };
}

/**
 * Rebuilds the bundle from parsed shares: one ceremony (same date, threshold
 * and kek_ids), distinct share numbers, at least the threshold; given more,
 * every subset of `threshold` shares must rebuild the same bundle (a share
 * that disagrees is named).
 */
export async function combineShares(shares: ParsedShare[]): Promise<RebuiltBundle> {
  if (shares.length === 0) throw new EscrowError('too_few_shares', 'no share given');
  const h = shares[0];
  for (const s of shares) {
    if (s.created !== h.created || s.threshold !== h.threshold || s.shares !== h.shares
        || s.kekIds.server !== h.kekIds.server || s.kekIds.edge !== h.kekIds.edge) {
      throw new EscrowError('inconsistent', `share ${s.number} belongs to another ceremony (date, threshold or kek_ids)`);
    }
  }
  const numbers = shares.map((s) => s.number);
  if (new Set(numbers).size !== numbers.length) throw new EscrowError('inconsistent', 'the same share is given twice');
  if (shares.length < h.threshold) {
    throw new EscrowError('too_few_shares', `${shares.length} share(s) given, ${h.threshold} needed`);
  }
  const results: Array<{ used: number[]; bundle: RebuiltBundle | null }> = [];
  for (const subset of subsets(shares, h.threshold)) {
    try {
      results.push({ used: subset.map((s) => s.number), bundle: await rebuildFrom(subset) });
    } catch (err) {
      if (!(err instanceof EscrowError)) throw err;
      results.push({ used: subset.map((s) => s.number), bundle: null });
    }
  }
  const good = results.filter((r) => r.bundle);
  const same = (a: RebuiltBundle, b: RebuiltBundle) => a.keys.server.equals(b.keys.server)
    && ((a.keys.edge === null && b.keys.edge === null) || (a.keys.edge !== null && b.keys.edge !== null && a.keys.edge.equals(b.keys.edge)))
    && JSON.stringify(a.extra) === JSON.stringify(b.extra);
  const wipe = () => { for (const r of results) { r.bundle?.keys.server.fill(0); r.bundle?.keys.edge?.fill(0); } };
  if (good.length === results.length && good.every((r) => same(r.bundle!, good[0].bundle!))) {
    const first = good[0].bundle!;
    const out: RebuiltBundle = {
      ...first, keys: { server: Buffer.from(first.keys.server), edge: first.keys.edge ? Buffer.from(first.keys.edge) : null },
      sharesUsed: numbers.slice().sort((a, b) => a - b),
    };
    wipe();
    return out;
  }
  wipe();
  if (shares.length === h.threshold) {
    throw new EscrowError('bundle_invalid', 'the shares do not rebuild a valid bundle (shares of different ceremonies, or a copying error)');
  }
  // The share in none of the subsets that rebuild a valid bundle disagrees with the others.
  const inGood = new Set(good.flatMap((r) => r.used));
  const odd = numbers.filter((n) => !inGood.has(n));
  throw new EscrowError('inconsistent', odd.length
    ? `share ${odd.join(', ')} disagrees with the others (copying error, or a share of another ceremony)`
    : 'the shares disagree with one another');
}

// ── CLI ─────────────────────────────────────────────────────────────────────

export interface EscrowIo {
  readStdin(): Promise<string>;
  write(text: string): void;
}

function pairs(args: string[], flag: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] !== flag) continue;
    const v = args[i + 1] ?? '';
    const eq = v.indexOf('=');
    if (eq <= 0 || eq === v.length - 1) throw new EscrowError('usage', `${flag} <name>=<value>`);
    out.push([v.slice(0, eq), v.slice(eq + 1)]);
  }
  return out;
}

function single(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

function readKek(name: string, file: string): { id: string; key: Buffer } {
  try {
    return readKekFile(file);
  } catch (err) {
    throw new EscrowError('io', `escrow split: ${name} KEK: ${(err as Error).message}`);
  }
}

function readExtra(name: string, file: string): string {
  let raw: Buffer;
  try {
    raw = readFileSync(file);
  } catch (err) {
    throw new EscrowError('io', `escrow split: extra ${name}: ${(err as { code?: string }).code === 'ENOENT' ? 'no such file' : 'unreadable'}`);
  }
  try {
    if (raw.length > EXTRA_MAX_BYTES + 2) throw new EscrowError('usage', `escrow split: extra ${name}: larger than ${EXTRA_MAX_BYTES} bytes`);
    return new TextDecoder('utf-8', { fatal: true }).decode(raw).replace(/[\r\n]+$/, '');
  } catch (err) {
    if (err instanceof EscrowError) throw err;
    throw new EscrowError('usage', `escrow split: extra ${name}: not UTF-8 text`);
  } finally {
    raw.fill(0);
  }
}

async function cliSplit(args: string[], io: EscrowIo): Promise<number> {
  const keks = new Map<KekName, { id: string; key: Buffer }>();
  const extra: Record<string, string> = {};
  try {
    for (const [name, file] of pairs(args, '--kek')) {
      if (!(KEK_NAMES as readonly string[]).includes(name)) throw new EscrowError('usage', 'escrow split: --kek server=<file> [--kek edge=<file>]');
      if (keks.has(name as KekName)) throw new EscrowError('usage', `escrow split: --kek ${name} given twice`);
      keks.set(name as KekName, readKek(name, file));
    }
    for (const [name, file] of pairs(args, '--extra')) {
      if (!EXTRA_NAME_RE.test(name)) throw new EscrowError('usage', 'escrow split: --extra <name>=<file>, name in [a-z0-9_]');
      extra[name] = readExtra(name, file);
    }
    const server = keks.get('server');
    if (!server) throw new EscrowError('usage', 'escrow split: --kek server=<file> is required');
    const edge = keks.get('edge') ?? null;
    if (edge && edge.id === server.id) throw new EscrowError('usage', 'escrow split: the server and edge KEKs are the same key');
    const threshold = Number(single(args, '--threshold') ?? 2);
    const total = Number(single(args, '--shares') ?? 3);
    const { header, shares } = await splitBundle({ keks: { server, edge }, extra, threshold, shares: total });
    io.write(`${shares.join('\n\n')}\n\n`);
    io.write(`${JSON.stringify({
      escrow: 'split', created: header.created, threshold: header.threshold, shares: header.shares,
      kekIds: header.kekIds, extra: Object.keys(extra).sort(),
    })}\n`);
    return 0;
  } finally {
    for (const k of keks.values()) k.key.fill(0);
  }
}

async function rebuildFromStdin(io: EscrowIo, command: string): Promise<{ bundle: RebuiltBundle; problems: string[] }> {
  const { shares, problems } = parseShares(await io.readStdin());
  try {
    if (shares.length === 0) {
      throw new EscrowError(problems.length ? 'share_invalid' : 'too_few_shares',
        `escrow ${command}: no readable share on stdin${problems.length ? ` (${problems.join('; ')})` : ''}`);
    }
    const bundle = await combineShares(shares).catch((err: unknown) => {
      if (err instanceof EscrowError && problems.length) {
        throw new EscrowError(err.code, `${err.message} (${problems.join('; ')})`);
      }
      throw err;
    });
    return { bundle, problems };
  } finally {
    for (const s of shares) s.bytes.fill(0);
  }
}

async function cliVerify(args: string[], io: EscrowIo): Promise<number> {
  const expected = pairs(args, '--expect');
  const expect: Partial<Record<KekName, string>> = {};
  for (const [name, id] of expected) {
    if (!(KEK_NAMES as readonly string[]).includes(name) || !KEK_ID_RE.test(id)) {
      throw new EscrowError('usage', 'escrow verify: --expect server=<kek_id> [--expect edge=<kek_id>] (16 hex characters)');
    }
    expect[name as KekName] = id;
  }
  if (!expect.server) throw new EscrowError('usage', 'escrow verify: --expect server=<kek_id> is required (the kek_id of the current KEK)');
  const { bundle, problems } = await rebuildFromStdin(io, 'verify');
  try {
    const mismatches = KEK_NAMES.filter((n) => expect[n] !== undefined && bundle.kekIds[n] !== expect[n]);
    const result = {
      escrow: 'verify', ok: mismatches.length === 0, created: bundle.created, shares: bundle.sharesUsed,
      kekIds: bundle.kekIds, expected: expect, extra: Object.keys(bundle.extra).sort(), refusedShares: problems,
    };
    io.write(`${JSON.stringify(result)}\n`);
    if (mismatches.length) {
      throw new EscrowError('kek_mismatch', `escrow verify: the shares hold other keys than expected (${mismatches
        .map((n) => `${n}: ${bundle.kekIds[n] ?? 'absent'} instead of ${expect[n]}`).join(', ')})`);
    }
    return 0;
  } finally {
    bundle.keys.server.fill(0);
    bundle.keys.edge?.fill(0);
  }
}

async function cliCombine(args: string[], io: EscrowIo): Promise<number> {
  const outDir = single(args, '--out-dir');
  if (!outDir) throw new EscrowError('usage', 'escrow combine: --out-dir <folder> is required');
  const { bundle, problems } = await rebuildFromStdin(io, 'combine');
  const written: string[] = [];
  try {
    try {
      mkdirSync(outDir, { recursive: true, mode: 0o700 });
    } catch {
      throw new EscrowError('io', 'escrow combine: --out-dir cannot be created');
    }
    const files: Array<[string, string]> = [['server_kek', `${bundle.keys.server.toString('base64')}\n`]];
    if (bundle.keys.edge) files.push(['edge_kek', `${bundle.keys.edge.toString('base64')}\n`]);
    for (const [name, value] of Object.entries(bundle.extra)) files.push([name, `${value}\n`]);
    for (const [name, content] of files) {
      try {
        // 'wx': never over an existing file (a key in place is never replaced by the tool).
        writeFileSync(path.join(outDir, name), content, { mode: 0o600, flag: 'wx' });
      } catch (err) {
        throw new EscrowError('io', `escrow combine: ${name}: ${(err as { code?: string }).code === 'EEXIST'
          ? 'a file of that name already exists in --out-dir (never replaced)' : 'cannot be written'}`
          + (written.length ? ` (already written: ${written.join(', ')})` : ''));
      }
      written.push(name);
    }
    io.write(`${JSON.stringify({
      escrow: 'combine', created: bundle.created, shares: bundle.sharesUsed, kekIds: bundle.kekIds, written, refusedShares: problems,
    })}\n`);
    return 0;
  } finally {
    bundle.keys.server.fill(0);
    bundle.keys.edge?.fill(0);
  }
}

/** `vault escrow <split | combine | verify>`: the exit code (EscrowError
 *  thrown for a refusal: its exitCode). */
export async function escrowCli(args: string[], io: EscrowIo): Promise<number> {
  const [sub, ...rest] = args;
  if (sub === 'split') return cliSplit(rest, io);
  if (sub === 'combine') return cliCombine(rest, io);
  if (sub === 'verify') return cliVerify(rest, io);
  throw new EscrowError('usage', 'usage: vault escrow <split | combine | verify> [options] (coffre-secrets §9.2)');
}
