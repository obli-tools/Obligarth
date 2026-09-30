import fs from 'node:fs';
import path from 'node:path';

// ── Google attestation revocation list (device-bound 2FA, §4.3 step 4) ─────
//
// docs/mobile/device-bound-2fa.md §4.3 step 4 and [D4]:
//   - source: https://android.googleapis.com/attestation/status
//     ({"entries": {"<serial lowercase hex>": {"status": "REVOKED" |
//     "SUSPENDED", "reason"?, "expires"?, "comment"?}}}), Cache-Control 24 h;
//   - kept 24 h in memory and in a file (`<CUSTOM_DIR>/device-keys/
//     attestation-status.json`, so a restart does not need Google);
//   - Google unreachable: a copy up to 7 days old is still used; beyond
//     that, or with no copy at all, get() returns null and the enrolment
//     fails closed ('status_unavailable') when attestation is required.
//
// No project import (node --test): the caller injects the file path, the
// fetch function, the clock and a logger. Erasable TypeScript only.

export const STATUS_URL = 'https://android.googleapis.com/attestation/status';
export const STATUS_FRESH_MS = 24 * 60 * 60 * 1000;
export const STATUS_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
/** After a failed download, serve the cache without retrying for this long. */
export const STATUS_RETRY_AFTER_FAILURE_MS = 5 * 60 * 1000;
export const STATUS_FETCH_TIMEOUT_MS = 10_000;
/** The list is ~180 KB (2026-09); refuse anything absurd. */
export const STATUS_MAX_BYTES = 8 * 1024 * 1024;

export interface StatusListView {
  /** serial (lowercase hex, no leading zeros) → 'REVOKED' | 'SUSPENDED'. */
  entries: ReadonlyMap<string, string>;
  /** When this copy was downloaded from Google (epoch ms). */
  fetchedAt: number;
}

export type StatusLog = (level: 'info' | 'warn', msg: string, extra?: Record<string, unknown>) => void;

export interface StatusStoreOptions {
  url?: string;
  /** Cache file; null disables the file cache. */
  filePath: string | null;
  fetchImpl?: (url: string, init: { signal: AbortSignal; headers: Record<string, string> }) => Promise<{
    ok: boolean; status: number; text(): Promise<string>; headers?: { get(name: string): string | null };
  }>;
  now?: () => number;
  log?: StatusLog;
  freshMs?: number;
  maxAgeMs?: number;
  retryAfterFailureMs?: number;
  timeoutMs?: number;
}

/** Serial as written by the status list: lowercase hex, no leading zeros. */
export function normaliseSerial(hex: string): string {
  const s = String(hex).toLowerCase().replace(/^0+/, '');
  return s === '' ? '0' : s;
}

/**
 * Validates the status list JSON. Returns the REVOKED / SUSPENDED entries,
 * or null when the document is not a status list. Unknown statuses are
 * ignored (the schema only allows these two).
 */
export function parseStatusList(json: unknown): Map<string, string> | null {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return null;
  const entries = (json as { entries?: unknown }).entries;
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) return null;
  const out = new Map<string, string>();
  for (const [serial, v] of Object.entries(entries as Record<string, unknown>)) {
    if (!/^[0-9a-fA-F]{1,128}$/.test(serial)) continue;
    const status = v && typeof v === 'object' ? (v as { status?: unknown }).status : undefined;
    if (status === 'REVOKED' || status === 'SUSPENDED') out.set(normaliseSerial(serial), status);
  }
  return out;
}

interface Snapshot { fetchedAt: number; entries: Map<string, string> }

export interface StatusListStore {
  /** A list younger than 7 days (downloading when older than 24 h), or null. */
  get(): Promise<StatusListView | null>;
  /** Downloads now (daily task). True on success. Never throws. */
  refresh(): Promise<boolean>;
  /** The copy in memory (tests, investigation). */
  current(): StatusListView | null;
}

export function createStatusListStore(opts: StatusStoreOptions): StatusListStore {
  const url = opts.url ?? STATUS_URL;
  const now = opts.now ?? (() => Date.now());
  const log: StatusLog = opts.log ?? (() => undefined);
  const freshMs = opts.freshMs ?? STATUS_FRESH_MS;
  const maxAgeMs = opts.maxAgeMs ?? STATUS_MAX_AGE_MS;
  const retryAfterFailureMs = opts.retryAfterFailureMs ?? STATUS_RETRY_AFTER_FAILURE_MS;
  const timeoutMs = opts.timeoutMs ?? STATUS_FETCH_TIMEOUT_MS;
  const fetchImpl = opts.fetchImpl ?? ((u, init) => fetch(u, init));

  let mem: Snapshot | null = null;
  let fileLoaded = false;
  let lastFailureAt = -Infinity;
  let inflight: Promise<boolean> | null = null;

  const view = (s: Snapshot): StatusListView => ({ entries: s.entries, fetchedAt: s.fetchedAt });
  const ageOf = (s: Snapshot) => now() - s.fetchedAt;
  /** A copy dated in the future (clock change, edited file) is not trusted. */
  const plausible = (s: Snapshot) => ageOf(s) >= -5 * 60 * 1000;

  function loadFile(): void {
    fileLoaded = true;
    if (!opts.filePath) return;
    try {
      const raw = fs.readFileSync(opts.filePath, 'utf8');
      if (raw.length > STATUS_MAX_BYTES * 2) return;
      const doc = JSON.parse(raw) as { fetchedAt?: unknown; list?: unknown };
      const fetchedAt = typeof doc.fetchedAt === 'string' ? Date.parse(doc.fetchedAt) : NaN;
      const entries = parseStatusList(doc.list);
      if (!Number.isFinite(fetchedAt) || !entries) {
        log('warn', 'attestation status cache file ignored (unreadable)', { file: opts.filePath });
        return;
      }
      const snap = { fetchedAt, entries };
      if (!plausible(snap)) {
        log('warn', 'attestation status cache file ignored (dated in the future)', { file: opts.filePath });
        return;
      }
      if (!mem || snap.fetchedAt > mem.fetchedAt) mem = snap;
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
        log('warn', 'attestation status cache file unreadable', { file: opts.filePath, err: String(err) });
      }
    }
  }

  function saveFile(list: unknown, fetchedAt: number): void {
    if (!opts.filePath) return;
    try {
      fs.mkdirSync(path.dirname(opts.filePath), { recursive: true });
      const tmp = `${opts.filePath}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ fetchedAt: new Date(fetchedAt).toISOString(), source: url, list }));
      fs.renameSync(tmp, opts.filePath);
    } catch (err) {
      log('warn', 'attestation status cache file not written', { file: opts.filePath, err: String(err) });
    }
  }

  async function download(): Promise<boolean> {
    try {
      const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/json' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const declared = Number(res.headers?.get('content-length') ?? NaN);
      if (Number.isFinite(declared) && declared > STATUS_MAX_BYTES) throw new Error('status list too large');
      const text = await res.text();
      if (text.length > STATUS_MAX_BYTES) throw new Error('status list too large');
      const list = JSON.parse(text) as unknown;
      const entries = parseStatusList(list);
      if (!entries) throw new Error('not a status list');
      const fetchedAt = now();
      mem = { fetchedAt, entries };
      saveFile(list, fetchedAt);
      log('info', 'attestation status list refreshed', { entries: entries.size });
      return true;
    } catch (err) {
      lastFailureAt = now();
      log('warn', 'attestation status list download failed', { err: String(err) });
      return false;
    }
  }

  function refresh(): Promise<boolean> {
    if (!inflight) {
      inflight = download().finally(() => { inflight = null; });
    }
    return inflight;
  }

  return {
    async get() {
      if (!fileLoaded) loadFile();
      if (mem && plausible(mem) && ageOf(mem) < freshMs) return view(mem);
      if (now() - lastFailureAt >= retryAfterFailureMs) await refresh();
      if (mem && plausible(mem) && ageOf(mem) < freshMs) return view(mem);
      if (mem && plausible(mem) && ageOf(mem) <= maxAgeMs) return view(mem);
      return null;
    },
    refresh,
    current() {
      if (!fileLoaded) loadFile();
      return mem ? view(mem) : null;
    },
  };
}
