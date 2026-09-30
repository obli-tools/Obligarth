import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import type { ObliReachDesired, ObliReachAutoStatus } from '@obliance/shared';

// ── ObliReach automatic install / update (server side) ──────────────────────
//
// The Obliance agent keeps ObliReach at the version THIS server ships. The
// server publishes the target in the /api/agent/push response (`oblireach`:
// enabled, version, file, sha256, size, hold); the agent reconciles and
// reports its state in its next push body, stored in devices.oblireach_status.
// No command type, no extra poll.
//
// The files are the ones /api/agent/download serves (agent/dist, baked into
// the server image). Their SHA-256 is computed once per file content (cached
// on mtime + size, re-checked at most every 60 s, streamed: never blocks the
// event loop), shared by the push response and the download route.

const DEFAULT_DIST_DIR = path.resolve(__dirname, '../../../../agent/dist');
let distDir = DEFAULT_DIST_DIR;

const VERSION_TTL_MS = 60_000;
const STAT_TTL_MS = 60_000;
/** An 'active' session older than this is a leftover, not a reason to hold. */
const HOLD_MAX_SESSION_AGE_MS = 12 * 3600_000;

let versionCache: { value: string | null; at: number } | null = null;

export interface DistFileInfo { sha256: string; size: number }
interface HashEntry { checkedAt: number; info: DistFileInfo | null; mtimeMs: number; size: number }
const hashCache = new Map<string, HashEntry>();
const inflight = new Map<string, Promise<DistFileInfo | null>>();

/** Tests only: point the helpers at another dist folder (and drop the caches). */
export function __setObliReachDistDirForTests(dir: string | null): void {
  distDir = dir ?? DEFAULT_DIST_DIR;
  versionCache = null;
  hashCache.clear();
  inflight.clear();
}

/** Absolute path of a file of the agent dist folder (name already allow-listed by the caller). */
export function distFilePath(fileName: string): string {
  return path.join(distDir, fileName);
}

/** Version of the ObliReach build shipped by this server (agent/dist/oblireach-version.txt), 60 s cache. */
export function getShippedObliReachVersion(): string | null {
  const now = Date.now();
  if (versionCache && now - versionCache.at < VERSION_TTL_MS) return versionCache.value;
  let v: string | null = null;
  try {
    v = fs.readFileSync(path.join(distDir, 'oblireach-version.txt'), 'utf-8').trim() || null;
  } catch { v = null; }
  // A version string only (it goes to every agent): no whitespace, bounded.
  if (v && !/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$/.test(v)) v = null;
  versionCache = { value: v, at: now };
  return v;
}

function hashFile(fp: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(fp);
    s.on('error', reject);
    s.on('data', (chunk) => h.update(chunk));
    s.on('end', () => resolve(h.digest('hex')));
  });
}

/**
 * SHA-256 + size of a dist file, or null when it is missing. Cached per file
 * content; concurrent callers share one computation. `fresh`: stat the file
 * now (the download route) instead of trusting a check younger than 60 s
 * (the push hot path); the hash is still reused while mtime + size match.
 */
export async function getDistFileInfo(fileName: string, opts: { fresh?: boolean } = {}): Promise<DistFileInfo | null> {
  const fp = path.join(distDir, fileName);
  const now = Date.now();
  const cached = hashCache.get(fp);
  if (!opts.fresh && cached && now - cached.checkedAt < STAT_TTL_MS) return cached.info;
  const running = inflight.get(fp);
  if (running) return running;

  const p = (async (): Promise<DistFileInfo | null> => {
    try {
      const st = await fs.promises.stat(fp);
      if (!st.isFile()) {
        hashCache.set(fp, { checkedAt: Date.now(), info: null, mtimeMs: 0, size: 0 });
        return null;
      }
      const prev = hashCache.get(fp);
      if (prev?.info && prev.mtimeMs === st.mtimeMs && prev.size === st.size) {
        hashCache.set(fp, { ...prev, checkedAt: Date.now() });
        return prev.info;
      }
      const sha256 = await hashFile(fp);
      // Replaced while being read: do not pair this hash with the new file.
      const st2 = await fs.promises.stat(fp);
      if (st2.mtimeMs !== st.mtimeMs || st2.size !== st.size) {
        hashCache.delete(fp);
        return null;
      }
      const info = { sha256, size: st.size };
      hashCache.set(fp, { checkedAt: Date.now(), info, mtimeMs: st.mtimeMs, size: st.size });
      return info;
    } catch {
      // Missing / unreadable: remembered for the TTL (no stat per push).
      hashCache.set(fp, { checkedAt: Date.now(), info: null, mtimeMs: 0, size: 0 });
      return null;
    } finally {
      inflight.delete(fp);
    }
  })();
  inflight.set(fp, p);
  return p;
}

function normArch(osArch: string | null | undefined): string {
  const a = String(osArch ?? '').trim().toLowerCase();
  if (a === 'amd64' || a === 'x86_64' || a === 'x64') return 'amd64';
  if (a === 'arm64' || a === 'aarch64') return 'arm64';
  return a;
}

/**
 * ObliReach build for a device's os_type / os_arch ('' = none). The MSI is
 * x64-only; there is no linux-arm64 nor FreeBSD build.
 */
export function obliReachArtifactFor(osType: string | null | undefined, osArch: string | null | undefined): string {
  const arch = normArch(osArch);
  switch (osType) {
    case 'windows': return arch === 'amd64' ? 'oblireach-agent.msi' : '';
    case 'macos':
      if (arch === 'amd64') return 'oblireach-agent-darwin-amd64';
      if (arch === 'arm64') return 'oblireach-agent-darwin-arm64';
      return '';
    case 'linux': return arch === 'amd64' ? 'oblireach-agent-linux-amd64' : '';
    default: return '';
  }
}

/** A value of the settings cascade / app_config read as a switch (absent = on). */
export function switchOn(v: unknown): boolean {
  if (v === undefined || v === null) return true;
  if (v === false || v === 0) return false;
  const s = String(v).trim().toLowerCase();
  return !(s === 'false' || s === '0' || s === 'off' || s === 'no');
}

/** An ObliReach session (connecting / active, recent) is open on the device. */
export function obliReachHoldFrom(
  openSessions: Array<{ status: string; protocol: string; started_at?: Date | string | null }>,
  now = Date.now(),
): boolean {
  return openSessions.some((s) => {
    if (s.protocol !== 'oblireach') return false;
    if (s.status !== 'connecting' && s.status !== 'active') return false;
    const started = s.started_at ? new Date(s.started_at).getTime() : NaN;
    return !Number.isFinite(started) || now - started < HOLD_MAX_SESSION_AGE_MS;
  });
}

/**
 * The push-response block, or null when it must be omitted: legacy agent
 * (cannot run ObliReach), or no ObliReach build shipped by this server.
 */
export async function buildObliReachDesired(input: {
  enabled: boolean;
  osType: string | null | undefined;
  osArch: string | null | undefined;
  agentFlavor: string | null | undefined;
  hold: boolean;
}): Promise<ObliReachDesired | null> {
  if (input.agentFlavor === 'legacy') return null;
  const version = getShippedObliReachVersion();
  if (!version) return null;
  const file = obliReachArtifactFor(input.osType, input.osArch);
  const info = file ? await getDistFileInfo(file) : null;
  return {
    enabled: input.enabled,
    version,
    file: info ? file : '',
    sha256: info?.sha256 ?? '',
    size: info?.size ?? 0,
    hold: input.hold,
  };
}

// ── Agent report → stored status ────────────────────────────────────────────
//
// A2 (agent/oblireach_manager.go ObliReachReport): state, reason,
// installedVersion, desiredVersion, running, error, attempts, lastAttemptAt,
// nextAttemptAt, since. Everything is re-validated here (the value is shown in
// the UI and written to the database): codes, versions, bounded text, times.

/** The report as compared between pushes; `since` is the agent's own stamp
 *  (null when it sent none — the server then stamps the first reception). */
export type ObliReachStatusCore = Omit<ObliReachAutoStatus, 'since'> & { since: string | null };

const STATE_ALIASES: Record<string, string> = {
  ok: 'up_to_date', aligned: 'up_to_date', uptodate: 'up_to_date', current: 'up_to_date',
  updating: 'installing', upgrading: 'installing', downgrading: 'installing', downloading: 'installing',
  error: 'failed', failure: 'failed',
  waiting: 'pending', scheduled: 'pending',
  privacy: 'privacy_deferred', privacy_mode: 'privacy_deferred',
  off: 'disabled',
};

function cleanText(v: unknown, max: number): string | null {
  if (typeof v !== 'string') return null;
  // Control characters out (the value is displayed), whitespace collapsed.
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ').replace(/\s+/g, ' ').trim();
  return s ? s.slice(0, max) : null;
}

function cleanVersion(v: unknown): string | null {
  const s = cleanText(v, 64);
  if (!s) return null;
  return /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$/.test(s) ? s : null;
}

function cleanTime(v: unknown): string | null {
  let ms: number;
  if (typeof v === 'number' && Number.isFinite(v)) ms = v < 1e12 ? v * 1000 : v;
  else if (typeof v === 'string' && v.trim()) ms = Date.parse(v.trim());
  else return null;
  if (!Number.isFinite(ms)) return null;
  const y = new Date(ms).getUTCFullYear();
  if (y < 2000 || y > 2200) return null; // Go zero time, garbage
  return new Date(ms).toISOString();
}

/** A short code (state, reason): lowercase snake_case, ≤ 32 chars. */
function cleanCode(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase().replace(/[\s-]+/g, '_');
  return /^[a-z][a-z0-9_]{0,31}$/.test(s) ? s : null;
}

/**
 * Push body `oblireach` → normalised status.
 *   undefined → nothing to do (field absent, or unusable: keep what is stored)
 *   null      → explicit clear
 */
export function normalizeObliReachReport(raw: unknown): ObliReachStatusCore | null | undefined {
  if (raw === undefined) return undefined;
  if (raw === null) return null;
  if (typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  const code = cleanCode(r.state ?? r.status);
  if (!code) return undefined;
  const state = STATE_ALIASES[code] ?? code;
  const attemptsRaw = r.attempts;
  const attempts = typeof attemptsRaw === 'number' && Number.isFinite(attemptsRaw)
    ? Math.max(0, Math.min(1_000_000, Math.floor(attemptsRaw)))
    : 0;
  return {
    state,
    reason: cleanCode(r.reason),
    installedVersion: cleanVersion(r.installedVersion),
    desiredVersion: cleanVersion(r.desiredVersion ?? r.targetVersion),
    running: typeof r.running === 'boolean' ? r.running : null,
    error: cleanText(r.error ?? r.lastError, 500),
    attempts,
    lastAttemptAt: cleanTime(r.lastAttemptAt),
    nextAttemptAt: cleanTime(r.nextAttemptAt),
    since: cleanTime(r.since),
  };
}

/** Stored JSONB (object or string) → status, null when absent / corrupt. */
export function parseStoredObliReachStatus(raw: unknown): ObliReachAutoStatus | null {
  if (raw == null) return null;
  let v: unknown = raw;
  if (typeof raw === 'string') {
    try { v = JSON.parse(raw); } catch { return null; }
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (typeof o.state !== 'string') return null;
  const str = (x: unknown) => (typeof x === 'string' ? x : null);
  return {
    state: o.state,
    reason: str(o.reason),
    installedVersion: str(o.installedVersion),
    desiredVersion: str(o.desiredVersion),
    running: typeof o.running === 'boolean' ? o.running : null,
    error: str(o.error),
    attempts: typeof o.attempts === 'number' ? o.attempts : 0,
    lastAttemptAt: str(o.lastAttemptAt),
    nextAttemptAt: str(o.nextAttemptAt),
    since: str(o.since) ?? '',
  };
}

/** Same report as the stored one (`since` compared only when the agent sent one). */
export function sameObliReachStatus(stored: ObliReachAutoStatus, rep: ObliReachStatusCore): boolean {
  return stored.state === rep.state
    && stored.reason === rep.reason
    && stored.installedVersion === rep.installedVersion
    && stored.desiredVersion === rep.desiredVersion
    && stored.running === rep.running
    && stored.error === rep.error
    && stored.attempts === rep.attempts
    && stored.lastAttemptAt === rep.lastAttemptAt
    && stored.nextAttemptAt === rep.nextAttemptAt
    && (rep.since === null || stored.since === rep.since);
}

/**
 * What the push route writes to devices.oblireach_status for this push:
 *   undefined → no write
 *   null      → clear
 *   status    → new value
 * `report` is the push body field; a stored status is cleared when the agent
 * stops reporting after changing version (downgraded below the feature) or
 * when the device now runs the legacy agent.
 */
export function nextObliReachStatus(opts: {
  report: unknown;
  stored: unknown;
  agentVersionChanged: boolean;
  legacy: boolean;
  nowIso: string;
}): ObliReachAutoStatus | null | undefined {
  const cur = parseStoredObliReachStatus(opts.stored);
  if (opts.legacy) return cur ? null : undefined;
  const rep = normalizeObliReachReport(opts.report);
  if (rep === undefined) {
    if (opts.report === undefined && cur && opts.agentVersionChanged) return null;
    return undefined;
  }
  if (rep === null) return cur ? null : undefined;
  if (cur && sameObliReachStatus(cur, rep)) return undefined;
  return { ...rep, since: rep.since ?? opts.nowIso };
}
