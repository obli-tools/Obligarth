import { createHash } from 'node:crypto';
import { BENCH_STATION_TOKEN_RE, benchVerificationCode, type BenchStationStatus } from '@obligarth/shared';
import { db } from '../db';
import { asNone } from '../db/context';
import { BENCH_SURFACE_ACTOR, stationActor } from './actor';

// =============================================================================
// The stations (lot BANC §3.2, §3.3): the token of a station, its Authorization header, the verdict of its access by
// scope, the transitions of its status, its registration and its contact. Pure functions first (tested by the bench),
// then the definer calls of the station surface (context none).
// =============================================================================

export type BenchScope = 'self' | 'act';

/** The token of a station: 64 to 256 hexadecimal characters (lower case), an even count, 8 distinct characters at least
 *  (a token made of one repeated character is refused). null otherwise. */
export function normaliseStationToken(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const t = raw.trim().toLowerCase();
  if (!BENCH_STATION_TOKEN_RE.test(t) || t.length % 2 !== 0) return null;
  if (new Set(t).size < 8) return null;
  return t;
}

export const stationTokenHash = (token: string): string => createHash('sha256').update(token, 'utf8').digest('hex');

/** The verification code of a station (§3.3), from the sha256 of its token: shown by the station only (registration and
 *  GET /stations/me), never by the console, and not derivable from the station's id (in the console's URLs). */
export function stationVerificationCode(tokenSha256: string): string {
  return benchVerificationCode(createHash('sha256').update(`obligarth-bench-verification:${tokenSha256}`, 'utf8').digest('hex'));
}

export type ParsedAuthorization = { ok: true; token: string } | { ok: false; reason: 'missing' | 'wrong_scheme' | 'malformed' };

/** `Authorization: Bench <token>`. */
export function parseBenchAuthorization(header: unknown): ParsedAuthorization {
  if (typeof header !== 'string' || header.trim() === '') return { ok: false, reason: 'missing' };
  const m = /^(\S+)\s+(\S+)$/.exec(header.trim());
  if (!m) return { ok: false, reason: 'malformed' };
  if (m[1] !== 'Bench') return { ok: false, reason: 'wrong_scheme' };
  const token = normaliseStationToken(m[2]);
  return token ? { ok: true, token } : { ok: false, reason: 'malformed' };
}

export type AccessVerdict = { ok: true } | { ok: false; status: 401 | 403; code: string; error: string };

/** §3.3: what a station of `status` may reach with `scope`; an unknown token is 401, any state outside the vocabulary
 *  is refused. */
export function stationAccessVerdict(status: string | null | undefined, scope: BenchScope): AccessVerdict {
  if (status === null || status === undefined) return { ok: false, status: 401, code: 'unknown_station', error: 'Unknown station' };
  switch (status as BenchStationStatus) {
    case 'approved': return { ok: true };
    case 'pending': return scope === 'self' ? { ok: true } : { ok: false, status: 403, code: 'station_pending', error: 'The station awaits its approval' };
    case 'suspended': return scope === 'self' ? { ok: true } : { ok: false, status: 403, code: 'station_suspended', error: 'The station is suspended' };
    case 'revoked': return { ok: false, status: 403, code: 'station_revoked', error: 'The station is revoked' };
    default: return { ok: false, status: 403, code: 'station_refused', error: 'The station is refused' };
  }
}

export type StationAction = 'approve' | 'suspend' | 'resume' | 'revoke';

/** The status a station takes by `action`, or null when the action does not apply to its status (compare-and-set:
 *  the update names the status read). */
export function planStationTransition(from: BenchStationStatus, action: StationAction): BenchStationStatus | null {
  switch (action) {
    case 'approve': return from === 'pending' ? 'approved' : null;
    case 'suspend': return from === 'approved' ? 'suspended' : null;
    case 'resume': return from === 'suspended' ? 'approved' : null;
    case 'revoke': return from === 'revoked' ? null : 'revoked';
    default: return null;
  }
}

export interface StationLookup {
  id: string;
  status: BenchStationStatus;
  name: string;
  allowedCidrs: string[] | null;
  /** The sha256 of the token the request presented (computed here, never read back from the base). */
  tokenSha256: string;
  /** The open session of a technician whose account is active (bench_station_lookup), else null. */
  session: { id: string; userId: number; expiresAt: Date; technician: string | null; technicianPlatformAdmin: boolean } | null;
}

/** The station of a token, with its open session (context none, i:bench-station); null when unknown. Never cached:
 *  a revocation or a suspension is seen by the next request. */
export async function lookupStation(token: string): Promise<StationLookup | null> {
  const tokenSha256 = stationTokenHash(token);
  const r = await asNone(BENCH_SURFACE_ACTOR, () => db.raw(
    'SELECT * FROM obligarth.bench_station_lookup(?)', [tokenSha256],
  )) as { rows: Array<Record<string, any>> };
  const row = r.rows[0];
  if (!row) return null;
  return {
    id: String(row.id).toLowerCase(), status: row.status, name: row.name, tokenSha256,
    allowedCidrs: Array.isArray(row.allowed_cidrs) ? row.allowed_cidrs.map(String) : null,
    session: row.session_id ? {
      id: String(row.session_id).toLowerCase(), userId: Number(row.session_user_id), expiresAt: new Date(row.session_expires_at),
      technician: row.technician ?? null, technicianPlatformAdmin: row.technician_platform_admin === true,
    } : null,
  };
}

/** The last contact of a station (once a minute at most, by the definer function). Never throws. */
export async function touchStation(stationId: string, ip: string | null, version: string | null): Promise<void> {
  try {
    await asNone(stationActor(stationId), () => db.raw('SELECT obligarth.bench_station_touch(?::uuid, ?::inet, ?)', [stationId, ip, version ?? '']));
  } catch { /* the contact is informative */ }
}

export interface RegisterOutcome { refused: 'too_many_pending' | null; id: string | null; status: BenchStationStatus | null; created: boolean; name: string | null }

/** The registration of a station (public route): idempotent on the token's hash, never a rename. */
export async function registerStation(input: { name: string; hostname: string; token: string; version: string | null; ip: string | null }): Promise<RegisterOutcome> {
  const r = await asNone(BENCH_SURFACE_ACTOR, () => db.transaction((trx) => trx.raw(
    'SELECT * FROM obligarth.bench_register_station(?, ?, ?, ?, ?::inet)',
    [input.name, input.hostname, stationTokenHash(input.token), input.version ?? '', input.ip],
  ))) as { rows: Array<Record<string, any>> };
  const row = r.rows[0] ?? {};
  if (row.refused) return { refused: 'too_many_pending', id: null, status: null, created: false, name: null };
  return { refused: null, id: String(row.id).toLowerCase(), status: row.status, created: row.created === true, name: row.name ?? null };
}

/** A station name or host as the console shows it: control characters out, trimmed, bounded. */
export function cleanLabel(v: unknown, max: number): string | null {
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max).trim();
  return s ? s : null;
}
