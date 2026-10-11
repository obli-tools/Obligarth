import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { config } from '../../config';
import type { ProposedChange, TouchedDevice } from './impact';

// =============================================================================
// Token of the full list of the devices an impact preview touches (docs:
// modele-donnees-mdm §7.11, S13): signed (HMAC-SHA256, key derived from the
// session secret), bound to the tenant and to the user, valid 15 minutes. It
// carries the change itself (compressed): GET /api/mdm/impact/:token/devices
// computes the preview again and pages its devices, filtered by the caller's
// scopes. A small cache keeps the computed list for the pages that follow.
// =============================================================================

const TTL_MS = 15 * 60_000;
const INFO = 'obligarth mdm impact token v1';
const MAX_TOKEN_LENGTH = 6000;

interface Payload { v: 1; t: number; u: number; exp: number; c: ProposedChange }

let key: Buffer | null = null;
function tokenKey(): Buffer {
  if (!key) {
    const secret = config.sessionSecret;
    if (!secret) throw new Error('impact token: no session secret');
    key = Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.alloc(0), INFO, 32));
  }
  return key;
}

const mac = (body: string): Buffer => createHmac('sha256', tokenKey()).update(body, 'utf8').digest();

/** The token of a change previewed by `userId` in `tenantId`; null when the change is too large to travel in a URL. */
export function signImpactToken(tenantId: number, userId: number, change: ProposedChange, now = Date.now()): string | null {
  const payload: Payload = { v: 1, t: tenantId, u: userId, exp: now + TTL_MS, c: change };
  const body = deflateRawSync(Buffer.from(JSON.stringify(payload), 'utf8')).toString('base64url');
  const token = `${body}.${mac(body).toString('base64url')}`;
  return token.length <= MAX_TOKEN_LENGTH ? token : null;
}

/** The change of a token, when it is genuine, unexpired, of this tenant and of this user; null otherwise. */
export function verifyImpactToken(token: string, tenantId: number, userId: number, now = Date.now()): ProposedChange | null {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) return null;
  const m = /^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/.exec(token);
  if (!m) return null;
  const given = Buffer.from(m[2], 'base64url');
  const expected = mac(m[1]);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  let p: Payload;
  try {
    p = JSON.parse(inflateRawSync(Buffer.from(m[1], 'base64url'), { maxOutputLength: 1 << 20 }).toString('utf8')) as Payload;
  } catch {
    return null;
  }
  if (p?.v !== 1 || p.t !== tenantId || p.u !== userId || typeof p.exp !== 'number' || p.exp < now) return null;
  return p.c;
}

// The computed lists of the last tokens (pages of one preview), 15 minutes at most.
const CACHE_MAX = 20;
const cache = new Map<string, { at: number; touched: TouchedDevice[] }>();

export function cachedTouched(token: string, now = Date.now()): TouchedDevice[] | null {
  const hit = cache.get(token);
  if (!hit) return null;
  if (now - hit.at > TTL_MS) { cache.delete(token); return null; }
  return hit.touched;
}

export function cacheTouched(token: string, touched: TouchedDevice[], now = Date.now()): void {
  cache.set(token, { at: now, touched });
  while (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value as string);
}
