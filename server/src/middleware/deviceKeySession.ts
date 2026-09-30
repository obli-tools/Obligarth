import type { Request, Response, NextFunction } from 'express';
import { DEVICE_KEY_HEADER } from '@obliance/shared';
import { isUuid } from '../services/deviceKey/payload';
import { clientAddress } from '../utils/clientIp';

// Device-bound 2FA — session binding (docs/mobile/device-bound-2fa.md §4.7,
// §6.4). Mounted on /api in app.ts, after the session, captureStepUpProof,
// the session user guard and the unauthenticated rate limiter (apiLimiter),
// before every router.
//
// A session is BOUND to a device key (req.session.deviceKeyId) at the end of
// an enrolment, at a sign-in carrying the key's X-Obli-Device-Key header,
// or here, at the first authenticated request carrying the header of an
// active key of the session's user. A bound session is never re-bound to
// another key (another header is ignored).
//
// On every request of a bound session the key is re-checked (status cache
// 30 s, dropped locally by each revocation): a key that is no longer active,
// whose credential version drifted (a password / TOTP / activation change,
// even through a path without a revocation hook), that belongs to another
// user, or that is 'unverified' while attestation is required, kills the
// session: 401 {error:'Authentication required', deviceKeyStatus:'revoked'}
// (J4). This per-request check also covers a session row resurrected by a
// concurrent save after a revocation deleted it.
//
// The header of the user's OWN dead key kills the session the same way; the
// header of an unknown key, or of another user's key, is ignored without any
// information. A request without a signed-in session that names a DEAD key
// (its session was deleted by the revocation) gets the same 401, so the app
// learns why and purges the key — except on the sign-in routes, where the
// key simply does not take part. That anonymous lookup only runs for a
// request that still carries a session cookie (the phone whose session the
// revocation deleted), at most ANON_LOOKUPS_PER_IP per minute per IP: an
// anonymous flood of random ids cannot turn into one database query each.
//
// Does nothing while the feature is off (DEVICE_KEYS_DISABLED or
// device_keys_enabled !== 'true'): bound sessions then behave as unbound.

const SIGN_IN_PATHS = /^\/api\/(auth\/login|profile\/2fa\/)/;
/** express-session's cookie (default name, app.ts). */
const SESSION_COOKIE_RE = /(?:^|;\s*)connect\.sid=/;

/** Anonymous key lookups (no signed-in session) per IP and minute. */
export const ANON_LOOKUPS_PER_IP = 20;
const ANON_WINDOW_MS = 60_000;
const ANON_MAX_IPS = 10_000;
const anonLookups = new Map<string, number[]>();

function anonLookupAllowed(ip: string): boolean {
  const now = Date.now();
  const hits = (anonLookups.get(ip) ?? []).filter((t) => now - t < ANON_WINDOW_MS);
  if (hits.length >= ANON_LOOKUPS_PER_IP) { anonLookups.set(ip, hits); return false; }
  if (!anonLookups.has(ip) && anonLookups.size >= ANON_MAX_IPS) anonLookups.clear();
  hits.push(now);
  anonLookups.set(ip, hits);
  return true;
}

/** Tests: clears the anonymous lookup counters. */
export function resetDeviceKeySessionMemory(): void {
  anonLookups.clear();
}

function destroy(req: Request): Promise<void> {
  return new Promise((resolve) => {
    if (!req.session) { resolve(); return; }
    req.session.destroy(() => resolve());
  });
}

async function refuse(req: Request, res: Response): Promise<void> {
  await destroy(req);
  res.status(401).json({ success: false, error: 'Authentication required', deviceKeyStatus: 'revoked' });
}

export async function deviceKeySession(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const dk = await import('../services/deviceKey/deviceKey.service');
    const policy = await dk.getPolicy();
    if (!policy.enabled) { next(); return; }

    // Dead key status of `st` (and revocation of a still-active key that
    // failed a permanent check, so the audit says why): THE shared rule
    // (also the Socket.io handshake).
    const dead = (keyId: string, st: Awaited<ReturnType<typeof dk.keyStatusCached>>): Promise<boolean> =>
      dk.deadKeyStatus(keyId, st, policy.requireAttestation, req);

    const userId = Number(req.session?.userId);
    const header = req.get(DEVICE_KEY_HEADER);

    if (!Number.isSafeInteger(userId) || userId <= 0) {
      // No signed-in session. A pending sign-in or the sign-in routes: the
      // key takes part (or not) in the sign-in itself.
      if (!isUuid(header) || req.session?.pendingMfaUserId || SIGN_IN_PATHS.test(req.originalUrl)) { next(); return; }
      // Only a client that still holds a session cookie (the revoked phone),
      // and a few lookups per IP and minute: no database query per request
      // for an anonymous flood of random ids (§6.4).
      if (!SESSION_COOKIE_RE.test(String(req.headers.cookie ?? ''))) { next(); return; }
      let ip = '';
      try { ip = clientAddress(req).ip || ''; } catch { ip = ''; }
      if (!anonLookupAllowed(ip || '-')) { next(); return; }
      const st = await dk.keyStatusCached(header);
      if (st && await dead(header, st)) { await refuse(req, res); return; }
      next();
      return;
    }

    const boundId = req.session.deviceKeyId;
    if (boundId) {
      const st = await dk.keyStatusCached(boundId);
      if (!st || st.userId !== userId || await dead(boundId, st)) { await refuse(req, res); return; }
      next();
      return;
    }

    if (isUuid(header)) {
      const st = await dk.keyStatusCached(header);
      if (st && st.userId === userId) {
        if (await dead(header, st)) { await refuse(req, res); return; }
        req.session.deviceKeyId = header; // the binding (§4.7, third case)
      }
      // Unknown key, or another user's: ignored.
    }
    next();
  } catch (err) {
    next(err);
  }
}
