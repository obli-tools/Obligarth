import { performance } from 'node:perf_hooks';

// Ids of the sessions deleted by a credential change (password reset or
// changed, second factor reset: services/userSessions.service.ts), kept a day.
//
// A session deleted while its user stays active is not caught by the
// is_active check of sessionUserGuard: a request of that session still in
// flight saves it back when it ends (connect-pg-simple `set` is an upsert),
// and an intruder whose console polls the server almost always has one.
// sessionUserGuard and the Socket.io handshake end any request that still
// presents one of these ids. No project import: unit-tested on its own.

const REVOKED_TTL_MS = 24 * 60 * 60 * 1000;
const REVOKED_MAX = 50_000;
const revoked = new Map<string, number>();

export function markSessionsRevoked(sids: ReadonlyArray<string>, now: number = performance.now()): void {
  const list = sids.filter((s) => typeof s === 'string' && s.length > 0);
  if (list.length === 0) return;
  if (revoked.size + list.length > REVOKED_MAX) {
    for (const [sid, at] of revoked) if (now - at >= REVOKED_TTL_MS) revoked.delete(sid);
    // Still full: the oldest go first (insertion order).
    while (revoked.size > 0 && revoked.size + list.length > REVOKED_MAX) {
      revoked.delete(revoked.keys().next().value as string);
    }
  }
  for (const sid of list) {
    revoked.delete(sid);
    revoked.set(sid, now);
  }
}

export function isSessionRevoked(sid: string | undefined | null, now: number = performance.now()): boolean {
  if (typeof sid !== 'string' || !sid) return false;
  const at = revoked.get(sid);
  if (at === undefined) return false;
  if (now - at >= REVOKED_TTL_MS) { revoked.delete(sid); return false; }
  return true;
}

/** Tests only. */
export function forgetRevokedSessions(): void {
  revoked.clear();
}

export const REVOKED_SESSION_TTL_MS = REVOKED_TTL_MS;
