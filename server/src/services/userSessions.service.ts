import { db } from '../db';
import { getIO } from '../socket';
import { logger } from '../utils/logger';
import { forgetSessionUser } from '../middleware/sessionUserGuard';
import { sessionHash, sessionRoom } from '../utils/sessionHash';
import { forgetTenantMemberships } from './tenant.service';
import { forgetGrantsOfUser } from '../db/platformAccess';

// Session kill-switch for one user (P6, docs/mobile/device-bound-2fa.md §6.0).
//
// requireAuth only checks that req.session.userId is set, and requireRole /
// the admin bypasses read req.session.role: a session outlives a
// deactivation, a deletion or a demotion of its user until it expires
// (7 days). Every path that takes access away calls this to delete the
// user's rows from the connect-pg-simple `session` table (sess is JSON),
// including half-open sign-ins (pendingMfaUserId), and to drop the user's
// live Socket.io connections (room `user:<id>`, joined at handshake).
//
// Deleting rows alone is not enough: a request already in flight saves its
// session back when it ends. middleware/sessionUserGuard.ts re-reads the
// user on every request, and requireTenant (middleware/tenant.ts) its
// membership of the session's tenant (both caches of the user are dropped
// here): on its next use, such a resurrected row dies (user disabled or
// deleted), loses the admin bypasses (user demoted) or is refused its tenant
// (membership removed). Connections that outlive the session are closed
// too: the modules close theirs through their onSessionsKilled hooks.

// ── Hooks of the modules ────────────────────────────────────────────────────

/** What a module closes when sessions end (onSessionsKilled). */
export interface SessionsKilledHook {
  /** Key of its count in the log line. */
  name: string;
  /** What it closes, for the failure log. */
  label: string;
  /** Every session of this user was deleted (killSessionsForUser): returns
   *  how many of its channels it closed. */
  forUser?: (userId: number, reason: string) => number | Promise<number>;
  /** These sessions (sha256 of their ids) were deleted (closeSessionChannels):
   *  returns how many of its channels it closed. */
  forSessions?: (sessionHashes: string[], reason: string) => number | Promise<number>;
}

const hooks: SessionsKilledHook[] = [];

/** Registers a module's hook, run after the core closed the sessions and
 *  their sockets (in registration order; a failure is logged, never thrown). */
export function onSessionsKilled(hook: SessionsKilledHook): void {
  if (hooks.some((h) => h.name === hook.name)) throw new Error(`Session hook '${hook.name}' registered twice`);
  hooks.push(hook);
}

export async function killSessionsForUser(userId: number, reason: string): Promise<number> {
  if (!Number.isInteger(userId) || userId <= 0) return 0;
  const uid = String(userId);
  // Text comparison (not ::int) so one malformed row can never make the
  // whole DELETE fail.
  const res = await db.raw(
    `DELETE FROM session
      WHERE (sess::jsonb ->> 'userId') = ?
         OR (sess::jsonb ->> 'pendingMfaUserId') = ?`,
    [uid, uid],
  ) as { rowCount?: number } | undefined;
  const count = Number(res?.rowCount ?? 0);
  forgetSessionUser(userId);
  forgetTenantMemberships(userId);
  // The cached global-view grants of its sessions (they expire by themselves
  // in the database; the base re-checks the administrator at every query).
  forgetGrantsOfUser(userId);
  try {
    getIO().in(`user:${userId}`).disconnectSockets(true);
  } catch { /* Socket.io not initialised (CLI) */ }
  const closed: Record<string, number> = {};
  for (const hook of hooks) {
    if (!hook.forUser) continue;
    closed[hook.name] = 0;
    try {
      closed[hook.name] = await hook.forUser(userId, reason);
    } catch (err) {
      logger.warn({ err, userId }, `${hook.label} of a removed user not closed`);
    }
  }
  logger.info({ userId, reason, count, ...closed }, 'user sessions killed');
  return count;
}

// ── Per-session live channels (device-bound 2FA revocation, §6.7) ──────────
//
// Socket.io authenticates once, at the handshake, and a module's raw channel
// once, at its upgrade: deleting a session row does not close what that
// session already opened. Each socket joins `sess:<sha256(sid)>` at the
// handshake (socket.ts) and a module's channel records the same hash, so a
// revocation that deletes session rows closes exactly their channels, never
// the other sessions of the same user.

export { sessionHash, sessionRoom };

/**
 * Closes the live channels of these (already deleted) sessions: their
 * Socket.io connections, and what the modules' hooks close for them. Never
 * throws. Returns the modules' counts by hook name.
 */
export async function closeSessionChannels(sids: ReadonlyArray<string>, reason: string): Promise<Record<string, number>> {
  const list = [...new Set(sids.filter((x) => typeof x === 'string' && x.length > 0))];
  const closed: Record<string, number> = {};
  for (const hook of hooks) if (hook.forSessions) closed[hook.name] = 0;
  if (list.length === 0) return closed;
  const hashes = list.map(sessionHash);
  try {
    const io = getIO();
    for (const h of hashes) io.in(`sess:${h}`).disconnectSockets(true);
  } catch { /* Socket.io not initialised (CLI) */ }
  for (const hook of hooks) {
    if (!hook.forSessions) continue;
    try {
      closed[hook.name] = await hook.forSessions(hashes, reason);
    } catch (err) {
      logger.warn({ err }, `${hook.label} of revoked sessions not closed`);
    }
  }
  logger.info({ sessions: list.length, ...closed, reason }, 'live channels of deleted sessions closed');
  return closed;
}
