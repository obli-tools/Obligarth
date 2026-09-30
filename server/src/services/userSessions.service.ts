import { db } from '../db';
import { getIO } from '../socket';
import { logger } from '../utils/logger';
import { forgetSessionUser } from '../middleware/sessionUserGuard';
import { sessionHash, sessionRoom } from '../utils/sessionHash';

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
// user on every request (its cache entry is dropped here), so such a
// resurrected row dies on its next use. Connections that outlive the
// session are closed too: remote sessions the user started (browser relay,
// ObliReach, bastion jumps) and authenticated SSH bastion connections.

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
  try {
    getIO().in(`user:${userId}`).disconnectSockets(true);
  } catch { /* Socket.io not initialised (CLI) */ }
  let remote = 0;
  let bastion = 0;
  try {
    const { remoteService } = await import('./remote.service');
    remote = await remoteService.closeSessionsForUser(userId, reason);
  } catch (err) {
    logger.warn({ err, userId }, 'remote sessions of a removed user not closed');
  }
  try {
    const { endBastionConnectionsForUser } = await import('./sshBastion/sshBastion.service');
    bastion = endBastionConnectionsForUser(userId);
  } catch (err) {
    logger.warn({ err, userId }, 'bastion connections of a removed user not closed');
  }
  logger.info({ userId, reason, count, remote, bastion }, 'user sessions killed');
  return count;
}

// ── Per-session live channels (device-bound 2FA revocation, §6.7) ──────────
//
// Socket.io authenticates once, at the handshake, and a remote relay once, at
// its upgrade: deleting a session row does not close what that session
// already opened. Each socket joins `sess:<sha256(sid)>` at the handshake
// (socket.ts) and each browser relay records the same hash (remote.service),
// so a revocation that deletes session rows closes exactly their channels,
// never the other sessions of the same user.

export { sessionHash, sessionRoom };

/**
 * Closes the live channels of these (already deleted) sessions: their
 * Socket.io connections, and the remote sessions whose browser relay they
 * attached or that they started (shell, ObliReach, VM console). Never throws.
 */
export async function closeSessionChannels(sids: ReadonlyArray<string>, reason: string): Promise<{ remote: number }> {
  const list = [...new Set(sids.filter((x) => typeof x === 'string' && x.length > 0))];
  if (list.length === 0) return { remote: 0 };
  const hashes = list.map(sessionHash);
  try {
    const io = getIO();
    for (const h of hashes) io.in(`sess:${h}`).disconnectSockets(true);
  } catch { /* Socket.io not initialised (CLI) */ }
  let remote = 0;
  try {
    const { remoteService } = await import('./remote.service');
    remote = await remoteService.closeSessionsForSessionHashes(hashes, reason);
  } catch (err) {
    logger.warn({ err }, 'remote sessions of revoked sessions not closed');
  }
  logger.info({ sessions: list.length, remote, reason }, 'live channels of deleted sessions closed');
  return { remote };
}
