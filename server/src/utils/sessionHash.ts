import crypto from 'crypto';

// Identifier of one express session in memory and in Socket.io rooms: the
// sha256 of its id (the raw id is the session cookie's secret part and is
// never kept outside the session store). Used to close the live channels of
// a session a revocation deleted (userSessions.service closeSessionChannels,
// socket.ts, remote.service). No project import: safe for socket.ts.

/** sha256 (hex) of an express-session id. */
export function sessionHash(sid: string): string {
  return crypto.createHash('sha256').update(String(sid)).digest('hex');
}

/** Socket.io room of one express session. */
export function sessionRoom(sid: string): string {
  return `sess:${sessionHash(sid)}`;
}
