import { Server as HttpServer } from 'http';
import { Server as SocketIOServer, type Socket } from 'socket.io';
import { db } from './db';
import { logger } from './utils/logger';
import { getSessionMiddleware } from './app';
import { sessionRoom } from './utils/sessionHash';

let io: SocketIOServer;

// ── Module handlers ─────────────────────────────────────────────────────────
// The core keeps the handshake (identity from the session cookie only), the
// rooms and the live-session helpers. A module's own events are installed by
// its handler on every connection, in registration order, once the rooms are
// joined (modules/rmm.ts registers the RMM's).

/** A socket's express session as the store holds it. */
export type LiveSession = { userId?: number; currentTenantId?: number };

/** One connection, as a module's handler sees it. The identity (user,
 *  tenant) is the handshake's, frozen for the socket's life. */
export interface SocketConnection {
  io: SocketIOServer;
  socket: Socket;
  /** The users row read at the handshake. */
  user: any;
  /** The tenant resolved at the handshake (session's current tenant,
   *  membership-checked), if any. */
  tenantId: number | undefined;
  isAdmin: boolean;
  /** The socket's express session id, when known. */
  sid: string | undefined;
  /** The LIVE session, or null (store unreachable, session gone or now
   *  someone else's — the socket is then disconnected). */
  liveSession: () => Promise<LiveSession | null>;
  /** The device belongs to the handshake's tenant. */
  verifyDevice: (deviceId: number) => Promise<boolean>;
}

export type SocketHandler = (conn: SocketConnection) => void;

const socketHandlers: Array<{ name: string; install: SocketHandler }> = [];

export function registerSocketHandler(name: string, install: SocketHandler): void {
  if (socketHandlers.some((h) => h.name === name)) throw new Error(`Socket handler '${name}' registered twice`);
  socketHandlers.push({ name, install });
}

/** Largest message a client may send: Socket.io's default (1 MB), unless a
 *  module needs more (requireSocketMessageSize, before createSocketServer). */
let maxHttpBufferSize = 1e6;

export function requireSocketMessageSize(bytes: number): void {
  if (io) throw new Error('requireSocketMessageSize must be called before createSocketServer');
  if (bytes > maxHttpBufferSize) maxHttpBufferSize = bytes;
}

export function createSocketServer(server: HttpServer): SocketIOServer {
  io = new SocketIOServer(server, {
    cors: {
      // Reflect the request origin instead of a fixed string.
      // In production, nginx proxies everything (same-origin from the browser)
      // but WebSocket upgrades always send the Origin header (RFC 6455), so a
      // fixed CLIENT_ORIGIN that doesn't include the port (e.g. "http://localhost"
      // vs "http://localhost:3003") silently breaks the handshake.
      // Auth is enforced by the io.use() middleware below, not by CORS.
      origin: true,
      credentials: true,
    },
    transports: ['websocket', 'polling'],
    maxHttpBufferSize,
  });

  // Run the Express session middleware on the handshake request, so the
  // httpOnly session cookie (sent by the browser on the WS upgrade / polling
  // requests) populates socket.request.session.
  const sessionMw = getSessionMiddleware();
  if (sessionMw) io.engine.use(sessionMw as any);

  // Authentication middleware — the identity comes from the SESSION only.
  // SECURITY: never trust `handshake.auth.userId`: it is client-controlled.
  // Until 2026-09 it was the only check, so anyone reaching /socket.io could
  // claim any user id (e.g. the bootstrap admin) without credentials.
  io.use(async (socket, next) => {
    try {
      const sess = (socket.request as any).session as { userId?: number; currentTenantId?: number; deviceKeyId?: string } | undefined;
      const userId = sess?.userId;
      if (!userId) return next(new Error('Unauthorized'));

      // Device-bound 2FA (docs/mobile/device-bound-2fa.md §6.4, §6.7): the
      // handshake is the ONLY check a socket gets. A session bound to a
      // phone key that is dead (revoked, credentials changed, …) — e.g. a
      // row brought back by a concurrent save after the revocation deleted
      // it — must not open a new socket (same rule as deviceKeySession).
      if (sess?.deviceKeyId) {
        const { boundSessionDead } = await import('./services/deviceKey/deviceKey.service');
        if (await boundSessionDead(sess.deviceKeyId, userId)) return next(new Error('Unauthorized'));
      }

      // Tenant: the session's current tenant (what the REST API uses); the
      // client-supplied one is only a fallback and is membership-checked below.
      const tenantId = sess?.currentTenantId ?? socket.handshake.auth?.tenantId;

      const user = await db('users').where({ id: userId, is_active: true }).first();
      if (!user) return next(new Error('Unauthorized'));

      // Validate tenant membership — prevent cross-tenant spoofing.
      // Admins bypass this check (they can access any tenant, matching REST behaviour).
      if (tenantId && user.role !== 'admin') {
        const membership = await db('user_tenants')
          .where({ user_id: user.id, tenant_id: tenantId })
          .first();
        if (!membership) return next(new Error('Unauthorized — not a member of this tenant'));
      }

      (socket as any).user = user;
      (socket as any).tenantId = tenantId;
      next();
    } catch (err) {
      logger.error(err, 'Socket auth error');
      next(new Error('Authentication failed'));
    }
  });

  io.on('connection', (socket) => {
    const user = (socket as any).user;
    const tenantId = (socket as any).tenantId;
    const isAdmin = user.role === 'admin';

    // Join rooms
    socket.join(`user:${user.id}`);
    // The socket's express session (sha256 of the sid): a device-key
    // revocation that deletes this session disconnects exactly its sockets
    // (userSessions.service closeSessionChannels).
    const sid = (socket.request as any).sessionID;
    if (typeof sid === 'string' && sid) socket.join(sessionRoom(sid));
    if (tenantId) {
      socket.join(`tenant:${tenantId}`);
      socket.join(`tenant:${tenantId}:notifications`);
      if (isAdmin) {
        socket.join(`tenant:${tenantId}:admin`);
        socket.join('role:admin');
      }
    }
    socket.join('general');

    // Join all accessible tenant rooms (for multi-tenant live alerts)
    db('user_tenants').where({ user_id: user.id }).then((memberships) => {
      for (const m of memberships) {
        socket.join(`tenant:${m.tenant_id}:notifications`);
      }
    }).catch(() => {});

    logger.debug({ userId: user.id, tenantId }, 'Socket connected');

    // ── Live session ────────────────────────────────────────────────────────
    // The handshake identity (user, tenant) is frozen for the socket's life,
    // but the session behind it can end (sign-out: a desktop client may keep
    // its socket while the next user signs in behind it) or switch tenant.
    // An action that reaches a machine (a chat window on someone's desktop,
    // the file explorer on its disks) re-reads the LIVE session first.
    // Resolves undefined when the store is unreachable, null when the
    // session is gone.
    const readSession = (): Promise<LiveSession | null | undefined> =>
      new Promise((resolve) => {
        const store = (socket.request as any).sessionStore;
        if (!store || typeof sid !== 'string' || !sid) { resolve(undefined); return; }
        store.get(sid, (err: unknown, sess: any) => resolve(err ? undefined : (sess ?? null)));
      });
    // The live session, or null. A session that is gone, or now belongs to
    // someone else, also ends this socket: its rooms belong to the user who
    // signed out.
    const liveSession = async (): Promise<LiveSession | null> => {
      const sess = await readSession();
      if (sess === undefined) return null; // store unreachable: refuse, keep the socket
      if (!sess || Number(sess.userId) !== Number(user.id)) {
        socket.disconnect(true);
        return null;
      }
      return sess;
    };

    // ── Helper: verify device belongs to tenant ─────────────────────────────
    const verifyDevice = async (deviceId: number): Promise<boolean> => {
      if (!tenantId) return false;
      const device = await db('devices').where({ id: deviceId, tenant_id: tenantId }).first();
      return !!device;
    };

    const conn: SocketConnection = {
      io,
      socket,
      user,
      tenantId,
      isAdmin,
      sid: typeof sid === 'string' && sid ? sid : undefined,
      liveSession,
      verifyDevice,
    };
    for (const h of socketHandlers) h.install(conn);

    socket.on('disconnect', () => {
      logger.debug({ userId: user.id }, 'Socket disconnected');
    });
  });

  return io;
}

export function getIO(): SocketIOServer {
  if (!io) throw new Error('Socket.io not initialized');
  return io;
}
