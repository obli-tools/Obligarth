import { STATUS_CODES, ServerResponse, type IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';
import { timingSafeEqual } from 'node:crypto';
import { WebSocketServer, type WebSocket } from 'ws';
import {
  REMOTE_RELAY_LIMITS, REMOTE_VIEWER_PROTOCOL, REMOTE_VIEWER_TOKEN_PROTOCOL_PREFIX, remoteEffectiveMode,
} from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../audit';
import { getSessionMiddleware } from '../app';
import { config } from '../config';
import { db } from '../db';
import { asNone, asTenant, userActor, type DbActor } from '../db/context';
import { withTenantTransaction } from '../db/tenantContext';
import { personFacts } from '../guard/people';
import { safeErr } from '../jobs/errors';
import { LEGACY_AGENT_ACTOR } from '../legacyAgent/actor';
import { currentServerKey } from '../legacyAgent/serverKey';
import { fromB64url, p256PublicKey } from '../legacyAgent/signature';
import { CLOCK_WINDOW_SECONDS, identifyAgent, isAgentReply, surfaceLimits, type Exchange } from '../legacyAgent/surface';
import { clientIp } from '../utils/clientIp';
import { logger } from '../utils/logger';
import { sessionHash } from '../utils/sessionHash';
import {
  FrameOpener, FrameSealer, NONCE_BYTES, STREAM_TOKEN_BYTES, attachBodySha256, ephemeralKey, sessionKeys, sharedSecret, signHello,
} from './crypto';
import { streamTokenSha256 } from './agentSurface';
import {
  agentAttached, attachAgent, attachViewer, tunnelHeld, tunnelSessionOf, viewerAttached,
} from './relay';
import { RemoteEffects, flushRemoteEffects, lockSession, onEndAttaching, sha256Hex, type Transition } from './sessions';

// =============================================================================
// The two ends of the relay (P0-15 §4.4, T5): raw WebSocket upgrades (lifecycle registerUpgradeHandler, served before
// Socket.io on the same port), every refusal in HTTP BEFORE the handshake (rejectUpgrade, as Obliance: a status line,
// its standard text, the socket destroyed; no reason beyond the code).
//   GET /api/remote-sessions/<uuid>/tunnel   the viewer (the console): no secret in the URL; the Origin equal to the
//            public origin of the console (APP_URL, else CLIENT_ORIGIN): 403 otherwise; the viewer's token in
//            Sec-WebSocket-Protocol (obl-remote.1, obl-viewer.<token>; obl-remote.1 alone answered): 401 without it;
//            the console session (the express session of the cookie, as socket.ts; a phone key it is bound to alive):
//            401; its tenant's session, its requester (404 otherwise, whether it exists or not), SHA-256 of the token
//            equal to viewer_token_sha256 and the console session the token was handed to (viewer_session_sha256,
//            constant time): 403; connecting or live: 409; the conditions
//            (checkOpenable: a condition lost ends the session, 403). One viewer per session: a second replaces the
//            first (a tab reloaded), audited.
//   GET /agent/v1/remote/<uuid>/stream       the bridge agent (through edge-proxy): Obl-Agent-Id, Obl-Seq 0 (never
//            consumed: the one-use token is the anti-replay), Obl-Ts, Obl-Stream-Token (32 bytes), Obl-Nonce (16
//            bytes), Obl-Ecdh (SPKI of an ephemeral P-256 key), Obl-Signature over OBL-AGENT-1 (GET, path, agent, 0, ts,
//            SHA-256(token ‖ nonce ‖ key)): 401 malformed, unknown agent, bad signature or clock; 403 revoked; 429 beyond
//            the limiter of /accept and /end (20 a minute per agent); 503
//            without the instance key; 409 an agent attached already; 404 not a session of its device; 409 not
//            connecting; 403 the token wrong, used or expired (remote_session_consume_stream_token, one UPDATE),
//            or the conditions lost. Then the hello, in clear, signed by the instance key (remote/crypto.ts), and
//            every frame after it sealed (relay.ts).
// =============================================================================

const VIEWER_RE = /^\/api\/remote-sessions\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\/tunnel$/;
const AGENT_RE = /^\/agent\/v1\/remote\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/stream$/;
const UUID_LOWER = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TS_RE = /^[0-9]{1,12}$/;
const VIEWER_TOKEN_RE = /^[0-9a-f]{64}$/;
/** A message of the agent as sealed: its plain bounded, the 29 bytes of the header and the tag, and room. */
const AGENT_MAX_PAYLOAD = REMOTE_RELAY_LIMITS.agentMessageMaxBytes + 64;
const SESSION_LOOKUP_MS = 10_000;

/** No compression (the frames are encrypted, the agent refuses any extension), no tracking (the relay holds them). */
const agentWss = new WebSocketServer({ noServer: true, perMessageDeflate: false, clientTracking: false, maxPayload: AGENT_MAX_PAYLOAD });
const viewerWss = new WebSocketServer({
  noServer: true, perMessageDeflate: false, clientTracking: false, maxPayload: REMOTE_RELAY_LIMITS.viewerMessageMaxBytes,
  // The token is never answered back: obl-remote.1 alone.
  handleProtocols: (protocols: Set<string>) => (protocols.has(REMOTE_VIEWER_PROTOCOL) ? REMOTE_VIEWER_PROTOCOL : false),
});

/** A refusal before the handshake (recopied from Obliance remoteSessionSecurity.ts): its status, nothing more. */
export function rejectUpgrade(socket: Duplex, status: number): void {
  if (socket.destroyed) return;
  const body = STATUS_CODES[status] ?? 'Error';
  socket.on('error', () => socket.destroy());
  socket.once('finish', () => socket.destroy());
  try {
    socket.end(`HTTP/1.1 ${status} ${body}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n`
      + `Cache-Control: no-store\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
  } catch {
    socket.destroy();
  }
}

class Refusal extends Error {
  readonly status: number;
  constructor(status: number, why: string) {
    super(why);
    this.status = status;
  }
}

const header = (req: IncomingMessage, name: string): string | null => {
  const v = req.headers[name];
  return typeof v === 'string' ? v : null;
};

/** Runs the async checks of an upgrade, the socket guarded meanwhile (Node removed its own error listener before
 *  'upgrade'), then accepts or refuses. */
function serve(socket: Duplex, label: string, work: () => Promise<(() => void) | null>): void {
  const onEarlyError = (): void => { socket.destroy(); };
  socket.on('error', onEarlyError);
  work().then((accept) => {
    socket.removeListener('error', onEarlyError);
    if (socket.destroyed) return;
    if (accept) accept();
  }).catch((err: unknown) => {
    socket.removeListener('error', onEarlyError);
    if (err instanceof Refusal) {
      if (err.status === 403 || err.status === 409) logger.warn({ end: label, status: err.status, why: err.message }, 'remote relay: attachment refused');
      rejectUpgrade(socket, err.status);
      return;
    }
    logger.error({ err: safeErr(err), end: label }, 'remote relay: attachment failed');
    rejectUpgrade(socket, 503);
  });
}

/** The answer of a transition that refused an end (its state, a condition lost: the session ended there). */
function refusalOf(t: Extract<Transition, { ok: false }>): Refusal {
  return t.code === 'remoteSessionState' ? new Refusal(409, `state ${t.row.state}`) : new Refusal(403, t.code);
}

// ── The viewer ───────────────────────────────────────────────────────────────

/** The public origin of the console (§4.4): APP_URL, else CLIENT_ORIGIN; null when neither is a URL. */
export function consoleOrigin(): string | null {
  for (const u of [config.appUrl, config.clientOrigin]) {
    if (!u) continue;
    try { return new URL(u).origin; } catch { /* next */ }
  }
  return null;
}

/** The viewer's token of the subprotocols (exactly one obl-viewer.<64 hex>, beside obl-remote.1), or null. */
export function viewerTokenOf(req: IncomingMessage): string | null {
  const raw = header(req, 'sec-websocket-protocol');
  if (!raw) return null;
  const list = raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (!list.includes(REMOTE_VIEWER_PROTOCOL)) return null;
  const tokens = list.filter((p) => p.startsWith(REMOTE_VIEWER_TOKEN_PROTOCOL_PREFIX)).map((p) => p.slice(REMOTE_VIEWER_TOKEN_PROTOCOL_PREFIX.length));
  return tokens.length === 1 && VIEWER_TOKEN_RE.test(tokens[0]) ? tokens[0] : null;
}

/** The express session of an upgrade (the same middleware as the API and Socket.io; recopied from Obliance). */
function loadUpgradeSession(request: IncomingMessage): Promise<{ userId?: unknown; currentTenantId?: unknown; deviceKeyId?: unknown } | undefined> {
  const mw = getSessionMiddleware();
  if (!mw) return Promise.resolve(undefined);
  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn: () => void): void => { if (settled) return; settled = true; clearTimeout(timer); fn(); };
    const timer = setTimeout(() => settle(() => reject(new Error('session lookup timed out'))), SESSION_LOOKUP_MS);
    const res = new ServerResponse(request);
    try {
      (mw as unknown as (q: IncomingMessage, s: ServerResponse, n: (e?: unknown) => void) => void)(request, res, (err?: unknown) => settle(() => {
        if (err) reject(err);
        else resolve((request as unknown as { session?: { userId?: unknown; currentTenantId?: unknown; deviceKeyId?: unknown } }).session);
      }));
    } catch (err) {
      settle(() => reject(err));
    }
  });
}

/** Two SHA-256 (hex) compared in constant time. */
const sameHash = (x: string, y: string): boolean => {
  const a = Buffer.from(String(x ?? ''), 'hex');
  const b = Buffer.from(String(y ?? ''), 'hex');
  return a.length === 32 && b.length === 32 && timingSafeEqual(a, b);
};
const sameToken = (token: string, sha: string): boolean => sameHash(sha256Hex(token), sha);

async function authorizeViewer(request: IncomingMessage, sessionId: string): Promise<(ws: WebSocket) => void> {
  const origin = consoleOrigin();
  if (!origin || header(request, 'origin') !== origin) throw new Refusal(403, 'origin');
  const token = viewerTokenOf(request);
  if (!token) throw new Refusal(401, 'no viewer token');
  const sess = await loadUpgradeSession(request);
  const userId = Number(sess?.userId);
  const tenantId = Number(sess?.currentTenantId);
  const sid = (request as unknown as { sessionID?: unknown }).sessionID;
  if (!Number.isSafeInteger(userId) || userId <= 0 || typeof sid !== 'string' || !sid) throw new Refusal(401, 'no console session');
  if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new Refusal(404, 'no tenant');
  const actor: DbActor = userActor(userId);
  const ip = clientIp(request) || null;
  // Device-bound 2FA: an upgrade never goes through deviceKeySession; a session bound to a dead key opens nothing.
  const dead = await asNone(actor, async () => {
    if (!sess?.deviceKeyId) return false;
    const { boundSessionDead } = await import('../services/deviceKey/deviceKey.service');
    return boundSessionDead(sess.deviceKeyId, userId);
  });
  if (dead) throw new Refusal(401, 'console session bound to a dead key');
  const facts = await asTenant(tenantId, actor, () => personFacts(userId, tenantId));
  if (!facts.exists || !facts.active || (!facts.platformAdmin && facts.tenantRole === null)) throw new Refusal(401, 'user');
  const auditCtx: AuditWriteContext = await asTenant(tenantId, actor, () =>
    audit.fromDbActor(actor, tenantId, { ...(ip ? { ip } : {}), route: 'GET /api/remote-sessions/:id/tunnel' }));
  const fx = new RemoteEffects();
  const reattach = viewerAttached(sessionId);
  let t: Transition;
  try {
    t = await withTenantTransaction(tenantId, actor, async (trx) => {
      const r = await lockSession(trx, tenantId, sessionId);
      if (!r || Number(r.requested_by) !== userId) throw new Refusal(404, 'not found');
      if (!sameToken(token, r.viewer_token_sha256)) throw new Refusal(403, 'token');
      // The token is bound to the console session it was handed to (§0.1 rule 3).
      if (!r.viewer_session_sha256 || !sameHash(sessionHash(sid), r.viewer_session_sha256)) throw new Refusal(403, 'another console session');
      if (r.state === 'live' && !tunnelHeld(sessionId)) throw new Refusal(409, 'live without its tunnel');
      return onEndAttaching(trx, fx, r, { end: 'viewer', reattach, auditCtx });
    });
  } finally {
    await flushRemoteEffects(fx, actor, auditCtx);
  }
  if (!t.ok) throw refusalOf(t);
  const row = t.row;
  const session = tunnelSessionOf(row);
  const hash = sessionHash(sid);
  return (ws: WebSocket) => attachViewer(ws, { session, userId, sessionHash: hash, ip, auditCtx });
}

// ── The agent ────────────────────────────────────────────────────────────────

async function authorizeAgent(request: IncomingMessage, sessionId: string, path: string): Promise<(ws: WebSocket) => void> {
  const agentId = header(request, 'obl-agent-id');
  const seq = header(request, 'obl-seq');
  const ts = header(request, 'obl-ts');
  const signature = header(request, 'obl-signature');
  const token = fromB64url(header(request, 'obl-stream-token'), STREAM_TOKEN_BYTES);
  const nonce = fromB64url(header(request, 'obl-nonce'), NONCE_BYTES);
  const ecdhRaw = fromB64url(header(request, 'obl-ecdh'), 128);
  if (!agentId || !UUID_LOWER.test(agentId) || seq !== '0' || !ts || !TS_RE.test(ts) || !signature || signature.length > 120
    || !token || token.length !== STREAM_TOKEN_BYTES || !nonce || nonce.length !== NONCE_BYTES || !ecdhRaw || !p256PublicKey(ecdhRaw)) {
    throw new Refusal(401, 'headers');
  }
  const ecdh = ecdhRaw;
  const key = await currentServerKey();
  if (!key) throw new Refusal(503, 'no instance key');
  const ex: Exchange = { agentId, seq: '0', ts: Number(ts), signature, reqSha: attachBodySha256(token, nonce, ecdh), path, method: 'GET' };
  const who = await identifyAgent(ex);
  if (isAgentReply(who)) throw new Refusal(who.status === 403 ? 403 : 401, String(who.body.code ?? 'agent'));
  if (Math.abs(ex.ts - Math.floor(Date.now() / 1000)) > CLOCK_WINDOW_SECONDS) throw new Refusal(401, 'clock');
  // The limiter of /accept and /end (20 a minute per agent): an agent retrying its attachment in a loop.
  if (surfaceLimits.remotePerAgent.hit(who.agentId)) throw new Refusal(429, 'rate');
  if (agentAttached(sessionId)) throw new Refusal(409, 'an agent is attached');
  const found = await asNone(LEGACY_AGENT_ACTOR, () => db.raw(
    'SELECT tenant_id, state FROM obligarth.remote_session_stream_lookup(?::uuid, ?::uuid)', [sessionId, agentId],
  )) as { rows: Array<{ tenant_id: number; state: string }> };
  const s = found.rows[0];
  if (!s || Number(s.tenant_id) !== who.tenantId) throw new Refusal(404, 'not a session of the device');
  if (s.state !== 'connecting') throw new Refusal(409, `state ${s.state}`);
  const consumed = await asNone(LEGACY_AGENT_ACTOR, () => db.raw(
    'SELECT obligarth.remote_session_consume_stream_token(?::uuid, ?::uuid, ?) AS ok', [sessionId, agentId, streamTokenSha256(token)],
  )) as { rows: Array<{ ok: boolean }> };
  if (consumed.rows[0]?.ok !== true) throw new Refusal(403, 'stream token');
  const auditCtx = await asTenant(who.tenantId, LEGACY_AGENT_ACTOR, () => audit.fromDbActor(LEGACY_AGENT_ACTOR, who.tenantId));
  const fx = new RemoteEffects();
  let t: Transition | null;
  try {
    t = await withTenantTransaction(who.tenantId, LEGACY_AGENT_ACTOR, async (trx) => {
      const r = await lockSession(trx, who.tenantId, sessionId);
      return r && Number(r.device_id) === who.deviceId ? onEndAttaching(trx, fx, r, { end: 'agent', auditCtx }) : null;
    });
  } finally {
    await flushRemoteEffects(fx, LEGACY_AGENT_ACTOR, auditCtx);
  }
  if (!t) throw new Refusal(404, 'not a session of the device');
  if (!t.ok) throw refusalOf(t);
  const session = tunnelSessionOf(t.row);
  const mode = remoteEffectiveMode(t.row.mode, t.row.consented_mode);
  return (ws: WebSocket) => {
    const own = ephemeralKey();
    const secret = sharedSecret(own.privateKey, ecdh);
    if (!secret) { ws.terminate(); return; }
    const keys = sessionKeys(secret, nonce, sessionId);
    secret.fill(0);
    const hello = signHello(key.privateKey, {
      agentNonce: nonce, agentEcdhSpki: ecdh, serverEcdhSpki: own.spki, sessionId, mode, ts: Math.floor(Date.now() / 1000),
    });
    attachAgent(ws, {
      session, sealer: new FrameSealer(keys.serverToAgent), opener: new FrameOpener(keys.agentToServer), hello: JSON.stringify(hello),
    });
    keys.agentToServer.fill(0);
    keys.serverToAgent.fill(0);
  };
}


// ── Registration (modules/remote.ts) ─────────────────────────────────────────

/** The viewer's upgrade handler: its own path only. */
export function viewerUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer, pathname: string): boolean {
  const m = VIEWER_RE.exec(pathname);
  if (!m) return false;
  const sessionId = m[1].toLowerCase();
  serve(socket, 'viewer', async () => {
    const onSocket = await authorizeViewer(request, sessionId);
    return () => viewerWss.handleUpgrade(request, socket, head, onSocket);
  });
  return true;
}

/** The agent's upgrade handler: its own path only (the exact path signed: no query). */
export function agentUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer, pathname: string): boolean {
  const m = AGENT_RE.exec(pathname);
  if (!m) return false;
  const path = String(request.url ?? '');
  serve(socket, 'agent', async () => {
    if (path !== pathname) throw new Refusal(401, 'path');
    const onSocket = await authorizeAgent(request, m[1], path);
    return () => {
      if (agentAttached(m[1])) { rejectUpgrade(socket, 409); return; }
      agentWss.handleUpgrade(request, socket, head, onSocket);
    };
  });
  return true;
}
