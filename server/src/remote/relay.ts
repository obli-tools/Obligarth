import { WebSocket, type RawData } from 'ws';
import {
  REMOTE_LIMITS, REMOTE_RELAY_LIMITS, isRemoteFinalState, remoteEffectiveMode,
  type RemoteChannel, type RemoteEndReason, type RemoteEndedBy, type RemoteMode, type RemoteServerToAgentMessage,
  type RemoteServerToViewerMessage,
} from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../audit';
import { db } from '../db';
import { asNone, userActor, type DbActor } from '../db/context';
import { withTenantTransaction } from '../db/tenantContext';
import { safeErr } from '../jobs/errors';
import { logger } from '../utils/logger';
import { FRAME_KIND_BINARY, FRAME_KIND_TEXT, FrameError, type FrameOpener, type FrameSealer } from './crypto';
import { remoteMetrics } from './metrics';
import { InputRate, checkAgentBinary, checkAgentText, checkViewerText, type DropReason } from './protocol';
import {
  RemoteEffects, endSession, flushRemoteEffects, lockSession, onAttached, revalidateSession, type RemoteCounters, type SessionRow,
  type Transition,
} from './sessions';

// =============================================================================
// The relay of the remote sessions (P0-15 §4.4, §5, T5): one tunnel per session in memory (the instance is one
// process), its agent's end (the stream of the bridge agent, every frame opened and sealed with the keys of its hello,
// remote/crypto.ts) and its viewer's end (the console, TLS up to the proxy). Attached by remote/upgrade.ts once each end
// passed its checks before the handshake; paired when both are there (connecting → live, sessions.ts onAttached).
//   agent → viewer   the frames opened, then relayed without another change (texts of agent → viewer of §5.2 within
//                    4 KiB, JPEG and H.264 binaries); the last init and display_state kept for a viewer that attaches;
//                    the video dropped while no viewer is there or beyond 2 MiB waiting for it, until the next key frame
//                    (a key_request of the relay when the viewer catches up), never the control messages; a viewer that
//                    falls 8 MiB behind is closed (it attaches again)
//   viewer → agent   texts of viewer → agent of §5.2 within their bounds, rewritten with their known fields, sealed; the
//                    inputs dropped while the effective mode is view (the agent refuses them too), 200 inputs a second
//                    at most; a binary, a type of the other direction (consent_state…), unknown or malformed: dropped
//   server           hello (upgrade.ts), mode (the control granted or released, sessions.ts once committed: the filter
//                    of the relay follows it, the viewer told), session_end to both ends when the session ends
//   ping             every 25 s on both ends, a pong within 20 s or the end is cut
//   revalidation     every 60 s (and at the deadline of a session still connecting): the counters written, the
//                    deadline, the console session of the viewer (the session table, by the hash of its id), the
//                    conditions of its requester (checkOpenable): the first failure ends the session (revoked, freeze)
//   ends             an end that closes ends the session: the agent's after its inactivity_timeout (idle), past the
//                    maximum (max_duration), otherwise after 5 s for its /end to arrive (device_timeout when the
//                    connection was lost, agent_error otherwise); a protocol fault of the agent (a clear frame, a frame
//                    that does not open, a counter not increasing) at once (agent_error); the viewer's after 30 s
//                    without a new one (operator); the maximum duration at its time; the revocation of the console
//                    session or of its user (onSessionsKilled, modules/remote.ts: revoked)
// Every end of the session, wherever it comes from (the console, the sweep, the agent's /end, the freeze), closes the
// tunnel (onRemoteSessionEnded) with session_end { reason } to both ends. No token, no image, no typed text in a log
// line: the session, the codes and the counts only.
// =============================================================================

const RELAY_ACTOR: DbActor = { type: 'job', name: 'remote.relay' };

/** The delays of the relay (REMOTE_LIMITS, REMOTE_RELAY_LIMITS), in ms; shortened by the tests only. */
const DEFAULT_TIMINGS = Object.freeze({
  tickMs: 5_000,
  pingMs: REMOTE_LIMITS.pingSeconds * 1000,
  pongMs: REMOTE_LIMITS.pongSeconds * 1000,
  viewerReattachMs: REMOTE_RELAY_LIMITS.viewerReattachSeconds * 1000,
  agentGoneMs: REMOTE_RELAY_LIMITS.agentGoneGraceSeconds * 1000,
});
let timings: { -readonly [K in keyof typeof DEFAULT_TIMINGS]: number } = { ...DEFAULT_TIMINGS };

/** Tests only: shorter delays (null: the defaults). Taken by the tunnels created after the call. */
export function setRelayTimings(t: Partial<typeof DEFAULT_TIMINGS> | null): void {
  timings = { ...DEFAULT_TIMINGS, ...(t ?? {}) };
}
const CLOSE_GRACE_MS = 2_000;
/** Close codes of the relay (RFC 6455 §7.4.1). */
const CLOSE_NORMAL = 1000;
const CLOSE_POLICY = 1008;
const CLOSE_TRY_AGAIN = 1013;
const CLOSE_REPLACED = 4001;

interface End {
  ws: WebSocket;
  /** Time of the ping awaiting its pong (0: none), of the last ping sent. */
  pingAt: number;
  lastPing: number;
}

interface AgentEnd extends End { sealer: FrameSealer; opener: FrameOpener }

interface ViewerEnd extends End {
  userId: number;
  /** sha256 of the express session id of the console (userSessions.service closeSessionChannels). */
  sessionHash: string;
  ip: string | null;
  auditCtx: AuditWriteContext;
}

interface Tunnel {
  id: string;
  tenantId: number;
  deviceId: number;
  channel: RemoteChannel;
  requestedBy: number | null;
  effective: RemoteMode;
  maxEndsAt: number | null;
  createdAt: number;
  live: boolean;
  agent: AgentEnd | null;
  viewer: ViewerEnd | null;
  /** The agent's end left (its /end awaited a few seconds), or the viewer's (a new one awaited). */
  agentGoneTimer: NodeJS.Timeout | null;
  viewerGoneTimer: NodeJS.Timeout | null;
  closing: boolean;
  ending: boolean;
  promoting: boolean;
  revalidating: boolean;
  nextRevalidate: number;
  counters: RemoteCounters;
  dropped: Partial<Record<DropReason, number>>;
  rate: InputRate;
  awaitKey: boolean;
  lastKeyRequest: number;
  idleSeen: boolean;
  lastInit: Buffer | null;
  lastDisplay: Buffer | null;
  timer: NodeJS.Timeout;
}

const tunnels = new Map<string, Tunnel>();

/** The session's row as an end attaches (its tenant's transaction just read it). */
export interface TunnelSession {
  id: string;
  tenantId: number;
  deviceId: number;
  channel: RemoteChannel;
  requestedBy: number | null;
  mode: RemoteMode;
  consentedMode: RemoteMode | null;
  state: string;
  maxEndsAt: Date | string | null;
}

const sessionOf = (r: SessionRow): TunnelSession => ({
  id: String(r.id).toLowerCase(), tenantId: Number(r.tenant_id), deviceId: Number(r.device_id), channel: r.channel,
  requestedBy: r.requested_by === null ? null : Number(r.requested_by), mode: r.mode, consentedMode: r.consented_mode ?? null, state: r.state,
  maxEndsAt: r.max_ends_at,
});
export { sessionOf as tunnelSessionOf };

function tunnelFor(s: TunnelSession): Tunnel {
  const existing = tunnels.get(s.id);
  if (existing) return existing;
  const now = Date.now();
  const t: Tunnel = {
    id: s.id, tenantId: s.tenantId, deviceId: s.deviceId, channel: s.channel, requestedBy: s.requestedBy,
    effective: remoteEffectiveMode(s.mode, s.consentedMode), maxEndsAt: s.maxEndsAt ? new Date(s.maxEndsAt).getTime() : null,
    createdAt: now, live: s.state === 'live', agent: null, viewer: null, agentGoneTimer: null, viewerGoneTimer: null,
    closing: false, ending: false, promoting: false, revalidating: false,
    // A session still connecting is read again at its deadline (60 s to attach), a live one every 60 s.
    nextRevalidate: now + (s.state === 'live' ? REMOTE_LIMITS.revalidateSeconds : REMOTE_LIMITS.connectingSeconds + 2) * 1000,
    counters: { bytesDown: 0, bytesUp: 0, inputEvents: 0 }, dropped: {}, rate: new InputRate(), awaitKey: true, lastKeyRequest: 0,
    idleSeen: false, lastInit: null, lastDisplay: null,
    timer: setInterval(() => tick(t), timings.tickMs),
  };
  t.timer.unref?.();
  tunnels.set(s.id, t);
  return t;
}

const toBuffer = (data: RawData): Buffer =>
  Buffer.isBuffer(data) ? data : Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as ArrayBuffer);

function drop(t: Tunnel, reason: DropReason): void {
  t.dropped[reason] = (t.dropped[reason] ?? 0) + 1;
  remoteMetrics.dropped(reason);
}

function closeWs(ws: WebSocket, code: number): void {
  try {
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.close(code);
  } catch { /* closed */ }
  setTimeout(() => { try { ws.terminate(); } catch { /* closed */ } }, CLOSE_GRACE_MS).unref?.();
}

// ── Sending ──────────────────────────────────────────────────────────────────

/** A message sealed for the agent's end (the server's own, or the viewer's checked). */
function sendAgent(t: Tunnel, message: object): boolean {
  const a = t.agent;
  if (!a || a.ws.readyState !== WebSocket.OPEN) return false;
  const plain = Buffer.from(JSON.stringify(message), 'utf8');
  try {
    a.ws.send(a.sealer.seal(FRAME_KIND_TEXT, plain), { binary: true });
  } catch (err) {
    if (err instanceof FrameError) { violation(t, err.message); return false; }
    return false;
  }
  t.counters.bytesUp += plain.length;
  remoteMetrics.relayed('up', plain.length);
  return true;
}

function sendViewer(t: Tunnel, data: Buffer | string, binary = false): boolean {
  const v = t.viewer;
  if (!v || v.ws.readyState !== WebSocket.OPEN) return false;
  try { v.ws.send(data, { binary }); } catch { return false; }
  return true;
}

const sendViewerMessage = (t: Tunnel, message: RemoteServerToViewerMessage): boolean => sendViewer(t, JSON.stringify(message));

// ── The agent's end ──────────────────────────────────────────────────────────

/** A fault of the agent's protocol: the stream is cut, the session ends (agent_error). */
function violation(t: Tunnel, reason: string): void {
  logger.warn({ sessionId: t.id, reason }, 'remote relay: protocol fault of the agent, the session ends');
  if (t.agent) closeWs(t.agent.ws, CLOSE_POLICY);
  void endFromRelay(t, 'agent_error', 'system', { protocol: reason.slice(0, 80) });
}

function maybeKeyRequest(t: Tunnel, now: number): void {
  if (now - t.lastKeyRequest < REMOTE_RELAY_LIMITS.keyRequestMs) return;
  t.lastKeyRequest = now;
  sendAgent(t, { type: 'key_request' });
}

/** A video frame towards the viewer: dropped until the next key frame while nobody watches or the viewer lags. */
function forwardVideo(t: Tunnel, plain: Buffer, key: boolean): void {
  const v = t.viewer;
  if (!v || v.ws.readyState !== WebSocket.OPEN) { t.awaitKey = true; drop(t, 'no_viewer'); return; }
  const buffered = v.ws.bufferedAmount;
  if (buffered > REMOTE_RELAY_LIMITS.viewerStallBytes) {
    logger.info({ sessionId: t.id }, 'remote relay: the viewer lags too far, closed (it attaches again)');
    closeWs(v.ws, CLOSE_TRY_AGAIN);
    return;
  }
  const now = Date.now();
  const caughtUp = buffered <= REMOTE_LIMITS.bufferBytes / 2;
  if (t.awaitKey) {
    if (!key || !caughtUp) {
      drop(t, 'backpressure');
      if (caughtUp) maybeKeyRequest(t, now);
      return;
    }
    t.awaitKey = false;
  } else if (buffered > REMOTE_LIMITS.bufferBytes) {
    t.awaitKey = true;
    drop(t, 'backpressure');
    return;
  }
  sendViewer(t, plain, true);
}

function onAgentMessage(t: Tunnel, a: AgentEnd, data: RawData, isBinary: boolean): void {
  if (t.agent !== a || t.closing) return;
  if (!isBinary) { violation(t, 'clear frame after the hello'); return; }
  let opened;
  try {
    opened = a.opener.open(toBuffer(data));
  } catch (err) {
    violation(t, err instanceof FrameError ? err.message : 'frame');
    return;
  }
  const plain = opened.plain;
  t.counters.bytesDown += plain.length;
  remoteMetrics.relayed('down', plain.length);
  if (opened.kind === FRAME_KIND_BINARY) {
    const c = checkAgentBinary(plain);
    if (!c.ok) { drop(t, c.reason); return; }
    forwardVideo(t, plain, c.key);
    return;
  }
  const c = checkAgentText(plain);
  if (!c.ok) { drop(t, c.reason); return; }
  if (c.type === 'inactivity_timeout') t.idleSeen = true;
  if (c.type === 'init') { t.lastInit = plain; t.awaitKey = true; }
  if (c.type === 'display_state') t.lastDisplay = plain;
  if (!sendViewer(t, plain)) drop(t, 'no_viewer');
}

/** Why the agent's end left without a word (its /end not received meanwhile). */
const agentGoneReason = (code: number): RemoteEndReason => (code === 1006 || code === 1001 ? 'device_timeout' : 'agent_error');

function onAgentClose(t: Tunnel, a: AgentEnd, code: number): void {
  if (t.agent !== a) return;
  t.agent = null;
  if (t.closing) return;
  if (t.idleSeen) { void endFromRelay(t, 'idle', 'system'); return; }
  if (t.maxEndsAt !== null && Date.now() >= t.maxEndsAt - 5_000) { void endFromRelay(t, 'max_duration', 'system'); return; }
  // The agent tells its own end (/end: screen off, its error) on another connection: awaited a few seconds.
  t.agentGoneTimer = setTimeout(() => {
    t.agentGoneTimer = null;
    if (!t.closing) void endFromRelay(t, agentGoneReason(code), 'system', { agentClose: code });
  }, timings.agentGoneMs);
  t.agentGoneTimer.unref?.();
}

export interface AgentAttach {
  session: TunnelSession;
  sealer: FrameSealer;
  opener: FrameOpener;
  /** The hello, in clear, the first frame. */
  hello: string;
}

/** Is the agent's end of a session attached now. */
export const agentAttached = (sessionId: string): boolean => !!tunnels.get(sessionId)?.agent;

/** The agent's end of a session, its upgrade done (upgrade.ts): the hello first, then its frames. A second agent never
 *  reaches here (the one-use stream token, and the 409 of the upgrade). */
export function attachAgent(ws: WebSocket, x: AgentAttach): void {
  const t = tunnelFor(x.session);
  if (t.agent || t.closing) { closeWs(ws, CLOSE_POLICY); return; }
  const now = Date.now();
  const a: AgentEnd = { ws, sealer: x.sealer, opener: x.opener, pingAt: 0, lastPing: now };
  t.agent = a;
  t.awaitKey = true;
  ws.on('error', () => { /* the close follows */ });
  ws.on('pong', () => { a.pingAt = 0; });
  ws.on('message', (data, isBinary) => onAgentMessage(t, a, data, isBinary));
  ws.on('close', (code) => onAgentClose(t, a, code));
  ws.send(x.hello, { binary: false });
  logger.info({ sessionId: t.id, mode: t.effective }, 'remote relay: agent attached');
  void promote(t);
}

// ── The viewer's end ─────────────────────────────────────────────────────────

function onViewerMessage(t: Tunnel, v: ViewerEnd, data: RawData, isBinary: boolean): void {
  if (t.viewer !== v || t.closing) return;
  if (isBinary) { drop(t, 'binary_from_viewer'); return; }
  const c = checkViewerText(toBuffer(data).toString('utf8'), t.effective);
  if (!c.ok) { drop(t, c.reason); return; }
  if (c.input && !t.rate.take()) { drop(t, 'input_rate'); return; }
  const a = t.agent;
  if (!a) { drop(t, 'no_agent'); return; }
  if (a.ws.bufferedAmount > REMOTE_LIMITS.bufferBytes) { drop(t, 'backpressure'); return; }
  if (sendAgent(t, c.message) && c.input) t.counters.inputEvents++;
}

function onViewerClose(t: Tunnel, v: ViewerEnd): void {
  if (t.viewer !== v) return;
  t.viewer = null;
  if (t.closing) return;
  if (!t.live) {
    // Not paired yet: nothing held for it (the deadline of connecting ends the session).
    if (!t.agent) forget(t);
    return;
  }
  t.awaitKey = true;
  t.viewerGoneTimer = setTimeout(() => {
    t.viewerGoneTimer = null;
    if (!t.closing && !t.viewer) void endFromRelay(t, 'operator', 'system', { viewerGone: true });
  }, timings.viewerReattachMs);
  t.viewerGoneTimer.unref?.();
}

export interface ViewerAttach {
  session: TunnelSession;
  userId: number;
  sessionHash: string;
  ip: string | null;
  auditCtx: AuditWriteContext;
}

/** Is a viewer attached to a session now (its replacement is audited). */
export const viewerAttached = (sessionId: string): boolean => !!tunnels.get(sessionId)?.viewer;

/** A live session whose tunnel is gone (its agent left, the server restarted): no viewer can attach to it any more. */
export const tunnelHeld = (sessionId: string): boolean => tunnels.has(sessionId);

/** The viewer's end of a session, its upgrade done: replaces the one attached (a tab reloaded), gets the last init,
 *  display_state and the effective mode, and a key frame is asked. */
export function attachViewer(ws: WebSocket, x: ViewerAttach): void {
  const t = tunnelFor(x.session);
  if (t.closing) { closeWs(ws, CLOSE_TRY_AGAIN); return; }
  const previous = t.viewer;
  const now = Date.now();
  const v: ViewerEnd = { ws, userId: x.userId, sessionHash: x.sessionHash, ip: x.ip, auditCtx: x.auditCtx, pingAt: 0, lastPing: now };
  t.viewer = v;
  if (previous) closeWs(previous.ws, CLOSE_REPLACED);
  if (t.viewerGoneTimer) { clearTimeout(t.viewerGoneTimer); t.viewerGoneTimer = null; }
  ws.on('error', () => { /* the close follows */ });
  ws.on('pong', () => { v.pingAt = 0; });
  ws.on('message', (data, isBinary) => onViewerMessage(t, v, data, isBinary));
  ws.on('close', () => onViewerClose(t, v));
  sendViewerMessage(t, { type: 'mode', effective: t.effective });
  if (t.lastInit) sendViewer(t, t.lastInit);
  if (t.lastDisplay) sendViewer(t, t.lastDisplay);
  t.awaitKey = true;
  t.lastKeyRequest = 0;
  if (t.agent) maybeKeyRequest(t, now);
  logger.info({ sessionId: t.id, replaced: !!previous }, 'remote relay: viewer attached');
  void promote(t);
}

// ── Pairing, revalidation, ends ──────────────────────────────────────────────

/** Both ends attached to a session still connecting: live (onAttached: the conditions again, remote.session_started
 *  critical with the console's address), the technician's act. */
async function promote(t: Tunnel): Promise<void> {
  if (t.live || t.promoting || t.closing || !t.agent || !t.viewer) return;
  t.promoting = true;
  const v = t.viewer;
  const actor = userActor(v.userId);
  const fx = new RemoteEffects();
  let res: Transition | null = null;
  try {
    res = await withTenantTransaction(t.tenantId, actor, async (trx) => {
      const r = await lockSession(trx, t.tenantId, t.id);
      return r ? onAttached(trx, fx, r, v.auditCtx, { ip: v.ip }) : null;
    });
  } catch (err) {
    logger.error({ err: safeErr(err), sessionId: t.id }, 'remote relay: the pairing of a session failed');
  }
  await flushRemoteEffects(fx, actor, v.auditCtx);
  t.promoting = false;
  if (res?.ok) {
    t.live = true;
    t.maxEndsAt = res.row.max_ends_at ? new Date(res.row.max_ends_at).getTime() : t.maxEndsAt;
    t.nextRevalidate = Date.now() + REMOTE_LIMITS.revalidateSeconds * 1000;
    logger.info({ sessionId: t.id, mode: t.effective }, 'remote relay: session live');
    return;
  }
  // Refused (the session ended meanwhile, a condition lost: it ended there and its listener closed the tunnel), or
  // the database failed: the session cannot be relayed.
  if (!res || !isRemoteFinalState(res.row.state)) void endFromRelay(t, 'agent_error', 'system', { pairing: res ? res.code : 'failed' });
  else closeTunnel(t.id, res.row.end_reason ?? 'agent_error');
}

/** The console session of the viewer still valid (§0.1 rule 3): its row of the session store not expired, the same
 *  user, a phone key it is bound to still alive. Read by the hash of its id (the id itself is never kept). */
async function consoleSessionAlive(v: ViewerEnd): Promise<boolean> {
  return asNone(RELAY_ACTOR, async () => {
    const r = await db.raw(
      "SELECT sess FROM session WHERE expire > now() AND encode(sha256(convert_to(sid, 'UTF8')), 'hex') = ?", [v.sessionHash],
    ) as { rows: Array<{ sess: unknown }> };
    const raw = r.rows[0]?.sess;
    if (raw === undefined) return false;
    const sess = (typeof raw === 'string' ? JSON.parse(raw) : raw) as { userId?: unknown; deviceKeyId?: unknown } | null;
    if (Number(sess?.userId) !== v.userId) return false;
    if (sess?.deviceKeyId) {
      const { boundSessionDead } = await import('../services/deviceKey/deviceKey.service');
      if (await boundSessionDead(sess.deviceKeyId, v.userId)) return false;
    }
    return true;
  });
}

const relayAuditCtx = (t: Tunnel): AuditWriteContext => audit.fromJob({ name: 'remote.relay', requestId: `relay-${t.id.slice(0, 8)}` });

async function revalidate(t: Tunnel): Promise<void> {
  if (t.revalidating || t.closing || t.ending) return;
  t.revalidating = true;
  const auditCtx = relayAuditCtx(t);
  const fx = new RemoteEffects();
  try {
    const consoleSession = t.viewer ? await consoleSessionAlive(t.viewer) : null;
    const res = await withTenantTransaction(t.tenantId, RELAY_ACTOR, async (trx) => {
      const r = await lockSession(trx, t.tenantId, t.id);
      return r ? revalidateSession(trx, fx, r, { counters: { ...t.counters }, consoleSession, auditCtx }) : null;
    });
    await flushRemoteEffects(fx, RELAY_ACTOR, auditCtx);
    if (!res) { closeTunnel(t.id, 'revoked'); return; }
    if (!res.ok) {
      if (isRemoteFinalState(res.row.state)) closeTunnel(t.id, res.row.end_reason ?? 'revoked');
      return;
    }
    // The database is the reference of the mode (a mode the agent missed is sent again).
    const effective = remoteEffectiveMode(res.row.mode, res.row.consented_mode);
    if (effective !== t.effective) deliverToTunnel(t, { type: 'mode', effective });
    t.maxEndsAt = res.row.max_ends_at ? new Date(res.row.max_ends_at).getTime() : t.maxEndsAt;
  } catch (err) {
    logger.warn({ err: safeErr(err), sessionId: t.id }, 'remote relay: revalidation failed (again at the next run)');
  } finally {
    t.revalidating = false;
    t.nextRevalidate = Date.now() + REMOTE_LIMITS.revalidateSeconds * 1000;
  }
}

/** The relay ends the session (an end left, the maximum, a revocation): in the tenant's transaction, as the relay; the
 *  listener of the end then closes the tunnel (closed here too when the session was final already or the database
 *  failed). */
async function endFromRelay(t: Tunnel, reason: RemoteEndReason, by: RemoteEndedBy, details: Record<string, unknown> = {}): Promise<void> {
  if (t.ending || t.closing) return;
  t.ending = true;
  const auditCtx = relayAuditCtx(t);
  const fx = new RemoteEffects();
  let final: RemoteEndReason = reason;
  try {
    await withTenantTransaction(t.tenantId, RELAY_ACTOR, async (trx) => {
      const r = await lockSession(trx, t.tenantId, t.id);
      if (!r) return;
      const row = await endSession(trx, fx, r, { reason, by, auditCtx, details: { endedFrom: 'relay', ...details } });
      if (row.end_reason) final = row.end_reason;
    });
  } catch (err) {
    logger.error({ err: safeErr(err), sessionId: t.id, reason }, 'remote relay: the end of a session not written (closed anyway)');
  }
  await flushRemoteEffects(fx, RELAY_ACTOR, auditCtx);
  closeTunnel(t.id, final);
}

function tick(t: Tunnel): void {
  if (t.closing) return;
  const now = Date.now();
  for (const e of [t.agent, t.viewer]) {
    if (!e) continue;
    if (e.pingAt && now - e.pingAt > timings.pongMs) {
      try { e.ws.terminate(); } catch { /* closed */ }
      continue;
    }
    if (!e.pingAt && now - e.lastPing >= timings.pingMs) {
      e.pingAt = now;
      e.lastPing = now;
      try { e.ws.ping(); } catch { /* the close follows */ }
    }
  }
  if (t.live && t.maxEndsAt !== null && now >= t.maxEndsAt) { void endFromRelay(t, 'max_duration', 'system'); return; }
  if (now >= t.nextRevalidate) void revalidate(t);
}

function forget(t: Tunnel): void {
  clearInterval(t.timer);
  if (t.agentGoneTimer) clearTimeout(t.agentGoneTimer);
  if (t.viewerGoneTimer) clearTimeout(t.viewerGoneTimer);
  if (tunnels.get(t.id) === t) tunnels.delete(t.id);
}

/** The session ended (its transaction committed): session_end { reason } to both ends, both closed. */
export function closeTunnel(sessionId: string, reason: RemoteEndReason): void {
  const t = tunnels.get(sessionId);
  if (!t || t.closing) return;
  t.closing = true;
  forget(t);
  const message = { type: 'session_end', reason } as const;
  if (t.agent) { sendAgent(t, message); closeWs(t.agent.ws, CLOSE_NORMAL); }
  if (t.viewer) { sendViewerMessage(t, message); closeWs(t.viewer.ws, CLOSE_NORMAL); }
  logger.info({ sessionId, reason, ...t.counters, dropped: t.dropped }, 'remote relay: tunnel closed');
}

function deliverToTunnel(t: Tunnel, message: RemoteServerToAgentMessage): boolean {
  if (message.type === 'mode') {
    t.effective = message.effective;
    sendViewerMessage(t, { type: 'mode', effective: message.effective });
  }
  return sendAgent(t, message);
}

/** The control messages of the state machine (channels/legacyAgent.ts setRemoteControlSink): mode, once committed. */
export const relayControlSink = {
  attached: agentAttached,
  deliver(sessionId: string, message: RemoteServerToAgentMessage): boolean {
    const t = tunnels.get(sessionId);
    return t && !t.closing ? deliverToTunnel(t, message) : false;
  },
};

/** The relay's counters of a session (sessions.ts endSession writes them with the end). */
export function tunnelCounters(sessionId: string): RemoteCounters | null {
  const t = tunnels.get(sessionId);
  return t ? { ...t.counters } : null;
}

/** onSessionsKilled (modules/remote.ts): the tunnels of a user (forUser: every session of the user deleted) or of these
 *  console sessions (forSessions: their hashes) end, revoked. Returns how many. */
export async function endTunnelsWhere(match: (t: Tunnel) => boolean, why: string): Promise<number> {
  const hit = [...tunnels.values()].filter((t) => !t.closing && match(t));
  await Promise.all(hit.map((t) => endFromRelay(t, 'revoked', 'system', { consoleSession: why.slice(0, 60) })));
  return hit.length;
}
export const endTunnelsOfUser = (userId: number, why: string): Promise<number> =>
  endTunnelsWhere((t) => t.requestedBy === userId || t.viewer?.userId === userId, why);
export const endTunnelsOfConsoleSessions = (hashes: string[], why: string): Promise<number> => {
  const set = new Set(hashes);
  return endTunnelsWhere((t) => !!t.viewer && set.has(t.viewer.sessionHash), why);
};

/** At the stop of the server: every relayed session ends (server_restart), within `budgetMs`. */
export async function stopRelay(budgetMs = 5_000): Promise<number> {
  const all = [...tunnels.values()];
  if (all.length === 0) return 0;
  await Promise.race([
    Promise.all(all.map((t) => endFromRelay(t, 'server_restart', 'system'))),
    new Promise((r) => { setTimeout(r, budgetMs).unref?.(); }),
  ]);
  for (const t of [...tunnels.values()]) closeTunnel(t.id, 'server_restart');
  return all.length;
}

/** The ends attached now (metrics), and tests. */
export function relayStats(): { tunnels: number; agent: number; viewer: number } {
  let agent = 0;
  let viewer = 0;
  for (const t of tunnels.values()) { if (t.agent) agent++; if (t.viewer) viewer++; }
  return { tunnels: tunnels.size, agent, viewer };
}

/** Tests: what a tunnel dropped, its counters and its effective mode. */
export function tunnelFacts(sessionId: string): { effective: RemoteMode; live: boolean; dropped: Partial<Record<DropReason, number>>; counters: RemoteCounters } | null {
  const t = tunnels.get(sessionId);
  return t ? { effective: t.effective, live: t.live, dropped: { ...t.dropped }, counters: { ...t.counters } } : null;
}

/** Tests: the next revalidation of a tunnel now. */
export function revalidateNow(sessionId: string): Promise<void> {
  const t = tunnels.get(sessionId);
  return t ? revalidate(t) : Promise.resolve();
}
