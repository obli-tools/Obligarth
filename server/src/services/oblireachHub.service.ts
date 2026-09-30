import type { WebSocket } from 'ws';
import { db } from '../db';
import { logger } from '../utils/logger';
import type { ObliReachWebView2Status } from '@obliance/shared';
import { getIO } from '../socket';
import { chatOfDevice, chatEndedByUser, chatRelayAllowed, chatUnavailable, chatIsEnded } from './oblireachChat.socket';
import { takeOrQueue, toWire } from './oblireachQueue';
import {
  buildObliReachUpdateCommand, claimAutoUpdate, pruneOrUpdateGate, releaseAutoUpdate,
  sanitizeObliReachSelfUpdate, type ObliReachSelfUpdate,
} from './oblireachUpdateGate';
import { getShippedObliReachVersion } from './oblireachAutoInstall.service';
import {
  buildWebView2InstallCommand, decideOnDemandInstall, decideProactiveInstall, forgetWebView2FirstSeen,
  getWebView2Mode, pruneWebView2Gate, releaseWebView2Auto, sanitizeChatUnavailable, sanitizeObliReachWebView2,
  webview2InstallOffer, webview2Key, webview2ModeCached,
} from './oblireachWebView2.service';

/**
 * Socket event: an ObliReach agent connected / reported another version,
 * self-update or WebView2 state / disconnected. The device page refetches its
 * ObliReach version and status (no reload needed after an update). Payload:
 * { deviceUuid, version?, online }.
 *
 * Only to those who may see the device (ObliReach visibility rule): the
 * admins of its tenant, the master tenant's admins (god view) and the users
 * whose teams see it (`user:<id>`) — never the whole tenant room (a member
 * without the device used to learn its uuid, version and presence).
 */
export const OBLIREACH_AGENT_UPDATED = 'OBLIREACH_AGENT_UPDATED';
const MASTER_TENANT = 1;

/** Viewer rooms of a device, cached briefly (a burst of reconnects — a
 *  server restart — must not become a burst of permission queries; a team
 *  change reaches the event within this delay). In-flight lookups shared. */
const AGENT_VIEWERS_TTL_MS = 30_000;
const AGENT_VIEWERS_MAX = 20_000;
const agentViewers = new Map<string, { at: number; rooms: Promise<string[]> }>();

/** Tests only. */
export function __resetAgentViewersForTests(): void {
  agentViewers.clear();
}

function adminRooms(...tenantIds: number[]): string[] {
  const rooms = new Set<string>();
  for (const t of [...tenantIds, MASTER_TENANT]) {
    if (Number.isInteger(Number(t)) && Number(t) > 0) rooms.add(`tenant:${Number(t)}:admin`);
  }
  return [...rooms];
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function lookupAgentViewerRooms(tenantId: number, deviceUuid: string): Promise<string[]> {
  const dev = UUID_RE.test(String(deviceUuid))
    ? await db('devices').where({ uuid: deviceUuid }).first('id', 'tenant_id')
    : undefined;
  const rooms = adminRooms(tenantId, ...(dev ? [Number(dev.tenant_id)] : []));
  if (dev) {
    const { permissionService } = await import('./permission.service');
    for (const uid of await permissionService.getUsersWithDeviceAccess(Number(dev.id))) rooms.push(`user:${Number(uid)}`);
  }
  return rooms;
}

function agentViewerRooms(tenantId: number, deviceUuid: string): Promise<string[]> {
  const key = `${Number(tenantId)}:${deviceUuid}`;
  const now = Date.now();
  const hit = agentViewers.get(key);
  if (hit && now - hit.at < AGENT_VIEWERS_TTL_MS) return hit.rooms;
  if (agentViewers.size >= AGENT_VIEWERS_MAX) {
    for (const [k, v] of agentViewers) if (now - v.at >= AGENT_VIEWERS_TTL_MS) agentViewers.delete(k);
    if (agentViewers.size >= AGENT_VIEWERS_MAX) agentViewers.clear();
  }
  const rooms = lookupAgentViewerRooms(tenantId, deviceUuid);
  agentViewers.set(key, { at: now, rooms });
  rooms.catch(() => { if (agentViewers.get(key)?.rooms === rooms) agentViewers.delete(key); });
  return rooms;
}

function emitAgentUpdated(tenantId: number, payload: { deviceUuid: string; version?: string | null; online: boolean }): void {
  const emit = (rooms: string[]) => {
    try {
      // One emit to every room: a socket in several of them (an admin who is
      // also in a team) gets it once.
      getIO().to(rooms).emit(OBLIREACH_AGENT_UPDATED, payload);
    } catch { /* socket server not ready */ }
  };
  agentViewerRooms(tenantId, payload.deviceUuid).then(emit, (err) => {
    // Permission lookup failed: the admins only (never the whole tenant).
    logger.warn({ deviceUuid: payload.deviceUuid, err: (err as Error)?.message }, 'ObliReach: device viewers lookup failed — agent update sent to the admins only');
    emit(adminRooms(tenantId));
  });
}

// ── Version helpers ────────────────────────────────────────────────────────────

/** Version shipped by this server (agent/dist/oblireach-version.txt, 60 s cache — the same reader as the Obliance agent's target). */
function getLatestVersion(): string | null {
  return getShippedObliReachVersion();
}

function isOlderVersion(current: string, latest: string): boolean {
  const parse = (v: string) => v.replace(/^v/, '').split('.').map(Number);
  const [cm, cmi, cp] = parse(current);
  const [lm, lmi, lp] = parse(latest);
  if (cm !== lm) return cm < lm;
  if (cmi !== lmi) return cmi < lmi;
  return cp < lp;
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface ObliReachConn {
  ws: WebSocket;
  deviceUuid: string;
  tenantId: number;
  /** agent_api_keys.id the channel authenticated with (null: unknown/legacy caller). */
  apiKeyId: number | null;
  /** Liveness: set by a pong / any message, cleared at each ping (see the keepalive). */
  alive: boolean;
  /** Version of the last heartbeat on this channel (undefined: none yet). */
  reportedVersion?: string;
  /**
   * Self-update state of the last heartbeat (guarded builds; null: the build
   * does not report it / nothing to report; undefined: no heartbeat yet).
   */
  selfUpdate?: ObliReachSelfUpdate | null;
  /**
   * Microsoft Edge WebView2 runtime of the chat window, as the last heartbeat
   * reported it (Windows builds that report it; null: not reported;
   * undefined: no heartbeat yet).
   */
  webview2?: ObliReachWebView2Status | null;
  /** When this channel connected. */
  connectedAt: number;
}

/** A self-update result older than this is not logged again when a channel (re)connects. */
const SELF_UPDATE_RESULT_LOG_MAX_AGE_MS = 30 * 60_000;
/** Longest back-off of ObliReach's guard (60 min) with margin: a later "next attempt" is a clock skew. */
const SELF_UPDATE_MAX_AGENT_WAIT_MS = 2 * 60 * 60_000;

/** Result of pushDetailed. */
export type OrPushResult = 'sent' | 'offline' | 'mismatch';

/** Binding a sensitive command's recipient must match (see push). */
export interface OrPushExpectation {
  /** Tenant of the target device. */
  tenantId: number;
  /** devices.api_key_id of the target device (null = device not bound to a key). */
  apiKeyId: number | null;
}

/** A command delivered from server → Oblireach agent over the WS channel. */
export interface OrCommand {
  /** 'open_remote_tunnel' | 'close_remote_tunnel' | 'update' */
  type: string;
  id: string;
  payload: Record<string, unknown>;
}

// ── Service ───────────────────────────────────────────────────────────────────

class ObliReachHubService {
  /** deviceUuid → active WS connection */
  private byDevice = new Map<string, ObliReachConn>();

  constructor() {
    // Server-side keepalive: ping every 15 s so idle connections survive
    // reverse-proxy idle timeouts (Nginx default 60 s, NPM ~20 s).
    // Liveness: a channel that answered neither the previous ping nor sent
    // anything since is dead (NAT / proxy / sleep dropped it silently while
    // the socket still looks OPEN here) — terminate it, so push() returns
    // false and the command goes to the offline queue instead of a black hole.
    setInterval(() => this.sweep(), 15_000);
  }

  /** One keepalive round (exported for tests through the instance). */
  sweep(): void {
    pruneOrUpdateGate();
    pruneWebView2Gate();
    for (const [uuid, conn] of this.byDevice) {
      if (conn.ws.readyState !== 1 /* OPEN */) {
        this._unregister(uuid, conn.ws);
        continue;
      }
      if (!conn.alive) {
        logger.warn({ deviceUuid: uuid }, 'ObliReach command channel: no pong since the last ping — terminated');
        try { (conn.ws as any).terminate(); } catch { /* already gone */ }
        this._unregister(uuid, conn.ws);
        continue;
      }
      conn.alive = false;
      try { (conn.ws as any).ping(); } catch { this._unregister(uuid, conn.ws); }
    }
  }

  /**
   * Register a new persistent WS connection for a Oblireach agent.
   * Replaces any previous connection for the same deviceUuid.
   * Drains any pending offline-queued command immediately.
   */
  async register(deviceUuid: string, tenantId: number, ws: WebSocket, apiKeyId: number | null = null): Promise<void> {
    // Replace stale connection if present
    const existing = this.byDevice.get(deviceUuid);
    if (existing?.ws.readyState === 1 /* OPEN */) {
      try { existing.ws.close(1000, 'replaced'); } catch {}
    }

    const conn: ObliReachConn = { ws, deviceUuid, tenantId, apiKeyId, alive: true, connectedAt: Date.now() };
    // WebView2 install mode known before this agent can report a chat that
    // could not open (_handleChatUnavailable decides synchronously).
    void getWebView2Mode();
    this.byDevice.set(deviceUuid, conn);

    ws.on('close', () => this._unregister(deviceUuid, ws));
    ws.on('error', () => this._unregister(deviceUuid, ws));
    ws.on('pong', () => { conn.alive = true; });
    ws.on('message', async (data: Buffer) => {
      conn.alive = true;
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'heartbeat') {
          await this._handleHeartbeat(conn, msg);
        } else if (msg.type === 'tunnel_failed') {
          await this._handleTunnelFailed(conn, msg);
        } else if (msg.type === 'chat_message' && msg.chatId) {
          // Only a chat of THIS device (and tenant): another agent can never
          // write into — or end — someone else's conversation.
          const chat = chatOfDevice(msg.chatId, conn.deviceUuid, conn.tenantId);
          if (!chat) return;
          const chatSender = String(msg.payload?.from || 'User').slice(0, 200);
          const chatText = typeof msg.payload?.text === 'string' ? msg.payload.text : '';
          // Relayed only while the chat's owner still has the right to it
          // (chatRelayAllowed: otherwise his sockets leave the room and get
          // chat:ended 'forbidden'). Stored either way: nothing changes on
          // the end user's side.
          if (await chatRelayAllowed(msg.chatId)) {
            try {
              getIO().to(`chat:${msg.chatId}`).emit('chat:message', {
                chatId: msg.chatId,
                sender: chatSender,
                message: chatText,
                timestamp: msg.payload?.timestamp || Date.now(),
                fromOperator: false,
              });
            } catch {}
          }
          // Persist to DB — under the device's tenant, like the operator's
          // messages (oblireachChat.socket.ts), so a resumed chat shows the
          // whole exchange.
          try {
            await db('chat_messages').insert({
              chat_id: msg.chatId,
              tenant_id: chat.tenantId,
              device_id: chat.deviceId,
              sender: chatSender,
              message: chatText,
              is_operator: false,
            });
          } catch {}
        } else if (msg.type === 'chat_event' && msg.chatId) {
          if (!chatOfDevice(msg.chatId, conn.deviceUuid, conn.tenantId)) return;
          // User event (closed, typing, allow_remote, deny_remote), or the
          // chat window could not open (chat_unavailable).
          const action = msg.payload?.action;
          if (action === 'chat_unavailable') {
            // Handled synchronously (no await before chatUnavailable): the
            // agent's user_closed that follows (for older servers) then finds
            // the chat ended and is ignored.
            this._handleChatUnavailable(conn, msg.chatId, msg.payload);
            return;
          }
          if (action !== 'user_closed' && action !== 'typing' && action !== 'allow_remote' && action !== 'deny_remote') return;
          // An ended chat (e.g. 'unavailable'): the agent's fallback
          // user_closed must not turn it into "closed by the user".
          if (action === 'user_closed' && chatIsEnded(msg.chatId)) return;
          // Same gate as the replies (chatRelayAllowed).
          const relay = await chatRelayAllowed(msg.chatId);
          if (action === 'user_closed') {
            // The end user closed the window: the chat is over (never resumed),
            // whoever is still allowed to hear about it. chat:closed stays for
            // older clients; chat:ended tells everyone left in the room.
            if (relay) {
              try { getIO().to(`chat:${msg.chatId}`).emit('chat:closed', { chatId: msg.chatId }); } catch {}
            }
            chatEndedByUser(msg.chatId);
          } else if (!relay) {
            return;
          } else if (action === 'typing') {
            try { getIO().to(`chat:${msg.chatId}`).emit('chat:typing', { chatId: msg.chatId }); } catch {}
          } else {
            try {
              getIO().to(`chat:${msg.chatId}`).emit('chat:remote_response', {
                chatId: msg.chatId,
                allowed: !!msg.payload?.allowed,
              });
            } catch {}
          }
        }
      } catch { /* malformed JSON — discard */ }
    });

    // Drain any command that was queued while the agent was offline.
    // This ensures urgent commands (e.g. open_remote_tunnel) are delivered
    // the instant the agent reconnects rather than waiting for the next push.
    try {
      await this._drainPendingCommand(conn);
    } catch (err) {
      logger.error(err, 'oblireachHub: drain pending command failed');
    }

    logger.info({ deviceUuid }, 'ObliReach agent command channel connected');
  }

  private _unregister(deviceUuid: string, ws: WebSocket): void {
    const existing = this.byDevice.get(deviceUuid);
    if (existing?.ws === ws) {
      this.byDevice.delete(deviceUuid);
      logger.info({ deviceUuid }, 'ObliReach agent command channel disconnected');
      emitAgentUpdated(existing.tenantId, { deviceUuid, online: false });
    }
  }

  /**
   * Deliver the commands queued in `pending_command` while the agent was
   * offline (a JSON array, see oblireachQueue), clearing the field first.
   * Expired entries and tunnels of sessions no longer waiting are skipped.
   * (pending_command is jsonb: pg returns it parsed — the old JSON.parse of
   * that object threw, so a queued command was never delivered on reconnect.)
   */
  private async _drainPendingCommand(conn: ObliReachConn): Promise<void> {
    const cmds = await takeOrQueue(conn.deviceUuid, conn.tenantId);
    for (const cmd of cmds) {
      if (conn.ws.readyState !== 1 /* OPEN */) {
        logger.warn({ deviceUuid: conn.deviceUuid, cmdType: cmd.type }, 'ObliReach: channel closed while draining — command dropped');
        continue;
      }
      try {
        conn.ws.send(JSON.stringify(toWire(cmd)));
        logger.info(
          { deviceUuid: conn.deviceUuid, cmdType: cmd.type },
          'ObliReach: pending command delivered on reconnect',
        );
      } catch (err) {
        logger.error(err, 'ObliReach: failed to deliver drained command');
      }
    }
  }

  /**
   * `{"type":"tunnel_failed","sessionToken","code","message"}`: the agent
   * could not open (or keep) a session before any relay connection existed.
   * Only honoured for a session of THIS channel's device (uuid + tenant + key
   * binding) — see remoteService.failSessionFromAgent.
   */
  private async _handleTunnelFailed(conn: ObliReachConn, msg: any): Promise<void> {
    const token = typeof msg?.sessionToken === 'string' ? msg.sessionToken : '';
    if (!/^[0-9a-f]{64}$/.test(token)) return;
    try {
      // Lazy import: remote.service imports this module.
      const { remoteService } = await import('./remote.service');
      await remoteService.failSessionFromAgent(token, String(msg.code ?? ''), String(msg.message ?? ''), {
        deviceUuid: conn.deviceUuid, tenantId: conn.tenantId, apiKeyId: conn.apiKeyId,
      });
    } catch (err) {
      logger.error(err, 'ObliReach: tunnel_failed handling failed');
    }
  }

  /**
   * Handle a heartbeat message from the agent.
   * Updates the DB record (hostname, version, sessions, last_seen_at).
   * Also injects an auto-update command if the agent is outdated.
   */
  private async _handleHeartbeat(conn: ObliReachConn, msg: any): Promise<void> {
    const { hostname, os, arch, version, sessions } = msg;
    // SECURITY: a channel reports for ITS device only (the uuid it registered
    // with, whose API-key binding was checked at the upgrade —
    // oblireachHub.upgrade.ts). A heartbeat naming another uuid would let one
    // agent rewrite another device's row of its tenant (sessions shown to
    // operators, last_seen_at keeping a dead agent "online"): dropped.
    if (!msg.deviceUuid || msg.deviceUuid !== conn.deviceUuid) {
      if (msg.deviceUuid) logger.warn({ channelUuid: conn.deviceUuid, claimedUuid: String(msg.deviceUuid).slice(0, 64) }, 'ObliReach heartbeat for another device ignored');
      return;
    }
    const deviceUuid = conn.deviceUuid;

    // Feature flag check
    const flag = await db('app_config')
      .where({ key: 'integrated_oblireach_enabled' }).first();
    if (flag?.value === 'false') return;

    // The Windows sessions: a list of objects, else none (the clients draw them).
    const sessionsJson = Array.isArray(sessions)
      ? JSON.stringify(sessions.filter((s: unknown) => s !== null && typeof s === 'object' && !Array.isArray(s)))
      : null;

    const existing = await db('oblireach_devices')
      .where({ device_uuid: deviceUuid, tenant_id: conn.tenantId })
      .first();

    if (existing) {
      await db('oblireach_devices')
        .where({ id: existing.id })
        .update({ hostname, os, arch, version, sessions: sessionsJson, last_seen_at: new Date() });
    } else {
      await db('oblireach_devices').insert({
        tenant_id: conn.tenantId, device_uuid: deviceUuid,
        hostname, os, arch, version, sessions: sessionsJson, last_seen_at: new Date(),
      });
    }

    // Its own self-update (guarded builds): changes are logged here — the
    // agent's local log is otherwise the only trace of a failed update — and
    // the device page shows the state (GET /api/oblireach/devices/:uuid).
    const su = sanitizeObliReachSelfUpdate(msg.selfUpdate);
    const suChanged = this._noteSelfUpdate(conn, typeof version === 'string' ? version : '', su);
    // WebView2 runtime of the chat window (Windows builds that report it).
    const wv2 = sanitizeObliReachWebView2(msg.webview2);
    const wv2Changed = this._noteWebView2(conn, wv2);

    // First heartbeat on this channel, or another version (an update just
    // restarted the agent), or another self-update / WebView2 state: the
    // device page refreshes its ObliReach version / status.
    const reported = typeof version === 'string' ? version : '';
    if (conn.reportedVersion !== reported || suChanged || wv2Changed) {
      conn.reportedVersion = reported;
      emitAgentUpdated(conn.tenantId, { deviceUuid, version: reported || null, online: true });
    }

    // WebView2 'proactive' mode: install the missing runtime once the
    // device's spread slot (0-60 min after connecting) has come.
    if (wv2) {
      try {
        await this._maybeProactiveWebView2(conn, wv2);
      } catch (err) {
        logger.warn({ deviceUuid, err: (err as Error)?.message }, 'ObliReach WebView2: proactive install check failed');
      }
    }

    // Auto-update: send `update` when the agent is outdated — at most once per
    // device and target version every 10 min, and not while the Obliance
    // agent is installing ObliReach / waiting for a running installer or an
    // install_oblireach is on its way (oblireachUpdateGate). It used to go
    // out on EVERY heartbeat (30 s): overlapping msiexec runs.
    if (version) {
      const latest = getLatestVersion();
      // Its own attempt is running, or its guard waits after a failure: no
      // `update` now (it would only be skipped) — the first heartbeat after
      // its back-off gets one, instead of the next 10-min window. (A wait
      // beyond its longest back-off = a wrong agent clock: ignored.)
      const waitMs = su?.nextAttemptAt ? Date.parse(su.nextAttemptAt) - Date.now() : NaN;
      const agentWaits = !!su?.inProgress || (Number.isFinite(waitMs) && waitMs > 0 && waitMs < SELF_UPDATE_MAX_AGENT_WAIT_MS);
      if (latest && isOlderVersion(version, latest) && !agentWaits) {
        const claim = await claimAutoUpdate(deviceUuid, conn.tenantId, latest);
        if (!claim.send) {
          if (claim.reason !== 'throttled') {
            logger.info({ deviceUuid, version, latest, reason: claim.reason }, 'ObliReach: auto-update not sent — an update / install is already in progress');
          }
          return;
        }
        const updateCmd: OrCommand = await buildObliReachUpdateCommand('auto_update_ws', os, arch, latest);
        try {
          conn.ws.send(JSON.stringify(updateCmd));
          logger.info({ deviceUuid, version, latest }, 'ObliReach: auto-update pushed via WS (next one not before 10 min)');
        } catch (err) {
          // Channel closed between the heartbeat and the send: nothing went
          // out — free the 10-min window so the next heartbeat tries again.
          releaseAutoUpdate(deviceUuid, conn.tenantId, latest);
          logger.warn({ deviceUuid, version, latest, err: (err as Error)?.message }, 'ObliReach: auto-update NOT sent (channel closed) — retried at the next heartbeat');
        }
      }
    }
  }

  /**
   * Store the self-update block of a heartbeat and log what changed: an
   * attempt that starts, a new result (a failure as a warning, with the
   * agent's reason and the next automatic attempt). Returns true when the
   * state shown to users changed.
   */
  private _noteSelfUpdate(conn: ObliReachConn, version: string, su: ObliReachSelfUpdate | null): boolean {
    const prev = conn.selfUpdate;
    conn.selfUpdate = su;
    const deviceUuid = conn.deviceUuid;
    if (su) {
      if (su.inProgress && !prev?.inProgress) {
        logger.info({ deviceUuid, version, target: su.target, since: su.since }, 'ObliReach self-update in progress');
      }
      const newResult = su.lastResultAt && su.lastResultAt !== prev?.lastResultAt
        // (re)connected channel: only a recent result is worth a line
        && (prev !== undefined || Date.now() - Date.parse(su.lastResultAt) < SELF_UPDATE_RESULT_LOG_MAX_AGE_MS);
      if (newResult) {
        const fields = {
          deviceUuid, version, outcome: su.lastOutcome, result: su.lastResult, error: su.lastError,
          failures: su.failures, nextAttemptAt: su.nextAttemptAt, at: su.lastResultAt,
        };
        if (su.lastOutcome === 'installed') logger.info(fields, 'ObliReach self-update result: installed');
        else logger.warn(fields, 'ObliReach self-update did not complete');
      }
    }
    const key = (s: ObliReachSelfUpdate | null | undefined) => (s
      ? `${s.inProgress}|${s.target}|${s.lastResultAt}|${s.lastOutcome}|${s.nextAttemptAt}`
      : '');
    return prev !== undefined && key(prev) !== key(su);
  }

  /** Self-update state reported by this device's connected ObliReach (null: offline / not reported). */
  selfUpdateOf(deviceUuid: string): ObliReachSelfUpdate | null {
    return this.byDevice.get(deviceUuid)?.selfUpdate ?? null;
  }

  // ── WebView2 runtime of the chat window ──────────────────────────────────

  /** Store a heartbeat's `webview2` block, log what changed; true when the state shown to users changed. */
  private _noteWebView2(conn: ObliReachConn, wv2: ObliReachWebView2Status | null): boolean {
    const prev = conn.webview2;
    conn.webview2 = wv2;
    if (webview2Key(prev) === webview2Key(wv2)) return false;
    if (wv2) {
      const fields = {
        deviceUuid: conn.deviceUuid, state: wv2.state, version: wv2.version, scope: wv2.scope, reason: wv2.reason,
        installer: wv2.installer, attempts: wv2.attempts, lastError: wv2.lastError, nextAttemptAt: wv2.nextAttemptAt,
      };
      if (wv2.state === 'failed' || wv2.state === 'blocked') logger.warn(fields, 'ObliReach WebView2 runtime not installed');
      else if (wv2.state !== 'ok' || (prev && prev.state !== 'ok')) logger.info(fields, `ObliReach WebView2 runtime: ${wv2.state}`);
    }
    return prev !== undefined;
  }

  /** WebView2 state reported by this device's connected ObliReach (null: offline / not reported by this build). */
  webview2Of(deviceUuid: string): ObliReachWebView2Status | null {
    return this.byDevice.get(deviceUuid)?.webview2 ?? null;
  }

  private async _maybeProactiveWebView2(conn: ObliReachConn, wv2: ObliReachWebView2Status): Promise<void> {
    if (wv2.state === 'ok') { forgetWebView2FirstSeen(conn.deviceUuid, conn.tenantId); return; }
    if (wv2.state !== 'missing' && wv2.state !== 'failed') return; // nothing to install: no DB read
    const mode = await getWebView2Mode();
    if (!decideProactiveInstall({ mode, status: wv2, deviceUuid: conn.deviceUuid, tenantId: conn.tenantId })) return;
    const cmd = buildWebView2InstallCommand('auto_webview2', false);
    try {
      conn.ws.send(JSON.stringify(cmd));
      logger.info({ deviceUuid: conn.deviceUuid, state: wv2.state, attempts: wv2.attempts }, 'ObliReach WebView2: install sent (proactive mode)');
    } catch (err) {
      releaseWebView2Auto(conn.deviceUuid, conn.tenantId);
      logger.warn({ deviceUuid: conn.deviceUuid, err: (err as Error)?.message }, 'ObliReach WebView2: install NOT sent (channel closed)');
    }
  }

  /**
   * `chat_event` chat_unavailable: the chat window could not open on the
   * machine. The conversation ends at once with the exact reason (never
   * "closed by the user"); when the runtime is missing and the platform
   * allows it, its install is started now (on-demand — also in proactive mode,
   * without waiting for the device's slot) and the operator is told so.
   * Synchronous on purpose (see the caller).
   */
  private _handleChatUnavailable(conn: ObliReachConn, chatId: string, payload: unknown): void {
    if (chatIsEnded(chatId)) return;
    const info = sanitizeChatUnavailable(payload);
    const status = conn.webview2 ?? null;
    const mode = webview2ModeCached();
    if (!info.installing && decideOnDemandInstall({
      mode, status, code: info.code, deviceUuid: conn.deviceUuid, tenantId: conn.tenantId,
    })) {
      try {
        conn.ws.send(JSON.stringify(buildWebView2InstallCommand('ondemand_webview2', false)));
        info.installing = true;
        logger.info({ deviceUuid: conn.deviceUuid, chatId }, 'ObliReach WebView2: install sent (a chat could not open)');
      } catch {
        releaseWebView2Auto(conn.deviceUuid, conn.tenantId);
      }
    }
    if (!info.state && status) info.state = status.state;
    if (!info.detail && status?.lastError && (info.state === 'failed' || info.state === 'unknown')) info.detail = status.lastError;
    if (info.code === 'webview2_missing') {
      // Translatable reason (network, per_user_only…) and what the device
      // page offers: never "install it from the device page" when the
      // setting is disabled or this ObliReach build cannot install it.
      info.wv2Reason = status?.reason ?? null;
      info.installOffer = info.installing ? null : webview2InstallOffer(mode, status);
    }
    logger.info({ deviceUuid: conn.deviceUuid, chatId, code: info.code, installing: info.installing, state: info.state }, 'Chat could not open on the machine');
    chatUnavailable(chatId, info);
  }

  /**
   * Ask this device's ObliReach to install the WebView2 runtime (device
   * page's button: force — its back-off does not apply, one attempt at a
   * time and a 1-min floor still do). 'offline' when no live channel of the
   * device's tenant.
   */
  requestWebView2Install(deviceUuid: string, tenantId: number): 'sent' | 'offline' | 'mismatch' {
    return this.pushDetailed(deviceUuid, buildWebView2InstallCommand('manual_webview2', true), { tenantId, apiKeyId: null });
  }

  /**
   * Push a command directly to a connected agent.
   *
   * Returns `true` if the message was delivered, `false` if the agent is
   * offline — caller should fall back to DB `pending_command` so the command
   * is delivered when the agent next connects.
   *
   * `expect` (pass it for anything carrying a secret, e.g. the relay token):
   * the channel registered for this uuid must belong to the device's tenant
   * and, when the device is bound to a key, have authenticated with that key.
   * Otherwise the command is NOT sent (treated as offline) — a channel
   * registered under a uuid by some other agent never receives it.
   */
  push(deviceUuid: string, cmd: OrCommand, expect?: OrPushExpectation): boolean {
    return this.pushDetailed(deviceUuid, cmd, expect) === 'sent';
  }

  /**
   * Same as push, telling apart an offline agent ('offline': queue it) from
   * a live channel that does not match the device's key binding ('mismatch':
   * never queue it — see remoteService.createSession, which answers 409).
   */
  pushDetailed(deviceUuid: string, cmd: OrCommand, expect?: OrPushExpectation): OrPushResult {
    const conn = this.byDevice.get(deviceUuid);
    if (!conn || conn.ws.readyState !== 1 /* OPEN */) return 'offline';
    if (expect) {
      const tenantOk = Number(conn.tenantId) === Number(expect.tenantId);
      const keyOk = expect.apiKeyId == null || (conn.apiKeyId != null && Number(conn.apiKeyId) === Number(expect.apiKeyId));
      if (!tenantOk || !keyOk) {
        logger.warn({ deviceUuid, cmdType: cmd.type }, 'ObliReach: channel does not match the device key binding — command not sent');
        return 'mismatch';
      }
    }
    try {
      conn.ws.send(JSON.stringify(cmd));
      return 'sent';
    } catch {
      this._unregister(deviceUuid, conn.ws);
      return 'offline';
    }
  }

  /**
   * Returns true when the agent currently has an open WS command channel.
   * More accurate than the `last_seen_at` heuristic for real-time status.
   */
  isConnected(deviceUuid: string): boolean {
    const conn = this.byDevice.get(deviceUuid);
    return !!conn && conn.ws.readyState === 1;
  }

  connectedCount(): number {
    return this.byDevice.size;
  }

  /**
   * Broadcast a command to ALL connected agents.
   * Used for chat messages where we don't track device→chatId mapping server-side.
   * The agent ignores commands for chatIDs it doesn't own.
   */
  broadcastCommand(cmd: OrCommand): void {
    const json = JSON.stringify(cmd);
    for (const [, conn] of this.byDevice) {
      if (conn.ws.readyState === 1) {
        try { conn.ws.send(json); } catch {}
      }
    }
  }

  /** Broadcast a command only to agents belonging to the specified tenant. */
  broadcastCommandToTenant(tenantId: number, cmd: OrCommand): void {
    const json = JSON.stringify(cmd);
    for (const [, conn] of this.byDevice) {
      if (conn.tenantId === tenantId && conn.ws.readyState === 1) {
        try { conn.ws.send(json); } catch {}
      }
    }
  }
}

export const oblireachHub = new ObliReachHubService();
