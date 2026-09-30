import crypto from 'crypto';
import type { IncomingMessage } from 'http';
import { db } from '../db';
import { commandService } from './command.service';
import { agentHub } from './agentHub.service';
import { oblireachHub } from './oblireachHub.service';
import { privacyGateService } from './privacyGate.service';
import { permissionService } from './permission.service';
import {
  decideReachFilesPolicy,
  gateAgentFrame,
  gateBrowserFrame,
  type DeniedFileAttempt,
  type ReachFilesPolicy,
} from './reachFilesGate';
import type { OrCommand } from './oblireachHub.service';
import { getIO } from '../socket';
import { SocketEvents, isMasterTenant } from '@obliance/shared';
import type { RemoteSession, RemoteProtocol, RemoteDelivery } from '@obliance/shared';
import { logger } from '../utils/logger';
import { sessionHash } from '../utils/sessionHash';
import { AppError } from '../middleware/errorHandler';
import {
  emitRemoteSessionEvent,
  evaluateAgentTunnelAccess,
  evaluateBrowserTunnelAccess,
  agentKeyMayActForDevice,
  loadUpgradeSession,
  toPublicRemoteSession,
  type AgentTunnelVerdict,
  type PublicRemoteSession,
  type RemoteSessionEvent,
  type TunnelAccessVerdict,
} from './remoteSessionSecurity';

interface TunnelEntry {
  browser?: any;
  agent?: any;
  /** sha256 of the express-session id that attached the browser end (the
   *  upgrade cookie): a revocation deleting that session closes the relay. */
  browserSessionHash?: string;
  /** The browser end is a real WebSocket (index.ts upgrade), not an
   *  in-process bastion adapter: only those get the relay's JSON notices
   *  ({"type":"waiting"}, {"type":"error",…}) — an adapter treats its first
   *  send() as "paired". */
  browserIsWs?: boolean;
  /** The browser left before its agent paired: ends the session unless it comes back. */
  browserGoneTimer?: NodeJS.Timeout;
  /** Keepalive of a real browser WebSocket waiting for its agent (see registerBrowserTunnel). */
  browserPreKeepAlive?: NodeJS.Timeout;
  /** Client IP of the browser end (audit of file transfers). */
  browserIp?: string;
  /** Messages received from agent before browser connected — flushed on bridge. */
  agentBuffer: Array<{ data: Buffer; isBinary: boolean }>;
  /** Bytes of BINARY frames held in agentBuffer (capped, see AGENT_BUFFER_MAX_BYTES). */
  agentBufferBytes?: number;
  /** ObliReach file transfers seen passing through this relay, by tid (audit). */
  transfers?: Map<number, RelayTransfer>;
  /** remote.file_denied entries written for this relay (bounded, see FILE_DENIED_AUDIT_MAX). */
  filesDeniedAudits?: number;
  /** ObliReach file-transfer decision of this relay, pinned when its agent end
   *  registers (the authorization resolved it in the same tick, see
   *  authorizeAgentTunnel): the relay's gates read it from here, so no later
   *  eviction from `filesPolicies` can ever open them. */
  filesPolicy?: ReachFilesPolicy;
}

/** Refused transfer requests audited per relay (a viewer retrying in a loop
 *  never floods the audit log). */
const FILE_DENIED_AUDIT_MAX = 20;
/** Soft bound on the per-session file-transfer decisions kept in memory: above
 *  it, only STALE decisions (older than FILES_POLICY_STALE_MS, relay not
 *  attached) are dropped — never one a waiting or live session may still need. */
const FILES_POLICY_MAX = 10_000;
/** A decision older than this whose relay is not attached is stale: its session
 *  waited at most ~6 min for its agent (queued open command), and an attached
 *  relay carries its own copy (TunnelEntry.filesPolicy). */
const FILES_POLICY_STALE_MS = 15 * 60_000;

/**
 * A file transfer relayed between viewer and ObliReach agent (contract §1.6),
 * reconstructed from the control messages that pass through — the relay
 * only READS them (bytes are forwarded unchanged) to audit who sent or
 * fetched which file: remote.file_upload / remote.file_download.
 */
interface RelayTransfer {
  dir: 'up' | 'down';
  name?: string;
  /** Size announced (file_begin / file_offer). */
  size?: number;
  /** Payload bytes actually relayed (0x20 / 0x21 frames). */
  bytes: number;
  sha256?: string;
  /** Upload destination asked for (file_begin.dest) and final path (file_accept / file_done). */
  dest?: string;
  path?: string;
  /** Download source (file_get). */
  source?: string;
  idx?: number;
  startedAt: number;
}

/** Transfers tracked per relay (a flood of file_begin never grows memory). */
const RELAY_TRANSFERS_MAX = 64;
/** Control messages above this size are never parsed by the audit peek. */
const RELAY_PEEK_MAX_BYTES = 16 * 1024;
const FILE_TYPE_MARK = Buffer.from('"file_');

/** Browser keepalive ping period (proxies cut idle sockets after ~20–60 s). */
const BROWSER_KEEPALIVE_MS = 15_000;

/** Bound on the "started from which express session" memo. */
const CREATOR_MEMO_MAX = 10_000;

/** A browser that leaves before its agent paired may come back this long. */
const BROWSER_RETURN_GRACE_MS = 15_000;

/** Binary agent frames buffered while no browser is attached (video): oldest dropped beyond this. */
const AGENT_BUFFER_MAX_BYTES = 16 * 1024 * 1024;

/** Relay → browser notice sent before the relay closes the browser end. */
export interface RelayErrorNotice {
  type: 'error';
  code: 'agent_timeout' | 'agent_offline' | 'agent_error' | 'session_closed';
  message: string;
  /** false for a terminal failure; true for a transient agent error the viewer
   *  should auto-retry (helper_spawn_failed, helper_timeout, capture_init_failed,
   *  session_switch_timeout — see RETRYABLE_AGENT_CODES). */
  retry: boolean;
  /** agent_error from a tunnel_failed: the agent's own code (helper_spawn_failed…). */
  agentCode?: string;
}

/**
 * Transient ObliReach agent error codes: a fresh attempt can succeed, so the
 * viewer is told retry:true and auto-reconnects (a new session) instead of
 * stopping. These happen during the console re-attach race (the helper spawns
 * into a session that is being torn down) and during a session follow that
 * could not settle. Every other agent code stays terminal (retry:false).
 * session_switch_timeout: after a follow that could not bring the capture back
 * within 30 s, the agent first sends session_state live (reason switch_failed)
 * so the viewers' "session change pending" guard lets this retry reconnect;
 * after the 10-minute wait for a disconnected session the viewers keep their
 * pending state and offer a manual retry / another session instead.
 */
const RETRYABLE_AGENT_CODES: ReadonlySet<string> = new Set([
  'helper_spawn_failed', 'helper_timeout', 'capture_init_failed', 'session_switch_timeout',
]);

/** Keep [a-z0-9_] codes only (agent-supplied values end up in end_reason / the UI). */
function safeCode(raw: unknown): string {
  const c = String(raw ?? '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 40);
  return c || 'internal';
}

/** One-line printable text, bounded (agent-supplied error text). */
function safeText(raw: unknown, max: number): string {
  return String(raw ?? '')
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

const OPEN_STATUSES = ['waiting', 'connecting', 'active'];

class RemoteService {
  // WebSocket relay store: sessionToken → TunnelEntry
  private tunnels = new Map<string, TunnelEntry>();
  /** remote session id → sha256 of the express-session id that STARTED it
   *  (POST /api/remote/sessions). In memory, bounded: lets a device-key
   *  revocation also end a session whose relay is not attached here (e.g.
   *  the standalone ObliReach relay), see closeSessionsForSessionHashes. */
  private creatorSessions = new Map<string, string>();
  /** ObliReach session token → may its operator transfer files (reachFilesGate.ts).
   *  Decided at createSession; recomputed from the DB when a tunnel end
   *  attaches and it is missing (server restarted meanwhile); pinned on the
   *  relay when its agent end registers (TunnelEntry.filesPolicy). In memory,
   *  dropped with the relay; above FILES_POLICY_MAX only stale entries go. */
  private filesPolicies = new Map<string, { policy: ReachFilesPolicy; at: number }>();
  private filesPolicyOverflowLogged = false;

  private rememberFilesPolicy(sessionToken: string, policy: ReachFilesPolicy, now = Date.now()): void {
    this.filesPolicies.delete(sessionToken);
    if (this.filesPolicies.size >= FILES_POLICY_MAX) {
      // Oldest first (insertion order); never a decision a session may still
      // need: a recent one (its session may still be waiting for its agent)
      // or one whose relay is attached.
      for (const [token, entry] of this.filesPolicies) {
        if (this.filesPolicies.size < FILES_POLICY_MAX) break;
        if (now - entry.at < FILES_POLICY_STALE_MS) break; // the rest is newer
        if (this.tunnels.get(token)?.agent) continue;
        this.filesPolicies.delete(token);
      }
      if (this.filesPolicies.size >= FILES_POLICY_MAX && !this.filesPolicyOverflowLogged) {
        this.filesPolicyOverflowLogged = true;
        logger.warn({ size: this.filesPolicies.size }, 'ObliReach: many open sessions — file-transfer decisions kept above the soft bound');
      }
    }
    this.filesPolicies.set(sessionToken, { policy, at: now });
  }

  /** The file-transfer decision of an ObliReach session (undefined: not one):
   *  the relay's pinned copy first. */
  filesPolicyOf(sessionToken: string): ReachFilesPolicy | undefined {
    return this.tunnels.get(sessionToken)?.filesPolicy ?? this.filesPolicies.get(sessionToken)?.policy;
  }

  /**
   * May `userId` transfer files through Reach on this device: capability
   * 'files' (admins, from the LIVE role, hold it), no tenant restriction on
   * the file explorer's transfers (`command.upload_file` /
   * `command.download_file`: the device's tenant, plus the master's when the
   * session is on it — explorerRestrictionLevel, the explorer's own rule) and,
   * with privacy mode on, the privacy unlock of 'files'. Never throws: an
   * error refuses (fail closed). See reachFilesGate.ts.
   */
  async resolveFilesPolicy(userId: number, deviceId: number, sessionTenantId?: number | null): Promise<ReachFilesPolicy> {
    try {
      const user = await db('users').where({ id: userId }).first('role');
      const isAdmin = user?.role === 'admin';
      const hasFilesCapability = await permissionService.canUseCapability(userId, deviceId, isAdmin, 'files');
      const dev = await db('devices').where({ id: deviceId }).first('privacy_mode_enabled', 'tenant_id');
      if (!dev) return { allowed: false, reason: 'capability' };
      let restricted = false;
      if (hasFilesCapability) {
        const { explorerRestrictionLevel } = await import('./fileExplorerGate.service');
        for (const type of ['upload_file', 'download_file']) {
          if (await explorerRestrictionLevel(type, deviceId, Number(dev.tenant_id), sessionTenantId ?? null) !== 'none') {
            restricted = true;
            break;
          }
        }
      }
      const privacyEnabled = !!dev.privacy_mode_enabled;
      const hasFilesUnlock = privacyEnabled && !!privacyGateService.get(userId, deviceId, 'files');
      return decideReachFilesPolicy({ hasFilesCapability, restricted, privacyEnabled, hasFilesUnlock });
    } catch (err) {
      logger.warn({ err, deviceId }, 'ObliReach: file-transfer permission check failed — transfers refused');
      return { allowed: false, reason: 'capability' };
    }
  }

  /** A tunnel end of an ObliReach session attaches: make sure its file-transfer
   *  decision is known before any frame flows (see filesPolicies). */
  private async ensureFilesPolicy(
    sessionToken: string,
    row: { protocol?: string; status?: string; started_by?: number | null; device_id?: number | null; tenant_id?: number | null } | null | undefined,
  ): Promise<void> {
    if (!row || row.protocol !== 'oblireach' || this.filesPolicies.has(sessionToken)) return;
    if (!row.status || !OPEN_STATUSES.includes(row.status)) return; // refused anyway
    const userId = Number(row.started_by);
    const deviceId = Number(row.device_id);
    const policy = Number.isInteger(userId) && userId > 0 && Number.isInteger(deviceId) && deviceId > 0
      ? await this.resolveFilesPolicy(userId, deviceId, row.tenant_id ?? null)
      : { allowed: false, reason: 'capability' as const };
    if (!this.filesPolicies.has(sessionToken)) this.rememberFilesPolicy(sessionToken, policy);
  }

  /** Records the express session that started a remote session. */
  noteCreatorSession(remoteSessionId: string, sessionHash: string): void {
    if (!remoteSessionId || !sessionHash) return;
    this.creatorSessions.delete(remoteSessionId);
    while (this.creatorSessions.size >= CREATOR_MEMO_MAX) {
      const oldest = this.creatorSessions.keys().next();
      if (oldest.done) break;
      this.creatorSessions.delete(oldest.value);
    }
    this.creatorSessions.set(remoteSessionId, sessionHash);
  }

  rowToSession(row: any): RemoteSession {
    return {
      id: row.id, deviceId: row.device_id, tenantId: row.tenant_id,
      protocol: row.protocol, status: row.status,
      sessionToken: row.session_token,
      startedBy: row.started_by,
      startedAt: row.started_at, connectedAt: row.connected_at,
      endedAt: row.ended_at, durationSeconds: row.duration_seconds,
      endReason: row.end_reason, notes: row.notes, createdAt: row.created_at,
    };
  }

  /**
   * THE single way to emit REMOTE_SESSION_UPDATED / REMOTE_TUNNEL_READY.
   * The full session (with sessionToken) goes to the starter's `user:<id>`
   * room only; the rest of the tenant gets a token-free copy. Never emit
   * these events with a raw row or to a tenant room directly — the token is
   * the relay key and must not reach other users.
   * Accepts a DB row (snake_case) or an already-mapped RemoteSession.
   */
  emitSessionEvent(event: RemoteSessionEvent, rowOrSession: any) {
    if (!rowOrSession) return;
    const session: RemoteSession = 'session_token' in rowOrSession || 'tenant_id' in rowOrSession
      ? this.rowToSession(rowOrSession)
      : rowOrSession;
    try {
      emitRemoteSessionEvent(getIO(), event, session);
    } catch { /* socket.io not initialised (boot / scripts) — nothing to notify */ }
  }

  /**
   * Authorize the browser end of /api/remote/tunnel/<token>: the upgrade
   * request must carry a valid express-session cookie whose user started the
   * session, and the session must still be open. `sessionMw` is the app's
   * express-session middleware (app.getSessionMiddleware()).
   * Never throws — errors resolve to a 4000 verdict.
   */
  async authorizeBrowserTunnel(
    request: IncomingMessage,
    sessionToken: string,
    sessionMw: ((req: any, res: any, next: (err?: unknown) => void) => void) | null,
  ): Promise<TunnelAccessVerdict> {
    try {
      const sess = await loadUpgradeSession(sessionMw, request) as { userId?: number; deviceKeyId?: string } | undefined;
      const userId = sess?.userId;
      if (!userId) return evaluateBrowserTunnelAccess({ userId: null, userActive: false, row: null });
      // Device-bound 2FA (§6.4 / §6.7): an upgrade never goes through the
      // per-request deviceKeySession check. A session bound to a dead key
      // (e.g. a row resurrected by a concurrent save after a revocation)
      // must not open a relay.
      const { boundSessionDead } = await import('./deviceKey/deviceKey.service');
      if (await boundSessionDead(sess?.deviceKeyId, userId)) {
        return { ok: false, code: 4003, reason: 'Authentication required', userId };
      }
      const row = await db('remote_sessions')
        .where({ session_token: sessionToken })
        .first('id', 'started_by', 'status', 'protocol', 'device_id', 'tenant_id');
      const user = row ? await db('users').where({ id: userId }).first('is_active') : null;
      const verdict = evaluateBrowserTunnelAccess({ userId, userActive: !!user && user.is_active !== false, row });
      if (verdict.ok) await this.ensureFilesPolicy(sessionToken, row);
      const sid = (request as { sessionID?: unknown }).sessionID;
      if (verdict.ok && typeof sid === 'string' && sid) {
        return { ...verdict, sessionHash: sessionHash(sid) };
      }
      return verdict;
    } catch (err) {
      logger.error(err, 'Browser remote tunnel authorization error');
      return { ok: false, code: 4000, reason: 'Internal error' };
    }
  }

  /**
   * Authorize the agent end of /api/remote/agent-tunnel/<token>: the
   * X-Api-Key must be the key the session's DEVICE is bound to (same rule as
   * the /api/agent/ws channel), the session must still be waiting for its
   * agent, and no agent may already be attached. The caller must register
   * the tunnel in the same tick as a positive verdict (no await in between)
   * so the "no live agent" check cannot race.
   * Never throws — errors resolve to a 500 verdict.
   */
  async authorizeAgentTunnel(apiKey: string | undefined, sessionToken: string): Promise<AgentTunnelVerdict> {
    try {
      if (!apiKey) return { ok: false, status: 401, reason: 'Missing X-Api-Key header' };
      const key = await db('agent_api_keys').where({ key: apiKey }).first('id', 'tenant_id', 'is_active');
      if (!key || key.is_active === false) return evaluateAgentTunnelAccess({ key: null, row: null, hasLiveAgent: false });
      const row = await db('remote_sessions as rs')
        .leftJoin('devices as d', 'd.id', 'rs.device_id')
        .where('rs.session_token', sessionToken)
        .first(
          'rs.id', 'rs.status', 'rs.device_id', 'rs.protocol', 'rs.started_by', 'rs.tenant_id',
          'd.tenant_id as device_tenant_id', 'd.api_key_id as device_api_key_id',
        );
      // The file-transfer decision must be known before the agent's first
      // frame; resolved BEFORE the verdict so nothing is awaited between the
      // "no live agent" check and the registration (see above).
      if (row) await this.ensureFilesPolicy(sessionToken, row);
      return evaluateAgentTunnelAccess({ key, row, hasLiveAgent: this.hasLiveAgent(sessionToken) });
    } catch (err) {
      logger.error(err, 'Agent remote tunnel authorization error');
      return { ok: false, status: 500, reason: 'Internal error' };
    }
  }

  /** True while an agent WebSocket is attached (and not closed) for this token. */
  hasLiveAgent(sessionToken: string): boolean {
    const agent = this.tunnels.get(sessionToken)?.agent;
    // ws readyState: 0 CONNECTING, 1 OPEN, 2 CLOSING, 3 CLOSED
    return !!agent && (agent.readyState === 0 || agent.readyState === 1);
  }

  async createSession(
    deviceId: number,
    tenantId: number,
    userId: number,
    protocol: RemoteProtocol = 'oblireach',
    /** WTS session ID to capture (Windows only). Omit to capture the console session. */
    wtsSessionId?: number,
    /** Hyper-V VM GUID — required when protocol === 'vmconsole'. */
    vmId?: string,
  ): Promise<RemoteSession> {
    // Privacy mode stops the ObliReach service on the device. A session
    // requested meanwhile used to be QUEUED as "agent offline" and started by
    // itself if the user lifted privacy within 5 minutes. Refused up front
    // instead (423, like the command route), unless this user holds a
    // privacy unlock for 'remote' (its token rides in the command).
    if (protocol === 'oblireach') {
      const dev = await db('devices').where({ id: deviceId }).first('privacy_mode_enabled');
      if (dev?.privacy_mode_enabled && !privacyGateService.get(userId, deviceId, 'remote')) {
        throw new AppError(423,
          "Privacy mode is active on this device — unlock required for feature 'remote'",
          'privacy_mode');
      }
    }

    const sessionToken = crypto.randomBytes(32).toString('hex');

    const [row] = await db('remote_sessions').insert({
      device_id: deviceId, tenant_id: tenantId,
      protocol, status: 'waiting',
      session_token: sessionToken,
      started_by: userId,
    }).returning('*');

    const session = this.rowToSession(row);
    let delivery: RemoteDelivery = 'queued';

    // Look up the connecting user's display name for agent-side notifications.
    let username = 'Unknown';
    try {
      const user = await db('users').where({ id: userId }).first();
      if (user) username = user.display_name || user.username || user.email || 'Unknown';
    } catch {}

    // Deliver the open_remote_tunnel command to the appropriate agent.
    const commandPayload: Record<string, unknown> = {
      sessionToken, protocol, serverWsUrl: `/api/remote/tunnel/${sessionToken}`,
      username,
    };
    if (wtsSessionId !== undefined) {
      commandPayload.sessionId = wtsSessionId;
    }
    // Attach privacy unlock token if the user has an active unlock for 'remote'.
    const remoteToken = privacyGateService.get(userId, deviceId, 'remote');
    if (remoteToken) {
      commandPayload.unlockToken = remoteToken;
    }
    // ObliReach file transfers (paste / drop uploads, files copied on the
    // remote): capability 'files' + the privacy unlock of 'files'
    // (reachFilesGate.ts). The agent enforces `files`, the relay as well.
    if (protocol === 'oblireach') {
      const filesPolicy = await this.resolveFilesPolicy(userId, deviceId, tenantId);
      this.rememberFilesPolicy(sessionToken, filesPolicy);
      commandPayload.files = filesPolicy.allowed;
      if (!filesPolicy.allowed) {
        logger.info({ sessionId: row.id, deviceId, reason: filesPolicy.reason }, 'ObliReach session: file transfers not permitted');
      }
    }

    if (protocol === 'oblireach') {
      // Oblireach: try instant WS delivery first; fall back to DB queue so the
      // command is picked up the moment the agent reconnects (even if offline now).
      const device = await db('devices').where({ id: deviceId }).first();
      if (device?.uuid) {
        const orCmd: OrCommand = {
          type: 'open_remote_tunnel',
          id: `or_${sessionToken.slice(0, 8)}`,
          payload: commandPayload,
        };
        // Only to a channel registered with this device's key (the command
        // carries the relay token) — see oblireachHub.push.
        const pushed = oblireachHub.pushDetailed(device.uuid, orCmd, {
          tenantId: device.tenant_id, apiKeyId: device.api_key_id ?? null,
        });
        if (pushed === 'sent') {
          delivery = 'live';
        } else if (pushed === 'mismatch') {
          // A live channel for this uuid authenticated with ANOTHER key: never
          // queue (the binding rule is not relaxed) — refuse with a clear 409.
          this.filesPolicies.delete(sessionToken);
          const [failed] = await db('remote_sessions').where({ id: row.id })
            .update({ status: 'failed', ended_at: new Date(), end_reason: 'key_mismatch' })
            .returning('*');
          this.emitSessionEvent(SocketEvents.REMOTE_SESSION_UPDATED, failed ?? row);
          logger.warn({ deviceId, sessionId: row.id }, 'ObliReach session refused: agent channel registered with another API key');
          throw new AppError(409,
            'The ObliReach agent is registered with another API key. Reinstall ObliReach from Obliance.',
            'oblireach_key_mismatch');
        } else {
          // Agent offline — queue in DB (JSON array, 5 min TTL); drained on its
          // next WS connect / HTTP push. oblireach_devices rows are keyed by
          // the AGENT's tenant, i.e. the device's (the session tenant is the
          // master's for a god-view start).
          const { enqueueOrCommand } = await import('./oblireachQueue');
          await enqueueOrCommand(device.uuid, device.tenant_id, orCmd);
        }
      } else {
        logger.warn({ deviceId, sessionId: row.id }, 'ObliReach session: device has no uuid — the open command cannot be delivered');
      }
    } else if (protocol === 'vmconsole') {
      // Hyper-V VM interactive console: the Obliance agent spawns the bundled
      // FreeRDP helper which streams the VM console as H.264 into the same relay.
      // Live-only — there is no DB-queue fallback (an interactive stream needs
      // the agent online right now); if undelivered the session simply times out.
      const vmPayload: Record<string, unknown> = { ...commandPayload, vmId };
      const delivered = agentHub.push(deviceId, {
        type: 'command',
        id: `vmc_${sessionToken.slice(0, 8)}`,
        commandType: 'open_vm_console',
        payload: vmPayload,
      });
      if (!delivered) {
        const [failed] = await db('remote_sessions').where({ id: row.id })
          .update({ status: 'failed', ended_at: new Date(), end_reason: 'agent_offline' })
          .returning('*');
        this.emitSessionEvent(SocketEvents.REMOTE_SESSION_UPDATED, failed ?? row);
        logger.warn({ deviceId, sessionId: row.id }, 'vm console: agent offline, session failed');
        // Do NOT hand back a session that is already dead: the viewer would
        // open a tunnel that is refused and, on its reconnect path, create
        // another dead session in a loop. A 409 stops the caller instead.
        throw new AppError(409, 'The host agent is not connected — the VM console needs a live agent connection.');
      }
      delivery = 'live';
    } else {
      // RDP / SSH / Shell: prefer instant command channel, fall back to DB queue.
      const delivered = agentHub.push(deviceId, {
        type: 'command',
        id: `remote_${sessionToken.slice(0, 8)}`,
        commandType: 'open_remote_tunnel',
        payload: commandPayload,
      });
      if (delivered) {
        delivery = 'live';
      } else {
        await commandService.enqueue({
          deviceId, tenantId, type: 'open_remote_tunnel',
          payload: commandPayload,
          priority: 'urgent',
          expiresInSeconds: 300,
          createdBy: userId,
        });
      }
    }

    // Notify UI (token only to the starter — see emitSessionEvent)
    this.emitSessionEvent(SocketEvents.REMOTE_SESSION_UPDATED, session);

    logger.info({ sessionId: session.id, deviceId, protocol, delivery }, 'Remote session created');
    return { ...session, delivery };
  }

  /**
   * Ends an OPEN session (waiting / connecting / active): final status, agent
   * told to close, relay closed with a notice, change emitted. Returns true
   * when it ended one. A session already over (failed, timeout, closed,
   * expired) is left as it is — its end_reason (agent_error:<code>,
   * command_failure: <text>, timeout…) is the diagnostic the supervision
   * history shows; a viewer's Retry used to overwrite it with
   * 'user_disconnect', and the agent was pushed a close (old agents then
   * showed the remote user "technician disconnected") for nothing.
   */
  async endSession(sessionId: string, tenantId: number, reason: string = 'user_disconnect'): Promise<boolean> {
    // Master tenant gets god-view (can close any tenant's session);
    // child tenants stay scoped.
    const isMaster = isMasterTenant(tenantId);
    const q = db('remote_sessions').where({ id: sessionId });
    if (!isMaster) q.where({ tenant_id: tenantId });
    const session = await q.first();
    if (!session) return false;
    this.creatorSessions.delete(String(sessionId));
    if (!OPEN_STATUSES.includes(session.status)) {
      // Nothing may stay attached to a finished session (no-op normally).
      this.closeRelay(session.session_token);
      return false;
    }

    const duration = session.connected_at
      ? Math.floor((Date.now() - new Date(session.connected_at).getTime()) / 1000)
      : 0;
    // Sessions that never connected (waiting/connecting) are marked 'expired', not 'closed'
    const finalStatus = session.connected_at ? 'closed' : 'expired';
    const ended = await db('remote_sessions').where({ id: sessionId }).whereIn('status', OPEN_STATUSES).update({
      status: finalStatus, ended_at: new Date(),
      duration_seconds: duration, end_reason: reason,
    });
    if (!ended) {
      // Finished by someone else meanwhile (agent failure, timeout).
      this.closeRelay(session.session_token);
      return false;
    }

    // Tell agent to close tunnel — include username for agent-side notification.
    let closingUsername = 'Unknown';
    try {
      const user = await db('users').where({ id: session.started_by }).first();
      if (user) closingUsername = user.display_name || user.username || user.email || 'Unknown';
    } catch {}
    const closePayload = { sessionToken: session.session_token, username: closingUsername };
    if (session.protocol === 'oblireach') {
      // Deliver close via WS if connected; no DB fallback needed (close is best-effort —
      // the session is ending regardless, and the agent will detect the tunnel close).
      const device = await db('devices').where({ id: session.device_id }).first();
      if (device?.uuid) {
        oblireachHub.push(device.uuid, {
          type: 'close_remote_tunnel',
          id: `close_${session.session_token.slice(0, 8)}`,
          payload: closePayload,
        }, { tenantId: device.tenant_id, apiKeyId: device.api_key_id ?? null });
      }
    } else {
      const closePushed = agentHub.push(session.device_id, {
        type: 'command',
        id: `close_${session.session_token.slice(0, 8)}`,
        commandType: 'close_remote_tunnel',
        payload: closePayload,
      });
      if (!closePushed) {
        await commandService.enqueue({
          deviceId: session.device_id, tenantId: session.tenant_id,
          type: 'close_remote_tunnel',
          payload: closePayload,
          priority: 'urgent',
        });
      }
    }

    // Close the in-memory relay (both ends). It used to be only forgotten:
    // the viewer of a session ended from elsewhere (supervision "End", a
    // kill) then sat on a live-looking socket. A real browser is told why.
    this.closeRelay(session.session_token, {
      type: 'error', code: 'session_closed', retry: false,
      message: `Remote session closed (${safeText(reason, 60)})`,
    });

    // Notify UI (token only to the starter — see emitSessionEvent)
    try {
      const updated = await db('remote_sessions').where({ id: sessionId }).first();
      this.emitSessionEvent(SocketEvents.REMOTE_SESSION_UPDATED, updated);
    } catch {}
    return true;
  }

  async getSessions(tenantId: number, filters?: {
    deviceId?: number; status?: string;
    callerUserId?: number; callerIsAdmin?: boolean;
  }) {
    // Visibility cascade — strictest wins:
    //   - Master tenant (id=1) god view: every session install-wide.
    //   - Otherwise tenant-scoped.
    //   - Plain user (callerIsAdmin=false): further restricted to
    //     sessions THEY started (started_by = callerUserId). Without
    //     this, a non-admin with the `remote` capability would see
    //     other users' sessions on shared devices, which the user
    //     explicitly asked to prevent.
    const isMaster = isMasterTenant(tenantId);
    let q = db('remote_sessions as rs')
      .leftJoin('users as u', 'u.id', 'rs.started_by');
    if (!isMaster) q = q.where({ 'rs.tenant_id': tenantId });
    if (filters?.deviceId) q = q.where({ 'rs.device_id': filters.deviceId });
    if (filters?.status) q = q.where({ 'rs.status': filters.status });
    if (filters?.callerIsAdmin === false && filters.callerUserId != null) {
      q = q.where({ 'rs.started_by': filters.callerUserId });
    }
    const rows = await q
      .select('rs.*', 'u.username as started_by_username', 'u.display_name as started_by_display_name')
      .orderBy('rs.started_at', 'desc').limit(100);
    return rows.map((row: any): RemoteSession | PublicRemoteSession => {
      const session = this.rowToSession(row);
      if (row.started_by_username || row.started_by_display_name) {
        session.startedByUser = {
          id: row.started_by,
          username: row.started_by_username,
          displayName: row.started_by_display_name,
        };
      }
      // The relay token only goes to the user who started the session (the
      // tunnel refuses anyone else anyway). Admins still see every session,
      // without the token — same shape as the socket.io tenant copy.
      const isOwn = filters?.callerUserId != null && Number(row.started_by) === Number(filters.callerUserId);
      return isOwn ? session : toPublicRemoteSession(session);
    });
  }

  // Called when agent WebSocket connects for a session (after
  // authorizeAgentTunnel). Agent data may arrive before the browser has
  // connected, so we buffer it until registerBrowserTunnel() flushes the
  // buffer and sets up full relay.
  // Returns false — and registers nothing — when an agent is already
  // attached: a second agent is never swapped in or bridged to the browser
  // (it would receive everything the user types).
  registerAgentTunnel(sessionToken: string, agentWs: any): boolean {
    if (this.hasLiveAgent(sessionToken)) return false;
    if (!this.tunnels.has(sessionToken)) this.tunnels.set(sessionToken, { agentBuffer: [] });
    const tunnel = this.tunnels.get(sessionToken)!;
    tunnel.agent = agentWs;
    // Pin the file-transfer decision on the relay (resolved by
    // authorizeAgentTunnel in this same tick): the gates below read it here.
    tunnel.filesPolicy ??= this.filesPolicies.get(sessionToken)?.policy;

    // Buffer agent→browser frames until browser is ready.
    // The second parameter `isBinary` is provided by the `ws` library (v8+):
    // text frames arrive as isBinary=false, binary frames as isBinary=true.
    // We MUST forward the same frame type so the browser (xterm) interprets
    // binary frames as raw terminal bytes and not UTF-8 text.
    agentWs.on('message', (raw: Buffer, isBinary: boolean) => {
      let data = raw;
      // ObliReach session without file transfers (reachFilesGate.ts): file
      // messages / 0x21 data dropped, the init rewritten (features, reason).
      const filesPolicy = tunnel.filesPolicy;
      if (filesPolicy && !filesPolicy.allowed) {
        if (!Buffer.isBuffer(raw)) return; // never with the 'nodebuffer' binaryType; unread = dropped
        const gated = gateAgentFrame(raw, isBinary, filesPolicy);
        if (!gated) return;
        data = gated;
      }
      this.peekTransfer(sessionToken, tunnel, 'agent', data, isBinary);
      if (tunnel.browser) {
        try { tunnel.browser.send(data, { binary: isBinary }); } catch {}
      } else {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        tunnel.agentBuffer.push({ data: buf, isBinary });
        if (isBinary) {
          tunnel.agentBufferBytes = (tunnel.agentBufferBytes ?? 0) + buf.length;
          // No browser to drain it (it left, or never came): drop the oldest
          // BINARY frames (video / audio) — control text (init…) is kept.
          while ((tunnel.agentBufferBytes ?? 0) > AGENT_BUFFER_MAX_BYTES) {
            const i = tunnel.agentBuffer.findIndex((f) => f.isBinary);
            if (i < 0) break;
            tunnel.agentBufferBytes = (tunnel.agentBufferBytes ?? 0) - tunnel.agentBuffer[i].data.length;
            tunnel.agentBuffer.splice(i, 1);
          }
        }
      }
    });

    // Keepalive ping every 15 s — prevents intermediate proxies (Nginx/NPM)
    // from dropping idle tunnel WS connections. 15 s covers proxies with
    // timeouts as low as ~20 s and ensures the first ping fires well before
    // a typical 40–60 s idle cutoff.
    const agentKeepAlive = setInterval(() => {
      try { (agentWs as any).ping(); } catch { clearInterval(agentKeepAlive); }
    }, 15_000);
    agentWs.on('close', () => {
      clearInterval(agentKeepAlive);
      this.handleTunnelClose(sessionToken, 'agent_disconnect');
    });

    // If browser arrived first (unusual but possible), flush immediately
    if (tunnel.browser) {
      this._flushAndBridgeBrowser(sessionToken, tunnel.browser, agentWs);
    }

    // Update session status — only a session still waiting for its agent
    // becomes 'active'. If it was ended/expired meanwhile, drop the tunnel
    // and hang up on the agent instead of resurrecting the session.
    db('remote_sessions')
      .where({ session_token: sessionToken })
      .whereIn('status', ['waiting', 'connecting'])
      .update({ status: 'active', connected_at: new Date() })
      .returning('*')
      .then((rows: any[]) => {
        const row = rows?.[0];
        if (row) {
          this.emitSessionEvent(SocketEvents.REMOTE_TUNNEL_READY, row);
          return;
        }
        const current = this.tunnels.get(sessionToken);
        if (current && current.agent === agentWs) {
          this.tunnels.delete(sessionToken); // handleTunnelClose then no-ops
          try { current.browser?.close(); } catch {}
        }
        try { agentWs.close(4004, 'Session not open'); } catch {}
      })
      .catch((err: unknown) => logger.error(err, 'Remote tunnel: failed to mark session active'));
    return true;
  }

  // Called when browser WebSocket connects for a session. `meta.sessionHash`:
  // the express session of the upgrade (none for the in-process bastion).
  // `meta.isWebSocket`: a real browser WebSocket (index.ts) — it is told
  // {"type":"waiting"} while the agent has not paired, and if it leaves
  // before the agent pairs and does not come back within 15 s the session
  // is ended (it used to stay 'waiting', and a late agent then streamed —
  // helper, watermark — to nobody).
  registerBrowserTunnel(sessionToken: string, browserWs: any, meta: { sessionHash?: string; isWebSocket?: boolean; clientIp?: string } = {}) {
    if (!this.tunnels.has(sessionToken)) this.tunnels.set(sessionToken, { agentBuffer: [] });
    const tunnel = this.tunnels.get(sessionToken)!;
    if (tunnel.browserGoneTimer) {
      clearTimeout(tunnel.browserGoneTimer);
      tunnel.browserGoneTimer = undefined;
    }
    this.stopBrowserPreKeepAlive(tunnel);
    tunnel.browser = browserWs;
    tunnel.browserSessionHash = meta.sessionHash;
    tunnel.browserIsWs = !!meta.isWebSocket;
    tunnel.browserIp = meta.clientIp;

    if (tunnel.agent) {
      this._flushAndBridgeBrowser(sessionToken, browserWs, tunnel.agent);
      return;
    }
    // If agent hasn't connected yet, browser→agent relay will be set up
    // in registerAgentTunnel when the agent eventually arrives.
    if (meta.isWebSocket) {
      try { browserWs.send(JSON.stringify({ type: 'waiting' })); } catch { /* closing */ }
      // Keepalive while waiting for the agent (up to 5.5 min for a queued
      // launch): it used to start only at pairing, and a reverse proxy
      // (NPM ~20 s, nginx 60 s) cut the silent socket — the viewer then
      // started a NEW session every minute until it gave up.
      const keepAlive = setInterval(() => {
        if (tunnel.browser !== browserWs || tunnel.agent) { clearInterval(keepAlive); return; }
        try { browserWs.ping(); } catch { clearInterval(keepAlive); }
      }, BROWSER_KEEPALIVE_MS);
      (keepAlive as any).unref?.();
      tunnel.browserPreKeepAlive = keepAlive;
      try {
        browserWs.on('close', () => {
          if (tunnel.browserPreKeepAlive === keepAlive) this.stopBrowserPreKeepAlive(tunnel);
          else clearInterval(keepAlive);
          this.onBrowserLeftBeforePairing(sessionToken, browserWs);
        });
      } catch { /* not an emitter */ }
    }
  }

  private stopBrowserPreKeepAlive(tunnel: TunnelEntry) {
    if (tunnel.browserPreKeepAlive) {
      clearInterval(tunnel.browserPreKeepAlive);
      tunnel.browserPreKeepAlive = undefined;
    }
  }

  /** The browser end closed while its agent had not paired yet (see registerBrowserTunnel). */
  private onBrowserLeftBeforePairing(sessionToken: string, browserWs: any) {
    const tunnel = this.tunnels.get(sessionToken);
    // Replaced by another browser, gone, or paired meanwhile (the bridge's
    // own close handler then ends the session).
    if (!tunnel || tunnel.browser !== browserWs || tunnel.agent) return;
    tunnel.browser = undefined;
    tunnel.browserGoneTimer = setTimeout(() => {
      const current = this.tunnels.get(sessionToken);
      if (current !== tunnel || tunnel.browser) return; // came back
      tunnel.browserGoneTimer = undefined;
      if (tunnel.agent) {
        // Paired while nobody watched: hang up both ends and end the session.
        this.handleTunnelClose(sessionToken, 'browser_disconnect').catch(() => { /* logged there */ });
        return;
      }
      this.tunnels.delete(sessionToken);
      db('remote_sessions').where({ session_token: sessionToken }).whereIn('status', OPEN_STATUSES)
        .first('id', 'tenant_id')
        .then((row: { id: string; tenant_id: number } | undefined) => {
          if (row) return this.endSession(row.id, row.tenant_id, 'browser_disconnect');
          return undefined;
        })
        .catch((err: unknown) => logger.warn({ err }, 'Remote tunnel: ending a session left before pairing failed'));
    }, BROWSER_RETURN_GRACE_MS);
    (tunnel.browserGoneTimer as any).unref?.();
  }

  /**
   * Close both ends of a relay (and forget it). A real browser end first gets
   * `notice` (why). No-op when the relay is not attached here.
   */
  private closeRelay(sessionToken: string, notice?: RelayErrorNotice) {
    this.filesPolicies.delete(sessionToken);
    const tunnel = this.tunnels.get(sessionToken);
    if (!tunnel) return;
    this.tunnels.delete(sessionToken);
    if (tunnel.browserGoneTimer) {
      clearTimeout(tunnel.browserGoneTimer);
      tunnel.browserGoneTimer = undefined;
    }
    this.stopBrowserPreKeepAlive(tunnel);
    this.flushTransfers(sessionToken, tunnel, 'session_closed');
    if (notice && tunnel.browser && tunnel.browserIsWs) {
      try { tunnel.browser.send(JSON.stringify(notice)); } catch { /* closing */ }
    }
    try { tunnel.browser?.close(); } catch { /* already closed */ }
    try { tunnel.agent?.close(); } catch { /* already closed */ }
  }

  /** Drop a tunnel entry whose browser side gave up BEFORE the agent paired
   *  (e.g. the in-process SSH bastion hit its connect timeout). Without this
   *  the entry would linger in memory until an agent that never comes. */
  dropTunnel(sessionToken: string) {
    this.tunnels.delete(sessionToken);
  }

  /** Flush buffered agent frames to the browser, then wire up browser→agent relay. */
  private _flushAndBridgeBrowser(sessionToken: string, browserWs: any, agentWs: any) {
    const tunnel = this.tunnels.get(sessionToken);
    if (!tunnel) return;
    // The bridge's own keepalive takes over from the waiting one.
    this.stopBrowserPreKeepAlive(tunnel);

    // Signal the browser that the agent is paired and streaming is starting.
    // This triggers the viewer transition from 'waiting' → 'streaming' even
    // if the agent's init frame was already buffered (and would be lost as
    // binary when text/binary metadata is not preserved in the buffer).
    try { browserWs.send(JSON.stringify({ type: 'paired' })); } catch {}

    // Drain buffer: send accumulated agent frames to browser, preserving frame type
    for (const { data, isBinary } of tunnel.agentBuffer) {
      try { browserWs.send(data, { binary: isBinary }); } catch {}
    }
    tunnel.agentBuffer = [];

    // Keepalive ping every 25 s on the browser WS — same reason as agent side.
    const browserKeepAlive = setInterval(() => {
      try { (browserWs as any).ping(); } catch { clearInterval(browserKeepAlive); }
    }, 15_000);

    // Browser → agent relay (agent→browser is already wired in registerAgentTunnel).
    // Preserve the WS frame type (text vs binary) so the agent can distinguish
    // JSON control messages (text, e.g. resize) from raw shell stdin (binary).
    browserWs.on('message', (data: Buffer, isBinary: boolean) => {
      // ObliReach session without file transfers (reachFilesGate.ts): no
      // file message or binary frame reaches the agent; a request the viewer
      // waits on is answered file_error{forbidden} and audited.
      const filesPolicy = tunnel.filesPolicy;
      if (filesPolicy && !filesPolicy.allowed) {
        const verdict = gateBrowserFrame(data, isBinary);
        if (!verdict.forward) {
          if (verdict.reply) { try { browserWs.send(verdict.reply); } catch { /* closing */ } }
          if (verdict.attempt) this.auditDeniedFile(sessionToken, tunnel, filesPolicy, verdict.attempt);
          return;
        }
      }
      this.peekTransfer(sessionToken, tunnel, 'browser', data, isBinary);
      try { agentWs.send(data, { binary: isBinary }); } catch {}
    });
    browserWs.on('close', () => {
      clearInterval(browserKeepAlive);
      this.handleTunnelClose(sessionToken, 'browser_disconnect');
    });
  }

  // ── File-transfer audit (passive peek) ──────────────────────────────────
  // ObliReach uploads (operator → session user's Downloads) and downloads
  // (a file the session user copied) cross this relay. It reads — never
  // changes, delays or drops — the file_* control messages and counts the
  // 0x20 / 0x21 data bytes, to write one audit entry per transfer:
  // remote.file_upload / remote.file_download (name, size, bytes relayed,
  // SHA-256, destination path, ok / error). Video / audio frames only cost a
  // byte comparison; text frames a Buffer search, and are parsed only when
  // they mention "file_.

  private peekTransfer(sessionToken: string, tunnel: TunnelEntry, from: 'browser' | 'agent', data: unknown, isBinary: boolean) {
    try {
      if (!Buffer.isBuffer(data)) return;
      if (isBinary) {
        const map = tunnel.transfers;
        if (!map || map.size === 0 || data.length < 9) return;
        const type = data[0];
        if ((from === 'browser' && type === 0x20) || (from === 'agent' && type === 0x21)) {
          const t = map.get(data.readUInt32LE(1));
          if (t && t.dir === (type === 0x20 ? 'up' : 'down')) t.bytes += data.length - 9;
        }
        return;
      }
      if (data.length > RELAY_PEEK_MAX_BYTES || data.indexOf(FILE_TYPE_MARK) < 0) return;
      let msg: any;
      try { msg = JSON.parse(data.toString('utf8')); } catch { return; }
      if (!msg || typeof msg.type !== 'string' || !msg.type.startsWith('file_')) return;
      const tid = Number(msg.tid);
      if (!Number.isInteger(tid) || tid < 0 || tid > 0xffffffff) return;
      const map = tunnel.transfers ?? (tunnel.transfers = new Map());
      const str = (v: unknown, max: number) => (typeof v === 'string' && v ? safeText(v, max) : undefined);
      const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : undefined);
      const hash = (v: unknown) => (typeof v === 'string' && /^[0-9a-f]{64}$/i.test(v) ? v.toLowerCase() : undefined);
      const t = map.get(tid);
      switch (`${from}:${msg.type}`) {
        case 'browser:file_begin':
        case 'browser:file_get': {
          if (t) this.finishTransfer(sessionToken, tunnel, tid, false, 'superseded');
          if (map.size >= RELAY_TRANSFERS_MAX) {
            const oldest = map.keys().next();
            if (!oldest.done) this.finishTransfer(sessionToken, tunnel, oldest.value, false, 'untracked');
          }
          map.set(tid, msg.type === 'file_begin'
            ? { dir: 'up', name: str(msg.name, 255), size: num(msg.size), dest: str(msg.dest, 64), bytes: 0, startedAt: Date.now() }
            : { dir: 'down', source: str(msg.source, 32), idx: num(msg.idx), bytes: 0, startedAt: Date.now() });
          return;
        }
        case 'agent:file_accept':
          if (t) t.path = str(msg.path, 1024) ?? t.path;
          return;
        case 'agent:file_offer':
          if (t) { t.name = str(msg.name, 255) ?? t.name; t.size = num(msg.size) ?? t.size; }
          return;
        case 'browser:file_end':
          if (t) t.sha256 = hash(msg.sha256) ?? t.sha256;
          return;
        case 'agent:file_done':
          if (!t) return;
          t.path = str(msg.path, 1024) ?? t.path;
          t.name = t.name ?? str(msg.name, 255);
          t.sha256 = hash(msg.sha256) ?? t.sha256;
          this.finishTransfer(sessionToken, tunnel, tid, msg.ok !== false, msg.ok === false ? safeCode(msg.code) : undefined);
          return;
        case 'agent:file_error':
        case 'browser:file_error':
          if (t) this.finishTransfer(sessionToken, tunnel, tid, false, safeCode(msg.code));
          return;
        case 'agent:file_cancel':
        case 'browser:file_cancel':
          if (t) this.finishTransfer(sessionToken, tunnel, tid, false, from === 'browser' ? 'cancelled_by_operator' : 'cancelled_by_agent');
          return;
        default:
          return;
      }
    } catch (err) {
      logger.debug({ err }, 'Remote relay: transfer peek failed');
    }
  }

  /**
   * A transfer request refused because the operator may not transfer files in
   * this session: one remote.file_denied entry (at most FILE_DENIED_AUDIT_MAX
   * per relay), on the session's tenant, like remote.file_upload / download.
   */
  private auditDeniedFile(sessionToken: string, tunnel: TunnelEntry, policy: ReachFilesPolicy, attempt: DeniedFileAttempt) {
    const n = tunnel.filesDeniedAudits ?? 0;
    if (n >= FILE_DENIED_AUDIT_MAX) return;
    tunnel.filesDeniedAudits = n + 1;
    const ip = tunnel.browserIp;
    void (async () => {
      const row = await db('remote_sessions').where({ session_token: sessionToken })
        .first('id', 'tenant_id', 'device_id', 'started_by', 'protocol');
      if (!row) return;
      const { auditService } = await import('./audit.service');
      await auditService.log({
        tenantId: row.tenant_id,
        userId: row.started_by ?? undefined,
        deviceId: row.device_id ?? undefined,
        action: 'remote.file_denied',
        resourceType: 'remote_session',
        resourcePath: String(row.id),
        ipAddress: ip,
        details: {
          sessionId: row.id,
          protocol: row.protocol,
          reason: policy.reason ?? 'capability',
          request: safeCode(attempt.type),
          direction: attempt.type === 'file_get' ? 'remote_to_operator' : 'operator_to_remote',
          tid: attempt.tid ?? null,
          name: attempt.name !== undefined ? safeText(attempt.name, 255) : null,
          size: attempt.size ?? null,
          ...(n + 1 === FILE_DENIED_AUDIT_MAX ? { furtherAttemptsNotLogged: true } : {}),
        },
      });
    })().catch((err) => logger.warn({ err }, 'Remote relay: refused file transfer audit failed'));
  }

  /** Transfers still open when the relay goes away. */
  private flushTransfers(sessionToken: string, tunnel: TunnelEntry, reason: string) {
    const map = tunnel.transfers;
    if (!map || map.size === 0) return;
    for (const tid of [...map.keys()]) this.finishTransfer(sessionToken, tunnel, tid, false, reason);
  }

  private finishTransfer(sessionToken: string, tunnel: TunnelEntry, tid: number, ok: boolean, error?: string) {
    const t = tunnel.transfers?.get(tid);
    if (!t) return;
    tunnel.transfers!.delete(tid);
    const ip = tunnel.browserIp;
    void (async () => {
      const row = await db('remote_sessions').where({ session_token: sessionToken })
        .first('id', 'tenant_id', 'device_id', 'started_by', 'protocol');
      if (!row) return;
      const { auditService } = await import('./audit.service');
      await auditService.log({
        tenantId: row.tenant_id,
        userId: row.started_by ?? undefined,
        deviceId: row.device_id ?? undefined,
        action: t.dir === 'up' ? 'remote.file_upload' : 'remote.file_download',
        resourceType: 'remote_session',
        resourcePath: String(row.id),
        ipAddress: ip,
        details: {
          sessionId: row.id,
          protocol: row.protocol,
          direction: t.dir === 'up' ? 'operator_to_remote' : 'remote_to_operator',
          name: t.name ?? null,
          size: t.size ?? null,
          bytes: t.bytes,
          sha256: t.sha256 ?? null,
          ...(t.dir === 'up' ? { dest: t.dest ?? null, path: t.path ?? null } : { source: t.source ?? null, index: t.idx ?? null }),
          ok,
          ...(error ? { error } : {}),
          durationMs: Date.now() - t.startedAt,
        },
      });
    })().catch((err) => logger.warn({ err }, 'Remote relay: file transfer audit failed'));
  }

  private async handleTunnelClose(sessionToken: string, reason: string) {
    const tunnel = this.tunnels.get(sessionToken);
    if (!tunnel) return;
    this.tunnels.delete(sessionToken);
    this.filesPolicies.delete(sessionToken);
    if (tunnel.browserGoneTimer) {
      clearTimeout(tunnel.browserGoneTimer);
      tunnel.browserGoneTimer = undefined;
    }
    this.stopBrowserPreKeepAlive(tunnel);
    this.flushTransfers(sessionToken, tunnel, 'disconnected');

    // Propagate close to the other side so neither end hangs as an orphan.
    // The guard above ensures this is called only once per tunnel.
    try { tunnel.browser?.close(); } catch {}
    try { tunnel.agent?.close(); } catch {}

    const session = await db('remote_sessions').where({ session_token: sessionToken }).first();
    if (session && session.tenant_id) {
      this.endSession(session.id, session.tenant_id, reason);
    }
  }

  /**
   * P6: ends every open remote session STARTED BY a user whose access was
   * just taken away (disabled, deleted, demoted). The live relay (browser /
   * in-process bastion end AND agent end) is closed, and sessions that never
   * paired are closed the same way through endSession. Returns the count.
   */
  async closeSessionsForUser(userId: number, reason: string): Promise<number> {
    const rows = await db('remote_sessions')
      .where({ started_by: userId })
      .whereIn('status', ['waiting', 'connecting', 'active'])
      .select('id', 'tenant_id', 'session_token') as Array<{ id: string; tenant_id: number; session_token: string }>;
    for (const row of rows) {
      try {
        // Same teardown as handleTunnelClose, but awaited (errors stay here):
        // the entry is removed first, so the close handlers of both ends
        // find nothing left to do.
        this.closeRelay(row.session_token, {
          type: 'error', code: 'session_closed', retry: false,
          message: `Remote session closed (${safeText(reason, 60)})`,
        });
        await this.endSession(row.id, row.tenant_id, reason);
      } catch (err) {
        logger.warn({ err, sessionId: row.id }, 'remote session close (user access removed) failed');
      }
    }
    return rows.length;
  }

  /**
   * Device-bound 2FA revocation (§6.7): ends every open remote session whose
   * browser relay was attached by, or which was started from, one of these
   * express sessions (sha256 of the sid), i.e. the sessions a revocation just
   * deleted. The relay (both ends) is closed and the agent told to close,
   * like closeSessionsForUser, but the user's OTHER sessions are untouched.
   */
  async closeSessionsForSessionHashes(hashes: ReadonlyArray<string>, reason: string): Promise<number> {
    const wanted = new Set(hashes);
    if (wanted.size === 0) return 0;
    const tokens = new Set<string>();
    for (const [token, entry] of this.tunnels) {
      if (entry.browserSessionHash && wanted.has(entry.browserSessionHash)) tokens.add(token);
    }
    const ids = new Set<string>();
    for (const [id, h] of this.creatorSessions) if (wanted.has(h)) ids.add(id);
    if (tokens.size === 0 && ids.size === 0) return 0;
    const closeRelay = (token: string) => this.closeRelay(token, {
      type: 'error', code: 'session_closed', retry: false,
      message: `Remote session closed (${safeText(reason, 60)})`,
    });
    const rows = await db('remote_sessions')
      .whereIn('status', ['waiting', 'connecting', 'active'])
      .where((q) => {
        if (tokens.size > 0) q.orWhereIn('session_token', [...tokens]);
        if (ids.size > 0) q.orWhereIn('id', [...ids]);
      })
      .select('id', 'tenant_id', 'session_token') as Array<{ id: string; tenant_id: number; session_token: string }>;
    for (const row of rows) {
      try {
        closeRelay(row.session_token);
        tokens.delete(row.session_token);
        await this.endSession(row.id, row.tenant_id, reason);
      } catch (err) {
        logger.warn({ err, sessionId: row.id }, 'remote session close (device key revoked) failed');
      }
    }
    for (const token of tokens) closeRelay(token); // relay still up, row already closed
    for (const id of ids) this.creatorSessions.delete(id);
    return rows.length;
  }

  // Expire stale sessions and notify the UI
  async cleanupStaleSessions() {
    const timeout = await db('app_config').where({ key: 'remote_session_timeout_minutes' }).first();
    const minutes = parseInt(timeout?.value || '60');
    const now = new Date();

    // "waiting" sessions: short fuse (6 min) — the open_remote_tunnel command expires
    // in 5 min, so after 6 min a waiting session is definitively stuck.
    const timedOutWaiting = await db('remote_sessions')
      .where({ status: 'waiting' })
      .where('started_at', '<', new Date(Date.now() - 6 * 60 * 1000))
      .update({ status: 'timeout', ended_at: now, end_reason: 'timeout' })
      .returning('*');

    // "connecting" sessions: use the admin-configured timeout
    const timedOutConnecting = await db('remote_sessions')
      .where({ status: 'connecting' })
      .where('started_at', '<', new Date(Date.now() - minutes * 60 * 1000))
      .update({ status: 'timeout', ended_at: now, end_reason: 'timeout' })
      .returning('*');

    // Notify UI for each session that was timed out, and hang up a browser
    // still waiting on the relay (it used to wait forever) — with the reason.
    const allTimedOut = [...(timedOutWaiting || []), ...(timedOutConnecting || [])];
    for (const row of allTimedOut) {
      this.closeRelay(row.session_token, {
        type: 'error', code: 'agent_timeout', retry: false,
        message: 'The agent did not open the session in time.',
      });
      this.creatorSessions.delete(String(row.id));
      this.emitSessionEvent(SocketEvents.REMOTE_SESSION_UPDATED, row);
    }
  }

  /**
   * At server start no relay exists in this process: 'active' sessions are
   * leftovers of the previous run (their relay died with it). Close them
   * with reason 'server_restart'. ObliReach sessions are skipped when a
   * standalone relay (OBLIREACH_RELAY_URL) may still carry them.
   */
  async closeOrphanedSessionsAtBoot(): Promise<number> {
    const q = db('remote_sessions').where({ status: 'active' });
    if (process.env.OBLIREACH_RELAY_URL) q.whereNot({ protocol: 'oblireach' });
    const rows = await q.update({
      status: 'closed',
      ended_at: new Date(),
      end_reason: 'server_restart',
      duration_seconds: db.raw('COALESCE(EXTRACT(EPOCH FROM (NOW() - connected_at))::int, 0)'),
    }).returning('*');
    for (const row of rows || []) this.emitSessionEvent(SocketEvents.REMOTE_SESSION_UPDATED, row);
    if (rows?.length) logger.info({ count: rows.length }, 'Remote sessions left active by the previous run closed (server_restart)');
    return rows?.length ?? 0;
  }

  /**
   * `tunnel_failed` from an ObliReach command channel: the agent could not
   * open the session (helper spawn, relay refused…). Honoured only for a
   * session whose DEVICE is the channel's (uuid, tenant, key binding — the
   * same rule as the channel itself): the session is marked failed with
   * end_reason `agent_error:<code>`, the change is emitted, and an attached
   * browser gets {"type":"error","code":"agent_error"} and is closed.
   */
  async failSessionFromAgent(
    sessionToken: string,
    code: string,
    message: string,
    channel: { deviceUuid: string; tenantId: number; apiKeyId: number | null },
  ): Promise<boolean> {
    const row = await db('remote_sessions as rs')
      .join('devices as d', 'd.id', 'rs.device_id')
      .where('rs.session_token', sessionToken)
      .first('rs.id', 'rs.status', 'rs.protocol', 'rs.connected_at',
        'd.uuid as device_uuid', 'd.tenant_id as device_tenant_id', 'd.api_key_id as device_api_key_id');
    if (!row || row.protocol !== 'oblireach') return false;
    const keyOk = channel.apiKeyId != null
      ? agentKeyMayActForDevice({ id: channel.apiKeyId, tenant_id: channel.tenantId }, { tenant_id: row.device_tenant_id, api_key_id: row.device_api_key_id })
      : row.device_api_key_id == null && Number(row.device_tenant_id) === Number(channel.tenantId);
    if (row.device_uuid !== channel.deviceUuid || !keyOk) {
      logger.warn({ sessionId: row.id, deviceUuid: channel.deviceUuid }, 'ObliReach tunnel_failed ignored: session of another device');
      return false;
    }
    if (!OPEN_STATUSES.includes(row.status)) return false;
    const agentCode = safeCode(code);
    const text = safeText(message, 300);
    const duration = row.connected_at ? Math.floor((Date.now() - new Date(row.connected_at).getTime()) / 1000) : 0;
    const [updated] = await db('remote_sessions').where({ id: row.id }).whereIn('status', OPEN_STATUSES)
      .update({ status: 'failed', ended_at: new Date(), duration_seconds: duration, end_reason: `agent_error:${agentCode}`.slice(0, 100) })
      .returning('*');
    if (!updated) return false;
    const retry = RETRYABLE_AGENT_CODES.has(agentCode);
    this.closeRelay(sessionToken, {
      type: 'error', code: 'agent_error', agentCode, retry,
      message: text || `The agent could not open the session (${agentCode}).`,
    });
    this.creatorSessions.delete(String(row.id));
    this.emitSessionEvent(SocketEvents.REMOTE_SESSION_UPDATED, updated);
    logger.warn({ sessionId: row.id, code: agentCode, message: text }, 'ObliReach session failed on the agent (tunnel_failed)');
    return true;
  }

  /**
   * A failed open_remote_tunnel ack (WS command channel or HTTP push) for a
   * session of `deviceId`: the session is failed — also when already
   * 'active' (shell tunnels dial the relay before spawning the shell) — with
   * the agent's error in end_reason, and an attached browser gets the text.
   * When the relay close already ended it ('agent_disconnect'), only the
   * reason is completed. Returns the failed row (null: nothing changed).
   */
  async failSessionFromCommandAck(sessionToken: string, deviceId: number, errorText?: string): Promise<any | null> {
    const text = safeText(errorText, 200);
    const reason = (text ? `command_failure: ${text}` : 'command_failure').slice(0, 100);
    const [updated] = await db('remote_sessions')
      .where({ session_token: sessionToken, device_id: deviceId })
      .whereIn('status', OPEN_STATUSES)
      .update({ status: 'failed', ended_at: new Date(), end_reason: reason })
      .returning('*');
    if (updated) {
      this.closeRelay(sessionToken, {
        type: 'error', code: 'agent_error', retry: false,
        message: text || 'The agent could not open the session.',
      });
      this.creatorSessions.delete(String(updated.id));
      this.emitSessionEvent(SocketEvents.REMOTE_SESSION_UPDATED, updated);
      return updated;
    }
    if (text) {
      await db('remote_sessions')
        .where({ session_token: sessionToken, device_id: deviceId })
        .whereIn('status', ['closed', 'expired'])
        .whereIn('end_reason', ['agent_disconnect', 'browser_disconnect'])
        .where('ended_at', '>', new Date(Date.now() - 2 * 60_000))
        .update({ end_reason: reason });
    }
    return null;
  }
}

export const remoteService = new RemoteService();
