import type { IncomingMessage } from 'http';
import type { Duplex } from 'stream';
import { WebSocketServer } from 'ws';
import type { WebSocket } from 'ws';
import { getSessionMiddleware } from '../app';
import { clientIp } from '../utils/clientIp';
import { logger } from '../utils/logger';
import { remoteService } from './remote.service';
import { browserVerdictHttpStatus, rejectUpgrade } from './remoteSessionSecurity';

// ── Remote tunnels: raw WebSocket upgrades ──────────────────────────────────
// /api/remote/tunnel/<token> (browser) and /api/remote/agent-tunnel/<token>
// (agent), served next to Socket.io on the same port by the upgrade
// dispatcher (lifecycle.ts). Registered by modules/rmm.ts.

const remoteWss = new WebSocketServer({ noServer: true, maxPayload: 150 * 1024 * 1024 });

// Session-token pattern: 64 hex chars produced by crypto.randomBytes(32)
const BROWSER_RE    = /^\/api\/remote\/tunnel\/([0-9a-f]{64})$/;
const AGENT_RE      = /^\/api\/remote\/agent-tunnel\/([0-9a-f]{64})$/;

/** Upgrade handler of the two tunnel ends (registerUpgradeHandler). */
export function remoteTunnelUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer, pathname: string): boolean {
  const clientIpOf = () => clientIp(request);

  // ── Browser remote tunnel ──────────────────────────────────────────────
  // SECURITY: the token in the URL is NOT a credential on its own. The
  // upgrade must carry the express-session cookie of the user who STARTED
  // the session (same cookie as the REST API / socket.io), and the session
  // must still be open. A refusal is a plain HTTP 401/403/404 written
  // BEFORE the handshake (never a 101 then a close): the client gets no
  // `open`, so a viewer's retry counter is not reset by a tunnel it may not
  // use. The in-process SSH bastion does not come through here (it calls
  // registerBrowserTunnel directly).
  const browserMatch = BROWSER_RE.exec(pathname);
  if (browserMatch) {
    const sessionToken = browserMatch[1];
    // Authenticate BEFORE accepting the WebSocket so the browser tunnel is
    // registered synchronously in the handleUpgrade callback (no window
    // where early browser frames could be dropped). Node removed its own
    // 'error' listener before emitting 'upgrade': guard the socket while
    // we wait, or a client reset during the lookup would crash the process.
    const onEarlyError = () => socket.destroy();
    socket.on('error', onEarlyError);
    remoteService.authorizeBrowserTunnel(request, sessionToken, getSessionMiddleware())
      .then((verdict) => {
        socket.removeListener('error', onEarlyError);
        if (socket.destroyed) return;
        if (!verdict.ok) {
          if (verdict.code === 4003) {
            logger.warn({ sessionId: verdict.sessionId, userId: verdict.userId, ip: clientIpOf(), reason: verdict.reason },
              'Browser remote tunnel refused');
          }
          rejectUpgrade(socket, browserVerdictHttpStatus(verdict), verdict.reason);
          return;
        }
        remoteWss.handleUpgrade(request, socket, head, (ws: WebSocket) => {
          remoteService.registerBrowserTunnel(sessionToken, ws, { sessionHash: verdict.sessionHash, isWebSocket: true, clientIp: clientIpOf() });
          logger.info({ sessionId: verdict.sessionId, userId: verdict.userId }, 'Browser remote tunnel connected');
        });
      })
      .catch((err) => {
        logger.error(err, 'Browser remote tunnel setup error');
        socket.destroy();
      });
    return true; // handled — do NOT forward to socket.io
  }

  // ── Agent remote tunnel ────────────────────────────────────────────────
  // SECURITY: the X-Api-Key must be the key the session's DEVICE is bound
  // to (same rule as the /api/agent/ws channel), the session must still be
  // waiting for its agent, and only one agent may attach — a second "agent"
  // would otherwise receive every keystroke of the user. Refused before the
  // handshake, like the browser end.
  const agentMatch = AGENT_RE.exec(pathname);
  if (agentMatch) {
    const sessionToken = agentMatch[1];
    const apiKey = request.headers['x-api-key'] as string | undefined;
    const onEarlyError = () => socket.destroy();
    socket.on('error', onEarlyError);
    remoteService.authorizeAgentTunnel(apiKey, sessionToken)
      .then((verdict) => {
        socket.removeListener('error', onEarlyError);
        if (socket.destroyed) return;
        // Re-check in this tick: another agent may have attached while we
        // were reading the DB. handleUpgrade then calls back synchronously.
        if (verdict.ok && remoteService.hasLiveAgent(sessionToken)) {
          verdict = { ok: false, status: 409, reason: 'Agent already attached', sessionId: verdict.sessionId, deviceId: verdict.deviceId };
        }
        if (!verdict.ok) {
          if (verdict.status === 403 || verdict.status === 409) {
            logger.warn({ sessionId: verdict.sessionId, deviceId: verdict.deviceId, ip: clientIpOf(), reason: verdict.reason },
              'Agent remote tunnel refused');
          }
          rejectUpgrade(socket, verdict.status, verdict.reason);
          return;
        }
        const { sessionId, deviceId } = verdict;
        remoteWss.handleUpgrade(request, socket, head, (ws: WebSocket) => {
          if (!remoteService.registerAgentTunnel(sessionToken, ws)) {
            ws.close(4009, 'Agent already attached');
            return;
          }
          logger.info({ sessionId, deviceId }, 'Agent remote tunnel connected');
        });
      })
      .catch((err) => {
        logger.error(err, 'Agent remote tunnel setup error');
        socket.destroy();
      });
    return true; // handled — do NOT forward to socket.io
  }

  return false;
}

/** At shutdown: no new tunnel is accepted. */
export function closeRemoteTunnelServer(): void {
  remoteWss.close();
}
