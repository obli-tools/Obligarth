import type { IncomingMessage } from 'http';
import type { Duplex } from 'stream';
import { WebSocketServer } from 'ws';
import type { WebSocket } from 'ws';
import { db } from '../db';
import { clientIp } from '../utils/clientIp';
import { logger } from '../utils/logger';
import { oblireachHub } from './oblireachHub.service';
import { agentKeyMayActForDevice, isUuid } from './remoteSessionSecurity';

// ── ObliReach agent command channel: raw WebSocket upgrade ──────────────────
// /api/oblireach/ws, served next to Socket.io on the same port by the
// upgrade dispatcher (lifecycle.ts). Registered by modules/rmm.ts.

const oblireachWss = new WebSocketServer({ noServer: true, maxPayload: 150 * 1024 * 1024 });

const OBLIREACH_CMD_RE   = /^\/api\/oblireach\/ws$/;

/** Upgrade handler of the ObliReach command channel (registerUpgradeHandler). */
export function oblireachChannelUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer, pathname: string): boolean {
  // ── Oblireach agent command channel ────────────────────────────────────
  if (!OBLIREACH_CMD_RE.test(pathname)) return false;
  const clientIpOf = () => clientIp(request);
  const apiKey  = request.headers['x-api-key'] as string | undefined;
  const reqUrl  = new URL(request.url ?? '/', 'http://localhost');
  const devUuid = reqUrl.searchParams.get('uuid');
  oblireachWss.handleUpgrade(request, socket, head, async (ws: WebSocket) => {
    try {
      if (!apiKey)  { ws.close(4003, 'Missing X-Api-Key'); return; }
      if (!devUuid) { ws.close(4000, 'Missing uuid query param'); return; }
      // No is_active check — matches agentAuth middleware (is_active may be NULL on older keys).
      const keyRow = await db('agent_api_keys').where({ key: apiKey }).first();
      if (!keyRow || keyRow.is_active === false) { ws.close(4003, 'Invalid API key'); return; }
      // SECURITY: this channel receives open_remote_tunnel (relay token +
      // privacy unlock token). If the uuid belongs to an enrolled device,
      // the key must be the one that device is bound to (same rule as
      // /api/agent/ws) — otherwise any key could claim another device's
      // channel. A uuid with no devices row (standalone ObliReach agent)
      // is still accepted: no session can target it, and oblireachHub.push
      // re-checks the key binding before sending anything sensitive.
      if (isUuid(devUuid)) {
        const device = await db('devices').where({ uuid: devUuid }).first('id', 'tenant_id', 'api_key_id');
        if (device && !agentKeyMayActForDevice(keyRow, device)) {
          logger.warn({ deviceId: device.id, apiKeyId: keyRow.id, ip: clientIpOf() }, 'ObliReach command channel refused: device/API-key mismatch');
          ws.close(4003, 'Device/API-key mismatch');
          return;
        }
      }
      await oblireachHub.register(devUuid, keyRow.tenant_id, ws, keyRow.id);
    } catch (err) {
      logger.error(err, 'ObliReach command channel setup error');
      ws.close(4000, 'Internal error');
    }
  });
  return true; // handled — do NOT forward to socket.io
}

/** At shutdown: no new ObliReach channel is accepted. */
export function closeOblireachChannelServer(): void {
  oblireachWss.close();
}
