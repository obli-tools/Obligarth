import type { IncomingMessage } from 'http';
import type { Duplex } from 'stream';
import { WebSocketServer } from 'ws';
import type { WebSocket } from 'ws';
import { db } from '../db';
import { clientIp } from '../utils/clientIp';
import { logger } from '../utils/logger';
import { deviceService } from './device.service';
import { agentHub } from './agentHub.service';

// ── Agent command channel: raw WebSocket upgrade ────────────────────────────
// /api/agent/ws, served next to Socket.io on the same port by the upgrade
// dispatcher (lifecycle.ts). Registered by modules/rmm.ts.

const agentWss = new WebSocketServer({ noServer: true, maxPayload: 150 * 1024 * 1024 });

const AGENT_CMD_RE       = /^\/api\/agent\/ws$/;

/** Upgrade handler of the agent command channel (registerUpgradeHandler). */
export function agentChannelUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer, pathname: string): boolean {
  // ── Agent command channel ───────────────────────────────────────────────
  if (!AGENT_CMD_RE.test(pathname)) return false;
  const apiKey = request.headers['x-api-key'] as string | undefined;
  agentWss.handleUpgrade(request, socket, head, async (ws: WebSocket) => {
    try {
      if (!apiKey) { ws.close(4003, 'Missing X-Api-Key'); return; }
      // Note: no is_active check here — matches agentAuth middleware which also omits it.
      // is_active may be NULL on older keys; requiring true would silently block WS while
      // HTTP push (which uses agentAuth) succeeds — causing the agent to reconnect every 10s.
      const keyRow = await db('agent_api_keys').where({ key: apiKey }).first();
      if (!keyRow || keyRow.is_active === false) { ws.close(4003, 'Invalid API key'); return; }
      const deviceUuid = request.headers['x-device-uuid'] as string | undefined;
      let device = deviceUuid
        ? await db('devices').where({ uuid: deviceUuid, tenant_id: keyRow.tenant_id }).first()
        : await db('devices').where({ api_key_id: keyRow.id }).first();

      // SECURITY: if a device row exists but was registered with a
      // DIFFERENT api_key_id, the agent is presenting a UUID it
      // doesn't own. Treat as auth failure rather than silently
      // letting a foreign key claim the device. (The previous
      // behaviour would have re-attached the device to whichever
      // key talked to it last — an attacker who knew a target
      // device's UUID + had any valid API key in the same tenant
      // could intercept its command channel.)
      if (device && device.api_key_id != null && device.api_key_id !== keyRow.id) {
        ws.close(4003, 'Device/API-key mismatch');
        return;
      }

      // No device row yet — this can happen if the WS channel reaches the
      // server before the first HTTP push (fresh install, flaky HTTP, HTTPS
      // misconfig on an HTTP-only agent, etc.). Auto-register a minimal
      // pending row here so the device actually appears in the admin UI
      // for approval rather than silently spinning on 4004 forever.
      // Subsequent HTTP pushes will fill in hostname, OS, metrics.
      if (!device && deviceUuid) {
        const { deviceId } = await deviceService.registerDevice({
          uuid: deviceUuid,
          hostname: deviceUuid,
          osType: 'other',
          apiKeyId: keyRow.id,
          tenantId: keyRow.tenant_id,
        });
        device = await db('devices').where({ id: deviceId }).first();
        logger.info({ deviceId, uuid: deviceUuid }, 'Auto-registered device via WS channel');
      }

      if (!device) { ws.close(4004, 'Device not found'); return; }
      await agentHub.register(device.id, device.tenant_id, ws, keyRow.id, device.uuid, clientIp(request));
    } catch (err) {
      logger.error(err, 'Agent command channel setup error');
      ws.close(4000, 'Internal error');
    }
  });
  return true; // handled — do NOT forward to socket.io
}

/** At shutdown: no new agent channel is accepted. */
export function closeAgentChannelServer(): void {
  agentWss.close();
}
