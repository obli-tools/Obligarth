import { SocketEvents } from '@obliance/shared';
import type { SocketConnection } from '../socket';
import { permissionService } from './permission.service';
import { processService } from './process.service';

/** Live process list of a device (Socket.io), installed on every connection
 *  by modules/rmm.ts (registerSocketHandler). */
export function installProcessSocketHandlers({ socket, user, tenantId, isAdmin, verifyDevice }: SocketConnection): void {
  // ── Process list subscriptions (with permission check) ──────────────────
  socket.on(SocketEvents.PROCESS_SUBSCRIBE, async (payload: { deviceId: number }) => {
    if (!payload?.deviceId || !tenantId) return;
    // Verify device belongs to tenant and user has read access
    if (!await verifyDevice(payload.deviceId)) return;
    if (!isAdmin) {
      const canRead = await permissionService.canReadDevice(user.id, payload.deviceId, false);
      if (!canRead) return;
    }
    processService.subscribe(payload.deviceId, tenantId, socket.id, user.id);
  });
  socket.on(SocketEvents.PROCESS_UNSUBSCRIBE, (payload: { deviceId: number }) => {
    if (payload?.deviceId) {
      processService.unsubscribe(payload.deviceId, socket.id);
    }
  });

  socket.on('disconnect', async () => {
    processService.removeSocket(socket.id);
  });
}
