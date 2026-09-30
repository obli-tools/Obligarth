import type { SocketConnection } from '../socket';
import { permissionService } from './permission.service';

/** Custom sections' live output streams (Socket.io), installed on every
 *  connection by modules/rmm.ts (registerSocketHandler). */
export function installCustomSectionSocketHandlers({ socket, user, tenantId, isAdmin, verifyDevice }: SocketConnection): void {
  // ── Custom Sections (live output streams) ─────────────────────────────
  socket.on('CUSTOM_SECTION_OPEN', async (
    payload: { deviceId: number; sectionId: number; cols?: number; rows?: number },
    ack?: (res: any) => void,
  ) => {
    if (!payload?.deviceId || !payload?.sectionId || !tenantId) {
      ack?.({ error: 'invalid request' });
      return;
    }
    if (!await verifyDevice(payload.deviceId)) { ack?.({ error: 'device not found' }); return; }
    if (!isAdmin) {
      const allowed = await permissionService.canUseCapability(user.id, payload.deviceId, false, 'execute');
      if (!allowed) { ack?.({ error: 'permission denied' }); return; }
    }
    const { customSectionStreamService } = await import('./customSectionStream.service');
    const res = await customSectionStreamService.open({
      deviceId: payload.deviceId,
      sectionId: payload.sectionId,
      tenantId,
      socketId: socket.id,
      userId: user.id,
      cols: payload.cols || 120,
      rows: payload.rows || 30,
    });
    ack?.(res);
  });

  socket.on('CUSTOM_SECTION_CLOSE', async (payload: { streamId: string }) => {
    if (!payload?.streamId) return;
    const { customSectionStreamService } = await import('./customSectionStream.service');
    customSectionStreamService.close(payload.streamId);
  });

  socket.on('CUSTOM_SECTION_RESIZE', async (payload: { streamId: string; cols: number; rows: number }) => {
    if (!payload?.streamId) return;
    const { customSectionStreamService } = await import('./customSectionStream.service');
    customSectionStreamService.resize(payload.streamId, payload.cols, payload.rows);
  });

  socket.on('disconnect', async () => {
    try {
      const { customSectionStreamService } = await import('./customSectionStream.service');
      customSectionStreamService.removeSocket(socket.id);
    } catch {}
  });
}
