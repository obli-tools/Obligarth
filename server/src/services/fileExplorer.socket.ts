import type { SocketConnection } from '../socket';
import { logger } from '../utils/logger';
import { clientIp } from '../utils/clientIp';
import { sessionHash } from '../utils/sessionHash';
import { fileExplorerService } from './fileExplorer.service';
import { FILE_EXPLORER_COMMANDS, authorizeExplorerCommand, type ExplorerFailure } from './fileExplorerGate.service';

/** File explorer commands (Socket.io), installed on every connection by
 *  modules/rmm.ts (registerSocketHandler). */
export function installFileExplorerSocketHandlers({ socket, user, sid, liveSession }: SocketConnection): void {
  // ── File explorer commands ──────────────────────────────────────────────
  // FILE_EXPLORER_CMD {requestId, deviceId, commandType, payload}
  //   → FILE_EXPLORER_RESULT {id: requestId, commandType, status, result}
  // Authorized PER DEVICE (fileExplorerGate.service.ts), not against the
  // tenant frozen at the handshake: the live session, the user's live
  // state, the device's tenant membership + capability 'files' (admins:
  // any device), then the tenant's restriction on `command.<type>`
  // ('sensitive' needs this session's step-up grant, 'restricted' is
  // refused). Every refusal is answered with a FILE_EXPLORER_RESULT failure
  // {error, code[, action]} — before, the client only saw its own timeout.
  // The client's address for the audit (read now: the handshake request's
  // socket may be gone once the transport upgraded).
  const explorerIp = (() => { try { return clientIp(socket.request) || undefined; } catch { return undefined; } })();
  socket.on('FILE_EXPLORER_CMD', async (payload: { requestId?: unknown; deviceId?: unknown; commandType?: unknown; payload?: unknown; audit?: unknown }) => {
    const requestId = typeof payload?.requestId === 'string' && payload.requestId.length > 0 && payload.requestId.length <= 64
      ? payload.requestId : undefined;
    const commandType = typeof payload?.commandType === 'string' ? payload.commandType.slice(0, 64) : undefined;
    const fail = (failure: ExplorerFailure) => {
      socket.emit('FILE_EXPLORER_RESULT', { id: requestId, commandType, status: 'failure', result: failure });
    };
    try {
      const raw = payload?.payload;
      if (!payload || typeof payload !== 'object' || !commandType
        || (raw !== undefined && (raw === null || typeof raw !== 'object' || Array.isArray(raw)))) {
        fail({ error: 'Invalid request', code: 'invalid' });
        return;
      }
      // SECURITY: this channel pushes the command straight to the agent, so
      // only the file-explorer command types may travel through it. Without
      // this list any caller could push `run_script` (or anything else) here,
      // bypassing the `execute` capability, restrictions and approvals.
      if (!FILE_EXPLORER_COMMANDS.has(commandType)) {
        logger.warn({ userId: user.id, commandType }, 'FILE_EXPLORER_CMD: rejected non file-explorer command type');
        fail({ error: 'Command not allowed on the file explorer channel', code: 'invalid' });
        return;
      }
      const sess = await liveSession();
      if (!sess) { fail({ error: 'Session expired', code: 'session' }); return; }
      const decision = await authorizeExplorerCommand({
        userId: user.id,
        sessionHash: sid ? sessionHash(sid) : null,
        clientIp: explorerIp ?? null,
        sessionTenantId: Number(sess.currentTenantId) || null,
        deviceId: payload.deviceId,
        commandType,
      });
      if (!decision.ok) { fail(decision.failure); return; }
      const device = decision.device;

      // The command's own fields only: the privacy unlock token is the
      // server's to attach (fileExplorerService), never the client's.
      const p: Record<string, any> = { ...((raw as Record<string, any> | undefined) ?? {}) };
      delete p.unlockToken;
      // Mutating operations are always audited server-side: the client-sent
      // `audit` block is ignored (it could be omitted by a crafted client).
      // Filed in the DEVICE's tenant (a master-tenant admin's god view).
      const mutating = commandType !== 'list_directory';
      const audit = mutating
        ? {
            action: `file_explorer.${commandType}`,
            resourceType: typeof p.path === 'string' && p.path.endsWith('/') ? 'directory' : 'file',
            resourcePath: String(p.path || p.oldPath || '').slice(0, 1024),
            details: p.newPath ? { newPath: String(p.newPath).slice(0, 1024) } : undefined,
            userId: user.id,
            ipAddress: explorerIp,
          }
        : undefined;
      await fileExplorerService.send(
        device.id, device.tenant_id, socket.id,
        commandType, p,
        audit,
        requestId,
        user.id,
      );
    } catch (err) {
      logger.error({ err, userId: user.id, commandType }, 'FILE_EXPLORER_CMD failed');
      fail({ error: 'File explorer request failed', code: 'error' });
    }
  });

  socket.on('disconnect', async () => {
    fileExplorerService.removeSocket(socket.id);
  });
}
