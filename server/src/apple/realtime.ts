import { SocketEvents } from '@obligarth/shared';
import { getIO } from '../socket';
import { logger } from '../utils/logger';

// =============================================================================
// Realtime events of the Apple integration (docs: integration-apple-edge §12.4,
// I12): identifiers only; the client reads the objects back through the REST
// routes, which apply the scopes and the capabilities. Never the legacy
// DEVICE_* emissions for an Apple record (gap 5 of conception §6.2).
//   APPLE_DEVICE_CHANGED        tenant:<id>        { deviceIds }
//   MDM_COMMAND_CHANGED         tenant:<id>        { commandIds, deviceIds }
//   ENROLLMENT_SESSION_CHANGED  tenant:<id>:admin  { sessionIds }
//   INTEGRATION_CHANGED         tenant:<id>:admin  { kinds }
// The outbox handlers call it through ctx.afterCommit, the routes and jobs
// after their commit. The identifiers are grouped per tenant and event until
// the next turn of the event loop (setImmediate): the effects of one batch of
// the outbox, run one after the other after its commit, leave as one message
// per tenant and event. Best effort, in memory: no Socket.io in the process
// (a CLI, the jobs-only mode) drops them.
// =============================================================================

export type IntegrationKind = 'push' | 'ade' | 'vpp' | 'edge' | 'deadlines';

interface Pending {
  devices: Set<number>;
  commands: Set<string>;
  commandDevices: Set<number>;
  sessions: Set<string>;
  kinds: Set<IntegrationKind>;
}

/** Largest number of identifiers of one message (a bigger group is split). */
const MAX_IDS = 500;

const pending = new Map<number, Pending>();
let scheduled = false;

const validTenant = (tenantId: number): boolean => Number.isSafeInteger(tenantId) && tenantId > 0;

function slot(tenantId: number): Pending {
  let p = pending.get(tenantId);
  if (!p) {
    p = { devices: new Set(), commands: new Set(), commandDevices: new Set(), sessions: new Set(), kinds: new Set() };
    pending.set(tenantId, p);
  }
  if (!scheduled) {
    scheduled = true;
    setImmediate(flush);
  }
  return p;
}

function chunks<T>(values: Iterable<T>): T[][] {
  const all = [...values];
  const out: T[][] = [];
  for (let i = 0; i < all.length; i += MAX_IDS) out.push(all.slice(i, i + MAX_IDS));
  return out;
}

function flush(): void {
  scheduled = false;
  const batch = [...pending.entries()];
  pending.clear();
  let io: ReturnType<typeof getIO>;
  try {
    io = getIO();
  } catch {
    return;                                            // no Socket.io in this process
  }
  for (const [tenantId, p] of batch) {
    try {
      const room = io.to(`tenant:${tenantId}`);
      const admin = io.to(`tenant:${tenantId}:admin`);
      for (const deviceIds of chunks(p.devices)) room.emit(SocketEvents.APPLE_DEVICE_CHANGED, { deviceIds });
      if (p.commands.size > 0) {
        const deviceIds = [...p.commandDevices].slice(0, MAX_IDS);
        for (const commandIds of chunks(p.commands)) room.emit(SocketEvents.MDM_COMMAND_CHANGED, { commandIds, deviceIds });
      }
      for (const sessionIds of chunks(p.sessions)) admin.emit(SocketEvents.ENROLLMENT_SESSION_CHANGED, { sessionIds });
      if (p.kinds.size > 0) admin.emit(SocketEvents.INTEGRATION_CHANGED, { kinds: [...p.kinds] });
    } catch (err) {
      logger.warn({ tenantId, err: (err as Error)?.message }, 'apple realtime: emission failed');
    }
  }
}

export const realtime = {
  deviceChanged(tenantId: number, ...deviceIds: Array<number | null | undefined>): void {
    if (!validTenant(tenantId)) return;
    const ids = deviceIds.filter((d): d is number => Number.isSafeInteger(d) && (d as number) > 0);
    if (ids.length === 0) return;
    const p = slot(tenantId);
    for (const d of ids) p.devices.add(d);
  },
  commandChanged(tenantId: number, commandIds: string[], deviceIds: number[]): void {
    if (!validTenant(tenantId) || commandIds.length === 0) return;
    const p = slot(tenantId);
    for (const c of commandIds) if (/^[0-9a-f-]{36}$/i.test(c)) p.commands.add(c.toLowerCase());
    for (const d of deviceIds) if (Number.isSafeInteger(d) && d > 0) p.commandDevices.add(d);
  },
  sessionChanged(tenantId: number, ...sessionIds: Array<string | null | undefined>): void {
    if (!validTenant(tenantId)) return;
    const ids = sessionIds.filter((s): s is string => typeof s === 'string' && /^[0-9a-f-]{36}$/i.test(s));
    if (ids.length === 0) return;
    const p = slot(tenantId);
    for (const s of ids) p.sessions.add(s.toLowerCase());
  },
  integrationChanged(tenantId: number, ...kinds: IntegrationKind[]): void {
    if (!validTenant(tenantId) || kinds.length === 0) return;
    const p = slot(tenantId);
    for (const k of kinds) p.kinds.add(k);
  },
};
