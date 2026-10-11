import type { Knex } from 'knex';
import { z } from 'zod';
import { SocketEvents } from '@obligarth/shared';
import { db } from '../../db';
import { defaultRuntime, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { getIO } from '../../socket';
import { appleCatalog } from '../apple/catalog';
import { syncConflictAlerts } from './alerts';
import { loadDevices, loadPolicyState } from './loader';
import { resolveDevices } from './resolver';
import { lockDevices, writeResolution } from './writer';

// =============================================================================
// Queues of the resolution (docs: modele-donnees-mdm §7.12, §10.5; file
// durable §5.1, motifs M5 and M8):
//   mdm.policies.resolve-tenant  publication, change of assignments, archival:
//                                every device of the tenant, by slices of 200,
//                                each in its transaction (stately, t:<id>),
//                                never a delta in the payload;
//   mdm.policies.resolve-device  onboarding, group, ownership, supervision, OS,
//                                DDM capabilities, end user: one device
//                                (stately, t:<id>:d:<device>).
// Payloads carry internal identifiers only. The effective state they write is
// announced to the tenant's room (DEVICE_CONFIG_CHANGED, identifiers only).
// Both queues are woken by NOTIFY when a job is sent (every job can run at
// once: triggers.ts) and polled every five minutes only (a retry that became
// due; file-durable L3). Requests committed together are announced once, and
// a worker that ran one job would wait for its next poll before the others:
// each run ends by waking its queue, which empties without waiting.
// =============================================================================

const SLICE = 200;

/** Polling interval of the two queues: nothing waits for it but the retry of a failed job. */
const IDLE_POLL_SECONDS = 300;

const TENANT_QUEUE = 'mdm.policies.resolve-tenant';
const DEVICE_QUEUE = 'mdm.policies.resolve-device';

/** The worker of `queue` fetches again as soon as the running job ends (no effect in a process without workers). */
function fetchNext(queue: string): void {
  try { defaultRuntime.wake(queue); } catch { /* the runtime is stopping */ }
}

const TenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();
const DevicePayload = z.object({ tenantId: z.number().int().positive(), deviceId: z.number().int().positive() }).strict();

let tenantJob: JobHandle<z.infer<typeof TenantPayload>> | null = null;
let deviceJob: JobHandle<z.infer<typeof DevicePayload>> | null = null;

/** DEVICE_CONFIG_CHANGED to the tenant's room (identifiers only); never throws. */
export function emitConfigChanged(tenantId: number, deviceIds: number[]): void {
  if (!deviceIds.length) return;
  try {
    for (let i = 0; i < deviceIds.length; i += 1000) {
      getIO().to(`tenant:${tenantId}`).emit(SocketEvents.DEVICE_CONFIG_CHANGED, { deviceIds: deviceIds.slice(i, i + 1000) });
    }
  } catch { /* no Socket.io in this process */ }
}

/** Resolution of every device of the tenant, by slices (each slice locked, loaded, resolved and written in its
 *  transaction). The assignments and resources are read once. */
export async function resolveTenant(ctx: Pick<JobContext<unknown>, 'inTenant' | 'withTenant' | 'throwIfAborted'>, tenantId: number):
  Promise<{ devices: number; changed: number[]; upserted: number; deleted: number }> {
  const ids = await ctx.inTenant(async () => (await db('devices').where({ tenant_id: tenantId }).whereNot('enrollment_state', 'unenrolled')
    .orderBy('id').pluck('id') as number[]).map(Number));
  const state = await ctx.inTenant(() => loadPolicyState(db, tenantId));
  const out = { devices: ids.length, changed: [] as number[], upserted: 0, deleted: 0 };
  for (let i = 0; i < ids.length; i += SLICE) {
    ctx.throwIfAborted();
    const slice = ids.slice(i, i + SLICE);
    const s = await ctx.withTenant(async (trx) => {
      await lockDevices(trx, slice);
      const set = await loadDevices(trx, tenantId, slice);
      return writeResolution(trx, tenantId, resolveDevices({ ...state, ...set, catalog: appleCatalog() }));
    });
    out.changed.push(...s.changedDeviceIds);
    out.upserted += s.upserted;
    out.deleted += s.deleted;
  }
  // The conflicts stored for the tenant: their alerts raised, those of the conflicts gone resolved (section 7.7).
  await ctx.withTenant((trx) => syncConflictAlerts(trx, tenantId, null));
  return out;
}

/** Resolution of one device, in `trx` (its tenant's context). */
export async function resolveDeviceInTx(trx: Knex.Transaction, tenantId: number, deviceIds: number[]):
  Promise<{ changed: number[]; upserted: number; deleted: number }> {
  await lockDevices(trx, deviceIds);
  const state = await loadPolicyState(trx, tenantId);
  const set = await loadDevices(trx, tenantId, deviceIds);
  const s = await writeResolution(trx, tenantId, resolveDevices({ ...state, ...set, catalog: appleCatalog() }));
  if (s.changedDeviceIds.length) await syncConflictAlerts(trx, tenantId, s.changedDeviceIds);
  return { changed: s.changedDeviceIds, upserted: s.upserted, deleted: s.deleted };
}

async function runTenant(ctx: JobContext<z.infer<typeof TenantPayload>>): Promise<JobResult> {
  try {
    const r = await resolveTenant(ctx, ctx.payload.tenantId);
    emitConfigChanged(ctx.payload.tenantId, r.changed);
    return { output: { devices: r.devices, changed: r.changed.length, upserted: r.upserted, deleted: r.deleted } };
  } finally {
    fetchNext(TENANT_QUEUE);
  }
}

async function runDevice(ctx: JobContext<z.infer<typeof DevicePayload>>): Promise<JobResult> {
  try {
    const r = await ctx.withTenant((trx) => resolveDeviceInTx(trx, ctx.payload.tenantId, [ctx.payload.deviceId]));
    emitConfigChanged(ctx.payload.tenantId, r.changed);
    return { output: { changed: r.changed.length, upserted: r.upserted, deleted: r.deleted } };
  } finally {
    fetchNext(DEVICE_QUEUE);
  }
}

let registered = false;

export function registerPolicyJobs(): void {
  if (registered) return;
  registered = true;
  tenantJob = registerJob({
    name: TENANT_QUEUE,
    scope: 'tenant',
    description: 'Resolve the policies of every device of a tenant (effective configuration)',
    payload: TenantPayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 30, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 900,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    concurrency: { perTenant: 1 },
    handler: runTenant,
  });
  deviceJob = registerJob({
    name: DEVICE_QUEUE,
    scope: 'tenant',
    description: 'Resolve the policies of one device (effective configuration)',
    payload: DevicePayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 10, backoff: true, maxDelaySeconds: 300 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: runDevice,
  });
}

/** The handles (registerMdmModule must have run); null otherwise. */
export const resolveTenantJob = (): JobHandle<z.infer<typeof TenantPayload>> | null => tenantJob;
export const resolveDeviceJob = (): JobHandle<z.infer<typeof DevicePayload>> | null => deviceJob;

