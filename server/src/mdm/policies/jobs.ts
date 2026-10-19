import { setTimeout as sleep } from 'node:timers/promises';
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

/** Rounds of a tenant's resolution that skip the device rows another transaction holds (MDM-B5c-R13). */
const SKIP_LOCKED_ROUNDS = 4;
/** Attempts of one slice when PostgreSQL chooses it as the victim of a deadlock (40P01). */
const DEADLOCK_ATTEMPTS = 5;

const isDeadlock = (err: unknown): boolean => (err as { code?: unknown })?.code === '40P01';

/** fn again when PostgreSQL cancels it to break a deadlock (40P01), a few times, with a short growing pause. */
export async function retryOnDeadlock<T>(fn: () => Promise<T>, attempts = DEADLOCK_ATTEMPTS): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (!isDeadlock(err) || attempt >= attempts) throw err;
      await sleep(50 * attempt + Math.floor(Math.random() * 50));
    }
  }
}

/**
 * Resolution of every device of the tenant, by slices (each slice locked, loaded, resolved and written in its
 * transaction). The assignments and resources are read once.
 *
 * Locks (review of the integration of lot B, MDM-B5c-R13): a slice writes the rows of its devices (their effective
 * state, their artifacts) under their row locks, taken in ascending order; the outbox consumer keeps the rows its
 * events locked (mdm.seen_batch, the results of commands) until its batch commits, in the order of the events. A
 * slice that waited on a row the consumer holds, while holding one the consumer wants, ended in a deadlock and the
 * whole tenant was retried. Now a slice takes only the rows nobody holds (FOR UPDATE SKIP LOCKED: it never waits
 * on a row lock), and the devices it skipped are taken by the next rounds; the last round waits for them, in
 * ascending order, and a slice cancelled by a deadlock is played again alone (retryOnDeadlock) rather than the
 * tenant.
 */
export async function resolveTenant(ctx: Pick<JobContext<unknown>, 'inTenant' | 'withTenant' | 'throwIfAborted'>, tenantId: number):
  Promise<{ devices: number; changed: number[]; upserted: number; deleted: number; deferred: number }> {
  const ids = await ctx.inTenant(async () => (await db('devices').where({ tenant_id: tenantId }).whereNot('enrollment_state', 'unenrolled')
    .orderBy('id').pluck('id') as number[]).map(Number));
  const state = await ctx.inTenant(() => loadPolicyState(db, tenantId));
  const out = { devices: ids.length, changed: [] as number[], upserted: 0, deleted: 0, deferred: 0 };
  let pending = ids;
  for (let round = 1; pending.length > 0; round++) {
    const wait = round > SKIP_LOCKED_ROUNDS;
    const skipped: number[] = [];
    for (let i = 0; i < pending.length; i += SLICE) {
      ctx.throwIfAborted();
      const slice = pending.slice(i, i + SLICE);
      const s = await retryOnDeadlock(() => ctx.withTenant(async (trx) => {
        await lockDevices(trx, slice);
        // The rows of the slice nobody else holds (all of them in the last round, waited for in ascending order).
        const held = await trx('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [slice]).orderBy('id')
          .modify((q) => { if (wait) q.forUpdate(); else q.forUpdate().skipLocked(); })
          .pluck('id') as number[];
        const mine = new Set(held.map(Number));
        const busy = slice.filter((d) => !mine.has(d));
        if (mine.size === 0) return { busy, w: null };
        const set = await loadDevices(trx, tenantId, slice.filter((d) => mine.has(d)));
        const catalog = appleCatalog();
        const w = await writeResolution(trx, tenantId, resolveDevices({ ...state, ...set, catalog }), { devices: set.devices, tenant: state.tenant, catalog });
        return { busy, w };
      }));
      skipped.push(...s.busy);
      if (s.w) {
        out.changed.push(...new Set([...s.w.changedDeviceIds, ...s.w.artifactDeviceIds]));
        out.upserted += s.w.upserted;
        out.deleted += s.w.deleted;
      }
    }
    if (round === 1) out.deferred = skipped.length;
    pending = wait ? [] : skipped;
    // The transactions that held them commit in a moment (a batch of the consumer): a short pause between rounds.
    if (pending.length > 0) await sleep(100 * round);
  }
  // The conflicts stored for the tenant: their alerts raised, those of the conflicts gone resolved (section 7.7).
  await retryOnDeadlock(() => ctx.withTenant((trx) => syncConflictAlerts(trx, tenantId, null)));
  return out;
}

/** Resolution of one device, in `trx` (its tenant's context). */
export async function resolveDeviceInTx(trx: Knex.Transaction, tenantId: number, deviceIds: number[]):
  Promise<{ changed: number[]; upserted: number; deleted: number }> {
  await lockDevices(trx, deviceIds);
  const state = await loadPolicyState(trx, tenantId);
  const set = await loadDevices(trx, tenantId, deviceIds);
  const catalog = appleCatalog();
  const s = await writeResolution(trx, tenantId, resolveDevices({ ...state, ...set, catalog }), { devices: set.devices, tenant: state.tenant, catalog });
  if (s.changedDeviceIds.length) await syncConflictAlerts(trx, tenantId, s.changedDeviceIds);
  return { changed: [...new Set([...s.changedDeviceIds, ...s.artifactDeviceIds])].sort((a, b) => a - b), upserted: s.upserted, deleted: s.deleted };
}

async function runTenant(ctx: JobContext<z.infer<typeof TenantPayload>>): Promise<JobResult> {
  try {
    const r = await resolveTenant(ctx, ctx.payload.tenantId);
    emitConfigChanged(ctx.payload.tenantId, r.changed);
    return { output: { devices: r.devices, changed: r.changed.length, upserted: r.upserted, deleted: r.deleted, deferred: r.deferred } };
  } finally {
    fetchNext(TENANT_QUEUE);
  }
}

async function runDevice(ctx: JobContext<z.infer<typeof DevicePayload>>): Promise<JobResult> {
  try {
    const r = await retryOnDeadlock(() => ctx.withTenant((trx) => resolveDeviceInTx(trx, ctx.payload.tenantId, [ctx.payload.deviceId])));
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

