import { z } from 'zod';
import { SocketEvents } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { forEachTenant } from '../../db/tenantContext';
import { defaultRuntime, JobError, registerJob, type JobContext, type JobResult } from '../../jobs';
import { getIO } from '../../socket';
import { bindComplianceJob } from '../apple/requests';
import { evaluateDevices } from './evaluate';

// =============================================================================
// Queues of the minimal compliance (docs: modele-donnees-mdm §4.4, §10.5):
//   mdm.compliance.evaluate-device  tenant, stately t:<id>:d:<device>: a
//                                   result, a DDM status, the inventory or the
//                                   configuration of a device changed;
//   mdm.compliance.evaluate-all     platform, hourly: the reasons that come
//                                   with time and no event (a device that
//                                   stopped checking in, a deadline that
//                                   passed), tenant by tenant in the tenant's
//                                   context, by pages of 500 devices.
// Payloads: internal identifiers only. A state that changes is announced to
// the tenant's room (DEVICE_CONFIG_CHANGED, identifiers only).
// =============================================================================

const DEVICE_QUEUE = 'mdm.compliance.evaluate-device';
const ALL_QUEUE = 'mdm.compliance.evaluate-all';
const IDLE_POLL_SECONDS = 300;
const PAGE = 500;

const DevicePayload = z.object({ tenantId: z.number().int().positive(), deviceId: z.number().int().positive() }).strict();
const empty = z.object({}).strict();

function fetchNext(queue: string): void {
  try { defaultRuntime.wake(queue); } catch { /* the runtime is stopping */ }
}

function announce(tenantId: number, deviceIds: number[]): void {
  if (!deviceIds.length) return;
  try {
    for (let i = 0; i < deviceIds.length; i += 1000) {
      getIO().to(`tenant:${tenantId}`).emit(SocketEvents.DEVICE_CONFIG_CHANGED, { deviceIds: deviceIds.slice(i, i + 1000) });
    }
  } catch { /* no Socket.io in this process */ }
}

async function runDevice(ctx: JobContext<z.infer<typeof DevicePayload>>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  try {
    const r = await ctx.withTenant((trx) => evaluateDevices(trx, tenantId, [ctx.payload.deviceId]));
    announce(tenantId, r.changed);
    return { output: { evaluated: r.evaluated, changed: r.changed.length } };
  } finally {
    fetchNext(DEVICE_QUEUE);
  }
}

async function runAll(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let evaluated = 0;
  let changed = 0;
  const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    let cursor = 0;
    for (;;) {
      ctx.throwIfAborted();
      const ids = (await db('devices').where({ tenant_id: tenantId }).whereIn('enrollment_state', ['enrolled', 'awaiting_configuration'])
        .where('id', '>', cursor).orderBy('id').limit(PAGE).pluck('id') as number[]).map(Number);
      if (ids.length === 0) break;
      const r = await db.transaction((trx) => evaluateDevices(trx, tenantId, ids));
      evaluated += r.evaluated;
      changed += r.changed.length;
      announce(tenantId, r.changed);
      if (ids.length < PAGE) break;
      cursor = ids[ids.length - 1];
    }
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
  return { output: { tenants: ok, evaluated, changed } };
}

let registered = false;

/** The queues of the minimal compliance (registerMdmModule). */
export function registerComplianceJobs(): void {
  if (registered) return;
  registered = true;
  bindComplianceJob(registerJob({
    name: DEVICE_QUEUE,
    scope: 'tenant',
    description: 'Evaluate the minimal compliance of one device',
    payload: DevicePayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 15, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 60,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: runDevice,
  }));
  registerJob({
    name: ALL_QUEUE,
    scope: 'platform',
    description: 'Hourly: evaluate the compliance of every managed device (the reasons that come with time)',
    payload: empty,
    policy: 'exclusive',
    // APPLE_EDGE_MODE=off: no device is managed, the hourly job is not scheduled (file-durable L3).
    ...(config.apple.mode === 'on' ? { schedule: { cron: '27 * * * *' } } : {}),
    deadLetter: false,                               // the next hourly run does the work again
    retry: { limit: 2, delaySeconds: 60, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 600,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: runAll,
  });
}
