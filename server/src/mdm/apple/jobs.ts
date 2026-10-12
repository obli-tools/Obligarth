import { z } from 'zod';
import { config } from '../../config';
import { db } from '../../db';
import { forEachTenant } from '../../db/tenantContext';
import { defaultRuntime, JobError, registerJob, type JobContext, type JobResult } from '../../jobs';
import { emitConfigChanged } from '../policies/jobs';
import { RECONCILE_QUEUE, reconcileDevice, stuckDevices } from './reconcile';
import { bindReconcileJob, requestArtifactReconcile } from './requests';

// =============================================================================
// Delivery queues of the data model (docs: modele-donnees-mdm §7.10, §10.5;
// file-durable §5.1, motifs M5 and M8). Payloads: internal identifiers only.
//   apple.artifacts.reconcile-device  tenant, stately t:<id>:d:<device>: the
//                                     profiles and settings of one device
//                                     (reconcile.ts), by the command bus;
//   mdm.artifacts.gc                  platform, daily: the bodies no device
//                                     wants any more (7 days old at least),
//                                     the artifacts removed 30 days ago, by
//                                     slices of 500; and the daily sweep: the
//                                     devices whose artifacts wait for nothing
//                                     (an error to try again after 24 hours, a
//                                     refusal that may have lifted) are
//                                     reconciled again.
// Like the queues of the resolution: no deferred job, NOTIFY wakes the worker,
// the poll (300 s) only picks up a retry, and each run ends by waking its
// queue (requests committed together are announced once).
// =============================================================================

const GC_QUEUE = 'mdm.artifacts.gc';
const IDLE_POLL_SECONDS = 300;
const SLICE_ROWS = 500;
/** A body no device wants is deleted once this old. */
const ARTIFACT_UNUSED_DAYS = 7;
/** A removed artifact is kept this long (the console shows what left the device). */
const REMOVED_KEPT_DAYS = 30;
/** Devices of one tenant the daily sweep asks again, per run. */
const SWEEP_DEVICES = 1000;

const DevicePayload = z.object({ tenantId: z.number().int().positive(), deviceId: z.number().int().positive() }).strict();
const empty = z.object({}).strict();

function fetchNext(queue: string): void {
  try { defaultRuntime.wake(queue); } catch { /* the runtime is stopping */ }
}

async function runReconcile(ctx: JobContext<z.infer<typeof DevicePayload>>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const deviceId = ctx.payload.deviceId;
  try {
    const r = await ctx.withTenant((trx) => reconcileDevice(trx, tenantId, deviceId, `j:${ctx.name}`));
    if (r.changed) emitConfigChanged(tenantId, [deviceId]);
    return { output: { outcome: r.outcome, installs: r.installs, removals: r.removals, adopted: r.adopted, waiting: r.waiting } };
  } finally {
    fetchNext(RECONCILE_QUEUE);
  }
}

async function runGc(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  const out = { artifacts: 0, removed: 0, swept: 0 };
  const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    for (;;) {
      ctx.throwIfAborted();
      const res = await db.raw(`
        DELETE FROM obligarth.mdm_artifacts m
         WHERE m.tenant_id = ? AND m.hash IN (
           SELECT x.hash FROM obligarth.mdm_artifacts x
            WHERE x.tenant_id = ? AND x.created_at < now() - make_interval(days => ?::int)
              AND NOT EXISTS (SELECT 1 FROM obligarth.device_artifacts d WHERE d.tenant_id = x.tenant_id AND d.desired_hash = x.hash)
            ORDER BY x.hash LIMIT ?)
           AND NOT EXISTS (SELECT 1 FROM obligarth.device_artifacts d WHERE d.tenant_id = m.tenant_id AND d.desired_hash = m.hash)`,
      [tenantId, tenantId, ARTIFACT_UNUSED_DAYS, SLICE_ROWS]) as { rowCount?: number };
      const n = Number(res.rowCount ?? 0);
      out.artifacts += n;
      if (n < SLICE_ROWS) break;
    }
    for (;;) {
      ctx.throwIfAborted();
      const res = await db.raw(`
        DELETE FROM obligarth.device_artifacts a
         WHERE a.tenant_id = ? AND (a.device_id, a.artifact_key) IN (
           SELECT x.device_id, x.artifact_key FROM obligarth.device_artifacts x
            WHERE x.tenant_id = ? AND x.state = 'removed' AND x.state_at < now() - make_interval(days => ?::int)
            ORDER BY x.device_id, x.artifact_key LIMIT ?)
           AND a.state = 'removed'`,
      [tenantId, tenantId, REMOVED_KEPT_DAYS, SLICE_ROWS]) as { rowCount?: number };
      const n = Number(res.rowCount ?? 0);
      out.removed += n;
      if (n < SLICE_ROWS) break;
    }
    out.swept += await requestArtifactReconcile(null, tenantId, await stuckDevices(db, tenantId, SWEEP_DEVICES));
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
  return { output: { tenants: ok, ...out } };
}

let registered = false;

/** The delivery queues of the data model (registerMdmModule). */
export function registerArtifactJobs(): void {
  if (registered) return;
  registered = true;
  bindReconcileJob(registerJob({
    name: RECONCILE_QUEUE,
    scope: 'tenant',
    description: 'Reconcile the profiles and settings of a device with what its policies want (commands of origin policy)',
    payload: DevicePayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 15, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: runReconcile,
  }));
  registerJob({
    name: GC_QUEUE,
    scope: 'platform',
    description: 'Delete the artifact bodies no device wants and the artifacts removed 30 days ago; reconcile again the devices whose artifacts wait',
    payload: empty,
    policy: 'exclusive',
    // APPLE_EDGE_MODE=off: nothing is delivered, the daily job is not scheduled (file-durable L3).
    ...(config.apple.mode === 'on' ? { schedule: { cron: '50 4 * * *' } } : {}),
    deadLetter: false,                               // the next daily run does the work again
    retry: { limit: 2, delaySeconds: 60, backoff: true, maxDelaySeconds: 900 },
    timeoutSeconds: 900,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: runGc,
  });
}
