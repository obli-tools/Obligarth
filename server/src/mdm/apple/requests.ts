import type { Knex } from 'knex';
import { defaultRuntime, type JobHandle, type SendJobOptions } from '../../jobs';
import { logger } from '../../utils/logger';

// =============================================================================
// Requests of the delivery queues of the data model (docs: modele-donnees-mdm
// §7.10, §10.5), for the writers that only know a device changed:
//   apple.artifacts.reconcile-device  the profiles and settings of a device
//                                     (a resolution, a ProfileList, the end of
//                                     a command);
//   mdm.compliance.evaluate-device    its compliance (a result, a DDM status,
//                                     the inventory, its configuration).
// One waiting job and one running job per device (stately): a request while a
// job waits is absorbed by it. In the caller's transaction when given: the job
// exists if and only if it commits; a request absorbed there is sent again
// once the transaction is committed (the waiting job may start before it).
// A leaf module: the queues hand their handles at registration, so that the
// inventory, the hooks and the writers request without importing them.
// Outside a process that runs the job runtime, a request is dropped: the next
// change, or the daily sweep, asks again.
// =============================================================================

type DevicePayload = { tenantId: number; deviceId: number };

let reconcileJob: JobHandle<DevicePayload> | null = null;
let complianceJob: JobHandle<DevicePayload> | null = null;

export function bindReconcileJob(job: JobHandle<DevicePayload>): void {
  reconcileJob = job;
}

export function bindComplianceJob(job: JobHandle<DevicePayload>): void {
  complianceJob = job;
}

/** The promise of the outermost transaction of `trx` (a nested transaction ends before its outer one commits). */
function outermostExecution(trx: Knex.Transaction): Promise<unknown> | null {
  type Nested = Knex.Transaction & { parentTransaction?: Knex.Transaction };
  let t = trx as Nested;
  for (let depth = 0; depth < 16 && t.parentTransaction; depth++) t = t.parentTransaction as Nested;
  return t.executionPromise ?? null;
}

/** Requests absorbed inside `trx` by a waiting job, sent again once the outermost transaction is committed (one
 *  after the other: a tenant-wide pass may have thousands of them). */
function resendAfterCommit(job: JobHandle<DevicePayload>, trx: Knex.Transaction, absorbed: Array<{ payload: DevicePayload; opts: SendJobOptions }>): void {
  const committed = outermostExecution(trx);
  if (!committed || absorbed.length === 0) return;
  void committed.then(async () => { for (const a of absorbed) await job.send(a.payload, a.opts); }, () => undefined)
    .catch((err) => logger.warn({ queue: job.name, err: { message: (err as Error)?.message } }, 'request not sent again after the commit'));
}

async function sendGrouped(job: JobHandle<DevicePayload>, trx: Knex.Transaction | null, payload: DevicePayload, opts: SendJobOptions): Promise<boolean> {
  if (!trx) return (await job.send(payload, opts)) !== null;
  const id = await job.sendInTx(trx, payload, opts);
  if (id !== null) return true;
  resendAfterCommit(job, trx, [{ payload, opts }]);
  return false;
}

async function request(job: JobHandle<DevicePayload> | null, trx: Knex.Transaction | null, tenantId: number, deviceIds: number[]): Promise<number> {
  const ids = [...new Set(deviceIds.filter((n) => Number.isSafeInteger(n) && n > 0))];
  if (!job || ids.length === 0 || !defaultRuntime.isStarted()) return 0;
  const itemOf = (deviceId: number) => ({ payload: { tenantId, deviceId }, opts: { singletonKey: `t:${tenantId}:d:${deviceId}`, tenantId } });
  if (trx && ids.length > 1) {
    // A pass over many devices (the resolution of a tenant asks for every device of its slice): one statement for
    // the list instead of one per device.
    const items = ids.map(itemOf);
    const sentIds = await job.sendManyInTx(trx, items);
    resendAfterCommit(job, trx, items.filter((_, i) => sentIds[i] === null));
    return sentIds.filter((id) => id !== null).length;
  }
  let sent = 0;
  for (const deviceId of ids) {
    const item = itemOf(deviceId);
    if (await sendGrouped(job, trx, item.payload, item.opts)) sent++;
  }
  return sent;
}

/** The reconciliation of the profiles and settings of devices of the tenant (section 7.10). */
export function requestArtifactReconcile(trx: Knex.Transaction | null, tenantId: number, deviceIds: number[]): Promise<number> {
  return request(reconcileJob, trx, tenantId, deviceIds);
}

/** The evaluation of the compliance of devices of the tenant (section 4.4). */
export function requestComplianceEvaluation(trx: Knex.Transaction | null, tenantId: number, deviceIds: number[]): Promise<number> {
  return request(complianceJob, trx, tenantId, deviceIds);
}
