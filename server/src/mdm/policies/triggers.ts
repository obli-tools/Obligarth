import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { defaultRuntime } from '../../jobs';
import { resolveDeviceJob, resolveTenantJob } from './jobs';

// =============================================================================
// Triggers of the resolution (docs: modele-donnees-mdm §7.12):
//   - publication, change of assignments, archival, a group moved in the tree
//     or deleted → the tenant (mdm.policies.resolve-tenant);
//   - enrollment (apple.device-onboard: resolveAtOnboarding), change of group,
//     of ownership, of supervision, of OS, of platform, of serial number or
//     model (inventory), of the assigned end user or of its profile
//     (variables), of DDM client capabilities (status channel) → the device
//     (mdm.policies.resolve-device; a large batch asks the tenant's instead).
// In the caller's transaction when given (the job exists if and only if it
// commits). Requests are grouped by the queue itself (stately: one queued job
// and one running job per key, the key being the tenant or the device): a
// request while a job is queued is absorbed by it, a request while a job runs
// queues the next one. Every job can start at once, so the workers are woken
// by NOTIFY and nothing waits for a poll (no deferred job: a job dated in the
// future is not announced). A tenant without any assignment, whose devices
// have no effective state, has nothing to resolve: no job. A process without
// the MDM module requests nothing; outside a server that runs the job runtime
// (a CLI, a test that does not start it), a request is logged and dropped: the
// next change of the tenant resolves again.
// =============================================================================

/** Beyond this many devices, one resolution of the tenant instead of one per device. */
const DEVICE_BATCH_MAX = 50;

/** The promise of the outermost transaction of `trx` (a nested transaction ends before its outer one commits). */
function outermostExecution(trx: Knex.Transaction): Promise<unknown> | null {
  type Nested = Knex.Transaction & { parentTransaction?: Knex.Transaction };
  let t = trx as Nested;
  for (let depth = 0; depth < 16 && t.parentTransaction; depth++) t = t.parentTransaction as Nested;
  return t.executionPromise ?? null;
}

/**
 * A request sent in a transaction and absorbed by a job already queued is sent again once the transaction is
 * committed (never when it rolls back). The queued job may start, and read the tenant, before this transaction
 * commits: its change would then stay unresolved until the next trigger. Sent again, the request is absorbed
 * once more if that job has not started (it will then read the committed change), or queues a new job.
 */
function resendAfterCommit(trx: Knex.Transaction, send: () => Promise<unknown>, what: Record<string, unknown>): void {
  const committed = outermostExecution(trx);
  if (!committed) return;
  void committed.then(() => send(), () => undefined)
    .catch((err) => logger.warn({ ...what, err: { message: (err as Error)?.message } }, 'policy resolution not requested again after the commit'));
}

async function somethingToResolve(q: Knex | Knex.Transaction, tenantId: number, deviceIds: number[] | null): Promise<boolean> {
  const a = await q('assignments').where({ tenant_id: tenantId }).first('id');
  if (a) return true;
  const e = q('device_effective_settings').where({ tenant_id: tenantId });
  if (deviceIds) e.whereIn('device_id', deviceIds);
  return !!(await e.first('device_id'));
}

/** Requests the resolution of every device of the tenant. */
export async function requestTenantResolution(trx: Knex.Transaction | null, tenantId: number): Promise<string | null> {
  const job = resolveTenantJob();
  if (!job || !(await somethingToResolve(trx ?? db, tenantId, null))) return null;
  if (!defaultRuntime.isStarted()) {
    logger.warn({ tenantId }, 'policy resolution not requested: the job runtime is not started');
    return null;
  }
  const opts = { singletonKey: `t:${tenantId}`, tenantId };
  if (!trx) return job.send({ tenantId }, opts);
  const id = await job.sendInTx(trx, { tenantId }, opts);
  if (id === null) resendAfterCommit(trx, () => job.send({ tenantId }, opts), { tenantId });
  return id;
}

/** Requests the resolution of devices of the tenant (the tenant's beyond 50 devices). */
export async function requestDeviceResolution(trx: Knex.Transaction | null, tenantId: number, deviceIds: number[]): Promise<number> {
  const ids = [...new Set(deviceIds.filter((n) => Number.isSafeInteger(n) && n > 0))];
  const job = resolveDeviceJob();
  if (!ids.length || !job || !(await somethingToResolve(trx ?? db, tenantId, ids))) return 0;
  if (!defaultRuntime.isStarted()) {
    logger.warn({ tenantId, devices: ids.length }, 'policy resolution not requested: the job runtime is not started');
    return 0;
  }
  if (ids.length > DEVICE_BATCH_MAX) return (await requestTenantResolution(trx, tenantId)) ? 1 : 0;
  let sent = 0;
  for (const deviceId of ids) {
    const opts = { singletonKey: `t:${tenantId}:d:${deviceId}`, tenantId };
    const id = trx ? await job.sendInTx(trx, { tenantId, deviceId }, opts) : await job.send({ tenantId, deviceId }, opts);
    if (id) sent++;
    else if (trx) resendAfterCommit(trx, () => job.send({ tenantId, deviceId }, opts), { tenantId, deviceId });
  }
  return sent;
}

/** Requests the resolution of the devices assigned to end users whose profile changed: the variables {{user.…}}
 *  read it, and one that gains or loses its value changes what applies (section 7.2). */
export async function requestEndUserResolution(trx: Knex.Transaction | null, tenantId: number, endUserIds: number[]): Promise<number> {
  const ids = [...new Set(endUserIds.filter((n) => Number.isSafeInteger(n) && n > 0))];
  if (!ids.length || !resolveDeviceJob()) return 0;
  const devices = await (trx ?? db)('devices').where({ tenant_id: tenantId }).whereIn('end_user_id', ids)
    .whereNot('enrollment_state', 'unenrolled').pluck('id') as number[];
  return requestDeviceResolution(trx, tenantId, devices.map(Number));
}

/**
 * The step of the onboarding of a device (apple.device-onboard, section 10.4): its first resolution, once its
 * identity certificate is known. In the tenant's context (the job's). Registered with the integration's onboarding
 * steps by registerMdmModule; idempotent (a retried job requests it again, the queue groups the requests).
 */
export async function resolveAtOnboarding(tenantId: number, deviceId: number): Promise<void> {
  await requestDeviceResolution(null, tenantId, [deviceId]);
}
