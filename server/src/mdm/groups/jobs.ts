import { z } from 'zod';
import { db } from '../../db';
import { forEachTenant } from '../../db/tenantContext';
import { JobError, SCHEDULED_POLL_SECONDS, defaultRuntime, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { evaluateTenant, recomputeGroups } from './evaluate';

// =============================================================================
// Queues of the dynamic groups (P0-5 T5, §4.3; file durable §5.1):
//   mdm.groups.evaluate  the incremental computation of a tenant (evaluate.ts evaluateTenant): stately, one key per
//                        tenant (t:<id>), woken by NOTIFY when requestGroupEvaluation sends it (triggers.ts), polled
//                        every five minutes only (a retry that became due; file-durable L3), one run per tenant at a
//                        time. A run that yields with markings left sends the next one.
//   mdm.groups.schedule  hourly (cron 23 * * * *), the only scheduled task of the dynamic groups (no task every
//                        minute: the L3 budget of baseline-boot), tenant by tenant, for the tenants that have groups:
//                          - the markings a wake missed: the tenant's queue is sent;
//                          - the groups that read a temporal field (last_checkin, enrolled_at: never marked) computed
//                            in full;
//                          - at 02:23 UTC (or a manual run with { full: true }), every group computed in full against
//                            the drift (with the mass guard for a targeted group);
//                          - the pending changes of the held groups counted again.
// Payloads carry internal identifiers only.
// =============================================================================

const EVALUATE_QUEUE = 'mdm.groups.evaluate';
const SCHEDULE_QUEUE = 'mdm.groups.schedule';

/** Polling interval of the queue: nothing waits for it but the retry of a failed job. */
const IDLE_POLL_SECONDS = 300;

/** The hour (UTC) of the full pass against the drift. */
export const DRIFT_HOUR_UTC = 2;

const EvaluatePayload = z.object({ tenantId: z.number().int().positive() }).strict();
const SchedulePayload = z.object({ full: z.boolean().optional() }).strict();

let evaluateJob: JobHandle<z.infer<typeof EvaluatePayload>> | null = null;

/** The worker of the queue fetches again as soon as the running job ends (no effect in a process without workers). */
function fetchNext(): void {
  try { defaultRuntime.wake(EVALUATE_QUEUE); } catch { /* the runtime is stopping */ }
}

async function runEvaluate(ctx: JobContext<z.infer<typeof EvaluatePayload>>): Promise<JobResult> {
  try {
    const r = await evaluateTenant(ctx, ctx.payload.tenantId);
    // Markings left beyond the run's slices: the next run (absorbed by a job already queued).
    if (r.more && evaluateJob) await evaluateJob.send({ tenantId: ctx.payload.tenantId }, { singletonKey: `t:${ctx.payload.tenantId}`, tenantId: ctx.payload.tenantId });
    return { output: { slices: r.slices, devices: r.devices, changed: r.changed.length, held: r.held.length, resolved: r.resolved, more: r.more } };
  } finally {
    fetchNext();
  }
}

async function runSchedule(ctx: JobContext<z.infer<typeof SchedulePayload>>): Promise<JobResult> {
  const full = ctx.payload.full === true || new Date().getUTCHours() === DRIFT_HOUR_UTC;
  let tenants = 0;
  let woken = 0;
  let recomputed = 0;
  let held = 0;
  const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    if (!(await db('smart_groups').where({ tenant_id: tenantId }).first('id'))) return;
    tenants++;
    if (evaluateJob && defaultRuntime.isStarted() && await db('smart_group_dirty').where({ tenant_id: tenantId }).first('device_id')) {
      if (await evaluateJob.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId })) woken++;
    }
    const r = await recomputeGroups(tenantId, ctx.dbActor, full ? 'all' : 'temporal');
    recomputed += r.groups;
    held += r.held.length;
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
  return { output: { tenants, woken, recomputed, held, full } };
}

let registered = false;

export function registerGroupJobs(): void {
  if (registered) return;
  registered = true;
  evaluateJob = registerJob({
    name: EVALUATE_QUEUE,
    scope: 'tenant',
    description: 'Compute again the dynamic groups of a tenant for the devices whose inventory changed',
    payload: EvaluatePayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 30, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 900,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    concurrency: { perTenant: 1 },
    handler: runEvaluate,
  });
  registerJob({
    name: SCHEDULE_QUEUE,
    scope: 'platform',
    description: 'Hourly pass of the dynamic groups: forgotten markings, temporal rules, nightly full computation',
    payload: SchedulePayload,
    schedule: { cron: '23 * * * *' },
    policy: 'exclusive',
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    timeoutSeconds: 3600,
    heartbeatSeconds: 60,
    handler: runSchedule,
  });
}

/** The handle of mdm.groups.evaluate (registerMdmModule must have run); null otherwise. */
export const evaluateGroupsJob = (): JobHandle<z.infer<typeof EvaluatePayload>> | null => evaluateJob;
