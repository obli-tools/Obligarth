// The jobs of the guard engine (docs: audit-durci §10.5, §10.7, §10.8,
// §13.2; file-durable annex B):
//   actions.execute-delayed   tenant, one per action (deterministic id), the
//                             delayed execution: revalidation, then execution;
//                             never redriven by hand (a destructive action)
//   actions.expire-paused     hourly: pauses older than 24 h expire
//   actions.edge-freeze-sync  tenant, on demand: the freeze by the handlers of
//                             the modules (apple-edge, Android): the single
//                             queue of the freeze (lot AN-P, COH-22; its name
//                             kept: the queues of an instance unchanged)
//   actions.privilege-watch   every minute: an alert per privilege grant, and
//                             per loss of a client approver (AUD-A7-R4)
//   actions.purge             daily: finished actions and grants after 13 months
import { z } from 'zod';
import { defaultRuntime, registerJob, type JobHandle } from '../jobs';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';

export const EXECUTE_QUEUE = 'actions.execute-delayed';

const ExecutePayload = z.object({
  tenantId: z.number().int().positive(),
  actionUuid: z.string().uuid(),
}).strict();
const TenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();
const empty = z.object({}).strict();

let execute: JobHandle<z.infer<typeof ExecutePayload>> | null = null;
let edgeFreezeSync: JobHandle<z.infer<typeof TenantPayload>> | null = null;
let registered = false;

export function executeJob(): JobHandle<z.infer<typeof ExecutePayload>> {
  if (!execute) throw new Error('guard: the module is not registered (registerGuardModule)');
  return execute;
}

export function edgeFreezeSyncJob(): JobHandle<z.infer<typeof TenantPayload>> {
  if (!edgeFreezeSync) throw new Error('guard: the module is not registered (registerGuardModule)');
  return edgeFreezeSync;
}

/** A delay of 0 s: this instance's workers start the execution at once. */
export function wakeExecutor(): void {
  defaultRuntime.wake(EXECUTE_QUEUE);
}

/** Cancels a job that has not run (best effort: the executor checks the
 *  action's state and job id anyway). */
export async function cancelJob(jobId: string): Promise<void> {
  try {
    await executeJob().cancel(jobId);
  } catch (err) {
    logger.warn({ err: safeErr(err), jobId }, 'guard: job not cancelled (the executor checks the action state)');
  }
}

export function registerGuardJobs(): void {
  if (registered) return;
  registered = true;

  execute = registerJob({
    name: EXECUTE_QUEUE,
    scope: 'tenant',
    description: 'Execute a guarded action once its delay is over: revalidation, then execution (idempotent)',
    payload: ExecutePayload,
    policy: 'standard',
    retry: { limit: 3, delaySeconds: 30, backoff: true },
    timeoutSeconds: 900,
    heartbeatSeconds: 60,
    deadLetter: true,
    redrivable: false,
    notify: true,
    handler: async (ctx) => (await import('./executor')).executeDelayed(ctx),
  });

  // Polling at rest (file-durable L3: the idle server stays under 5
  // statements per second): the hourly and daily jobs every 60 s; the
  // per-minute watch every 60 s; the freeze at apple-edge woken by NOTIFY
  // (sent rarely, retried every minute), polled every 30 s otherwise; the
  // delayed execution woken by NOTIFY (backstop 30 s) and, for a delay of
  // 0 s, by this instance (wakeExecutor).
  registerJob({
    name: 'actions.expire-paused',
    scope: 'platform',
    description: 'Expire the guarded actions paused for more than 24 hours',
    payload: empty,
    schedule: { cron: '5 * * * *' },
    pollSeconds: 60,
    timeoutSeconds: 600,
    handler: async (ctx) => (await import('./executor')).expirePaused(ctx),
  });

  edgeFreezeSync = registerJob({
    name: 'actions.edge-freeze-sync',
    scope: 'tenant',
    description: "Apply a tenant's emergency freeze (or its end) by every module (apple-edge, Android)",
    payload: TenantPayload,
    policy: 'stately',
    retry: { limit: 10, delaySeconds: 60, backoff: false },
    timeoutSeconds: 120,
    deadLetter: true,
    notify: true,
    pollSeconds: 30,
    handler: async (ctx) => (await import('./executor')).edgeFreezeSync(ctx),
  });

  registerJob({
    name: 'actions.privilege-watch',
    scope: 'platform',
    description: 'Alert on every new administrator or approver grant and every loss of a client approver, whatever its path',
    payload: empty,
    schedule: { cron: '* * * * *' },
    pollSeconds: 60,
    timeoutSeconds: 60,
    handler: async (ctx) => (await import('./executor')).privilegeWatch(ctx),
  });

  registerJob({
    name: 'actions.purge',
    scope: 'platform',
    description: 'Purge the finished guarded actions and the privilege grants older than 13 months',
    payload: empty,
    schedule: { cron: '35 3 * * *' },
    pollSeconds: 60,
    timeoutSeconds: 600,
    handler: async (ctx) => (await import('./executor')).purge(ctx),
  });
}
