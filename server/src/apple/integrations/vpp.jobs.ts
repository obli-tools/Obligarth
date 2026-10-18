import { z } from 'zod';
import { db } from '../../db';
import { forEachTenant } from '../../db/tenantContext';
import { JobError, jobIdFor, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { isVppApiError } from './vpp.client';
import {
  bindVppSenders, checkOperationStatus, liveTokenIds, processNotification, submitOperation, syncToken,
} from './vpp.service';

// =============================================================================
// The queues of Apps and Books (docs: integration-apple-edge §11.3, annex B):
//   vpp.sync-all          platform, every hour (minute 40): vpp.sync-token for
//                         every live content token of every tenant
//   vpp.sync-token        tenant, exclusive, key vpp:<id>: mdmInfo, assets,
//                         assignments, purges (vpp.service.ts, syncToken)
//   vpp.operation-submit  tenant, one job per operation and submission: the call
//                         of Apple (429, 9646, 5xx: the retries of the queue,
//                         exponential)
//   vpp.event-status      tenant, stately, key vppop:<id> (or vppop:<id>:now
//                         after a notification): the event status
//   vpp.notification      tenant, one job per notification received
// Payloads: internal identifiers only (never a token, a serial number nor a
// user). Scheduled whatever APPLE_EDGE_MODE says: Apps and Books does not go
// through apple-edge.
// =============================================================================

const Tenant = { tenantId: z.number().int().positive() };
const SyncPayload = z.object({ ...Tenant, vppId: z.string().uuid(), full: z.boolean().default(false) }).strict();
const OperationPayload = z.object({ ...Tenant, operationId: z.string().uuid() }).strict();
const InboxPayload = z.object({ ...Tenant, inboxId: z.string().uuid() }).strict();
const Empty = z.object({}).strict();

let syncJob: JobHandle<z.infer<typeof SyncPayload>> | null = null;
let submitJob: JobHandle<z.infer<typeof OperationPayload>> | null = null;
let statusJob: JobHandle<z.infer<typeof OperationPayload>> | null = null;
let notifyJob: JobHandle<z.infer<typeof InboxPayload>> | null = null;

const handle = <P>(h: JobHandle<P> | null, name: string): JobHandle<P> => {
  if (!h) throw new Error(`${name}: not registered`);
  return h;
};

/** A failure of Apple that waiting may heal: the queue's retries; anything else is the operation's end (already written). */
function retryable(err: unknown): never {
  if (isVppApiError(err)) throw new JobError(err.code, `Apps and Books: ${err.kind}`, true);
  throw err;
}

async function syncAll(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let tokens = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    for (const id of await liveTokenIds(db, tenantId)) {
      await handle(syncJob, 'vpp.sync-token').send({ tenantId, vppId: id, full: false }, { singletonKey: `vpp:${id}`, tenantId });
      tokens++;
    }
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { tokens } };
}

async function syncOne(ctx: JobContext<z.infer<typeof SyncPayload>>): Promise<JobResult> {
  const { tenantId, vppId, full } = ctx.payload;
  try {
    const r = await ctx.inTenant(() => syncToken(tenantId, vppId, { full, actor: ctx.dbActor }));
    return { output: { outcome: r.outcome, assets: r.assets, assignments: r.assignments, changed: r.changed } };
  } catch (err) { retryable(err); }
}

async function submit(ctx: JobContext<z.infer<typeof OperationPayload>>): Promise<JobResult> {
  try {
    const outcome = await ctx.inTenant(() => submitOperation(ctx.payload.tenantId, ctx.payload.operationId));
    return { output: { outcome } };
  } catch (err) { retryable(err); }
}

async function status(ctx: JobContext<z.infer<typeof OperationPayload>>): Promise<JobResult> {
  try {
    const outcome = await ctx.inTenant(() => checkOperationStatus(ctx.payload.tenantId, ctx.payload.operationId));
    return { output: { outcome } };
  } catch (err) { retryable(err); }
}

async function notification(ctx: JobContext<z.infer<typeof InboxPayload>>): Promise<JobResult> {
  const r = await ctx.inTenant(() => processNotification(ctx.payload.tenantId, ctx.payload.inboxId));
  return { output: { type: r.type, outcome: r.outcome } };
}

let registered = false;

export function registerVppJobs(): void {
  if (registered) return;
  registered = true;
  registerJob({
    name: 'vpp.sync-all',
    scope: 'platform',
    description: 'Every hour: the synchronisation of every content token of Apps and Books',
    payload: Empty,
    policy: 'exclusive',
    schedule: { cron: '40 * * * *' },
    retry: { limit: 2, delaySeconds: 300, backoff: true },
    timeoutSeconds: 600,
    pollSeconds: 300,
    deadLetter: false,
    trackStatus: 'queue',
    manualRun: true,
    keepFinishedSeconds: 172_800,
    keepPendingSeconds: 86_400,
    handler: syncAll,
  });
  syncJob = registerJob({
    name: 'vpp.sync-token',
    scope: 'tenant',
    description: 'Synchronise a content token of Apps and Books: mdmInfo, licences, assignments',
    payload: SyncPayload,
    policy: 'exclusive',
    retry: { limit: 3, delaySeconds: 60, backoff: true, maxDelaySeconds: 1800 },
    timeoutSeconds: 600,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: 300,
    handler: syncOne,
  });
  submitJob = registerJob({
    name: 'vpp.operation-submit',
    scope: 'tenant',
    description: 'Submit an operation of Apps and Books (associate, disassociate, revoke, users)',
    payload: OperationPayload,
    policy: 'standard',
    retry: { limit: 6, delaySeconds: 30, backoff: true, maxDelaySeconds: 1800 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: 300,
    handler: submit,
  });
  statusJob = registerJob({
    name: 'vpp.event-status',
    scope: 'tenant',
    description: 'Look at the status of an operation of Apps and Books at Apple',
    payload: OperationPayload,
    policy: 'stately',
    retry: { limit: 6, delaySeconds: 30, backoff: true, maxDelaySeconds: 900 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: 30,
    handler: status,
  });
  notifyJob = registerJob({
    name: 'vpp.notification',
    scope: 'tenant',
    description: 'Process a notification of Apps and Books (it only hastens the follow-up)',
    payload: InboxPayload,
    policy: 'standard',
    retry: { limit: 5, delaySeconds: 30, backoff: true, maxDelaySeconds: 900 },
    timeoutSeconds: 60,
    notify: true,
    pollSeconds: 300,
    handler: notification,
  });
  bindVppSenders({
    async submit(trx, tenantId, operationId, attempt) {
      await handle(submitJob, 'vpp.operation-submit').sendInTx(trx, { tenantId, operationId },
        { id: jobIdFor('vpp.operation-submit', `${operationId}:${attempt}`), tenantId });
    },
    async eventStatus(trx, tenantId, operationId, delaySeconds) {
      const opts = { singletonKey: delaySeconds > 0 ? `vppop:${operationId}` : `vppop:${operationId}:now`, tenantId,
        ...(delaySeconds > 0 ? { startAfter: delaySeconds } : {}) };
      const h = handle(statusJob, 'vpp.event-status');
      if (trx) await h.sendInTx(trx, { tenantId, operationId }, opts);
      else await h.send({ tenantId, operationId }, opts);
    },
    async syncToken(trx, tenantId, vppId, full) {
      const h = handle(syncJob, 'vpp.sync-token');
      const opts = { singletonKey: `vpp:${vppId}`, tenantId };
      if (trx) await h.sendInTx(trx, { tenantId, vppId, full }, opts);
      else await h.send({ tenantId, vppId, full }, opts);
    },
    async notification(trx, tenantId, inboxId) {
      await handle(notifyJob, 'vpp.notification').sendInTx(trx, { tenantId, inboxId }, { id: jobIdFor('vpp.notification', inboxId), tenantId });
    },
  });
}
