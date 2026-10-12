import type { Knex } from 'knex';
import { z } from 'zod';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import type { DbActor } from '../../db/context';
import { forEachTenant } from '../../db/tenantContext';
import { defaultRuntime, JobError, registerJob, sanitizeError, type JobContext, type JobHandle, type JobResult, type SendJobOptions } from '../../jobs';
import { logger } from '../../utils/logger';
import { raiseAlert } from '../alerts/service';
import { realtime } from '../realtime';
import { BASELINE_AFTER_SECONDS } from './baseline';
import { setRecomputeSender, type RecomputeScope } from './engine';
import { ddmMetrics } from './metrics';
import type { StatusReport } from './report';
import { applyStatusReport, setStatusSyncRequester } from './status';
import { hasDdmSyncSender, setSyncFollowUp, syncDevice } from './sync';
import type { DroppedDeclaration } from './validate';

// =============================================================================
// Queues of the DDM engine (docs: integration-apple-edge §9.4, §9.6, §9.7,
// annex B; file-durable §5.1, motifs M5 and M8). Payloads: internal
// identifiers only.
//   apple.ddm.device-sync       tenant, stately d:<id>: the set of one device
//                               computed and announced (§9.4)
//   apple.ddm.recompute-tenant  tenant, stately t:<id>: one device-sync per
//                               managed Apple device, by pages of 500
//   apple.ddm.recompute-all     platform, daily (safety net): one
//                               recompute-tenant per tenant with such devices
//   apple.ddm.status-ingest     tenant, stately d:<id>: the status reports of
//                               a device waiting in the inbox, in the order
//                               they were received, 20 per run (§9.6)
//   apple.ddm.gc                platform, daily: declarations unused for 30
//                               days and cited by no set, previous sets past
//                               their 24 hours, inbox rows left for 7 days
// Grouping is the queues' own (stately: one waiting job and one running job per
// key): a request while a job waits is absorbed by it, a request while a job
// runs queues the next one. No job is deferred, so NOTIFY wakes the workers
// and the queues are polled only for the retry of a failed job (file-durable
// L3); each run ends by waking its queue, which empties without waiting for a
// poll (several jobs committed together are announced once). A request sent
// in a transaction and absorbed is sent again once the transaction is
// committed: the waiting job may have started before the commit.
// =============================================================================

const DEVICE_SYNC = 'apple.ddm.device-sync';
const RECOMPUTE_TENANT = 'apple.ddm.recompute-tenant';
const RECOMPUTE_ALL = 'apple.ddm.recompute-all';
const STATUS_INGEST = 'apple.ddm.status-ingest';
const GC = 'apple.ddm.gc';

/** Polling of a queue woken by NOTIFY: only the retry of a failed job waits for it. */
const IDLE_POLL_SECONDS = 300;
/** Devices per page of a tenant's recomputation. */
const PAGE = 500;
/** Beyond this many devices, one recomputation of the tenant instead of one job per device. */
const DEVICE_BATCH_MAX = 50;
/** Status reports of a device applied by one run. */
const REPORTS_PER_RUN = 20;
/** Attempts after which a status report is left for the purge. */
const REPORT_MAX_ATTEMPTS = 4;
/** Declarations unused for this long, and cited by no set, are deleted. */
const DECLARATION_UNUSED_DAYS = 30;
/** Rows of the inboxes left this long (failed, or never ingested) are deleted. */
const INBOX_KEPT_DAYS = 7;
/** Rows deleted per slice (motif M8). */
const SLICE_ROWS = 500;

const DevicePayload = z.object({ tenantId: z.number().int().positive(), deviceId: z.number().int().positive() }).strict();
const TenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();
const empty = z.object({}).strict();
type DeviceJob = z.infer<typeof DevicePayload>;
type TenantJob = z.infer<typeof TenantPayload>;

let deviceSyncJob: JobHandle<DeviceJob> | null = null;
let recomputeTenantJob: JobHandle<TenantJob> | null = null;
let statusIngestJob: JobHandle<DeviceJob> | null = null;

/** The worker of `queue` fetches again as soon as the running job ends (no effect in a process without workers). */
function fetchNext(queue: string): void {
  try { defaultRuntime.wake(queue); } catch { /* the runtime is stopping */ }
}

/** The promise of the outermost transaction of `trx` (a nested transaction ends before its outer one commits). */
function outermostExecution(trx: Knex.Transaction): Promise<unknown> | null {
  type Nested = Knex.Transaction & { parentTransaction?: Knex.Transaction };
  let t = trx as Nested;
  for (let depth = 0; depth < 16 && t.parentTransaction; depth++) t = t.parentTransaction as Nested;
  return t.executionPromise ?? null;
}

/**
 * Sends a grouped request (singletonKey), in the transaction when given. A request absorbed by a job already
 * waiting is sent again once the transaction is committed (never when it rolls back): that job may start, and read
 * the device, before the commit.
 */
async function sendGrouped<P>(job: JobHandle<P>, trx: Knex.Transaction | null, payload: P, opts: SendJobOptions): Promise<string | null> {
  if (!trx) return job.send(payload, opts);
  const id = await job.sendInTx(trx, payload, opts);
  if (id === null) {
    const committed = outermostExecution(trx);
    if (committed) {
      void committed.then(() => job.send(payload, opts), () => undefined)
        .catch((err) => logger.warn({ queue: job.name, err: { message: (err as Error)?.message } }, 'DDM request not sent again after the commit'));
    }
  }
  return id;
}

/** The synchronisation of devices of a tenant (their set computed and announced), grouped per device. */
export async function requestDeviceSync(trx: Knex.Transaction | null, tenantId: number, deviceIds: number[]): Promise<number> {
  const ids = [...new Set(deviceIds.filter((n) => Number.isSafeInteger(n) && n > 0))];
  if (!ids.length || !deviceSyncJob) return 0;
  if (!defaultRuntime.isStarted()) {
    logger.warn({ tenantId, devices: ids.length }, 'DDM synchronisation not requested: the job runtime is not started');
    return 0;
  }
  if (ids.length > DEVICE_BATCH_MAX) return (await requestTenantRecompute(trx, tenantId)) ? 1 : 0;
  let sent = 0;
  for (const deviceId of ids) {
    if (await sendGrouped(deviceSyncJob, trx, { tenantId, deviceId }, { singletonKey: `d:${deviceId}`, tenantId })) sent++;
  }
  return sent;
}

/** The recomputation of every managed Apple device of a tenant. */
export async function requestTenantRecompute(trx: Knex.Transaction | null, tenantId: number): Promise<string | null> {
  if (!recomputeTenantJob) return null;
  if (!defaultRuntime.isStarted()) {
    logger.warn({ tenantId }, 'DDM recomputation not requested: the job runtime is not started');
    return null;
  }
  return sendGrouped(recomputeTenantJob, trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
}

/** The ingestion of the status reports of a device (the relay sends it with the report, in its transaction). */
export async function requestStatusIngest(trx: Knex.Transaction | null, tenantId: number, deviceId: number): Promise<string | null> {
  if (!statusIngestJob || !defaultRuntime.isStarted()) return null;
  return sendGrouped(statusIngestJob, trx, { tenantId, deviceId }, { singletonKey: `d:${deviceId}`, tenantId });
}

// ── Declarations set aside: logs and platform alerts, throttled in this process ─────────────────────────

const reported = new Map<string, number>();
const REPORT_EVERY_MS = 10 * 60_000;

/** The declarations a provider returned and the engine refused: counted, logged and, for a secret or an identifier
 *  returned twice, raised as a platform alert. One report per provider, identifier and reason every ten minutes
 *  (every device of a tenant meets the same defect). Outside any transaction; never throws. */
export async function reportDropped(actor: DbActor, tenantId: number, dropped: DroppedDeclaration[]): Promise<void> {
  for (const d of dropped) {
    ddmMetrics.declarationDropped(d.reason);
    // EX-12: a type the device did not announce is the engine working as intended.
    if (d.reason === 'client_unsupported') continue;
    const key = `${d.provider}|${d.identifier}|${d.reason}`;
    const now = Date.now();
    if (now - (reported.get(key) ?? 0) < REPORT_EVERY_MS) continue;
    if (reported.size > 5000) reported.clear();
    reported.set(key, now);
    const fields = { tenantId, provider: d.provider, declaration: d.identifier || undefined, reason: d.reason, ...(d.where ? { where: d.where } : {}) };
    if (d.reason === 'secret') {
      logger.error(fields, 'DDM: a declaration carried a secret and is not served');
      await raiseAlert(actor, MASTER_TENANT_ID, 'ddm.secret_in_declaration', { discriminant: d.provider, params: { provider: d.provider } });
    } else if (d.reason === 'duplicate') {
      logger.error(fields, 'DDM: two declarations share an identifier, neither is served');
      await raiseAlert(actor, MASTER_TENANT_ID, 'ddm.declaration_conflict', { discriminant: d.provider, params: { provider: d.provider, identifier: d.identifier } });
    } else {
      logger.warn(fields, 'DDM: declaration of a provider set aside');
    }
  }
}

// ── Handlers ───────────────────────────────────────────────────────────────────────

let noSenderWarned = false;

async function runDeviceSync(ctx: JobContext<DeviceJob>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const deviceId = ctx.payload.deviceId;
  try {
    const r = await ctx.withTenant((trx) => syncDevice(trx, tenantId, deviceId, `j:${ctx.name}`));
    if (r.set?.dropped.length) await reportDropped(ctx.dbActor, tenantId, r.set.dropped);
    if (r.outcome === 'no_sender' && !noSenderWarned) {
      noSenderWarned = true;
      logger.warn('DDM: no sender of the DeclarativeManagement command is registered (command queue): sets are served, not announced');
    }
    if (r.set?.changed || r.outcome === 'sent') realtime.deviceChanged(tenantId, deviceId);
    return { output: { outcome: r.outcome, changed: r.set?.changed ?? false, declarations: r.set?.items.length ?? 0, ...(r.refusal ? { refusal: r.refusal } : {}) } };
  } finally {
    fetchNext(DEVICE_SYNC);
  }
}

async function runRecomputeTenant(ctx: JobContext<TenantJob>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const job = deviceSyncJob;
  if (!job) return { output: { skipped: 'not_registered' } };
  let cursor = 0;
  let devices = 0;
  let sent = 0;
  try {
    for (;;) {
      ctx.throwIfAborted();
      const ids = await ctx.inTenant(async () => (await db('devices as d')
        .join('apple_devices as a', function joinSat() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
        .where('d.tenant_id', tenantId).whereIn('d.enrollment_state', ['enrolled', 'awaiting_configuration']).where('d.id', '>', cursor)
        .orderBy('d.id').limit(PAGE).pluck('d.id') as number[]).map(Number));
      for (const deviceId of ids) {
        if (await job.send({ tenantId, deviceId }, { singletonKey: `d:${deviceId}`, tenantId })) sent++;
      }
      devices += ids.length;
      if (ids.length < PAGE) break;
      cursor = ids[ids.length - 1];
    }
    return { output: { devices, sent } };
  } finally {
    fetchNext(RECOMPUTE_TENANT);
    fetchNext(DEVICE_SYNC);
  }
}

async function runRecomputeAll(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
  const job = recomputeTenantJob;
  if (!job) return { output: { skipped: 'not_registered' } };
  let sent = 0;
  const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const any = await db('apple_devices as a')
      .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .where('a.tenant_id', tenantId).whereIn('d.enrollment_state', ['enrolled', 'awaiting_configuration']).first('a.device_id');
    if (any && await job.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId })) sent++;
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
  return { output: { tenants: ok, sent } };
}

interface InboxRow { id: string; report: StatusReport; received_at: Date; attempts: number }

async function runStatusIngest(ctx: JobContext<DeviceJob>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const deviceId = ctx.payload.deviceId;
  let applied = 0;
  let failed = 0;
  // The inbox of the device was read to its end (otherwise the run stopped at its quota and more reports may wait).
  let emptied = false;
  try {
    for (let n = 0; n < REPORTS_PER_RUN; n++) {
      ctx.throwIfAborted();
      const current: { id: string | null } = { id: null };
      try {
        const done = await ctx.withTenant(async (trx) => {
          const row = await trx('apple_ddm_status_inbox').where({ tenant_id: tenantId, device_id: deviceId })
            .where('attempts', '<', REPORT_MAX_ATTEMPTS).orderBy('received_at').orderBy('id').forUpdate().first('id', 'report', 'received_at', 'attempts') as InboxRow | undefined;
          if (!row) return false;
          current.id = row.id;
          await applyStatusReport(trx, tenantId, deviceId, row.report, new Date(row.received_at));
          await trx('apple_ddm_status_inbox').where({ tenant_id: tenantId, id: row.id }).del();
          return true;
        });
        if (!done) {
          emptied = true;
          break;
        }
        applied++;
        ddmMetrics.statusReport('ingested');
      } catch (err) {
        const id = current.id;
        if (id === null) throw err;
        const e = sanitizeError(err);
        failed++;
        ddmMetrics.statusReport('failed');
        // The failure on the row: a report that can never be applied is left for the purge, the next ones follow;
        // a transient failure is retried with the job (the order of the reports is kept).
        await ctx.withTenant((trx) => trx('apple_ddm_status_inbox').where({ tenant_id: tenantId, id })
          .update({ attempts: e.retryable ? trx.raw('attempts + 1') : REPORT_MAX_ATTEMPTS, last_error_code: e.code.slice(0, 64) }));
        if (e.retryable) throw err;
        ctx.log.warn({ code: e.code }, 'DDM: a status report could not be applied and is left for the purge');
      }
    }
    if (applied > 0) realtime.deviceChanged(tenantId, deviceId);
    // More reports wait: the next run takes them (this job is running: the queue accepts the next one of its key).
    if (!emptied && statusIngestJob) await statusIngestJob.send({ tenantId, deviceId }, { singletonKey: `d:${deviceId}`, tenantId });
    return { output: { applied, failed } };
  } finally {
    fetchNext(STATUS_INGEST);
  }
}

/** One slice of the declarations of a tenant unused for 30 days and cited by no set (current or previous still served). */
export async function gcDeclarationsSlice(q: Knex | Knex.Transaction, tenantId: number, limit = SLICE_ROWS): Promise<number> {
  const res = await q.raw(`
    DELETE FROM obligarth.apple_declarations d
     WHERE d.tenant_id = ? AND d.id IN (
       SELECT x.id FROM obligarth.apple_declarations x
        WHERE x.tenant_id = ? AND x.last_used_at < now() - make_interval(days => ?::int)
          AND NOT EXISTS (
            SELECT 1 FROM obligarth.apple_declaration_sets s
             WHERE s.tenant_id = x.tenant_id
               AND (s.items @> jsonb_build_array(jsonb_build_object('identifier', x.identifier, 'server_token', x.server_token))
                 OR (s.previous_until > now()
                     AND s.previous_items @> jsonb_build_array(jsonb_build_object('identifier', x.identifier, 'server_token', x.server_token)))))
        ORDER BY x.id LIMIT ?)
       AND d.last_used_at < now() - make_interval(days => ?::int)`,
  [tenantId, tenantId, DECLARATION_UNUSED_DAYS, limit, DECLARATION_UNUSED_DAYS]) as { rowCount?: number };
  return Number(res.rowCount ?? 0);
}

async function runGc(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  const out = { declarations: 0, previous_sets: 0, status_inbox: 0, results_inbox: 0 };
  const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    for (;;) {
      ctx.throwIfAborted();
      const n = await gcDeclarationsSlice(db, tenantId);
      out.declarations += n;
      if (n < SLICE_ROWS) break;
    }
    out.previous_sets += await db('apple_declaration_sets').where({ tenant_id: tenantId }).where('previous_until', '<', db.fn.now())
      .update({ previous_items: null, previous_until: null });
    out.status_inbox += await db('apple_ddm_status_inbox').where({ tenant_id: tenantId })
      .whereRaw('received_at < now() - make_interval(days => ?::int)', [INBOX_KEPT_DAYS]).del();
    out.results_inbox += await db('apple_command_results_inbox').where({ tenant_id: tenantId })
      .whereRaw('created_at < now() - make_interval(days => ?::int)', [INBOX_KEPT_DAYS]).del();
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
  return { output: { tenants: ok, ...out } };
}

let registered = false;

/** The queues of the DDM engine (registerAppleModule). */
export function registerDdmJobs(): void {
  if (registered) return;
  registered = true;
  // APPLE_EDGE_MODE=off: no device is served, the daily jobs are not scheduled (file-durable L3).
  const on = config.apple.mode === 'on';

  deviceSyncJob = registerJob({
    name: DEVICE_SYNC,
    scope: 'tenant',
    description: 'Compute the declaration set of a device and announce it (DeclarativeManagement) when it changed',
    payload: DevicePayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 15, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: runDeviceSync,
  });
  recomputeTenantJob = registerJob({
    name: RECOMPUTE_TENANT,
    scope: 'tenant',
    description: 'Request the DDM synchronisation of every managed Apple device of a tenant',
    payload: TenantPayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 30, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 900,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: runRecomputeTenant,
  });
  registerJob({
    name: RECOMPUTE_ALL,
    scope: 'platform',
    description: 'Daily safety net: request the DDM recomputation of every tenant with managed Apple devices',
    payload: empty,
    policy: 'exclusive',
    ...(on ? { schedule: { cron: '15 4 * * *' } } : {}),
    deadLetter: false,                               // the next daily run does the work again
    retry: { limit: 2, delaySeconds: 60, backoff: true, maxDelaySeconds: 900 },
    timeoutSeconds: 600,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: runRecomputeAll,
  });
  statusIngestJob = registerJob({
    name: STATUS_INGEST,
    scope: 'tenant',
    description: 'Apply the DDM status reports of a device waiting in the inbox, in the order they were received',
    payload: DevicePayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 15, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: runStatusIngest,
  });
  registerJob({
    name: GC,
    scope: 'platform',
    description: 'Delete the declarations unused for 30 days, the previous sets past their 24 hours and the inbox rows left for 7 days',
    payload: empty,
    policy: 'exclusive',
    ...(on ? { schedule: { cron: '40 4 * * *' } } : {}),
    deadLetter: false,                               // the next daily run does the work again
    retry: { limit: 2, delaySeconds: 60, backoff: true, maxDelaySeconds: 900 },
    timeoutSeconds: 900,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: runGc,
  });

  // What the engine, the synchronisation and the status channel ask of these queues.
  setRecomputeSender(async (trx: Knex.Transaction | null, tenantId: number, scope: RecomputeScope) => {
    if ('all' in scope) await requestTenantRecompute(trx, tenantId);
    else await requestDeviceSync(trx, tenantId, scope.deviceIds);
  });
  setSyncFollowUp({
    requestSync: async (trx, tenantId, deviceId) => { await requestDeviceSync(trx, tenantId, [deviceId]); },
    // Its own key: a job dated in the future must not absorb the immediate requests of the device for 15 minutes.
    scheduleBaselineCheck: async (trx, tenantId, deviceId) => {
      if (!deviceSyncJob || !defaultRuntime.isStarted()) return;
      await deviceSyncJob.sendInTx(trx, { tenantId, deviceId }, { singletonKey: `d:${deviceId}:baseline`, tenantId, startAfter: BASELINE_AFTER_SECONDS + 5 });
    },
  });
  setStatusSyncRequester(async (trx, tenantId, deviceId) => { await requestDeviceSync(trx, tenantId, [deviceId]); });
}

/** The handles (registerAppleModule must have run); null otherwise. Tests run the handlers through them. */
export const ddmJobs = {
  deviceSync: (): JobHandle<DeviceJob> | null => deviceSyncJob,
  recomputeTenant: (): JobHandle<TenantJob> | null => recomputeTenantJob,
  statusIngest: (): JobHandle<DeviceJob> | null => statusIngestJob,
  hasSender: hasDdmSyncSender,
};
