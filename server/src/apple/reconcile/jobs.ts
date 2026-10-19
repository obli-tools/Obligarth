import { z } from 'zod';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit } from '../../audit';
import { config } from '../../config';
import { db } from '../../db';
import { asNone, asTenant, type DbActor } from '../../db/context';
import { withTenantTransaction } from '../../db/tenantContext';
import { JobError, PermanentJobError, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { logger } from '../../utils/logger';
import { requestTenantRecompute } from '../ddm/jobs';
import { isAppleEdgeError } from '../edge/errors';
import { requestAdeProfilesSync } from '../enrollment/adeProfiles';
import { liveTokenIds, requestVppSync } from '../integrations/vpp.service';
import { checkOpenTargets } from './openTargets';
import { compareTenants, reconcileTenant, type ReconcileCounts } from './tenant';

// =============================================================================
// Jobs of the reconciliation and of the recovery after a restore (docs:
// integration-apple-edge §13.1, §13.2; file-durable annex B):
//   apple-edge.reconcile-all       platform, every 15 minutes and at start:
//                                  apple-edge's tenants against the brain's
//                                  (platform.edge_orphan, tenant.edge_missing),
//                                  then apple-edge.reconcile-tenant for every
//                                  tenant with a key, spread over
//                                  APPLE_RECONCILE_SPREAD_S (600 s); a full
//                                  pass of the enrollments at the first run of
//                                  the process and each night (the run of 03:00
//                                  UTC), an incremental one otherwise
//   apple-edge.reconcile-tenant    tenant, exclusive (key t:<id>): reconcile.ts
//   apple-edge.open-targets-check  platform, 20 * * * *: the open targets apple-
//                                  edge no longer holds, tenant by tenant (each
//                                  device at most once a day)
//   apple-edge.restore-check       platform, exclusive, on demand (the
//                                  administration of the platform, the recovery
//                                  of FND-09): full reconciliation of every
//                                  tenant, every open target, the DDM sets sent
//                                  again (sent_token = NULL, recomputation),
//                                  the Apps and Books tokens and the ADE profiles
//                                  synchronised, a summary in the master
//                                  tenant's journal (apple.restore_check)
// With APPLE_EDGE_MODE=off, nothing is scheduled and a job sent anyway ends
// with { skipped: 'apple_edge_off' }.
// =============================================================================

const empty = z.object({}).strict();
const TenantPayload = z.object({ tenantId: z.number().int().positive(), full: z.boolean() }).strict();
type TenantJob = z.infer<typeof TenantPayload>;

let tenantJob: JobHandle<TenantJob> | null = null;
let restoreJob: JobHandle<Record<string, never>> | null = null;
/** The first reconcile-all of this process runs a full pass (« au démarrage »). */
let startPassDone = false;

const off = (): JobResult => ({ output: { skipped: 'apple_edge_off' } });

/** Is this run of reconcile-all the nightly full pass (the one that starts between 03:00 and 03:15 UTC)? */
export function isNightlyPass(now = new Date()): boolean {
  return now.getUTCHours() === 3 && now.getUTCMinutes() < 15;
}

function sum(into: ReconcileCounts, from: ReconcileCounts): void {
  for (const [k, v] of Object.entries(from)) into[k as keyof ReconcileCounts] = (into[k as keyof ReconcileCounts] ?? 0) + (v as number);
}

async function reconcileAll(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return off();
  const full = !startPassDone || isNightlyPass();
  const c = await compareTenants(ctx.dbActor, { requestId: ctx.requestId, signal: ctx.signal });
  const spread = Math.max(0, config.apple.reconcileSpreadS);
  let sent = 0;
  for (const tenantId of c.withKey) {
    ctx.throwIfAborted();
    const delay = spread > 0 ? Math.floor(Math.random() * spread) : 0;
    const id = await (tenantJob as JobHandle<TenantJob>).send({ tenantId, full },
      { singletonKey: `t:${tenantId}`, tenantId, ...(delay > 0 ? { startAfter: delay } : {}) });
    if (id) sent++;
  }
  startPassDone = true;
  return { output: { tenants: c.withKey.length, sent, orphans: c.orphans, missing: c.missing, full } };
}

async function reconcileOne(ctx: JobContext<TenantJob>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return off();
  const tenantId = ctx.tenantId as number;
  try {
    const r = await reconcileTenant(tenantId, { full: ctx.payload.full, actor: ctx.dbActor, requestId: ctx.requestId, signal: ctx.signal });
    const fixes = Object.values(r.fixes).reduce((a, b) => a + (b ?? 0), 0);
    return { output: { outcome: r.outcome, full: r.full, enrollments: r.enrollments, unknown: r.unknown, fixes } };
  } catch (err) {
    if (isAppleEdgeError(err)) {
      await withTenantTransaction(tenantId, ctx.dbActor, (trx) => trx('tenant_apple_edge').where({ tenant_id: tenantId })
        .update({ last_error_code: String(err.code).slice(0, 64), updated_at: new Date() })).catch(() => undefined);
      if (err.retryable) throw new JobError('edge_unavailable', `apple-edge did not answer the reconciliation (${err.code})`);
      throw new PermanentJobError('edge_refused', `apple-edge refused the reconciliation (${err.code})`);
    }
    throw err;
  }
}

async function tenantsWithKey(actor: DbActor): Promise<number[]> {
  return (await asNone(actor, () => db('tenants').whereNotNull('mdm_key').orderBy('id').pluck('id')) as number[]).map(Number);
}

async function openTargetsAll(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return off();
  let devices = 0;
  let expired = 0;
  let failed = 0;
  const day = new Date().toISOString().slice(0, 10);
  for (const tenantId of await tenantsWithKey(ctx.dbActor)) {
    ctx.throwIfAborted();
    try {
      const r = await checkOpenTargets(tenantId, {
        actor: ctx.dbActor, requestId: ctx.requestId, signal: ctx.signal,
        oncePerDay: (deviceId, check) => ctx.once(`open-targets:${deviceId}:${day}`, 2 * 86_400, check),
      });
      devices += r.devices;
      expired += r.expired;
    } catch (err) {
      failed++;
      logger.warn({ tenantId, code: (err as { code?: unknown })?.code }, 'apple-edge.open-targets-check: tenant skipped');
    }
  }
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { devices, expired } };
}

export interface RestoreCheckSummary {
  tenants: number;
  failed: number;
  fixes: ReconcileCounts;
  openTargetsExpired: number;
  ddmSetsReset: number;
  vppTokens: number;
  adeProfiles: number;
  orphans: number;
  missing: number;
}

/** apple-edge.restore-check, the work (also called by the tests). */
export async function runRestoreCheck(actor: DbActor, o: { requestId?: string; signal?: AbortSignal } = {}): Promise<RestoreCheckSummary> {
  const out: RestoreCheckSummary = { tenants: 0, failed: 0, fixes: {}, openTargetsExpired: 0, ddmSetsReset: 0, vppTokens: 0, adeProfiles: 0, orphans: 0, missing: 0 };
  const c = await compareTenants(actor, o);
  out.orphans = c.orphans;
  out.missing = c.missing;
  for (const tenantId of c.withKey) {
    o.signal?.throwIfAborted();
    try {
      // 1. Full reconciliation; 2. every open target.
      const r = await reconcileTenant(tenantId, { full: true, actor, requestId: o.requestId, signal: o.signal });
      sum(out.fixes, r.fixes);
      const t = await checkOpenTargets(tenantId, { actor, requestId: o.requestId, signal: o.signal, all: true });
      out.openTargetsExpired += t.expired;
      // 3. Every DDM set sent again: the devices resynchronise.
      out.ddmSetsReset += await withTenantTransaction(tenantId, actor, (trx) => trx('apple_declaration_sets').where({ tenant_id: tenantId })
        .update({ sent_token: null }));
      await asTenant(tenantId, actor, () => requestTenantRecompute(null, tenantId));
      // 4. Apps and Books, ADE profiles.
      for (const id of await asTenant(tenantId, actor, () => liveTokenIds(db, tenantId))) {
        try {
          await asTenant(tenantId, actor, () => requestVppSync(tenantId, id));
          out.vppTokens++;
        } catch { /* a token no longer usable: its own alert says so */ }
      }
      const hasAde = await asTenant(tenantId, actor, () => db('tenant_apple_ade_tokens').where({ tenant_id: tenantId }).whereNot('state', 'removed').first('id'));
      if (hasAde) {
        await asTenant(tenantId, actor, () => requestAdeProfilesSync(tenantId));
        out.adeProfiles++;
      }
      out.tenants++;
    } catch (err) {
      out.failed++;
      logger.warn({ tenantId, code: (err as { code?: unknown })?.code }, 'apple-edge.restore-check: tenant failed');
    }
  }
  // 5. The summary in the master tenant's journal.
  await asTenant(MASTER_TENANT_ID, actor, () => audit.append({
    tenantId: MASTER_TENANT_ID, action: 'apple.restore_check', target: { type: 'platform', id: 'apple-edge' },
    details: {
      tenants: out.tenants, failed: out.failed, orphans: out.orphans, missing: out.missing, openTargetsExpired: out.openTargetsExpired,
      ddmSetsReset: out.ddmSetsReset, vppTokens: out.vppTokens, adeProfiles: out.adeProfiles, ...Object.fromEntries(Object.entries(out.fixes)),
    },
  }, audit.fromJob({ name: 'apple-edge.restore-check', requestId: o.requestId ?? 'restore-check' })));
  return out;
}

async function restoreCheck(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return off();
  const s = await runRestoreCheck(ctx.dbActor, { requestId: ctx.requestId, signal: ctx.signal });
  if (s.failed > 0) throw new JobError('partial_failure', `${s.failed} tenant(s) failed, ${s.tenants} done`);
  const fixes = Object.values(s.fixes).reduce((a, b) => a + (b ?? 0), 0);
  return { output: { tenants: s.tenants, fixes, openTargetsExpired: s.openTargetsExpired, ddmSetsReset: s.ddmSetsReset } };
}

/** The restore check now (the administration of the platform); null: one is queued or running already. */
export function sendRestoreCheck(): Promise<string | null> {
  if (!restoreJob) throw new Error('apple: the module is not registered (registerAppleModule)');
  return restoreJob.send({}, { singletonKey: 'restore-check' });
}

/** A reconciliation of one tenant now (full pass); null: one is queued or running already. */
export function sendTenantReconcile(tenantId: number, full = true): Promise<string | null> {
  if (!tenantJob) throw new Error('apple: the module is not registered (registerAppleModule)');
  return tenantJob.send({ tenantId, full }, { singletonKey: `t:${tenantId}`, tenantId });
}

let registered = false;

export function registerReconcileJobs(): void {
  if (registered) return;
  registered = true;
  const on = config.apple.mode === 'on';
  registerJob({
    name: 'apple-edge.reconcile-all',
    scope: 'platform',
    description: 'Compare the tenants of apple-edge with the brain\'s, then reconcile every tenant (spread)',
    payload: empty,
    ...(on ? { schedule: { cron: '*/15 * * * *' }, runAtStart: true } : {}),
    policy: 'exclusive',
    notify: true,
    pollSeconds: 60,
    timeoutSeconds: 600,
    handler: reconcileAll,
  });
  tenantJob = registerJob({
    name: 'apple-edge.reconcile-tenant',
    scope: 'tenant',
    description: 'Reconcile one tenant with apple-edge: mirror, enrollments, ADE servers, push certificate',
    payload: TenantPayload,
    policy: 'exclusive',
    retry: { limit: 3, delaySeconds: 60, backoff: true, maxDelaySeconds: 1_800 },
    timeoutSeconds: 1_800,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: 60,
    handler: reconcileOne,
  });
  registerJob({
    name: 'apple-edge.open-targets-check',
    scope: 'platform',
    description: 'Expire the open command targets that apple-edge no longer holds (open for more than 24 hours)',
    payload: empty,
    ...(on ? { schedule: { cron: '20 * * * *' } } : {}),
    policy: 'exclusive',
    notify: true,
    pollSeconds: 60,
    timeoutSeconds: 1_800,
    handler: openTargetsAll,
  });
  restoreJob = registerJob({
    name: 'apple-edge.restore-check',
    scope: 'platform',
    description: 'After a restore: full reconciliation, open targets, DDM sets sent again, Apps and Books and ADE synchronised',
    payload: empty,
    policy: 'exclusive',
    retry: { limit: 2, delaySeconds: 300, backoff: true, maxDelaySeconds: 3_600 },
    timeoutSeconds: 7_200,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: 60,
    handler: restoreCheck,
  });
}

