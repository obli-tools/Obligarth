import { z } from 'zod';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { audit } from '../../audit';
import { edgeFreezeSyncJob } from '../../guard/jobs';
import { JobError, PermanentJobError, registerJob, type JobContext, type JobResult } from '../../jobs';
import { logger } from '../../utils/logger';
import { raiseAlert, resolveMasterInTx } from '../alerts/service';
import { isAppleEdgeError } from '../edge/errors';
import { probeEdge } from '../edge/health';
import { appleEdge } from '../edge/instance';
import type { EdgeCa } from '../edge/wire';
import { appleMetrics } from '../metrics';
import { recordDeviceCaDeadline, setProvisionSender, upsertMirror, type EdgeMirrorState } from './registry';

// =============================================================================
// Jobs of the tenant registry (docs: integration-apple-edge §5.5, §6.2, annex
// B):
//   apple-edge.provision-tenant  tenant, exclusive (key t:<id>), 8 retries from
//                                30 s to 1 h, 120 s: creates the tenant at
//                                apple-edge (external_ref = tenants.uuid) or
//                                reads it, writes the key once, the mirror, the
//                                device CA deadline, apple.tenant_provisioned
//                                at the first key; carries a freeze of the
//                                guard engine over (INT-RC10);
//   apple-edge.provision-all     platform, 7 * * * * and at start: every
//                                tenant without key, or whose mirror is in
//                                error for more than an hour;
//   apple-edge.health            platform, * * * * *, no retry: the probe.
// Every call to apple-edge happens between two transactions (T-1). With
// APPLE_EDGE_MODE=off, provision-all and the probe are neither scheduled nor
// sent at start, and a job sent anyway ends with { skipped: 'apple_edge_off' }.
// =============================================================================

const TenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();
const empty = z.object({}).strict();
/** A mirror in error is provisioned again by provision-all after this delay. */
const ERROR_RETRY_MS = 60 * 60_000;

type EdgeView = { key: string; state: string; commandsFrozen: boolean; ca: EdgeCa | null; verifyOnly: EdgeCa[] };

const EDGE_STATES = new Set(['active', 'suspended', 'retiring', 'retired']);

function mirrorStateOf(state: string): EdgeMirrorState {
  return (EDGE_STATES.has(state) ? state : 'error') as EdgeMirrorState;
}

async function tenantName(tenantId: number, ctx: JobContext<unknown>): Promise<string> {
  const row = await ctx.inTenant(() => db('tenants').where({ id: tenantId }).first('name')) as { name: string } | undefined;
  return row?.name ?? `#${tenantId}`;
}

/** The failure of a provisioning attempt: mirror, last code; at the last attempt, the platform alert. */
async function provisioningFailed(ctx: JobContext<{ tenantId: number }>, code: string, state: EdgeMirrorState | null, final: boolean): Promise<void> {
  const tenantId = ctx.tenantId as number;
  await ctx.withTenant((trx) => upsertMirror(trx, tenantId, { ...(state ? { edge_state: state, edge_state_at: new Date() } : {}), last_error_code: code.slice(0, 64) }));
  if (final) {
    await raiseAlert(ctx.dbActor, MASTER_TENANT_ID, 'tenant.provisioning_failed', {
      discriminant: tenantId, params: { tenantName: await tenantName(tenantId, ctx) },
    });
  }
}

async function provisionTenant(ctx: JobContext<{ tenantId: number }>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
  const tenantId = ctx.tenantId as number;
  const o = { actor: ctx.actor, requestId: ctx.requestId };

  // 1. The tenant's reference and key; the attempt counted.
  const before = await ctx.withTenant(async (trx) => {
    const t = await trx('tenants').where({ id: tenantId }).first('uuid', 'mdm_key') as { uuid: string; mdm_key: string | null } | undefined;
    if (!t) throw new PermanentJobError('tenant_gone', 'the tenant no longer exists');
    // Without a key: 'provisioning' (from 'unprovisioned' or 'error'); with one, the state stays.
    await trx.raw(`
      INSERT INTO obligarth.tenant_apple_edge AS m (tenant_id, edge_state, provision_attempts)
      VALUES (?, ?, 1)
      ON CONFLICT (tenant_id) DO UPDATE
         SET provision_attempts = m.provision_attempts + 1,
             edge_state = CASE WHEN EXCLUDED.edge_state = 'provisioning' AND m.edge_state IN ('unprovisioned', 'error')
                               THEN 'provisioning' ELSE m.edge_state END,
             updated_at = now()`, [tenantId, t.mdm_key ? 'unprovisioned' : 'provisioning']);
    return { uuid: String(t.uuid), key: t.mdm_key };
  });

  // 2. apple-edge, outside any transaction.
  let edge: EdgeView;
  let created = false;
  try {
    if (!before.key) {
      const r = await appleEdge.createTenant(before.uuid, { ...o, signal: ctx.signal });
      created = r.created;
      edge = { key: r.tenant.key, state: r.tenant.state, commandsFrozen: false, ca: r.tenant.ca, verifyOnly: [] };
    } else {
      const t = await appleEdge.getTenant(before.key, { ...o, signal: ctx.signal });
      const active = t.cas.find((c) => c.status === 'active') ?? null;
      edge = {
        key: t.key, state: t.load_failed ? 'load_failed' : t.state, commandsFrozen: t.commands_frozen, ca: active,
        verifyOnly: t.cas.filter((c) => c.status === 'verify_only'),
      };
    }
  } catch (err) {
    if (!isAppleEdgeError(err)) throw err;
    if (err.code === 'tenant_not_live') {
      // external_ref of a tenant retired at apple-edge (a backup of the brain older than its deletion there):
      // never taken back; a new tenant is needed.
      await provisioningFailed(ctx, 'tenant_not_live', 'retired', false);
      await raiseAlert(ctx.dbActor, MASTER_TENANT_ID, 'tenant.edge_retired', { discriminant: tenantId, params: { tenantName: await tenantName(tenantId, ctx) } });
      appleMetrics.provisioned('failed');
      return { output: { state: 'retired' } };
    }
    if (err.code === 'tenant_not_found' && before.key) {
      await provisioningFailed(ctx, 'tenant_not_found', 'missing', false);
      await raiseAlert(ctx.dbActor, MASTER_TENANT_ID, 'tenant.edge_missing', { discriminant: tenantId, params: { tenantName: await tenantName(tenantId, ctx) } });
      appleMetrics.provisioned('failed');
      return { output: { state: 'missing' } };
    }
    const final = !err.retryable || ctx.isLastAttempt;
    await provisioningFailed(ctx, String(err.code), final ? 'error' : null, final);
    appleMetrics.provisioned('failed');
    if (err.retryable) throw new JobError('edge_unavailable', `apple-edge did not provision the tenant (${err.code})`);
    throw new PermanentJobError('edge_refused', `apple-edge refused the provisioning (${err.code})`);
  }

  // 3. Key (written once), mirror, deadline, audit at the first key, alert resolved, freeze carried over.
  let firstKey = false;
  try {
    await ctx.withTenant(async (trx) => {
      const current = await trx('tenants').where({ id: tenantId }).forUpdate().first('mdm_key') as { mdm_key: string | null } | undefined;
      firstKey = !current?.mdm_key;
      await trx.raw('SELECT obligarth.tenant_set_mdm_key(?, ?)', [tenantId, edge.key]);
      await upsertMirror(trx, tenantId, {
        edge_state: edge.state === 'load_failed' ? 'load_failed' : mirrorStateOf(edge.state),
        edge_state_at: new Date(),
        commands_frozen: edge.commandsFrozen,
        ...(edge.ca ? { ca: edge.ca } : {}),
        verify_only: edge.verifyOnly.map((c) => ({ id: c.id, sha256: c.sha256, not_after: c.not_after })),
        last_error_code: null,
        last_synced_at: new Date(),
      });
      if (edge.ca) await recordDeviceCaDeadline(trx, tenantId, edge.ca);
      await resolveMasterInTx(trx, 'tenant.provisioning_failed', tenantId, ctx.dbActor, tenantId);
      const guard = await trx('tenant_guard_settings').where({ tenant_id: tenantId }).first('frozen_at') as { frozen_at: Date | null } | undefined;
      if (guard?.frozen_at && !edge.commandsFrozen) {
        await edgeFreezeSyncJob().sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
      }
      if (firstKey) {
        await audit.appendInTx(trx, {
          tenantId, action: 'apple.tenant_provisioned', target: { type: 'tenant', id: String(tenantId) },
          details: { created, state: edge.state },
        }, audit.fromJob({ name: ctx.name, requestId: ctx.requestId }), { onFailure: 'spool' });
      }
    });
  } catch (err) {
    if ((err as { code?: unknown })?.code === '23505') {
      // The tenant holds another key, or the key belongs to another tenant: the two bases disagree
      // (partial restore). Never retried.
      await raiseAlert(ctx.dbActor, MASTER_TENANT_ID, 'tenant.mdm_key_conflict', { discriminant: tenantId, params: { tenantName: await tenantName(tenantId, ctx) } });
      appleMetrics.provisioned('failed');
      throw new PermanentJobError('mdm_key_conflict', 'the MDM key of apple-edge conflicts with the brain\'s');
    }
    throw err;
  }
  appleMetrics.provisioned(created ? 'created' : 'existing');
  logger.info({ tenantId, created, firstKey, edgeState: edge.state }, 'tenant provisioned at apple-edge');

  // 4. The enrollment configuration in cache (a failure leaves it to the next reader).
  try {
    const ec = await appleEdge.enrollmentConfig(edge.key, o);
    await ctx.withTenant((trx) => upsertMirror(trx, tenantId, { enrollment_config: ec }));
  } catch (err) {
    logger.warn({ tenantId, code: isAppleEdgeError(err) ? err.code : 'error' }, 'enrollment configuration not cached after the provisioning');
  }
  return { output: { created, firstKey, state: edge.state } };
}

/** Every tenant without key, or whose mirror stayed in error for an hour: provisioned again. */
async function provisionAll(ctx: JobContext<unknown>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
  const tenants = await db('tenants').select('id', 'mdm_key').orderBy('id') as Array<{ id: number; mdm_key: string | null }>;
  let sent = 0;
  let failed = 0;
  for (const t of tenants) {
    ctx.throwIfAborted();
    try {
      const mirror = await asTenant(t.id, ctx.dbActor, () => db('tenant_apple_edge').where({ tenant_id: t.id }).first('edge_state', 'updated_at')) as
        { edge_state: string; updated_at: Date } | undefined;
      const due = !t.mdm_key
        ? !(mirror?.edge_state === 'error' && Date.now() - new Date(mirror.updated_at).getTime() < ERROR_RETRY_MS)
          && mirror?.edge_state !== 'retired'
        : !mirror || mirror.edge_state === 'unprovisioned'
          || (mirror.edge_state === 'error' && Date.now() - new Date(mirror.updated_at).getTime() >= ERROR_RETRY_MS);
      if (!due) continue;
      const id = await provisionHandle().send({ tenantId: t.id }, { singletonKey: `t:${t.id}`, tenantId: t.id });
      if (id) sent++;
    } catch (err) {
      failed++;
      logger.warn({ tenantId: t.id, code: (err as { code?: unknown })?.code }, 'apple-edge.provision-all: tenant skipped');
    }
  }
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${sent} sent`);
  return { output: { tenants: tenants.length, sent } };
}

let provisionJob: ReturnType<typeof registerProvisionJob> | null = null;

function registerProvisionJob() {
  return registerJob({
    name: 'apple-edge.provision-tenant',
    scope: 'tenant',
    description: 'Create (or read) the tenant at apple-edge, write its MDM key once, mirror its state',
    payload: TenantPayload,
    policy: 'exclusive',
    retry: { limit: 8, delaySeconds: 30, backoff: true, maxDelaySeconds: 3_600 },
    timeoutSeconds: 120,
    deadLetter: true,
    notify: true,
    pollSeconds: 30,                                   // woken by NOTIFY on send (file-durable L3)
    handler: provisionTenant,
  });
}

function provisionHandle(): NonNullable<typeof provisionJob> {
  if (!provisionJob) throw new Error('apple: the module is not registered (registerAppleModule)');
  return provisionJob;
}

/** The administration's "Retry" (§6.2): the provisioning job now (null: one is already queued or running). */
export function provisionTenantNow(tenantId: number): Promise<string | null> {
  return provisionHandle().send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
}

let registered = false;

export function registerTenantJobs(): void {
  if (registered) return;
  registered = true;
  provisionJob = registerProvisionJob();
  setProvisionSender((trx, tenantId) => provisionHandle().sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));

  registerJob({
    name: 'apple-edge.provision-all',
    scope: 'platform',
    description: 'Provision at apple-edge every tenant without MDM key (or whose mirror stayed in error)',
    payload: empty,
    // Explicit: the schedule depends on the mode, the policy of the queue must not (a queue never changes it).
    policy: 'exclusive',
    // APPLE_EDGE_MODE=off: neither scheduled nor sent at start (no call to make; file-durable L3)
    ...(config.apple.mode === 'on' ? { schedule: { cron: '7 * * * *' }, runAtStart: true } : {}),
    pollSeconds: 60,
    timeoutSeconds: 300,
    handler: provisionAll,
  });

  registerJob({
    name: 'apple-edge.health',
    scope: 'platform',
    description: 'Probe of apple-edge (GET /internal/v1/status): reachability, version, alerts of the master tenant',
    payload: empty,
    // Explicit: the schedule depends on the mode, the policy of the queue must not (a queue never changes it).
    policy: 'exclusive',
    ...(config.apple.mode === 'on' ? { schedule: { cron: '* * * * *' } } : {}),   // off: no probe
    retry: { limit: 0 },
    timeoutSeconds: 30,
    notify: true,
    pollSeconds: 30,
    handler: async (ctx): Promise<JobResult> => {
      if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
      const r = await probeEdge(ctx.dbActor, ctx.requestId);
      return { output: { up: r.up, compatible: r.compatible } };
    },
  });
}

