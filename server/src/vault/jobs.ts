// The vault's durable jobs and hooks (docs: coffre-secrets §6.6, §6.7, §11.4;
// file-durable annex B), registered by index.ts (registerVaultJobs) before
// jobs.start():
//   vault.reencrypt-tenant   on demand (DEK rotation), exclusive per tenant
//                            (singleton key t:<id> or t:instance), by slices;
//   vault.verify-daily       daily: every DEK unwraps, one sealed value per
//                            column and DEK opens; metric and alert;
//   vault.tenant-secrets-gc  daily: garbage collection of tenant_secrets;
// a boot task that expires the stale authorizations and resumes the DEK
// rotations left authorized or running; and the executor of the two-step
// approval 'vault_kek_rotation' (an operation authorized for 24 h, run by the
// CLI with the server stopped). Payloads carry identifiers only.
import type { Knex } from 'knex';
import { z } from 'zod';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { db } from '../db';
import { JobError, SCHEDULED_POLL_SECONDS, registerJob, type JobHandle } from '../jobs';
import { registerBootTask } from '../lifecycle';
import { refuse, registerApprovalRequestType, requirePlatformAdmin } from '../services/approval.service';
import { logger } from '../utils/logger';
import { masterEntry, vaultAlert, writeVaultAudit } from './events';
import { KEK_ROTATION_VALIDITY_MS, vaultOperations } from './operations';
import { runDekRotation } from './reseal';
import { collectTenantSecrets, verifyVault } from './verify';
import { vaultInternals } from './vault';
import { vaultMetrics } from './metrics';

const OperationPayload = z.object({ operationId: z.string().uuid() }).strict();
const empty = z.object({}).strict();

let reencrypt: JobHandle<z.infer<typeof OperationPayload>> | null = null;
let registered = false;

/** Sends the re-encryption of a DEK rotation (one at a time per tenant),
 *  inside `trx` when given (the job exists if and only if it commits). */
export async function sendDekRotation(operationId: string, tenantId: number | null, trx?: Knex.Transaction): Promise<string | null> {
  if (!reencrypt) throw new Error('vault jobs not registered');
  const opts = { singletonKey: tenantId === null ? 't:instance' : `t:${tenantId}` };
  return trx ? reencrypt.sendInTx(trx, { operationId }, opts) : reencrypt.send({ operationId }, opts);
}

export function registerVaultJobs(): void {
  if (registered) return;
  registered = true;

  reencrypt = registerJob({
    name: 'vault.reencrypt-tenant',
    scope: 'platform',
    description: 'Reseal the secrets of a tenant (or of the instance) under its new data key (DEK rotation)',
    payload: OperationPayload,
    policy: 'exclusive',
    // A rotation is rare (an incident, never periodic) and long: a slow poll
    // keeps the server's queries at rest low (L3 of the durable queue).
    pollSeconds: 15,
    retry: { limit: 3, delaySeconds: 60, backoff: true, maxDelaySeconds: 900 },
    timeoutSeconds: 3600,
    heartbeatSeconds: 60,
    deadLetter: true,
    handler: async (ctx) => {
      const r = await runDekRotation(ctx.payload.operationId, { actor: ctx.dbActor, signal: ctx.signal });
      const n = Object.values(r.resealed).reduce((a, b) => a + b, 0);
      return { output: { resealed: n, tenant: r.tenantId ?? 'instance' } };
    },
  });

  registerJob({
    name: 'vault.verify-daily',
    scope: 'platform',
    description: 'Check that every data key unwraps and that one sealed value per column and key opens',
    payload: empty,
    schedule: { cron: '10 4 * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    timeoutSeconds: 900,
    handler: async (ctx) => {
      const report = await verifyVault({ actor: ctx.dbActor, signal: ctx.signal });
      vaultMetrics.setVerifyFailures(report.failures);
      if (report.failures > 0) {
        const failed = Object.fromEntries(Object.entries(report.columns).filter(([, c]) => c.failed > 0).map(([k, c]) => [k, c.failed]));
        await writeVaultAudit([masterEntry('vault.verify_failed', { deksFailed: report.deks.failed, columns: failed })]);
        vaultAlert('vault:verify-failed', 'Vault verification failed',
          `${report.failures} key(s) or sealed value(s) could not be opened: see the vault operations and the server logs.`);
        throw new JobError('verify_failed', `${report.failures} failure(s)`);
      }
      return { output: { deks: report.deks.checked, values: Object.values(report.columns).reduce((n, c) => n + c.checked, 0) } };
    },
  });

  registerJob({
    name: 'vault.tenant-secrets-gc',
    scope: 'platform',
    description: 'Mark the tenant secrets no document refers to, delete them 30 days later',
    payload: empty,
    schedule: { cron: '25 4 * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    timeoutSeconds: 900,
    handler: async (ctx) => {
      const r = await collectTenantSecrets(ctx.dbActor);
      return { output: { orphaned: r.orphaned, revived: r.revived, deleted: r.deleted } };
    },
  });

  // After jobs.start(): expired authorizations, and the DEK rotations to resume.
  registerBootTask('vault.resume-operations', async () => {
    try {
      const expired = await vaultOperations.expireStale(db);
      if (expired) logger.info({ expired }, 'vault: authorizations past their validity expired');
      const ops = await db('vault_operations').where({ kind: 'dek_rotation' }).whereIn('state', ['authorized', 'running'])
        .select('id', 'tenant_id', 'params') as Array<{ id: string; tenant_id: number | null; params: Record<string, unknown> | null }>;
      for (const op of ops) {
        const t = op.params && typeof op.params.tenantId === 'number' ? op.params.tenantId : null;
        await sendDekRotation(op.id, t);
      }
      if (ops.length) logger.info({ operations: ops.length }, 'vault: DEK rotations resumed');
    } catch (err) {
      logger.error({ code: (err as { code?: string }).code ?? 'error' }, 'vault: operations not resumed at start');
      vaultAlert('vault:resume-failed', 'Vault operations not resumed', 'The pending key rotations could not be resumed at start.', 'warning');
    }
  });

  // Two-step approval of a KEK rotation (V12): approved by another platform
  // administrator, executed as the requester; it authorizes the operation for
  // 24 h, which the CLI runs with the server stopped (vault kek-rotate).
  registerApprovalRequestType('vault_kek_rotation', async ({ tenantId, requesterId, payload }) => {
    await requirePlatformAdmin(requesterId);
    if (tenantId !== MASTER_TENANT_ID) refuse('A KEK rotation is requested from the master tenant');
    const operationId = typeof payload?.operationId === 'string' ? payload.operationId : '';
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(operationId)) refuse('Invalid request: no operation id');
    vaultInternals.requireReady();
    if (await vaultOperations.get(db, operationId)) refuse('This KEK rotation was already authorized');
    const approval = await db('pending_approvals').where({ tenant_id: MASTER_TENANT_ID, request_type: 'vault_kek_rotation' })
      .whereRaw("payload ->> 'operationId' = ?", [operationId]).first('id') as { id: number } | undefined;
    const op = await vaultOperations.create(db, {
      id: operationId, kind: 'kek_rotation', state: 'authorized', approvalId: approval?.id ?? null,
      requestedBy: requesterId, reason: typeof payload?.reason === 'string' ? payload.reason : null,
      params: { kekId: vaultInternals.keyring.provider().id },
      authorizedUntil: new Date(Date.now() + KEK_ROTATION_VALIDITY_MS),
    });
    logger.info({ operationId: op.id }, 'vault: KEK rotation authorized for 24 hours');
  });
}
