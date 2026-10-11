import type { Knex } from 'knex';
import { z } from 'zod';
import { config } from '../config';
import { db } from '../db';
import { allTenantIds, forEachTenant, withTenantTransaction } from '../db/tenantContext';
import {
  appleRetentionRules, purgeDeviceInEdge, purgeEnrollmentSessionsSlice, purgeEnrollmentTokensSlice,
} from '../apple/retention';
import { JobError, registerJob, type JobContext, type JobHandle, type JobResult } from '../jobs';
import { safeErr } from '../jobs/errors';
import { deleteDueDeviceRecords, devicesDueForPurge, mdmRetentionRules, type MdmRetentionRule } from '../mdm/inventory/retention';
import { logger } from '../utils/logger';

// =============================================================================
// PRIVACY — generic retention (CNF-04; docs: file-durable annex B,
// modele-donnees-mdm §5.5, integration-apple-edge §4.9 and §13.3).
//   - privacy.retention-all (daily, platform): one privacy.retention-tenant
//     per tenant (exclusive, key t:<id>: a tenant whose previous run is not
//     over is not queued twice);
//   - privacy.retention-tenant: the rules of the data model (departed end
//     users, DDM status history, lost-mode locations) and of the integration
//     (commands of the queue, timeline, devices removed from Apple Business),
//     then the records of the devices out of management, in slices (motif M8:
//     each slice its own tenant transaction, abort checked between two,
//     idempotent: a new run starts again from the database). A rule that
//     fails does not stop the others; the run fails afterwards.
//     A device record is deleted ONLY after its enrollments were purged at
//     apple-edge (apple/retention.ts purgeDeviceInEdge, integration §13.3),
//     outside any transaction; a failure postpones it to the next run, and
//     without apple-edge (mode off, unreachable, tenant unknown there) no
//     record is deleted at all;
//   - enrollment.purge-expired (daily): enrollment sessions ended or
//     abandoned for 30 days, enrollment tokens expired or revoked for 90 days
//     (integration §4.9).
// Schedules in UTC, off the hour, between 02:00 and 05:00, five minutes from
// the others (file-durable §6.2). index.ts calls registerPrivacyModule()
// before anything starts.
// =============================================================================

/** Rows per slice (motif M8). */
const SLICE_ROWS = 500;
/** Device records per slice: each one costs calls to apple-edge. */
const DEVICE_SLICE = 25;

const empty = z.object({}).strict();
const TenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();

let tenantJob: JobHandle<z.infer<typeof TenantPayload>> | null = null;

/** A rule's name as a key of the job's output (letters, digits and underscores only). */
const outputKey = (name: string): string => name.replace(/[^A-Za-z0-9_]/g, '_');

/** Applies `slice` (at most SLICE_ROWS rows, in its own tenant transaction) until a slice removes fewer
 *  rows than that. */
async function drain(ctx: JobContext<unknown>, slice: (trx: Knex.Transaction) => Promise<number>): Promise<number> {
  let total = 0;
  for (;;) {
    ctx.throwIfAborted();
    const n = await ctx.withTenant(slice);
    total += n;
    if (n < SLICE_ROWS) return total;
  }
}

// ── Device records: purge at apple-edge first (integration §13.3) ───────────

interface DeviceRecordsResult { deleted: number; deferred: number; skipped: string | null }

/** The records due: purged at apple-edge one by one, then deleted by slice. The slices follow the ids
 *  (a record postponed is passed, never retried in the same run); the next run starts again from the
 *  first record still due. */
async function purgeDeviceRecords(ctx: JobContext<unknown>, tenantId: number, now: Date): Promise<DeviceRecordsResult> {
  const due = await ctx.inTenant(() => devicesDueForPurge(db, tenantId, now, 1));
  if (!due.length) return { deleted: 0, deferred: 0, skipped: null };
  // APPLE_EDGE_MODE=off: the enrollments cannot be purged at apple-edge, so no record is deleted.
  if (config.apple.mode !== 'on') return { deleted: 0, deferred: 0, skipped: 'apple_edge_off' };
  const key = await ctx.inTenant(async () => {
    const t = await db('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
    return t?.mdm_key ?? null;
  });
  if (!key) return { deleted: 0, deferred: 0, skipped: 'tenant_without_key' };

  let deleted = 0;
  let deferred = 0;
  let afterId = 0;
  for (;;) {
    ctx.throwIfAborted();
    const cursor = afterId;
    const ids = await ctx.inTenant(() => devicesDueForPurge(db, tenantId, now, DEVICE_SLICE, cursor));
    if (!ids.length) break;
    afterId = ids[ids.length - 1];
    const purged: number[] = [];
    let stopped: string | null = null;
    for (const id of ids) {
      ctx.throwIfAborted();
      const r = await purgeDeviceInEdge(ctx, tenantId, key, id, now);
      if (r === 'purged') purged.push(id);
      else if (r === 'deferred') deferred++;
      else { stopped = r; break; }
    }
    // What was purged at apple-edge is deleted even when the run stops here.
    if (purged.length) {
      const n = await ctx.withTenant((trx) => deleteDueDeviceRecords(trx, tenantId, now, purged));
      deleted += n;
      deferred += purged.length - n;                   // came back under management meanwhile
    }
    if (stopped) return { deleted, deferred, skipped: stopped };
    if (ids.length < DEVICE_SLICE) break;
  }
  return { deleted, deferred, skipped: null };
}

// ── privacy.retention-tenant ───────────────────────────────────────────────

async function retentionTenant(ctx: JobContext<z.infer<typeof TenantPayload>>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const now = new Date();                              // one instant for the whole run
  const output: Record<string, string | number | boolean | null> = {};
  const failed: string[] = [];
  /** One step of the run: its failure is logged and counted, the next steps still run. An abort ends the run. */
  const step = async (name: string, work: () => Promise<void>): Promise<void> => {
    try {
      ctx.throwIfAborted();
      await work();
    } catch (err) {
      if (ctx.signal.aborted) throw err;
      failed.push(name);
      ctx.log.warn({ err: safeErr(err), rule: name }, 'privacy.retention: rule failed, the others go on');
    }
  };
  const rules: MdmRetentionRule[] = [...mdmRetentionRules, ...appleRetentionRules];
  for (const rule of rules) {
    await step(rule.name, async () => {
      output[outputKey(rule.name)] = await drain(ctx, (trx) => rule.purge(trx, tenantId, now, SLICE_ROWS));
    });
  }
  await step('devices.records', async () => {
    const devices = await purgeDeviceRecords(ctx, tenantId, now);
    output.devices_records = devices.deleted;
    output.devicesDeferred = devices.deferred;
    output.devicesSkipped = devices.skipped;
    if (devices.skipped && devices.skipped !== 'apple_edge_off') {
      // The other rules are done; the records wait for the next run.
      logger.warn({ tenantId, reason: devices.skipped }, 'privacy.retention: device records postponed');
    }
  });
  if (failed.length) throw new JobError('partial_failure', `${failed.length} retention rule(s) failed: ${failed.join(', ')}`);
  return { output };
}

// ── Registration ─────────────────────────────────────────────────────────────

let registered = false;

export function registerPrivacyModule(): void {
  if (registered) return;
  registered = true;

  tenantJob = registerJob({
    name: 'privacy.retention-tenant',
    scope: 'tenant',
    description: 'Retention of one tenant: departed end users, status history, locations, settled commands, timeline, device records (after apple-edge)',
    payload: TenantPayload,
    policy: 'exclusive',
    retry: { limit: 2, delaySeconds: 300, backoff: true, maxDelaySeconds: 3_600 },
    timeoutSeconds: 1_800,
    heartbeatSeconds: 60,
    // Woken by NOTIFY when privacy.retention-all queues it, polled once a minute at rest (file-durable L3).
    notify: true,
    pollSeconds: 60,
    deadLetter: false,                                 // the next daily run starts again
    trackStatus: 'tenant',
    handler: retentionTenant,
  });

  registerJob({
    name: 'privacy.retention-all',
    scope: 'platform',
    description: 'Queue the retention of every tenant (privacy.retention-tenant)',
    payload: empty,
    schedule: { cron: '5 3 * * *' },
    policy: 'exclusive',
    notify: true,
    pollSeconds: 60,
    timeoutSeconds: 300,
    handler: async (ctx) => {
      const ids = await allTenantIds();
      let queued = 0;
      let failed = 0;
      for (const tenantId of ids) {
        ctx.throwIfAborted();
        try {
          if (await tenantJob!.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId })) queued++;
        } catch (err) {
          failed++;
          logger.warn({ tenantId, code: (err as { code?: unknown })?.code }, 'privacy.retention-all: tenant not queued');
        }
      }
      if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) not queued, ${queued} queued`);
      return { output: { tenants: ids.length, queued } };
    },
  });

  registerJob({
    name: 'enrollment.purge-expired',
    scope: 'platform',
    description: 'Delete the enrollment sessions ended or abandoned for 30 days and the enrollment tokens expired or revoked for 90 days',
    payload: empty,
    schedule: { cron: '40 3 * * *' },
    policy: 'exclusive',
    notify: true,
    pollSeconds: 60,
    timeoutSeconds: 900,
    heartbeatSeconds: 60,
    handler: async (ctx) => {
      const now = new Date();
      let sessions = 0;
      let tokens = 0;
      /** One tenant's slices of `slice`, each in its own transaction, until one is not full. */
      const drainTenant = async (tenantId: number,
        slice: (trx: Knex.Transaction, tenantId: number, now: Date, limit: number) => Promise<number>): Promise<number> => {
        let total = 0;
        for (;;) {
          ctx.throwIfAborted();
          const n = await withTenantTransaction(tenantId, ctx.dbActor, (trx) => slice(trx, tenantId, now, SLICE_ROWS));
          total += n;
          if (n < SLICE_ROWS) return total;
        }
      };
      const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
        sessions += await drainTenant(tenantId, purgeEnrollmentSessionsSlice);
        tokens += await drainTenant(tenantId, purgeEnrollmentTokensSlice);
      });
      if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
      return { output: { tenants: ok, sessions, tokens } };
    },
  });
}
