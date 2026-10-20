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
import { channelsDueForPurge, deleteDueDeviceRecords, devicesDueForPurge, mdmRetentionRules, type MdmRetentionRule } from '../mdm/inventory/retention';
import type { ManagementChannel } from '../guard/types';
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
//     A device record is deleted ONLY after the purger of its management
//     channel purged it outside the brain (registerDevicePurger, lot AN-P,
//     COH-10), outside any transaction: apple_mdm purges its enrollments at
//     apple-edge (apple/retention.ts purgeDeviceInEdge, integration §13.3),
//     amapi deletes its own policy at Google and checks the device is gone
//     there, legacy_agent has nothing outside the brain. A failure postpones
//     it to the next run; a channel that cannot purge (apple-edge off,
//     unreachable, tenant unknown there or without its MDM key; no purger
//     registered) keeps its records, never the other channels' (a tenant
//     without an MDM key is not skipped for its other channels);
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

// ── Device records: purged by the purger of their channel first (COH-10) ────

interface DeviceRecordsResult { deleted: number; deferred: number; skipped: string | null }

/** What a purger needs of the job that runs it (a JobContext of a tenant job, the tenant and the run's instant). */
export interface DevicePurgeContext {
  readonly tenantId: number;
  readonly now: Date;
  readonly actor: string;
  readonly requestId: string;
  readonly signal: AbortSignal;
  throwIfAborted(): void;
  /** fn in the tenant's database context, each statement its own lease (no transaction held open). */
  inTenant<T>(fn: () => Promise<T>): Promise<T>;
}

/** The purge of the records of one channel outside the brain (android-amapi §22.6, COH-10). */
export interface DevicePurger {
  /** null: the channel can purge in this run; else why its records all wait (apple_edge_off, tenant_without_key). */
  ready?(ctx: DevicePurgeContext): Promise<string | null>;
  /**
   * Purges outside the brain the records `deviceIds` (due at ctx.now, of the channel, ascending, one slice): those
   * `purged` are deleted by the caller (only those still due); `deferred` were postponed to the next run; `stopped`:
   * why the rest of the channel waits (what was purged before is still deleted).
   */
  purge(ctx: DevicePurgeContext, deviceIds: number[]): Promise<{ purged: number[]; deferred: number; stopped: string | null }>;
}

const purgers = new Map<ManagementChannel, DevicePurger>();

/** The purger of a management channel (one per channel, registered by its module before anything runs). */
export function registerDevicePurger(channel: ManagementChannel, purger: DevicePurger): void {
  if (purgers.has(channel)) throw new Error(`device purger of ${channel}: registered twice`);
  purgers.set(channel, purger);
}

/** The records due of one channel: purged by its purger by slice, then deleted. The slices follow the ids (a record
 *  postponed is passed, never retried in the same run); the next run starts again from the first record still due. */
async function purgeChannelRecords(ctx: JobContext<unknown>, pctx: DevicePurgeContext, channel: string, purger: DevicePurger):
  Promise<DeviceRecordsResult> {
  const { tenantId, now } = pctx;
  const notReady = purger.ready ? await purger.ready(pctx) : null;
  if (notReady) return { deleted: 0, deferred: 0, skipped: notReady };
  let deleted = 0;
  let deferred = 0;
  let afterId = 0;
  for (;;) {
    ctx.throwIfAborted();
    const cursor = afterId;
    const ids = await ctx.inTenant(() => devicesDueForPurge(db, tenantId, now, DEVICE_SLICE, cursor, channel));
    if (!ids.length) break;
    afterId = ids[ids.length - 1];
    const r = await purger.purge(pctx, ids);
    const purged = r.purged.filter((id) => ids.includes(id));
    deferred += r.deferred;
    // What was purged outside the brain is deleted even when the run stops here.
    if (purged.length) {
      const n = await ctx.withTenant((trx) => deleteDueDeviceRecords(trx, tenantId, now, purged));
      deleted += n;
      deferred += purged.length - n;                   // came back under management meanwhile
    }
    if (r.stopped) return { deleted, deferred, skipped: r.stopped };
    if (ids.length < DEVICE_SLICE) break;
  }
  return { deleted, deferred, skipped: null };
}

/** The records due of every channel, each by its purger (registration order of the purgers: legacy_agent, apple_mdm,
 *  amapi as index.ts loads the modules; each channel independent of the others); a channel without a
 *  purger keeps its records (no_purger). `skipped`: the first reason a channel waited. */
async function purgeDeviceRecords(ctx: JobContext<unknown>, tenantId: number, now: Date): Promise<DeviceRecordsResult> {
  const channels = await ctx.inTenant(() => channelsDueForPurge(db, tenantId, now));
  if (!channels.length) return { deleted: 0, deferred: 0, skipped: null };
  const order = [...purgers.keys()] as string[];
  const rank = (c: string): number => (order.includes(c) ? order.indexOf(c) : order.length);
  channels.sort((a, b) => rank(a) - rank(b));
  const pctx: DevicePurgeContext = {
    tenantId, now, actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal,
    throwIfAborted: () => ctx.throwIfAborted(), inTenant: (fn) => ctx.inTenant(fn),
  };
  const out: DeviceRecordsResult = { deleted: 0, deferred: 0, skipped: null };
  for (const channel of channels) {
    const purger = purgers.get(channel as ManagementChannel);
    const r = purger ? await purgeChannelRecords(ctx, pctx, channel, purger) : { deleted: 0, deferred: 0, skipped: 'no_purger' };
    out.deleted += r.deleted;
    out.deferred += r.deferred;
    out.skipped ??= r.skipped;
  }
  return out;
}

// ── The purger of the channel apple_mdm: apple-edge first (integration §13.3) ─

/** The MDM key of the tenant (its enrollments are `<key>_…` at apple-edge), null without one. */
async function mdmKeyOf(pctx: DevicePurgeContext): Promise<string | null> {
  return pctx.inTenant(async () => {
    const t = await db('tenants').where({ id: pctx.tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
    return t?.mdm_key ?? null;
  });
}

/** apple_mdm: every enrollment of the record purged at apple-edge before the record goes (purgeDeviceInEdge); without
 *  apple-edge (mode off) or without the tenant's MDM key, its records wait. */
export const appleDevicePurger: DevicePurger = {
  async ready(pctx) {
    // APPLE_EDGE_MODE=off: the enrollments cannot be purged at apple-edge, so no record is deleted.
    if (config.apple.mode !== 'on') return 'apple_edge_off';
    return (await mdmKeyOf(pctx)) ? null : 'tenant_without_key';
  },
  async purge(pctx, deviceIds) {
    const key = await mdmKeyOf(pctx);
    if (!key) return { purged: [], deferred: 0, stopped: 'tenant_without_key' };
    const purged: number[] = [];
    let deferred = 0;
    for (const id of deviceIds) {
      pctx.throwIfAborted();
      const r = await purgeDeviceInEdge(pctx, pctx.tenantId, key, id, pctx.now);
      if (r === 'purged') purged.push(id);
      else if (r === 'deferred') deferred++;
      else return { purged, deferred, stopped: r };
    }
    return { purged, deferred, stopped: null };
  },
};

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
    if (devices.skipped && devices.skipped !== 'apple_edge_off' && devices.skipped !== 'no_purger') {
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

  // The purger of the Apple channel (the other channels register theirs: legacy_agent, amapi; lot AN-P).
  registerDevicePurger('apple_mdm', appleDevicePurger);

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
