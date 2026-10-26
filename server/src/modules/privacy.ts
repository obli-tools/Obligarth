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
import {
  channelsDueForPurge, deleteDueDeviceRecords, devicesDueForPurge, mdmRetentionRules, realignLostModePurgeDates, realignRetentionDates,
  type MdmRetentionRule,
} from '../mdm/inventory/retention';
import { legacyAgentRetentionRules } from '../legacyAgent/retention';
import type { ManagementChannel } from '../guard/types';
import { registerPrivacyProfileChanges } from '../privacy';
import { installPrivacyProfiles } from '../privacy/profiles';
import { privacyMetrics } from '../privacy/metrics';
import { registerMetricsCollector } from '../ops/metrics';
import { logger } from '../utils/logger';

// =============================================================================
// PRIVACY — generic retention (CNF-04; docs: file-durable annex B,
// modele-donnees-mdm §5.5, integration-apple-edge §4.9 and §13.3).
//   - privacy.retention-all (daily, platform): one privacy.retention-tenant
//     per tenant (exclusive, key t:<id>: a tenant whose previous run is not
//     over is not queued twice);
//   - privacy.retention-tenant: the rules of the data model (departed end
//     users, DDM status history, lost-mode locations), of the integration
//     (commands of the queue, timeline, devices removed from Apple Business)
//     and of the bridge agent (its commands), with the durations of the
//     tenant (P0-13 T4, CNF-04: privacy/retention.ts, the defaults when it set
//     none); the dates of purge of the positions in lost mode (before the
//     rules: realignLostModePurgeDates) and of the records out of management
//     (realignRetentionDates) follow a change of the tenant's retention; then the
//     records of the devices out of management, in slices (motif M8:
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
// before anything starts; it also installs the tenants' privacy profiles as
// the resolver of the collection rules (privacy/profiles.ts, P0-13 T1) and
// registers their changes and the retention's (privacy/index.ts, P0-13 T3
// and T4: approvals, audit, restrictions, job privacy.apply-profile). Two
// failures in a row of privacy.retention-tenant raise the alert
// privacy.retention_failing of the master tenant (key privacy:retention:<id>,
// one per tenant, instead of jobs:failing). Counters: privacy/metrics.ts, the
// collector 'privacy' of ops/metrics.ts.
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
      privacyMetrics.ruleFailed(name);
      ctx.log.warn({ err: safeErr(err), rule: name }, 'privacy.retention: rule failed, the others go on');
    }
  };
  // The dates of purge of the positions in lost mode, after a change of lost_mode_location_days (an increase as a
  // decrease), before the rules: a position kept longer by an increase is not purged by its former date.
  await step('lost_mode_locations.purge_at', async () => {
    output.lost_mode_locations_realigned = await drain(ctx, (trx) => realignLostModePurgeDates(trx, tenantId, SLICE_ROWS));
  });
  const rules: MdmRetentionRule[] = [...mdmRetentionRules, ...appleRetentionRules, ...legacyAgentRetentionRules];
  for (const rule of rules) {
    await step(rule.name, async () => {
      const n = await drain(ctx, (trx) => rule.purge(trx, tenantId, now, SLICE_ROWS));
      output[outputKey(rule.name)] = n;
      privacyMetrics.purged(rule.name, n);
    });
  }
  // The dates of purge of the records out of management, after a change of the tenant's retention (before the records
  // due are listed: they are purged by the value in force).
  await step('devices.retention_until', async () => {
    const n = await drain(ctx, (trx) => realignRetentionDates(trx, tenantId, SLICE_ROWS));
    output.devices_realigned = n;
    privacyMetrics.realigned(n);
  });
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

/** One slice of a module's enrollment tokens ended long enough ago (enrollment.purge-expired, after the sessions and
 *  the tokens of lot C1): at most `limit` rows deleted in `trx` (the tenant's context). Android: its AMAPI tokens used,
 *  expired, revoked or failed for 90 days (android-amapi §4.8, §10.3; lot AN-C1). */
export type EnrollmentPurgeSlice = (trx: Knex.Transaction, tenantId: number, now: Date, limit: number) => Promise<number>;
const enrollmentPurgeSlices: Array<{ name: string; slice: EnrollmentPurgeSlice }> = [];
export function registerEnrollmentPurgeSlice(name: string, slice: EnrollmentPurgeSlice): void {
  if (!enrollmentPurgeSlices.some((x) => x.name === name)) enrollmentPurgeSlices.push({ name, slice });
}
/** The names of the registered slices (the testbed). */
export const enrollmentPurgeSliceNames = (): string[] => enrollmentPurgeSlices.map((x) => x.name);

export function registerPrivacyModule(): void {
  if (registered) return;
  registered = true;

  // The tenants' privacy profiles replace the laboratory rules of every Apple consumer (P0-13 T1, CNF-02), before any
  // service runs; a tenant without a profile keeps the rules of before.
  installPrivacyProfiles();
  // Their changes (P0-13 T3) and the retention's (T4): the approval request types and their examination, the audit
  // actions, the restrictions privacy.profile_change and privacy.retention_change, the job privacy.apply-profile.
  registerPrivacyProfileChanges();

  // The counters of the module (rows purged per rule, failures, changes), no tenant label.
  registerMetricsCollector('privacy', () => privacyMetrics.families());

  // The purger of the Apple channel (the other channels register theirs: legacy_agent, amapi; lot AN-P).
  registerDevicePurger('apple_mdm', appleDevicePurger);

  tenantJob = registerJob({
    name: 'privacy.retention-tenant',
    scope: 'tenant',
    description: 'Retention of one tenant, its durations: departed end users, status history, locations, settled commands (MDM queue, bridge agent), timeline, device records (after apple-edge)',
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
    // privacy.retention_failing (P0-13 T4): from the second failure in a row of a tenant, one alert per tenant.
    alertAfterFailures: 2,
    failureAlert: ({ tenantId, failures, code }) => ({
      stableKey: `privacy:retention:${tenantId ?? 0}`,
      severity: 'warning',
      title: 'Retention failing (privacy.retention_failing)',
      message: `The retention of tenant ${tenantId ?? '?'} failed ${failures} times in a row (last error: ${code}): data past their retention are kept until it succeeds.`,
    }),
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
        for (const x of enrollmentPurgeSlices) tokens += await drainTenant(tenantId, x.slice);
      });
      if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
      return { output: { tenants: ok, sessions, tokens } };
    },
  });
}
