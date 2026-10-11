import type { Knex } from 'knex';
import { z } from 'zod';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { db } from '../../db';
import type { DbActor } from '../../db/context';
import { applyTenantContext, withTenantTransaction } from '../../db/tenantContext';
import { jobIdFor, registerJob, type JobHandle } from '../../jobs';
import { announce, emitResolved, trimTenant } from '../../services/liveAlert.service';
import { logger } from '../../utils/logger';
import {
  APPLE_ALERTS, cleanParams, isAppleAlertKind, render, stableKeyOf, type AlertParams, type AppleAlertKind,
  type AppleAlertSeverity,
} from './catalog';

// =============================================================================
// Alerts of the Apple integration (docs: integration-apple-edge §12.2, §12.3):
// written in the transaction of what raises them (an outbox event, a job, a
// route), deduplicated on the unresolved row of the same stable key (read or
// not: its parameters are refreshed, nothing new is announced), resolved by
// what ends them. Delivery after the commit by the durable job alerts.deliver
// (one per alert and event): NOTIFICATION_NEW / NOTIFICATION_RESOLVED to the
// tenant's notifications room, then the trim of the tenant to 200 rows. The
// external channels of a warning or critical alert (notification_bindings of
// the tenant, rendered in its language, throttled) come with the operations
// lot (C5).
//   raiseInTx / resolveInTx    the transaction's context is the alert's tenant
//   raiseMasterInTx            a platform alert from another context of the
//                              transaction (rule G-6: the master tenant's
//                              context, then the caller's again)
//   raiseAlert / resolveAlert  their own transaction, in the alert's tenant
// =============================================================================

export interface RaiseOptions {
  /** Internal identifier only (tenant id, device id, token id). */
  discriminant?: string | number;
  params?: AlertParams;
  navigateTo?: string | null;
  /** A severity above the catalogue's for this occurrence (§12.1: ade.token_error is critical when Apple refuses
   *  the token); never below it. */
  severity?: AppleAlertSeverity;
}

const SEVERITY_RANK: Record<AppleAlertSeverity, number> = { info: 0, warning: 1, critical: 2 };

/** The catalogue's severity, raised by the occurrence's when higher. */
function severityOf(kind: AppleAlertKind, wanted: AppleAlertSeverity | undefined): AppleAlertSeverity {
  const base = APPLE_ALERTS[kind].severity as AppleAlertSeverity;
  return wanted && SEVERITY_RANK[wanted] > SEVERITY_RANK[base] ? wanted : base;
}

const DeliverPayload = z.object({
  tenantId: z.number().int().positive(),
  alertId: z.number().int().positive(),
  event: z.enum(['raised', 'resolved']),
}).strict();

let deliverJob: JobHandle<z.infer<typeof DeliverPayload>> | null = null;

function requireKind(kind: string): AppleAlertKind {
  if (!isAppleAlertKind(kind)) throw new Error(`alert ${kind}: not in the catalogue`);
  return kind;
}

function checkScope(kind: AppleAlertKind, tenantId: number): void {
  if (APPLE_ALERTS[kind].scope === 'master' && tenantId !== MASTER_TENANT_ID) {
    throw new Error(`alert ${kind}: a platform alert is filed in the master tenant`);
  }
}

async function sendDelivery(trx: Knex.Transaction, tenantId: number, alertId: number, event: 'raised' | 'resolved'): Promise<void> {
  if (!deliverJob) {
    logger.warn({ tenantId, alertId, event }, 'apple alert written, not announced: the module is not registered');
    return;
  }
  await deliverJob.sendInTx(trx, { tenantId, alertId, event }, { id: jobIdFor('alerts.deliver', `${alertId}:${event}`), tenantId });
}

/** In the caller's transaction, whose database context is `tenantId`'s. */
export async function raiseInTx(trx: Knex.Transaction, tenantId: number, kindName: AppleAlertKind, opts: RaiseOptions = {}):
  Promise<{ id: number; created: boolean }> {
  const kind = requireKind(kindName);
  checkScope(kind, tenantId);
  const def = APPLE_ALERTS[kind];
  const stableKey = stableKeyOf(kind, opts.discriminant);
  const params = cleanParams(opts.params);
  await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`live_alert:${tenantId}:${stableKey}`]);
  const existing = await trx('live_alerts')
    .where({ tenant_id: tenantId, stable_key: stableKey })
    .whereNull('resolved_at')
    .orderBy('id', 'desc')
    .first('id', 'i18n_params', 'severity') as { id: number; i18n_params: AlertParams | null; severity: string } | undefined;
  const title = render(def.title, params).slice(0, 500);
  const message = render(def.message, params).slice(0, 2000);
  if (existing) {
    const set: Record<string, unknown> = {};
    if (JSON.stringify(existing.i18n_params ?? {}) !== JSON.stringify(params)) Object.assign(set, { i18n_params: JSON.stringify(params), title, message });
    // An occurrence graver than the open row raises it (an ADE server first in error, then refused by Apple); a
    // lighter one never lowers it.
    const wanted = severityOf(kind, opts.severity);
    if (SEVERITY_RANK[wanted] > (SEVERITY_RANK[existing.severity as AppleAlertSeverity] ?? 0)) set.severity = wanted;
    if (Object.keys(set).length > 0) await trx('live_alerts').where({ id: existing.id, tenant_id: tenantId }).update(set);
    return { id: Number(existing.id), created: false };
  }
  const [row] = await trx('live_alerts').insert({
    tenant_id: tenantId, severity: severityOf(kind, opts.severity), title, message, navigate_to: opts.navigateTo ?? null, stable_key: stableKey,
    kind, i18n_key: `apple.alerts.${kind}`, i18n_params: JSON.stringify(params),
  }).returning('id') as Array<{ id: number }>;
  const id = Number(row.id);
  await sendDelivery(trx, tenantId, id, 'raised');
  return { id, created: true };
}

/** The occurrence an event adds to a counted alert: its time and id order the occurrences (a total order). */
export interface CountedOccurrence {
  /** occurred_at of the event. */
  at: Date;
  /** event_id of the event (ties of the same millisecond). */
  eventId: string;
  /** What the occurrence adds to the count (1 by default). */
  increment?: number;
}

const counted = z.object({ lastAt: z.string(), lastEvent: z.string() });

/** (at, eventId) of `o` after the occurrence a row of the alert counted last? */
function isAfter(o: CountedOccurrence, params: unknown): boolean {
  const last = counted.safeParse(params);
  if (!last.success) return true;
  const lastAt = Date.parse(last.data.lastAt);
  if (!Number.isFinite(lastAt)) return true;
  const at = o.at.getTime();
  return at > lastAt || (at === lastAt && o.eventId.toLowerCase() > last.data.lastEvent.toLowerCase());
}

/**
 * A counted alert (aggregates whose count the events add up: enrollment.unknown_session, security.topic_mismatch,
 * security.identity_revoked, apns.throttled, ade.assignment_failed), idempotent: an occurrence adds to the count
 * only when it is after the last one counted by the alert's latest row (resolved or not), so that an event applied
 * again (at-least-once delivery, consumed_at reset) counts once (review of lot B2, MDM-B2-R7). An occurrence
 * consumed after a later one (events reordered across two batches) is not counted: the count is a lower bound.
 * The params carry lastAt and lastEvent (the event's time and id: never device data). In the caller's
 * transaction (tenant context). `counted` is false when the occurrence was already counted (nothing written).
 */
export async function raiseCountedInTx(trx: Knex.Transaction, tenantId: number, kindName: AppleAlertKind,
  o: CountedOccurrence, opts: RaiseOptions = {}): Promise<{ id: number | null; created: boolean; counted: boolean }> {
  const kind = requireKind(kindName);
  checkScope(kind, tenantId);
  const stableKey = stableKeyOf(kind, opts.discriminant);
  await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`live_alert:${tenantId}:${stableKey}`]);
  const latest = await trx('live_alerts')
    .where({ tenant_id: tenantId, stable_key: stableKey })
    .orderBy('id', 'desc')
    .first('id', 'i18n_params', 'resolved_at') as { id: number; i18n_params: AlertParams | null; resolved_at: Date | null } | undefined;
  if (latest && !isAfter(o, latest.i18n_params)) return { id: Number(latest.id), created: false, counted: false };
  const previous = latest && latest.resolved_at === null ? Number(latest.i18n_params?.count ?? 0) : 0;
  const increment = Math.max(0, Math.floor(o.increment ?? 1));
  const r = await raiseInTx(trx, tenantId, kind, {
    ...opts,
    params: {
      ...(opts.params ?? {}),
      count: (Number.isFinite(previous) ? previous : 0) + increment,
      lastAt: o.at.toISOString(),
      lastEvent: o.eventId.toLowerCase(),
    },
  });
  return { ...r, counted: true };
}

/** Window of the spike of enrollments (§12.1). */
const SPIKE_WINDOW_MINUTES = 10;
/** The spike also exceeds this many times the average of the last seven days (per window). */
const SPIKE_FACTOR = 5;

/**
 * enrollment.spike (§12.1): APPLE_ENROLLMENT_SPIKE_COUNT enrollments of the tenant ended in the last 10 minutes
 * (episodes enrolled up to `at`), and more than five times the average of the seven previous days per 10 minutes.
 * Counted from the episodes: idempotent. Resolved automatically after 24 h (alerts.auto-resolve, lot C5).
 */
export async function checkEnrollmentSpike(trx: Knex.Transaction, tenantId: number, at: Date, threshold: number): Promise<boolean> {
  const since = new Date(at.getTime() - SPIKE_WINDOW_MINUTES * 60_000);
  const recent = await trx('device_enrollments').where({ tenant_id: tenantId })
    .where('enrolled_at', '>', since).where('enrolled_at', '<=', at)
    .count('* as n').first() as { n: string | number } | undefined;
  const count = Number(recent?.n ?? 0);
  if (count < threshold) return false;
  const weekStart = new Date(since.getTime() - 7 * 86_400_000);
  const week = await trx('device_enrollments').where({ tenant_id: tenantId })
    .where('enrolled_at', '>', weekStart).where('enrolled_at', '<=', since)
    .count('* as n').first() as { n: string | number } | undefined;
  const average = Number(week?.n ?? 0) / ((7 * 24 * 60) / SPIKE_WINDOW_MINUTES);
  if (count <= SPIKE_FACTOR * average) return false;
  await raiseInTx(trx, tenantId, 'enrollment.spike', { params: { count, minutes: SPIKE_WINDOW_MINUTES } });
  return true;
}

/** Resolves the unresolved rows of the kind (and discriminant) in the caller's transaction (tenant context). */
export async function resolveInTx(trx: Knex.Transaction, tenantId: number, kindName: AppleAlertKind, discriminant?: string | number): Promise<number[]> {
  const kind = requireKind(kindName);
  checkScope(kind, tenantId);
  const stableKey = stableKeyOf(kind, discriminant);
  const rows = await trx('live_alerts')
    .where({ tenant_id: tenantId, stable_key: stableKey })
    .whereNull('resolved_at')
    .update({ resolved_at: new Date() })
    .returning('id') as Array<{ id: number }>;
  const ids = rows.map((r) => Number(r.id));
  for (const id of ids) await sendDelivery(trx, tenantId, id, 'resolved');
  return ids;
}

/** A platform alert from a transaction in another context (rule G-6): the master tenant's context for the
 *  write, then `restore` (the tenant of the caller's context, or null for 'none'). */
export async function raiseMasterInTx(trx: Knex.Transaction, kind: AppleAlertKind, opts: RaiseOptions, actor: DbActor,
  restore: number | null): Promise<{ id: number; created: boolean }> {
  await applyTenantContext(trx, MASTER_TENANT_ID, actor);
  try {
    return await raiseInTx(trx, MASTER_TENANT_ID, kind, opts);
  } finally {
    await applyTenantContext(trx, restore, actor);
  }
}

export async function resolveMasterInTx(trx: Knex.Transaction, kind: AppleAlertKind, discriminant: string | number | undefined,
  actor: DbActor, restore: number | null): Promise<number[]> {
  await applyTenantContext(trx, MASTER_TENANT_ID, actor);
  try {
    return await resolveInTx(trx, MASTER_TENANT_ID, kind, discriminant);
  } finally {
    await applyTenantContext(trx, restore, actor);
  }
}

/** Its own transaction, in the alert's tenant (the master tenant for a platform alert). Never throws: an
 *  alert that cannot be written is logged. */
export async function raiseAlert(actor: DbActor, tenantId: number, kind: AppleAlertKind, opts: RaiseOptions = {}): Promise<void> {
  try {
    await withTenantTransaction(tenantId, actor, (trx) => raiseInTx(trx, tenantId, kind, opts));
  } catch (err) {
    logger.error({ alert: kind, tenantId, code: (err as { code?: unknown })?.code }, 'apple alert not written');
  }
}

export async function resolveAlert(actor: DbActor, tenantId: number, kind: AppleAlertKind, discriminant?: string | number): Promise<void> {
  try {
    await withTenantTransaction(tenantId, actor, (trx) => resolveInTx(trx, tenantId, kind, discriminant));
  } catch (err) {
    logger.error({ alert: kind, tenantId, code: (err as { code?: unknown })?.code }, 'apple alert not resolved');
  }
}

/** alerts.deliver: Socket.io, then the trim of the tenant. */
async function deliver(tenantId: number, alertId: number, event: 'raised' | 'resolved'): Promise<void> {
  const row = await db('live_alerts').where({ id: alertId, tenant_id: tenantId }).first() as Record<string, unknown> | undefined;
  if (!row) return;                                   // trimmed or deleted meanwhile
  if (event === 'raised') {
    if (row.resolved_at === null) await announce(row, tenantId);
  } else {
    emitResolved([{ id: alertId, tenant_id: tenantId }]);
  }
  await trimTenant(tenantId);
}

let registered = false;

/** registerAppleModule(): the delivery job. */
export function registerAppleAlertJobs(): void {
  if (registered) return;
  registered = true;
  deliverJob = registerJob({
    name: 'alerts.deliver',
    scope: 'tenant',
    description: 'Announce a raised or resolved alert of the Apple integration (Socket.io) and trim the tenant\'s alerts',
    payload: DeliverPayload,
    notify: true,
    pollSeconds: 30,                                   // woken by NOTIFY on send (file-durable L3)
    retry: { limit: 5, delaySeconds: 10, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 60,
    handler: async (ctx) => {
      await ctx.inTenant(() => deliver(ctx.payload.tenantId, ctx.payload.alertId, ctx.payload.event));
    },
  });
}
