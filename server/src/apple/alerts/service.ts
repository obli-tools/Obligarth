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
    .first('id', 'i18n_params') as { id: number; i18n_params: AlertParams | null } | undefined;
  const title = render(def.title, params).slice(0, 500);
  const message = render(def.message, params).slice(0, 2000);
  if (existing) {
    if (JSON.stringify(existing.i18n_params ?? {}) !== JSON.stringify(params)) {
      await trx('live_alerts').where({ id: existing.id, tenant_id: tenantId }).update({ i18n_params: JSON.stringify(params), title, message });
    }
    return { id: Number(existing.id), created: false };
  }
  const [row] = await trx('live_alerts').insert({
    tenant_id: tenantId, severity: def.severity, title, message, navigate_to: opts.navigateTo ?? null, stable_key: stableKey,
    kind, i18n_key: `apple.alerts.${kind}`, i18n_params: JSON.stringify(params),
  }).returning('id') as Array<{ id: number }>;
  const id = Number(row.id);
  await sendDelivery(trx, tenantId, id, 'raised');
  return { id, created: true };
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
