import type { Knex } from 'knex';
import { z } from 'zod';
import { config } from '../../config';
import { db } from '../../db';
import { forEachTenant, withTenantTransaction } from '../../db/tenantContext';
import { JobError, registerJob, type JobContext, type JobResult } from '../../jobs';
import { resolveWhereInTx, raiseInTx, resolveInTx } from './service';

// =============================================================================
// Housekeeping of the alerts of the Apple integration (docs: integration-
// apple-edge §12.5; file-durable annex B):
//   alerts.inactive-devices  platform, hourly (17 * * * *), exclusive, tenant
//                            by tenant (each in its own context and
//                            transaction): devices.inactive (devices under
//                            management without contact for APPLE_INACTIVE_DAYS)
//                            and devices.identity_expired (devices under
//                            management whose identity certificate expired),
//                            raised, refreshed (their count) or resolved (back to 0)
//   alerts.auto-resolve      platform, hourly (41 * * * *): the alerts resolved
//                            by time, enrollment.spike 24 h after it was raised,
//                            apns.throttled one hour after the last throttling
// Both run with APPLE_EDGE_MODE=off too (database only, nothing to call).
// =============================================================================

const empty = z.object({}).strict();
const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
/** enrollment.spike resolves itself after a day (§12.1). */
export const SPIKE_AUTO_RESOLVE_MS = 24 * HOUR_MS;
/** apns.throttled resolves itself an hour after the last throttling (§12.1). */
export const THROTTLED_AUTO_RESOLVE_MS = HOUR_MS;

const MANAGED = ['enrolled', 'awaiting_configuration'];

/** The counts of one tenant (its context). */
export async function countInactive(q: Knex | Knex.Transaction, tenantId: number, days: number, now = new Date()): Promise<{ inactive: number; expired: number }> {
  const since = new Date(now.getTime() - days * DAY_MS);
  const inactive = await q('devices as d')
    .join('apple_devices as a', function joinSatellite() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereIn('d.enrollment_state', MANAGED)
    .whereRaw('coalesce(d.last_checkin_at, d.enrolled_at, a.authenticated_at) < ?', [since])
    .count('* as n').first() as { n: string | number } | undefined;
  const expired = await q('devices as d')
    .join('apple_devices as a', function joinSatellite() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereIn('d.enrollment_state', MANAGED)
    .where((w) => w.where('a.cert_not_after', '<', now).orWhere('a.identity_state', 'expired'))
    .count('* as n').first() as { n: string | number } | undefined;
  return { inactive: Number(inactive?.n ?? 0), expired: Number(expired?.n ?? 0) };
}

/** devices.inactive and devices.identity_expired of one tenant, in its transaction. */
export async function inactiveDevicesInTx(trx: Knex.Transaction, tenantId: number, days: number, now = new Date()):
  Promise<{ inactive: number; expired: number }> {
  const c = await countInactive(trx, tenantId, days, now);
  if (c.inactive > 0) await raiseInTx(trx, tenantId, 'devices.inactive', { params: { count: c.inactive, days }, navigateTo: '/devices' });
  else await resolveInTx(trx, tenantId, 'devices.inactive');
  if (c.expired > 0) await raiseInTx(trx, tenantId, 'devices.identity_expired', { params: { count: c.expired }, navigateTo: '/devices' });
  else await resolveInTx(trx, tenantId, 'devices.identity_expired');
  return c;
}

/** The alerts of a tenant resolved by time, in its transaction. */
export async function autoResolveInTx(trx: Knex.Transaction, tenantId: number, now = new Date()): Promise<number> {
  let n = 0;
  n += (await resolveWhereInTx(trx, tenantId, 'enrollment.spike',
    (q) => q.where('created_at', '<', new Date(now.getTime() - SPIKE_AUTO_RESOLVE_MS)))).length;
  // apns.throttled: the time of the last throttling it counted (lastAt), else its creation.
  n += (await resolveWhereInTx(trx, tenantId, 'apns.throttled',
    (q) => q.whereRaw(`coalesce(
      CASE WHEN (i18n_params->>'lastAt') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' THEN (i18n_params->>'lastAt')::timestamptz END,
      created_at) < ?`, [new Date(now.getTime() - THROTTLED_AUTO_RESOLVE_MS)]))).length;
  return n;
}

async function inactiveDevices(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let raised = 0;
  const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    // Only the tenants that have Apple devices (a tenant without any has nothing to raise nor resolve).
    const any = await db('apple_devices').where({ tenant_id: tenantId }).first('device_id');
    const open = any ? true : !!(await db('live_alerts').where({ tenant_id: tenantId }).whereNull('resolved_at')
      .whereIn('kind', ['devices.inactive', 'devices.identity_expired']).first('id'));
    if (!open) return;
    const c = await withTenantTransaction(tenantId, ctx.dbActor, (trx) => inactiveDevicesInTx(trx, tenantId, config.apple.inactiveDays));
    if (c.inactive > 0 || c.expired > 0) raised += 1;
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
  return { output: { tenants: ok, withAlerts: raised } };
}

async function autoResolve(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let resolved = 0;
  const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const open = await db('live_alerts').where({ tenant_id: tenantId }).whereNull('resolved_at')
      .whereIn('kind', ['enrollment.spike', 'apns.throttled']).first('id');
    if (!open) return;
    resolved += await withTenantTransaction(tenantId, ctx.dbActor, (trx) => autoResolveInTx(trx, tenantId));
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
  return { output: { tenants: ok, resolved } };
}

let registered = false;

export function registerAlertMaintenanceJobs(): void {
  if (registered) return;
  registered = true;
  registerJob({
    name: 'alerts.inactive-devices',
    scope: 'platform',
    description: 'Raise or resolve the alerts of inactive devices and expired device identities, tenant by tenant',
    payload: empty,
    schedule: { cron: '17 * * * *' },
    policy: 'exclusive',
    notify: true,
    pollSeconds: 60,
    timeoutSeconds: 900,
    handler: inactiveDevices,
  });
  registerJob({
    name: 'alerts.auto-resolve',
    scope: 'platform',
    description: 'Resolve the alerts of the Apple integration that end by time (spike of enrollments, throttled pushes)',
    payload: empty,
    schedule: { cron: '41 * * * *' },
    policy: 'exclusive',
    notify: true,
    pollSeconds: 60,
    timeoutSeconds: 600,
    handler: autoResolve,
  });
}
