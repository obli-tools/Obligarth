import { z } from 'zod';
import { db } from '../db';
import { forEachTenant } from '../db/tenantContext';
import { registerFleetSizeProvider, registerGuardedAction, type GuardedActionDef } from '../guard';
import { JobError, registerJob, type JobContext } from '../jobs';
import { registerAuditResourceName } from '../services/audit.service';
import { registerApprovalExecutor, registerApprovalRequestType } from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { deviceService } from '../services/device.service';
import { executeBulkDelete, executeChangeGroup, executeDeviceRequest } from '../services/deviceApproval';
import { registerSecretColumn } from '../vault';

// =============================================================================
// DEVICE REGISTRY — its hooks into the core's registries (durable jobs,
// audit names, two-step approvals, restrictions matrix, sealed columns of the
// vault), registered here and
// only here; index.ts calls registerDeviceModule() before anything starts.
// Registration order is kept where it shows: start-up order, order of the
// restrictions matrix.
// =============================================================================

let registered = false;

export function registerDeviceModule(): void {
  if (registered) return;
  registered = true;

  // ── Background jobs (durable, jobs/) ──────────────────────────────────────
  // Platform jobs that work tenant by tenant (forEachTenant: one tenant
  // context per tenant, rls-tenant §7.6): a tenant that fails does not stop
  // the others, and the run then fails as a whole (partial_failure: counted,
  // retried, alerted). Schedules in UTC, off the hour.
  const empty = z.object({}).strict();
  const perTenant = (step: (tenantId: number) => Promise<unknown>) => async (ctx: JobContext<unknown>) => {
    const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
      ctx.throwIfAborted();
      await step(tenantId);
    });
    if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed, ${ok} done`);
    return { output: { tenants: ok } };
  };

  // Inventory retention (every 6 h). Leaves with the agent's inventory
  // (data model, lot B).
  registerJob({
    name: 'devices.inventory-retention',
    scope: 'platform',
    description: 'Delete software inventory scans older than inventory_retention_days',
    payload: empty,
    schedule: { cron: '25 */6 * * *' },
    timeoutSeconds: 900,
    handler: perTenant((tenantId) => deviceService.pruneInventory(tenantId)),
  });

  // Daily fleet snapshot (dashboard deltas, timeseries chart); also at start
  // (idempotent upsert), so a fresh deploy has a "today" row right away.
  registerJob({
    name: 'devices.fleet-daily',
    scope: 'platform',
    description: 'Daily fleet snapshot of every tenant (dashboard deltas)',
    payload: empty,
    schedule: { cron: '5 0 * * *' },
    runAtStart: true,
    timeoutSeconds: 600,
    handler: perTenant((tenantId) => deviceService.snapshotFleetDaily(tenantId)),
  });

  // Hourly fleet snapshot (24 h "Activité du parc" view; 7 days kept by the
  // job itself); also at start, for a first point right away.
  registerJob({
    name: 'devices.fleet-hourly',
    scope: 'platform',
    description: 'Hourly fleet snapshot of every tenant (7 days kept)',
    payload: empty,
    schedule: { cron: '1 * * * *' },
    runAtStart: true,
    timeoutSeconds: 600,
    handler: perTenant((tenantId) => deviceService.snapshotFleetHourly(tenantId)),
  });

  // Self-healing: records of deleted devices, their live alerts (every 4 h,
  // and at start).
  registerJob({
    name: 'devices.clean-orphans',
    scope: 'platform',
    description: 'Self-healing: purge records of deleted devices, resolve their live alerts',
    payload: empty,
    schedule: { cron: '35 */4 * * *' },
    runAtStart: true,
    timeoutSeconds: 900,
    handler: perTenant((tenantId) => deviceService.cleanOrphans(tenantId)),
  });

  // ── Vault: the sealed license keys (docs: coffre-secrets V9) ──────────────
  // Registered before the vault's boot backfill (index.ts calls this first):
  // the inherited clear keys move into license_key_enc.
  registerSecretColumn({
    table: 'device_licenses', column: 'license_key_enc', pk: 'id', pkType: 'integer',
    tenantColumn: 'tenant_id', encoding: 'utf8', owner: 'devices.licenses',
    legacy: { kind: 'column', column: 'license_key', encoding: 'text' },
    onLoss: 'null',
  });

  // ── Audit: names of the resources (audit.service) ─────────────────────────
  registerAuditResourceName('api_key', 'agent_api_keys');                     // enrollment keys

  // ── Two-step approvals: executors (approval.service) ──────────────────────
  registerApprovalExecutor('change_group', executeChangeGroup);                // bulk group change
  // Record deletion goes through the guard engine (audit-durci §10.2): a
  // request filed before it (delete_devices, device_uninstall) is refused.
  registerApprovalExecutor('delete_devices', executeBulkDelete);
  registerApprovalRequestType('device_uninstall', executeDeviceRequest);
  // The tenant transfer is gone (rls-tenant R10): no 'transfer_tenant'
  // executor; a request filed before finds none and is refused.

  // ── Guarded action: deletion of device records (audit-durci §10.2) ────────
  // Floors of D23: one or two devices 'sensitive' (step-up, the trusted IP
  // accepted), a batch (3 or more, a group, the tenant) 'restricted' (second
  // approver); no delay, no hourly cap (records, not devices: the MDM's
  // erase has them); the whole fleet refused; typed confirmation. Also the
  // first entry of the restrictions matrix (registered here, in its order).
  registerGuardedAction(deviceDeleteAction);
  // The active fleet of a tenant (hourly cap, whole fleet): every device
  // until the MDM's model (lot B) registers the managed ones.
  registerFleetSizeProvider(async (tenantId) => {
    const row = await db('devices').where({ tenant_id: tenantId }).count<{ n: string }[]>('id as n').first();
    return Number(row?.n ?? 0);
  });

  // ── Restrictions matrix (restriction.service), in the order it lists them ─
  registerRestrictableActions([
    { key: 'device.bulk_group_change',     label: 'Bulk change group',        category: 'Device' },
  ], {
    // Recommended default levels: every new tenant starts with them
    // (tenantService.create), the seed writes the same on the master tenant.
    'device.bulk_group_change':     'sensitive',
  });
}

/**
 * device.delete: deletion of device records (inventory, licenses, alerts
 * and reports' references purged with them, deviceService.bulkDelete), in
 * the action's tenant. Revalidation: the device still exists in the tenant.
 * Idempotent: a device already gone is skipped. No serial number in the
 * registry before the MDM's model (lot B, devices.serial_number): the
 * execution entry carries the ids (J29: noted in the specification).
 */
const deviceDeleteAction: GuardedActionDef<Record<string, never>> = {
  key: 'device.delete',
  label: 'Delete device records',
  family: 'device_records',
  singleFloor: 'sensitive',
  singleStrictStepUp: false,
  bulkThreshold: 3,
  singleDelaySeconds: 0,
  bulkDelaySeconds: 0,
  hourlyCap: false,
  forbidWholeFleet: true,
  refuseOwnership: [],
  confirmation: 'typed',
  paramsSchema: z.object({}).strict() as unknown as z.ZodType<Record<string, never>>,
  tenantCapability: 'devices.manage',
  category: 'Device',
  defaultLevel: 'sensitive',
  async revalidate(ctx) {
    const present = new Set((await db('devices').whereIn('id', ctx.deviceIds).andWhere({ tenant_id: ctx.tenantId }).pluck('id') as number[]).map(Number));
    return new Map(ctx.deviceIds.map((id) => [id, present.has(id) ? 'ok' as const : { code: 'not_found' }]));
  },
  async execute(ctx, deviceIds) {
    const deleted = new Set((await deviceService.bulkDelete(deviceIds, ctx.tenantId)).map(Number));
    return new Map(deviceIds.map((id) => [id, deleted.has(id) ? { status: 'done' as const } : { status: 'skipped' as const, code: 'not_found' }]));
  },
};
