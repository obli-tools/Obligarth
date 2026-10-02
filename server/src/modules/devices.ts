import { z } from 'zod';
import { db } from '../db';
import { forEachTenant } from '../db/tenantContext';
import { registerFleetSizeProvider, registerGuardedAction, registerOwnershipProvider, type DeviceOwnership, type GuardedActionDef } from '../guard';
import { JobError, registerJob, type JobContext } from '../jobs';
import { registerApprovalExecutor } from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { deviceService } from '../services/device.service';
import { executeBulkDelete, executeChangeGroup } from '../services/deviceApproval';
import { registerSecretColumn } from '../vault';

// =============================================================================
// DEVICE REGISTRY — its hooks into the core's registries (durable jobs,
// two-step approvals, restrictions matrix, guarded deletion of records, the
// guard engine's providers, sealed columns of the vault), registered here and
// only here; index.ts calls registerDeviceModule() before anything starts.
// The MDM data model (mdm/index.ts) adds its own: end users, episodes,
// ownership change, console API.
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

  // ── Two-step approvals: executors (approval.service) ──────────────────────
  registerApprovalExecutor('change_group', executeChangeGroup);                // bulk group change
  // Record deletion goes through the guard engine (audit-durci §10.2): a
  // request filed before it (delete_devices) is refused, with its reason.
  registerApprovalExecutor('delete_devices', executeBulkDelete);
  // The agent's requests (device_uninstall) and the tenant transfer
  // (transfer_tenant, rls-tenant R10) are gone with the agent
  // (modele-donnees-mdm §11.1, §10.7): no executor, a request filed before
  // finds none and is refused.

  // ── Guarded action: deletion of device records (audit-durci §10.2) ────────
  // Floors of D23: one or two devices 'sensitive' (step-up, the trusted IP
  // accepted), a batch (3 or more, a group, the tenant) 'restricted' (second
  // approver); no delay, no hourly cap (records, not devices: the MDM's
  // erase has them); the whole fleet refused; typed confirmation. Also the
  // first entry of the restrictions matrix (registered here, in its order).
  registerGuardedAction(deviceDeleteAction);
  // The active fleet of a tenant (hourly cap, whole fleet): the devices under
  // management (every enrollment state but 'unenrolled').
  registerFleetSizeProvider(async (tenantId) => {
    const row = await db('devices').where({ tenant_id: tenantId }).whereNot('enrollment_state', 'unenrolled')
      .count<{ n: string }[]>('id as n').first();
    return Number(row?.n ?? 0);
  });
  // The ownership of devices (devices.ownership, never unknown: modele-donnees-mdm DM25), read by the guard
  // engine for the actions that refuse an ownership (erasure of a personal device…).
  registerOwnershipProvider(async (tenantId, deviceIds) => {
    if (deviceIds.length === 0) return new Map();
    const rows = await db('devices').whereIn('id', deviceIds).andWhere({ tenant_id: tenantId }).select('id', 'ownership') as
      Array<{ id: number; ownership: DeviceOwnership }>;
    return new Map(rows.map((r) => [Number(r.id), r.ownership]));
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
 * device.delete: deletion of device records out of management (inventory,
 * episodes, satellites, effective state cascade; licenses, alerts and the
 * reports' references purged with them, deviceService.bulkDelete), in the
 * action's tenant. A record under management is never deleted (it leaves
 * management first, ENR-17: devices_guard_delete in the base). Revalidation:
 * the device still exists in the tenant and is still out of management.
 * Idempotent: a device already gone is skipped. The execution entry carries
 * the serial numbers the registry kept (J29).
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
  async serialsOf(tenantId, deviceIds) {
    const rows = await db('devices').whereIn('id', deviceIds).andWhere({ tenant_id: tenantId }).select('id', 'serial_number') as
      Array<{ id: number; serial_number: string | null }>;
    return new Map(rows.map((r) => [Number(r.id), r.serial_number ?? '']));
  },
  async revalidate(ctx) {
    const rows = await db('devices').whereIn('id', ctx.deviceIds).andWhere({ tenant_id: ctx.tenantId }).select('id', 'enrollment_state') as
      Array<{ id: number; enrollment_state: string }>;
    const state = new Map(rows.map((r) => [Number(r.id), r.enrollment_state]));
    return new Map(ctx.deviceIds.map((id) => {
      const s = state.get(id);
      if (s === undefined) return [id, { code: 'not_found' }];
      return [id, s === 'unenrolled' ? 'ok' as const : { code: 'under_management' }];
    }));
  },
  async execute(ctx, deviceIds) {
    const deleted = new Set((await deviceService.bulkDelete(deviceIds, ctx.tenantId)).map(Number));
    return new Map(deviceIds.map((id) => [id, deleted.has(id) ? { status: 'done' as const } : { status: 'skipped' as const, code: 'not_found_or_managed' }]));
  },
};
