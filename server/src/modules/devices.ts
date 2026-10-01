import { z } from 'zod';
import { forEachTenant } from '../db/tenantContext';
import { JobError, registerJob, type JobContext } from '../jobs';
import { registerAuditResourceName } from '../services/audit.service';
import { registerApprovalExecutor, registerApprovalRequestType } from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { deviceService } from '../services/device.service';
import { executeBulkDelete, executeChangeGroup, executeDeviceRequest } from '../services/deviceApproval';

// =============================================================================
// DEVICE REGISTRY — its hooks into the core's registries (durable jobs,
// audit names, two-step approvals, restrictions matrix), registered here and
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

  // ── Audit: names of the resources (audit.service) ─────────────────────────
  registerAuditResourceName('api_key', 'agent_api_keys');                     // enrollment keys

  // ── Two-step approvals: executors (approval.service) ──────────────────────
  registerApprovalExecutor('change_group', executeChangeGroup);                // bulk group change
  registerApprovalExecutor('delete_devices', executeBulkDelete);               // bulk record deletion
  registerApprovalRequestType('device_uninstall', executeDeviceRequest);      // record deletion
  // The tenant transfer is gone (rls-tenant R10): no 'transfer_tenant'
  // executor; a request filed before finds none and is refused.

  // ── Restrictions matrix (restriction.service), in the order it lists them ─
  registerRestrictableActions([
    { key: 'device.delete',                label: 'Delete device (record)',   category: 'Device' },
    { key: 'device.bulk_group_change',     label: 'Bulk change group',        category: 'Device' },
  ], {
    // Recommended default levels: every new tenant starts with them
    // (tenantService.create), the seed writes the same on the master tenant.
    'device.delete':                'sensitive',
    'device.bulk_group_change':     'sensitive',
  });
}
