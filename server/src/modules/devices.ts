import { registerStartTask } from '../lifecycle';
import { forEachTenant, runJob } from '../db/tenantContext';
import { registerAuditResourceName } from '../services/audit.service';
import { registerApprovalExecutor, registerApprovalRequestType } from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { deviceService } from '../services/device.service';
import { executeBulkDelete, executeChangeGroup, executeDeviceRequest } from '../services/deviceApproval';

// =============================================================================
// DEVICE REGISTRY — its hooks into the core's registries (background jobs,
// audit names, two-step approvals, restrictions matrix), registered here and
// only here; index.ts calls registerDeviceModule() before anything starts.
// Registration order is kept where it shows: start-up order, order of the
// restrictions matrix.
// =============================================================================

let registered = false;

export function registerDeviceModule(): void {
  if (registered) return;
  registered = true;

  // ── Background jobs (lifecycle.ts) ────────────────────────────────────────
  // Each run opens its own database context (runJob), then works tenant by
  // tenant (forEachTenant: one tenant context per tenant; rls-tenant §7.6).
  const perTenant = (name: string, step: (tenantId: number) => Promise<unknown>) => () => runJob(name, async (actor) => {
    const { ok, failed } = await forEachTenant(actor, async (tenantId) => { await step(tenantId); });
    if (failed > 0) throw new Error(`${name}: ${failed} tenant(s) failed, ${ok} done`);
  });

  // Inventory retention (every 6h).
  const pruneInventory = perTenant('devices.inventoryRetention', (tenantId) => deviceService.pruneInventory(tenantId));
  registerStartTask('devices.inventoryRetention', () => { setInterval(() => { void pruneInventory(); }, 6 * 60 * 60 * 1000); });

  // Daily fleet snapshot for the dashboard hero deltas + timeseries chart.
  // Run once on boot (idempotent via onConflict merge) so a fresh deploy has
  // a "today" row right away, then every 24h. The chart synthesises today's
  // live point regardless, so the cadence isn't user-visible.
  const fleetDaily = perTenant('devices.fleetDaily', (tenantId) => deviceService.snapshotFleetDaily(tenantId));
  registerStartTask('devices.fleetDaily', () => {
    void fleetDaily();
    setInterval(() => { void fleetDaily(); }, 24 * 60 * 60 * 1000);
  });

  // Hourly fleet snapshot — feeds the 24h "Activité du parc" view. Run once
  // on boot (so the dashboard has at least 1 historical point right away)
  // and every hour after that. Retention is handled by the job itself (7 days
  // of hourly history, kept ~168 rows per tenant max).
  const fleetHourly = perTenant('devices.fleetHourly', (tenantId) => deviceService.snapshotFleetHourly(tenantId));
  registerStartTask('devices.fleetHourly', () => {
    void fleetHourly();
    setInterval(() => { void fleetHourly(); }, 60 * 60 * 1000);
  });

  // Self-healing: purge orphaned records from tables whose device no longer
  // exists (every 4h).
  const orphans = perTenant('devices.orphans', (tenantId) => deviceService.cleanOrphans(tenantId));
  registerStartTask('devices.orphans', () => {
    void orphans(); // run once at startup
    setInterval(() => { void orphans(); }, 4 * 60 * 60 * 1000);
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
