import { registerStartTask } from '../lifecycle';
import { registerAuditResourceName } from '../services/audit.service';
import { registerApprovalExecutor, registerApprovalRequestType } from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { deviceService } from '../services/device.service';
import { executeBulkDelete, executeChangeGroup, executeDeviceRequest, executeTransferTenant } from '../services/deviceApproval';

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

  // Inventory retention (every 6h).
  registerStartTask('devices.inventoryRetention', () => { setInterval(() => deviceService.pruneInventory(), 6 * 60 * 60 * 1000); });

  // Daily fleet snapshot for the dashboard hero deltas + timeseries chart.
  // Run once on boot (idempotent via onConflict merge) so a fresh deploy has
  // a "today" row right away, then every 24h. The chart synthesises today's
  // live point regardless, so the cadence isn't user-visible.
  registerStartTask('devices.fleetDaily', () => {
    deviceService.snapshotFleetDaily().catch(() => {});
    setInterval(() => deviceService.snapshotFleetDaily(), 24 * 60 * 60 * 1000);
  });

  // Hourly fleet snapshot — feeds the 24h "Activité du parc" view. Run once
  // on boot (so the dashboard has at least 1 historical point right away)
  // and every hour after that. Retention is handled by the job itself (7 days
  // of hourly history, kept ~168 rows per tenant max).
  registerStartTask('devices.fleetHourly', () => {
    deviceService.snapshotFleetHourly().catch(() => {});
    setInterval(() => deviceService.snapshotFleetHourly(), 60 * 60 * 1000);
  });

  // Self-healing: purge orphaned records from tables whose device no longer
  // exists (every 4h).
  registerStartTask('devices.orphans', () => {
    deviceService.cleanOrphans().catch(() => {}); // run once at startup
    setInterval(() => deviceService.cleanOrphans(), 4 * 60 * 60 * 1000);
  });

  // ── Audit: names of the resources (audit.service) ─────────────────────────
  registerAuditResourceName('api_key', 'agent_api_keys');                     // enrollment keys

  // ── Two-step approvals: executors (approval.service) ──────────────────────
  registerApprovalExecutor('change_group', executeChangeGroup);                // bulk group change
  registerApprovalExecutor('transfer_tenant', executeTransferTenant);          // bulk tenant transfer
  registerApprovalExecutor('delete_devices', executeBulkDelete);               // bulk record deletion
  registerApprovalRequestType('device_uninstall', executeDeviceRequest);      // record deletion / tenant transfer

  // ── Restrictions matrix (restriction.service), in the order it lists them ─
  registerRestrictableActions([
    { key: 'device.delete',                label: 'Delete device (record)',   category: 'Device' },
    { key: 'device.bulk_group_change',     label: 'Bulk change group',        category: 'Device' },
    { key: 'device.transfer_tenant',       label: 'Transfer device to another tenant', category: 'Device' },
  ], {
    // Recommended default levels: every new tenant starts with them
    // (tenantService.create), the seed writes the same on the master tenant.
    'device.delete':                'sensitive',
    'device.bulk_group_change':     'sensitive',
    'device.transfer_tenant':       'sensitive',
  });
}
