import { db } from '../db';
import { logger } from '../utils/logger';
import { registerStartTask, registerStopTask, registerUpgradeHandler } from '../lifecycle';
import { exemptFromApiLimiter } from '../middleware/rateLimiter';
import { registerSettingsWrite } from '../services/settingsWrite.service';
import { registerAuditResourceName } from '../services/audit.service';
import {
  registerApprovalExecutor, registerApprovalRequestType, registerDefaultApprovalExecutor,
} from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { registerSecretCommandFields } from '../services/approvalSecrets';
import { registerDashboardStat } from '../services/obligate.service';
// RMM modules
import { deviceService } from '../services/device.service';
import { commandService } from '../services/command.service';
import { agentChannelUpgrade, closeAgentChannelServer } from '../services/agentHub.upgrade';
import { globalThresholdsWrite } from '../services/thresholdSettings.service';
import { executeDeviceCommands, executeUpdateAllAgents } from '../services/commandApproval';
import { executeChangeGroup, executeDeviceRequest, executeTransferTenant } from '../services/deviceApproval';

// =============================================================================
// RMM MODULES (Obliance heritage) — TO BE REMOVED.
//
// Every hook of the RMM into the core is registered here, and only here: the
// core (sessions, settings, audit, approvals, restrictions, sockets, start-up,
// tenants, rate limiting, Obligate) imports no RMM module, index.ts imports
// this file. Removing an RMM module = deleting its files, its route mounts
// (routes/index.ts) and its lines below, tagged with the module:
//   [agent]      agent channel, commands and supervision (agentHub, command,
//                diskHealth, rewind, metrics, agent update rollout)
//   [devices]    agent-managed device jobs and actions of device.service
//                (to adapt: the device registry itself stays)
//   [thresholds] metric thresholds (cascade)
//   [privacy]    privacy mode
// Registration order is kept where it shows: start-up order of the former
// index.ts, order of the restrictions matrix.
// =============================================================================

let registered = false;

export function registerRmmModules(): void {
  if (registered) return;
  registered = true;

  // ── Start-up, background jobs, shutdown (lifecycle.ts) ───────────────────

  // [agent] Expire timed-out commands.
  registerStartTask('commands.cleanup', () => { commandService.startCleanupJob(); });

  // [agent] Native SMART disk-health collector (server-driven, zero agent change).
  registerStartTask('agent.diskHealthCollector', () => {
    import('../services/diskHealthCollector.service')
      .then(({ diskHealthCollector }) => diskHealthCollector.start())
      .catch((err) => logger.error(err, 'diskHealthCollector failed to start'));
  });
  registerStopTask('agent.diskHealthCollector', () => {
    import('../services/diskHealthCollector.service')
      .then(({ diskHealthCollector }) => diskHealthCollector.stop())
      .catch(() => {});
  });

  // [agent] Rewind time-machine process-snapshot collector (server-driven, zero agent change).
  registerStartTask('agent.rewindCollector', () => {
    import('../services/rewindCollector.service')
      .then(({ rewindCollector }) => rewindCollector.start())
      .catch((err) => logger.error(err, 'rewindCollector failed to start'));
  });
  registerStopTask('agent.rewindCollector', () => {
    import('../services/rewindCollector.service')
      .then(({ rewindCollector }) => rewindCollector.stop())
      .catch(() => {});
  });

  // [devices] Device offline detection (every 30s).
  registerStartTask('devices.offline', () => { setInterval(() => deviceService.checkOfflineDevices(), 30_000); });

  // [devices] Expire pending_uninstall devices whose 10-min timer has elapsed (every 30s).
  registerStartTask('devices.uninstallExpiry', () => { setInterval(() => deviceService.expireUninstalls(), 30_000); });

  // [devices] Inventory retention (every 6h).
  registerStartTask('devices.inventoryRetention', () => { setInterval(() => deviceService.pruneInventory(), 6 * 60 * 60 * 1000); });

  // [agent] Per-device metric-history retention (hourly ≤72h, daily ≤40d). The
  // history buckets are written incrementally on each push; this just prunes.
  // Every 6h.
  registerStartTask('devices.metricHistoryRetention', () => {
    deviceService.pruneMetricHistory().catch(() => {});
    setInterval(() => deviceService.pruneMetricHistory(), 6 * 60 * 60 * 1000);
  });

  // [devices] Daily fleet snapshot for the dashboard hero deltas + timeseries
  // chart. Run once on boot (idempotent via onConflict merge) so a fresh
  // deploy has a "today" row right away, then every 24h. The chart
  // synthesises today's live point regardless, so the cadence isn't
  // user-visible.
  registerStartTask('devices.fleetDaily', () => {
    deviceService.snapshotFleetDaily().catch(() => {});
    setInterval(() => deviceService.snapshotFleetDaily(), 24 * 60 * 60 * 1000);
  });

  // [devices] Hourly fleet snapshot — feeds the 24h "Activité du parc" view.
  // Run once on boot (so the dashboard has at least 1 historical point right
  // away) and every hour after that. Retention is handled by the job itself
  // (7 days of hourly history, kept ~168 rows per tenant max).
  registerStartTask('devices.fleetHourly', () => {
    deviceService.snapshotFleetHourly().catch(() => {});
    setInterval(() => deviceService.snapshotFleetHourly(), 60 * 60 * 1000);
  });

  // [devices] Self-healing: purge orphaned records from tables whose device no
  // longer exists (every 4h).
  registerStartTask('devices.orphans', () => {
    deviceService.cleanOrphans().catch(() => {}); // run once at startup
    setInterval(() => deviceService.cleanOrphans(), 4 * 60 * 60 * 1000);
  });

  // ── Raw WebSocket upgrades (lifecycle.ts dispatcher) ─────────────────────
  // [agent] /api/agent/ws — agent command channel.
  registerUpgradeHandler('agent.channel', agentChannelUpgrade);
  registerStopTask('agent.channel', closeAgentChannelServer);

  // ── Platform settings (settingsWrite) ────────────────────────────────────
  registerSettingsWrite(globalThresholdsWrite);    // [thresholds] PUT /api/admin/config/global-thresholds

  // ── Audit: names of the resources (audit.service) ────────────────────────
  registerAuditResourceName('api_key', 'agent_api_keys');                     // [agent] enrollment keys

  // ── Two-step approvals: executors (approval.service) ─────────────────────
  registerApprovalExecutor('change_group', executeChangeGroup);                // [devices] bulk group change
  registerApprovalExecutor('transfer_tenant', executeTransferTenant);          // [devices] bulk tenant transfer
  registerApprovalExecutor('update_all_agents', executeUpdateAllAgents);       // [agent] dashboard "update all agents"
  registerDefaultApprovalExecutor(executeDeviceCommands);                      // [agent] device commands
  registerApprovalRequestType('device_uninstall', executeDeviceRequest);      // [devices] uninstall / delete / transfer

  // ── Restrictions matrix (restriction.service), in the order it lists them ─
  registerRestrictableActions([
    // [agent]
    { key: 'command.reboot',               label: 'Reboot a device',          category: 'Power' },
    { key: 'command.shutdown',             label: 'Shutdown a device',        category: 'Power' },
    { key: 'command.sleep',                label: 'Sleep a device',           category: 'Power' },
    { key: 'command.restart_agent',        label: 'Restart agent',            category: 'Power' },
    { key: 'command.update_agent',         label: 'Update agent',             category: 'Power' },
    { key: 'command.uninstall_agent',      label: 'Uninstall agent',          category: 'Power' },
    // [agent] [privacy]
    { key: 'command.enable_airgap',        label: 'Enable airgap',            category: 'Isolation' },
    { key: 'command.disable_airgap',       label: 'Disable airgap',           category: 'Isolation' },
    { key: 'command.enable_privacy_mode',  label: 'Enable privacy mode',      category: 'Isolation' },
    { key: 'command.disable_privacy_mode', label: 'Disable privacy mode',     category: 'Isolation' },
    // [devices]
    { key: 'device.delete',                label: 'Delete device (record)',   category: 'Device' },
    { key: 'device.bulk_group_change',     label: 'Bulk change group',        category: 'Device' },
    { key: 'device.transfer_tenant',       label: 'Transfer device to another tenant', category: 'Device' },
    // [agent] Services — start is low-risk, stop/restart impact the host.
    { key: 'command.start_service',        label: 'Start a service',          category: 'Services' },
    { key: 'command.stop_service',         label: 'Stop a service',           category: 'Services' },
    { key: 'command.restart_service',      label: 'Restart a service',        category: 'Services' },
  ], {
    // Recommended default levels (the migrations seed the same).
    'command.reboot':               'sensitive',
    'command.shutdown':             'sensitive',
    // sleep + restart_agent + update_agent = none (not listed). update_agent
    // sits at 'none' on purpose — pushing an agent update is frictionless by
    // default (admins can opt into approval/TOTP from the matrix), unlike
    // uninstall_agent which defaults to 'restricted'.
    'command.uninstall_agent':      'restricted',
    'command.enable_airgap':        'sensitive',
    'command.disable_airgap':       'restricted',
    // enable_privacy_mode = none
    'command.disable_privacy_mode': 'sensitive',
    'device.delete':                'sensitive',
    'device.bulk_group_change':     'sensitive',
    'device.transfer_tenant':       'sensitive',
    // Services are intentionally NOT defaulted — admins opt in from the
    // matrix once they have TOTP deployed across privileged accounts,
    // otherwise a fresh install could softlock itself.
  });

  // ── Secrets of the device commands (approvalSecrets) ─────────────────────
  // Never kept in an approval: such a command asks a fresh step-up instead.
  registerSecretCommandFields('reconfigure_agent', ['apiKey']);                      // [agent]

  // ── Rate limiter exemptions (apiLimiter) ─────────────────────────────────
  // [agent] All /api/agent/* paths are API-key authenticated (X-API-Key
  // header). Rate-limiting them would cause false positives when agents post
  // inventory, service lists and metrics at their natural cadence. Security
  // is provided by the API key itself.
  exemptFromApiLimiter('/api/agent/');
  // Passive heartbeats (token authenticated, triggered by external systems):
  // no route serves this path any more; kept so the limiter counts nothing new.
  exemptFromApiLimiter('/api/heartbeat/');

  // ── Obligate dashboard card (GET /api/auth/dashboard-stats) ─────────────
  registerDashboardStat({ // [agent]
    label: 'Pending Commands',
    color: '#d29922',
    count: async () => Number(((await db('command_queue').where({ status: 'pending' }).count('id as c').first()) as any)?.c ?? 0),
  });
}
