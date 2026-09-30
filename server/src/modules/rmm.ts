import { db } from '../db';
import { logger } from '../utils/logger';
import { registerBootTask, registerStartTask, registerStopTask, registerUpgradeHandler } from '../lifecycle';
import { registerSocketHandler, requireSocketMessageSize } from '../socket';
import { exemptFromApiLimiter } from '../middleware/rateLimiter';
import { onSessionsKilled } from '../services/userSessions.service';
import { onTrustRevoked } from '../services/tfaTrust.service';
import { registerConfigKey } from '../services/appConfig.service';
import { registerSettingsWrite } from '../services/settingsWrite.service';
import { registerAuditResourceName } from '../services/audit.service';
import {
  registerApprovalExecutor, registerApprovalRequestType, registerDefaultApprovalExecutor,
} from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { registerSecretCommandFields } from '../services/approvalSecrets';
import { registerTenantFanoutTable } from '../services/tenant.service';
import { registerDashboardStat } from '../services/obligate.service';
// RMM modules
import { deviceService } from '../services/device.service';
import { scheduleService } from '../services/schedule.service';
import { commandService } from '../services/command.service';
import { remoteService } from '../services/remote.service';
import { endBastionConnectionsForUser, startSshBastion } from '../services/sshBastion/sshBastion.service';
import { complianceService } from '../services/compliance.service';
import { softwareComplianceService } from '../services/softwareCompliance.service';
import { clearExplorerStepUpsOfUser } from '../services/fileExplorerGate.service';
import { remoteTunnelUpgrade, closeRemoteTunnelServer } from '../services/remoteTunnel.upgrade';
import { agentChannelUpgrade, closeAgentChannelServer } from '../services/agentHub.upgrade';
import { oblireachChannelUpgrade, closeOblireachChannelServer } from '../services/oblireachHub.upgrade';
import { installProcessSocketHandlers } from '../services/process.socket';
import { installFileExplorerSocketHandlers } from '../services/fileExplorer.socket';
import { installCustomSectionSocketHandlers } from '../services/customSection.socket';
import { installChatSocketHandlers } from '../services/oblireachChat.socket';
import { WEBVIEW2_MODE_KEY, WEBVIEW2_MODES, noteWebView2Mode, parseWebView2Mode } from '../services/oblireachWebView2.service';
import { editableExtensionsWrite } from '../services/fileExplorerSettings.service';
import { globalThresholdsWrite } from '../services/thresholdSettings.service';
import {
  executeDeviceCommands, executeUpdateAllAgents, isRemoteSessionStart, refuseRemoteSessionStart,
} from '../services/commandApproval';
import { executeChangeGroup, executeDeviceRequest, executeTransferTenant } from '../services/deviceApproval';
import { executeSoftwareRemediation, isSoftwareRemediation } from '../services/softwareComplianceApproval';
import {
  executeManualScriptRun, executeSettingChange, isManualScriptRun,
} from '../services/automationApproval';
import type { ObliReachWebView2Mode } from '@obliance/shared';

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
//   [remote]     remote sessions and tunnels (remote.service)
//   [oblireach]  ObliReach channel, chat, WebView2
//   [bastion]    SSH bastion (services/sshBastion)
//   [explorer]   file explorer
//   [sections]   custom sections
//   [processes]  live process list
//   [scripts]    scripts and schedules
//   [scenarios]  scenarios
//   [compliance] compliance policies and presets
//   [software]   software compliance
//   [cve]        CVE catalog
//   [thresholds] metric thresholds (cascade)
//   [privacy]    privacy mode
//   [hyperv]     Hyper-V   [veeam] Veeam backups
// Registration order is kept where it shows: start-up order of the former
// index.ts, order of the restrictions matrix.
// =============================================================================

let registered = false;

export function registerRmmModules(): void {
  if (registered) return;
  registered = true;

  // ── Start-up, background jobs, shutdown (lifecycle.ts) ───────────────────

  // [scenarios] Scenario accountability epoch (scenarioPermission.service):
  // recorded before any request can save / enable a scenario or a trigger
  // can fire.
  registerBootTask('scenarios.accountability', async () => {
    const { initScenarioAccountability } = await import('../services/scenarioPermission.service');
    await initScenarioAccountability();
  });

  // [scripts] Script scheduler + catch-up.
  registerStartTask('scripts.scheduler', () => { scheduleService.start(); });
  registerStopTask('scripts.scheduler', () => { scheduleService.stop(); });

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

  // [remote] No relay survives a restart: sessions the previous run left
  // 'active' are closed (awaited: before the jobs below and the port).
  registerStartTask('remote.orphanedSessions', () => remoteService.closeOrphanedSessionsAtBoot()
    .catch((err) => logger.error(err, 'Closing remote sessions left active by the previous run failed')));

  // [remote] Clean up stale remote sessions (waiting/connecting with no
  // activity) every 2 min.
  registerStartTask('remote.staleSessions', () => {
    remoteService.cleanupStaleSessions();                                    // run once at startup
    setInterval(() => remoteService.cleanupStaleSessions(), 2 * 60 * 1000); // then every 2 min
  });

  // [bastion] SSH Bastion (ObliJump) — opt-in via .env; binds its own port
  // only when SSH_BASTION_ENABLED=true. No-op otherwise.
  registerStartTask('bastion.start', () => { startSshBastion(); });

  // [compliance] Sync built-in preset rules to existing policies (auto-update
  // on deploy), then scheduled compliance checks — every 6h, skip devices
  // checked within the window (first run 1 min after startup).
  registerStartTask('compliance.checks', () => {
    complianceService.syncPresetsToExistingPolicies()
      .then((n: number) => { if (n > 0) logger.info({ synced: n }, 'Compliance presets synced to existing policies'); })
      .catch(() => {});
    const COMPLIANCE_INTERVAL = 6 * 60 * 60 * 1000;
    setTimeout(() => complianceService.runScheduledChecks(COMPLIANCE_INTERVAL).catch(() => {}), 60_000); // first run 1 min after startup
    setInterval(() => complianceService.runScheduledChecks(COMPLIANCE_INTERVAL).catch(() => {}), COMPLIANCE_INTERVAL);
  });

  // [software] Scheduled software compliance checks — every 6h, same pattern
  // (first run 1.5 min after startup).
  registerStartTask('software.checks', () => {
    const SW_COMPLIANCE_INTERVAL = 6 * 60 * 60 * 1000;
    setTimeout(() => softwareComplianceService.runScheduledChecks(SW_COMPLIANCE_INTERVAL).catch(() => {}), 90_000); // first run 1.5 min after startup
    setInterval(() => softwareComplianceService.runScheduledChecks(SW_COMPLIANCE_INTERVAL).catch(() => {}), SW_COMPLIANCE_INTERVAL);
  });

  // [cve] CVE catalog sync — daily refresh + fleet rescan. Pulls every
  // registered source (NVD KEV + NVD recent CRITICAL today, extensible via
  // CVE_SOURCES in cve.service.ts). Master tenant rescan covers every child
  // in one pass since device_cves is tenant-scoped at the device level.
  registerStartTask('cve.sync', () => {
    setTimeout(async () => {
      try {
        const { cveService } = await import('../services/cve.service');
        await cveService.syncAllSources();
        await cveService.rescanFleet(1);
      } catch (err) { logger.error(err, 'CVE initial sync/rescan failed'); }
    }, 2 * 60_000);
    setInterval(async () => {
      try {
        const { cveService } = await import('../services/cve.service');
        await cveService.syncAllSources();
        await cveService.rescanFleet(1);
      } catch (err) { logger.error(err, 'CVE daily sync/rescan failed'); }
    }, 24 * 60 * 60 * 1000);
  });

  // [scenarios] Scenarios v2 — boot migration + cron tick. Convert any
  // leftover v1 (steps-based) scenarios to the new graph model, then start a
  // per-minute tick that fires schedule_cron triggers. Both run with an
  // exception barrier so a single broken scenario doesn't take the boot
  // down. Not awaited.
  registerStartTask('scenarios.engine', () => {
    (async () => {
      try {
        const { migrateAllV1Scenarios } = await import('../services/scenarioMigrate.service');
        await migrateAllV1Scenarios();
      } catch (err) { logger.error(err, 'Scenarios v2 boot migration failed'); }
      try {
        const { scenarioGraphCron } = await import('../services/scenarioGraphCron.service');
        scenarioGraphCron.start();
      } catch (err) { logger.error(err, 'Scenarios v2 cron scheduler failed to start'); }
      try {
        const { rearmWaitTimersOnBoot } = await import('../services/scenarioGraph.service');
        await rearmWaitTimersOnBoot();
      } catch (err) { logger.error(err, 'Scenarios v2 wait timer rearm failed'); }
    })();
  });

  // ── Raw WebSocket upgrades (lifecycle.ts dispatcher) ─────────────────────
  // [remote] /api/remote/tunnel/<token> (browser) and /api/remote/agent-tunnel/<token>.
  registerUpgradeHandler('remote.tunnels', remoteTunnelUpgrade);
  registerStopTask('remote.tunnels', closeRemoteTunnelServer);
  // [agent] /api/agent/ws — agent command channel.
  registerUpgradeHandler('agent.channel', agentChannelUpgrade);
  registerStopTask('agent.channel', closeAgentChannelServer);
  // [oblireach] /api/oblireach/ws — ObliReach agent command channel.
  registerUpgradeHandler('oblireach.channel', oblireachChannelUpgrade);
  registerStopTask('oblireach.channel', closeOblireachChannelServer);

  // ── Socket.io handlers (socket.ts) ───────────────────────────────────────
  registerSocketHandler('processes', installProcessSocketHandlers);        // [processes]
  registerSocketHandler('explorer', installFileExplorerSocketHandlers);    // [explorer]
  registerSocketHandler('sections', installCustomSectionSocketHandlers);   // [sections]
  registerSocketHandler('oblireach.chat', installChatSocketHandlers);      // [oblireach]
  // [explorer] File uploads travel in Socket.io messages (base64): 150 MB.
  requireSocketMessageSize(150 * 1024 * 1024);

  // ── End of sessions (userSessions.service) ───────────────────────────────
  // Connections that outlive a session: remote sessions the user started or
  // whose browser relay a session attached (browser relay, ObliReach, VM
  // console), and authenticated SSH bastion connections.
  onSessionsKilled({ // [remote]
    name: 'remote',
    label: 'remote sessions',
    forUser: (userId, reason) => remoteService.closeSessionsForUser(userId, reason),
    forSessions: (hashes, reason) => remoteService.closeSessionsForSessionHashes(hashes, reason),
  });
  onSessionsKilled({ // [bastion]
    name: 'bastion',
    label: 'bastion connections',
    forUser: (userId) => endBastionConnectionsForUser(userId),
  });

  // [explorer] The file explorer's step-up grants of a user go with the
  // user's trusted IPs (tfaTrust.service revokeAllForUser).
  onTrustRevoked((userId) => { clearExplorerStepUpsOfUser(userId); });

  // ── Platform settings (appConfig / settingsWrite) ────────────────────────
  // [oblireach] Automatic install / update by the Obliance agent
  // (platform-wide; absent = on). Tenant / group / device: settings key
  // 'oblireachAutoInstall'.
  registerConfigKey({
    key: 'oblireach_auto_install',
    type: 'boolean',
    read: (v) => (v === 'false' ? 'false' : 'true'),
  });
  // [oblireach] Install of the Microsoft Edge WebView2 runtime of the chat
  // window (proactive | on_demand | disabled; absent = proactive; no
  // per-tenant switch). A write is applied at once by the ObliReach hub.
  registerConfigKey({
    key: WEBVIEW2_MODE_KEY,
    type: 'enum',
    values: WEBVIEW2_MODES,
    read: (v) => parseWebView2Mode(v),
    afterWrite: (v) => noteWebView2Mode(v as ObliReachWebView2Mode),
  });
  registerSettingsWrite(editableExtensionsWrite);  // [explorer]   PUT /api/admin/config/editable-extensions
  registerSettingsWrite(globalThresholdsWrite);    // [thresholds] PUT /api/admin/config/global-thresholds

  // ── Audit: names of the resources (audit.service) ────────────────────────
  registerAuditResourceName('script', 'scripts');                             // [scripts]
  registerAuditResourceName('scenario', 'scenarios');                         // [scenarios]
  registerAuditResourceName('api_key', 'agent_api_keys');                     // [agent] enrollment keys
  registerAuditResourceName('schedule', 'script_schedules');                  // [scripts]
  registerAuditResourceName('software_policy', 'software_compliance_lists');  // [software]

  // ── Two-step approvals: executors (approval.service) ─────────────────────
  registerApprovalExecutor(isManualScriptRun, executeManualScriptRun);         // [scripts] POST /api/scripts/:id/execute
  registerApprovalExecutor('change_group', executeChangeGroup);                // [devices] bulk group change
  registerApprovalExecutor('transfer_tenant', executeTransferTenant);          // [devices] bulk tenant transfer
  registerApprovalExecutor(isRemoteSessionStart, refuseRemoteSessionStart);    // [remote] never from an approval
  registerApprovalExecutor(isSoftwareRemediation, executeSoftwareRemediation); // [software] manual remediation
  registerApprovalExecutor('update_all_agents', executeUpdateAllAgents);       // [agent] dashboard "update all agents"
  registerDefaultApprovalExecutor(executeDeviceCommands);                      // [agent] device commands
  registerApprovalRequestType('device_uninstall', executeDeviceRequest);      // [devices] uninstall / delete / transfer
  registerApprovalRequestType('setting_change', executeSettingChange);        // [scenarios] [scripts] privacy bypass

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
    // [software]
    { key: 'software.remediate_install',   label: 'Install software (manual)', category: 'Software' },
    { key: 'software.remediate_uninstall', label: 'Uninstall software (manual)', category: 'Software' },
    // [explorer] Listing is a low-risk read; upload/delete/rename are destructive.
    { key: 'command.list_directory',       label: 'Browse file explorer',     category: 'File Explorer' },
    { key: 'command.upload_file',          label: 'Upload a file to the device', category: 'File Explorer' },
    { key: 'command.download_file',        label: 'Download a file from the device', category: 'File Explorer' },
    { key: 'command.delete_file',          label: 'Delete a file on the device', category: 'File Explorer' },
    { key: 'command.rename_file',          label: 'Rename a file on the device', category: 'File Explorer' },
    { key: 'command.create_directory',     label: 'Create a directory on the device', category: 'File Explorer' },
    // [remote] Remote sessions (any protocol — SSH, CMD, PowerShell, ObliReach).
    { key: 'remote.session_start',         label: 'Start a remote session (SSH / CMD / PowerShell / ObliReach)', category: 'Remote' },
    // [agent] Services — start is low-risk, stop/restart impact the host.
    { key: 'command.start_service',        label: 'Start a service',          category: 'Services' },
    { key: 'command.stop_service',         label: 'Stop a service',           category: 'Services' },
    { key: 'command.restart_service',      label: 'Restart a service',        category: 'Services' },
    // [processes]
    { key: 'command.kill_process',         label: 'Kill a process',           category: 'Processes' },
    // [scripts] Manual execution from the UI (schedules are un-gated).
    { key: 'script.execute_manual',        label: 'Manually execute a script', category: 'Scripts' },
    // [scenarios] [scripts] Bypass-privacy toggles on automations — flipping
    // these on lets an automation run on a device whose user has explicitly
    // enabled privacy mode. Default is "restricted" (double admin approval)
    // so an admin can't single-handedly override a user's privacy choice.
    { key: 'scenario.bypass_privacy_mode', label: 'Allow a scenario to run on privacy-mode devices', category: 'Automations' },
    { key: 'schedule.bypass_privacy_mode', label: 'Allow a schedule to run on privacy-mode devices', category: 'Automations' },
    // [hyperv] Power actions on a VM are low-risk (a guest reboot is no worse
    // than rebooting a physical box); checkpoints, edits and especially
    // create/delete escalate. delete = double-admin by default.
    { key: 'hyperv.vm_start',             label: 'Start a VM',                     category: 'Hyper-V' },
    { key: 'hyperv.vm_stop',              label: 'Power off a VM (hard)',          category: 'Hyper-V' },
    { key: 'hyperv.vm_shutdown',          label: 'Shut down a VM (graceful)',      category: 'Hyper-V' },
    { key: 'hyperv.vm_restart',           label: 'Restart a VM',                   category: 'Hyper-V' },
    { key: 'hyperv.vm_save',              label: 'Save / pause / resume a VM',     category: 'Hyper-V' },
    { key: 'hyperv.vm_checkpoint',        label: 'Create a VM checkpoint',         category: 'Hyper-V' },
    { key: 'hyperv.vm_checkpoint_apply',  label: 'Apply / restore a VM checkpoint',category: 'Hyper-V' },
    { key: 'hyperv.vm_checkpoint_delete', label: 'Delete a VM checkpoint',         category: 'Hyper-V' },
    { key: 'hyperv.vm_edit',              label: 'Edit VM settings (vCPU / RAM / …)', category: 'Hyper-V' },
    { key: 'hyperv.vm_create',            label: 'Create a VM',                    category: 'Hyper-V' },
    { key: 'hyperv.vm_delete',            label: 'Delete a VM',                    category: 'Hyper-V' },
    // [veeam] start / retry / enable ensure backups run (benign); stop
    // interrupts a running job and disable silently turns off scheduled
    // backups (real data-loss risk) → default-gated with 2FA.
    { key: 'veeam.job_start',             label: 'Start a backup job',             category: 'Backups' },
    { key: 'veeam.job_stop',              label: 'Stop a running backup job',      category: 'Backups' },
    { key: 'veeam.job_retry',             label: 'Retry a backup job',             category: 'Backups' },
    { key: 'veeam.job_enable',            label: 'Enable a backup job schedule',   category: 'Backups' },
    { key: 'veeam.job_disable',           label: 'Disable a backup job schedule',  category: 'Backups' },
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
    'software.remediate_install':   'sensitive',
    'software.remediate_uninstall': 'sensitive',
    // Manual script execution defaults to sensitive — scripts can do anything
    // on the target host, so a fresh TOTP confirm is a sane default.
    'script.execute_manual':        'sensitive',
    // File explorer is gated at the menu-entry point (list_directory) only,
    // so a user enters a code ONCE when opening the explorer and then browses
    // / downloads / uploads freely without re-prompting. Individual
    // destructive operations stay None by default — admins can opt in per
    // action from the matrix if they want a double-gate.
    'command.list_directory':       'sensitive',
    // Privacy-mode bypass on automations — restricted by default so two
    // admins must sign off before an automation can sweep across a device
    // whose user has opted into privacy. Migration 102 seeds the same.
    'scenario.bypass_privacy_mode': 'restricted',
    'schedule.bypass_privacy_mode': 'restricted',
    // Veeam: stopping a running backup and disabling a backup schedule are the
    // risky ones (incomplete/no backup) → 2FA. start/retry/enable stay un-gated.
    'veeam.job_stop':              'sensitive',
    'veeam.job_disable':           'sensitive',
    // Hyper-V defaults follow the product owner's spec: power actions are
    // un-gated (none), checkpoint-restore/delete + edit + create require a
    // fresh 2FA (sensitive), and deleting a VM needs a second admin
    // (restricted). Plain checkpoint creation is non-destructive → none.
    'hyperv.vm_checkpoint_apply':  'sensitive',
    'hyperv.vm_checkpoint_delete': 'sensitive',
    'hyperv.vm_edit':              'sensitive',
    'hyperv.vm_create':            'sensitive',
    'hyperv.vm_delete':            'restricted',
    // Remote sessions / services / processes are intentionally NOT defaulted
    // — admins opt in from the matrix once they have TOTP deployed across
    // privileged accounts, otherwise a fresh install could softlock itself.
  });

  // ── Secrets of the device commands (approvalSecrets) ─────────────────────
  // Never kept in an approval: such a command asks a fresh step-up instead.
  registerSecretCommandFields('set_privacy_password', ['password']);                 // [privacy]
  registerSecretCommandFields('change_privacy_password', ['oldPassword', 'newPassword']); // [privacy]
  registerSecretCommandFields('remove_privacy_password', ['password']);              // [privacy]
  registerSecretCommandFields('verify_privacy_password', ['password']);              // [privacy]
  registerSecretCommandFields('reconfigure_agent', ['apiKey']);                      // [agent]

  // ── Rate limiter exemptions (apiLimiter) ─────────────────────────────────
  // [agent] All /api/agent/* paths are API-key authenticated (X-API-Key
  // header). Rate-limiting them would cause false positives when agents post
  // inventory, compliance results, scan data, and metrics at their natural
  // cadence. Security is provided by the API key itself.
  exemptFromApiLimiter('/api/agent/');
  // [oblireach] Oblireach agent pushes (same auth, same frequency).
  exemptFromApiLimiter('/api/oblireach/');
  // Passive heartbeats (token authenticated, triggered by external systems):
  // no route serves this path any more; kept so the limiter counts nothing new.
  exemptFromApiLimiter('/api/heartbeat/');

  // ── Tenant deletion: master-owned fan-out arrays (tenant.service) ────────
  registerTenantFanoutTable('scripts');             // [scripts]
  registerTenantFanoutTable('scenarios');           // [scenarios]
  registerTenantFanoutTable('script_schedules');    // [scripts]
  registerTenantFanoutTable('compliance_policies'); // [compliance]

  // ── Obligate dashboard card (GET /api/auth/dashboard-stats) ─────────────
  registerDashboardStat({ // [agent]
    label: 'Pending Commands',
    color: '#d29922',
    count: async () => Number(((await db('command_queue').where({ status: 'pending' }).count('id as c').first()) as any)?.c ?? 0),
  });
}
