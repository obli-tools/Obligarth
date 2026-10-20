import { db } from '../db';
import { asIdentity, currentDbContext, type DbActor } from '../db/context';
import { registerEdgeFreezeHandler } from '../guard';
import { registerFreezeMirror } from '../guard/frozen';
import { appleEdgeFrozen } from '../apple/commands/bus';
import { registerBootTask, registerStartTask } from '../lifecycle';
import { registerAlertDefinitions } from '../services/alertCatalog';
import { APPLE_ALERTS, type AppleAlertKind } from '../apple/alerts/catalog';
import { APPLE_ALERTS_FR } from '../apple/alerts/catalog.fr';
import { logger } from '../utils/logger';
import { registerSecretColumn, setEdgeKekIdSource } from '../vault';
import { registerAppleEdgeAdmin } from '../apple/admin.routes';
import { registerAlertMaintenanceJobs } from '../apple/alerts/maintenance';
import { registerAppleAlertJobs } from '../apple/alerts/service';
import { registerAppleAuditActions } from '../apple/audit';
import { registerAppleCommands, sendDdmSyncCommand } from '../apple/commands';
import { registerMvpResultIngestors, registerResultJobs } from '../apple/commands/results';
import { requestResubmitAll, requestResubmitHeld } from '../apple/commands/submit';
import { registerAppleDdm } from '../apple/ddm';
import { registerAppleEnrollment } from '../apple/enrollment';
import { registerAppleIntegrations } from '../apple/integrations';
import { registerDdmSyncSender } from '../apple/ddm/sync';
import { registerDeviceJobs } from '../apple/devices/jobs';
import { registerRetireJob } from '../apple/devices/retire';
import { registerReconcileJobs } from '../apple/reconcile/jobs';
import { checkEdgeAtStart, edgeKekId, onEdgeRecovered } from '../apple/edge/health';
import { registerAppleOutboxHandlers } from '../apple/outbox';
import { registerTenantJobs } from '../apple/tenants/jobs';
import { appleTenants } from '../apple/tenants/registry';

// =============================================================================
// APPLE INTEGRATION (apple-edge) — its hooks into the core's registries
// (docs: integration-apple-edge §3.3), registered here and only here;
// index.ts calls registerAppleModule() right after registerDeviceModule(),
// before anything starts. No I/O. Jobs and outbox handlers are registered
// even with APPLE_EDGE_MODE=off: a job that would call apple-edge then ends
// with { skipped: 'apple_edge_off' }, and the handlers (database only) stay
// ready for the day the integration is turned on. No timer: periodic and
// deferred work goes through durable jobs.
// Lot B1: the tenant registry (provisioning, mirror, state, CA), the probe of
// apple-edge, the handlers of the tenant events, the platform alerts, the
// administration routes. Lot B3: the handlers of every event of the outbox
// (enrollment cycles, commands, security, push, ADE), their follow-up jobs and
// the ingestion of the results. Lot B4: the command queue (catalogue, bus,
// submission, relaunches, cancellation, guarded MDM actions, inventory, setup
// plan). Lot C1: OTA enrollment (device surface mounted by app.ts, console
// routes by routes/index.ts, enrollment.sessions-expire). Lot C3: the push
// certificate, the ADE servers, the échéancier and the readiness of a tenant
// (apple/integrations). Lot C4: Apps and Books. Lot C5: the operations (alerts
// housekeeping and external channels, reconciliation, recovery after a
// restore, verified retirement).
// =============================================================================

let registered = false;

/** app_config.instance_id (UUID v4), if it is missing: a safety net, the migration audit_hardening creates
 *  it (review INT-RC9); for mdmInfo of Apps and Books and the exchange files of the vendor's signing tool. */
async function ensureInstanceId(): Promise<void> {
  await asIdentity({ type: 'job', name: 'apple.instance-id' }, () => db.raw(
    "INSERT INTO obligarth.app_config (key, value) VALUES ('instance_id', gen_random_uuid()::text) ON CONFLICT (key) DO NOTHING"));
}

export function registerAppleModule(): void {
  if (registered) return;
  registered = true;

  // ── Vault: the sealed columns of the integration (coffre-secrets §4.2) ──────
  registerSecretColumn({
    table: 'tenant_apple_vpp_tokens', column: 's_token_enc', pk: 'id', pkType: 'uuid',
    tenantColumn: 'tenant_id', encoding: 'utf8', owner: 'apple.vpp', onLoss: 'delete',
  });
  registerSecretColumn({
    table: 'mdm_commands', column: 'plist_enc', pk: 'id', pkType: 'uuid',
    tenantColumn: 'tenant_id', encoding: 'utf8', owner: 'apple.mdm', onLoss: 'delete',
  });
  // apple-edge's kek_id in the vault's state (coffre-secrets §8.4-1).
  setEdgeKekIdSource(edgeKekId);

  // ── Durable jobs and outbox handlers ───────────────────────────────────────
  registerTenantJobs();
  registerAppleAlertJobs();
  registerDeviceJobs();           // apple.device-onboard, apple.await-configuration, devices.unenroll-cleanup
  registerResultJobs();           // apple.command-result-ingest
  registerMvpResultIngestors();   // §7.6: the ingestors whose writers the data model provides
  // §8: catalogue, bus jobs (mdm.commands.*), guarded MDM actions, restrictable actions, approvals of restricted
  // commands, initial and periodic inventory (apple.inventory.*), setup plan (apple.setup-timeout)
  registerAppleCommands();
  registerAppleOutboxHandlers();  // the 34 handlers of §7.4
  registerAppleDdm();             // §9: core provider, apple.ddm.* queues, DeclarativeManagement ingestor, onboarding step
  registerDdmSyncSender(sendDdmSyncCommand);   // §9.4: the DDM engine announces a set through the command queue
  registerAppleEnrollment();      // §10 (lot C1): enrollment.sessions-expire
  registerAppleIntegrations();    // §11 (lot C3): integrations.* jobs, approvals of a topic change and of an ADE deletion
  // §12, §13 (lot C5): alerts.inactive-devices, alerts.auto-resolve; apple-edge.reconcile-all, reconcile-tenant,
  // open-targets-check, restore-check; apple.device-retire
  registerAlertMaintenanceJobs();
  registerReconcileJobs();
  registerRetireJob();

  // ── Alerts of the platform (scope 'master'): read by the platform administrators only (§12.1, lot C5) ──
  // The Apple kinds in the catalogue of the alerts opened to the modules (lot AN-P); its platform kinds are read by the
  // platform administrators only.
  registerAlertDefinitions('apple', (Object.keys(APPLE_ALERTS) as AppleAlertKind[]).map((k) => ({
    key: k, scope: APPLE_ALERTS[k].scope, severity: APPLE_ALERTS[k].severity, title: APPLE_ALERTS[k].title, message: APPLE_ALERTS[k].message,
    fr: APPLE_ALERTS_FR[k], i18nKey: `apple.alerts.${k}`,
  })));

  // ── Audit, restrictions, approvals ─────────────────────────────────────────
  registerAppleAuditActions();
  registerAppleEdgeAdmin();

  // ── Guard engine: the freeze of the Apple commands ────────────────────────
  // A freeze set at apple-edge (its mirror, tenant_apple_edge.commands_frozen) holds the Apple commands like the
  // engine's (guard/frozen.ts, lot AN-P).
  registerFreezeMirror('apple_mdm', appleEdgeFrozen);
  // The emergency freeze of the commands at apple-edge
  // (audit-durci §10.7; called after the freeze's commit and by the job
  // actions.edge-freeze-sync, which retries every minute).
  registerEdgeFreezeHandler(async (tenantId, frozen) => {
    // The actor of the freeze (the request that froze), else the guard's job.
    const actor: DbActor = currentDbContext()?.actor ?? { type: 'job', name: 'actions.edge-freeze-sync' };
    const r = await appleTenants.setCommandsFrozen(tenantId, frozen, actor);
    if (r === 'done') logger.info({ tenantId, frozen }, 'commands freeze applied at apple-edge');
    // The unfreeze: the commands held meanwhile go back to their submission (§8.6). Best effort: the sweep
    // mdm.commands.resubmit-all finds them within 5 minutes otherwise.
    if (!frozen) await requestResubmitHeld(tenantId).catch((err) => { logger.warn({ tenantId, code: (err as { code?: unknown })?.code }, 'held commands not resubmitted at the unfreeze'); });
    return r;
  });

  // apple-edge back after an outage: the commands held meanwhile (edge_unavailable) are submitted again (§8.6).
  onEdgeRecovered(() => requestResubmitAll());

  // ── Lifecycle ──────────────────────────────────────────────────────────────
  registerBootTask('apple.instance-id', ensureInstanceId);
  // Version out of the matrix, or the brain's KEK: refusal to start; apple-edge
  // unreachable: degraded start, probed every minute (§5.5, I15). 5 s at most.
  registerStartTask('apple.edge-check', () => checkEdgeAtStart());
}
