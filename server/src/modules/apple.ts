import { db } from '../db';
import { asIdentity, currentDbContext, type DbActor } from '../db/context';
import { registerEdgeFreezeHandler } from '../guard';
import { registerBootTask, registerStartTask } from '../lifecycle';
import { logger } from '../utils/logger';
import { registerSecretColumn, setEdgeKekIdSource } from '../vault';
import { registerAppleEdgeAdmin } from '../apple/admin.routes';
import { registerAppleAlertJobs } from '../apple/alerts/service';
import { registerAppleAuditActions } from '../apple/audit';
import { registerMvpResultIngestors, registerResultJobs } from '../apple/commands/results';
import { registerDeviceJobs } from '../apple/devices/jobs';
import { checkEdgeAtStart, edgeKekId } from '../apple/edge/health';
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
// the ingestion of the results; the device surface, the command queue, the
// DDM relay and the integrations of the console come with their lots (B4 to
// C4).
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
  registerAppleOutboxHandlers();  // the 34 handlers of §7.4

  // ── Audit, restrictions, approvals ─────────────────────────────────────────
  registerAppleAuditActions();
  registerAppleEdgeAdmin();

  // ── Guard engine: the emergency freeze of the commands at apple-edge ───────
  // (audit-durci §10.7; called after the freeze's commit and by the job
  // actions.edge-freeze-sync, which retries every minute).
  registerEdgeFreezeHandler(async (tenantId, frozen) => {
    // The actor of the freeze (the request that froze), else the guard's job.
    const actor: DbActor = currentDbContext()?.actor ?? { type: 'job', name: 'actions.edge-freeze-sync' };
    const r = await appleTenants.setCommandsFrozen(tenantId, frozen, actor);
    if (r === 'done') logger.info({ tenantId, frozen }, 'commands freeze applied at apple-edge');
    return r;
  });

  // ── Lifecycle ──────────────────────────────────────────────────────────────
  registerBootTask('apple.instance-id', ensureInstanceId);
  // Version out of the matrix, or the brain's KEK: refusal to start; apple-edge
  // unreachable: degraded start, probed every minute (§5.5, I15). 5 s at most.
  registerStartTask('apple.edge-check', () => checkEdgeAtStart());
}
