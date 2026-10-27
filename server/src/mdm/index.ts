import { Router } from 'express';
import { db } from '../db';
import { userActor } from '../db/context';
import { audit, registerAuditActions } from '../audit';
import { registerAuditResourceName } from '../audit/read';
import {
  refuse, registerApprovalExecutor, registerApprovalRequestType, requireTenantCapability, type ApprovalExecution,
  type BatchCommandPayload,
} from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { findSecretRefs, registerSecretReferenceHolder } from '../vault';
import { registerCommandResultIngestor, onTargetFinal } from '../apple/commands/results';
import { registerProfileSource } from '../apple/commands/sensitive';
import { registerSetupContributor } from '../apple/commands/setup';
import { registerDeclarationProvider } from '../apple/ddm/engine';
import { registerStatusHook } from '../apple/ddm/status';
import { registerOnboardStep } from './registry/onboard';
import { registerBootTask } from '../lifecycle';
import { resolveOnCatalogChange } from './apple/catalogRelease';
import { registerArtifactJobs } from './apple/jobs';
import { onDeclarationStatus, policiesDeclarationProvider } from './apple/policiesProvider';
import { policyProfileSource } from './apple/profileSource';
import { ingestSettingsResult, onPolicyTargetFinal } from './apple/reconcile';
import { requestComplianceEvaluation } from './apple/requests';
import { policiesSetupContributor } from './apple/setupContributor';
import { registerComplianceJobs } from './compliance/jobs';
import { registerMdmJobs } from './jobs';
import { registerPolicyJobs } from './policies/jobs';
import { executePolicyPublish, onPolicyPublishClosed } from './policies/publish';
import { requestDeviceResolution, resolveAtOnboarding } from './policies/triggers';
import { changeOwnership } from './registry/ownership';
import deviceRoutes from './routes/devices.routes';
import endUserRoutes from './routes/endUsers.routes';
import policyRoutes from './routes/policies.routes';
import appRoutes from './routes/apps.routes';
import deviceViewRoutes from './routes/deviceViews.routes';
import { onOperationFinal, onTokenSynced } from '../apple/integrations/vpp.service';
import { onManagedAppsIngested } from './inventory/ingestors';
import { appleArtifactProvider, registerAppLicenseGate } from './apple/artifacts';
import { registerArtifactChannel } from './policies/artifacts';
import { registerAppRemovedHook } from './apple/reconcile';
import { applyManagedApps } from './apps/delivery';
import { licenseGate, onLicenseOperationFinal, onLicenseTokenSynced, releaseDeviceLicenses } from './apps/licensing';
import { onUnenrollCleanup } from '../apple/devices/jobs';

// =============================================================================
// MDM DATA MODEL — its hooks into the core's registries (docs:
// modele-donnees-mdm §10.1, §10.5, §10.7), registered here and only here;
// index.ts calls registerMdmModule() before registerAppleModule(), before
// anything starts. No I/O.
// Lot B2: the registry (devices, episodes, end users), its jobs, audit
// actions, restriction and approval executor, the console API. Lot B5b: the
// policies (envelope, versions, assignments), their resolution queues, the
// restriction and the approval of their publication, the secret references
// of their contents. Lot B5c: the Apple compilation and the delivery of the
// artifacts (the declaration provider 'policies' of the DDM engine, the
// profile source 'policy' and the reconciliation by the command bus, the
// contributor of the setup plan), the hooks of their ends (final state of a
// target, declaration status), the minimal compliance, their queues, and the
// resolution of every tenant when the catalog shipped with the server changes.
// =============================================================================

/** Status items of the DDM channel whose change may change the compliance of a device (section 5.4). */
const COMPLIANCE_ITEM_RE = /^(passcode|softwareupdate)\./;

let registered = false;

/** The ownership change approved by a second administrator (restriction device.change_ownership):
 *  executed as the requester, rights and device checked again. */
async function executeChangeOwnership(x: ApprovalExecution): Promise<void> {
  const payload = x.payload as BatchCommandPayload;
  await requireTenantCapability(x.requesterId, x.tenantId, 'devices.manage');
  const deviceId = Number(payload.deviceIds?.[0]);
  const to = payload.params?.to;
  if (!Number.isSafeInteger(deviceId) || deviceId <= 0 || (to !== 'corporate' && to !== 'corporate_personal')) {
    refuse('Malformed ownership change request');
  }
  if (!(await db('devices').where({ tenant_id: x.tenantId, id: deviceId }).first('id'))) {
    refuse('The device of this request is no longer in the tenant');
  }
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  const reason = typeof payload.params?.reason === 'string' ? payload.params.reason : '';
  const ticket = typeof payload.params?.ticket === 'string' ? payload.params.ticket : null;
  try {
    await db.transaction((trx) => changeOwnership(trx, x.tenantId, deviceId, to, ctx, reason, ticket));
  } catch (err) {
    const e = err as { statusCode?: number; message?: string };
    if (e.statusCode && e.statusCode < 500) refuse(e.message ?? 'Ownership change refused');
    throw err;
  }
}

export function registerMdmModule(): void {
  if (registered) return;
  registered = true;

  // ── Durable jobs (§10.5) ───────────────────────────────────────────────────
  registerMdmJobs();
  registerPolicyJobs();
  // The onboarding of a device (§10.4; registry by channel, lot AN-P): its policies are resolved, in the tenant's
  // context. Apple (apple.device-onboard): once its identity certificate is known, the artifacts settled before its
  // new cycle reset first. Android (android.policies.push-device, until the device is attached to its own policy):
  // its artifact amapi:policy written by the resolution before the push of the job.
  registerOnboardStep('apple_mdm', { name: 'policies.resolve', run: ({ job, tenantId, deviceId }) => job.inTenant(() => resolveAtOnboarding(tenantId, deviceId)) });
  registerOnboardStep('amapi', { name: 'policies.resolve', run: async ({ job, tenantId, deviceId }) => {
    await job.inTenant(() => requestDeviceResolution(null, tenantId, [deviceId]));
  } });
  registerArtifactJobs();          // apple.artifacts.reconcile-device, mdm.artifacts.gc
  registerComplianceJobs();        // mdm.compliance.evaluate-device, mdm.compliance.evaluate-all

  // ── Delivery (§7.10): the extension points of the integration, and only them ─
  // The Apple channels of the common artifact store (profile, ddm, app, setting: lot AN-P, COH-2), the default
  // provider: every setting no other module claims.
  registerArtifactChannel(appleArtifactProvider);
  // The 'ddm' artifacts of a device are its declarations obg.cfg.pol-…, with their activation.
  registerDeclarationProvider(policiesDeclarationProvider);
  // What the device reports of them is their state; a passcode or update status that changes, its compliance.
  registerStatusHook({
    name: 'mdm.policies',
    onDeclarationStatus,
    onItemsChanged: async (trx, tenantId, deviceId, items) => {
      if (items.some((i) => COMPLIANCE_ITEM_RE.test(i))) await requestComplianceEvaluation(trx, tenantId, [deviceId]);
    },
  });
  // The profiles of the policies, rendered per device when their command is written (secrets read then, never before).
  registerProfileSource(policyProfileSource);
  // The end of their commands, and the per-item status of a Settings command.
  onTargetFinal('mdm.policies', onPolicyTargetFinal);
  registerCommandResultIngestor({ requestType: 'Settings', mode: 'inline', apply: ingestSettingsResult });
  // An ADE device leaves the setup assistant with its profiles and settings installed.
  registerSetupContributor(policiesSetupContributor);
  // ── Apps (§8.3, lot C4): the licence gate of the writer, the ends of the operations of Apps and Books and the
  //    synchronisations of its tokens, the state of an app from the inventory, the licence given back when the app
  //    leaves a device or the device leaves management.
  registerAppLicenseGate(licenseGate);
  onOperationFinal(onLicenseOperationFinal);
  onTokenSynced(onLicenseTokenSynced);
  onManagedAppsIngested(applyManagedApps);
  registerAppRemovedHook(async (trx, tenantId, deviceId, identifier) => { await releaseDeviceLicenses(trx, tenantId, deviceId, identifier); });
  onUnenrollCleanup(async (trx, tenantId, deviceId) => { await releaseDeviceLicenses(trx, tenantId, deviceId); });
  // A new catalog, overlay or compiler: every tenant is resolved again (after jobs.start(): the task enqueues).
  registerBootTask('mdm.catalog-release', async () => { await resolveOnCatalogChange(); });

  // ── Audit (§10.7; audit-durci §3.4): critical P1 in the transaction of the effect,
  //    standard P3 after it, protective P4 never blocked. Details: identifiers and counters only.
  //    The registry's actions (device.ownership_changed, device.group_changed, device.end_user_assigned,
  //    end_user.*) and the resource name end_user are the core's (audit/coreActions.ts, audit/read.ts):
  //    the routes of /api/mdm are mounted with the core API.
  registerAuditActions([
    { name: 'enrollment.ownership_mismatch', criticality: 'standard', label: 'Enrollment refused: ownership and mode' },
    // Policies, assignments and apps (lots B5, C4)
    { name: 'policy.published', criticality: 'critical', label: 'Policy published' },
    { name: 'assignment.changed', criticality: 'critical', label: 'Assignments changed' },
    { name: 'policy.created', criticality: 'standard', label: 'Policy created' },
    { name: 'policy.draft_saved', criticality: 'standard', label: 'Policy draft saved' },
    { name: 'policy.submitted', criticality: 'standard', label: 'Policy submitted' },
    { name: 'policy.archived', criticality: 'standard', label: 'Policy archived' },
    { name: 'policy.updated', criticality: 'standard', label: 'Policy renamed or described' },
    { name: 'policy.draft_discarded', criticality: 'standard', label: 'Policy draft discarded' },
    { name: 'policy.raw_profile_imported', criticality: 'standard', label: 'Configuration profile imported into a policy draft' },
    { name: 'policy.rejected', criticality: 'protective', label: 'Policy version rejected' },
    { name: 'app.created', criticality: 'standard', label: 'App added to the catalog' },
    { name: 'app.updated', criticality: 'standard', label: 'App of the catalog updated' },
    { name: 'app.archived', criticality: 'standard', label: 'App of the catalog archived' },
    // Saved views of the device list (P0-5 T2, D6): the shared ones only, never a private view.
    { name: 'device_view.shared_created', criticality: 'standard', label: 'Shared device view created' },
    { name: 'device_view.shared_updated', criticality: 'standard', label: 'Shared device view changed' },
    { name: 'device_view.shared_deleted', criticality: 'standard', label: 'Shared device view deleted' },
  ]);
  registerAuditResourceName('policy', 'policies');
  registerAuditResourceName('app', 'apps');
  registerAuditResourceName('device_view', 'device_views');

  // ── Restrictions (§10.7, DM4): the ownership change, a second approver by default; never below a step-up.
  //    The publication of a policy or a change of assignments (§7.12, DM23): a step-up at least (its floor, no
  //    stored default), a second approver beyond the thresholds or when the matrix says 'restricted'.
  registerRestrictableActions(
    [{ key: 'device.change_ownership', label: 'Change device ownership', category: 'MDM' },
      { key: 'mdm.policy_publish', label: 'Publish a policy or change assignments', category: 'MDM' }],
    { 'device.change_ownership': 'restricted' },
    { 'device.change_ownership': { level: 'sensitive' }, 'mdm.policy_publish': { level: 'sensitive' } },
  );
  registerApprovalExecutor('change_ownership', executeChangeOwnership);
  // One request type for every change of the effective configuration that needs a second approver: a version to
  // publish, a batch of assignment changes, a group moved in the tree or deleted (policies/groupTree.ts, S12).
  registerApprovalRequestType('mdm_policy_publish', executePolicyPublish, { onClosed: onPolicyPublishClosed });

  // ── Secret references of the documents (DM17; coffre-secrets §6.4): kept alive by the garbage collection of
  //    tenant_secrets while a version, an assignment or an artifact refers to them.
  for (const [table, column] of [['policy_versions', 'content'], ['assignments', 'options'], ['mdm_artifacts', 'body']] as const) {
    registerSecretReferenceHolder({ table, column, tenantColumn: 'tenant_id', refs: (v) => findSecretRefs(typeof v === 'string' ? JSON.parse(v) : v) });
  }
}

/** The console API of the data model, mounted at /api/mdm (routes/index.ts), after requireTenant. */
export function createMdmRouter(): Router {
  const router = Router();
  router.use('/end-users', endUserRoutes);
  router.use('/device-views', deviceViewRoutes);
  router.use('/', policyRoutes);
  router.use('/', appRoutes);
  router.use('/', deviceRoutes);
  return router;
}
