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
import { registerOnboardStep } from '../apple/devices/jobs';
import { registerMdmJobs } from './jobs';
import { registerPolicyJobs } from './policies/jobs';
import { executePolicyPublish, onPolicyPublishClosed } from './policies/publish';
import { resolveAtOnboarding } from './policies/triggers';
import { changeOwnership } from './registry/ownership';
import deviceRoutes from './routes/devices.routes';
import endUserRoutes from './routes/endUsers.routes';
import policyRoutes from './routes/policies.routes';

// =============================================================================
// MDM DATA MODEL — its hooks into the core's registries (docs:
// modele-donnees-mdm §10.1, §10.5, §10.7), registered here and only here;
// index.ts calls registerMdmModule() before registerAppleModule(), before
// anything starts. No I/O.
// Lot B2: the registry (devices, episodes, end users), its jobs, audit
// actions, restriction and approval executor, the console API. Lot B5b: the
// policies (envelope, versions, assignments), their resolution queues, the
// restriction and the approval of their publication, the secret references
// of their contents. The compilation and the delivery come with lot B5c.
// =============================================================================

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
  // The onboarding of a device (apple.device-onboard, §10.4): once its identity certificate is known, its policies
  // are resolved (a step of the integration's job, in the tenant's context).
  registerOnboardStep('policies.resolve', ({ job, tenantId, deviceId }) => job.inTenant(() => resolveAtOnboarding(tenantId, deviceId)));

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
    { name: 'policy.rejected', criticality: 'protective', label: 'Policy version rejected' },
    { name: 'app.created', criticality: 'standard', label: 'App added to the catalog' },
    { name: 'app.updated', criticality: 'standard', label: 'App of the catalog updated' },
    { name: 'app.archived', criticality: 'standard', label: 'App of the catalog archived' },
  ]);
  registerAuditResourceName('policy', 'policies');
  registerAuditResourceName('app', 'apps');

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
  router.use('/', policyRoutes);
  router.use('/', deviceRoutes);
  return router;
}
