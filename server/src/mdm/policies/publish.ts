import type { Request } from 'express';
import type { Knex } from 'knex';
import { z } from 'zod';
import {
  ASSIGNMENT_PRIORITY, POLICY_PUBLISH_REQUEST_TYPE,
  type AssignmentChange, type JsonValue, type PolicyContentV1, type PolicyImpact, type PolicyPublishKind, type PolicyValidationIssue,
  type SubmitOutcome,
} from '@obligarth/shared';
import { db } from '../../db';
import { userActor } from '../../db/context';
import { audit, type AuditWriteContext } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import {
  approvalService, refuse, requireTenantCapability, type ApprovalClosed, type ApprovalExecution, type PendingApproval,
} from '../../services/approval.service';
import { permissionService } from '../../services/permission.service';
import { logger } from '../../utils/logger';
import { lockTenantConfiguration, withConfigurationLock } from './configLock';
import { recordDirectChange } from './changeLedger';
import { executeDeviceMove } from './deviceMove';
import { executeGroupTreeChange } from './groupTree';
import {
  approvalImpact, computeImpact, describeKeys, impactSummary, type AssignmentDelta, type ImpactResult, type ProposedChange,
} from './impact';
import { quoted } from './impactPure';
import { signImpactToken } from './impactToken';
import { rowToAssignment } from './loader';
import { policyService, rowToVersion, settleOrphanedPending, validateForSubmission, validationFailed } from './policyService';
import {
  approvedImpactOf, conflictRefusal, emitPolicyChanged, impactChanged, matrixLevel, refuseUnlessAsApproved, requiredLevel, stepUp,
  visibleDevices, type RouteOutcome,
} from './publishGuard';
import type { ResolutionAssignment } from './resolver';
import { requestTenantResolution } from './triggers';
import { assignableApp, normalizeAppOptions } from '../apps/appCatalogService';
import { requireTargetableGroup } from '../groups/smartGroupService';
import { executeDeviceFactsChange, executeSmartGroupChange } from '../groups/governance';
import { androidContributions } from '../android/contributions';
import { validateAndroidSection } from '../android/validate';
import { checkAndroidAppAssignment, holdsSecretValue, sealAndroidAppOptions } from '../../android/apps/assignments';

// =============================================================================
// Submission, publication and approval (docs: modele-donnees-mdm §7.11,
// §7.12, DM23): a version submitted, or a batch of assignment changes, is
// validated (content, conflicts) and previewed; the restriction
// mdm.policy_publish of the tenant (a step-up at least: its floor) is raised
// to a second approver beyond the thresholds (25 touched devices, 10 % of the
// enrolled fleet, a removal on 3 devices) or when the matrix says
// 'restricted'. Without a second approver: step-up, then publication in the
// same request. With one: the version waits ('pending_approval', or the
// batch in the request's payload), the request type mdm_policy_publish is
// executed as the requester once approved, and its executor computes the
// preview again: beyond 20 % more touched devices or removals than approved,
// with another content than the one approved, or with a key of that content
// set on more devices than approved (same tolerance), the execution is refused
// (impactChanged, contentChanged) and the version goes back to the draft. A
// refused or expired request rejects the version.
// The decision is taken where the change is written (review of lot B5b,
// MDM-B5b-C1): a first look, outside any transaction, tells what the request
// must prove (a second factor) and answers a refusal early; then, in one
// transaction that holds the lock of the tenant's configuration
// (configLock.ts), the change is validated and previewed again on what is
// committed, and that preview decides: written at once, or a request for
// approval, in the same transaction as the check. Two changes of a tenant
// made at the same time are thus decided one after the other, each on the
// state the other left.
// The publication and the change of assignments are written with their
// critical entry (P1, last statement), and request the resolution of the
// tenant (mdm.policies.resolve-tenant).
// A dynamic group as a target (P0-5 T6): one of the tenant's whose rule holds
// targetable fields only (D2: 409 smartGroupNotTargetable, the fields at
// fault), an inclusion with an explicit priority (D1, modele §7.13: it ranks
// as the static group a device is directly in), written by an administrator of
// the tenant or of the platform only (D3, as the whole tenant). An exclusion by
// a dynamic group is admitted.
// The request type mdm_policy_publish carries other kinds of change, each with
// its own executor (registerPublishKind, below): the tree of groups
// (groupTree.ts), a move of devices (deviceMove.ts), and the governed changes
// of the dynamic groups and of the facts of a device (P0-5 T7,
// groups/governance.ts).
// =============================================================================

export { emitPolicyChanged, type RouteOutcome };

const POLICY_MANAGE = 'mdm.policies.manage' as const;
const APPS_MANAGE = 'mdm.apps.manage' as const;

/** The preview as stored with a version, read by every member of the tenant and shown to the approver: its counters,
 *  keys and conflicts. The sample of devices and the token of their list are the requester's (their scopes, their
 *  session): never stored (S13); a reader asks for a preview of their own. */
const storedImpact = (impact: PolicyImpact): string => JSON.stringify({ ...impact, sample: [], devicesToken: undefined });

/** A preview with its token of the full list of touched devices. */
async function preview(req: Request, tenantId: number, change: ProposedChange): Promise<PolicyImpact> {
  const { impact } = await computeImpact(db, tenantId, change, { matrixLevel: await matrixLevel(tenantId), visibleDeviceIds: await visibleDevices(req) });
  impact.devicesToken = signImpactToken(tenantId, req.session.userId!, change);
  return impact;
}

// ── Versions ───────────────────────────────────────────────────────────────

/** The preview of the publication of a version (POST …/versions/:v/impact): nothing written. */
export async function versionImpact(req: Request, tenantId: number, policyId: number, version: number): Promise<PolicyImpact> {
  await policyService.policyRow(db, tenantId, policyId);
  const row = await policyService.versionRow(db, tenantId, policyId, version);
  return preview(req, tenantId, { kind: 'version', policyId, versionId: Number(row.id) });
}

/**
 * Publication of a version in `trx`: the previous published version superseded, the version published (from a
 * draft, or from 'pending_approval' when an approval is executed), the envelope pointing to it, the resolution of
 * the tenant requested, then the critical entry policy.published (P1, last statement). Under the lock of the
 * tenant's configuration (taken here when the caller does not hold it yet).
 */
export async function publishVersionInTx(trx: Knex.Transaction, tenantId: number, policyId: number, versionId: number,
  ctx: AuditWriteContext, o: { from: 'draft' | 'pending_approval'; approvalId?: number; impact: PolicyImpact; userId: number | null;
    /** The content validated and previewed: a draft saved meanwhile is not published (409 policyVersionChanged). */
    expectedSha?: string }): Promise<void> {
  await lockTenantConfiguration(trx, tenantId);
  // The policy, then its version (the order of every writer of the versions); an archived policy publishes nothing.
  const policy = await trx('policies').where({ tenant_id: tenantId, id: policyId }).forUpdate().first('state') as { state: string } | undefined;
  if (!policy) throw new AppError(404, 'Policy not found');
  if (policy.state === 'archived') throw new AppError(409, 'An archived policy does not change', 'policyArchived');
  const v = await trx('policy_versions').where({ tenant_id: tenantId, id: versionId, policy_id: policyId }).forUpdate()
    .first('id', 'version', 'state', 'approval_id', 'content_sha256') as { id: number; version: number; state: string; approval_id: number | null; content_sha256: string } | undefined;
  if (!v) throw new AppError(404, 'Policy version not found');
  if (v.state !== o.from || (o.from === 'pending_approval' && Number(v.approval_id) !== o.approvalId)) {
    throw new AppError(409, 'The version is no longer in the state of its submission', 'policyVersionNotDraft', { state: v.state });
  }
  if (o.expectedSha !== undefined && String(v.content_sha256).trim() !== o.expectedSha) versionChanged();
  const now = new Date();
  await trx('policy_versions').where({ tenant_id: tenantId, policy_id: policyId, state: 'published' })
    .update({ state: 'superseded', superseded_at: now });
  await trx('policy_versions').where({ tenant_id: tenantId, id: versionId }).update({
    state: 'published', published_at: now, published_by: o.userId,
    ...(o.from === 'draft' ? { submitted_at: now, submitted_by: o.userId } : {}),
    impact: storedImpact(o.impact),
  });
  await trx('policies').where({ tenant_id: tenantId, id: policyId })
    .update({ current_version_id: versionId, state: 'published', updated_at: now, updated_by: o.userId });
  await requestTenantResolution(trx, tenantId);
  await audit.appendInTx(trx, {
    tenantId, action: 'policy.published', target: { type: 'policy', id: String(policyId) },
    approvalIds: o.approvalId ? [o.approvalId] : undefined,
    details: { version: Number(v.version), contentSha256: String(v.content_sha256).trim(), approvalId: o.approvalId ?? null,
      impact: impactSummary(o.impact) },
  }, ctx);
}

const versionChanged = (): never => {
  throw new AppError(409, 'The draft changed while it was checked: submit it again', 'policyVersionChanged');
};

interface VersionCheck extends ImpactResult { issues: PolicyValidationIssue[]; contentSha256: string }

/** Checks a version for its publication: content, references, conflicts. Returns the preview (with the digest of
 *  its content) and the hash of the content checked (unchanged from the validation to the end of the preview). */
async function checkVersion(q: Knex | Knex.Transaction, tenantId: number, policyId: number, versionId: number,
  o: { visibleDeviceIds?: number[] | 'all' } = {}): Promise<VersionCheck> {
  const policy = await q('policies').where({ tenant_id: tenantId, id: policyId }).first('uuid', 'state') as { uuid: string; state: string } | undefined;
  if (!policy) throw new AppError(404, 'Policy not found');
  if (policy.state === 'archived') throw new AppError(409, 'An archived policy does not change', 'policyArchived');
  const row = await q('policy_versions').where({ tenant_id: tenantId, id: versionId, policy_id: policyId }).first('content', 'content_sha256') as
    { content: unknown; content_sha256: string } | undefined;
  if (!row) throw new AppError(404, 'Policy version not found');
  const contentSha256 = String(row.content_sha256).trim();
  const { issues, content, androidWipeRules } = await validateForSubmission(q, tenantId, policy.uuid, typeof row.content === 'string' ? JSON.parse(row.content) : row.content);
  const result = await computeImpact(q, tenantId, { kind: 'version', policyId, versionId },
    { matrixLevel: await matrixLevel(tenantId), visibleDeviceIds: o.visibleDeviceIds ?? 'all' });
  // Android (android-amapi §22.4, lot AN-A2): a version that adds, removes or changes a wipe-capable setting is
  // published at the restricted level (a second approver), whatever the thresholds.
  if (!issues.length && await wipeSettingsChanged(q, tenantId, policyId, content, androidWipeRules)) {
    result.impact.approval.required = true;
    if (!result.impact.approval.reasons.includes('wipe_settings')) result.impact.approval.reasons.push('wipe_settings');
  }
  const after = await q('policy_versions').where({ tenant_id: tenantId, id: versionId }).first('content_sha256') as { content_sha256: string } | undefined;
  if (!after || String(after.content_sha256).trim() !== contentSha256) versionChanged();
  return { ...result, issues, contentSha256 };
}

/** Does a version add, remove or change a wipe-capable Android setting against the policy's published version
 *  (android-amapi §22.4)? Compared by setting key and value hash. */
async function wipeSettingsChanged(q: Knex | Knex.Transaction, tenantId: number, policyId: number,
  content: PolicyContentV1 | null, wipeRules: string[]): Promise<boolean> {
  const current = await q('policies as p').join('policy_versions as v', function joinVersion() {
    this.on('v.id', '=', 'p.current_version_id').andOn('v.tenant_id', '=', 'p.tenant_id');
  }).where({ 'p.tenant_id': tenantId, 'p.id': policyId }).first('v.content') as { content: unknown } | undefined;
  const before = current ? (typeof current.content === 'string' ? JSON.parse(current.content) : current.content) as PolicyContentV1 : null;
  const beforeWipe = before?.sections?.android ? validateAndroidSection(before.sections.android).wipeRules : [];
  if (!wipeRules.length && !beforeWipe.length) return false;
  const hashes = (c: PolicyContentV1 | null): Map<string, string> =>
    new Map(androidContributions(c?.sections?.android).map((x) => [x.settingKey, x.valueHash]));
  const now = hashes(content);
  const was = hashes(before);
  for (const key of new Set([...wipeRules, ...beforeWipe])) {
    if (!wipeRules.includes(key) || !beforeWipe.includes(key) || now.get(key) !== was.get(key)) return true;
  }
  return false;
}

/** POST /api/mdm/policies/:id/versions/:v/submit (section 7.12). */
export async function submitVersion(req: Request, tenantId: number, policyId: number, version: number): Promise<RouteOutcome> {
  await policyService.policyRow(db, tenantId, policyId);
  await settleOrphanedPending(db, tenantId, policyId);
  const row = await policyService.versionRow(db, tenantId, policyId, version);
  if (row.state !== 'draft') throw new AppError(409, 'Only a draft is submitted', 'policyVersionNotDraft', { state: row.state });
  const versionId = Number(row.id);
  const visible = await visibleDevices(req);
  const userId = req.session.userId ?? null;
  const requester: Requester = { userId: req.session.userId!, isPlatformAdmin: req.session.role === 'admin' };
  await requireWriteOnAssignedTargets(db, tenantId, policyId, requester);
  // A first look, before anything is locked: an early refusal, and what the request must prove.
  const first = await checkVersion(db, tenantId, policyId, versionId, { visibleDeviceIds: visible });
  if (first.issues.length) validationFailed(first.issues);
  if (first.impact.conflicts.length) conflictRefusal(first.impact.conflicts);
  let proven = false;
  if ((await requiredLevel(tenantId, first.impact)) === 'sensitive') {
    const refused = await stepUp(req);
    if (refused) return refused;
    proven = true;
  }
  const ctx = await audit.fromRequest(req, tenantId);
  // The decision, where the version is written: checked and previewed again under the lock of the configuration.
  const done = await withConfigurationLock(tenantId, async (trx): Promise<{ impact: PolicyImpact; approval: PendingApproval | null }> => {
    const policy = await trx('policies').where({ tenant_id: tenantId, id: policyId }).forUpdate().first('name', 'state') as
      { name: string; state: string } | undefined;
    if (!policy) throw new AppError(404, 'Policy not found');
    if (policy.state === 'archived') throw new AppError(409, 'An archived policy does not change', 'policyArchived');
    const locked = await trx('policy_versions').where({ tenant_id: tenantId, id: versionId, policy_id: policyId }).forUpdate().first('state') as
      { state: string } | undefined;
    if (!locked) throw new AppError(404, 'Policy version not found');
    if (locked.state !== 'draft') throw new AppError(409, 'Only a draft is submitted', 'policyVersionNotDraft', { state: locked.state });
    await requireWriteOnAssignedTargets(trx, tenantId, policyId, requester);
    const check = await checkVersion(trx, tenantId, policyId, versionId, { visibleDeviceIds: visible });
    if (check.issues.length) validationFailed(check.issues);
    const { impact } = check;
    if (impact.conflicts.length) conflictRefusal(impact.conflicts);
    const level = await requiredLevel(tenantId, impact);
    if (level === 'restricted') {
      const approval = await approvalService.createInTx(trx, {
        tenantId, userId: Number(userId), requestType: POLICY_PUBLISH_REQUEST_TYPE,
        description: `Publish version ${version} of the policy ${quoted(policy.name)} — ${impact.devicesTouched} device(s) touched, `
          + `${impact.artifacts.removals} removal(s) (${impact.approval.reasons.join(', ')}); keys: ${describeKeys(impact)}`,
        payload: { kind: 'version', policyId, versionId, version, impact: approvalImpact(check) },
        auditCtx: ctx,
      });
      await trx('policy_versions').where({ tenant_id: tenantId, id: versionId }).update({
        state: 'pending_approval', approval_id: approval.id, impact: storedImpact(impact), submitted_at: new Date(), submitted_by: userId,
      });
      return { impact, approval };
    }
    if (level === 'sensitive' && !proven) impactChanged();
    await publishVersionInTx(trx, tenantId, policyId, versionId, ctx, { from: 'draft', impact, userId, expectedSha: check.contentSha256 });
    await recordDirectChange(trx, tenantId, 'version', { deviceIds: check.touched.map((t) => t.deviceId), removalDeviceIds: check.removalDeviceIds });
    return { impact, approval: null };
  });
  const { impact, approval } = done;
  impact.devicesToken = signImpactToken(tenantId, req.session.userId!, { kind: 'version', policyId, versionId });
  if (approval) approvalService.announceCreated(approval);
  await audit.append({
    tenantId, action: 'policy.submitted', target: { type: 'policy', id: String(policyId) }, approvalIds: approval ? [approval.id] : undefined,
    details: approval
      ? { version, devicesTouched: impact.devicesTouched, approvalRequired: true, reasons: impact.approval.reasons }
      : { version, devicesTouched: impact.devicesTouched, approvalRequired: false },
  }, ctx);
  emitPolicyChanged(tenantId, [policyId]);
  const body: SubmitOutcome = approval
    ? { outcome: 'awaiting_approval', approvalId: approval.id, impact }
    : { outcome: 'published', versionId, impact };
  return { status: approval ? 202 : 200, body: { data: body } };
}

// ── Assignments ────────────────────────────────────────────────────────────

const Change = z.object({
  op: z.enum(['create', 'update', 'delete']),
  id: z.number().int().positive().optional(),
  resourceType: z.enum(['policy', 'app']).optional(),
  resourceId: z.number().int().positive().optional(),
  resourceTenantId: z.number().int().positive().optional(),
  targetScope: z.enum(['tenant', 'group', 'device', 'smart_group']).optional(),
  targetId: z.number().int().positive().nullable().optional(),
  mode: z.enum(['include', 'exclude']).optional(),
  priority: z.number().int().min(ASSIGNMENT_PRIORITY.min).max(ASSIGNMENT_PRIORITY.max).optional(),
  options: z.record(z.string(), z.unknown()).optional(),
}).strict();
export const ChangesBody = z.object({ changes: z.array(Change).min(1).max(100) }).strict();

export interface Requester { userId: number; isPlatformAdmin: boolean }

/** May the requester write assignments on this target? The whole tenant and a dynamic group (P0-5 D3: it gives no team
 *  scope, D8): a tenant administrator; a group or a device: write access through the teams (an administrator always). */
async function canWriteTarget(r: Requester, tenantId: number, scope: string, id: number | null): Promise<boolean> {
  if (r.isPlatformAdmin) return true;
  const ut = await db('user_tenants').where({ user_id: r.userId, tenant_id: tenantId }).first('role') as { role: string } | undefined;
  if (ut?.role === 'admin') return true;
  if (scope === 'tenant' || scope === 'smart_group') return false;
  if (scope === 'group') return permissionService.canWriteGroup(r.userId, Number(id), false);
  return permissionService.canWriteDevice(r.userId, Number(id), false);
}

/**
 * A version published changes the configuration of every device its policy is included on: the requester must be
 * able to write each of those targets, as an assignment to them requires (review of lot B5b, MDM-B5b-C6; decision
 * of the owners of 15/10/2026). A tenant administrator (and a platform administrator) always can. An exclusion is
 * not a target the publication changes. 403 policyTargetNotWritable, naming the first target refused.
 */
export async function requireWriteOnAssignedTargets(q: Knex | Knex.Transaction, tenantId: number, policyId: number, r: Requester): Promise<void> {
  if (r.isPlatformAdmin) return;
  const ut = await db('user_tenants').where({ user_id: r.userId, tenant_id: tenantId }).first('role') as { role: string } | undefined;
  if (ut?.role === 'admin') return;
  const targets = await q('assignments').where({
    tenant_id: tenantId, resource_type: 'policy', resource_tenant_id: tenantId, resource_id: policyId, mode: 'include',
  }).orderBy('id').select('target_scope', 'target_id') as Array<{ target_scope: string; target_id: number | null }>;
  for (const t of targets) {
    const id = t.target_id === null ? null : Number(t.target_id);
    if (!(await canWriteTarget(r, tenantId, t.target_scope, id))) {
      throw new AppError(403, 'No write permission on a target the policy is assigned to', 'policyTargetNotWritable', { scope: t.target_scope, id });
    }
  }
}

/**
 * The changes of a batch against the tenant as it is (rights of the requester re-checked): each one as the
 * assignment before and after it. A policy's assignment needs mdm.policies.manage and has no options; an app's (lot C4,
 * section 8.2) needs mdm.apps.manage and carries its options (AppleAppOptionsSchema, defaults filled).
 */
export async function normalizeChanges(q: Knex | Knex.Transaction, tenantId: number, changes: AssignmentChange[], r: Requester): Promise<AssignmentDelta[]> {
  const deltas: AssignmentDelta[] = [];
  const touchedIds = new Set<number>();
  /** The Android apps of the batch (lot AN-C1): their options are an ApplicationPolicy, checked by the Android module. */
  const androidApps = new Set<number>();
  let next = -1;
  // The capability of each kind of resource of the batch, read once.
  const held = new Map<string, boolean>();
  const requireCapabilityFor = async (type: 'policy' | 'app'): Promise<void> => {
    if (r.isPlatformAdmin) return;
    const cap = type === 'app' ? APPS_MANAGE : POLICY_MANAGE;
    if (!held.has(cap)) held.set(cap, await permissionService.userHasTenantCapability(r.userId, tenantId, cap));
    if (!held.get(cap)) throw new AppError(403, 'Insufficient permissions');
  };
  for (const [i, ch] of changes.entries()) {
    const bad = (message: string, field?: string): never => {
      throw new AppError(400, message, 'invalidRequest', { index: i, ...(field ? { field } : {}) });
    };
    if (ch.op === 'create') {
      if (ch.id !== undefined) bad('A new assignment has no id', 'id');
      const resourceType = ch.resourceType ?? 'policy';
      if (!ch.resourceId) bad('resourceId required', 'resourceId');
      if (!ch.targetScope) bad('targetScope required', 'targetScope');
      await requireCapabilityFor(resourceType);
      const resourceTenantId = ch.resourceTenantId ?? tenantId;
      if (resourceType === 'policy') {
        const policy = await q('policies').where({ id: ch.resourceId, tenant_id: resourceTenantId }).first('id', 'state') as { id: number; state: string } | undefined;
        if (!policy) throw new AppError(404, 'Policy not found');
        if (policy.state === 'archived') throw new AppError(409, 'An archived policy is not assigned', 'policyArchived');
      } else {
        const app = await assignableApp(q, tenantId, resourceTenantId, ch.resourceId!);
        if (app.platformFamily === 'android') androidApps.add(app.id);
      }
      const scope = ch.targetScope!;
      const targetId = scope === 'tenant' ? null : (ch.targetId ?? null);
      if (scope !== 'tenant' && targetId === null) bad('targetId required', 'targetId');
      if (scope === 'tenant' && ch.targetId) bad('The tenant has no target id', 'targetId');
      if (scope === 'group' && !(await q('device_groups').where({ tenant_id: tenantId, id: targetId }).first('id'))) throw new AppError(404, 'Group not found');
      if (scope === 'device' && !(await q('devices').where({ tenant_id: tenantId, id: targetId }).first('id'))) throw new AppError(404, 'Device not found');
      if (scope === 'smart_group') await requireTargetableGroup(q, tenantId, targetId!);
      const mode = ch.mode ?? 'include';
      if (scope === 'tenant' && mode === 'exclude') bad('The whole tenant is never excluded', 'mode');
      if (scope === 'smart_group' && mode === 'include' && ch.priority === undefined) bad('An inclusion by a dynamic group needs an explicit priority', 'priority');
      if (resourceType === 'policy' && ch.options && Object.keys(ch.options).length) bad('A policy assignment has no options', 'options');
      if (resourceType === 'app' && mode === 'exclude' && ch.options && Object.keys(ch.options).length) bad('An exclusion has no options', 'options');
      const options = resourceType !== 'app' || mode !== 'include' ? {}
        : androidApps.has(ch.resourceId!) ? await checkedAndroidOptions(q, tenantId, ch.resourceId!, ch.options ?? {}, i)
          : normalizeAppOptions(ch.options ?? {});
      const exists = await q('assignments').where({
        tenant_id: tenantId, resource_type: resourceType, resource_tenant_id: resourceTenantId, resource_id: ch.resourceId, target_scope: scope,
      }).where((w) => (targetId === null ? w.whereNull('target_id') : w.where({ target_id: targetId }))).first('id');
      if (exists) throw new AppError(409, 'This resource is already assigned to this target', 'assignmentExists', { id: Number(exists.id) });
      if (!(await canWriteTarget(r, tenantId, scope, targetId))) throw new AppError(403, 'No write permission on the target');
      const after: ResolutionAssignment = {
        id: next--, resourceType, resourceId: ch.resourceId!, resourceTenantId, targetScope: scope, targetId, mode,
        priority: ch.priority ?? ASSIGNMENT_PRIORITY.default, options,
      };
      if (deltas.some((d) => d.after && d.after.resourceType === after.resourceType && d.after.resourceId === after.resourceId && d.after.resourceTenantId === after.resourceTenantId
        && d.after.targetScope === after.targetScope && d.after.targetId === after.targetId)) bad('The same assignment twice in a batch');
      deltas.push({ before: null, after });
      continue;
    }
    if (!ch.id) bad('id required', 'id');
    if (touchedIds.has(ch.id!)) bad('The same assignment twice in a batch', 'id');
    touchedIds.add(ch.id!);
    const row = await q('assignments').where({ tenant_id: tenantId, id: ch.id }).first() as Record<string, unknown> | undefined;
    if (!row) throw new AppError(404, 'Assignment not found');
    const before = rowToAssignment(row);
    await requireCapabilityFor(before.resourceType);
    if (!(await canWriteTarget(r, tenantId, before.targetScope, before.targetId))) throw new AppError(403, 'No write permission on the target');
    if (ch.op === 'delete') {
      deltas.push({ before, after: null });
      continue;
    }
    for (const f of ['resourceType', 'resourceId', 'resourceTenantId', 'targetScope', 'targetId'] as const) {
      const given = ch[f];
      const current = (before as unknown as Record<string, unknown>)[f];
      if (given !== undefined && given !== current) bad('The resource and the target of an assignment do not change (delete, then create)', f);
    }
    const mode = ch.mode ?? before.mode;
    if (before.targetScope === 'tenant' && mode === 'exclude') bad('The whole tenant is never excluded', 'mode');
    // An exclusion by a dynamic group made an inclusion: its priority is given again (D1), and its rule still targetable.
    if (before.targetScope === 'smart_group' && mode === 'include' && before.mode === 'exclude') {
      if (ch.priority === undefined) bad('An inclusion by a dynamic group needs an explicit priority', 'priority');
      await requireTargetableGroup(q, tenantId, before.targetId!);
    }
    if (before.resourceType === 'policy' && ch.options && Object.keys(ch.options).length) bad('A policy assignment has no options', 'options');
    if (before.resourceType === 'app' && mode === 'exclude' && ch.options && Object.keys(ch.options).length) bad('An exclusion has no options', 'options');
    const android = before.resourceType === 'app' && await isAndroidApp(q, before.resourceTenantId, before.resourceId);
    const options = before.resourceType !== 'app' || mode === 'exclude' ? (mode === 'exclude' ? {} : before.options)
      : android ? await checkedAndroidOptions(q, tenantId, before.resourceId, ch.options !== undefined ? ch.options : before.options ?? {}, i)
        : ch.options !== undefined ? normalizeAppOptions(ch.options) : Object.keys(before.options ?? {}).length ? before.options : normalizeAppOptions({});
    deltas.push({ before, after: { ...before, mode, priority: ch.priority ?? before.priority, options } });
  }
  return deltas;
}

/** Is the app an Android app of the catalog? */
async function isAndroidApp(q: Knex | Knex.Transaction, tenantId: number, appId: number): Promise<boolean> {
  return !!(await q('apps').where({ tenant_id: tenantId, id: appId, platform_family: 'android' }).first('id'));
}

/**
 * The options of an assignment of an Android app (android-amapi §9.6; lot AN-C1, raccord of AN-E1): checked against
 * the app's schema and the tenant's secrets (checkAndroidAppAssignment); 422 androidAppOptionsInvalid with the issues
 * otherwise. A secret typed in ({"$secretValue"}) is admitted here (the preview) and sealed by sealBatchAndroidOptions
 * before anything stores the batch.
 */
async function checkedAndroidOptions(q: Knex | Knex.Transaction, tenantId: number, appId: number, options: unknown, index: number):
  Promise<Record<string, JsonValue>> {
  const c = await checkAndroidAppAssignment(q, tenantId, appId, options);
  if (!c) throw new AppError(404, 'App not found', 'appNotFound');
  if (c.issues.length) throw new AppError(422, 'Invalid options of an Android app assignment', 'androidAppOptionsInvalid', { index, issues: c.issues.slice(0, 20) });
  return (options ?? {}) as Record<string, JsonValue>;
}

/**
 * The secrets typed in the options of the batch's Android app assignments moved to the tenant's vault and replaced by
 * their reference (sealAndroidAppOptions), once, before the batch or its approval request is stored: no value in clear
 * ever reaches assignments.options, pending_approvals nor a log. Returns the batch as it is then stored.
 */
async function sealBatchAndroidOptions(tenantId: number, changes: AssignmentChange[], userId: number): Promise<AssignmentChange[]> {
  if (!changes.some((c) => c.options && holdsSecretValue(c.options))) return changes;
  return db.transaction(async (trx) => {
    const out: AssignmentChange[] = [];
    for (const ch of changes) {
      if (!ch.options || !holdsSecretValue(ch.options)) { out.push(ch); continue; }
      let appId: number | null = null;
      if (ch.op === 'create' && ch.resourceType === 'app' && ch.resourceId) appId = ch.resourceId;
      else if (ch.op !== 'create' && ch.id) {
        const row = await trx('assignments').where({ tenant_id: tenantId, id: ch.id, resource_type: 'app' }).first('resource_id') as { resource_id: number } | undefined;
        appId = row ? Number(row.resource_id) : null;
      }
      const c = appId !== null && await isAndroidApp(trx, tenantId, appId) ? await checkAndroidAppAssignment(trx, tenantId, appId, ch.options) : null;
      if (!c) throw new AppError(400, 'A secret value is admitted in the options of an Android app only', 'invalidRequest');
      if (c.issues.length) throw new AppError(422, 'Invalid options of an Android app assignment', 'androidAppOptionsInvalid', { issues: c.issues.slice(0, 20) });
      out.push({ ...ch, options: await sealAndroidAppOptions(trx, tenantId, ch.options as Record<string, JsonValue>, c.secrets, { userId }) });
    }
    return out;
  });
}

/** A policy a batch of assignment changes names, as it stands: its published version (null: none yet). */
export interface PolicyBase { tenantId: number; policyId: number; versionId: number | null; version: number | null; name: string }

/** The policies a batch names, with the version each one has published (the content the batch would assign). */
export async function policyBaseOf(q: Knex | Knex.Transaction, deltas: AssignmentDelta[]): Promise<PolicyBase[]> {
  const pairs = new Map<string, [number, number]>();
  for (const d of deltas) {
    const a = (d.after ?? d.before)!;
    if (a.resourceType === 'policy') pairs.set(`${a.resourceTenantId}:${a.resourceId}`, [a.resourceTenantId, a.resourceId]);
  }
  if (!pairs.size) return [];
  const rows = await q('policies as p')
    .leftJoin('policy_versions as v', function joinVersion() { this.on('v.id', '=', 'p.current_version_id').andOn('v.tenant_id', '=', 'p.tenant_id'); })
    .whereIn(['p.tenant_id', 'p.id'], [...pairs.values()])
    .orderBy([{ column: 'p.tenant_id' }, { column: 'p.id' }])
    .select('p.tenant_id', 'p.id', 'p.name', 'p.current_version_id', 'v.version') as
    Array<{ tenant_id: number; id: number; name: string; current_version_id: number | null; version: number | null }>;
  return rows.map((r) => ({
    tenantId: Number(r.tenant_id), policyId: Number(r.id), name: String(r.name),
    versionId: r.current_version_id === null ? null : Number(r.current_version_id),
    version: r.version === null || r.version === undefined ? null : Number(r.version),
  }));
}

/** The policies of a batch in a few words, for the description of its request. */
function describePolicies(base: PolicyBase[], max = 4): string {
  const one = (b: PolicyBase): string => `${quoted(b.name)} (${b.version === null ? 'not published' : `version ${b.version}`})`;
  if (base.length === 1) return `the policy ${one(base[0])}`;
  const shown = base.slice(0, max).map(one).join(', ');
  return `${base.length} policies: ${base.length > max ? `${shown} (+${base.length - max} more)` : shown}`;
}

/** Applies normalised changes in `trx`, requests the resolution, then the critical entry assignment.changed (P1).
 *  Under the lock of the tenant's configuration (taken here when the caller does not hold it yet). */
export async function applyChangesInTx(trx: Knex.Transaction, tenantId: number, deltas: AssignmentDelta[], ctx: AuditWriteContext,
  o: { userId: number | null; approvalId?: number; impact: PolicyImpact }): Promise<{ created: number; updated: number; deleted: number }> {
  await lockTenantConfiguration(trx, tenantId);
  const out = { created: 0, updated: 0, deleted: 0 };
  const now = new Date();
  for (const d of deltas) {
    if (d.before && !d.after) {
      const n = await trx('assignments').where({ tenant_id: tenantId, id: d.before.id }).delete();
      if (!n) throw new AppError(409, 'An assignment of the batch changed meanwhile', 'assignmentChanged', { id: d.before.id });
      out.deleted++;
    } else if (d.before && d.after) {
      const n = await trx('assignments').where({ tenant_id: tenantId, id: d.before.id, mode: d.before.mode, priority: d.before.priority })
        .whereRaw('options = ?::jsonb', [JSON.stringify(d.before.options ?? {})])
        .update({ mode: d.after.mode, priority: d.after.priority, options: JSON.stringify(d.after.options ?? {}), updated_at: now });
      if (!n) throw new AppError(409, 'An assignment of the batch changed meanwhile', 'assignmentChanged', { id: d.before.id });
      out.updated++;
    } else if (d.after) {
      try {
        await trx('assignments').insert({
          tenant_id: tenantId, resource_type: d.after.resourceType, resource_id: d.after.resourceId,
          resource_tenant_id: d.after.resourceTenantId, target_scope: d.after.targetScope, target_id: d.after.targetId,
          mode: d.after.mode, priority: d.after.priority, options: JSON.stringify(d.after.options ?? {}), created_by: o.userId,
        });
      } catch (err) {
        if ((err as { code?: string }).code === '23505') throw new AppError(409, 'This resource is already assigned to this target', 'assignmentExists');
        throw err;
      }
      out.created++;
    }
  }
  await requestTenantResolution(trx, tenantId);
  const idsOf = (type: 'policy' | 'app'): number[] => [...new Set(deltas.map((d) => (d.after ?? d.before)!).filter((a) => a.resourceType === type)
    .map((a) => a.resourceId))].sort((a, b) => a - b);
  const policies = idsOf('policy');
  const apps = idsOf('app');
  await audit.appendInTx(trx, {
    tenantId, action: 'assignment.changed',
    target: policies.length + apps.length === 1 ? { type: policies.length ? 'policy' : 'app', id: String(policies[0] ?? apps[0]) } : { type: 'assignment', id: 'batch' },
    approvalIds: o.approvalId ? [o.approvalId] : undefined,
    details: { ...out, policies: policies.slice(0, 50), ...(apps.length ? { apps: apps.slice(0, 50) } : {}), approvalId: o.approvalId ?? null, impact: impactSummary(o.impact) },
  }, ctx);
  return out;
}

/** POST /api/mdm/assignments/changes (?dryRun=true for the preview). */
export async function changeAssignments(req: Request, tenantId: number, rawBody: unknown, dryRun: boolean): Promise<RouteOutcome> {
  const parsed = ChangesBody.safeParse(rawBody ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  const requester: Requester = { userId: req.session.userId!, isPlatformAdmin: req.session.role === 'admin' };
  let changes = parsed.data.changes as AssignmentChange[];
  const visible = await visibleDevices(req);
  /** The batch against the tenant as `q` reads it: its changes, their preview. */
  const look = async (q: Knex | Knex.Transaction): Promise<ImpactResult & { deltas: AssignmentDelta[]; change: ProposedChange }> => {
    const deltas = await normalizeChanges(q, tenantId, changes, requester);
    const change: ProposedChange = { kind: 'assignments', changes: deltas };
    const result = await computeImpact(q, tenantId, change, { matrixLevel: await matrixLevel(tenantId), visibleDeviceIds: visible });
    return { ...result, deltas, change };
  };
  // A first look, before anything is locked: the preview asked for, an early refusal, what the request must prove.
  const first = await look(db);
  if (dryRun) {
    first.impact.devicesToken = signImpactToken(tenantId, requester.userId, first.change);
    const body: SubmitOutcome = { outcome: 'preview', impact: first.impact };
    return { status: 200, body: { data: body } };
  }
  if (first.impact.conflicts.length) conflictRefusal(first.impact.conflicts);
  let proven = false;
  if ((await requiredLevel(tenantId, first.impact)) === 'sensitive') {
    const refused = await stepUp(req);
    if (refused) return refused;
    proven = true;
  }
  // The secrets typed in for Android apps sealed now, before the batch, its approval request or a log can hold them
  // (the checks of the first look and the step-up passed: the batch is about to be stored; review AN-C1: a request
  // refused by its step-up writes nothing in the vault).
  changes = await sealBatchAndroidOptions(tenantId, changes, requester.userId);
  const ctx = await audit.fromRequest(req, tenantId);
  // The decision, where the batch is written: normalised and previewed again under the lock of the configuration.
  const done = await withConfigurationLock(tenantId, async (trx) => {
    const now = await look(trx);
    const { impact, deltas } = now;
    if (impact.conflicts.length) conflictRefusal(impact.conflicts);
    const level = await requiredLevel(tenantId, impact);
    if (level === 'restricted') {
      // The request names the version each policy has published: the approval is given on that content (DM10).
      const base = await policyBaseOf(trx, deltas);
      const approval = await approvalService.createInTx(trx, {
        tenantId, userId: requester.userId, requestType: POLICY_PUBLISH_REQUEST_TYPE,
        description: `Change ${changes.length} assignment(s) of ${describePolicies(base)} — ${impact.devicesTouched} device(s) touched, `
          + `${impact.artifacts.removals} removal(s) (${impact.approval.reasons.join(', ')}); keys: ${describeKeys(impact)}`,
        payload: {
          kind: 'assignments', changes, impact: approvalImpact(now),
          base: base.map((b) => ({ tenantId: b.tenantId, policyId: b.policyId, versionId: b.versionId, version: b.version })),
        },
        auditCtx: ctx,
      });
      return { impact, change: now.change, approval, deltas };
    }
    if (level === 'sensitive' && !proven) impactChanged();
    await applyChangesInTx(trx, tenantId, deltas, ctx, { userId: requester.userId, impact });
    await recordDirectChange(trx, tenantId, 'assignments', { deviceIds: now.touched.map((t) => t.deviceId), removalDeviceIds: now.removalDeviceIds });
    return { impact, change: now.change, approval: null, deltas };
  });
  const { impact } = done;
  impact.devicesToken = signImpactToken(tenantId, requester.userId, done.change);
  if (done.approval) {
    approvalService.announceCreated(done.approval);
    const body: SubmitOutcome = { outcome: 'awaiting_approval', approvalId: done.approval.id, impact };
    return { status: 202, body: { data: body } };
  }
  emitPolicyChanged(tenantId, [...new Set(done.deltas.map((d) => (d.after ?? d.before)!.resourceId))]);
  const body: SubmitOutcome = { outcome: 'applied', impact };
  return { status: 200, body: { data: body } };
}

// ── Approval of a publication or of a batch (request type mdm_policy_publish) ──

interface PublishPayload {
  kind: PolicyPublishKind;
  policyId?: number;
  versionId?: number;
  version?: number;
  changes?: AssignmentChange[];
  /** The version each policy of a batch had published when the request was filed (policyBaseOf). */
  base?: Array<{ tenantId: number; policyId: number; versionId: number | null }>;
  /** What the request keeps of its preview (approvalImpact): counters, keys, digest of the content. */
  impact?: unknown;
}

/** Back to the draft: a version whose approved request could not be executed goes back to its author, who submits
 *  it again (a request is executed once: left 'pending_approval', the version would block its policy). */
async function backToDraft(tenantId: number, versionId: number, approvalId: number | undefined): Promise<void> {
  if (!Number.isSafeInteger(versionId) || versionId <= 0 || approvalId === undefined) return;
  await db('policy_versions').where({ tenant_id: tenantId, id: versionId, state: 'pending_approval', approval_id: approvalId })
    .update({ state: 'draft', approval_id: null });
}

/** The publication of an approved version: rights, content, conflicts and preview checked again under the lock of
 *  the configuration, then published in the same transaction. */
async function executeVersionPublication(x: ApprovalExecution, p: PublishPayload, policyId: number, versionId: number): Promise<void> {
  const r = await requireTenantCapability(x.requesterId, x.tenantId, POLICY_MANAGE);
  const approved = approvedImpactOf(p);
  if (!approved) refuse('Malformed publication request');
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  await withConfigurationLock(x.tenantId, async (trx) => {
    const v = await trx('policy_versions').where({ tenant_id: x.tenantId, id: versionId, policy_id: policyId }).first('state', 'approval_id') as
      { state: string; approval_id: number | null } | undefined;
    if (!v || v.state !== 'pending_approval' || Number(v.approval_id) !== x.approvalId) refuse('This version no longer awaits this approval');
    await requireWriteOnAssignedTargets(trx, x.tenantId, policyId, { userId: x.requesterId, isPlatformAdmin: r.isPlatformAdmin })
      .catch((err: { statusCode?: number }) => { if (err?.statusCode === 403) refuse('The requester can no longer write every target the policy is assigned to'); throw err; });
    const check = await checkVersion(trx, x.tenantId, policyId, versionId);
    if (check.issues.length) refuse('The content of the version is no longer valid: submit it again');
    if (check.impact.conflicts.length) refuse('policyConflict: the version now conflicts with another policy at the same priority; submit it again');
    refuseUnlessAsApproved(approved!, check, 'the version is back to the draft, submit it again');
    await publishVersionInTx(trx, x.tenantId, policyId, versionId, ctx,
      { from: 'pending_approval', approvalId: x.approvalId, impact: check.impact, userId: x.requesterId, expectedSha: check.contentSha256 });
  }, { unbounded: true });
}

/** The versions a batch was filed with, when the payload names them all in the expected form; null otherwise. */
function approvedBaseOf(p: PublishPayload): Map<string, number | null> | null {
  if (!Array.isArray(p.base)) return null;
  const out = new Map<string, number | null>();
  for (const b of p.base) {
    const ok = b && Number.isSafeInteger(b.tenantId) && Number.isSafeInteger(b.policyId)
      && (b.versionId === null || Number.isSafeInteger(b.versionId));
    if (!ok) return null;
    out.set(`${b.tenantId}:${b.policyId}`, b.versionId);
  }
  return out;
}

/**
 * An approved batch of assignment changes: rights and targets checked again, previewed again under the lock of the
 * configuration, then applied in the same transaction. The batch was approved for the version each of its policies
 * had published: a policy published again since then is not assigned by this approval (DM10; MDM-B5b-C3).
 */
async function executeAssignmentChanges(x: ApprovalExecution, p: PublishPayload): Promise<void> {
  // The capability of the batch's first kind of resource here (and the requester's state); normalizeChanges reads
  // the capability of every kind it meets again.
  const firstType = Array.isArray(p.changes) && p.changes.length && p.changes.every((c) => c.op === 'create' && c.resourceType === 'app') ? 'app' : 'policy';
  const r = await requireTenantCapability(x.requesterId, x.tenantId, firstType === 'app' ? APPS_MANAGE : POLICY_MANAGE);
  const approved = approvedImpactOf(p);
  const approvedBase = approvedBaseOf(p);
  const changes = ChangesBody.safeParse({ changes: p.changes });
  if (!approved || !approvedBase || !changes.success) refuse('Malformed publication request');
  const stale = (err: unknown): never => {
    const e = err as { statusCode?: number; message?: string };
    if (e.statusCode && e.statusCode < 500) refuse(`The batch no longer applies: ${e.message}`);
    throw err;
  };
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  const deltas = await withConfigurationLock(x.tenantId, async (trx) => {
    const list = await normalizeChanges(trx, x.tenantId, changes.data!.changes as AssignmentChange[],
      { userId: x.requesterId, isPlatformAdmin: r.isPlatformAdmin }).catch(stale);
    const base = await policyBaseOf(trx, list);
    for (const b of base) {
      const key = `${b.tenantId}:${b.policyId}`;
      if (!approvedBase!.has(key) || approvedBase!.get(key) !== b.versionId) {
        refuse(`policyVersionChanged: the policy ${quoted(b.name)} was published again since the request `
          + `(${b.version === null ? 'no published version' : `version ${b.version}`} now); submit the batch again`);
      }
    }
    const now = await computeImpact(trx, x.tenantId, { kind: 'assignments', changes: list }, { matrixLevel: await matrixLevel(x.tenantId) });
    if (now.impact.conflicts.length) refuse('policyConflict: the batch now sets a key to two values at the same priority');
    refuseUnlessAsApproved(approved!, now, 'submit the batch again');
    await applyChangesInTx(trx, x.tenantId, list, ctx, { userId: x.requesterId, approvalId: x.approvalId, impact: now.impact }).catch(stale);
    return list;
  }, { unbounded: true });
  emitPolicyChanged(x.tenantId, [...new Set(deltas.map((d) => (d.after ?? d.before)!.resourceId))]);
}

/** Executes an approved request as the requester: checks again, previews again, publishes or applies. */
export async function executePolicyPublish(x: ApprovalExecution): Promise<string | void> {
  const p = (x.payload ?? {}) as PublishPayload;
  if (p.kind === 'version') {
    const policyId = Number(p.policyId);
    const versionId = Number(p.versionId);
    try {
      await executeVersionPublication(x, p, policyId, versionId);
    } catch (err) {
      // Whatever stopped the execution (a refusal, the journal unavailable, the base), the version does not stay
      // behind a request that is over. Should this fail too, the next change of the policy settles it.
      await backToDraft(x.tenantId, versionId, x.approvalId)
        .catch((e) => logger.error({ err: e, tenantId: x.tenantId, policyId, approvalId: x.approvalId }, 'policy version not given back to its author'));
      if (Number.isSafeInteger(policyId)) emitPolicyChanged(x.tenantId, [policyId]);
      throw err;
    }
    emitPolicyChanged(x.tenantId, [policyId]);
    return;
  }
  if (p.kind === 'assignments') return executeAssignmentChanges(x, p);
  // The other kinds: their own executor (the same request type, the same checks of the preview approved).
  const executor = typeof p.kind === 'string' ? publishKindExecutors.get(p.kind) : undefined;
  if (executor) return executor(x);
  refuse('Malformed publication request');
}

/** Executes an approved request of one kind of change (its payload's kind) as the requester. */
export type PublishKindExecutor = (x: ApprovalExecution) => Promise<string | void>;

/**
 * The executors of the kinds of change a request of the type mdm_policy_publish carries besides a version and a batch
 * (the coordination's brick « changement gouverné », P0-5 T7): a lot that adds a governed kind (its proposal registered
 * in impact.ts, registerProposedKind) registers its executor here (registerPublishKind) instead of a branch above.
 */
const publishKindExecutors = new Map<string, PublishKindExecutor>();

/** Registers the executor of a kind of change of the requests mdm_policy_publish. */
export function registerPublishKind(kind: Exclude<PolicyPublishKind, 'version' | 'assignments'>, execute: PublishKindExecutor): void {
  publishKindExecutors.set(kind, execute);
}

// A group moved in the tree or deleted (groupTree.ts), devices moved into a group (deviceMove.ts, S12); the governed
// changes of the dynamic groups (P0-5 T7, groups/governance.ts): a new rule, a deletion, a release, the facts of a device.
// Called through a closure: resolved when a request is executed, whatever the order the modules were loaded in.
registerPublishKind('group_move', (x) => executeGroupTreeChange(x));
registerPublishKind('group_delete', (x) => executeGroupTreeChange(x));
registerPublishKind('device_move', (x) => executeDeviceMove(x));
registerPublishKind('smart_group_rule', (x) => executeSmartGroupChange(x));
registerPublishKind('smart_group_delete', (x) => executeSmartGroupChange(x));
registerPublishKind('smart_group_release', (x) => executeSmartGroupChange(x));
registerPublishKind('device_facts', (x) => executeDeviceFactsChange(x));

/** A request closed without execution: a refused or expired version is rejected (a new draft can be made), a
 *  cancelled one goes back to the draft of its author. P4 entry policy.rejected. */
export async function onPolicyPublishClosed(x: ApprovalClosed): Promise<void> {
  const p = (x.payload ?? {}) as PublishPayload;
  if (p.kind !== 'version') return;
  const versionId = Number(p.versionId);
  const to = x.status === 'cancelled' ? 'draft' : 'rejected';
  const n = await db('policy_versions').where({ tenant_id: x.tenantId, id: versionId, state: 'pending_approval', approval_id: x.approvalId })
    .update(to === 'draft' ? { state: 'draft', approval_id: null } : { state: 'rejected' });
  if (!n) return;
  const ctx = x.byUserId ? await audit.fromDbActor(userActor(x.byUserId), x.tenantId)
    : audit.fromJob({ name: 'core.approvals.expire', requestId: `approval-${x.approvalId}` });
  await audit.append({
    tenantId: x.tenantId, action: 'policy.rejected', target: { type: 'policy', id: String(p.policyId) }, approvalIds: [x.approvalId],
    details: { version: p.version ?? null, status: x.status, to },
  }, ctx);
  emitPolicyChanged(x.tenantId, [Number(p.policyId)]);
  logger.info({ tenantId: x.tenantId, policyId: p.policyId, version: p.version, status: x.status }, 'policy version not published');
}

export { rowToVersion };
