import type { Request } from 'express';
import type { Knex } from 'knex';
import {
  POLICY_PUBLISH_REQUEST_TYPE, canonicalRule, ruleSha256, validateRule,
  type DeviceFactsEffect, type DeviceFactsOutcome, type PolicyImpact, type RuleNode, type SmartGroupGovernedOutcome,
  type SmartGroupMembershipDelta,
} from '@obligarth/shared';
import { db } from '../../db';
import { userActor } from '../../db/context';
import { audit, type AuditWriteContext } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import {
  approvalService, refuse, requireTenantCapability, type ApprovalExecution, type PendingApproval,
} from '../../services/approval.service';
import { deviceService } from '../../services/device.service';
import { permissionService } from '../../services/permission.service';
import { recordDirectChange } from '../policies/changeLedger';
import { withConfigurationLock } from '../policies/configLock';
import {
  approvalImpact, computeImpact, describeKeys, impactSummary, registerProposedKind,
  type DeviceFactsChange, type ImpactResult, type MembershipDelta, type Proposal, type ProposedChange, type SmartGroupChange,
} from '../policies/impact';
import { quoted } from '../policies/impactPure';
import { signImpactToken } from '../policies/impactToken';
import type { PolicyState } from '../policies/loader';
import {
  approvedImpactOf, conflictRefusal, emitPolicyChanged, impactChanged, matrixLevel, refuseUnlessAsApproved, stepUp, visibleDevices,
  type Level, type RouteOutcome,
} from '../policies/publishGuard';
import { requestDeviceResolution } from '../policies/triggers';
import {
  DevicePatchBody, factsWithPatch, labelOf, touchesRuleFacts, writeDevicePatch, type DevicePatch,
} from '../registry/devicePatch';
import { evaluateRule } from '../rules/evaluate';
import { loadRuleFacts } from '../rules/facts';
import { emitGroupsChanged } from './evaluate';
import {
  SmartGroupPatchBody, checkRuleGroups, deleteInTx, isTargeted, journalAfter, lockForGovernance, markDrift, memberIdsOf, releaseInTx,
  requireTargetable, selectMembers, smartGroupAdminOnly, smartGroupNotFound, smartGroupNotHeld, smartGroupService, visibleCount,
  writeRuleInTx, type GovernedWrite, type LockedGroup,
} from './smartGroupService';
import { requestGroupEvaluation } from './triggers';

// =============================================================================
// Governed changes of the dynamic groups (P0-5 T7, §4.4; D3, D4, D11; the coordination's brick « changement
// gouverné »). A dynamic group an assignment targets is part of the configuration: what its members receive follows
// its rule, as what a static group's devices receive follows the tree. So its changes go the way of a change of the
// tree of groups (groupTree.ts):
//   - smart_group_rule (PATCH /api/mdm/smart-groups/:id with a new rule), smart_group_delete (DELETE …/:id),
//     smart_group_release (POST …/:id/release: the changes the mass guard kept waiting, D4): a preview by the same pure
//     function as the resolution (computeImpact, the proposals registered below: the devices that enter or leave the
//     group, their dynamic groups once written), with the entries and exits; when it touches the configuration of a
//     device, the restriction mdm.policy_publish (a step-up at least), raised to a second approver beyond the
//     thresholds of DM23 (cumulative over the hour) or when the matrix says 'restricted'; decided and written under
//     the lock of the tenant's configuration, then the group's row (lockForGovernance); a request of the type
//     mdm_policy_publish beyond the thresholds, executed as the requester once approved: refused when the rule of the
//     group changed since the request (its version), when the preview computed again is no longer the one approved
//     (refuseUnlessAsApproved: DM23's tolerance, the digest of the content, the reach of each key), or when the
//     requester lost their rights. Only a tenant administrator (or a platform administrator) changes a group an
//     assignment targets (D3: 403 smartGroupAdminOnly), with groups.manage (the route). A new rule creating a conflict
//     on devices is refused (422 policyConflict); a release is not (what it applies is the inventory's: an overlap is
//     broken by the resolution and signalled by policy.conflict, as the incremental computation does).
//   - device_facts (PATCH /api/mdm/devices/:id, D11): a change of the name, tags, custom fields or asset statuses of a
//     device that makes it enter or leave a dynamic group an assignment targets (the TypeScript evaluator on the facts
//     before and after the patch, the active groups only: a held group applies nothing until its governed release, a
//     group in error is frozen) needs devices.manage (403 deviceFactsGoverned) and goes through the same circuit (the
//     preview of the device: its groups and its name, a variable of the policies). A change that moves the device in no
//     such group goes through as before; when it touches a field a rule may read while a group of the tenant is
//     targeted, it is decided under the lock of the configuration too (an assignment written meanwhile is then seen:
//     409 impactChanged, submit again); while none is, without that lock (as before this lot). The device's
//     membership itself follows from the marking of the change (smart_group_dirty) and the incremental computation.
// In the caller's tenant (the session's for a group; the device's: asTargetTenant).
// =============================================================================

type Q = Knex | Knex.Transaction;

/** 403 smartGroupAdminOnly: a member who is not an administrator of the tenant changes a group an assignment targets (D3). */
const adminOnly = smartGroupAdminOnly;

/** 403 deviceFactsGoverned: the change makes the device enter or leave a targeted group, without devices.manage (D11). */
const factsGoverned = (effect: DeviceFactsEffect): AppError => new AppError(403,
  'This change makes the device enter or leave a dynamic group an assignment targets: it needs devices.manage',
  'deviceFactsGoverned', { entered: effect.entered, left: effect.left });

/** Is the user an administrator of the tenant (or of the platform)? */
async function tenantAdmin(userId: number, tenantId: number, isPlatformAdmin: boolean): Promise<boolean> {
  if (isPlatformAdmin) return true;
  const ut = await db('user_tenants').where({ user_id: userId, tenant_id: tenantId }).first('role') as { role: string } | undefined;
  return ut?.role === 'admin';
}

// ── Proposals (impact.ts: registerProposedKind) ──────────────────────────────────────────────────────────────────

/** The dynamic groups of a device with (or without) one of them. */
function withMembership(ids: number[] | undefined, groupId: number, member: boolean): number[] {
  const rest = (ids ?? []).filter((x) => x !== groupId);
  return member ? [...rest, groupId].sort((a, b) => a - b) : rest;
}

/**
 * A group whose members become `proposed`: the devices that enter or leave it are the ones reached (those that stay
 * receive the same thing before and after: the assignments do not change), their dynamic groups once written.
 */
function membershipProposal(state: PolicyState, groupId: number, current: number[], proposed: number[]): Proposal {
  const cur = new Set(current);
  const next = new Set(proposed);
  const added = proposed.filter((id) => !cur.has(id));
  const removed = current.filter((id) => !next.has(id));
  return {
    proposed: state, targets: [], deviceIds: [...added, ...removed].sort((a, b) => a - b), focus: null, deviceConflicts: true,
    membership: { smartGroupId: groupId, added, removed, total: proposed.length, members: proposed },
    reshape: (set) => ({
      devices: set.devices.map((d) => (cur.has(d.id) !== next.has(d.id) ? { ...d, smartGroupIds: withMembership(d.smartGroupIds, groupId, next.has(d.id)) } : d)),
      groupAncestors: set.groupAncestors,
    }),
  };
}

const asObject = (v: unknown): unknown => (typeof v === 'string' ? JSON.parse(v) : v);

/** The row of a group of the tenant (404 smartGroupNotFound). */
async function groupRow(q: Q, tenantId: number, id: number): Promise<{ id: number; state: string; rule: RuleNode }> {
  const g = await q('smart_groups').where({ tenant_id: tenantId, id }).first('id', 'state', 'rule') as { id: number; state: string; rule: unknown } | undefined;
  if (!g) throw smartGroupNotFound();
  return { id: Number(g.id), state: g.state, rule: asObject(g.rule) as RuleNode };
}

/** 400 invalidRule (its issues) for a rule the catalog does not validate. */
function requireValidRule(rule: unknown, status = 400): asserts rule is RuleNode {
  const issues = validateRule(rule);
  if (issues.length) throw new AppError(status, 'Invalid rule', 'invalidRule', { issues });
}

registerProposedKind('smart_group_rule', async (q, tenantId, state, change) => {
  const c = change as Extract<SmartGroupChange, { kind: 'smart_group_rule' }>;
  await groupRow(q, tenantId, c.smartGroupId);
  requireValidRule(c.rule);
  return membershipProposal(state, c.smartGroupId, await memberIdsOf(q, tenantId, c.smartGroupId), await selectMembers(q, tenantId, c.rule));
});

registerProposedKind('smart_group_release', async (q, tenantId, state, change) => {
  const c = change as Extract<SmartGroupChange, { kind: 'smart_group_release' }>;
  const g = await groupRow(q, tenantId, c.smartGroupId);
  if (g.state !== 'held') throw smartGroupNotHeld();
  requireValidRule(g.rule, 409);
  return membershipProposal(state, c.smartGroupId, await memberIdsOf(q, tenantId, c.smartGroupId), await selectMembers(q, tenantId, g.rule));
});

registerProposedKind('smart_group_delete', async (q, tenantId, state, change) => {
  const c = change as Extract<SmartGroupChange, { kind: 'smart_group_delete' }>;
  await groupRow(q, tenantId, c.smartGroupId);
  const id = c.smartGroupId;
  const current = await memberIdsOf(q, tenantId, id);
  // Its assignments are deleted with it (smart_groups_assignments_cleanup), its members leave it.
  return {
    proposed: { ...state, assignments: state.assignments.filter((a) => !(a.targetScope === 'smart_group' && a.targetId === id)) },
    targets: [], deviceIds: current, focus: null,
    membership: { smartGroupId: id, added: [], removed: current, total: 0, members: [] },
    reshape: (set) => ({ devices: set.devices.map((d) => ({ ...d, smartGroupIds: withMembership(d.smartGroupIds, id, false) })), groupAncestors: set.groupAncestors }),
  };
});

registerProposedKind('device_facts', async (q, tenantId, state, change) => {
  const c = change as DeviceFactsChange;
  const effect = await deviceFactsEffect(q, tenantId, c.deviceId, c.patch);
  const entered = new Set(effect.entered);
  const left = new Set(effect.left);
  return {
    proposed: state, targets: [], deviceIds: [c.deviceId], focus: null, deviceConflicts: true,
    reshape: (set) => ({
      devices: set.devices.map((d) => {
        if (d.id !== c.deviceId) return d;
        const groups = (d.smartGroupIds ?? []).filter((g) => !left.has(g));
        for (const g of entered) if (!groups.includes(g)) groups.push(g);
        return { ...d, label: effect.label ?? d.label, smartGroupIds: groups.sort((a, b) => a - b) };
      }),
      groupAncestors: set.groupAncestors,
    }),
  };
});

// ── The facts of a device (D11) ──────────────────────────────────────────────────────────────────────────────────

/** What a patch changes for a device: the targeted groups it enters and leaves, and its name (null: unchanged). */
export interface FactsEffect extends DeviceFactsEffect {
  label: string | null;
  /** The dynamic groups of the tenant an assignment targets, whatever their state (0: the patch cannot move the device
   *  in any, now; the PATCH then needs no lock of the configuration). */
  targeted: number;
}

/**
 * The dynamic groups an assignment targets (active: a held group applies nothing until its release, a group in error
 * is frozen) that a patch makes a device of the tenant enter or leave: the TypeScript evaluator (rules/evaluate.ts, the
 * semantics of the SQL) on its facts before and after the patch. A device out of management is in no group (D9).
 * 404 for a device the tenant does not have.
 */
export async function deviceFactsEffect(q: Q, tenantId: number, deviceId: number, patch: DevicePatch, now = new Date()): Promise<FactsEffect> {
  const row = await q('devices').where({ tenant_id: tenantId, id: deviceId })
    .first('uuid', 'device_name', 'model_name', 'model', 'enrollment_state') as
    { uuid: string; device_name: string | null; model_name: string | null; model: string | null; enrollment_state: string } | undefined;
  if (!row) throw new AppError(404, 'Device not found');
  const parts = { deviceName: row.device_name ?? null, modelName: row.model_name ?? null, model: row.model ?? null, uuid: String(row.uuid) };
  const out: FactsEffect = {
    entered: [], left: [],
    label: patch.displayName === undefined ? null : labelOf({ ...parts, displayName: patch.displayName === null ? null : String(patch.displayName).slice(0, 500) }),
    targeted: 0,
  };
  if (!touchesRuleFacts(patch) || row.enrollment_state === 'unenrolled') return out;
  const rows = await q('smart_groups as g').where({ 'g.tenant_id': tenantId })
    .whereExists(function targeted() {
      this.select(q.raw('1')).from('assignments as a')
        .whereRaw('a.tenant_id = g.tenant_id').where('a.target_scope', 'smart_group').whereRaw('a.target_id = g.id');
    })
    .orderBy('g.id').select('g.id', 'g.state', 'g.rule') as Array<{ id: number; state: string; rule: unknown }>;
  out.targeted = rows.length;
  const groups = rows.filter((r) => r.state === 'active')
    .map((r) => ({ id: Number(r.id), rule: asObject(r.rule) as RuleNode })).filter((g) => validateRule(g.rule).length === 0);
  if (!groups.length) return out;
  const [facts] = await loadRuleFacts(q, tenantId, [deviceId], { rules: groups.map((g) => g.rule) });
  if (!facts) return out;
  const next = factsWithPatch(facts, patch, parts);
  for (const g of groups) {
    const before = evaluateRule(g.rule, facts, now);
    const after = evaluateRule(g.rule, next, now);
    if (after && !before) out.entered.push(g.id);
    if (before && !after) out.left.push(g.id);
  }
  return out;
}

const movesGroups = (e: DeviceFactsEffect): boolean => e.entered.length > 0 || e.left.length > 0;

// ── The look: preview and level ──────────────────────────────────────────────────────────────────────────────────

interface GovernedLook extends ImpactResult { level: Level }

/** The preview of a governed change as `q` reads the tenant, and the level it needs (groupTree.ts's rule: a change that
 *  touches the configuration of a device needs the restriction mdm.policy_publish, a second approver beyond DM23). */
async function look(q: Q, tenantId: number, change: ProposedChange, visible: number[] | 'all'): Promise<GovernedLook> {
  const result = await computeImpact(q, tenantId, change, { visibleDeviceIds: visible });
  const { impact } = result;
  const reasons = [...impact.approval.reasons];
  let level: Level = 'none';
  if (impact.devicesTouched > 0) {
    level = reasons.length ? 'restricted' : await matrixLevel(tenantId);
    if (level === 'restricted' && !reasons.length) reasons.push('restriction');
  }
  impact.approval = { required: level === 'restricted', reasons: level === 'restricted' ? reasons : [] };
  return { ...result, level };
}

/** The entries and exits of a preview, counted: on the tenant for an administrator ('all'), on the devices their teams
 *  see for another caller (D3: never a count of the devices out of their reach, as POST /preview). */
function deltaOf(m: MembershipDelta | undefined, groupId: number, visible: number[] | 'all'): SmartGroupMembershipDelta {
  const v = visible === 'all' ? null : visible;
  const scope = v ? 'visible' as const : 'all' as const;
  if (!m) return { smartGroupId: groupId, added: 0, removed: 0, total: 0, scope };
  return {
    smartGroupId: m.smartGroupId, added: visibleCount(m.added, v), removed: visibleCount(m.removed, v),
    total: v ? visibleCount(m.members, v) : m.total, scope,
  };
}

/** Does a kind of change refuse the conflicts it creates on devices? A new rule and the facts of a device: written by
 *  an operator, as an assignment. A release applies what the inventory changed (broken at run time, signalled). */
const refusesConflicts = (kind: ProposedChange['kind']): boolean => kind === 'smart_group_rule' || kind === 'device_facts';

// ── Dynamic groups: rule, deletion, release ──────────────────────────────────────────────────────────────────────

/** Name and description that come with a new rule (PATCH). */
export interface GroupFields { name?: string; description?: string | null }

async function writeGroupChange(trx: Knex.Transaction, tenantId: number, g: LockedGroup, change: SmartGroupChange, fields: GroupFields,
  ctx: AuditWriteContext, o: { userId: number; approvalId?: number; details: Record<string, unknown> }): Promise<GovernedWrite> {
  if (change.kind === 'smart_group_rule') return writeRuleInTx(trx, tenantId, g, change.rule, fields, ctx, o);
  if (change.kind === 'smart_group_delete') return deleteInTx(trx, tenantId, g, ctx, o);
  return releaseInTx(trx, tenantId, g, ctx, o);
}

/** The policies assigned to a group (their POLICY_CHANGED once it is deleted: their assignments went with it). */
async function policiesOf(q: Q, tenantId: number, groupId: number): Promise<number[]> {
  return (await q('assignments').where({ tenant_id: tenantId, target_scope: 'smart_group', target_id: groupId, resource_type: 'policy' })
    .pluck('resource_id') as number[]).map(Number);
}

function describeGroupChange(g: { name: string }, change: SmartGroupChange, now: GovernedLook): string {
  const m = deltaOf(now.membership, change.smartGroupId, 'all');
  const what = change.kind === 'smart_group_rule' ? `Change the rule of the dynamic group ${quoted(g.name)}`
    : change.kind === 'smart_group_delete' ? `Delete the dynamic group ${quoted(g.name)}`
      : `Release the dynamic group ${quoted(g.name)} held by the mass guard`;
  const { impact } = now;
  return `${what} — ${m.added} device(s) enter, ${m.removed} leave; ${impact.devicesTouched} touched, `
    + `${impact.artifacts.removals} removal(s) (${impact.approval.reasons.join(', ')}); keys: ${describeKeys(impact)}`;
}

/**
 * PATCH /api/mdm/smart-groups/:id with a new rule (`fields`: the name and description that come with it), DELETE
 * /api/mdm/smart-groups/:id, POST /api/mdm/smart-groups/:id/release, once the route has checked groups.manage; in the
 * session's tenant. `dryRun`: the preview only, nothing written.
 * Answers: 200 { data: SmartGroupGovernedOutcome } (preview, applied); 202 (awaiting_approval); the challenge of the
 * step-up otherwise. 403 smartGroupAdminOnly (D3), 409 smartGroupNotHeld, smartGroupNotTargetable, 422 policyConflict.
 */
export async function changeSmartGroup(req: Request, change: SmartGroupChange, fields: GroupFields, dryRun: boolean): Promise<RouteOutcome> {
  const tenantId = req.tenantId!;
  const userId = req.session.userId!;
  const isPlatformAdmin = req.session.role === 'admin';
  const id = change.smartGroupId;
  const g = await groupRow(db, tenantId, id);
  const targeted = await isTargeted(db, tenantId, id);
  if (targeted && !(await tenantAdmin(userId, tenantId, isPlatformAdmin))) throw adminOnly();
  if (change.kind === 'smart_group_release' && g.state !== 'held') throw smartGroupNotHeld();
  if (change.kind === 'smart_group_rule') {
    await checkRuleGroups(db, tenantId, change.rule);
    if (targeted) requireTargetable(change.rule);
  }
  const visible = await visibleDevices(req);
  const token = (): string | null => signImpactToken(tenantId, userId, change);
  // A first look, before anything is locked: the preview asked for, an early refusal, what the request must prove.
  const first = await look(db, tenantId, change, visible);
  if (dryRun) {
    first.impact.devicesToken = token();
    const body: SmartGroupGovernedOutcome = { outcome: 'preview', membership: deltaOf(first.membership, id, visible), impact: first.impact };
    return { status: 200, body: { data: body } };
  }
  if (refusesConflicts(change.kind) && first.impact.conflicts.length) conflictRefusal(first.impact.conflicts);
  let proven = false;
  if (first.level === 'sensitive') {
    const refused = await stepUp(req);
    if (refused) return refused;
    proven = true;
  }
  const ctx = await audit.fromRequest(req, tenantId);
  // The decision, where the group is written: previewed again under the lock of the configuration and the group's row.
  const done = await withConfigurationLock(tenantId, async (trx): Promise<{
    look: GovernedLook; approval: PendingApproval | null; write: GovernedWrite | null; policyIds: number[];
  }> => {
    const locked = await lockForGovernance(trx, tenantId, id);
    // Targeted meanwhile: D3 again.
    if (locked.assignment_count > 0 && !(await tenantAdmin(userId, tenantId, isPlatformAdmin))) throw adminOnly();
    if (change.kind === 'smart_group_release' && locked.state !== 'held') throw smartGroupNotHeld();
    if (change.kind === 'smart_group_rule' && locked.assignment_count > 0) requireTargetable(change.rule);
    const now = await look(trx, tenantId, change, visible);
    if (refusesConflicts(change.kind) && now.impact.conflicts.length) conflictRefusal(now.impact.conflicts);
    if (now.level === 'restricted') {
      const m = deltaOf(now.membership, id, 'all');
      const approval = await approvalService.createInTx(trx, {
        tenantId, userId, requestType: POLICY_PUBLISH_REQUEST_TYPE,
        description: describeGroupChange(locked, change, now),
        payload: {
          kind: change.kind, smartGroupId: id, ruleVersion: locked.rule_version,
          ...(change.kind === 'smart_group_rule' ? { rule: change.rule, ruleSha256: change.ruleSha256 } : {}),
          ...(change.kind === 'smart_group_rule' && fields.name !== undefined ? { name: fields.name } : {}),
          ...(change.kind === 'smart_group_rule' && fields.description !== undefined ? { description: fields.description } : {}),
          membership: { added: m.added, removed: m.removed, total: m.total },
          impact: approvalImpact(now),
        },
        auditCtx: ctx,
      });
      return { look: now, approval, write: null, policyIds: [] };
    }
    // A second factor is owed that the request was not asked for.
    if (now.level === 'sensitive' && !proven) impactChanged();
    const policyIds = change.kind === 'smart_group_delete' ? await policiesOf(trx, tenantId, id) : [];
    const write = await writeGroupChange(trx, tenantId, locked, change, fields, ctx, { userId, details: { impact: impactSummary(now.impact) } });
    await recordDirectChange(trx, tenantId, change.kind, { deviceIds: now.touched.map((t) => t.deviceId), removalDeviceIds: now.removalDeviceIds });
    return { look: now, approval: null, write, policyIds };
  });
  const { impact } = done.look;
  impact.devicesToken = token();
  const membership = deltaOf(done.look.membership, id, visible);
  if (done.approval) {
    approvalService.announceCreated(done.approval);
    const body: SmartGroupGovernedOutcome = {
      outcome: 'awaiting_approval', status: 'pending_approval', approvalId: done.approval.id, membership, impact,
    };
    return { status: 202, body: { data: body } };
  }
  await journalAfter(tenantId, ctx, done.write!.entry);
  if (change.kind === 'smart_group_rule') await markDrift(tenantId, id, change.ruleSha256);
  emitGroupsChanged(tenantId, [id]);
  emitPolicyChanged(tenantId, [...new Set(done.policyIds)]);
  const change_ = done.write!.change;
  // As the caller sees it (D3: the members of their teams' devices for a non-administrator).
  const scope = visible === 'all' ? null : visible;
  const group = change.kind === 'smart_group_delete' ? null
    : await smartGroupService.get({ tenantId, userId, visibleIds: visible, admin: visible === 'all' }, id);
  const body: SmartGroupGovernedOutcome = {
    outcome: 'applied', membership, impact, group,
    added: change_ ? visibleCount(change_.added, scope) : null, removed: change_ ? visibleCount(change_.removed, scope) : null,
    ...(change.kind === 'smart_group_delete' ? { deleted: true as const } : {}),
  };
  return { status: 200, body: { data: body } };
}

/** The governed change of a group as named by a request's payload; null when malformed. */
function groupChangeOf(p: Record<string, unknown>): SmartGroupChange | null {
  const id = Number(p.smartGroupId);
  if (!Number.isSafeInteger(id) || id <= 0) return null;
  if (p.kind === 'smart_group_delete' || p.kind === 'smart_group_release') return { kind: p.kind, smartGroupId: id };
  if (p.kind !== 'smart_group_rule' || validateRule(p.rule).length > 0) return null;
  const canonical = canonicalRule(p.rule as RuleNode);
  // The rule approved is the one whose hash the request carries.
  if (typeof p.ruleSha256 !== 'string' || ruleSha256(canonical) !== p.ruleSha256) return null;
  return { kind: 'smart_group_rule', smartGroupId: id, rule: canonical, ruleSha256: p.ruleSha256 };
}

/**
 * An approved change of a dynamic group (request type mdm_policy_publish, kinds smart_group_rule, smart_group_delete,
 * smart_group_release), executed as the requester: groups.manage and, for a targeted group, an administrator of the
 * tenant (D3) checked again; under the lock of the configuration and the group's row, the version of its rule must be
 * the one of the request (the rule did not change since), the preview computed again is compared with the one
 * approved, then written in the same transaction.
 */
export async function executeSmartGroupChange(x: ApprovalExecution): Promise<void> {
  const p = (x.payload ?? {}) as Record<string, unknown>;
  const change = groupChangeOf(p);
  const approved = approvedImpactOf(p);
  const version = Number(p.ruleVersion);
  const fields = SmartGroupPatchBody.safeParse({
    ...(p.name !== undefined ? { name: p.name } : {}), ...(p.description !== undefined ? { description: p.description } : {}),
  });
  if (!change || !approved || !Number.isSafeInteger(version) || version <= 0 || !fields.success) {
    refuse('Malformed request of a change of a dynamic group');
  }
  const r = await requireTenantCapability(x.requesterId, x.tenantId, 'groups.manage');
  const stale = (err: unknown): never => {
    const e = err as { statusCode?: number; message?: string };
    if (e.statusCode && e.statusCode < 500) refuse(`The change no longer applies: ${e.message}`);
    throw err;
  };
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  const id = change!.smartGroupId;
  const done = await withConfigurationLock(x.tenantId, async (trx) => {
    const g = await lockForGovernance(trx, x.tenantId, id).catch(stale);
    if (g.rule_version !== version) {
      refuse(`ruleChanged: the rule of the group changed since the request (version ${g.rule_version} now, ${version} requested); `
        + 'request the change again');
    }
    if (g.assignment_count > 0 && !(await tenantAdmin(x.requesterId, x.tenantId, r.isPlatformAdmin))) {
      refuse('The requester is no longer an administrator of the tenant');
    }
    if (change!.kind === 'smart_group_release' && g.state !== 'held') refuse('The group is no longer held: nothing to release');
    const now = await computeImpact(trx, x.tenantId, change!, { cumulative: false }).catch(stale);
    if (refusesConflicts(change!.kind) && now.impact.conflicts.length) {
      refuse('policyConflict: the change now sets a key to two values at the same priority on devices; request it again');
    }
    refuseUnlessAsApproved(approved!, now, 'request the change again');
    const policyIds = change!.kind === 'smart_group_delete' ? await policiesOf(trx, x.tenantId, id) : [];
    const write = await writeGroupChange(trx, x.tenantId, g, change!, fields.data as GroupFields, ctx,
      { userId: x.requesterId, approvalId: x.approvalId, details: { impact: impactSummary(now.impact) } }).catch(stale);
    return { write, policyIds };
  }, { unbounded: true });
  await journalAfter(x.tenantId, ctx, done.write.entry);
  if (change!.kind === 'smart_group_rule') await markDrift(x.tenantId, id, change!.ruleSha256);
  emitGroupsChanged(x.tenantId, [id]);
  emitPolicyChanged(x.tenantId, [...new Set(done.policyIds)]);
}

// ── The facts of a device: PATCH /api/mdm/devices/:id (D11) ─────────────────────────────────────────────────────

function describeFactsChange(label: string, patch: DevicePatch, effect: DeviceFactsEffect, now: GovernedLook): string {
  const { impact } = now;
  return `Change the fields ${Object.keys(patch).join(', ')} of the device ${quoted(label)} — it enters ${effect.entered.length} and leaves `
    + `${effect.left.length} dynamic group(s) an assignment targets; ${impact.devicesTouched} touched, ${impact.artifacts.removals} removal(s) `
    + `(${impact.approval.reasons.join(', ')}); keys: ${describeKeys(impact)}`;
}

/**
 * PATCH /api/mdm/devices/:id once the route has checked write access on the device, in the device's tenant
 * (asTargetTenant). Writes the patch and answers null (the route answers the record and does what follows a change of
 * the record), or answers itself: the preview (?dryRun=true: DeviceFactsOutcome), the request for a second approver
 * (202), the challenge of the step-up; 403 deviceFactsGoverned without devices.manage (D11).
 */
export async function changeDeviceFacts(req: Request, tenantId: number, deviceId: number, patch: DevicePatch, dryRun: boolean):
  Promise<RouteOutcome | null> {
  const preview = (governed: boolean, smartGroups: DeviceFactsEffect, impact: PolicyImpact | null): RouteOutcome => {
    const body: DeviceFactsOutcome = { outcome: 'preview', governed, smartGroups, impact };
    return { status: 200, body: { data: body } };
  };
  const none: DeviceFactsEffect = { entered: [], left: [] };
  // Nothing a rule reads: as before (no lock).
  if (!touchesRuleFacts(patch)) {
    if (dryRun) return preview(false, none, null);
    await db.transaction(async (trx) => {
      if (!(await writeDevicePatch(trx, tenantId, deviceId, patch))) throw new AppError(404, 'Device not found');
    });
    return null;
  }
  const effectOf = (q: Q): Promise<FactsEffect> => deviceFactsEffect(q, tenantId, deviceId, patch);
  const first = await effectOf(db);
  const groupsOf = (e: FactsEffect): DeviceFactsEffect => ({ entered: e.entered, left: e.left });
  if (!movesGroups(first)) {
    if (dryRun) return preview(false, groupsOf(first), null);
    // No dynamic group of the tenant is targeted: written as before, without the lock (a rename or a tag never waits
    // behind a publication). A group targeted in the meantime then sees the device enter as any change of the
    // inventory: by the incremental computation, under the mass guard.
    if (first.targeted === 0) {
      await db.transaction(async (trx) => {
        if (!(await writeDevicePatch(trx, tenantId, deviceId, patch))) throw new AppError(404, 'Device not found');
      });
      return null;
    }
    // Decided under the lock of the configuration: an assignment written meanwhile to a group the device would enter
    // is seen here (409 impactChanged: submit again, the governed circuit then applies).
    await withConfigurationLock(tenantId, async (trx) => {
      if (movesGroups(await effectOf(trx))) impactChanged();
      if (!(await writeDevicePatch(trx, tenantId, deviceId, patch))) throw new AppError(404, 'Device not found');
    });
    return null;
  }
  // D11: devices.manage, and the governed preview.
  const userId = req.session.userId!;
  if (req.session.role !== 'admin' && !(await permissionService.userHasTenantCapability(userId, tenantId, 'devices.manage'))) {
    throw factsGoverned(groupsOf(first));
  }
  const change: DeviceFactsChange = { kind: 'device_facts', deviceId, patch };
  const visible = await visibleDevices(req);
  const head = await look(db, tenantId, change, visible);
  // One device: the sample shows it; no token of a list (it would carry the values of the patch in a URL).
  if (dryRun) return preview(true, groupsOf(first), head.impact);
  if (head.impact.conflicts.length) conflictRefusal(head.impact.conflicts);
  let proven = false;
  if (head.level === 'sensitive') {
    const refused = await stepUp(req);
    if (refused) return refused;
    proven = true;
  }
  const ctx = await audit.fromRequest(req, tenantId);
  const done = await withConfigurationLock(tenantId, async (trx): Promise<{ look: GovernedLook; effect: FactsEffect; approval: PendingApproval | null }> => {
    const effect = await effectOf(trx);
    const now = await look(trx, tenantId, change, visible);
    if (now.impact.conflicts.length) conflictRefusal(now.impact.conflicts);
    if (now.level === 'restricted') {
      const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).first('label') as { label: string } | undefined;
      const approval = await approvalService.createInTx(trx, {
        tenantId, userId, requestType: POLICY_PUBLISH_REQUEST_TYPE,
        description: describeFactsChange(d?.label ?? `#${deviceId}`, patch, effect, now),
        payload: { kind: 'device_facts', deviceId, patch, smartGroups: groupsOf(effect), impact: approvalImpact(now) },
        auditCtx: ctx,
      });
      return { look: now, effect, approval };
    }
    if (now.level === 'sensitive' && !proven) impactChanged();
    if (!(await writeDevicePatch(trx, tenantId, deviceId, patch))) throw new AppError(404, 'Device not found');
    await recordDirectChange(trx, tenantId, 'device_facts', { deviceIds: now.touched.map((t) => t.deviceId), removalDeviceIds: now.removalDeviceIds });
    return { look: now, effect, approval: null };
  });
  if (!done.approval) return null;
  approvalService.announceCreated(done.approval);
  const body: DeviceFactsOutcome = {
    outcome: 'awaiting_approval', status: 'pending_approval', approvalId: done.approval.id, smartGroups: groupsOf(done.effect), impact: done.look.impact,
  };
  return { status: 202, body: { data: body } };
}

/**
 * An approved change of the facts of a device (request type mdm_policy_publish, kind device_facts), executed as the
 * requester: devices.manage and write access on the device checked again, the preview computed again under the lock
 * of the configuration and compared with the one approved, then the patch written in the same transaction (the
 * incremental computation of the dynamic groups woken, the device resolved again when its name changed); the entry
 * device.updated with the approval.
 */
export async function executeDeviceFactsChange(x: ApprovalExecution): Promise<void> {
  const p = (x.payload ?? {}) as { deviceId?: unknown; patch?: unknown; impact?: unknown };
  const deviceId = Number(p.deviceId);
  const patch = DevicePatchBody.safeParse(p.patch);
  const approved = approvedImpactOf(p);
  if (!approved || !patch.success || !Number.isSafeInteger(deviceId) || deviceId <= 0) refuse('Malformed request of a change of a device');
  const r = await requireTenantCapability(x.requesterId, x.tenantId, 'devices.manage');
  if (!r.isPlatformAdmin && !(await permissionService.canWriteDevice(x.requesterId, deviceId, false))) {
    refuse('The requester no longer has write access to the device');
  }
  const change: DeviceFactsChange = { kind: 'device_facts', deviceId, patch: patch.data! };
  const stale = (err: unknown): never => {
    const e = err as { statusCode?: number; message?: string };
    if (e.statusCode && e.statusCode < 500) refuse(`The change no longer applies: ${e.message}`);
    throw err;
  };
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  await withConfigurationLock(x.tenantId, async (trx) => {
    const now = await computeImpact(trx, x.tenantId, change, { cumulative: false }).catch(stale);
    if (now.impact.conflicts.length) refuse('policyConflict: the change now sets a key to two values at the same priority on the device; request it again');
    refuseUnlessAsApproved(approved!, now, 'request the change again');
    if (!(await writeDevicePatch(trx, x.tenantId, deviceId, change.patch))) refuse('The device of this request is no longer in the tenant');
    await requestGroupEvaluation(trx, x.tenantId, [deviceId]);
    if (change.patch.displayName !== undefined || change.patch.customFields !== undefined) await requestDeviceResolution(trx, x.tenantId, [deviceId]);
  }, { unbounded: true });
  await audit.append({
    tenantId: x.tenantId, action: 'device.updated', target: { type: 'device', id: String(deviceId), device: deviceId },
    approvalIds: x.approvalId ? [x.approvalId] : undefined,
    details: { fields: Object.keys(change.patch).slice(0, 20), approvalId: x.approvalId ?? null },
  }, ctx);
  deviceService.emitChanged(x.tenantId, [deviceId]);
}
