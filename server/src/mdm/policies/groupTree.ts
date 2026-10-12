import type { Request } from 'express';
import type { Knex } from 'knex';
import { POLICY_PUBLISH_ACTION, POLICY_PUBLISH_REQUEST_TYPE, type DeviceGroup, type PolicyImpact } from '@obligarth/shared';
import { db } from '../../db';
import { userActor } from '../../db/context';
import { audit, type AuditWriteContext } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import { activeRequester, approvalService, refuse, type ApprovalExecution, type PendingApproval } from '../../services/approval.service';
import { groupNotificationService } from '../../services/groupNotification.service';
import { groupService } from '../../services/group.service';
import { permissionService } from '../../services/permission.service';
import { restrictionService } from '../../services/restriction.service';
import { withConfigurationLock } from './configLock';
import { approvalImpact, computeImpact, describeKeys, impactSummary, type GroupTreeChange, type ImpactResult } from './impact';
import { quoted } from './impactPure';
import { signImpactToken } from './impactToken';
import { devicesOfTargets } from './loader';
import {
  approvedImpactOf, impactChanged, matrixLevel, refuseUnlessAsApproved, stepUp, strictest, visibleDevices,
  type Level, type RouteOutcome,
} from './publishGuard';

// =============================================================================
// A group moved in the tree, a group deleted (docs: modele-donnees-mdm §7.6,
// §7.11, §7.12, S7, S12; review of lot B5b, MDM-B5b-C2). The policies are
// inherited along the ancestry of the groups: moving a group under another
// parent, or deleting it, changes the effective configuration of every device
// of its subtree, as an assignment would. So the change goes the way of an
// assignment:
//   - a preview, by the same pure function as the resolution, on the ancestry
//     the change would leave (computeImpact, kinds group_move and
//     group_delete);
//   - when it touches the configuration of a device: the restriction
//     mdm.policy_publish (a step-up at least), raised to a second approver
//     beyond the thresholds of DM23 or when the matrix says 'restricted';
//   - when the subtree holds more than one device under management, the
//     restriction device.bulk_group_change of the matrix too (S12): the
//     stricter of the two applies;
//   - decided and written under the lock of the tenant's configuration, with
//     the critical entry group.moved or group.deleted in the transaction;
//   - beyond the thresholds: a request of the type mdm_policy_publish, executed
//     as the requester once approved, rights and preview checked again.
// A change that touches no configuration and moves at most one device keeps
// its previous rule: write access on the group (and on the new parent).
// In the tenant of the group (the caller's context: asTargetTenant).
// =============================================================================

/** Restriction of the matrix on a bulk change of the group of devices (modules/devices.ts). */
const BULK_GROUP_ACTION = 'device.bulk_group_change';

/** Beyond this many devices, the scope of the matrix is not evaluated device by device: the restriction applies. */
const SCOPE_CHECK_MAX = 100;

interface TreeLook extends ImpactResult { level: Level; actionKey: string }

/** The preview of a change of the tree as `q` reads the tenant, and the level it needs. */
async function look(q: Knex | Knex.Transaction, tenantId: number, change: GroupTreeChange, visible: number[] | 'all'): Promise<TreeLook> {
  const result = await computeImpact(q, tenantId, change, { visibleDeviceIds: visible });
  const { impact } = result;
  const reasons = [...impact.approval.reasons];
  // The configuration of devices changes: the guard of a publication.
  let publish: Level = 'none';
  if (impact.devicesTouched > 0) {
    publish = reasons.length ? 'restricted' : await matrixLevel(tenantId);
    if (publish === 'restricted' && !reasons.length) reasons.push('restriction');
  }
  // More than one device changes of place in the tree: the guard of a bulk change of group.
  let bulk: Level = 'none';
  if (impact.devicesInScope > 1) {
    const ids = impact.devicesInScope <= SCOPE_CHECK_MAX ? await devicesOfTargets(q, tenantId, [{ scope: 'group', id: change.groupId }]) : undefined;
    bulk = await restrictionService.getLevelFor({ tenantId, actionKey: BULK_GROUP_ACTION, deviceIds: ids });
    if (bulk === 'restricted' && !reasons.includes('restriction')) reasons.push('restriction');
  }
  const level = strictest(publish, bulk);
  impact.approval = { required: level === 'restricted', reasons: level === 'restricted' ? reasons : [] };
  return { ...result, level, actionKey: publish !== 'none' && strictest(publish, bulk) === publish ? POLICY_PUBLISH_ACTION : BULK_GROUP_ACTION };
}

/** Writes the change in `trx` (which holds the lock), with its journal entry; null or false when the group is gone. */
async function write(trx: Knex.Transaction, change: GroupTreeChange,
  journal: { ctx: AuditWriteContext; approvalId?: number; impact: PolicyImpact }): Promise<DeviceGroup | boolean | null> {
  const o = { trx, journal: { ctx: journal.ctx, approvalId: journal.approvalId, details: { impact: impactSummary(journal.impact) } } };
  return change.kind === 'group_move' ? groupService.move(change.groupId, change.newParentId, o) : groupService.delete(change.groupId, o);
}

async function describe(q: Knex | Knex.Transaction, tenantId: number, group: { id: number; name: string }, change: GroupTreeChange,
  impact: PolicyImpact): Promise<string> {
  // Names chosen by the requester: quoted, so that none passes for the rest of the sentence.
  let what = `Delete the group ${quoted(group.name)}`;
  if (change.kind === 'group_move') {
    const parent = change.newParentId === null ? null
      : await q('device_groups').where({ tenant_id: tenantId, id: change.newParentId }).first('name') as { name: string } | undefined;
    what = `Move the group ${quoted(group.name)} ${change.newParentId === null ? 'to the root of the tree' : `under ${quoted(parent?.name ?? `#${change.newParentId}`)}`}`;
  }
  return `${what} — ${impact.devicesInScope} device(s) in its subtree, ${impact.devicesTouched} touched, `
    + `${impact.artifacts.removals} removal(s) (${impact.approval.reasons.join(', ')}); keys: ${describeKeys(impact)}`;
}

/**
 * POST /api/groups/:id/move and DELETE /api/groups/:id, once the route has checked the caller's rights on the group
 * (and on the new parent). `dryRun`: the preview only, nothing written.
 * Answers: 200 with the group moved ({ success, data }) or the deletion done ({ success, message }); 202 when a
 * second approver is required ({ data: { outcome: 'awaiting_approval', approvalId, status, impact } }); the
 * challenge of the step-up otherwise.
 */
export async function changeGroupTree(req: Request, group: DeviceGroup, change: GroupTreeChange, dryRun: boolean): Promise<RouteOutcome> {
  const tenantId = group.tenantId;
  const userId = req.session.userId!;
  const visible = await visibleDevices(req);
  // The token of the full list is read by /api/mdm/impact in the tenant of the session: none from the global view.
  const token = (): string | null => (tenantId === req.tenantId ? signImpactToken(tenantId, userId, change) : null);
  // A first look, before anything is locked: the preview asked for, what the request must prove.
  const first = await look(db, tenantId, change, visible);
  if (dryRun) {
    first.impact.devicesToken = token();
    return { status: 200, body: { success: true, data: { outcome: 'preview', impact: first.impact } } };
  }
  let proven = false;
  if (first.level === 'sensitive') {
    const refused = await stepUp(req, first.actionKey);
    if (refused) return refused;
    proven = true;
  }
  const ctx = await audit.fromRequest(req, tenantId);
  // The decision, where the tree is written: previewed again under the lock of the configuration.
  const done = await withConfigurationLock(tenantId, async (trx): Promise<{ impact: PolicyImpact; approval: PendingApproval | null; result: DeviceGroup | boolean | null }> => {
    const now = await look(trx, tenantId, change, visible);
    if (now.level === 'restricted') {
      const approval = await approvalService.createInTx(trx, {
        tenantId, userId, requestType: POLICY_PUBLISH_REQUEST_TYPE,
        description: await describe(trx, tenantId, group, change, now.impact),
        payload: {
          kind: change.kind, groupId: change.groupId, ...(change.kind === 'group_move' ? { newParentId: change.newParentId } : {}),
          impact: approvalImpact(now),
        },
        auditCtx: ctx,
      });
      return { impact: now.impact, approval, result: null };
    }
    // A second factor is owed that the request was not asked for, or was asked for another restriction.
    if (now.level === 'sensitive' && (!proven || now.actionKey !== first.actionKey)) impactChanged();
    return { impact: now.impact, approval: null, result: await write(trx, change, { ctx, impact: now.impact }) };
  });
  done.impact.devicesToken = token();
  if (done.approval) {
    approvalService.announceCreated(done.approval);
    return {
      status: 202,
      body: { success: true, data: { outcome: 'awaiting_approval', status: 'pending_approval', approvalId: done.approval.id, impact: done.impact } },
    };
  }
  if (!done.result) throw new AppError(404, 'Group not found');
  if (change.kind === 'group_delete') {
    groupNotificationService.removeGroup(change.groupId);
    return { status: 200, body: { success: true, message: 'Group deleted' } };
  }
  return { status: 200, body: { success: true, data: done.result } };
}

/**
 * An approved change of the tree (request type mdm_policy_publish, kinds group_move and group_delete), executed as
 * the requester: their rights on the group and on the new parent checked again, the preview computed again under
 * the lock of the configuration and compared with the one approved, then written in the same transaction.
 */
export async function executeGroupTreeChange(x: ApprovalExecution): Promise<void> {
  const p = (x.payload ?? {}) as { kind?: string; groupId?: unknown; newParentId?: unknown; impact?: unknown };
  const groupId = Number(p.groupId);
  const id = (v: unknown): boolean => Number.isSafeInteger(v) && (v as number) > 0;
  const approved = approvedImpactOf(p);
  if (!approved || !id(groupId) || (p.kind === 'group_move' && p.newParentId !== null && !id(p.newParentId))
    || (p.kind !== 'group_move' && p.kind !== 'group_delete')) {
    refuse('Malformed request of a change of the tree of groups');
  }
  const change: GroupTreeChange = p.kind === 'group_move'
    ? { kind: 'group_move', groupId, newParentId: p.newParentId === null ? null : Number(p.newParentId) }
    : { kind: 'group_delete', groupId };
  const requester = await activeRequester(x.requesterId);
  if (!requester.isPlatformAdmin) {
    if (!(await permissionService.canWriteGroup(x.requesterId, groupId, false))) refuse('The requester no longer has write access to the group');
    if (change.kind === 'group_move' && change.newParentId !== null
      && !(await permissionService.canWriteGroup(x.requesterId, change.newParentId, false))) {
      refuse('The requester no longer has write access to the new parent group');
    }
  }
  const stale = (err: unknown): never => {
    const e = err as { statusCode?: number; message?: string };
    if (e.statusCode && e.statusCode < 500) refuse(`The change no longer applies: ${e.message}`);
    throw err;
  };
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  await withConfigurationLock(x.tenantId, async (trx) => {
    const now = await computeImpact(trx, x.tenantId, change).catch(stale);
    refuseUnlessAsApproved(approved!, now, 'request the change again');
    const done = await write(trx, change, { ctx, approvalId: x.approvalId, impact: now.impact }).catch(stale);
    if (!done) refuse('The group of this request no longer exists');
  }, { unbounded: true });
  if (change.kind === 'group_delete') groupNotificationService.removeGroup(groupId);
}
