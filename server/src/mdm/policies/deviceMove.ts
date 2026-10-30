import type { Request } from 'express';
import type { Knex } from 'knex';
import { POLICY_PUBLISH_ACTION, POLICY_PUBLISH_REQUEST_TYPE, type PolicyImpact } from '@obligarth/shared';
import { db } from '../../db';
import { userActor } from '../../db/context';
import { audit, type AuditWriteContext } from '../../audit';
import { approvalService, refuse, requireTenantCapability, type ApprovalExecution, type PendingApproval } from '../../services/approval.service';
import { permissionService } from '../../services/permission.service';
import { restrictionService } from '../../services/restriction.service';
import { moveToGroup } from '../registry/ownership';
import { recordDirectChange } from './changeLedger';
import { withConfigurationLock } from './configLock';
import { approvalImpact, computeImpact, describeKeys, impactSummary, type DeviceMoveChange, type ImpactResult } from './impact';
import { quoted } from './impactPure';
import { signImpactToken } from './impactToken';
import {
  approvedImpactOf, impactChanged, matrixLevel, refuseUnlessAsApproved, stepUp, strictest, visibleDevices,
  type Level, type RouteOutcome,
} from './publishGuard';

// =============================================================================
// Devices moved from a group to another (docs: modele-donnees-mdm §7.11,
// §7.12, S12; decision of the owners of 15/10/2026 on MDM-B5b-C7 and S12).
// What a device inherits follows the ancestry of its group: moving devices
// into a group that carries a policy changes their configuration as an
// assignment would. Assigning a policy to an empty group (a second factor),
// then moving thirty devices into it, went through without a preview nor a
// second approver. The move now goes the way of a change of the tree:
//   - a preview by the same pure function as the resolution, on the group the
//     devices would have (computeImpact, kind device_move);
//   - when it touches the configuration of a device: the restriction
//     mdm.policy_publish (a step-up at least), raised to a second approver
//     beyond the thresholds of DM23 (cumulative over the last hour) or when
//     the matrix says 'restricted';
//   - beyond one device: the restriction device.bulk_group_change of the
//     matrix too, the stricter of the two applies;
//   - decided and written under the lock of the tenant's configuration;
//   - a second approver: a request of the type mdm_policy_publish (kind
//     device_move), executed as the requester once approved, rights and
//     preview checked again (no longer change_group).
// A move of one device that touches no configuration keeps its previous rule:
// devices.manage and write access on the new group. In the tenant of the
// devices (the caller's context: asTargetTenant for one device).
// =============================================================================

/** Restriction of the matrix on a bulk change of the group of devices (modules/devices.ts). */
const BULK_GROUP_ACTION = 'device.bulk_group_change';

/** Beyond this many devices, the scope of the matrix is not evaluated device by device: the restriction applies. */
const SCOPE_CHECK_MAX = 100;

interface MoveLook extends ImpactResult { level: Level; actionKey: string }

async function look(q: Knex | Knex.Transaction, tenantId: number, change: DeviceMoveChange, visible: number[] | 'all'): Promise<MoveLook> {
  const result = await computeImpact(q, tenantId, change, { visibleDeviceIds: visible });
  const { impact } = result;
  const reasons = [...impact.approval.reasons];
  let publish: Level = 'none';
  if (impact.devicesTouched > 0) {
    publish = reasons.length ? 'restricted' : await matrixLevel(tenantId);
    if (publish === 'restricted' && !reasons.length) reasons.push('restriction');
  }
  let bulk: Level = 'none';
  if (change.deviceIds.length > 1) {
    bulk = await restrictionService.getLevelFor({
      tenantId, actionKey: BULK_GROUP_ACTION, deviceIds: change.deviceIds.length <= SCOPE_CHECK_MAX ? change.deviceIds : undefined,
    });
    if (bulk === 'restricted' && !reasons.includes('restriction')) reasons.push('restriction');
  }
  const level = strictest(publish, bulk);
  impact.approval = { required: level === 'restricted', reasons: level === 'restricted' ? reasons : [] };
  return { ...result, level, actionKey: publish !== 'none' && strictest(publish, bulk) === publish ? POLICY_PUBLISH_ACTION : BULK_GROUP_ACTION };
}

async function describe(q: Knex | Knex.Transaction, tenantId: number, change: DeviceMoveChange, impact: PolicyImpact): Promise<string> {
  const group = change.groupId === null ? null
    : await q('device_groups').where({ tenant_id: tenantId, id: change.groupId }).first('name') as { name: string } | undefined;
  const where = change.groupId === null ? 'out of any group' : `into the group ${quoted(group?.name ?? `#${change.groupId}`)}`;
  return `Move ${change.deviceIds.length} device(s) ${where} — ${impact.devicesTouched} touched, ${impact.artifacts.removals} removal(s) `
    + `(${impact.approval.reasons.join(', ')}); keys: ${describeKeys(impact)}`;
}

async function journal(tenantId: number, change: DeviceMoveChange, changed: number[], ctx: AuditWriteContext,
  o: { impact: PolicyImpact; approvalId?: number }): Promise<void> {
  const many = change.deviceIds.length > 1;
  await audit.append({
    tenantId, action: many ? 'device.bulk_group_changed' : 'device.group_changed',
    target: many ? { type: 'device', id: change.deviceIds.join(',').slice(0, 200) } : { type: 'device', id: String(change.deviceIds[0]), device: change.deviceIds[0] },
    approvalIds: o.approvalId ? [o.approvalId] : undefined,
    details: { count: change.deviceIds.length, changed: changed.length, toGroupId: change.groupId, impact: impactSummary(o.impact) },
  }, ctx);
}

/**
 * POST /api/mdm/devices/batch/group and POST /api/mdm/devices/:id/group, once the route has checked the devices
 * (of `tenantId`), the group, devices.manage and write access on the group. `dryRun`: the preview only.
 * Answers: 200 { data: { updated, changed } }; 202 { data: { outcome: 'awaiting_approval', approvalId, status,
 * impact } }; the challenge of the step-up otherwise.
 * `opts` (the approval of an AI agent's move, mcp/tools/writes.ts): `expectImpact` is checked under the lock of the
 * configuration against the impact about to apply (409 impactChanged when false), so that what moves is exactly what
 * the human approved; `descriptionPrefix` names who asked in the description of an approval it files.
 */
export async function changeDevicesGroup(req: Request, tenantId: number, deviceIds: number[], groupId: number | null,
  dryRun: boolean, opts: { expectImpact?: (impact: PolicyImpact) => boolean; descriptionPrefix?: string } = {}): Promise<RouteOutcome> {
  const change: DeviceMoveChange = { kind: 'device_move', deviceIds: [...new Set(deviceIds)].sort((a, b) => a - b), groupId };
  const userId = req.session.userId!;
  const visible = await visibleDevices(req);
  const token = (): string | null => (tenantId === req.tenantId ? signImpactToken(tenantId, userId, change) : null);
  const first = await look(db, tenantId, change, visible);
  if (dryRun) {
    first.impact.devicesToken = token();
    return { status: 200, body: { data: { outcome: 'preview', impact: first.impact } } };
  }
  let proven = false;
  if (first.level === 'sensitive') {
    const refused = await stepUp(req, first.actionKey);
    if (refused) return refused;
    proven = true;
  }
  const ctx = await audit.fromRequest(req, tenantId);
  const done = await withConfigurationLock(tenantId, async (trx): Promise<{ impact: PolicyImpact; approval: PendingApproval | null; changed: number[] }> => {
    const now = await look(trx, tenantId, change, visible);
    if (opts.expectImpact && !opts.expectImpact(now.impact)) impactChanged();
    if (now.level === 'restricted') {
      const approval = await approvalService.createInTx(trx, {
        tenantId, userId, requestType: POLICY_PUBLISH_REQUEST_TYPE,
        description: (opts.descriptionPrefix ?? '') + await describe(trx, tenantId, change, now.impact),
        payload: { kind: 'device_move', deviceIds: change.deviceIds, groupId: change.groupId, impact: approvalImpact(now) },
        auditCtx: ctx,
      });
      return { impact: now.impact, approval, changed: [] };
    }
    if (now.level === 'sensitive' && (!proven || now.actionKey !== first.actionKey)) impactChanged();
    const changed = await moveToGroup(trx, tenantId, change.deviceIds, change.groupId);
    await recordDirectChange(trx, tenantId, 'device_move', { deviceIds: now.touched.map((t) => t.deviceId), removalDeviceIds: now.removalDeviceIds });
    return { impact: now.impact, approval: null, changed };
  });
  done.impact.devicesToken = token();
  if (done.approval) {
    approvalService.announceCreated(done.approval);
    return {
      status: 202,
      body: { data: { outcome: 'awaiting_approval', status: 'pending_approval', approvalId: done.approval.id, impact: done.impact } },
    };
  }
  if (done.changed.length) await journal(tenantId, change, done.changed, ctx, { impact: done.impact });
  return { status: 200, body: { data: { updated: change.deviceIds.length, changed: done.changed.length, changedIds: done.changed } } };
}

/**
 * An approved move of devices (request type mdm_policy_publish, kind device_move), executed as the requester:
 * devices.manage and write access on the group checked again, the preview computed again under the lock of the
 * configuration and compared with the one approved, then written in the same transaction.
 */
export async function executeDeviceMove(x: ApprovalExecution): Promise<void> {
  const p = (x.payload ?? {}) as { deviceIds?: unknown; groupId?: unknown; impact?: unknown };
  const id = (v: unknown): boolean => Number.isSafeInteger(v) && (v as number) > 0;
  const approved = approvedImpactOf(p);
  const ids = Array.isArray(p.deviceIds) ? p.deviceIds : [];
  if (!approved || !ids.length || ids.length > 10_000 || !ids.every(id) || (p.groupId !== null && !id(p.groupId))) {
    refuse('Malformed request of a move of devices');
  }
  const change: DeviceMoveChange = { kind: 'device_move', deviceIds: ids as number[], groupId: p.groupId === null ? null : Number(p.groupId) };
  const r = await requireTenantCapability(x.requesterId, x.tenantId, 'devices.manage');
  if (!r.isPlatformAdmin && change.groupId !== null && !(await permissionService.canWriteGroup(x.requesterId, change.groupId, false))) {
    refuse('The requester no longer has write access to the group');
  }
  const stale = (err: unknown): never => {
    const e = err as { statusCode?: number; message?: string };
    if (e.statusCode && e.statusCode < 500) refuse(`The move no longer applies: ${e.message}`);
    throw err;
  };
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  const done = await withConfigurationLock(x.tenantId, async (trx) => {
    const present = (await trx('devices').where({ tenant_id: x.tenantId }).whereIn('id', change.deviceIds).pluck('id') as number[]).map(Number);
    if (!present.length) refuse('None of the devices of this request is still in the tenant');
    const now = await computeImpact(trx, x.tenantId, change, { cumulative: false }).catch(stale);
    refuseUnlessAsApproved(approved!, now, 'request the move again');
    const changed = await moveToGroup(trx, x.tenantId, change.deviceIds, change.groupId).catch(stale);
    return { changed, impact: now.impact };
  }, { unbounded: true });
  if (done.changed.length) await journal(x.tenantId, change, done.changed, ctx, { impact: done.impact, approvalId: x.approvalId });
}
