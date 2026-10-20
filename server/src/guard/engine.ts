// The request of a guarded action (docs: audit-durci §10.3): the only way to
// a destructive action. In order: form, targets, channel of the targets
// (PONT-R-RV4), freeze, cooldown, ownership,
// whole fleet (and that of the action's channel, PONT-R-RV3), bulk or single
// (with the burst requalification), hourly cap (and its channel's),
// typed confirmation, level (matrix and floors), step-up, then one
// transaction in the target tenant's context: the pending action, its
// approval request or its delayed job, and the critical entries written last
// (P1: no action without its entry). Refusals of the steps 3 to 9 are
// journaled (guard.action_refused, standard) and feed the anomalies (§10.9).
import { randomUUID } from 'node:crypto';
import type { Request } from 'express';
import {
  MASTER_TENANT_ID, type GuardApprovalPayload, type GuardOutcome, type GuardRequestInput, type GuardSelection,
} from '@obligarth/shared';
import { audit, type AuditEntryInput, type AuditWriteContext } from '../audit';
import { db } from '../db';
import { asTargetTenant } from '../middleware/dbContext';
import { AppError } from '../middleware/errorHandler';
import { approvalService, type PendingApproval } from '../services/approval.service';
import { restrictionService } from '../services/restriction.service';
import { hasGlobalView } from '../services/deviceScope.service';
import { deviceList } from '../services/approvalDescribe';
import { jobIdFor } from '../jobs';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';
import { actorRecentTenants, alertA3 } from './anomalies';
import { capExceeded, quotaOf, fleetSize, ownChannelOf } from './cap';
import { guardedActionDef, ownershipOf } from './catalog';
import { executeJob, wakeExecutor } from './jobs';
import { guardMetrics } from './metrics';
import { alertTenants, notifyAction } from './notify';
import { cooldownUntil, personFacts, type PersonFacts } from './people';
import {
  checkReason, classify, confirmationMatches, expectedConfirmation, isWholeFleet, requestLevel,
  stricter, type MatrixLevel,
} from './policy';
import { recordRefusal } from './refusals';
import { parseSelection, resolveTargets, targetTenantOf, targetsWithoutRights, type ResolvedTargets } from './selection';
import { readSettings } from './settings';
import { findAction, toDto } from './store';
import type { GuardedActionDef } from './types';
import { config } from '../config';

/** The step-up of a request was not satisfied: the route sends `outcome`. */
export class GuardStepUpError extends Error {
  constructor(readonly outcome: { status: number; body: Record<string, unknown>; headers?: Record<string, string> }) {
    super('step-up required');
    this.name = 'GuardStepUpError';
  }
}

/** Families whose requests in several tenants within an hour raise A3. */
export const DESTRUCTIVE_FAMILIES = ['device_destruction', 'device_records'];

const BURST_WINDOW_SQL = "interval '15 minutes'";

/** What the console needs before sending (preview) and what the request uses. */
interface Assessment {
  def: GuardedActionDef<any>;
  params: Record<string, unknown>;
  reason: string;
  ticket: string | null;
  targets: ResolvedTargets;
  selection: GuardSelection;
  requester: PersonFacts;
  bulk: boolean;
  requalified: boolean;
  level: 'sensitive' | 'restricted';
  delaySeconds: number;
  expectedConfirmation: string | null;
}

const isUser = (req: Request): number => {
  const id = Number(req.session?.userId);
  if (!Number.isSafeInteger(id) || id <= 0) throw new AppError(401, 'Authentication required');
  return id;
};

/** Steps 1 and the shape of 2: definition, parameters, reason, ticket, selection. */
function form(input: Partial<GuardRequestInput> | undefined, o: { forPreview?: boolean } = {}): {
  def: GuardedActionDef<any>; params: Record<string, unknown>; reason: string; ticket: string | null; selection: GuardSelection;
} {
  const key = typeof input?.actionKey === 'string' ? input.actionKey : '';
  const def = guardedActionDef(key);
  if (!def) throw new AppError(400, 'Unknown guarded action', 'unknownGuardedAction');
  const parsed = (def.requestParamsSchema ?? def.paramsSchema).safeParse(input?.params ?? {});
  if (!parsed.success) throw new AppError(400, 'Invalid parameters for this action', 'invalidParams');
  let reason = '';
  let ticket: string | null = null;
  if (!o.forPreview) {
    const r = checkReason(input?.reason, input?.ticket);
    if (!r.ok) {
      throw new AppError(400, r.code === 'reasonRequired'
        ? 'A reason of 5 to 500 characters is required' : 'A ticket number has 64 characters at most', r.code);
    }
    reason = r.reason;
    ticket = r.ticket;
  }
  return { def, params: parsed.data as Record<string, unknown>, reason, ticket, selection: parseSelection(input?.selection) };
}

/** Single requests of the same family by the same requester in the last 15
 *  minutes (states other than refused and cancelled). */
async function priorSingles(tenantId: number, requesterId: number, family: string): Promise<number> {
  const res = await db.raw(
    `SELECT count(*)::integer AS n FROM pending_actions
      WHERE tenant_id = ? AND requested_by = ? AND family = ?
        AND state NOT IN ('refused', 'cancelled')
        AND created_at > now() - ${BURST_WINDOW_SQL}
        AND COALESCE(selection->>'mode', '') = 'single'`,
    [tenantId, requesterId, family],
  ) as { rows: Array<{ n: number }> };
  return Number(res.rows[0]?.n ?? 0);
}

/** The level of the tenant's matrix (with its single floor); from the global
 *  view, the stricter of the target tenant's and the master tenant's. */
async function matrixLevel(req: Request, def: GuardedActionDef<any>, tenantId: number, deviceIds: number[]): Promise<MatrixLevel> {
  let level = await restrictionService.getLevelFor({ tenantId, actionKey: def.key, deviceIds }) as MatrixLevel;
  const own = Number(req.tenantId);
  if (own !== tenantId && Number.isSafeInteger(own) && own > 0) {
    const { asTenant, userActor } = await import('../db/context');
    const other = await asTenant(own, userActor(isUser(req)), () => restrictionService.getLevelFor({ tenantId: own, actionKey: def.key, deviceIds }));
    level = stricter(level, other as MatrixLevel);
  }
  return level;
}

/**
 * Steps 2 to 10, in the target tenant's context. `refuse` journals and
 * throws the refusals of the steps 3 to 9 (a preview only throws).
 */
async function assess(req: Request, f: ReturnType<typeof form>, tenantId: number, o: { preview: boolean; confirm?: unknown }): Promise<Assessment> {
  const { def, params, reason, ticket, selection } = f;
  const requesterId = isUser(req);
  const requester = await personFacts(requesterId, tenantId);
  if (!requester.exists || !requester.active) throw new AppError(401, 'Authentication required');
  if (def.tenantCapability && !requester.platformAdmin) {
    const { permissionService } = await import('../services/permission.service');
    if (!(await permissionService.userHasTenantCapability(requesterId, tenantId, def.tenantCapability))) {
      throw new AppError(403, 'Insufficient permissions');
    }
  }
  const targets = await resolveTargets(tenantId, selection);
  const lacking = await targetsWithoutRights(def, requesterId, requester.platformAdmin, tenantId, targets.deviceIds);
  if (lacking.length) throw new AppError(404, 'Some targets are outside your scope', 'targetsOutsideScope');
  const count = targets.deviceIds.length;

  const refuse = async (status: number, code: string, message: string, details?: Record<string, unknown>): Promise<never> => {
    if (!o.preview) await recordRefusal(req, { tenantId, def, code, deviceIds: targets.deviceIds, reason, ticket, requester, details });
    throw new AppError(status, message, code, details);
  };

  // 2b. The channel of the targets (decision of the owners of 20/10/2026, PONT-R-RV4): an action of a channel never
  //     targets a device of another one; refused at once, nothing scheduled nor counted in the hourly cap.
  if (def.channels && count) {
    const rows = await db('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [targets.deviceIds])
      .select('id', 'management_channel') as Array<{ id: number; management_channel: string }>;
    const ok = new Set(rows.filter((r) => (def.channels as readonly string[]).includes(r.management_channel)).map((r) => Number(r.id)));
    const other = targets.deviceIds.filter((id) => !ok.has(id));
    if (other.length) {
      await refuse(422, 'channelMismatch', 'This action does not apply to the management channel of some targets',
        { channels: [...def.channels], deviceIds: other.slice(0, 200) });
    }
  }

  // 3. Emergency freeze.
  const settings = await readSettings(tenantId);
  if (settings.frozen_at) await refuse(423, 'tenantFrozen', 'The tenant is frozen: no guarded action until it is unfrozen');
  // 4. Cooldown of a new administrator (72 h).
  const until = await cooldownUntil(requesterId, tenantId, ['platform_admin', 'tenant_admin']);
  if (until && until.getTime() > Date.now()) {
    await refuse(403, 'privilegeCooldown', 'Your administrator rights are too recent for a destructive action', { until: until.toISOString() });
  }
  // 5. Ownership refused by the action (lot B: devices.ownership); unknown
  //    ownership counts as refused (fail closed).
  if (def.refuseOwnership.length) {
    const provider = ownershipOf();
    const owned = provider ? await provider(tenantId, targets.deviceIds) : new Map();
    const refused = targets.deviceIds.filter((id) => {
      const own = owned.get(id);
      return !own || def.refuseOwnership.includes(own);
    });
    if (refused.length) {
      await refuse(422, 'personalDeviceForbidden', 'This action is refused on personal devices', { deviceIds: refused.slice(0, 200) });
    }
  }
  // 6. The whole fleet.
  if (def.forbidWholeFleet && isWholeFleet(selection, count, await fleetSize(tenantId))) {
    await refuse(422, 'wholeFleetForbidden', 'This action is refused on the whole fleet');
  }
  //    An action of one channel: also the whole fleet of that channel (PONT-R-RV3; its targets are all of it, 2b).
  const channel = ownChannelOf(def);
  if (def.forbidWholeFleet && channel && isWholeFleet(selection, count, await fleetSize(tenantId, channel))) {
    await refuse(422, 'wholeFleetForbidden', 'This action is refused on the whole fleet of its channel', { channel });
  }
  // 7. Bulk or single, with the burst requalification.
  const { bulk, requalified } = classify(count, selection, await priorSingles(tenantId, requesterId, def.family), def.bulkThreshold);
  // 8. Hourly cap.
  //    An action of one channel: also the cap of that channel (PONT-R-RV3).
  const over = await capExceeded(def, tenantId, count);
  if (over) {
    const { quota } = over;
    await refuse(409, 'hourlyCapExceeded', 'The hourly cap of destructive actions would be exceeded',
      { cap: quota.cap, used: quota.used, remaining: quota.remaining, resetsAt: quota.resetsAt, ...(over.channel ? { channel: over.channel } : {}) });
  }
  // 9. Typed confirmation.
  const expected = def.confirmation === 'typed' ? expectedConfirmation(bulk, count, targets.singleName) : null;
  if (expected !== null && !o.preview && !confirmationMatches(o.confirm, expected)) {
    await refuse(400, 'confirmationMismatch', 'The confirmation does not match',
      { expect: !bulk && count === 1 && targets.singleName ? 'name' : 'count' });
  }
  // 10. Level: the matrix (floored) and the floor of the request's kind.
  const level = requestLevel(await matrixLevel(req, def, tenantId, targets.deviceIds), def.singleFloor, bulk);
  return {
    def, params, reason, ticket, targets, selection, requester, bulk, requalified, level,
    delaySeconds: bulk ? def.bulkDelaySeconds : def.singleDelaySeconds,
    expectedConfirmation: expected,
  };
}

/** The entries of a request: guard.action_requested (its targets), then
 *  guard.action_scheduled when it is scheduled. */
function requestEntries(a: Assessment, uuid: string, o: { scheduled: boolean; executeAfter: Date | null; approvalId: number | null }): AuditEntryInput[] {
  const tenantId = a.targets.tenantId;
  const onBehalfOf = a.requester.side === 'msp' && tenantId !== MASTER_TENANT_ID ? tenantId : undefined;
  const details = {
    actionKey: a.def.key, family: a.def.family, level: a.level, delaySeconds: a.delaySeconds, params: a.params,
    bulk: a.bulk, ...(a.requalified ? { requalified: true } : {}),
  };
  const common = {
    tenantId, onBehalfOf, reason: a.reason, ticket: a.ticket ?? undefined, links: { action: uuid },
    ...(a.targets.deviceIds.length === 1 && !a.bulk
      ? { target: { type: 'device', id: String(a.targets.deviceIds[0]), device: a.targets.deviceIds[0] } }
      : { targets: { deviceIds: a.targets.deviceIds, selection: { groups: a.targets.selection.groupIds, tenant: a.targets.selection.tenant || undefined } } }),
  };
  const out: AuditEntryInput[] = [{
    ...common, action: 'guard.action_requested', outcome: 'requested', details,
    ...(o.approvalId ? { approvalIds: [o.approvalId] } : {}),
  }];
  if (o.scheduled) {
    out.push({
      tenantId, onBehalfOf, action: 'guard.action_scheduled', outcome: 'scheduled', links: { action: uuid },
      details: { ...details, executeAfter: o.executeAfter?.toISOString() },
    });
  }
  return out;
}

/** The description a reviewer approves (server-built, English). */
async function describe(a: Assessment): Promise<string> {
  const list = await deviceList(a.targets.tenantId, a.targets.deviceIds);
  return `${a.def.label}: ${list} — reason: ${a.reason}${a.ticket ? ` (ticket ${a.ticket})` : ''}`;
}

/** The approval validity of the guard's requests (GUARD_APPROVAL_TTL_MINUTES). */
export const approvalTtlMinutes = (): number => config.guard.approvalTtlMinutes;

/**
 * guard.request: the request of a guarded action, from POST
 * /api/guard/actions or another route (device deletion). Returns the
 * outcome (202), or throws AppError (400, 403, 404, 409, 422, 423),
 * GuardStepUpError (the 401 of the step-up) or AuditUnavailableError (503:
 * nothing was recorded).
 */
export async function request(req: Request, input: Partial<GuardRequestInput>): Promise<GuardOutcome> {
  const f = form(input);
  const tenantId = await targetTenantOf(req, f.selection);
  return asTargetTenant(req, tenantId, () => requestInTenant(req, f, tenantId, input?.confirm));
}

async function requestInTenant(req: Request, f: ReturnType<typeof form>, tenantId: number, confirm: unknown): Promise<GuardOutcome> {
  const a = await assess(req, f, tenantId, { preview: false, confirm });
  const restricted = a.level === 'restricted';
  // The approver's side (D24) of a restricted request: refused, and
  // journaled like the refusals of the steps 3 to 9, while the tenant has no
  // client approver and the fallback is held (AUD-A7-R4).
  let approver: { side: GuardApprovalPayload['requiredSide']; fallback: boolean } = { side: 'msp', fallback: false };
  if (restricted) {
    const { requiredSideFor, refuseHeldFallback } = await import('./approvals');
    const required = await requiredSideFor(a.requester, tenantId);
    if (required.heldUntil) {
      await recordRefusal(req, {
        tenantId, def: a.def, code: 'approverFallbackHeld', deviceIds: a.targets.deviceIds, reason: a.reason, ticket: a.ticket,
        requester: a.requester, details: { until: required.heldUntil.toISOString() },
      });
      refuseHeldFallback(required);
    }
    approver = { side: required.side, fallback: required.fallback };
  }
  // 11. Step-up at the 'sensitive' level (no trusted-IP shortcut for a strict floor).
  if (a.level === 'sensitive') {
    const { checkSecondFactor } = await import('../services/deviceKey/stepUpProof');
    const outcome = await checkSecondFactor(req, {
      actionKey: a.def.key, deviceIds: a.targets.deviceIds, allowTrustedIp: !a.def.singleStrictStepUp, allowDevice: true,
    });
    if (!outcome.ok) throw new GuardStepUpError(outcome);
    req.stepUpVia = outcome.via;
  }
  const ctx = await audit.fromRequest(req, tenantId);
  const uuid = randomUUID();
  const requesterId = a.requester.userId;
  const description = restricted ? await describe(a) : '';
  const selection = {
    ...a.targets.selection, mode: a.bulk && !a.requalified ? 'bulk' : 'single', ...(a.requalified ? { requalified: true } : {}),
    ...(hasGlobalView(req) ? { fromGlobalView: true } : {}),
  };

  // 12. One transaction: the action, its approval or its job, its entries last.
  const { approval, executeAfter } = await db.transaction(async (trx): Promise<{ approval: PendingApproval | null; executeAfter: Date | null }> => {
    let approval: PendingApproval | null = null;
    let executeAfter: Date | null = null;
    // A secret typed in the request is sealed first: never stored nor journaled in clear (android-amapi §22.9).
    if (a.def.prepareParams) a.params = await a.def.prepareParams(trx, tenantId, a.params, requesterId);
    const base = {
      uuid, tenant_id: tenantId, action_key: a.def.key, family: a.def.family, requested_by: requesterId,
      requester_side: a.requester.side, approver_fallback: approver.fallback, selection: JSON.stringify(selection),
      target_device_ids: a.targets.deviceIds, target_count: a.targets.deviceIds.length, params: JSON.stringify(a.params),
      reason: a.reason, ticket: a.ticket, delay_seconds: a.delaySeconds,
    };
    if (restricted) {
      await trx('pending_actions').insert({ ...base, state: 'awaiting_approval' });
      const payload: GuardApprovalPayload = {
        action: 'guarded_action', actionUuid: uuid, actionKey: a.def.key, family: a.def.family,
        targetCount: a.targets.deviceIds.length, requiredSide: approver.side, approverFallback: approver.fallback,
        delaySeconds: a.delaySeconds, bulk: a.bulk, reason: a.reason, ...(a.ticket ? { ticket: a.ticket } : {}),
      };
      approval = await approvalService.createInTx(trx, {
        tenantId, userId: requesterId, requestType: 'guarded_action', description, payload, auditCtx: ctx,
      });
      await trx('pending_actions').where({ uuid }).update({ approval_id: approval.id });
    } else {
      executeAfter = new Date(Date.now() + a.delaySeconds * 1000);
      const jobId = jobIdFor('actions.execute-delayed', uuid);
      await trx('pending_actions').insert({ ...base, state: 'scheduled', execute_after: executeAfter, job_id: jobId });
      await executeJob().sendInTx(trx, { tenantId, actionUuid: uuid }, { id: jobId, startAfter: executeAfter, tenantId });
    }
    // P1, last: the head of the chain is held only until the commit.
    await audit.appendManyInTx(trx, requestEntries(a, uuid, {
      scheduled: !restricted, executeAfter, approvalId: approval ? approval.id : null,
    }), ctx);
    return { approval, executeAfter };
  });

  // 13. After the commit: fallback, notifications, events, anomaly A3.
  guardMetrics.inc('obligarth_guard_requests_total', { action: a.def.key, outcome: restricted ? 'awaiting_approval' : 'scheduled' });
  if (approval) approvalService.announceCreated(approval);
  if (approver.fallback) await fallbackNotice(tenantId, uuid, ctx);
  const row = await findAction(uuid, { tenantId });
  if (row) await notifyAction(await toDto(row));
  if (!restricted && a.delaySeconds === 0) wakeExecutor();
  await checkA3(a);
  if (approval) {
    return {
      state: 'awaiting_approval', actionUuid: uuid, approvalId: approval.id, approverSide: approver.side,
      approverFallback: approver.fallback, expiresAt: new Date(approval.expiresAt).toISOString(),
    };
  }
  return { state: 'scheduled', actionUuid: uuid, executeAfter: (executeAfter ?? new Date()).toISOString(), delaySeconds: a.delaySeconds };
}

/** The fallback of D24 (§10.4 point 4): entry guard.approver_fallback and a
 *  warning to the tenant (the client keeps its trace). */
export async function fallbackNotice(tenantId: number, uuid: string, ctx: AuditWriteContext): Promise<void> {
  await audit.append({
    tenantId, action: 'guard.approver_fallback', outcome: 'success', links: { action: uuid },
    details: { reason: 'no_client_approver' },
  }, ctx);
  await alertTenants([tenantId], {
    severity: 'warning',
    title: 'Approval by the MSP instead of a client approver',
    message: 'No client approver is designated: a second administrator of the MSP approves this action (fallback).',
    stableKey: `guard:${uuid}:fallback`,
    navigateTo: `/admin/security?tab=guard&action=${uuid}`,
  });
}

/** The same fallback for the guard's other requests (unfreeze, settings,
 *  designation of an approver): the entry names the approval request, the
 *  client keeps its trace and gets the warning. */
export async function requestFallbackNotice(tenantId: number, approval: Pick<PendingApproval, 'id' | 'requestType'>,
  ctx: AuditWriteContext): Promise<void> {
  await audit.append({
    tenantId, action: 'guard.approver_fallback', outcome: 'success', approvalIds: [approval.id],
    details: { reason: 'no_client_approver', requestType: approval.requestType },
  }, ctx);
  await alertTenants([tenantId], {
    severity: 'warning',
    title: 'Approval by the MSP instead of a client approver',
    message: 'No client approver is designated: a second administrator of the MSP approves this request (fallback).',
    stableKey: `guard:fallback:${approval.id}`,
    navigateTo: '/admin/security?tab=approvals',
  });
}

/** A3 (§10.9): the requester's destructive requests in 2 tenants or more
 *  within an hour. Never throws. */
async function checkA3(a: Assessment): Promise<void> {
  if (!DESTRUCTIVE_FAMILIES.includes(a.def.family)) return;
  try {
    const n = await actorRecentTenants(DESTRUCTIVE_FAMILIES);
    if (n >= 2) {
      guardMetrics.inc('obligarth_guard_anomalies_total', { rule: 'A3' });
      await audit.append({
        tenantId: MASTER_TENANT_ID, action: 'guard.anomaly_detected', outcome: 'success',
        details: { rule: 'A3', userId: a.requester.userId, tenants: n },
      }, await audit.fromDbActor({ type: 'job', name: 'guard.anomalies' }, MASTER_TENANT_ID));
      await alertA3(a.requester.userId, n);
    }
  } catch (err) {
    logger.warn({ err: safeErr(err) }, 'guard: anomaly A3 not checked');
  }
}

/** What the console shows before sending (no side effect, nothing
 *  journaled): level, delay, bulk, the expected confirmation, the quota. */
export async function preview(req: Request, input: Partial<GuardRequestInput>): Promise<Record<string, unknown>> {
  const f = form(input, { forPreview: true });
  const tenantId = await targetTenantOf(req, f.selection);
  return asTargetTenant(req, tenantId, async () => {
    const a = await assess(req, f, tenantId, { preview: true });
    const quota = a.def.hourlyCap ? await quotaOf(tenantId) : null;
    const ownChannel = a.def.hourlyCap ? ownChannelOf(a.def) : null;
    const channelQuota = ownChannel ? { channel: ownChannel, ...(await quotaOf(tenantId, { channel: ownChannel })) } : null;
    // The approver's side of a restricted request; held fallback: refused
    // here too (AUD-A7-R4), nothing journaled.
    let approver: { approverSide: string; approverFallback: boolean } | null = null;
    if (a.level === 'restricted') {
      const { requiredSideFor, refuseHeldFallback } = await import('./approvals');
      const required = await requiredSideFor(a.requester, tenantId);
      refuseHeldFallback(required);
      approver = { approverSide: required.side, approverFallback: required.fallback };
    }
    return {
      tenantId,
      actionKey: a.def.key,
      targetCount: a.targets.deviceIds.length,
      bulk: a.bulk,
      requalified: a.requalified,
      level: a.level,
      delaySeconds: a.delaySeconds,
      confirmation: a.expectedConfirmation === null ? 'none'
        : (!a.bulk && a.targets.deviceIds.length === 1 && a.targets.singleName ? 'name' : 'count'),
      expectedConfirmation: a.expectedConfirmation,
      quota,
      ...(channelQuota ? { channelQuota } : {}),
      ...(approver ?? {}),
    };
  });
}
