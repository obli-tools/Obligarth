// The approvals of the guard engine (docs: audit-durci §10.4, D24): the
// request types it files in the inherited approval engine, their
// examination policy, their executors (run as the requester, in the tenant's
// context) and what closes an action when its request is denied, cancelled
// or expired.
//   guarded_action            a guarded action at the 'restricted' level
//   guard_resume              the resumption of a paused action (full delay)
//   guard_unfreeze            the end of an emergency freeze
//   guard_settings_change     hourly cap, side of the approver of mass actions
//   guard_approver_designate  a designated approver (client or MSP side)
// Policy: the requester never reviews; an active account outside its 72-hour
// cooldown; the side the request requires (client by default for a request
// of the MSP, MSP when marked as a fallback, either side for a client's
// request); then a strict step-up of the reviewer.
import type { Request } from 'express';
import {
  MASTER_TENANT_ID, type GuardApprovalPayload, type GuardApproverSide, type GuardSettingsInput, type GuardSide,
} from '@obligarth/shared';
import { z } from 'zod';
import { audit, type AuditWriteContext } from '../audit';
import { db } from '../db';
import { userActor } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import {
  approvalService, refuse, registerApprovalRequestType, type ApprovalClosed, type ApprovalExecution,
  type ApprovalReviewCheck, type PendingApproval,
} from '../services/approval.service';
import { jobIdFor } from '../jobs';
import { quotaOf } from './cap';
import { guardedActionDef } from './catalog';
import { approvalTtlMinutes } from './engine';
import { actionEntry } from './executor';
import { unfreezeTenant } from './freeze';
import { executeJob } from './jobs';
import { notifyAction } from './notify';
import {
  activeClientApprovers, cooldownUntil, designationsOf, personFacts, reviewerFacts, type PersonFacts,
} from './people';
import { capAllows, requiredApproverSide, reviewerRefusal } from './policy';
import { recordRefusal } from './refusals';
import { targetsWithoutRights } from './selection';
import { readSettings } from './settings';
import { findAction, findActionByApproval, toDto } from './store';

const REVIEWER_MESSAGES: Record<string, string> = {
  selfApproval: 'The requester cannot review this request',
  reviewerInactive: 'Your account cannot review this request',
  privilegeCooldown: 'Your approver or administrator rights are too recent to review this request',
  approverSideRequired: 'This request needs an approver of the other side (client approver by default)',
};

/** The guard's examination policy (§10.4 points 1 to 3; the step-up is the
 *  type's reviewerStepUp). */
export async function guardReviewerPolicy(x: ApprovalReviewCheck): Promise<void> {
  const p = (x.approval.payload ?? {}) as GuardApprovalPayload;
  const required: GuardApproverSide = p.requiredSide === 'client' || p.requiredSide === 'msp' ? p.requiredSide : 'any';
  const requesterIds = [x.approval.requestedBy];
  if (typeof p.originalRequesterId === 'number') requesterIds.push(p.originalRequesterId);
  // The account a designation names never reviews it (no self-elevation).
  if (p.action === 'guard_approver_designate' && typeof p.userId === 'number') requesterIds.push(p.userId);
  const tenantId = x.approval.tenantId;
  // No approval of a guarded action while the tenant is frozen (§10.7); a
  // refusal is protective and stays possible.
  if (x.decision === 'approve' && (p.action === 'guarded_action' || p.action === 'guard_resume')
    && (await readSettings(tenantId)).frozen_at) {
    throw Object.assign(new Error('The tenant is frozen: no guarded action until it is unfrozen'), { status: 423, code: 'tenantFrozen' });
  }
  const facts = await reviewerFacts(x.reviewerId, tenantId);
  const refusal = reviewerRefusal(required, requesterIds, facts);
  if (refusal) {
    throw Object.assign(new Error(REVIEWER_MESSAGES[refusal] ?? 'Not allowed to review this request'), {
      status: 403, code: refusal,
      ...(refusal === 'privilegeCooldown' && facts.cooldownUntil ? { details: { until: facts.cooldownUntil.toISOString() } } : {}),
    });
  }
}

/** The side of the account that approved (approver_side of the action): a
 *  platform administrator is always on the MSP side (§9.1). */
async function approverSideOf(reviewerId: number | undefined, tenantId: number): Promise<GuardSide | null> {
  if (!reviewerId) return null;
  const f = await personFacts(reviewerId, tenantId);
  const d = await designationsOf(reviewerId, tenantId);
  return d.client && f.audience === 'client' && !f.platformAdmin ? 'client' : 'msp';
}

/** The required side of a request filed by `requester` in the tenant. */
export async function requiredSideFor(requester: PersonFacts, tenantId: number): Promise<{ side: GuardApproverSide; fallback: boolean }> {
  const settings = await readSettings(tenantId);
  return requiredApproverSide(requester.side, settings.mass_approver_side, await activeClientApprovers(tenantId));
}

/** May this account act on the tenant's freeze, cancellations and
 *  resumptions: a platform administrator, a tenant administrator, a
 *  designated approver (either side). */
export async function mayOperate(f: PersonFacts, tenantId: number): Promise<boolean> {
  if (!f.exists || !f.active) return false;
  if (f.platformAdmin || f.tenantRole === 'admin') return true;
  const d = await designationsOf(f.userId, tenantId);
  return d.client || d.msp;
}

// ── Closing an action whose request was denied, cancelled or expired ───────

const CLOSED_ENTRY = { refused: 'guard.action_refused', cancelled: 'guard.action_cancelled', expired: 'guard.action_expired' } as const;

/** An action still awaiting approval closes with its request (protective:
 *  never blocked by the journal). */
export async function closeAwaiting(tenantId: number, uuid: string, state: 'refused' | 'cancelled' | 'expired',
  byUserId: number | null, ctx: AuditWriteContext, reason?: string): Promise<boolean> {
  const now = new Date();
  const n = await db('pending_actions').where({ tenant_id: tenantId, uuid, state: 'awaiting_approval' }).update({
    state, updated_at: now,
    ...(state === 'cancelled' ? { cancelled_at: now, cancelled_by: byUserId, cancel_reason: reason?.slice(0, 500) ?? null } : {}),
    ...(state === 'refused' ? { result: JSON.stringify({ done: 0, failed: 0, skipped: 0, code: 'approvalDenied' }) } : {}),
  });
  if (!n) return false;
  const row = await findAction(uuid, { tenantId });
  if (!row) return true;
  await audit.append(actionEntry(row, CLOSED_ENTRY[state], {
    outcome: state === 'refused' ? 'denied' : state === 'cancelled' ? 'cancelled' : 'success',
    details: { code: state === 'refused' ? 'approvalDenied' : state === 'cancelled' ? 'cancelled' : 'approvalExpired' },
    ...(reason ? { reason } : {}),
  }), ctx);
  await notifyAction(await toDto(row));
  return true;
}

async function onGuardedClosed(x: ApprovalClosed): Promise<void> {
  const uuid = (x.payload as GuardApprovalPayload)?.actionUuid;
  if (typeof uuid !== 'string') return;
  const ctx = x.byUserId ? await audit.fromDbActor(userActor(x.byUserId), x.tenantId)
    : audit.fromJob({ name: 'core.approvals.expire', requestId: 'job' });
  await closeAwaiting(x.tenantId, uuid, x.status === 'denied' ? 'refused' : x.status, x.byUserId, ctx);
}

// ── Executors (as the requester, in the tenant's context) ──────────────────

/** Re-checks at approval or resumption (§10.4): freeze, cooldown of the
 *  requester, rights on the targets, hourly cap. A failure closes the action
 *  'refused' and refuses the execution (the request stays 'approved' with
 *  its execution_error). */
async function recheck(row: NonNullable<Awaited<ReturnType<typeof findAction>>>, approvalIds: number[], ctx: AuditWriteContext): Promise<void> {
  const def = guardedActionDef(row.action_key);
  const fail = async (code: string, message: string, details?: Record<string, unknown>): Promise<never> => {
    await db('pending_actions').where({ id: row.id, state: row.state }).update({
      state: 'refused', result: JSON.stringify({ done: 0, failed: 0, skipped: 0, code }), updated_at: new Date(),
    });
    if (def) {
      await recordRefusal(null, {
        tenantId: row.tenant_id, def, code, deviceIds: row.target_device_ids, reason: row.reason, ticket: row.ticket,
        details: { ...(details ?? {}), atApproval: true }, actionUuid: row.uuid, approvalIds,
      }, ctx);
    }
    const fresh = await findAction(row.uuid, { tenantId: row.tenant_id });
    if (fresh) await notifyAction(await toDto(fresh), { code });
    refuse(message);
  };
  if (!def) await fail('unknownAction', 'This guarded action is no longer known to the server — nothing was executed');
  if ((await readSettings(row.tenant_id)).frozen_at) await fail('tenantFrozen', 'The tenant is frozen — nothing was executed');
  const requester = await personFacts(row.requested_by, row.tenant_id);
  if (!requester.exists || !requester.active) await fail('requesterInactive', 'The requester is no longer an active user');
  const until = await cooldownUntil(row.requested_by, row.tenant_id, ['platform_admin', 'tenant_admin']);
  if (until && until.getTime() > Date.now()) {
    await fail('privilegeCooldown', 'The requester\'s administrator rights are too recent', { until: until.toISOString() });
  }
  const lacking = await targetsWithoutRights(def!, row.requested_by, requester.platformAdmin, row.tenant_id, row.target_device_ids);
  if (lacking.length) await fail('targetsOutsideScope', 'The requester no longer has rights on every target — nothing was executed', { lacking: lacking.length });
  if (def!.hourlyCap) {
    const quota = await quotaOf(row.tenant_id, { excludeUuid: row.uuid });
    if (!capAllows(quota.cap, quota.used, row.target_count)) {
      await fail('hourlyCapExceeded', 'The hourly cap of destructive actions would be exceeded — nothing was executed',
        { cap: quota.cap, used: quota.used, remaining: quota.remaining, resetsAt: quota.resetsAt });
    }
  }
}

/** Schedules an approved (or resumed) action: full delay, its job, its
 *  entry (P1, last). */
async function schedule(row: NonNullable<Awaited<ReturnType<typeof findAction>>>, x: ApprovalExecution, entry: 'guard.action_scheduled' | 'guard.action_resumed',
  jobKey: string): Promise<void> {
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  const approverSide = await approverSideOf(x.reviewerId, x.tenantId);
  const executeAfter = new Date(Date.now() + row.delay_seconds * 1000);
  const jobId = jobIdFor('actions.execute-delayed', jobKey);
  const approvalIds = x.approvalId ? [x.approvalId] : [];
  await db.transaction(async (trx) => {
    const n = await trx('pending_actions').where({ id: row.id, state: row.state }).update({
      state: 'scheduled', execute_after: executeAfter, job_id: jobId, paused_at: null, updated_at: new Date(),
      ...(entry === 'guard.action_scheduled' ? { approved_by: x.reviewerId ?? null, approver_side: approverSide } : {}),
    });
    if (!n) refuse('The action changed meanwhile — nothing was executed');
    await executeJob().sendInTx(trx, { tenantId: x.tenantId, actionUuid: row.uuid }, { id: jobId, startAfter: executeAfter, tenantId: x.tenantId });
    await audit.appendInTx(trx, actionEntry(row, entry, {
      outcome: 'scheduled', approvalIds,
      details: { executeAfter: executeAfter.toISOString(), delaySeconds: row.delay_seconds, ...(approverSide ? { approverSide } : {}) },
    }), ctx);
  });
  const fresh = await findAction(row.uuid, { tenantId: row.tenant_id });
  if (fresh) await notifyAction(await toDto(fresh));
}

async function executeGuardedAction(x: ApprovalExecution): Promise<void> {
  const row = await findActionByApproval(Number(x.approvalId));
  if (!row || row.tenant_id !== x.tenantId) refuse('No guarded action matches this request — nothing was executed');
  if (row!.state !== 'awaiting_approval') refuse(`The action is ${row!.state} — nothing was executed`);
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  await recheck(row!, x.approvalId ? [x.approvalId] : [], ctx);
  await schedule(row!, x, 'guard.action_scheduled', row!.uuid);
}

async function executeResume(x: ApprovalExecution): Promise<void> {
  const uuid = (x.payload as GuardApprovalPayload)?.actionUuid;
  const row = typeof uuid === 'string' ? await findAction(uuid, { tenantId: x.tenantId }) : undefined;
  if (!row) refuse('No guarded action matches this request — nothing was executed');
  if (row!.state !== 'paused') refuse(`The action is ${row!.state} — nothing was resumed`);
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  await recheck(row!, x.approvalId ? [x.approvalId] : [], ctx);
  await schedule(row!, x, 'guard.action_resumed', `${row!.uuid}:${x.approvalId}`);
}

async function executeUnfreeze(x: ApprovalExecution): Promise<void> {
  const requester = await personFacts(x.requesterId, x.tenantId);
  if (!(await mayOperate(requester, x.tenantId))) refuse('The requester may no longer unfreeze this tenant');
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  const reason = typeof x.payload?.reason === 'string' ? x.payload.reason : 'unfreeze';
  if (!(await unfreezeTenant(x.tenantId, ctx, { approvalIds: x.approvalId ? [x.approvalId] : [], reason, userId: x.requesterId }))) {
    refuse('The tenant is not frozen any more — nothing to do');
  }
}

const SettingsPayload = z.object({
  hourlyCapPercent: z.number().int().min(5).max(50).optional(),
  hourlyCapMin: z.number().int().min(3).max(50).optional(),
  massApproverSide: z.enum(['client', 'msp']).optional(),
}).strict();

async function executeSettingsChange(x: ApprovalExecution): Promise<void> {
  const requester = await personFacts(x.requesterId, x.tenantId);
  if (!requester.active || !requester.platformAdmin) refuse('The requester is no longer a platform administrator');
  const parsed = SettingsPayload.safeParse(x.payload?.settings ?? {});
  if (!parsed.success) refuse('Invalid guard settings request');
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  await applySettings(x.tenantId, parsed.data!, x.requesterId, ctx, x.approvalId ? [x.approvalId] : []);
}

/** The settings and guard.settings_changed in one transaction (P1). */
export async function applySettings(tenantId: number, input: GuardSettingsInput, userId: number, ctx: AuditWriteContext, approvalIds: number[]): Promise<void> {
  await db.transaction(async (trx) => {
    const before = await readSettings(tenantId, trx, { forUpdate: true });
    const patch: Record<string, unknown> = { updated_by: userId, updated_at: new Date() };
    const changes: Record<string, unknown> = {};
    if (input.hourlyCapPercent !== undefined && input.hourlyCapPercent !== before.hourly_cap_percent) {
      patch.hourly_cap_percent = input.hourlyCapPercent; changes.hourlyCapPercent = { from: before.hourly_cap_percent, to: input.hourlyCapPercent };
    }
    if (input.hourlyCapMin !== undefined && input.hourlyCapMin !== before.hourly_cap_min) {
      patch.hourly_cap_min = input.hourlyCapMin; changes.hourlyCapMin = { from: before.hourly_cap_min, to: input.hourlyCapMin };
    }
    if (input.massApproverSide !== undefined && input.massApproverSide !== before.mass_approver_side) {
      patch.mass_approver_side = input.massApproverSide; changes.massApproverSide = { from: before.mass_approver_side, to: input.massApproverSide };
    }
    if (!Object.keys(changes).length) return;
    await trx('tenant_guard_settings').where({ tenant_id: tenantId }).update(patch);
    await audit.appendInTx(trx, {
      tenantId, action: 'guard.settings_changed', outcome: 'success', approvalIds,
      target: { type: 'guard_settings', id: String(tenantId) }, details: changes,
      ...(tenantId !== MASTER_TENANT_ID ? { onBehalfOf: tenantId } : {}),
    }, ctx);
  });
}

/** Checks of a designation (§10.4): an active account; for the client side,
 *  a member of the tenant with a client-audience role who is not a platform
 *  administrator (always on the MSP side, §9.1); for the MSP side, a
 *  platform administrator or an MSP-audience role; a second factor. */
export async function designationRefusal(f: PersonFacts, side: GuardSide): Promise<string | null> {
  if (!f.exists || !f.active) return 'The account is not active';
  if (side === 'client' && f.platformAdmin) return 'A platform administrator is on the MSP side: never a client approver';
  if (side === 'client' && f.audience !== 'client') return 'A client approver needs a client role in this tenant (approver, auditor…)';
  if (side === 'msp' && !f.platformAdmin && f.audience !== 'msp') return 'An MSP approver is a platform administrator or holds an MSP role in this tenant';
  if (!f.hasSecondFactor) return 'An approver needs a second factor (authenticator app, or an Obligate account)';
  return null;
}

async function executeDesignation(x: ApprovalExecution): Promise<void> {
  const requester = await personFacts(x.requesterId, x.tenantId);
  if (!requester.active || !(requester.platformAdmin || requester.tenantRole === 'admin')) {
    refuse('The requester may no longer designate approvers in this tenant');
  }
  const userId = Number(x.payload?.userId);
  const side: GuardSide = x.payload?.side === 'msp' ? 'msp' : 'client';
  if (!Number.isSafeInteger(userId) || userId <= 0) refuse('Invalid designation request');
  const target = await personFacts(userId, x.tenantId);
  const why = await designationRefusal(target, side);
  if (why) refuse(why);
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  await db.transaction(async (trx) => {
    const exists = await trx('tenant_approvers').where({ tenant_id: x.tenantId, user_id: userId }).whereNull('revoked_at').first('id');
    if (exists) refuse('This account is already a designated approver of the tenant');
    const [row] = await trx('tenant_approvers').insert({
      tenant_id: x.tenantId, user_id: userId, side, designated_by: x.requesterId, approval_id: x.approvalId ?? null,
    }).returning('id');
    await audit.appendInTx(trx, {
      tenantId: x.tenantId, action: 'guard.approver_designated', outcome: 'success',
      approvalIds: x.approvalId ? [x.approvalId] : [], target: { type: 'user', id: String(userId) },
      details: { side, designation: Number(row?.id ?? row), username: target.username },
    }, ctx);
  });
}

// ── Filing a request of the guard ───────────────────────────────────────────

/** Files a guard request of `type` (P1 in its own transaction: the request
 *  and its entry), returns it. */
export async function fileGuardRequest(req: Request, tenantId: number, type: 'guard_resume' | 'guard_unfreeze' | 'guard_settings_change' | 'guard_approver_designate',
  description: string, payload: GuardApprovalPayload): Promise<PendingApproval> {
  const ctx = await audit.fromRequest(req, tenantId);
  const approval = await db.transaction((trx) => approvalService.createInTx(trx, {
    tenantId, userId: Number(req.session.userId), requestType: type, description, payload, auditCtx: ctx,
  }));
  approvalService.announceCreated(approval);
  return approval;
}

/** An error of the approval engine as an AppError (status, code, details). */
export function asAppError(err: any): AppError | null {
  if (err instanceof AppError) return err;
  if (err?.status) return new AppError(err.status, err.message, err.code, err.details);
  return null;
}

let registered = false;

/** The guard's request types in the approval engine. */
export function registerGuardApprovals(): void {
  if (registered) return;
  registered = true;
  const options = {
    expiryMinutes: () => approvalTtlMinutes(),
    reviewerPolicy: guardReviewerPolicy,
    reviewerStepUp: 'strict' as const,
  };
  registerApprovalRequestType('guarded_action', executeGuardedAction, { ...options, onClosed: onGuardedClosed });
  registerApprovalRequestType('guard_resume', executeResume, options);
  registerApprovalRequestType('guard_unfreeze', executeUnfreeze, options);
  registerApprovalRequestType('guard_settings_change', executeSettingsChange, options);
  registerApprovalRequestType('guard_approver_designate', executeDesignation, options);
}
