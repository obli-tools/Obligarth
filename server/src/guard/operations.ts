// What the console asks of the guard engine besides a request (docs:
// audit-durci §10.4 to §10.7, §10.11): cancel, resume, freeze, unfreeze,
// settings, designated approvers. Each in the database context of the
// tenant concerned (the session's; for a platform administrator in the
// global view, the action's tenant, one per request).
import type { Request } from 'express';
import {
  type GuardApprovalPayload, type GuardApproverDto, type GuardSettingsInput, type GuardSide,
  type PendingActionDto,
} from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { asTargetTenant, globalViewRead } from '../middleware/dbContext';
import { AppError } from '../middleware/errorHandler';
import { approvalService, type PendingApproval } from '../services/approval.service';
import { hasGlobalView } from '../services/deviceScope.service';
import { userLabels } from '../services/userLabels.service';
import {
  closeAwaiting, designationRefusal, fileGuardRequest, mayOperate, refuseHeldFallback, requiredSideFor,
} from './approvals';
import { guardedActionDef } from './catalog';
import { fallbackNotice, GuardStepUpError, requestFallbackNotice } from './engine';
import { actionEntry } from './executor';
import { freezeTenant, type FreezeResult } from './freeze';
import { cancelJob } from './jobs';
import { guardMetrics } from './metrics';
import { notifyAction } from './notify';
import { cooldownUntil, personFacts } from './people';
import { checkReason } from './policy';
import { readSettings } from './settings';
import { findAction, toDto, type PendingActionRow } from './store';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const notFound = (): AppError => new AppError(404, 'Guarded action not found', 'notFound');

const userOf = (req: Request): number => {
  const id = Number(req.session?.userId);
  if (!Number.isSafeInteger(id) || id <= 0) throw new AppError(401, 'Authentication required');
  return id;
};

/** The tenant of an action: the session's, or — global view — its own. */
async function actionTenant(req: Request, uuid: string): Promise<number> {
  if (!UUID_RE.test(uuid)) throw notFound();
  const own = Number(req.tenantId);
  if (!hasGlobalView(req)) return own;
  const row = await globalViewRead(req, () => db('pending_actions').where({ uuid: uuid.toLowerCase() }).first('tenant_id')) as
    { tenant_id: number } | undefined;
  if (!row) throw notFound();
  return Number(row.tenant_id);
}

/** Runs fn in the context of the action's tenant with its row. */
async function withAction<T>(req: Request, uuid: string, fn: (row: PendingActionRow, tenantId: number) => Promise<T>): Promise<T> {
  const tenantId = await actionTenant(req, uuid);
  return asTargetTenant(req, tenantId, async () => {
    const row = await findAction(uuid, { tenantId });
    if (!row) throw notFound();
    return fn(row, tenantId);
  });
}

/** A short reason, optional (cancellation, revocation: protective). */
function optionalReason(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const s = v.trim();
  return s ? s.slice(0, 500) : undefined;
}

// ── Cancellation (§10.5) ────────────────────────────────────────────────────

/**
 * Open to the requester, the platform administrators, the tenant's
 * administrators and its designated approvers. Awaiting approval: the
 * request is withdrawn; scheduled or paused: cancelled, job cancelled; both
 * protective (P4: passes even when the journal is unavailable). Executing:
 * the late cancellation of the action when it has one (undelivered MDM
 * commands), per target; otherwise 409.
 */
export async function cancelAction(req: Request, uuid: string, rawReason: unknown): Promise<{ action: PendingActionDto; cancellation?: Array<{ id: number; outcome: string }> }> {
  const userId = userOf(req);
  const reason = optionalReason(rawReason);
  return withAction(req, uuid, async (row, tenantId) => {
    const facts = await personFacts(userId, tenantId);
    if (row.requested_by !== userId && !(await mayOperate(facts, tenantId))) {
      throw new AppError(403, 'Not allowed to cancel this action', 'notAllowed');
    }
    const ctx = await audit.fromRequest(req, tenantId);
    if (row.state === 'awaiting_approval') {
      if (row.approval_id) {
        await approvalService.withdraw({ tenantId, approvalId: row.approval_id, byUserId: userId, auditCtx: ctx, reason });
      }
      if (!(await closeAwaiting(tenantId, row.uuid, 'cancelled', userId, ctx, reason))) {
        const now = await findAction(row.uuid, { tenantId });
        throw new AppError(409, `The action is ${now?.state ?? 'closed'}`, 'actionClosed');
      }
    } else if (row.state === 'scheduled' || row.state === 'paused') {
      const now = new Date();
      const n = await db('pending_actions').where({ id: row.id, state: row.state }).update({
        state: 'cancelled', cancelled_at: now, cancelled_by: userId, cancel_reason: reason ?? null, updated_at: now,
      });
      if (!n) {
        const fresh = await findAction(row.uuid, { tenantId });
        throw new AppError(409, `The action is ${fresh?.state ?? 'closed'}`, 'actionClosed');
      }
      if (row.job_id) await cancelJob(row.job_id);
      await audit.append(actionEntry(row, 'guard.action_cancelled', {
        outcome: 'cancelled', ...(reason ? { reason } : {}), details: { from: row.state, cancelledBy: userId },
      }), ctx);
      const fresh = await findAction(row.uuid, { tenantId });
      if (fresh) await notifyAction(await toDto(fresh));
    } else if (row.state === 'executing') {
      const def = guardedActionDef(row.action_key);
      if (!def?.cancelAfterDispatch) throw new AppError(409, 'The action is running and cannot be cancelled any more', 'actionExecuting');
      const { executionContext } = await import('./executor');
      const res = await def.cancelAfterDispatch(executionContext(row, row.target_device_ids, { requestId: req.requestId ?? 'request', actor: `user:${userId}` }));
      const cancellation = [...res.entries()].map(([id, outcome]) => ({ id, outcome }));
      await db('pending_actions').where({ id: row.id }).update({
        result: JSON.stringify({ ...(row.result ?? { done: 0, failed: 0, skipped: 0 }), cancellation: cancellation.slice(0, 200) }),
        updated_at: new Date(),
      });
      await audit.append(actionEntry(row, 'guard.action_cancelled', {
        outcome: 'cancelled', ...(reason ? { reason } : {}),
        details: {
          from: 'executing', late: true, cancelledBy: userId,
          cancelled: cancellation.filter((c) => c.outcome === 'cancelled').length,
          tooLate: cancellation.filter((c) => c.outcome !== 'cancelled').length,
        },
      }), ctx);
      guardMetrics.inc('obligarth_guard_cancellations_total', { state: 'executing' });
      return { action: await toDto((await findAction(row.uuid, { tenantId }))!), cancellation };
    } else {
      throw new AppError(409, `The action is ${row.state}`, 'actionClosed');
    }
    guardMetrics.inc('obligarth_guard_cancellations_total', { state: row.state });
    return { action: await toDto((await findAction(row.uuid, { tenantId }))!) };
  });
}

// ── Resumption of a paused action (§10.5) ──────────────────────────────────

/** A new approval request (another person than the requester, policy of
 *  §10.4); once approved the action starts its full delay again. */
export async function requestResume(req: Request, uuid: string): Promise<PendingApproval> {
  const userId = userOf(req);
  return withAction(req, uuid, async (row, tenantId) => {
    const facts = await personFacts(userId, tenantId);
    if (row.requested_by !== userId && !(await mayOperate(facts, tenantId))) {
      throw new AppError(403, 'Not allowed to resume this action', 'notAllowed');
    }
    if (row.state !== 'paused') throw new AppError(409, `The action is ${row.state}`, 'actionNotPaused');
    const original = await personFacts(row.requested_by, tenantId);
    const required = await requiredSideFor({ ...original, side: row.requester_side }, tenantId);
    refuseHeldFallback(required);
    const def = guardedActionDef(row.action_key);
    const payload: GuardApprovalPayload = {
      action: 'guard_resume', actionUuid: row.uuid, actionKey: row.action_key, family: row.family,
      targetCount: row.target_count, requiredSide: required.side, approverFallback: required.fallback,
      originalRequesterId: row.requested_by, delaySeconds: row.delay_seconds,
    };
    const approval = await fileGuardRequest(req, tenantId, 'guard_resume',
      `Resume ${def?.label ?? row.action_key} on ${row.target_count} device(s), paused since ${row.paused_at?.toISOString() ?? '?'} — reason: ${row.reason}`,
      payload);
    if (required.fallback) await fallbackNotice(tenantId, row.uuid, await audit.fromRequest(req, tenantId));
    return approval;
  });
}

// ── Freeze and unfreeze (§10.7) ─────────────────────────────────────────────

/** The tenant a freeze request acts on: the session's, or a platform
 *  administrator's choice from the global view (`tenantId` of the body). */
function freezeTenantOf(req: Request, raw: unknown): number {
  const own = Number(req.tenantId);
  if (raw === undefined || raw === null || raw === '') return own;
  const t = Number(raw);
  if (!Number.isSafeInteger(t) || t <= 0) throw new AppError(400, 'Invalid tenant', 'invalidTenant');
  if (t !== own && !hasGlobalView(req)) throw new AppError(404, 'Not found');
  return t;
}

export async function freeze(req: Request, body: { reason?: unknown; tenantId?: unknown }): Promise<FreezeResult> {
  const userId = userOf(req);
  const r = checkReason(body?.reason, undefined);
  if (!r.ok) throw new AppError(400, 'A reason of 5 to 500 characters is required', 'reasonRequired');
  const tenantId = freezeTenantOf(req, body?.tenantId);
  return asTargetTenant(req, tenantId, async () => {
    const facts = await personFacts(userId, tenantId);
    if (!(await mayOperate(facts, tenantId))) throw new AppError(403, 'Not allowed to freeze this tenant', 'notAllowed');
    // Step-up at 'sensitive', the trusted IP accepted (speed matters).
    const { checkSecondFactor } = await import('../services/deviceKey/stepUpProof');
    const outcome = await checkSecondFactor(req, { actionKey: 'guard.freeze', allowTrustedIp: true, allowDevice: true });
    if (!outcome.ok) throw new GuardStepUpError(outcome);
    req.stepUpVia = outcome.via;
    return freezeTenant(tenantId, { userId, source: 'manual', reason: r.reason }, await audit.fromRequest(req, tenantId));
  });
}

export async function requestUnfreeze(req: Request, body: { reason?: unknown; tenantId?: unknown }): Promise<PendingApproval> {
  const userId = userOf(req);
  const r = checkReason(body?.reason, undefined);
  if (!r.ok) throw new AppError(400, 'A reason of 5 to 500 characters is required', 'reasonRequired');
  const tenantId = freezeTenantOf(req, body?.tenantId);
  return asTargetTenant(req, tenantId, async () => {
    const facts = await personFacts(userId, tenantId);
    if (!(await mayOperate(facts, tenantId))) throw new AppError(403, 'Not allowed to unfreeze this tenant', 'notAllowed');
    const settings = await readSettings(tenantId);
    if (!settings.frozen_at) throw new AppError(409, 'The tenant is not frozen', 'notFrozen');
    const required = await requiredSideFor(facts, tenantId);
    refuseHeldFallback(required);
    const approval = await fileGuardRequest(req, tenantId, 'guard_unfreeze',
      `Unfreeze the tenant (frozen since ${settings.frozen_at.toISOString()}, ${settings.frozen_source}) — reason: ${r.reason}`,
      { action: 'guard_unfreeze', requiredSide: required.side, approverFallback: required.fallback, reason: r.reason });
    if (required.fallback) await requestFallbackNotice(tenantId, approval, await audit.fromRequest(req, tenantId));
    return approval;
  });
}

// ── Settings (§10.6) ────────────────────────────────────────────────────────

/** Platform administrators only; floor 'restricted' (guard.settings_change):
 *  always a request, reviewed with the policy of §10.4 (a client approver
 *  by default: the client agrees to a weaker protection). */
export async function requestSettings(req: Request, raw: unknown): Promise<PendingApproval | null> {
  const userId = userOf(req);
  if (req.session.role !== 'admin') throw new AppError(403, 'Insufficient permissions');
  const tenantId = Number(req.tenantId);
  const b = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const input: GuardSettingsInput = {};
  const intIn = (v: unknown, min: number, max: number, name: string): number => {
    if (!Number.isInteger(v) || (v as number) < min || (v as number) > max) {
      throw new AppError(400, `${name} must be an integer from ${min} to ${max}`, 'invalidSettings');
    }
    return v as number;
  };
  if (b.hourlyCapPercent !== undefined) input.hourlyCapPercent = intIn(b.hourlyCapPercent, 5, 50, 'hourlyCapPercent');
  if (b.hourlyCapMin !== undefined) input.hourlyCapMin = intIn(b.hourlyCapMin, 3, 50, 'hourlyCapMin');
  if (b.massApproverSide !== undefined) {
    if (b.massApproverSide !== 'client' && b.massApproverSide !== 'msp') throw new AppError(400, 'massApproverSide is client or msp', 'invalidSettings');
    input.massApproverSide = b.massApproverSide;
  }
  const s = await readSettings(tenantId);
  const changed = (input.hourlyCapPercent !== undefined && input.hourlyCapPercent !== s.hourly_cap_percent)
    || (input.hourlyCapMin !== undefined && input.hourlyCapMin !== s.hourly_cap_min)
    || (input.massApproverSide !== undefined && input.massApproverSide !== s.mass_approver_side);
  if (!changed) return null;
  const facts = await personFacts(userId, tenantId);
  const required = await requiredSideFor(facts, tenantId);
  refuseHeldFallback(required);
  const parts = [
    input.hourlyCapPercent !== undefined ? `hourly cap ${s.hourly_cap_percent} % → ${input.hourlyCapPercent} %` : null,
    input.hourlyCapMin !== undefined ? `cap minimum ${s.hourly_cap_min} → ${input.hourlyCapMin}` : null,
    input.massApproverSide !== undefined ? `approver of mass actions ${s.mass_approver_side} → ${input.massApproverSide}` : null,
  ].filter(Boolean);
  const approval = await fileGuardRequest(req, tenantId, 'guard_settings_change', `Guard settings: ${parts.join(', ')}`,
    { action: 'guard_settings_change', requiredSide: required.side, approverFallback: required.fallback, settings: input });
  if (required.fallback) await requestFallbackNotice(tenantId, approval, await audit.fromRequest(req, tenantId));
  return approval;
}

// ── Designated approvers (§10.4) ────────────────────────────────────────────

export async function listApprovers(tenantId: number): Promise<GuardApproverDto[]> {
  const rows = await db('tenant_approvers').where({ tenant_id: tenantId }).whereNull('revoked_at').orderBy('id')
    .select('id', 'tenant_id', 'user_id', 'side', 'designated_by', 'approval_id', 'created_at') as Array<{
      id: number; tenant_id: number; user_id: number; side: GuardSide; designated_by: number; approval_id: number | null; created_at: Date;
    }>;
  const labels = await userLabels(rows.map((r) => r.user_id));
  const out: GuardApproverDto[] = [];
  for (const r of rows) {
    const until = await cooldownUntil(r.user_id, tenantId, ['approver']);
    out.push({
      id: Number(r.id), tenantId: Number(r.tenant_id), userId: Number(r.user_id),
      username: labels.get(Number(r.user_id))?.username ?? null, displayName: labels.get(Number(r.user_id))?.displayName ?? null,
      side: r.side, designatedBy: Number(r.designated_by), approvalId: r.approval_id === null ? null : Number(r.approval_id),
      createdAt: new Date(r.created_at).toISOString(), cooldownUntil: until && until.getTime() > Date.now() ? until.toISOString() : null,
    });
  }
  return out;
}

/** A designation request: by a platform administrator or the tenant's
 *  administrator; floor 'restricted' (guard.approvers_change). */
export async function requestDesignation(req: Request, raw: unknown): Promise<PendingApproval> {
  const userId = userOf(req);
  const tenantId = Number(req.tenantId);
  const b = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const target = Number(b.userId);
  const side = b.side;
  if (!Number.isSafeInteger(target) || target <= 0 || (side !== 'client' && side !== 'msp')) {
    throw new AppError(400, 'userId and side (client or msp) are required', 'invalidApprover');
  }
  const requester = await personFacts(userId, tenantId);
  if (!requester.active || !(requester.platformAdmin || requester.tenantRole === 'admin')) {
    throw new AppError(403, 'Insufficient permissions');
  }
  const facts = await personFacts(target, tenantId);
  // An account outside the tenant answers like an unknown one.
  if (!facts.exists || (!facts.tenantRole && !facts.platformAdmin)) throw new AppError(404, 'User not found');
  const why = await designationRefusal(facts, side);
  if (why) throw new AppError(400, why, 'invalidApprover');
  if (await db('tenant_approvers').where({ tenant_id: tenantId, user_id: target }).whereNull('revoked_at').first('id')) {
    throw new AppError(409, 'This account is already a designated approver of the tenant', 'alreadyDesignated');
  }
  const required = await requiredSideFor(requester, tenantId);
  refuseHeldFallback(required);
  const approval = await fileGuardRequest(req, tenantId, 'guard_approver_designate',
    `Designate ${facts.username ?? `#${target}`} as ${side === 'client' ? 'client' : 'MSP'} approver of the tenant`,
    { action: 'guard_approver_designate', requiredSide: required.side, approverFallback: required.fallback, userId: target, side });
  if (required.fallback) await requestFallbackNotice(tenantId, approval, await audit.fromRequest(req, tenantId));
  return approval;
}

/** Revocation, immediate (P4): a platform administrator, the tenant's
 *  administrator, or the approver themself. */
export async function revokeDesignation(req: Request, rawId: unknown): Promise<void> {
  const userId = userOf(req);
  const tenantId = Number(req.tenantId);
  const id = Number(rawId);
  if (!Number.isSafeInteger(id) || id <= 0) throw new AppError(404, 'Not found');
  const row = await db('tenant_approvers').where({ id, tenant_id: tenantId }).whereNull('revoked_at').first('id', 'user_id', 'side') as
    { id: number; user_id: number; side: string } | undefined;
  if (!row) throw new AppError(404, 'Not found');
  const requester = await personFacts(userId, tenantId);
  if (Number(row.user_id) !== userId && !(requester.active && (requester.platformAdmin || requester.tenantRole === 'admin'))) {
    throw new AppError(403, 'Insufficient permissions');
  }
  const n = await db('tenant_approvers').where({ id, tenant_id: tenantId }).whereNull('revoked_at')
    .update({ revoked_at: new Date(), revoked_by: userId });
  if (!n) throw new AppError(404, 'Not found');
  await audit.append({
    tenantId, action: 'guard.approver_revoked', outcome: 'success', target: { type: 'user', id: String(row.user_id) },
    details: { side: row.side, designation: id },
  }, await audit.fromRequest(req, tenantId));
}
