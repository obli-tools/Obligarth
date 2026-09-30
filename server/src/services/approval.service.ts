import { db } from '../db';
import { logger } from '../utils/logger';
import { getIO } from '../socket';
import { auditService } from './audit.service';
import { isMasterTenant } from '@obliance/shared';
import type { TenantCapability } from '@obliance/shared';

// Two-step approval service — creates pending requests, handles approve/deny,
// and executes the approved actions. Designed so the existing handlers only
// need a thin wrapper: they either execute directly (tenant hasn't enabled
// 2-step) OR create a pending_approvals row and return that row's id/status
// to the UI. The core executes its own actions (settings, own profile, users,
// teams, audit log, restrictions); a module that files approvals for its own
// actions registers their executors (registerApprovalExecutor, below).
//
// Safety:
//   - Requester cannot approve (nor deny) their own request.
//   - Requests expire after EXPIRY_MINUTES (default 30); the sweeper
//     (startSweeper, started by index.ts) marks them 'expired', audits and
//     pushes APPROVAL_UPDATED.
//   - Executions are idempotent: the request is claimed pending → approved
//     by one conditional UPDATE, so two approvers (or a double click) execute
//     it once; once resolved, a second approval attempt is rejected (409).
//   - An approved request is executed AS THE REQUESTER: every executor
//     re-checks the requester's rights and the tenant rules at execution
//     time (they may have changed while the request waited). When it cannot
//     be executed, the request stays 'approved' with `execution_error` (shown
//     to the reviewers) instead of a silent "approved" that did nothing.
//   - No secret in a request (services/approvalSecrets.ts): the payload is
//     returned to every reviewer. Executor-only data that is not a clear
//     secret (bcrypt hash of a new user's password, avatar image) sits in
//     `sealed_payload`, never returned, wiped as soon as the request is
//     resolved (executed, failed, denied, cancelled, expired).

const EXPIRY_MINUTES = 30;
const SWEEP_INTERVAL_MS = 60_000;

export type ApprovalRequestType = 'batch_command' | 'device_uninstall';

export interface BatchCommandPayload {
  action: string;              // 'change_group' | 'transfer_tenant' | 'settings_update' | ...
  deviceIds: number[];
  params?: Record<string, any>;
}

/** tenant.manage_users requests (users.controller.ts). */
export interface UserActionPayload {
  action: string;              // 'user_create' | 'user_update' | 'user_delete' | 'user_2fa_reset' | 'user_tenants_set' | 'user_device_keys_revoke'
  userId: number;
  assignments?: unknown;
  /** user_device_keys_revoke: one key (absent: every key of the account). */
  keyId?: string;
  /** user_create / user_update: the fields (never a password). */
  body?: Record<string, unknown>;
}

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'executed' | 'expired' | 'cancelled';

export interface PendingApproval {
  id: number;
  tenantId: number;
  requestedBy: number;
  requestedByName?: string | null;
  requestType: ApprovalRequestType;
  description: string;
  payload: BatchCommandPayload | Record<string, unknown>;
  status: ApprovalStatus;
  reviewedBy: number | null;
  reviewedByName?: string | null;
  reviewedAt: string | null;
  reviewReason: string | null;
  createdAt: string;
  expiresAt: string;
  executedAt: string | null;
  /** Approved but not executed (status 'approved'), or executed only in
   *  part (status 'executed'): why. */
  executionError: string | null;
}

/** API / socket shape. `sealed_payload` is never part of it. A pending
 *  request past its expiry is reported 'expired' even before the sweeper ran. */
function rowToApproval(r: any): PendingApproval {
  const expired = r.status === 'pending' && r.expires_at && new Date(r.expires_at).getTime() <= Date.now();
  return {
    id: r.id,
    tenantId: r.tenant_id,
    requestedBy: r.requested_by,
    requestedByName: r.requested_by_name ?? null,
    requestType: r.request_type,
    description: r.description,
    payload: typeof r.payload === 'string' ? JSON.parse(r.payload) : r.payload,
    status: expired ? 'expired' : r.status,
    reviewedBy: r.reviewed_by,
    reviewedByName: r.reviewed_by_name ?? null,
    reviewedAt: r.reviewed_at,
    reviewReason: r.review_reason,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    executedAt: r.executed_at,
    executionError: r.execution_error ?? null,
  };
}

function emitUpdated(row: any): void {
  try { getIO().to(`tenant:${row.tenant_id}`).emit('APPROVAL_UPDATED', rowToApproval(row)); } catch {}
}

function parseJson(v: unknown): any {
  if (v == null) return null;
  if (typeof v !== 'string') return v;
  try { return JSON.parse(v); } catch { return null; }
}

/** An approved request that cannot be executed: the message is stored in
 *  `execution_error` and shown to the reviewers as is. */
export function refuse(message: string): never {
  throw Object.assign(new Error(message), { approvalRefusal: true });
}

export const REDO = 'redo the action once the restriction allows it';

/** Descriptions say what will run (approvalDescribe.ts): long lists capped. */
function capDescription(d: string): string {
  const s = String(d ?? '');
  return s.length > 4000 ? `${s.slice(0, 3999)}…` : s;
}

/** Still open for review: pending AND before its deadline (the conditional
 *  UPDATEs of approve / deny / cancel carry both, so a request that expires
 *  between the read and the write is never resolved otherwise). */
function stillOpen(q: any): any {
  return q.where('status', 'pending').andWhere('expires_at', '>', new Date(Date.now()));
}

function invalidRequest(e: { errors: Array<{ message: string }> }): never {
  refuse(`Invalid request: ${e.errors.map((x) => x.message).join('; ')}`);
}

/** The requester, still active (every executor starts here). */
export async function activeRequester(requesterId: number): Promise<{ role: string; isPlatformAdmin: boolean }> {
  const row = await db('users').where({ id: requesterId }).first('role', 'is_active') as { role: string; is_active: boolean } | undefined;
  if (!row?.is_active) refuse('The requester is no longer an active user');
  return { role: row.role, isPlatformAdmin: row.role === 'admin' };
}

export async function requirePlatformAdmin(requesterId: number): Promise<void> {
  const r = await activeRequester(requesterId);
  if (!r.isPlatformAdmin) refuse('The requester is no longer a platform administrator');
}

/** Platform admin, or holder of `capability` in the approval's tenant. */
export async function requireTenantCapability(requesterId: number, tenantId: number, capability: TenantCapability): Promise<{ isPlatformAdmin: boolean }> {
  const r = await activeRequester(requesterId);
  if (r.isPlatformAdmin) return r;
  const { permissionService } = await import('./permission.service');
  if (!(await permissionService.userHasTenantCapability(requesterId, tenantId, capability))) {
    refuse(`The requester no longer holds ${capability} in this tenant`);
  }
  return r;
}

export async function auditAs(tenantId: number, userId: number, action: string, extras: {
  resourceType?: string; resourcePath?: string; deviceId?: number; details?: Record<string, unknown>;
} = {}): Promise<void> {
  await auditService.log({
    tenantId, userId, action,
    resourceType: extras.resourceType, resourcePath: extras.resourcePath, deviceId: extras.deviceId,
    details: { ...(extras.details ?? {}), viaApproval: true },
  }).catch(() => {});
}

// ── Module executors ────────────────────────────────────────────────────────
// A module that files approvals for its own actions registers what executes
// them (modules/devices.ts for the device registry). Removing the module
// removes its executors: a request it filed earlier is then refused, never
// guessed at.

/** An approved request, executed AS THE REQUESTER. */
export interface ApprovalExecution {
  /** The approval's tenant. */
  tenantId: number;
  requesterId: number;
  /** The request's payload (for 'batch_command': BatchCommandPayload). */
  payload: any;
  /** Executor-only data (sealed_payload), never returned by the API. */
  sealed: Record<string, unknown>;
}

/**
 * Throws (refuse) when the action cannot be carried out: the request stays
 * 'approved' with `execution_error`. May return a note when it was carried
 * out only in part ('executed' + execution_error).
 */
export type ApprovalExecutor = (x: ApprovalExecution) => Promise<string | void>;

/** Does this executor take a 'batch_command' request of this action? */
export type ApprovalActionMatcher = (action: string, payload: BatchCommandPayload) => boolean;

const actionExecutors: Array<{ match: ApprovalActionMatcher; run: ApprovalExecutor }> = [];
const namedActions = new Set<string>();
const requestTypeExecutors = new Map<string, ApprovalExecutor>();
let defaultExecutor: ApprovalExecutor | null = null;

/**
 * Executor of 'batch_command' requests: an action name (exact match) or a
 * matcher. Tried after the core's own actions, in registration order.
 */
export function registerApprovalExecutor(action: string | ApprovalActionMatcher, run: ApprovalExecutor): void {
  if (typeof action === 'string') {
    if (namedActions.has(action)) throw new Error(`Approval action '${action}' registered twice`);
    namedActions.add(action);
  }
  const match: ApprovalActionMatcher = typeof action === 'string' ? (a) => a === action : action;
  actionExecutors.push({ match, run });
}

/** Executor of the 'batch_command' requests no other executor took (e.g. a
 *  module's device commands). Without one, such a request is refused. */
export function registerDefaultApprovalExecutor(run: ApprovalExecutor): void {
  if (defaultExecutor) throw new Error('Default approval executor registered twice');
  defaultExecutor = run;
}

/** Executor of a whole request type other than 'batch_command'. */
export function registerApprovalRequestType(requestType: string, run: ApprovalExecutor): void {
  if (requestType === 'batch_command') throw new Error("'batch_command' requests are dispatched by action (registerApprovalExecutor)");
  if (requestTypeExecutors.has(requestType)) throw new Error(`Approval request type '${requestType}' registered twice`);
  requestTypeExecutors.set(requestType, run);
}

export const approvalService = {
  /** Is 2-step approval required for this tenant? */
  async requiresApproval(tenantId: number): Promise<boolean> {
    const row = await db('tenants').where({ id: tenantId }).first('two_step_approval');
    return !!row?.two_step_approval;
  },

  /** Create a pending approval and notify admins. The payload is shown to
   *  every reviewer: a secret-named key that still reaches this point is
   *  stripped (last safety net — restrictionService.enforce asks a step-up
   *  for such actions). `sealed`: executor-only data, never returned. */
  async create(params: {
    tenantId: number;
    userId: number;
    requestType: ApprovalRequestType;
    description: string;
    payload: BatchCommandPayload | Record<string, unknown>;
    sealed?: Record<string, unknown>;
  }): Promise<PendingApproval> {
    const { scrubSecrets } = await import('./approvalSecrets');
    const { clean, removed } = scrubSecrets(params.payload);
    if (removed.length) {
      logger.warn({ requestType: params.requestType, removed }, 'approval payload: secret fields dropped');
    }
    const expiresAt = new Date(Date.now() + EXPIRY_MINUTES * 60 * 1000);
    const [row] = await db('pending_approvals').insert({
      tenant_id: params.tenantId,
      requested_by: params.userId,
      request_type: params.requestType,
      description: capDescription(params.description),
      payload: JSON.stringify(clean),
      sealed_payload: params.sealed ? JSON.stringify(params.sealed) : null,
      status: 'pending',
      expires_at: expiresAt,
    }).returning('*');

    // Audit trail
    await auditService.log({
      tenantId: params.tenantId,
      userId: params.userId,
      action: 'approval.requested',
      resourceType: 'approval',
      resourcePath: String(row.id),
      details: { requestType: params.requestType, description: capDescription(params.description) },
    }).catch(() => {});

    // Live push to all admins in the tenant so a red badge appears immediately.
    try { getIO().to(`tenant:${params.tenantId}`).emit('APPROVAL_CREATED', rowToApproval(row)); } catch {}

    return rowToApproval(row);
  },

  /** List pending approvals for a tenant (optionally all statuses).
   *  Master tenant gets the cross-tenant feed — useful for the
   *  platform admin to spot stuck approvals across customer accounts.
   *  "Pending" excludes the requests already past their expiry. */
  async list(tenantId: number, opts: { includeResolved?: boolean; limit?: number } = {}): Promise<PendingApproval[]> {
    const isMaster = isMasterTenant(tenantId);
    const q = db('pending_approvals as pa')
      .leftJoin('users as u1', 'u1.id', 'pa.requested_by')
      .leftJoin('users as u2', 'u2.id', 'pa.reviewed_by')
      .select(
        'pa.*',
        'u1.username as requested_by_name',
        'u2.username as reviewed_by_name',
      )
      .orderBy('pa.created_at', 'desc');
    if (!isMaster) q.where({ 'pa.tenant_id': tenantId });
    if (!opts.includeResolved) q.where('pa.status', 'pending').andWhere('pa.expires_at', '>', new Date(Date.now()));
    if (opts.limit) q.limit(opts.limit);
    const rows = await q;
    return rows.map(rowToApproval);
  },

  /** Approve and execute (as the requester). Blocks self-approval. */
  async approve(params: { tenantId: number; approvalId: number; reviewerId: number; reason?: string }): Promise<PendingApproval> {
    const row = await this._openRow(params.tenantId, params.approvalId);
    if (row.requested_by === params.reviewerId) {
      throw Object.assign(new Error('Cannot approve your own request'), { status: 403 });
    }

    // Conditional on 'pending' and the deadline: two approvers (or a double
    // click) racing on the same request execute it once.
    const claimed = await stillOpen(db('pending_approvals').where({ id: row.id })).update({
      status: 'approved',
      reviewed_by: params.reviewerId,
      reviewed_at: new Date(),
      review_reason: params.reason ?? null,
    });
    if (!claimed) await this._lostRace(row.id);

    // Execute the underlying action, as the requester.
    let failure: string | null = null;
    let partial: string | null = null;
    try {
      const payload = parseJson(row.payload) ?? {};
      const sealed = parseJson(row.sealed_payload) ?? {};
      partial = await this._execute(row, payload, sealed) ?? null;
    } catch (err) {
      failure = (err instanceof Error ? err.message : String(err)) || 'Execution failed';
      logger.error({ err, approvalId: row.id }, 'approval execution failed');
    }
    // The sealed part (password hash, image) never outlives the decision.
    await db('pending_approvals').where({ id: row.id }).update(failure
      ? { execution_error: failure.slice(0, 1000), sealed_payload: null }
      : { status: 'executed', executed_at: new Date(), execution_error: partial ? partial.slice(0, 1000) : null, sealed_payload: null });

    await auditService.log({
      tenantId: row.tenant_id,
      userId: params.reviewerId,
      action: 'approval.approved',
      resourceType: 'approval',
      resourcePath: String(row.id),
      details: { reason: params.reason, executed: !failure, ...(failure ? { error: failure.slice(0, 500) } : {}) },
    }).catch(() => {});

    const fresh = await db('pending_approvals').where({ id: row.id }).first();
    emitUpdated(fresh);
    return rowToApproval(fresh);
  },

  /** Deny — no execution. */
  async deny(params: { tenantId: number; approvalId: number; reviewerId: number; reason?: string }): Promise<PendingApproval> {
    const row = await this._openRow(params.tenantId, params.approvalId);
    if (row.requested_by === params.reviewerId) {
      throw Object.assign(new Error('Cannot deny your own request'), { status: 403 });
    }
    const done = await stillOpen(db('pending_approvals').where({ id: row.id })).update({
      status: 'denied',
      reviewed_by: params.reviewerId,
      reviewed_at: new Date(),
      review_reason: params.reason ?? null,
      sealed_payload: null,
    });
    if (!done) await this._lostRace(row.id);
    await auditService.log({
      tenantId: row.tenant_id,
      userId: params.reviewerId,
      action: 'approval.denied',
      resourceType: 'approval',
      resourcePath: String(row.id),
      details: { reason: params.reason },
    }).catch(() => {});
    const fresh = await db('pending_approvals').where({ id: row.id }).first();
    emitUpdated(fresh);
    return rowToApproval(fresh);
  },

  /** Requester cancels their own pending approval (no review needed). */
  async cancel(params: { tenantId: number; approvalId: number; userId: number }): Promise<PendingApproval> {
    const row = await this._openRow(params.tenantId, params.approvalId);
    if (row.requested_by !== params.userId) {
      throw Object.assign(new Error('Only the requester can cancel'), { status: 403 });
    }
    const done = await stillOpen(db('pending_approvals').where({ id: row.id }))
      .update({ status: 'cancelled', reviewed_at: new Date(), sealed_payload: null });
    if (!done) await this._lostRace(row.id);
    await auditService.log({
      tenantId: row.tenant_id,
      userId: params.userId,
      action: 'approval.cancelled',
      resourceType: 'approval',
      resourcePath: String(row.id),
    }).catch(() => {});
    const fresh = await db('pending_approvals').where({ id: row.id }).first();
    emitUpdated(fresh);
    return rowToApproval(fresh);
  },

  /** The request, still open for review: 404 unknown, 409 already resolved,
   *  410 past its deadline (then marked 'expired' — audited, pushed — the
   *  same whatever the endpoint: approve, deny or cancel). */
  async _openRow(tenantId: number, approvalId: number): Promise<any> {
    const row = await db('pending_approvals').where({ id: approvalId, tenant_id: tenantId }).first();
    if (!row) throw Object.assign(new Error('Not found'), { status: 404 });
    if (row.status !== 'pending') throw Object.assign(new Error(`Already ${row.status}`), { status: 409 });
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      await this._expire([row.id]);
      throw Object.assign(new Error('Expired'), { status: 410 });
    }
    return row;
  },

  /** A conditional UPDATE matched nothing: resolved meanwhile (409), or its
   *  deadline passed between the read and the write (410, expired). */
  async _lostRace(id: number): Promise<never> {
    const now = await db('pending_approvals').where({ id }).first('status', 'expires_at') as { status: string; expires_at: string | Date } | undefined;
    if (now?.status === 'pending' && new Date(now.expires_at).getTime() <= Date.now()) {
      await this._expire([id]);
      throw Object.assign(new Error('Expired'), { status: 410 });
    }
    throw Object.assign(new Error('Already handled'), { status: 409 });
  },

  /** Expire stale pending approvals — the sweeper (startSweeper). Each one:
   *  'expired', sealed part wiped, audited ('approval.expired'),
   *  APPROVAL_UPDATED pushed. Returns how many expired. */
  async sweepExpired(): Promise<number> {
    const ids = await db('pending_approvals')
      .where('status', 'pending')
      .andWhere('expires_at', '<=', new Date(Date.now()))
      .pluck('id') as number[];
    if (!ids.length) return 0;
    const n = await this._expire(ids);
    if (n > 0) logger.info({ count: n }, 'expired pending approvals');
    return n;
  },

  /** Starts the periodic expiry sweep (index.ts). Returns the timer. */
  startSweeper(intervalMs = SWEEP_INTERVAL_MS): NodeJS.Timeout {
    const run = () => { this.sweepExpired().catch((err) => logger.warn({ err }, 'approval expiry sweep failed')); };
    run();
    const timer = setInterval(run, intervalMs);
    timer.unref?.();
    return timer;
  },

  async _expire(ids: number[]): Promise<number> {
    if (!ids.length) return 0;
    const rows = await db('pending_approvals')
      .whereIn('id', ids)
      .andWhere('status', 'pending')
      .update({ status: 'expired', sealed_payload: null })
      .returning('*') as any[];
    for (const row of rows) {
      await auditService.log({
        tenantId: row.tenant_id,
        action: 'approval.expired',
        resourceType: 'approval',
        resourcePath: String(row.id),
        details: { requestType: row.request_type, description: row.description, requestedBy: row.requested_by },
      }).catch(() => {});
      emitUpdated(row);
    }
    return rows.length;
  },

  // ── Executors ────────────────────────────────────────────────────────────
  // Each one throws (→ execution_error, request stays 'approved') when the
  // action cannot be carried out; may return a note when it was carried out
  // only in part (→ 'executed' + execution_error).

  async _execute(row: any, payload: any, sealed: Record<string, unknown>): Promise<string | void> {
    const tenantId = Number(row.tenant_id);
    const requesterId = Number(row.requested_by);
    if (row.request_type === 'batch_command') return this._executeBatch(tenantId, requesterId, payload, sealed);
    // Any other request type belongs to the module that files it.
    const run = requestTypeExecutors.get(String(row.request_type));
    if (!run) refuse(`Unknown request type '${String(row.request_type)}'`);
    return run({ tenantId, requesterId, payload, sealed });
  },

  async _executeBatch(tenantId: number, userId: number, payload: BatchCommandPayload, sealed: Record<string, unknown> = {}): Promise<string | void> {
    const action = typeof payload.action === 'string' ? payload.action : '';
    // Platform settings (tenant.manage_settings envelope): executed as the
    // requester, who must still be an active platform administrator.
    if (action === 'settings_update') {
      await this._executeSettingsUpdate(tenantId, userId, payload as unknown as Record<string, unknown>);
      return;
    }
    // Own profile (tenant.manage_profile envelope).
    if (action === 'profile_update') {
      await this._executeProfileUpdate(tenantId, userId, payload as unknown as Record<string, unknown>, sealed);
      return;
    }
    // User-management requests (tenant.manage_users envelope) carry a
    // userId, no deviceIds.
    if (action.startsWith('user_')) {
      await this._executeUserAction(tenantId, userId, payload as unknown as UserActionPayload, sealed);
      return;
    }
    if (action.startsWith('team_')) {
      await this._executeTeamAction(tenantId, userId, payload as unknown as Record<string, unknown>);
      return;
    }
    if (action === 'audit_clear') { await this._executeAuditClear(tenantId, userId, payload as unknown as Record<string, unknown>); return; }
    if (action === 'restrictions_update') { await this._executeRestrictionsUpdate(tenantId, userId, payload as unknown as Record<string, unknown>); return; }
    // The modules' actions (registerApprovalExecutor), then their default.
    const x: ApprovalExecution = { tenantId, requesterId: userId, payload, sealed };
    for (const e of actionExecutors) {
      if (e.match(action, payload)) return e.run(x);
    }
    if (defaultExecutor) return defaultExecutor(x);
    refuse(`Approval action '${action}' is not supported here — nothing was executed`);
  },

  /**
   * Approved user-management request, executed AS THE REQUESTER: the P1
   * scope (services/userScope.service.ts) and the account rules
   * (services/userAdmin.service.ts) are re-checked now, since rights may
   * have changed while the request waited.
   *  - user_create      : account created from the bcrypt hash kept sealed
   *  - user_update      : display name / platform role / active
   *  - user_delete      : deletion
   *  - user_2fa_reset   : second factors removed, code lock and IP trusts lifted
   *  - user_tenants_set : tenant memberships (same resolution as the route)
   *  - user_device_keys_revoke : phone keys revoked
   * A password reset never reaches this point (the route asks a step-up
   * instead: a password must never sit in a request).
   */
  async _executeUserAction(tenantId: number, requesterId: number, payload: UserActionPayload, sealed: Record<string, unknown> = {}): Promise<void> {
    const requester = await activeRequester(requesterId);
    const actor = { userId: requesterId, isPlatformAdmin: requester.isPlatformAdmin, tenantId };
    if (!actor.isPlatformAdmin) {
      const { permissionService } = await import('./permission.service');
      if (!(await permissionService.userHasTenantCapability(requesterId, tenantId, 'users.manage'))) {
        refuse('The requester no longer holds users.manage in this tenant');
      }
    }
    const ctx = { auditTenantId: tenantId };
    const { createUserAccount, updateUserAccount, deleteUserAccount } = await import('./userAdmin.service');
    if (payload.action === 'user_create') {
      const hash = sealed.passwordHash;
      if (typeof hash !== 'string' || !hash) {
        refuse(`This creation request was filed without a stored password hash — ${REDO}`);
      }
      await createUserAccount(actor, payload.body ?? {}, hash, ctx);
      return;
    }

    const targetId = Number(payload.userId);
    if (!Number.isInteger(targetId) || targetId <= 0) refuse('User request without a valid user id');
    if (payload.action === 'user_update') {
      if (!payload.body || typeof payload.body !== 'object') refuse(`This request carries no change — ${REDO}`);
      await updateUserAccount(actor, targetId, payload.body, ctx);
      return;
    }
    if (targetId === requesterId) refuse('A user-management request cannot target its requester');
    const { userScope, resetSecondFactors } = await import('./userScope.service');

    switch (payload.action) {
      case 'user_delete': {
        await deleteUserAccount(actor, targetId, ctx);
        return;
      }
      case 'user_2fa_reset': {
        const target = await userScope.assertManageableTarget(actor, targetId);
        if (!(await resetSecondFactors(targetId, requesterId, { auditTenantId: tenantId }))) refuse('User not found');
        await auditService.log({
          tenantId, userId: requesterId, action: 'user.2fa_reset',
          resourceType: 'user', resourcePath: String(targetId),
          details: { username: target.username, viaApproval: true },
        }).catch(() => {});
        return;
      }
      case 'user_tenants_set': {
        const target = await userScope.assertManageableTarget(actor, targetId);
        if (target.foreign_source === 'obligate') refuse('SSO user tenant access is managed from Obligate');
        const assignments = await userScope.resolveTenantAssignments(actor, targetId, payload.assignments);
        const { userService } = await import('./user.service');
        await userService.setUserTenantAssignments(targetId, assignments);
        await auditService.log({
          tenantId, userId: requesterId, action: 'user.tenants_changed',
          resourceType: 'user', resourcePath: String(targetId),
          details: { username: target.username, assignments, viaApproval: true },
        }).catch(() => {});
        return;
      }
      case 'user_device_keys_revoke': {
        // Device-bound 2FA (§6.5 admin revocation): restrictive only.
        const target = await userScope.assertManageableTarget(actor, targetId);
        const { deviceKeyService } = await import('./deviceKey/deviceKey.service');
        const keyId = typeof payload.keyId === 'string' ? payload.keyId : null;
        // Audited as the requester, in the approval's tenant (no request here).
        const done = keyId
          ? await deviceKeyService.revoke([keyId], 'admin', { ownerId: targetId, byUserId: requesterId, auditTenantId: tenantId })
          : await deviceKeyService.revokeAllForUser(targetId, 'admin', { byUserId: requesterId, auditTenantId: tenantId });
        await auditService.log({
          tenantId, userId: requesterId, action: 'user.device_keys_revoked',
          resourceType: 'user', resourcePath: String(targetId),
          details: { username: target.username, keys: done.map((d) => d.id), viaApproval: true },
        }).catch(() => {});
        return;
      }
      default:
        refuse(`Approval action '${payload.action}' is not a known user action — ${REDO}`);
    }
  },

  /**
   * Approved own-profile write (tenant.manage_profile at 'restricted'), for
   * the requester's own account only. PUT / (display name, e-mail,
   * language, preferences), PUT /avatar (image kept sealed), DELETE /avatar.
   * A password change never becomes a request (step-up instead).
   */
  async _executeProfileUpdate(tenantId: number, requesterId: number, payload: Record<string, unknown>, sealed: Record<string, unknown>): Promise<void> {
    await activeRequester(requesterId);
    if (Number(payload.userId) !== requesterId) refuse('A profile request only changes its requester\'s own profile');
    const method = typeof payload.method === 'string' ? payload.method.toUpperCase() : '';
    const path = typeof payload.path === 'string' ? payload.path : '';
    const svc = await import('./profileWrite.service');
    if (method === 'PUT' && path === '/') {
      const { updateProfileSchema } = await import('../validators/profile.schema');
      const parsed = updateProfileSchema.safeParse(payload.body);
      if (!parsed.success || payload.body === undefined) refuse(`This profile request carries no change — ${REDO}`);
      const data = parsed.data;
      if (await svc.ssoEmailChangeRefused(requesterId, data)) refuse('The e-mail address of an SSO account is managed in Obligate');
      await svc.applyProfileUpdate(requesterId, data);
      await auditAs(tenantId, requesterId, 'profile.updated', { resourceType: 'user', resourcePath: String(requesterId), details: { fields: Object.keys(data) } });
      return;
    }
    if (method === 'PUT' && path === '/avatar') {
      if (typeof sealed.avatar !== 'string') refuse(`This avatar request carries no image — ${REDO}`);
      await svc.setAvatar(requesterId, sealed.avatar);
      await auditAs(tenantId, requesterId, 'profile.avatar_changed', { resourceType: 'user', resourcePath: String(requesterId) });
      return;
    }
    if (method === 'DELETE' && path === '/avatar') {
      await svc.clearAvatar(requesterId);
      await auditAs(tenantId, requesterId, 'profile.avatar_removed', { resourceType: 'user', resourcePath: String(requesterId) });
      return;
    }
    refuse(`Profile request ${method || '?'} ${path || '?'} cannot be executed from an approval — ${REDO}`);
  },

  /**
   * Approved `settings_update` (tenant.manage_settings at 'restricted'),
   * executed as the requester, who must still be an active platform
   * administrator. The device-bound 2FA switches carry key + value; the
   * other writes carry the request body (never a secret: the Obligate API
   * key / inbound secret ask a step-up instead).
   */
  async _executeSettingsUpdate(tenantId: number, requesterId: number, payload: Record<string, unknown>): Promise<void> {
    const { DEVICE_KEY_SETTING_KEYS } = await import('@obliance/shared');
    const key = typeof payload.key === 'string' ? payload.key : '';
    const value = payload.value;
    if ((DEVICE_KEY_SETTING_KEYS as readonly string[]).includes(key) && (value === 'true' || value === 'false')) {
      await requirePlatformAdmin(requesterId);
      const { deviceKeyService } = await import('./deviceKey/deviceKey.service');
      await deviceKeyService.setDeviceKeySetting(key as 'device_keys_enabled', value, {
        byUserId: requesterId, auditTenantId: tenantId, viaApproval: true,
      });
      return;
    }
    const method = typeof payload.method === 'string' ? payload.method : '';
    const path = typeof payload.path === 'string' ? payload.path : '';
    if (payload.body === undefined) {
      refuse(`This settings request (${method} ${path}) was filed without its content — ${REDO}`);
    }
    await requirePlatformAdmin(requesterId);
    const { findSecretPaths } = await import('./approvalSecrets');
    if (findSecretPaths(payload.body).length) refuse('A settings request never carries a secret');
    const { applySettingsRequest } = await import('./settingsWrite.service');
    await applySettingsRequest(method, path, payload.body, { byUserId: requesterId, auditTenantId: tenantId, viaApproval: true });
    await auditAs(tenantId, requesterId, 'settings.updated', { resourceType: 'settings', resourcePath: path, details: { method } });
  },

  /** Approved team request (tenant.manage_teams / tenant.manage_permissions;
   *  /api/teams is platform-admin only). */
  async _executeTeamAction(tenantId: number, requesterId: number, payload: Record<string, unknown>): Promise<void> {
    await requirePlatformAdmin(requesterId);
    const { teamService } = await import('./team.service');
    const schemas = await import('../validators/team.schema');
    const action = String(payload.action);
    if (action === 'team_create') {
      const parsed = schemas.createTeamSchema.safeParse(payload.body ?? {});
      if (!parsed.success) invalidRequest(parsed.error);
      const data = parsed.data;
      // Teams are mono-tenant; from the master tenant the target is required.
      let targetTenantId = tenantId;
      if (isMasterTenant(tenantId)) {
        if (!data.tenantId) refuse('tenantId is required when creating a team from the master tenant');
        targetTenantId = data.tenantId;
      }
      if (!(await db('tenants').where({ id: targetTenantId }).first('id'))) refuse('Target tenant not found');
      const team = await teamService.create(data, targetTenantId);
      await auditAs(tenantId, requesterId, 'team.created', { resourceType: 'team', resourcePath: String(team.id), details: { name: team.name } });
      return;
    }
    const teamId = Number(payload.teamId);
    const team = Number.isInteger(teamId) && teamId > 0 ? await teamService.getById(teamId) : null;
    if (!team || (!isMasterTenant(tenantId) && Number(team.tenantId) !== tenantId)) refuse('Team not found');
    switch (action) {
      case 'team_update': {
        if (payload.body === undefined) refuse(`This team request was filed without its content — ${REDO}`);
        const parsed = schemas.updateTeamSchema.safeParse(payload.body);
        if (!parsed.success) invalidRequest(parsed.error);
        const updated = await teamService.update(teamId, parsed.data);
        if (!updated) refuse('Team not found');
        await auditAs(tenantId, requesterId, 'team.updated', { resourceType: 'team', resourcePath: String(teamId), details: { name: updated.name } });
        return;
      }
      case 'team_delete': {
        if (!(await teamService.delete(teamId))) refuse('Team not found');
        await auditAs(tenantId, requesterId, 'team.deleted', { resourceType: 'team', resourcePath: String(teamId), details: { name: team.name } });
        return;
      }
      case 'team_members_set': {
        if (payload.memberIds === undefined) refuse(`This team request was filed without its content — ${REDO}`);
        const parsed = schemas.setTeamMembersSchema.safeParse({ memberIds: payload.memberIds });
        if (!parsed.success) invalidRequest(parsed.error);
        await teamService.setMembers(teamId, parsed.data.memberIds);
        await auditAs(tenantId, requesterId, 'team.members_changed', {
          resourceType: 'team', resourcePath: String(teamId), details: { userCount: parsed.data.memberIds.length, memberIds: parsed.data.memberIds },
        });
        return;
      }
      case 'team_permissions_set': {
        if (payload.permissions === undefined) refuse(`This team request was filed without its content — ${REDO}`);
        const parsed = schemas.setTeamPermissionsSchema.safeParse({ permissions: payload.permissions });
        if (!parsed.success) invalidRequest(parsed.error);
        await teamService.setPermissions(teamId, parsed.data.permissions);
        await auditAs(tenantId, requesterId, 'team.permissions_changed', {
          resourceType: 'team', resourcePath: String(teamId), details: { permissionCount: parsed.data.permissions.length },
        });
        return;
      }
      default:
        refuse(`Approval action '${action}' is not a known team action — ${REDO}`);
    }
  },

  /** Approved "clear the audit log" (audit.clear, 'restricted' by default). */
  async _executeAuditClear(tenantId: number, requesterId: number, payload: Record<string, unknown>): Promise<void> {
    await requirePlatformAdmin(requesterId);
    if (Number(payload.tenantId) !== tenantId) refuse('The request targets another tenant\'s audit log');
    const deleted = await db('audit_logs').where({ tenant_id: tenantId }).delete();
    // The act of clearing leaves a mark (who, when, how many), as the route does.
    await auditAs(tenantId, requesterId, 'audit.cleared', { resourceType: 'audit_log', resourcePath: 'tenant', details: { entriesDeleted: deleted } });
  },

  /** Approved restrictions matrix (tenant.manage_restrictions): exactly the
   *  changes the reviewer saw (key: before → after), applied onto the matrix
   *  of this moment — a key changed meanwhile by someone else is kept. */
  async _executeRestrictionsUpdate(tenantId: number, requesterId: number, payload: Record<string, unknown>): Promise<void> {
    await requirePlatformAdmin(requesterId);
    const changes = payload.changes;
    if (!Array.isArray(changes) || !changes.length) {
      refuse(`This restrictions request was filed without its list of changes — ${REDO}`);
    }
    const { restrictionService, isActionKey } = await import('./restriction.service');
    const map = await restrictionService.getMap(tenantId) as Record<string, unknown>;
    const applied: string[] = [];
    for (const c of changes as Array<{ key?: unknown; to?: unknown }>) {
      const key = typeof c?.key === 'string' ? c.key : '';
      // Removing an old malformed key is allowed; setting one is not.
      if (!key || (c.to !== null && c.to !== undefined && !isActionKey(key))) refuse(`Invalid action key in the request: ${JSON.stringify(c?.key)}`);
      if (c.to === null || c.to === undefined) delete map[key];
      else map[key] = c.to;
      applied.push(key);
    }
    await restrictionService.setMap(tenantId, map as any); // normalises (a bad entry → none)
    await auditAs(tenantId, requesterId, 'restrictions.updated', { resourceType: 'restrictions', resourcePath: 'tenant', details: { changed: applied } });
  },
};
