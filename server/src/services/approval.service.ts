import type { Request } from 'express';
import { db } from '../db';
import { logger } from '../utils/logger';
import { getIO } from '../socket';
import { userLabels } from './userLabels.service';
import { audit, type AuditEntryInput, type AuditWriteContext } from '../audit';
import { currentApprovalIds, runInApprovalScope } from './approvalContext';
import { isMasterTenant } from '@obligarth/shared';
import type { TenantCapability } from '@obligarth/shared';
import { asPlatform, asTenant, currentDbContext, switchToTenant, userActor, type DbActor } from '../db/context';
import { openPlatformGrant } from '../db/platformAccess';
import { vault, type SecretLocator } from '../vault';

// Database contexts (rls-tenant §8.2): a request is filed, read and resolved
// in the database context of its tenant; an approved request is executed AS
// THE REQUESTER (actor u:<requester>) in that tenant's context; the expiry
// sweep is a durable job (core.approvals.expire, jobs/core.jobs.ts) that
// works tenant by tenant.

/** Runs fn in the context 'tenant' of `tenantId`, keeping the current actor
 *  (an approval filed in the tenant that imposes the level). */
function inApprovalTenant<T>(tenantId: number, fn: () => Promise<T>): Promise<T> {
  const ctx = currentDbContext();
  if (ctx?.kind === 'tenant' && ctx.tenantId === tenantId) return fn();
  return switchToTenant(tenantId, fn);
}

/** A read across tenants by a platform administrator requester (an approval
 *  filed from the master tenant's global view): a grant of its own, then
 *  the context 'platform'. */
async function readAsPlatformRequester<T>(requesterId: number, fn: () => Promise<T>): Promise<T> {
  const grant = await openPlatformGrant({ actor: userActor(requesterId), reason: 'approval.execute' });
  return asPlatform(grant, fn);
}

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
//   - Who reviews is the policy of the request's type (audit-durci §10.4):
//     an active platform administrator for the inherited types; a type may
//     register its own (the guard engine: a client approver by default) and
//     a strict step-up of the reviewer at approval.
//   - Requests expire after EXPIRY_MINUTES (default 30; a type may set its
//     own validity: 240 minutes for the guard's); the job
//     core.approvals.expire (every minute) marks them 'expired', audits and
//     pushes APPROVAL_UPDATED; an access past the deadline expires the
//     request on the spot (_openRow) between two runs.
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
//     secret (bcrypt hash of a new user's password, avatar image) is sealed
//     by the vault in `sealed_payload_enc` (coffre-secrets V10: the DEK of the
//     request's tenant), never returned, wiped as soon as the request is
//     resolved (executed, failed, denied, cancelled, expired).

const EXPIRY_MINUTES = 30;

export type ApprovalRequestType = 'batch_command' | 'device_uninstall' | 'vault_kek_rotation'
  | 'guarded_action' | 'guard_resume' | 'guard_unfreeze' | 'guard_settings_change' | 'guard_approver_designate'
  // Publication of a policy version or a batch of assignment changes beyond the thresholds (mdm, lot B5b).
  | 'mdm_policy_publish'
  // A command of the MDM queue the tenant's matrix holds at 'restricted' (integration-apple-edge §8.11, lot B4).
  | 'apple_action'
  // A change of push topic or the deletion of an ADE server (integration-apple-edge §11.1, §11.2, lot C3).
  | 'apple_integration';

/** Where the executor-only data of a request is sealed (AAD
 *  obligarth.pending_approvals:sealed_payload_enc:<id>:<tenant>). */
const sealedAt = (id: number, tenantId: number): SecretLocator =>
  ({ table: 'pending_approvals', column: 'sealed_payload_enc', pk: id, tenantId });

export interface BatchCommandPayload {
  action: string;              // 'change_group' | 'delete_devices' | 'settings_update' | ...
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

/** API / socket shape. `sealed_payload_enc` is never part of it. A pending
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

type AuditExtras = { resourceType?: string; resourcePath?: string; deviceId?: number; details?: Record<string, unknown> };

/** The entry of an executor's action, filed in `tenantId` as the requester,
 *  naming the approval being executed (audit-durci §5.7). */
function executorEntry(tenantId: number, action: string, extras: AuditExtras): AuditEntryInput {
  const target = extras.resourceType || extras.deviceId !== undefined
    ? {
      type: extras.resourceType || 'device',
      id: extras.resourcePath ?? String(extras.deviceId ?? ''),
      ...(extras.deviceId !== undefined ? { device: extras.deviceId } : {}),
    }
    : undefined;
  return {
    tenantId, action, target, approvalIds: currentApprovalIds(),
    details: { ...(extras.details ?? {}), viaApproval: true },
  };
}

/** P3 / P4: an executor's standard or protective action, after the fact.
 *  Never throws (the writer spools a failure). A critical action goes
 *  through withAuditAs instead (P2). */
export async function auditAs(tenantId: number, userId: number, action: string, extras: AuditExtras = {}): Promise<void> {
  const ctx = await audit.fromDbActor(userActor(userId), tenantId);
  await audit.append(executorEntry(tenantId, action, extras), ctx);
}

/** P2: an executor's critical action — the intent is written before `fn`,
 *  which runs only if it was (AuditUnavailableError otherwise). */
export async function withAuditAs<T>(tenantId: number, userId: number, action: string, extras: AuditExtras, fn: () => Promise<T>,
  resultDetails?: (r: T) => Record<string, unknown>): Promise<T> {
  const ctx = await audit.fromDbActor(userActor(userId), tenantId);
  return audit.withIntent(executorEntry(tenantId, action, extras), ctx, fn, { resultDetails });
}

/** The audit context of a reviewer (the route's, else the reviewer's). */
async function reviewerContext(given: AuditWriteContext | undefined, reviewerId: number, tenantId: number): Promise<AuditWriteContext> {
  return given ?? audit.fromDbActor(userActor(reviewerId), tenantId);
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
  /** Executor-only data (sealed_payload_enc, opened by the vault), never returned by the API. */
  sealed: Record<string, unknown>;
  /** The request (pending_approvals.id) and who approved it. */
  approvalId?: number;
  reviewerId?: number;
}

// ── Examination policies (docs: audit-durci §10.4) ──────────────────────────
// Who may approve or deny a request. A request type registered without one
// keeps the inherited rule: an active platform administrator (other than the
// requester). The guard engine registers its own (client approver by
// default, D24), with a strict step-up of the reviewer.

/** What a policy examines: the request as stored, the reviewer, the decision. */
export interface ApprovalReviewCheck {
  approval: { id: number; tenantId: number; requestedBy: number; requestType: string; payload: any };
  reviewerId: number;
  decision: 'approve' | 'deny';
}

/** Throws (an error with `status` and `code`) when the reviewer may not
 *  decide. May also ask the strict step-up of the reviewer for this request
 *  (a policy that applies the guard's rule to a request of another type: the
 *  journal's requests examined by a client approver, audit-durci §7.2). */
export type ApprovalReviewerPolicy = (x: ApprovalReviewCheck) => Promise<void | { reviewerStepUp?: 'strict' }>;

/** A request closed without execution: denied, cancelled (by its requester
 *  or withdrawn), expired. */
export interface ApprovalClosed {
  approvalId: number;
  tenantId: number;
  status: 'denied' | 'cancelled' | 'expired';
  byUserId: number | null;
  payload: any;
}

export interface ApprovalTypeOptions {
  /** Validity of a request of this type (default 30 minutes). */
  expiryMinutes?: number | (() => number);
  /** Who may approve or deny (default: an active platform administrator). */
  reviewerPolicy?: ApprovalReviewerPolicy;
  /** 'strict': the reviewer proves a second factor at approval, never the
   *  trusted-IP shortcut (action key approvals.review). */
  reviewerStepUp?: 'strict' | 'none';
  /** Called once the request is closed without execution (never throws out). */
  onClosed?: (x: ApprovalClosed) => Promise<void>;
}

/** The reviewer's step-up was not satisfied: the route sends `outcome` as is
 *  (401 prompt, 403 no factor, 429…). */
export class ApprovalStepUpError extends Error {
  constructor(readonly outcome: { status: number; body: Record<string, unknown>; headers?: Record<string, string> }) {
    super('step-up required');
    this.name = 'ApprovalStepUpError';
  }
}

const typeOptions = new Map<string, ApprovalTypeOptions>();
const batchPolicies: Array<{ match: ApprovalActionMatcher; policy: ApprovalReviewerPolicy }> = [];

/** The policy of 'batch_command' requests of some actions (the journal's
 *  requests: retention, legal hold…), instead of the inherited rule. */
export function registerApprovalReviewerPolicy(action: string | ApprovalActionMatcher, policy: ApprovalReviewerPolicy): void {
  const match: ApprovalActionMatcher = typeof action === 'string' ? (a) => a === action : action;
  batchPolicies.push({ match, policy });
}

const forbidden = (message: string, code?: string): never => {
  throw Object.assign(new Error(message), { status: 403, code });
};

/** The inherited rule: an active platform administrator. */
export async function platformAdminPolicy(x: ApprovalReviewCheck): Promise<void> {
  const row = await db('users').where({ id: x.reviewerId }).first('role', 'is_active') as { role: string; is_active: boolean } | undefined;
  if (!row?.is_active || row.role !== 'admin') forbidden('Only a platform administrator can review this request', 'approvalReviewerNotAllowed');
}

function policyOf(row: any, payload: any): ApprovalReviewerPolicy {
  const type = String(row.request_type);
  if (type === 'batch_command') {
    const action = typeof payload?.action === 'string' ? payload.action : '';
    for (const p of batchPolicies) if (p.match(action, payload)) return p.policy;
    return platformAdminPolicy;
  }
  return typeOptions.get(type)?.reviewerPolicy ?? platformAdminPolicy;
}

function expiryOf(requestType: string): number {
  const o = typeOptions.get(requestType)?.expiryMinutes;
  const v = typeof o === 'function' ? o() : o;
  return Number.isInteger(v) && (v as number) > 0 ? (v as number) : EXPIRY_MINUTES;
}

/** Calls the onClosed hook of a request's type; never throws. */
async function closed(row: any, status: ApprovalClosed['status'], byUserId: number | null): Promise<void> {
  const hook = typeOptions.get(String(row.request_type))?.onClosed;
  if (!hook) return;
  try {
    await hook({ approvalId: Number(row.id), tenantId: Number(row.tenant_id), status, byUserId, payload: parseJson(row.payload) ?? {} });
  } catch (err) {
    logger.error({ err, approvalId: row.id, status }, 'approval: closing hook failed');
  }
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

/** Executor of a whole request type other than 'batch_command', with its
 *  options (validity, examination policy, step-up of the reviewer, closing
 *  hook); without options nothing changes (30 minutes, platform
 *  administrator). */
export function registerApprovalRequestType(requestType: string, run: ApprovalExecutor, options?: ApprovalTypeOptions): void {
  if (requestType === 'batch_command') throw new Error("'batch_command' requests are dispatched by action (registerApprovalExecutor)");
  if (requestTypeExecutors.has(requestType)) throw new Error(`Approval request type '${requestType}' registered twice`);
  requestTypeExecutors.set(requestType, run);
  if (options) typeOptions.set(requestType, Object.freeze({ ...options }));
}

interface NewApproval {
  tenantId: number;
  userId: number;
  requestType: ApprovalRequestType;
  description: string;
  payload: BatchCommandPayload | Record<string, unknown>;
  sealed?: Record<string, unknown>;
}

/** The row of a new request, in `trx`. The payload is shown to every
 *  reviewer: a secret-named key that still reaches this point is stripped
 *  (last safety net). */
async function insertApproval(trx: any, params: NewApproval): Promise<any> {
  const { scrubSecrets } = await import('./approvalSecrets');
  const { clean, removed } = scrubSecrets(params.payload);
  if (removed.length) {
    logger.warn({ requestType: params.requestType, removed }, 'approval payload: secret fields dropped');
  }
  const expiresAt = new Date(Date.now() + expiryOf(params.requestType) * 60 * 1000);
  // The id comes first: it is part of the AAD of the sealed part.
  const id = await vault.allocateId('pending_approvals', { trx });
  const [row] = await trx('pending_approvals').insert({
    id,
    tenant_id: params.tenantId,
    requested_by: params.userId,
    request_type: params.requestType,
    description: capDescription(params.description),
    payload: JSON.stringify(clean),
    sealed_payload_enc: params.sealed ? await vault.sealJson(sealedAt(id, params.tenantId), params.sealed, { trx }) : null,
    status: 'pending',
    expires_at: expiresAt,
  }).returning('*');
  return row;
}

function requestedEntry(row: any, params: NewApproval): AuditEntryInput {
  return {
    tenantId: params.tenantId, action: 'approval.requested', target: { type: 'approval', id: String(row.id) },
    approvalIds: [Number(row.id)],
    details: { requestType: params.requestType, description: capDescription(params.description) },
  };
}

/** May the reviewer decide this request (policy of its type, then for an
 *  approval the strict step-up the type, or the policy, asks)? Throws an
 *  error with `status` (403, 423…) or ApprovalStepUpError. */
async function checkReviewer(row: any, reviewerId: number, decision: 'approve' | 'deny', req?: Request): Promise<void> {
  const payload = parseJson(row.payload) ?? {};
  const verdict = await policyOf(row, payload)({
    approval: {
      id: Number(row.id), tenantId: Number(row.tenant_id), requestedBy: Number(row.requested_by),
      requestType: String(row.request_type), payload,
    },
    reviewerId,
    decision,
  });
  const strict = typeOptions.get(String(row.request_type))?.reviewerStepUp === 'strict'
    || (!!verdict && verdict.reviewerStepUp === 'strict');
  if (decision !== 'approve' || !strict) return;
  if (!req) forbidden('This request is approved from the console only (second factor of the reviewer)', 'reviewerStepUpRequired');
  const { checkSecondFactor } = await import('./deviceKey/stepUpProof');
  const outcome = await checkSecondFactor(req!, { actionKey: 'approvals.review', allowTrustedIp: false, allowDevice: true });
  if (!outcome.ok) throw new ApprovalStepUpError(outcome);
  req!.stepUpVia = outcome.via;
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
    // The id comes first: it is part of the AAD of the sealed part.
    const row = await inApprovalTenant(params.tenantId, () => db.transaction((trx) => insertApproval(trx, params)));

    // Audit trail (P3), in the approval's tenant (from its context, like the row).
    await inApprovalTenant(params.tenantId, async () => audit.append(requestedEntry(row, params),
      await audit.fromDbActor(userActor(params.userId), params.tenantId)));

    // Live push to all admins in the tenant so a red badge appears immediately.
    this.announceCreated(rowToApproval(row));

    return rowToApproval(row);
  },

  /** Same, in the caller's transaction (its tenant's context): the request
   *  exists if and only if the transaction commits (audit-durci §10.3 step
   *  12). Its approval.requested entry is written in the transaction too;
   *  the caller writes its own critical entries last, then announces the
   *  request after the commit (announceCreated). */
  async createInTx(trx: any, params: {
    tenantId: number;
    userId: number;
    requestType: ApprovalRequestType;
    description: string;
    payload: BatchCommandPayload | Record<string, unknown>;
    auditCtx: AuditWriteContext;
  }): Promise<PendingApproval> {
    const row = await insertApproval(trx, params);
    await audit.appendInTx(trx, requestedEntry(row, params), params.auditCtx);
    return rowToApproval(row);
  },

  /** APPROVAL_CREATED to the tenant's room (a red badge appears at once). */
  announceCreated(approval: PendingApproval): void {
    try { getIO().to(`tenant:${approval.tenantId}`).emit('APPROVAL_CREATED', approval); } catch {}
  },

  /** List pending approvals for a tenant (optionally all statuses).
   *  Master tenant gets the cross-tenant feed — useful for the
   *  platform admin to spot stuck approvals across customer accounts.
   *  "Pending" excludes the requests already past their expiry. */
  async list(tenantId: number, opts: {
    includeResolved?: boolean; limit?: number;
    /** The master tenant's feed of every tenant (a platform administrator's
     *  global view, context 'platform'); otherwise the tenant's requests only. */
    globalView?: boolean;
    /** Only this requester's own requests (a member who does not review). */
    requesterId?: number;
  } = {}): Promise<PendingApproval[]> {
    const isMaster = isMasterTenant(tenantId);
    const q = db('pending_approvals as pa')
      .select('pa.*')
      .orderBy('pa.created_at', 'desc');
    if (!isMaster || opts.globalView === false) q.where({ 'pa.tenant_id': tenantId });
    if (opts.requesterId !== undefined) q.where({ 'pa.requested_by': opts.requesterId });
    if (!opts.includeResolved) q.where('pa.status', 'pending').andWhere('pa.expires_at', '>', new Date(Date.now()));
    if (opts.limit) q.limit(opts.limit);
    const rows = await q;
    // Requesters' and reviewers' names: obligarth.user_labels (an MSP
    // administrator is named in the client's list, another client's
    // account never).
    const labels = await userLabels(rows.flatMap((r: any) => [r.requested_by, r.reviewed_by]).filter((id: unknown) => id != null));
    return rows.map((r: any) => rowToApproval({
      ...r,
      requested_by_name: labels.get(Number(r.requested_by))?.username ?? null,
      reviewed_by_name: r.reviewed_by != null ? labels.get(Number(r.reviewed_by))?.username ?? null : null,
    }));
  },

  /** Approve and execute (as the requester). Blocks self-approval. The
   *  decision is P1 (audit-durci §10.4, J27): the request is claimed and
   *  approval.approved written in the same transaction, before the execution;
   *  when the entry cannot be written the request stays pending and the
   *  reviewer gets 503 auditUnavailable. */
  async approve(params: {
    tenantId: number; approvalId: number; reviewerId: number; reason?: string; auditCtx?: AuditWriteContext;
    /** The reviewer's request: its type may ask a strict step-up (guard). */
    req?: Request;
  }): Promise<PendingApproval> {
    const row = await this._openRow(params.tenantId, params.approvalId);
    if (row.requested_by === params.reviewerId) {
      throw Object.assign(new Error('Cannot approve your own request'), { status: 403 });
    }
    // The examination policy of the request's type (audit-durci §10.4), then
    // its step-up; the audit context is taken after it (actor.stepUp).
    await checkReviewer(row, params.reviewerId, 'approve', params.req);
    const ctx = params.req ? await audit.fromRequest(params.req, Number(row.tenant_id))
      : await reviewerContext(params.auditCtx, params.reviewerId, Number(row.tenant_id));

    // Conditional on 'pending' and the deadline: two approvers (or a double
    // click) racing on the same request execute it once.
    const claimed = await db.transaction(async (trx) => {
      const n = await stillOpen(trx('pending_approvals').where({ id: row.id })).update({
        status: 'approved',
        reviewed_by: params.reviewerId,
        reviewed_at: new Date(),
        review_reason: params.reason ?? null,
      });
      if (!n) return 0;
      await audit.appendInTx(trx, {
        tenantId: Number(row.tenant_id), action: 'approval.approved', target: { type: 'approval', id: String(row.id) },
        approvalIds: [Number(row.id)], reason: typeof params.reason === 'string' && params.reason ? params.reason : undefined,
        details: { requestType: row.request_type, requestedBy: Number(row.requested_by), description: capDescription(row.description) },
      }, ctx);
      return n;
    });
    if (!claimed) await this._lostRace(row.id);

    // Execute the underlying action, as the requester: the database context
    // of the approval's tenant, actor = the requester.
    let failure: string | null = null;
    let partial: string | null = null;
    try {
      const payload = parseJson(row.payload) ?? {};
      // Opened right before the execution (as the requester, below).
      const sealed = row.sealed_payload_enc
        ? await vault.openJson<Record<string, unknown>>(sealedAt(Number(row.id), Number(row.tenant_id)), row.sealed_payload_enc)
        : {};
      partial = await runInApprovalScope(Number(row.id), () => asTenant(Number(row.tenant_id), userActor(Number(row.requested_by)),
        () => this._execute(row, payload, sealed, params.reviewerId))) ?? null;
    } catch (err) {
      failure = (err instanceof Error ? err.message : String(err)) || 'Execution failed';
      logger.error({ err, approvalId: row.id }, 'approval execution failed');
    }
    // The sealed part (password hash, image) never outlives the decision.
    await db('pending_approvals').where({ id: row.id }).update(failure
      ? { execution_error: failure.slice(0, 1000), sealed_payload_enc: null, sealed_payload: null }
      : { status: 'executed', executed_at: new Date(), execution_error: partial ? partial.slice(0, 1000) : null, sealed_payload_enc: null, sealed_payload: null });

    // The outcome of the execution (P3): a refusal or a partial execution.
    if (failure || partial) {
      await audit.append({
        tenantId: Number(row.tenant_id), action: 'approval.executed', outcome: failure ? 'failure' : 'success',
        target: { type: 'approval', id: String(row.id) }, approvalIds: [Number(row.id)],
        details: { requestType: row.request_type, ...(failure ? { error: failure.slice(0, 500) } : { partial: String(partial).slice(0, 500) }) },
      }, ctx);
    }

    const fresh = await db('pending_approvals').where({ id: row.id }).first();
    emitUpdated(fresh);
    return rowToApproval(fresh);
  },

  /** Deny — no execution. */
  async deny(params: { tenantId: number; approvalId: number; reviewerId: number; reason?: string; auditCtx?: AuditWriteContext }): Promise<PendingApproval> {
    const row = await this._openRow(params.tenantId, params.approvalId);
    if (row.requested_by === params.reviewerId) {
      throw Object.assign(new Error('Cannot deny your own request'), { status: 403 });
    }
    // The same examination policy as an approval, without the step-up: a
    // refusal is protective.
    await checkReviewer(row, params.reviewerId, 'deny');
    const done = await stillOpen(db('pending_approvals').where({ id: row.id })).update({
      status: 'denied',
      reviewed_by: params.reviewerId,
      reviewed_at: new Date(),
      review_reason: params.reason ?? null,
      sealed_payload_enc: null,
      sealed_payload: null,
    });
    if (!done) await this._lostRace(row.id);
    // P4 (protective): the refusal stands whatever the journal says.
    await audit.append({
      tenantId: Number(row.tenant_id), action: 'approval.denied', target: { type: 'approval', id: String(row.id) },
      approvalIds: [Number(row.id)], reason: typeof params.reason === 'string' && params.reason ? params.reason : undefined,
      details: { requestType: row.request_type },
    }, await reviewerContext(params.auditCtx, params.reviewerId, Number(row.tenant_id)));
    const fresh = await db('pending_approvals').where({ id: row.id }).first();
    emitUpdated(fresh);
    await closed(row, 'denied', params.reviewerId);
    return rowToApproval(fresh);
  },

  /** Requester cancels their own pending approval (no review needed). */
  async cancel(params: { tenantId: number; approvalId: number; userId: number; auditCtx?: AuditWriteContext }): Promise<PendingApproval> {
    const row = await this._openRow(params.tenantId, params.approvalId);
    if (row.requested_by !== params.userId) {
      throw Object.assign(new Error('Only the requester can cancel'), { status: 403 });
    }
    const done = await stillOpen(db('pending_approvals').where({ id: row.id }))
      .update({ status: 'cancelled', reviewed_at: new Date(), sealed_payload_enc: null, sealed_payload: null });
    if (!done) await this._lostRace(row.id);
    // P4 (protective).
    await audit.append({
      tenantId: Number(row.tenant_id), action: 'approval.cancelled', target: { type: 'approval', id: String(row.id) },
      approvalIds: [Number(row.id)], details: { requestType: row.request_type },
    }, await reviewerContext(params.auditCtx, params.userId, Number(row.tenant_id)));
    const fresh = await db('pending_approvals').where({ id: row.id }).first();
    emitUpdated(fresh);
    await closed(row, 'cancelled', params.userId);
    return rowToApproval(fresh);
  },

  /** A pending request withdrawn by the module that filed it (the guard
   *  engine, when its action is cancelled by someone allowed to: the
   *  requester, an administrator, an approver). Protective: the request is
   *  closed whatever the journal says (approval.cancelled, P4). No closing
   *  hook: the caller closes its own state. False when no longer pending. */
  async withdraw(params: { tenantId: number; approvalId: number; byUserId: number | null; auditCtx: AuditWriteContext; reason?: string }): Promise<boolean> {
    const row = await db('pending_approvals').where({ id: params.approvalId, tenant_id: params.tenantId })
      .first('id', 'tenant_id', 'request_type', 'status') as { id: number; tenant_id: number; request_type: string; status: string } | undefined;
    if (!row || row.status !== 'pending') return false;
    const done = await db('pending_approvals').where({ id: row.id, status: 'pending' })
      .update({ status: 'cancelled', reviewed_at: new Date(), review_reason: params.reason ?? null, sealed_payload_enc: null, sealed_payload: null });
    if (!done) return false;
    await audit.append({
      tenantId: Number(row.tenant_id), action: 'approval.cancelled', target: { type: 'approval', id: String(row.id) },
      approvalIds: [Number(row.id)], reason: params.reason || undefined,
      details: { requestType: row.request_type, withdrawn: true, ...(params.byUserId !== null ? { by: params.byUserId } : {}) },
    }, params.auditCtx);
    const fresh = await db('pending_approvals').where({ id: row.id }).first();
    emitUpdated(fresh);
    return true;
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

  /** Expire stale pending approvals of a tenant — the job
   *  core.approvals.expire, in the tenant's database context. Each one:
   *  'expired', sealed part wiped, audited ('approval.expired', with the
   *  job's `auditDetails`: actor job:<queue>, job id), APPROVAL_UPDATED
   *  pushed. Returns how many expired. */
  async sweepExpired(tenantId: number, auditDetails: Record<string, unknown> = {}): Promise<number> {
    const ids = await db('pending_approvals')
      .where({ tenant_id: tenantId })
      .andWhere('status', 'pending')
      .andWhere('expires_at', '<=', new Date(Date.now()))
      .pluck('id') as number[];
    if (!ids.length) return 0;
    const n = await this._expire(ids, auditDetails);
    if (n > 0) logger.info({ tenantId, count: n }, 'expired pending approvals');
    return n;
  },

  async _expire(ids: number[], auditDetails: Record<string, unknown> = {}): Promise<number> {
    if (!ids.length) return 0;
    const rows = await db('pending_approvals')
      .whereIn('id', ids)
      .andWhere('status', 'pending')
      .update({ status: 'expired', sealed_payload_enc: null, sealed_payload: null })
      .returning('*') as any[];
    // P3, as the job (actor j:<queue>, request id job-<id>) or the caller.
    const job = typeof auditDetails.actor === 'string' ? /^job:(.+)$/.exec(auditDetails.actor)?.[1] : undefined;
    const actor: DbActor = job ? { type: 'job', name: job } : currentDbContext()?.actor ?? { type: 'job', name: 'core.approvals.expire' };
    for (const row of rows) {
      const ctx = job
        ? audit.fromJob({ name: job, requestId: typeof auditDetails.jobId === 'string' ? `job-${auditDetails.jobId}` : 'job' })
        : await audit.fromDbActor(actor, Number(row.tenant_id));
      await audit.append({
        tenantId: Number(row.tenant_id), action: 'approval.expired', target: { type: 'approval', id: String(row.id) },
        approvalIds: [Number(row.id)],
        details: { requestType: row.request_type, description: capDescription(row.description), requestedBy: Number(row.requested_by) },
      }, ctx);
      emitUpdated(row);
      await closed(row, 'expired', null);
    }
    return rows.length;
  },

  // ── Executors ────────────────────────────────────────────────────────────
  // Each one throws (→ execution_error, request stays 'approved') when the
  // action cannot be carried out; may return a note when it was carried out
  // only in part (→ 'executed' + execution_error).

  async _execute(row: any, payload: any, sealed: Record<string, unknown>, reviewerId?: number): Promise<string | void> {
    const tenantId = Number(row.tenant_id);
    const requesterId = Number(row.requested_by);
    if (row.request_type === 'batch_command') return this._executeBatch(tenantId, requesterId, payload, sealed);
    // Any other request type belongs to the module that files it.
    const run = requestTypeExecutors.get(String(row.request_type));
    if (!run) refuse(`Unknown request type '${String(row.request_type)}'`);
    return run({ tenantId, requesterId, payload, sealed, approvalId: Number(row.id), reviewerId });
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
        // P2: the intent is written before the factors go.
        const done = await withAuditAs(tenantId, requesterId, 'user.2fa_reset',
          { resourceType: 'user', resourcePath: String(targetId), details: { username: target.username } },
          () => resetSecondFactors(targetId, requesterId, { auditTenantId: tenantId }));
        if (!done) refuse('User not found');
        return;
      }
      case 'user_tenants_set': {
        const target = await userScope.assertManageableTarget(actor, targetId);
        if (target.foreign_source === 'obligate') refuse('SSO user tenant access is managed from Obligate');
        const assignments = await userScope.resolveTenantAssignments(actor, targetId, payload.assignments);
        const { userService } = await import('./user.service');
        await withAuditAs(tenantId, requesterId, 'user.tenants_changed',
          { resourceType: 'user', resourcePath: String(targetId), details: { username: target.username, assignments } },
          () => userService.setUserTenantAssignments(targetId, assignments));
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
        await auditAs(tenantId, requesterId, 'user.device_keys_revoked', {
          resourceType: 'user', resourcePath: String(targetId), details: { username: target.username, keys: done.map((d) => d.id) },
        });
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
    const { DEVICE_KEY_SETTING_KEYS } = await import('@obligarth/shared');
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
   *  /api/teams is platform-admin only). Audited in the TEAM's tenant, from
   *  its context, as the direct route does (teams.controller auditTeam,
   *  logReqAs): an approval filed from
   *  the global view on another tenant's team leaves its trace in that
   *  tenant's own log, where the team's name resolves. */
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
      // Written, and audited, in the team's tenant (the audit entry from its
      // context: rls-tenant §5.3.5).
      await asTenant(targetTenantId, userActor(requesterId), async () => {
        const team = await teamService.create(data, targetTenantId);
        await auditAs(targetTenantId, requesterId, 'team.created', { resourceType: 'team', resourcePath: String(team.id), details: { name: team.name } });
      });
      return;
    }
    const teamId = Number(payload.teamId);
    // From the master tenant, the team may be another tenant's: read across
    // tenants, then written in the team's tenant as the requester.
    const team = Number.isInteger(teamId) && teamId > 0
      ? (isMasterTenant(tenantId)
        ? await readAsPlatformRequester(requesterId, () => teamService.getById(teamId))
        : await teamService.getById(teamId))
      : null;
    if (!team || (!isMasterTenant(tenantId) && Number(team.tenantId) !== tenantId)) refuse('Team not found');
    const teamTenantId = Number(team.tenantId);
    const inTeamTenant = <T>(fn: () => Promise<T>): Promise<T> => asTenant(teamTenantId, userActor(requesterId), fn);
    switch (action) {
      case 'team_update': {
        if (payload.body === undefined) refuse(`This team request was filed without its content — ${REDO}`);
        const parsed = schemas.updateTeamSchema.safeParse(payload.body);
        if (!parsed.success) invalidRequest(parsed.error);
        const updated = await inTeamTenant(() => teamService.update(teamId, parsed.data));
        if (!updated) refuse('Team not found');
        await inTeamTenant(() => auditAs(teamTenantId, requesterId, 'team.updated', { resourceType: 'team', resourcePath: String(teamId), details: { name: updated.name } }));
        return;
      }
      case 'team_delete': {
        if (!(await inTeamTenant(() => teamService.delete(teamId)))) refuse('Team not found');
        await inTeamTenant(() => auditAs(teamTenantId, requesterId, 'team.deleted', { resourceType: 'team', resourcePath: String(teamId), details: { name: team.name } }));
        return;
      }
      case 'team_members_set': {
        if (payload.memberIds === undefined) refuse(`This team request was filed without its content — ${REDO}`);
        const parsed = schemas.setTeamMembersSchema.safeParse({ memberIds: payload.memberIds });
        if (!parsed.success) invalidRequest(parsed.error);
        await inTeamTenant(() => withAuditAs(teamTenantId, requesterId, 'team.members_changed', {
          resourceType: 'team', resourcePath: String(teamId), details: { userCount: parsed.data.memberIds.length, memberIds: parsed.data.memberIds },
        }, () => teamService.setMembers(teamId, parsed.data.memberIds)));
        return;
      }
      case 'team_permissions_set': {
        if (payload.permissions === undefined) refuse(`This team request was filed without its content — ${REDO}`);
        const parsed = schemas.setTeamPermissionsSchema.safeParse({ permissions: payload.permissions });
        if (!parsed.success) invalidRequest(parsed.error);
        await inTeamTenant(() => withAuditAs(teamTenantId, requesterId, 'team.permissions_changed', {
          resourceType: 'team', resourcePath: String(teamId), details: { permissionCount: parsed.data.permissions.length },
        }, () => teamService.setPermissions(teamId, parsed.data.permissions)));
        return;
      }
      default:
        refuse(`Approval action '${action}' is not a known team action — ${REDO}`);
    }
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
    // P1: the matrix and its entry in one transaction (normalised: a bad entry → none).
    const ctx = await audit.fromDbActor(userActor(requesterId), tenantId);
    await db.transaction(async (trx) => {
      await restrictionService.setMap(tenantId, map as any, trx);
      await audit.appendInTx(trx, executorEntry(tenantId, 'restrictions.updated', {
        resourceType: 'restrictions', resourcePath: 'tenant', details: { changed: applied },
      }), ctx);
    });
  },
};
