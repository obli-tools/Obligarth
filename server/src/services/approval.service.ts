import { db } from '../db';
import { logger } from '../utils/logger';
import { getIO } from '../socket';
import { commandService } from './command.service';
import { auditService } from './audit.service';
import { isMasterTenant, SocketEvents } from '@obliance/shared';

// Two-step approval service — creates pending requests, handles approve/deny,
// and dispatches the actual commands once approved. Designed so the existing
// handlers (batch, uninstall) only need a thin wrapper: they either execute
// directly (tenant hasn't enabled 2-step) OR create a pending_approvals row
// and return that row's id/status to the UI.
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

export type ApprovalRequestType = 'batch_command' | 'device_uninstall' | 'setting_change';

export interface BatchCommandPayload {
  action: string;              // 'reboot' | 'shutdown' | 'restart_agent' | ...
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

export interface DeviceUninstallPayload {
  deviceId: number;
  /** DELETE /api/devices/:id (record only, no uninstall). */
  deleteOnly?: boolean;
  /** POST /api/devices/:id/transfer */
  targetTenantId?: number;
  targetApiKeyId?: number;
  serverUrl?: string;
}

// Generic setting flip — used today for the scenario / schedule
// `bypass_privacy_mode` toggle. Targets a row by (entityType, entityId)
// in the requester's tenant and overwrites a single column when the
// second admin approves. Keep the field list narrow on the executor
// side so an attacker can't repurpose approvals to flip unrelated rows.
export interface SettingChangePayload {
  entityType: 'scenario' | 'schedule';
  entityId: number;
  field: 'bypassPrivacyMode';
  value: boolean;
}

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'executed' | 'expired' | 'cancelled';

export interface PendingApproval {
  id: number;
  tenantId: number;
  requestedBy: number;
  requestedByName?: string | null;
  requestType: ApprovalRequestType;
  description: string;
  payload: BatchCommandPayload | DeviceUninstallPayload | SettingChangePayload | Record<string, unknown>;
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
function refuse(message: string): never {
  throw Object.assign(new Error(message), { approvalRefusal: true });
}

const REDO = 'redo the action once the restriction allows it';

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

/** Raw device commands only a platform administrator may send (POST
 *  /api/commands ADMIN_ONLY_COMMANDS; a software remediation from its own
 *  route carries a list id and is executed apart). */
const DEVICE_ADMIN_ONLY: ReadonlySet<string> = new Set([
  'install_software', 'uninstall_software', 'check_software_compliance', 'update_agent',
]);

/** Commands the legacy (Go 1.20) agent cannot run — same list as POST
 *  /api/commands (LEGACY_INCOMPATIBLE there). */
const LEGACY_INCOMPATIBLE: ReadonlySet<string> = new Set([
  'open_remote_tunnel', 'close_remote_tunnel',
  'install_oblireach',
  'install_software', 'uninstall_software', 'check_software_compliance',
  'enable_privacy_mode',
  'upload_file', 'download_file',
  'update_agent',
]);

/** Capability a non-admin requester needs on a device for this command
 *  (same mapping as POST /api/commands, hyperv.routes ACTION_META and
 *  veeam.routes). */
function commandCapability(action: string, params: Record<string, any> | undefined): string {
  if (['reboot', 'shutdown', 'sleep', 'restart_agent', 'uninstall_agent'].includes(action)) return 'power';
  if (['open_remote_tunnel', 'close_remote_tunnel'].includes(action)) return 'remote';
  if (['list_directory', 'create_directory', 'rename_file', 'delete_file', 'download_file', 'upload_file'].includes(action)) return 'files';
  if (action === 'hyperv_control') {
    const vm = String(params?.action ?? '');
    return ['start', 'stop', 'shutdown', 'restart', 'save', 'pause', 'resume'].includes(vm) ? 'hyperv:power' : 'hyperv:manage';
  }
  if (action === 'veeam_control') return 'veeam:control';
  return 'execute';
}

function invalidRequest(e: { errors: Array<{ message: string }> }): never {
  refuse(`Invalid request: ${e.errors.map((x) => x.message).join('; ')}`);
}

/** The requester, still active (every executor starts here). */
async function activeRequester(requesterId: number): Promise<{ role: string; isPlatformAdmin: boolean }> {
  const row = await db('users').where({ id: requesterId }).first('role', 'is_active') as { role: string; is_active: boolean } | undefined;
  if (!row?.is_active) refuse('The requester is no longer an active user');
  return { role: row.role, isPlatformAdmin: row.role === 'admin' };
}

async function requirePlatformAdmin(requesterId: number): Promise<void> {
  const r = await activeRequester(requesterId);
  if (!r.isPlatformAdmin) refuse('The requester is no longer a platform administrator');
}

/** Platform admin, or holder of `capability` in the approval's tenant. */
async function requireTenantCapability(requesterId: number, tenantId: number, capability: string): Promise<{ isPlatformAdmin: boolean }> {
  const r = await activeRequester(requesterId);
  if (r.isPlatformAdmin) return r;
  const { permissionService } = await import('./permission.service');
  if (!(await permissionService.userHasTenantCapability(requesterId, tenantId, capability))) {
    refuse(`The requester no longer holds ${capability} in this tenant`);
  }
  return r;
}

async function auditAs(tenantId: number, userId: number, action: string, extras: {
  resourceType?: string; resourcePath?: string; deviceId?: number; details?: Record<string, unknown>;
} = {}): Promise<void> {
  await auditService.log({
    tenantId, userId, action,
    resourceType: extras.resourceType, resourcePath: extras.resourcePath, deviceId: extras.deviceId,
    details: { ...(extras.details ?? {}), viaApproval: true },
  }).catch(() => {});
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
    payload: BatchCommandPayload | DeviceUninstallPayload | SettingChangePayload | Record<string, unknown>;
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
    switch (row.request_type) {
      case 'batch_command': return this._executeBatch(tenantId, requesterId, payload, sealed);
      case 'device_uninstall': return this._executeDeviceRequest(tenantId, requesterId, payload as DeviceUninstallPayload);
      case 'setting_change': return this._executeSettingChange(tenantId, requesterId, payload as SettingChangePayload);
      default: refuse(`Unknown request type '${String(row.request_type)}'`);
    }
  },

  async _executeBatch(tenantId: number, userId: number, payload: BatchCommandPayload, sealed: Record<string, unknown> = {}): Promise<string | void> {
    const action = typeof payload.action === 'string' ? payload.action : '';
    // Manual script run (POST /api/scripts/:id/execute): the bare `run_script`
    // command below would carry only {scriptId, parameterValues} — the agent
    // needs the script content, interpreter and timeout, and the run must
    // appear as a script execution. Go through the same path as the direct
    // (non-restricted) run, as the requester.
    const p = payload.params ?? {};
    const isManualScriptRun = action === 'run_script' && p.scriptId != null && (
      p.source === 'script_execute'
      // Requests filed before the marker existed: script id + parameter
      // values and no inline content (a raw command approval carries content).
      || (p.source === undefined && p.parameterValues !== undefined && p.content === undefined)
    );
    if (isManualScriptRun) {
      await this._executeManualScript(tenantId, userId, payload);
      return;
    }
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
    if (action === 'change_group') { await this._executeChangeGroup(tenantId, userId, payload); return; }
    if (action === 'transfer_tenant') {
      return this._executeTransfer(tenantId, userId, payload.deviceIds, {
        targetTenantId: Number(p.targetTenantId), targetApiKeyId: Number(p.targetApiKeyId), serverUrl: p.serverUrl,
      });
    }
    if (/^open_[a-z]+_session$/.test(action)) {
      // A remote session is opened live by its requester (browser tunnel):
      // an approval cannot start it afterwards.
      refuse('A remote session cannot be started from an approval — the requester must open it again (lower the remote.session_start restriction to "sensitive" to allow it with a code)');
    }
    if ((action === 'install_software' || action === 'uninstall_software') && p.listId != null && Array.isArray(p.entryIds)) {
      return this._executeSoftwareRemediation(tenantId, userId, payload);
    }
    // Dashboard "update all agents" (POST /api/devices/update-all-agents):
    // only a request of exactly that route's shape — no device list, the
    // scope matching the approval's tenant. Anything else carrying this
    // action string (e.g. a raw command filed as "update_all_agents on
    // HOST-X") is refused rather than turned into a fleet-wide rollout.
    if (action === 'update_all_agents') {
      const expectedScope = isMasterTenant(tenantId) ? 'all_tenants' : 'tenant';
      if ('deviceIds' in (payload as object) || p.scope !== expectedScope || Object.keys(p).some((k) => k !== 'scope')) {
        refuse('Not a dashboard "update all agents" request (unexpected device list or scope) — nothing was executed');
      }
      return this._executeUpdateAllAgents(tenantId, userId);
    }
    if (!Array.isArray(payload.deviceIds)) {
      refuse(`Approval action '${action}' has no device list — nothing to execute`);
    }
    return this._executeDeviceCommands(tenantId, userId, action, payload.deviceIds, p);
  },

  /**
   * Dashboard "update all agents" (POST /api/devices/update-all-agents),
   * executed as the requester, who must still be a platform administrator.
   * The target set is re-resolved NOW and its scope is the APPROVAL's tenant
   * — never a field of the payload: a request filed in a sub-tenant updates
   * that tenant's agents only, one filed in the master tenant every tenant's
   * (same rule as the direct route).
   */
  async _executeUpdateAllAgents(tenantId: number, userId: number): Promise<string | void> {
    await requirePlatformAdmin(userId);
    const { agentUpdateRollout } = await import('./agentUpdateRollout.service');
    const r = await agentUpdateRollout.updateAllOutdated(tenantId, userId);
    await auditAs(tenantId, userId, 'device.update_all_agents', {
      resourceType: 'device',
      details: {
        scope: r.allTenants ? 'all_tenants' : 'tenant', scopeTenantId: tenantId, targetVersion: r.latestVersion,
        targets: r.targets, queued: r.queued, alreadyQueued: r.alreadyQueued, online: r.online, offline: r.offline,
        ...(r.allTenants ? { tenants: r.byTenant.length } : {}),
      },
    });
    // Master scope: a summary row in each affected tenant's own log too.
    if (r.allTenants) {
      for (const { tenantId: t, ...counts } of r.byTenant) {
        if (t === tenantId) continue;
        await auditAs(t, userId, 'device.update_all_agents', {
          resourceType: 'device',
          details: { scope: 'all_tenants', initiatedFromTenantId: tenantId, targetVersion: r.latestVersion, ...counts },
        });
      }
    }
    if (r.targets === 0) return 'Nothing to do — every eligible agent already runs the current version';
  },

  /**
   * Device commands (POST /api/commands, /api/devices/batch, privacy mode,
   * airgap, Hyper-V, Veeam…), enqueued as the requester on the devices still
   * in the tenant. A privacy-gated command on a device in privacy mode needs
   * the requester's live unlock (commandService.enqueue attaches it; the
   * token itself is never kept in the request).
   */
  async _executeDeviceCommands(tenantId: number, userId: number, action: string, rawIds: unknown[], rawParams: Record<string, any>): Promise<string | void> {
    const requester = await activeRequester(userId);
    const ids = [...new Set(rawIds.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
    let devices = ids.length
      ? await db('devices').where({ tenant_id: tenantId }).whereIn('id', ids).select('id', 'hostname', 'privacy_mode_enabled', 'privacy_password_set', 'agent_flavor', 'approval_status', 'status') as
        Array<{ id: number; hostname: string; privacy_mode_enabled: boolean; privacy_password_set: boolean | null; agent_flavor: string | null; approval_status: string; status: string }>
      : [];
    if (!devices.length) refuse('None of the devices of this request is still in the tenant');
    const errors: string[] = [];
    // The device-state gates of the direct routes, re-applied now (the state
    // may have changed while the request waited):
    //  - a privacy password set on the device: disable_privacy_mode goes
    //    through /privacy/disable-with-password (the agent itself does not
    //    check the password on a raw disable);
    //  - the legacy (Go 1.20) agent lacks these handlers (POST /api/commands
    //    LEGACY_INCOMPATIBLE): the command would hang forever.
    devices = devices.filter((d) => {
      if (action === 'disable_privacy_mode' && d.privacy_password_set) {
        errors.push(`${d.hostname}: a privacy password is set on it — use "disable with password"`);
        return false;
      }
      if (d.agent_flavor === 'legacy' && LEGACY_INCOMPATIBLE.has(action)) {
        errors.push(`${d.hostname}: '${action}' is not supported on the legacy agent`);
        return false;
      }
      // An agent update waits for its device: never for one that will not
      // get it (same rule as POST /api/commands and /api/devices/batch).
      if (action === 'update_agent' && (d.approval_status !== 'approved' || ['suspended', 'pending_uninstall'].includes(d.status))) {
        errors.push(`${d.hostname}: not approved, suspended or being uninstalled`);
        return false;
      }
      return true;
    });
    if (!devices.length) refuse(`Nothing was sent — ${errors.join('; ')}`);
    // Rights may have changed while the request waited: a requester that is
    // not a platform admin still needs, on each device, the capability the
    // route required (power / remote / files / Hyper-V / Veeam / execute).
    if (!requester.isPlatformAdmin) {
      if (DEVICE_ADMIN_ONLY.has(action)) refuse(`Only a platform administrator can run '${action}'`);
      const { permissionService } = await import('./permission.service');
      if (action === 'enable_airgap' || action === 'disable_airgap') {
        if (!(await permissionService.userHasTenantCapability(userId, tenantId, 'devices.manage'))) {
          refuse('The requester no longer holds devices.manage in this tenant');
        }
      } else {
        const cap = commandCapability(action, rawParams);
        const lacking = new Set(await permissionService.devicesLackingCapability(userId, devices.map((d) => d.id), cap));
        for (const d of devices) {
          if (lacking.has(d.id)) errors.push(`${d.hostname}: the requester no longer holds '${cap}' on it`);
        }
        devices = devices.filter((d) => !lacking.has(d.id));
      }
    }
    const params: Record<string, any> = { ...(rawParams ?? {}) };
    delete params.unlockToken; // requests filed before the token was kept out
    const targets = devices;
    const { privacyGateService } = await import('./privacyGate.service');
    const doneIds: number[] = [];
    if (action === 'update_agent') {
      // Queued without expiry, one per device (an update already waiting
      // counts as done), in bulk; version refreshed at delivery.
      const { agentUpdateRollout } = await import('./agentUpdateRollout.service');
      await agentUpdateRollout.enqueueBulk(targets.map((d) => ({ id: d.id, tenant_id: tenantId })), { createdBy: userId, priority: 'high' });
      doneIds.push(...targets.map((d) => d.id));
    }
    for (const d of action === 'update_agent' ? [] : targets) {
      if (d.privacy_mode_enabled && privacyGateService.isBlockedByPrivacy(action)
        && !privacyGateService.get(userId, d.id, privacyGateService.featureForCommand(action))) {
        errors.push(`${d.hostname}: privacy mode is active and the requester's unlock has expired`);
        continue;
      }
      try {
        await commandService.enqueue({
          deviceId: d.id,
          tenantId,
          type: action as any,
          payload: params,
          priority: 'high',
          createdBy: userId,
        });
        doneIds.push(d.id);
      } catch (err) {
        logger.error({ err, deviceId: d.id }, 'batch approval execution: enqueue failed');
        errors.push(`${d.hostname}: ${err instanceof Error ? err.message.slice(0, 120) : 'enqueue failed'}`);
      }
    }
    if (!doneIds.length) refuse(`Nothing was sent — ${errors.join('; ') || 'no eligible device'}`);
    // Airgap: the device flag follows the command, as on the direct route.
    if (action === 'enable_airgap' || action === 'disable_airgap') {
      const on = action === 'enable_airgap';
      const at = on ? new Date() : null;
      await db('devices').where({ tenant_id: tenantId }).whereIn('id', doneIds)
        .update({ airgap_enabled: on, airgap_enabled_at: at, updated_at: new Date() });
      for (const id of doneIds) {
        try {
          getIO().to(`tenant:${tenantId}`).emit(SocketEvents.DEVICE_UPDATED, { id, airgapEnabled: on, airgapEnabledAt: at ? at.toISOString() : null });
        } catch {}
      }
    }
    for (const id of doneIds) {
      await auditAs(tenantId, userId, `command.${action}`, { deviceId: id, resourceType: 'command', details: { action } });
    }
    if (errors.length) return `Partially executed — ${errors.join('; ')}`;
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

  /** Approved bulk group change (device.bulk_group_change). */
  async _executeChangeGroup(tenantId: number, requesterId: number, payload: BatchCommandPayload): Promise<void> {
    await requireTenantCapability(requesterId, tenantId, 'devices.manage');
    const raw = payload.params?.groupId;
    const groupId = raw === null || raw === undefined ? null : Number(raw);
    if (groupId !== null && !(await db('device_groups').where({ id: groupId, tenant_id: tenantId }).first('id'))) refuse('Group not found');
    const ids = [...new Set((payload.deviceIds ?? []).map(Number).filter((n) => Number.isInteger(n) && n > 0))];
    const prev = ids.length ? await db('devices').whereIn('id', ids).andWhere({ tenant_id: tenantId }).select('id', 'group_id') as Array<{ id: number; group_id: number | null }> : [];
    if (!prev.length) refuse('None of the devices of this request is still in the tenant');
    await db('devices').whereIn('id', prev.map((d) => d.id)).andWhere({ tenant_id: tenantId }).update({ group_id: groupId, updated_at: new Date() });
    const changed = prev.filter((d) => d.group_id !== groupId).map((d) => d.id);
    if (groupId !== null && changed.length) {
      const { scenarioService } = await import('./scenario.service');
      for (const id of changed) {
        scenarioService.fireTrigger('group_join', id, tenantId, { groupId })
          .catch((err: unknown) => logger.error({ err, deviceId: id }, 'group_join trigger failed'));
      }
    }
    if (changed.length) {
      const { metricAlertRebaseline } = await import('./metricAlertRebaseline.service');
      metricAlertRebaseline.schedule({ kind: 'devices', deviceIds: changed }, 'bulk group change');
    }
    await auditAs(tenantId, requesterId, 'device.bulk_group_changed', {
      resourceType: 'device', resourcePath: prev.map((d) => d.id).join(','), details: { count: prev.length, changed: changed.length, toGroupId: groupId },
    });
  },

  /** Approved manual software remediation (software.remediate_*). */
  async _executeSoftwareRemediation(tenantId: number, requesterId: number, payload: BatchCommandPayload): Promise<void> {
    const requester = await activeRequester(requesterId);
    const deviceId = Number((payload.deviceIds ?? [])[0]);
    const listId = Number(payload.params?.listId);
    const entryIds = (payload.params?.entryIds as unknown[]).map(Number).filter((n) => Number.isInteger(n) && n > 0);
    if (!(await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id'))) refuse('Device not found');
    if (!requester.isPlatformAdmin) {
      const { permissionService } = await import('./permission.service');
      if (!(await permissionService.canWriteDevice(requesterId, deviceId, false))) refuse('The requester can no longer write to this device');
    }
    const { softwareComplianceService } = await import('./softwareCompliance.service');
    if (!(await softwareComplianceService.getListById(listId, tenantId))) refuse('Software list not found');
    await softwareComplianceService.triggerRemediation(deviceId, listId, entryIds, tenantId, requesterId);
    await auditAs(tenantId, requesterId, `software.${payload.action}`, { deviceId, resourceType: 'device', resourcePath: String(deviceId), details: { listId, entryIds } });
  },

  /**
   * Approved device request of type 'device_uninstall' — three routes file
   * it: uninstall (POST /:id/uninstall), record deletion (DELETE /:id,
   * `deleteOnly`) and tenant transfer (POST /:id/transfer, `targetTenantId`).
   * Each one does what its route does — never an uninstall for the others.
   */
  async _executeDeviceRequest(tenantId: number, requesterId: number, payload: DeviceUninstallPayload): Promise<string | void> {
    const deviceId = Number(payload.deviceId);
    if (!Number.isInteger(deviceId) || deviceId <= 0) refuse('Device request without a valid device id');
    if (payload.targetTenantId != null) {
      return this._executeTransfer(tenantId, requesterId, [deviceId], {
        targetTenantId: Number(payload.targetTenantId), targetApiKeyId: Number(payload.targetApiKeyId), serverUrl: payload.serverUrl,
      });
    }
    await requireTenantCapability(requesterId, tenantId, 'devices.manage');
    const { deviceService } = await import('./device.service');
    const existing = await deviceService.getDeviceById(deviceId, tenantId);
    if (!existing) refuse('Device not found');
    if (payload.deleteOnly) {
      await deviceService.deleteDevice(deviceId, tenantId);
      await auditAs(tenantId, requesterId, 'device.deleted', {
        deviceId, resourceType: 'device', resourcePath: String(deviceId),
        details: { hostname: existing.hostname, displayName: existing.displayName },
      });
      return;
    }
    // Uninstall: same 10-minute pending_uninstall window as the direct route.
    await deviceService.initiateUninstall(deviceId, tenantId);
    await commandService.enqueue({
      deviceId,
      tenantId,
      type: 'uninstall_agent' as any,
      payload: {},
      priority: 'urgent',
      expiresInSeconds: 600,
      createdBy: requesterId,
    });
    await auditAs(tenantId, requesterId, 'command.uninstall_agent', { deviceId, resourceType: 'device', resourcePath: String(deviceId), details: { hostname: existing.hostname } });
  },

  /**
   * Approved tenant transfer (device.transfer_tenant), single or bulk: the
   * same transaction as the routes (reconfigure_agent in the source queue
   * with the target key, device moved, cross-tenant artefacts dropped,
   * pending commands cancelled). The requester must still be a platform
   * admin or an administrator of BOTH tenants. The target API key is read
   * now (never kept in the request).
   */
  async _executeTransfer(tenantId: number, requesterId: number, rawIds: unknown[], t: { targetTenantId: number; targetApiKeyId: number; serverUrl?: unknown }): Promise<string | void> {
    const requester = await activeRequester(requesterId);
    if (!Number.isInteger(t.targetTenantId) || !Number.isInteger(t.targetApiKeyId) || t.targetTenantId === tenantId) {
      refuse('Transfer request without a valid target tenant / API key');
    }
    if (!requester.isPlatformAdmin) {
      const rows = await db('user_tenants').where({ user_id: requesterId, role: 'admin' }).whereIn('tenant_id', [tenantId, t.targetTenantId]).pluck('tenant_id');
      if (new Set(rows.map(Number)).size !== 2) refuse('The requester is no longer an administrator of both tenants');
    }
    // The configured public address first (the request's Host header is what
    // the direct route uses; the reviewer never saw it).
    const serverUrl = process.env.SERVER_URL
      || (typeof t.serverUrl === 'string' && /^https?:\/\/[^\s]+$/.test(t.serverUrl) ? t.serverUrl : '')
      || process.env.APP_URL || process.env.CLIENT_ORIGIN || '';
    if (!serverUrl) refuse(`This transfer request was filed without the server address — ${REDO}`);
    const targetKey = await db('agent_api_keys').where({ id: t.targetApiKeyId, tenant_id: t.targetTenantId }).first() as { key: string } | undefined;
    if (!targetKey) refuse('Target API key not found in target tenant');
    const ids = [...new Set(rawIds.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
    const devices = ids.length ? await db('devices').whereIn('id', ids).andWhere({ tenant_id: tenantId }).select('id', 'hostname') as Array<{ id: number; hostname: string }> : [];
    if (!devices.length) refuse('None of the devices of this request is still in the tenant');
    const moved: number[] = [];
    const failed: string[] = [];
    for (const device of devices) {
      try {
        // Keep in sync with device.routes.ts (POST /:id/transfer and /batch/transfer).
        await db.transaction(async (trx) => {
          await trx('command_queue').insert({
            device_id: device.id,
            tenant_id: tenantId,
            type: 'reconfigure_agent',
            payload: JSON.stringify({ apiKey: targetKey.key, serverUrl, targetTenantId: t.targetTenantId }),
            priority: 'urgent',
            status: 'pending',
            expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
            created_by: requesterId,
          });
          await trx('devices').where({ id: device.id }).update({
            tenant_id: t.targetTenantId,
            api_key_id: t.targetApiKeyId,
            group_id: null,
            schedule_alert: null,
            updated_at: new Date(),
          });
          await trx('device_custom_metrics').where({ device_id: device.id }).delete();
          await trx('software_compliance_results').where({ device_id: device.id }).delete();
          await trx('command_queue')
            .where({ device_id: device.id, tenant_id: tenantId })
            .whereIn('status', ['pending', 'sent'])
            .whereNot({ type: 'reconfigure_agent' })
            .update({ status: 'cancelled', finished_at: new Date() });
        });
        moved.push(device.id);
      } catch (err) {
        logger.error({ err, deviceId: device.id }, 'approved transfer: failed for device');
        failed.push(device.hostname);
      }
    }
    if (moved.length) {
      const { metricAlertRebaseline } = await import('./metricAlertRebaseline.service');
      metricAlertRebaseline.schedule({ kind: 'devices', deviceIds: moved }, 'tenant transfer');
    }
    await auditAs(tenantId, requesterId, moved.length > 1 || devices.length > 1 ? 'device.bulk_transferred' : 'device.transferred', {
      deviceId: devices.length === 1 ? devices[0].id : undefined,
      resourceType: 'device', resourcePath: devices.map((d) => d.id).join(','),
      details: { fromTenantId: tenantId, toTenantId: t.targetTenantId, targetApiKeyId: t.targetApiKeyId, transferred: moved.length, failed: failed.length },
    });
    if (!moved.length) refuse(`No device could be transferred (${failed.join(', ')})`);
    if (failed.length) return `Partially executed — not transferred: ${failed.join(', ')}`;
  },

  async _executeManualScript(tenantId: number, userId: number, payload: BatchCommandPayload): Promise<void> {
    const scriptId = Number(payload.params?.scriptId);
    if (!Number.isInteger(scriptId) || scriptId <= 0) refuse('Script run request without a valid script id');
    const parameterValues = (payload.params?.parameterValues && typeof payload.params.parameterValues === 'object')
      ? payload.params.parameterValues as Record<string, unknown>
      : {};
    let deviceIds = (payload.deviceIds ?? []).map(Number).filter((n) => Number.isInteger(n) && n > 0);
    deviceIds = await db('devices').where({ tenant_id: tenantId }).whereIn('id', deviceIds).pluck('id');
    // Rights may have changed while the request waited for its approver: the
    // requester still needs `execute` on each device (admins are unrestricted).
    const requester = await activeRequester(userId);
    if (!requester.isPlatformAdmin) {
      const { permissionService } = await import('./permission.service');
      const lacking = new Set(await permissionService.devicesLackingCapability(userId, deviceIds, 'execute'));
      if (lacking.size) {
        logger.warn({ scriptId, lacking: [...lacking] }, 'approved script run: requester lost execute on some devices — skipped');
        deviceIds = deviceIds.filter((id) => !lacking.has(id));
      }
    }
    if (!deviceIds.length) refuse('Approved script run: no device left to run on');
    // The approver reviewed THIS content: refuse if the script changed since.
    if (typeof payload.params?.contentSha256 === 'string') {
      const script = await db('scripts').where({ id: scriptId }).first('content') as { content: string | null } | undefined;
      const { createHash } = await import('crypto');
      const now = createHash('sha256').update(String(script?.content ?? '')).digest('hex');
      if (now !== payload.params.contentSha256) {
        refuse('Approved script run refused: the script was modified after the request');
      }
    }
    const { scheduleService } = await import('./schedule.service');
    await scheduleService.executeNow(scriptId, deviceIds, tenantId, parameterValues, userId);
  },

  /** Apply a single approved setting flip. Strict allowlist on
   *  (entityType, field) so an attacker who plants a malformed approval
   *  payload can't repurpose this to write arbitrary columns. */
  async _executeSettingChange(tenantId: number, requesterId: number, payload: SettingChangePayload): Promise<void> {
    if (payload.field !== 'bypassPrivacyMode' || typeof payload.value !== 'boolean') {
      refuse('Unsupported setting change');
    }
    const table = payload.entityType === 'scenario' ? 'scenarios'
                : payload.entityType === 'schedule' ? 'script_schedules'
                : null;
    if (!table) refuse('Unsupported setting change');
    // Rights re-checked as the requester, as the routes do: scripts.manage
    // in the tenant (route guard of PUT /scenarios/:id, PATCH /schedules/:id),
    // then — not a platform admin — the automation's targets.
    const requester = await requireTenantCapability(requesterId, tenantId, 'scripts.manage');
    const entityId = Number(payload.entityId);
    const row = Number.isInteger(entityId) && entityId > 0
      ? await db(table).where({ id: entityId, tenant_id: tenantId }).first('id', 'tenant_id', 'target_type', 'target_ids')
      : undefined;
    if (!row) refuse(`The ${payload.entityType} no longer exists`);
    if (!requester.isPlatformAdmin && payload.value === true) {
      const { permissionService } = await import('./permission.service');
      let denied: number | null = null;
      if (payload.entityType === 'scenario') {
        const { scenarioService } = await import('./scenario.service');
        const { scenarioDenialFor } = await import('./scenarioPermission.service');
        const runIds = await scenarioService.resolveTargetDevices(entityId, tenantId);
        const denial = await scenarioDenialFor(requesterId, { id: entityId, tenant_id: tenantId }, runIds);
        if (denial) denied = denial.deviceId;
      } else {
        const { scheduleService } = await import('./schedule.service');
        const ids = await scheduleService.resolveTargetDeviceIdsForAuthz(tenantId, row.target_type, row.target_ids);
        const lacking = await permissionService.devicesLackingCapability(requesterId, ids, 'execute');
        if (lacking.length) denied = lacking[0];
      }
      if (denied !== null) refuse(`The requester can no longer run this ${payload.entityType} on device #${denied}`);
    }
    const n = await db(table)
      .where({ id: payload.entityId, tenant_id: tenantId })
      .update({ bypass_privacy_mode: payload.value, updated_at: new Date() });
    if (!n) refuse(`The ${payload.entityType} no longer exists`);
    await auditAs(tenantId, requesterId, `${payload.entityType}.bypass_privacy_mode_changed`, {
      resourceType: payload.entityType, resourcePath: String(payload.entityId), details: { value: payload.value },
    });
  },
};
