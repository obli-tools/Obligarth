import type { Knex } from 'knex';
import {
  MCP_SCOPES, SocketEvents, type McpAuthorizationChanged, type McpAuthorizationLevel, type McpAuthorizationState, type McpAuthorizationView,
  type McpScope,
} from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../../audit';
import { db } from '../../db';
import { asNone, asTenant, userActor, type DbActor } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { approvalService } from '../../services/approval.service';
import { getIO } from '../../socket';
import { logger } from '../../utils/logger';
import { accessKeyDetail, mcpAuditCtx, systemCtx } from '../audit';
import { holdsTenantCapability, type McpCaller } from '../caller';
import { inetText } from '../ipUtil';
import { keyDeadReason, keyInfoOf, keysWithOwners, lockUserAuthorizations, type CancelCause } from '../keys/service';
import { assertDevicesInPerimeter, assertGroupTargetInPerimeter, effectiveTenants } from '../perimeter';
import { mcpSettings } from '../settings';

// =============================================================================
// Authorizations of the MCP server (owner decision 1; docs: specs mcp-server
// §5.3, §6.2 to §6.4). A sensitive action asked by an agent is never run by
// the key: a row 'pending' is written, its human is told (socket to user:<id>,
// the notification centre), and approves it in the console with a fresh
// second factor; it then runs once, as him, rights re-checked. An action the
// matrix holds at 'restricted' files the console's own approval request,
// tracked by a row 'filed' so that revoking the key cancels it, and that the
// approval is refused once the key or its perimeter is gone. Rows are
// written in the tenant's context; a user reads his own rows in every tenant
// (policy rls_self_read).
// =============================================================================

export const AUTH_COLUMNS = [
  'a.id', 'a.tenant_id', 'a.key_id', 'a.user_id', 'a.tool', 'a.action_key', 'a.level', 'a.summary', 'a.args', 'a.device_ids', 'a.state',
  'a.created_at', 'a.expires_at', 'a.decided_at', 'a.step_up_via', 'a.outcome', 'a.impact_digest', 'a.error_code', 'a.request_id', 'a.agent_ip',
];

export type AuthorizationRow = Record<string, any>;

const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);
const jsonOf = (v: unknown): any => { if (typeof v !== 'string') return v ?? null; try { return JSON.parse(v); } catch { return null; } };

/** A tool error the agent can act on (not a failure of the server). */
export const tooManyPending = (): AppError =>
  new AppError(429, 'Too many authorizations are waiting for a human: wait for them to be decided', 'tooManyPendingAuthorizations');

export function authorizationView(r: AuthorizationRow, keyName?: string | null, keyPublicId?: string | null): McpAuthorizationView {
  return {
    id: String(r.id), tenantId: Number(r.tenant_id), tool: String(r.tool), actionKey: String(r.action_key), level: r.level as McpAuthorizationLevel,
    summary: String(r.summary), state: r.state as McpAuthorizationState, createdAt: iso(r.created_at) as string, expiresAt: iso(r.expires_at) as string,
    decidedAt: iso(r.decided_at), stepUpVia: r.step_up_via ?? null, outcome: jsonOf(r.outcome), errorCode: r.error_code ?? null,
    key: { id: String(keyPublicId ?? r.key_public_id ?? ''), name: String(keyName ?? r.key_name ?? '') }, agentIp: inetText(r.agent_ip),
  };
}

/** Pushes the new state to the room of the key's owner only (never a tenant room): the server-built summary only. */
export function notifyOwner(r: AuthorizationRow): void {
  const payload: McpAuthorizationChanged = {
    id: String(r.id), tenantId: Number(r.tenant_id), state: r.state, summary: String(r.summary), expiresAt: iso(r.expires_at) as string,
  };
  try { getIO().to(`user:${Number(r.user_id)}`).emit(SocketEvents.MCP_AUTHORIZATION_CHANGED, payload); } catch { /* no socket (CLI, tests) */ }
}

/**
 * The caps of §3.5, counted on the user's own rows (any tenant, policy rls_self_read): pending and filed per key and
 * per user, created per hour. In the transaction of the insert, under the user's authorization lock: concurrent calls
 * (a batch, parallel requests) are counted one after the other, never all against the same count.
 */
async function enforceCaps(trx: Knex.Transaction, caller: McpCaller): Promise<void> {
  const s = await mcpSettings();
  const r = await trx('mcp_authorizations').where({ user_id: caller.userId }).first(trx.raw(`
    count(*) FILTER (WHERE state IN ('pending', 'filed', 'executing') AND key_id = ?)::int AS key_open,
    count(*) FILTER (WHERE state IN ('pending', 'filed', 'executing'))::int AS user_open,
    count(*) FILTER (WHERE key_id = ? AND created_at > now() - interval '1 hour')::int AS key_hour`, [caller.key.rowId, caller.key.rowId])) as
    { key_open: number; user_open: number; key_hour: number } | undefined;
  const counts = r ?? { key_open: 0, user_open: 0, key_hour: 0 };
  if (counts.key_open >= s.maxPendingPerKey || counts.user_open >= s.maxPendingPerUser || counts.key_hour >= s.maxCreatedPerKeyHour) {
    throw tooManyPending();
  }
}

/**
 * The key of the call is still alive, read again in the transaction of the insert (under the user's authorization
 * lock, which revokeKey takes too): a request authenticated before its key was revoked files nothing after it.
 */
async function assertKeyLive(trx: Knex.Transaction, caller: McpCaller): Promise<void> {
  const k = await trx('access_keys').where({ id: caller.key.rowId, user_id: caller.userId })
    .first('revoked_at', 'expires_at', 'credential_version') as { revoked_at: Date | null; expires_at: Date; credential_version: number } | undefined;
  const u = await trx('users').where({ id: caller.userId }).first('is_active', 'credential_version') as { is_active: boolean; credential_version: number } | undefined;
  if (!k || k.revoked_at || new Date(k.expires_at).getTime() <= Date.now() || !u || u.is_active !== true
    || Number(u.credential_version) !== Number(k.credential_version)) {
    throw new AppError(403, 'This access key is no longer active', 'keyInactive');
  }
}

/** The lock, the key and the caps, first thing in the transaction of a new row. */
async function admitNewRow(trx: Knex.Transaction, caller: McpCaller): Promise<void> {
  await lockUserAuthorizations(trx, caller.userId);
  await assertKeyLive(trx, caller);
  await enforceCaps(trx, caller);
}

export interface NewAuthorization {
  tenantId: number;
  tool: string;
  actionKey: string;
  level: McpAuthorizationLevel;
  summary: string;
  args: Record<string, unknown>;
  deviceIds: number[];
  impactDigest?: string | null;
}

const requestIdOf = (caller: McpCaller): string | null => (/^[A-Za-z0-9._:-]{1,64}$/.test(caller.requestId) ? caller.requestId : null);

/** A pending authorization (inside withTenant: the tenant's context), audited and told to its human. */
export async function createPending(caller: McpCaller, a: NewAuthorization): Promise<AuthorizationRow> {
  const s = await mcpSettings();
  const ctx = await mcpAuditCtx(caller, a.tenantId, a.tool);
  const row = await db.transaction(async (trx) => {
    await admitNewRow(trx, caller);
    const [r] = await trx('mcp_authorizations').insert({
      tenant_id: a.tenantId, key_id: caller.key.rowId, user_id: caller.userId, tool: a.tool, action_key: a.actionKey, level: a.level,
      summary: a.summary.slice(0, 500), args: JSON.stringify(a.args), device_ids: a.deviceIds, state: 'pending',
      expires_at: trx.raw("now() + make_interval(mins => ?)", [s.authorizationMinutes]), impact_digest: a.impactDigest ?? null,
      request_id: requestIdOf(caller), agent_ip: caller.ip || null,
    }).returning('*') as AuthorizationRow[];
    await audit.appendInTx(trx, {
      tenantId: a.tenantId, action: 'mcp.authorization.requested', outcome: 'requested', target: { type: 'mcp_authorization', id: String(r.id) },
      targets: a.deviceIds.length ? { deviceIds: a.deviceIds } : undefined,
      details: { tool: a.tool, actionKey: a.actionKey, level: a.level, summary: r.summary, accessKey: accessKeyDetail(caller), reasonSource: 'agent' },
    }, ctx);
    return r;
  });
  notifyOwner(row);
  return row;
}

/**
 * Files the console's approval request (restricted level), with the MCP audit context, and its tracking row 'filed'
 * in the same transaction (inside withTenant). The description says who filed it.
 */
export async function fileApproval(caller: McpCaller, a: NewAuthorization & {
  requestType: Parameters<typeof approvalService.createInTx>[1]['requestType'];
  description: string; payload: Record<string, unknown>; sealed?: Record<string, unknown>;
}): Promise<{ approvalId: number; row: AuthorizationRow }> {
  const s = await mcpSettings();
  const ctx = await mcpAuditCtx(caller, a.tenantId, a.tool);
  const prefix = `[AI agent, access key ${caller.key.name} (${caller.key.publicId}), from ${caller.ip || 'unknown address'}] `;
  const out = await db.transaction(async (trx) => {
    await admitNewRow(trx, caller);
    const approval = await approvalService.createInTx(trx, {
      tenantId: a.tenantId, userId: caller.userId, requestType: a.requestType, description: prefix + a.description,
      payload: a.payload, auditCtx: ctx, ...(a.sealed ? { sealed: a.sealed } : {}),
    });
    const [r] = await trx('mcp_authorizations').insert({
      tenant_id: a.tenantId, key_id: caller.key.rowId, user_id: caller.userId, tool: a.tool, action_key: a.actionKey, level: 'restricted',
      summary: a.summary.slice(0, 500), args: JSON.stringify(a.args), device_ids: a.deviceIds, state: 'filed',
      expires_at: trx.raw("now() + make_interval(mins => ?)", [s.authorizationMinutes]), outcome: JSON.stringify({ approvalId: approval.id }),
      request_id: requestIdOf(caller), agent_ip: caller.ip || null,
    }).returning('*') as AuthorizationRow[];
    await audit.appendInTx(trx, {
      tenantId: a.tenantId, action: 'mcp.authorization.filed', outcome: 'requested', target: { type: 'mcp_authorization', id: String(r.id) },
      approvalIds: [Number(approval.id)], targets: a.deviceIds.length ? { deviceIds: a.deviceIds } : undefined,
      details: { tool: a.tool, actionKey: a.actionKey, summary: r.summary, accessKey: accessKeyDetail(caller), reasonSource: 'agent' },
    }, ctx);
    return { approval, row: r };
  });
  approvalService.announceCreated(out.approval);
  notifyOwner(out.row);
  return { approvalId: Number(out.approval.id), row: out.row };
}

/** Moves a row of the tenant's context from `from` states to `to`; returns the row when it changed. */
export async function transition(q: Knex | Knex.Transaction, id: string, from: McpAuthorizationState[], to: McpAuthorizationState,
  extra: { outcome?: unknown; errorCode?: string | null; stepUpVia?: string | null; decided?: boolean } = {}): Promise<AuthorizationRow | null> {
  const [r] = await q('mcp_authorizations').where({ id }).whereIn('state', from).update({
    state: to,
    ...(extra.outcome !== undefined ? { outcome: JSON.stringify(extra.outcome) } : {}),
    ...(extra.errorCode !== undefined ? { error_code: extra.errorCode ? extra.errorCode.slice(0, 64) : null } : {}),
    ...(extra.stepUpVia !== undefined ? { step_up_via: extra.stepUpVia } : {}),
    ...(extra.decided ? { decided_at: new Date() } : {}),
  }).returning('*') as AuthorizationRow[];
  return r ?? null;
}

/** An entry of the life of an authorization, in its tenant's chain (never breaks the caller). */
export async function auditState(r: AuthorizationRow, action: string, ctx: AuditWriteContext, details: Record<string, unknown> = {}): Promise<void> {
  try {
    await audit.append({
      tenantId: Number(r.tenant_id), action, target: { type: 'mcp_authorization', id: String(r.id) },
      details: { tool: r.tool, actionKey: r.action_key, keyId: String(r.key_id), ...details },
    }, ctx);
  } catch (err) {
    logger.warn({ err, action, id: r.id }, 'mcp: authorization entry not written');
  }
}

// ── Cancellation with the key (§5.3) ────────────────────────────────────────

/**
 * Every 'pending' authorization of a key becomes 'cancelled'; every 'filed' one has its approval cancelled as its
 * requester (the approval already decided is left as is), then becomes 'cancelled'. A cancellation that fails keeps
 * 'filed' with error_code 'cancelFailed' (the minute step retries). `tenantId`: only that tenant (an exclusion).
 */
export async function cancelForKey(key: { rowId: string; userId: number; publicId?: string; name?: string }, why: string, tenantId?: number,
  cause?: CancelCause): Promise<number> {
  const U = key.userId;
  let rows: AuthorizationRow[];
  try {
    rows = await asNone(userActor(U), () => {
      const q = db('mcp_authorizations').where({ user_id: U, key_id: key.rowId }).whereIn('state', ['pending', 'filed']);
      if (tenantId !== undefined) q.where({ tenant_id: tenantId });
      return q.select('*');
    }) as AuthorizationRow[];
  } catch (err) {
    // Not even listed: the minute step (cancelDeadKeyRows) cancels the rows of a dead key, the approval check refuses them.
    logger.warn({ err, keyId: key.publicId ?? key.rowId }, 'mcp: authorizations of a key not listed for cancellation');
    throw err;
  }
  const keyRef = key.publicId ? { id: key.publicId, name: key.name ?? '' } : undefined;
  let n = 0;
  for (const r of rows) {
    try {
      if (await cancelOne(r, U, why, cause ?? { trigger: 'system' }, keyRef)) n++;
    } catch (err) {
      logger.warn({ err, id: r.id }, 'mcp: authorization not cancelled');
    }
  }
  return n;
}

/**
 * Cancels one row in its tenant. The approval is cancelled as its requester (approvalService.cancel requires him), but
 * both entries name who or what caused it: the acting person's context, or the system (never the owner unless he
 * acted), with the trigger and the key.
 */
async function cancelOne(r: AuthorizationRow, U: number, why: string, cause: CancelCause, keyRef?: { id: string; name: string }): Promise<boolean> {
  const actor: DbActor = userActor(U);
  return asTenant(Number(r.tenant_id), actor, async () => {
    const ctx = cause.ctx ?? systemCtx({ requestId: 'mcp-authorization-cancel' });
    const detail = { why, trigger: cause.trigger, ...(cause.by != null ? { by: cause.by } : {}), ...(keyRef ? { accessKey: keyRef } : {}) };
    if (r.state === 'pending') {
      const done = await transition(db, String(r.id), ['pending'], 'cancelled', { decided: true });
      if (!done) return false;
      await auditState(done, 'mcp.authorization.cancelled', ctx, detail);
      notifyOwner(done);
      return true;
    }
    const approvalId = Number(jsonOf(r.outcome)?.approvalId);
    if (Number.isSafeInteger(approvalId) && approvalId > 0) {
      try {
        await approvalService.cancel({ tenantId: Number(r.tenant_id), approvalId, userId: U, auditCtx: ctx });
      } catch (err) {
        const status = Number((err as { status?: unknown; statusCode?: unknown }).status ?? (err as { statusCode?: unknown }).statusCode);
        // 404 / 409 / 410: the approval is already decided, expired or gone: left as is.
        if (![404, 409, 410].includes(status)) {
          await db('mcp_authorizations').where({ id: r.id, state: 'filed' }).update({ error_code: 'cancelFailed' });
          throw err;
        }
      }
    }
    const done = await transition(db, String(r.id), ['filed'], 'cancelled', { decided: true, errorCode: null });
    if (!done) return false;
    await auditState(done, 'mcp.authorization.cancelled', ctx, { ...detail, approvalId });
    notifyOwner(done);
    return true;
  });
}

/** The tool of an authorization → the scope it needs on the key. */
export const SCOPE_OF_TOOL: Record<string, McpScope> = {
  send_device_message: 'commands.message', reboot_device: 'commands.restart', install_app: 'commands.apps', uninstall_app: 'commands.apps',
  pull_app: 'commands.apps', update_agent: 'commands.apps', refresh_inventory: 'commands.inventory', move_devices_to_group: 'groups.move',
};

/** Why an approval filed through a key may no longer run (§0.1, §1.1), or null. `rows`: its tracking rows. */
async function filedApprovalClosedReason(T: number, rows: AuthorizationRow[]): Promise<string | null> {
  const r = rows.find((x) => x.state === 'filed');
  if (!r) return 'tracking_closed';
  // A cancellation that failed is still a cancellation: never approvable while the minute step retries it.
  if (rows.some((x) => x.error_code === 'cancelFailed')) return 'cancellation_pending';
  const k = (await keysWithOwners([String(r.key_id)])).get(String(r.key_id));
  const dead = keyDeadReason(k);
  if (dead || !k || !k.owner) return dead ?? 'key_missing';
  const subject = { userId: k.owner.id, isPlatformAdmin: k.owner.role === 'admin', targets: k.targets, key: keyInfoOf(k.row) };
  const eff = await effectiveTenants(subject);
  if (!eff.tenants.some((t) => t.id === T)) return 'tenant_outside_perimeter';
  const scope = SCOPE_OF_TOOL[String(r.tool)];
  if (!scope || !subject.key.scopes.includes(scope)) return 'scope_lost';
  const lost = await asTenant(T, userActor(subject.userId), async () => {
    const need = MCP_SCOPES[scope].tenantNeed;
    if (need !== 'membership' && !(await holdsTenantCapability(subject, T, need))) return true;
    try {
      const ids = (Array.isArray(r.device_ids) ? r.device_ids : []).map(Number);
      if (ids.length > 0) await assertDevicesInPerimeter(subject, T, ids);
      if (r.tool === 'move_devices_to_group') {
        const a = (jsonOf(r.args) ?? {}) as { group_id?: unknown };
        await assertGroupTargetInPerimeter(subject, T, a.group_id === null || a.group_id === undefined ? null : Number(a.group_id));
      }
    } catch {
      return true;
    }
    return false;
  });
  return lost ? 'perimeter_lost' : null;
}

/**
 * The check of approvalService.approve (registered by modules/mcp.ts) for an approval filed through a key: it runs
 * only while its tracking row is 'filed' (not awaiting a failed cancellation), its key alive (not revoked nor expired,
 * the owner active with the same credentials: a password or TOTP change kills it at once, whether or not the key is
 * presented again), the tenant in the key's effective perimeter, the scope's need still held and the devices (and the
 * target group of a move) still inside the key's perimeter. Otherwise its rows and the approval are cancelled and the
 * approval refused, 409 authorizationClosed. An approval not filed through a key passes.
 */
export async function assertFiledApprovalLive(approval: { id: number; tenantId: number }): Promise<void> {
  const T = Number(approval.tenantId);
  const rows = await asTenant(T, { type: 'integration', name: 'mcp' }, () => db('mcp_authorizations')
    .where({ tenant_id: T }).whereRaw("outcome ->> 'approvalId' = ?", [String(approval.id)]).select('*')) as AuthorizationRow[];
  if (rows.length === 0) return;
  const why = await filedApprovalClosedReason(T, rows);
  if (!why) return;
  for (const r of rows.filter((x) => x.state === 'filed' && x.error_code !== 'cancelFailed')) {
    try {
      await cancelOne(r, Number(r.user_id), `approval refused: ${why}`, { trigger: why });
    } catch (err) {
      logger.warn({ err, id: r.id }, 'mcp: authorization of a refused approval not cancelled');
    }
  }
  throw Object.assign(new AppError(409, 'The access key that filed this request is no longer active', 'authorizationClosed', { why }), { status: 409 });
}

// ── Minute step, per tenant (§6.4) ──────────────────────────────────────────

/** Pending rows past their expiry become 'expired' (in tenant T's context). */
export async function expireDue(tenantId: number, ctx: AuditWriteContext): Promise<number> {
  const rows = await db('mcp_authorizations').where({ tenant_id: tenantId, state: 'pending' }).where('expires_at', '<=', new Date())
    .update({ state: 'expired', decided_at: new Date() }).returning('*') as AuthorizationRow[];
  for (const r of rows) { await auditState(r, 'mcp.authorization.expired', ctx); notifyOwner(r); }
  return rows.length;
}

/**
 * Rows 'executing' for more than 5 minutes (a crash between the claim and the end): 'executed' when a command carries
 * their idempotency key (the enqueue did commit), 'interrupted' otherwise; never run twice.
 */
export async function interruptStale(tenantId: number, ctx: AuditWriteContext): Promise<number> {
  const rows = await db('mcp_authorizations').where({ tenant_id: tenantId, state: 'executing' })
    .where('decided_at', '<', new Date(Date.now() - 5 * 60_000)).select('*') as AuthorizationRow[];
  let n = 0;
  for (const r of rows) {
    const key = `mcp-auth:${r.id}`;
    const cmd = await db('legacy_agent_commands').where({ tenant_id: tenantId, idempotency_key: key }).pluck('id') as string[];
    const done = cmd.length > 0
      ? await transition(db, String(r.id), ['executing'], 'executed', { outcome: { commandIds: cmd.map(String), recovered: true } })
      : await transition(db, String(r.id), ['executing'], 'interrupted', { errorCode: 'interrupted' });
    if (!done) continue;
    n++;
    await auditState(done, done.state === 'executed' ? 'mcp.authorization.executed' : 'mcp.authorization.interrupted', ctx, { recovered: true });
    notifyOwner(done);
  }
  return n;
}

/** Filed rows whose approval could not be cancelled when their key was revoked: retried. */
export async function retryCancelFailed(tenantId: number): Promise<number> {
  const rows = await db('mcp_authorizations').where({ tenant_id: tenantId, state: 'filed', error_code: 'cancelFailed' })
    .select('*').limit(100) as AuthorizationRow[];
  let n = 0;
  for (const r of rows) {
    try { if (await cancelOne(r, Number(r.user_id), 'retry after a failed cancellation', { trigger: 'retry' })) n++; } catch { /* next minute */ }
  }
  return n;
}

/**
 * Pending and filed rows of keys that can no longer act (expired, revoked, the owner's credentials changed or the
 * owner disabled) are cancelled, with their approvals (in tenant T's context): expiry is not a revocation, and a row
 * filed by a request already in flight when its key was revoked may have missed the revocation's sweep.
 */
export async function cancelDeadKeyRows(tenantId: number): Promise<number> {
  const rows = await db('mcp_authorizations').where({ tenant_id: tenantId }).whereIn('state', ['pending', 'filed'])
    .where((w) => w.whereNull('error_code').orWhereNot('error_code', 'cancelFailed')).select('*').limit(500) as AuthorizationRow[];
  if (rows.length === 0) return 0;
  const keys = await keysWithOwners(rows.map((r) => String(r.key_id)));
  let n = 0;
  for (const r of rows) {
    const why = keyDeadReason(keys.get(String(r.key_id)));
    if (!why) continue;
    const k = keys.get(String(r.key_id));
    const keyRef = k ? { id: String(k.row.public_id), name: String(k.row.name) } : undefined;
    try { if (await cancelOne(r, Number(r.user_id), `key no longer active (${why})`, { trigger: why }, keyRef)) n++; } catch { /* marked cancelFailed: retried */ }
  }
  return n;
}

/** The rows of a user (any tenant, policy rls_self_read), newest first, with their key's name. */
export async function listOwn(userId: number, o: { state?: 'pending' | 'filed' | 'all' | 'open'; keyRowId?: string; limit?: number } = {}): Promise<McpAuthorizationView[]> {
  return asNone(userActor(userId), async () => {
    const q = db('mcp_authorizations as a').leftJoin('access_keys as k', 'k.id', 'a.key_id').where('a.user_id', userId)
      .orderBy('a.created_at', 'desc').limit(Math.min(200, Math.max(1, o.limit ?? 50)))
      .select([...AUTH_COLUMNS, 'k.name as key_name', 'k.public_id as key_public_id']);
    if (o.keyRowId) q.where('a.key_id', o.keyRowId);
    if (o.state === 'pending') q.where('a.state', 'pending').where('a.expires_at', '>', new Date());
    else if (o.state === 'filed') q.where('a.state', 'filed');
    else if (o.state === 'open') q.whereIn('a.state', ['pending', 'filed', 'executing']);
    const rows = await q as AuthorizationRow[];
    return rows.map((r) => authorizationView(r));
  });
}
