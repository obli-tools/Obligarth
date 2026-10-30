import type { Knex } from 'knex';
import type { LegacyAgentCommandView, LegacyAgentDeviceDetail, LegacyAgentDeviceView, LegacyAgentPackageView, LegacyAgentReleaseView } from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../audit';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import type { GateOutcome, RestrictionGate } from '../mcp/gate';
import { commandSpecOrNull, legacyAgentCommands, POLICY_COMMAND_TYPES, type EnqueueOutcome } from './commands';
import { agentsQuery, commandView, consoleCommand, DEVICE_COLUMNS, deviceView, packageView, releaseView } from './routes';

// =============================================================================
// The console of the bridge agent without a request (docs: specs mcp-server
// §8 step 14): the reads and the command requests of legacyAgent/routes.ts for
// an explicit caller, its tenant and a restriction gate, so that the MCP server
// (an agent through a key, then the human approving it) runs the console's own
// rules: the type's capability on every device with write access (a platform
// administrator bypasses, as the console), the matrix through the gate, the same
// approval payload, the queue's own checks. The console routes are unchanged;
// they share the helpers exported by routes.ts.
// =============================================================================

export interface ConsoleCaller {
  userId: number;
  isPlatformAdmin: boolean;
  tenantId: number;
  auditCtx: AuditWriteContext;
  /** A second request with the same key returns the first outcome (the approval of an authorization: 'mcp-auth:<id>'). */
  idempotencyKey?: string;
}

/** The devices of `ids` the caller lacks the capability on (write access + the capability), [] for a platform admin. */
export async function lackingCapability(caller: Pick<ConsoleCaller, 'userId' | 'isPlatformAdmin'>, ids: number[], capability: Parameters<typeof permissionService.devicesLackingCapability>[2]): Promise<number[]> {
  if (caller.isPlatformAdmin) return [];
  const out = new Set(await permissionService.devicesLackingCapability(caller.userId, ids, capability));
  for (const id of ids) if (!out.has(id) && !(await permissionService.canWriteDevice(caller.userId, id, false))) out.add(id);
  return [...out];
}

export interface ListFilters {
  q?: string;
  conflict?: boolean;
  adminInactive?: boolean;
  silent?: boolean;
  revoked?: boolean;
  limit: number;
  offset: number;
}

/** GET /devices of the console, for a set of device ids already narrowed by the caller ('all' or ids). */
export async function listDevices(tenantId: number, f: ListFilters, deviceIds: number[] | 'all'): Promise<{ items: LegacyAgentDeviceView[]; total: number }> {
  let q = agentsQuery(tenantId);
  if (deviceIds !== 'all') {
    if (deviceIds.length === 0) return { items: [], total: 0 };
    q = q.whereRaw('d.id = ANY (?::int[])', [deviceIds]);
  }
  if (!f.revoked) q = q.whereNull('a.revoked_at');
  if (f.conflict) q = q.where('a.identity_conflict', true);
  if (f.adminInactive) q = q.where('a.admin_active', false);
  if (f.silent) q = q.where((w) => w.whereNull('a.last_poll_at').orWhere('a.last_poll_at', '<', new Date(Date.now() - 24 * 3_600_000)));
  const text = (f.q ?? '').trim().slice(0, 100);
  if (text) {
    const like = `%${text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    q = q.where((w) => w.whereILike('d.label', like).orWhereILike('d.serial_number', like).orWhereILike('d.model', like));
  }
  const total = Number((await q.clone().clearSelect().count<{ n: string }[]>('d.id as n').first())?.n ?? 0);
  const rows = await q.orderBy('d.id').limit(f.limit).offset(f.offset).select(DEVICE_COLUMNS) as Array<Record<string, any>>;
  return { items: rows.map(deviceView), total };
}

/** GET /devices/:id of the console (the device already checked by the caller). */
export async function deviceDetail(tenantId: number, id: number): Promise<LegacyAgentDeviceDetail | null> {
  const r = await agentsQuery(tenantId).where('d.id', id).first([...DEVICE_COLUMNS, 'a.android_id', 'a.claimed_serial', 'a.samsung_serial', 'a.imeis',
    'a.hints', 'a.knox_info', 'a.poll_seconds', 'a.clock_offset_s']) as Record<string, any> | undefined;
  if (!r) return null;
  const jsonOf = (v: unknown): any => { if (typeof v !== 'string') return v ?? null; try { return JSON.parse(v); } catch { return null; } };
  const status = await db('device_status_items').where({ tenant_id: tenantId, device_id: id }).where('item', 'like', 'agent.%').orderBy('item')
    .select('item', 'value', 'observed_at') as Array<{ item: string; value: unknown; observed_at: Date }>;
  const apps = await db('device_apps').where({ tenant_id: tenantId, device_id: id, source: 'agent_report' }).orderBy('identifier').limit(2000)
    .select('identifier', 'name', 'version', 'short_version', 'managed', 'is_system') as Array<Record<string, any>>;
  return {
    ...deviceView(r), androidId: r.android_id ?? null, claimedSerial: r.claimed_serial ?? null, samsungSerial: r.samsung_serial ?? null,
    imeis: Array.isArray(r.imeis) ? r.imeis : [], hints: jsonOf(r.hints), knoxInfo: jsonOf(r.knox_info), pollSeconds: r.poll_seconds ?? null,
    clockOffsetSeconds: r.clock_offset_s ?? null,
    status: status.map((s) => ({ item: s.item, value: jsonOf(s.value), observedAt: new Date(s.observed_at).toISOString() })),
    apps: apps.map((a) => ({ packageName: a.identifier, label: a.name ?? null, versionName: a.version ?? null, versionCode: a.short_version ?? null, managed: a.managed === true, system: a.is_system === true })),
  };
}

/** GET /devices/:id/commands of the console: the last 100, newest first. */
export async function deviceCommands(tenantId: number, id: number, state: 'open' | 'final' | 'all', limit = 100): Promise<LegacyAgentCommandView[]> {
  const q = db('legacy_agent_commands').where({ tenant_id: tenantId, device_id: id }).orderBy('created_at', 'desc').orderBy('id', 'desc')
    .limit(Math.min(100, Math.max(1, limit)));
  if (state === 'open') q.whereIn('state', ['pending', 'sent']);
  else if (state === 'final') q.whereNotIn('state', ['pending', 'sent']);
  return (await q.select('*') as Array<Record<string, any>>).map(commandView);
}

/** One command of the tenant (its device to be checked by the caller), or null. */
export async function commandOf(tenantId: number, commandId: string): Promise<LegacyAgentCommandView | null> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(commandId)) return null;
  const r = await db('legacy_agent_commands').where({ tenant_id: tenantId, id: commandId.toLowerCase() }).first('*') as Record<string, any> | undefined;
  return r ? commandView(r) : null;
}

/** GET /packages of the console (the caller checked mdm.apps.manage). */
export async function listPackages(tenantId: number): Promise<LegacyAgentPackageView[]> {
  const rows = await db('legacy_agent_packages').where({ tenant_id: tenantId }).orderBy('created_at', 'desc').limit(1000).select('*');
  return rows.map(packageView);
}

/** GET /releases of the console: the versions an agent.update may name (not withdrawn). */
export async function listReleases(): Promise<LegacyAgentReleaseView[]> {
  const rows = await db('legacy_agent_releases').whereNull('withdrawn_at').orderBy('version_code', 'desc').limit(100).select('*');
  return rows.map(releaseView);
}

export interface CommandRequest {
  type: string;
  params?: Record<string, unknown>;
  deviceIds: number[];
  reason?: string;
  ticket?: string;
  origin: 'console' | 'bulk';
}

export type CommandOutcome =
  | { kind: 'enqueued'; outcome: EnqueueOutcome }
  | { kind: 'gated'; gate: Exclude<GateOutcome, { ok: true }> };

/**
 * A command request of the console (POST /devices/:id/commands and /commands/bulk) for an explicit caller: the type
 * and its parameters (a package or a release resolved in the tenant), the devices of the tenant, the capability of
 * the type on each (write access), the matrix through the gate (the console's approval payload), then the queue in
 * one transaction; `inTx` runs in that transaction after the enqueue (the end of an approved authorization commits
 * with its commands).
 */
export async function requestCommand(caller: ConsoleCaller, r: CommandRequest, gate: RestrictionGate,
  opts: { inTx?: (trx: Knex.Transaction, outcome: EnqueueOutcome) => Promise<void> } = {}): Promise<CommandOutcome> {
  const tenantId = caller.tenantId;
  const ids = [...new Set(r.deviceIds.map(Number))];
  if (ids.length === 0) throw new AppError(404, 'No matching devices in this tenant');
  const found = await db('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [ids]).pluck('id') as number[];
  if (found.length !== ids.length) throw new AppError(404, 'No matching devices in this tenant');
  const { spec, params } = await consoleCommand(tenantId, r.type, r.params);
  const without = await lackingCapability(caller, ids, spec.capability);
  if (without.length > 0) throw new AppError(403, `Capability '${spec.capability}' not permitted on some devices`, 'capabilityMissing', { count: without.length });
  // The commands of the agent policy also need mdm.policies.manage, as on the console (lot PONT-POL §8.5).
  if (POLICY_COMMAND_TYPES.includes(spec.type) && !caller.isPlatformAdmin
    && !(await permissionService.userHasTenantCapability(caller.userId, tenantId, 'mdm.policies.manage'))) {
    throw new AppError(403, "Capability 'mdm.policies.manage' not permitted for your team", 'capabilityMissing');
  }
  if (spec.restrictionKey) {
    const g = await gate.check({
      tenantId, actionKey: spec.restrictionKey, deviceIds: ids, approvalRequestType: 'legacy_agent_action',
      approvalDescription: ids.length === 1 ? `${spec.type} on 1 Android agent device` : `${spec.type} on ${ids.length} Android agent device(s)`,
      approvalPayload: { action: 'legacy_agent.command', type: spec.type, deviceIds: ids, params, reason: r.reason ?? null, ticket: r.ticket ?? null },
    });
    if (!g.ok) return { kind: 'gated', gate: g };
  }
  const o = await db.transaction(async (trx) => {
    const out = await legacyAgentCommands.enqueue(trx, {
      tenantId, requestType: spec.type, deviceIds: ids, params, origin: r.origin, actor: `u:${caller.userId}`,
      requestedBy: caller.userId, reason: r.reason, ticket: r.ticket, idempotencyKey: caller.idempotencyKey, auditCtx: caller.auditCtx,
    });
    if (opts.inTx) await opts.inTx(trx, out);
    return out;
  });
  if (o.targets === 0 && o.refused[0]) {
    throw new AppError(422, `The command cannot be sent to this device (${o.refused[0].code})`, 'commandRefused', { refusal: o.refused[0].code });
  }
  return { kind: 'enqueued', outcome: o };
}

/**
 * The cancellation of a pending command (POST /commands/:commandId/cancel) for an explicit caller: the device seen by
 * the caller, then its author, or the capability of the type with write access. The MCP tool checks its perimeter
 * before.
 */
export async function cancelCommand(caller: ConsoleCaller, commandId: string): Promise<{ deviceId: number; result: string }> {
  const tenantId = caller.tenantId;
  const row = await db('legacy_agent_commands').where({ tenant_id: tenantId, id: commandId.toLowerCase() }).first('device_id', 'request_type', 'requested_by') as
    { device_id: number; request_type: string; requested_by: number | null } | undefined;
  if (!row) throw new AppError(404, 'Command not found');
  if (!caller.isPlatformAdmin && !(await permissionService.canReadDevice(caller.userId, Number(row.device_id), false))) throw new AppError(404, 'Command not found');
  const spec = commandSpecOrNull(row.request_type);
  const author = Number(row.requested_by) === Number(caller.userId);
  if (!author && (!spec || (await lackingCapability(caller, [Number(row.device_id)], spec.capability)).length > 0)) {
    throw new AppError(403, 'Insufficient permissions', 'capabilityMissing');
  }
  const r = await db.transaction((trx) => legacyAgentCommands.cancel(trx, tenantId, commandId, `u:${caller.userId}`, { auditCtx: caller.auditCtx }));
  if (r.result !== 'cancelled') {
    throw new AppError(409, r.result === 'already_delivered' ? 'The command was already delivered' : 'The command is finished', 'notCancellable', { outcome: r.result });
  }
  return r;
}

/** An entry next to a write whose service writes its own (the key, the agent's text marked as such). */
export async function auditToolWrite(trx: Knex.Transaction | null, ctx: AuditWriteContext, entry: Parameters<typeof audit.append>[0]): Promise<void> {
  if (trx) await audit.appendInTx(trx, entry, ctx, { onFailure: 'spool' });
  else await audit.append(entry, ctx);
}
