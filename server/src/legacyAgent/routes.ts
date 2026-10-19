import { randomBytes } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import {
  LEGACY_AGENT_CONSOLE_TYPES, LEGACY_AGENT_PACKAGE, LEGACY_AGENT_TOKEN_BOUNDS,
  type DeviceCapability, type LegacyAgentCommandView, type LegacyAgentDeviceDetail, type LegacyAgentDeviceView,
  type LegacyAgentPackageView, type LegacyAgentReleaseView, type LegacyAgentTokenCreated, type LegacyAgentTokenView,
} from '@obligarth/shared';
import { audit } from '../audit';
import { config } from '../config';
import { db } from '../db';
import { userActor } from '../db/context';
import { guard, GuardStepUpError } from '../guard';
import { asAppError } from '../guard/approvals';
import { AppError } from '../middleware/errorHandler';
import { requireTenantCapability } from '../middleware/rbac';
import { activeRequester, refuse, type ApprovalExecution } from '../services/approval.service';
import { parseRequestDeviceId, resolveRequestDevice } from '../services/deviceScope.service';
import { sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { permissionService } from '../services/permission.service';
import { applyRestriction } from '../services/restriction.service';
import { vault } from '../vault';
import { forgetKnoxKey, KNOX_PURPOSE, knoxSecretIdOf } from './agentConfig';
import { cancelOpenOfDevice, commandSpecOrNull, ERASE_ACTION, legacyAgentCommands, LOCK_ACTION, type CommandSpec, type EnqueueOutcome } from './commands';
import { looksLikeApk, receiveApk } from './packages';
import { currentServerKey } from './serverKey';
import { sha256Hex } from './signature';

// =============================================================================
// Console API of the bridge agent (docs: agent-pont-android §7), mounted at
// /api/legacy-agent behind the session and the tenant (requireAuth,
// requireTenant): every read and write is the session's tenant's; a device
// out of reach answers like an unknown one (404).
//   GET  /devices                       the agents of the tenant the caller sees
//   GET  /devices/:id                   one agent: satellite, status items, apps
//   GET  /devices/:id/commands          its queue
//   POST /devices/:id/commands          capability of the type, restriction → 202
//   POST /commands/bulk                 the same on 500 devices at most
//   POST /commands/:commandId/cancel    a pending command, not guarded
//   POST /actions                       lock / erase: the guard engine (its floors, delays, confirmation)
//   POST /devices/:id/revoke            restriction legacy_agent.revoke (floor sensitive)
//   GET  /tokens, POST /tokens, POST /tokens/:id/revoke     mdm.enrollment.manage
//   GET  /packages, POST /packages      mdm.apps.manage (POST: the raw APK)
//   GET  /releases                      the versions of the agent offered to agent.update
//   GET  /settings, PUT /settings/knox  the tenant's Knox licence key (sealed; never returned)
// The guarded types (device.wipe, device.lock) are refused on the command
// routes (409 guardedActionRequired): /actions goes through the engine.
// =============================================================================

const router = Router();

const keyOfUser = (req: Request): string => `u:${req.session?.userId ?? 'anonymous'}`;
const limitedHandler = (_q: Request, res: Response): void => { res.status(429).json({ success: false, error: 'Too many requests', code: 'rateLimited' }); };
const enqueueLimiter = rateLimit({ windowMs: 60_000, max: 60, keyGenerator: keyOfUser, standardHeaders: true, legacyHeaders: false, handler: limitedHandler });
const bulkLimiter = rateLimit({ windowMs: 60_000, max: 5, keyGenerator: keyOfUser, standardHeaders: true, legacyHeaders: false, handler: limitedHandler });
const tokenLimiter = rateLimit({ windowMs: 60_000, max: 20, keyGenerator: keyOfUser, standardHeaders: true, legacyHeaders: false, handler: limitedHandler });
const uploadLimiter = rateLimit({ windowMs: 60_000, max: 10, keyGenerator: keyOfUser, standardHeaders: true, legacyHeaders: false, handler: limitedHandler });

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA_RE = /^[0-9a-f]{64}$/;
const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);
const jsonOf = (v: unknown): any => { if (typeof v !== 'string') return v ?? null; try { return JSON.parse(v); } catch { return null; } };

function body<S extends z.ZodTypeAny>(schema: S, req: Request): z.infer<S> {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  return parsed.data;
}

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: (err?: unknown) => void): void => { fn(req, res).catch(next); };

// ── Devices and capabilities ───────────────────────────────────────────────

/** The device of a route, in the session's tenant (404 otherwise). */
async function deviceOf(req: Request): Promise<number> {
  const id = parseRequestDeviceId(req.params.id);
  if (id === null) throw new AppError(404, 'Device not found');
  const outcome = await resolveRequestDevice(req, id, {});
  if (!outcome.ok) throw new AppError(outcome.status, outcome.error, outcome.status === 403 ? 'capabilityMissing' : undefined);
  if (Number(outcome.device.tenant_id) !== Number(req.tenantId)) throw new AppError(404, 'Device not found');
  return id;
}

async function lacking(req: Request, ids: number[], capability: DeviceCapability): Promise<number[]> {
  if (req.session.role === 'admin') return [];
  const userId = req.session.userId!;
  const out = new Set(await permissionService.devicesLackingCapability(userId, ids, capability));
  for (const id of ids) if (!out.has(id) && !(await permissionService.canWriteDevice(userId, id, false))) out.add(id);
  return [...out];
}

async function visible(req: Request): Promise<number[] | 'all'> {
  if (req.session.role === 'admin') return 'all';
  return permissionService.getVisibleDeviceIds(req.session.userId!, false);
}

const DEVICE_COLUMNS = [
  'd.id', 'd.uuid', 'd.label', 'd.model', 'd.model_name', 'd.os_version', 'd.serial_number', 'd.enrollment_state', 'd.enrolled_at', 'd.group_id',
  'a.agent_id', 'a.api_level', 'a.security_patch', 'a.agent_version_code', 'a.agent_version_name', 'a.admin_active', 'a.knox_state',
  'a.key_storage', 'a.identity_conflict', 'a.last_poll_at', 'a.last_inventory_at', 'a.revoked_at', 'a.revoke_reason',
  db.raw("(SELECT s.value FROM obligarth.device_status_items s WHERE s.tenant_id = d.tenant_id AND s.device_id = d.id AND s.item = 'agent.battery.level') AS battery"),
  db.raw("(SELECT s.value FROM obligarth.device_status_items s WHERE s.tenant_id = d.tenant_id AND s.device_id = d.id AND s.item = 'agent.install.unknown-sources') AS unknown_sources"),
];

function agentsQuery(tenantId: number) {
  return db('legacy_agent_devices as a')
    .join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where('a.tenant_id', tenantId);
}

function deviceView(r: Record<string, any>): LegacyAgentDeviceView {
  const battery = jsonOf(r.battery);
  const unknown = jsonOf(r.unknown_sources);
  return {
    deviceId: Number(r.id), deviceUuid: String(r.uuid), agentId: String(r.agent_id), name: r.label ?? null, model: r.model ?? null,
    modelName: r.model_name ?? null, osVersion: r.os_version ?? null, apiLevel: r.api_level ?? null,
    securityPatch: r.security_patch ? new Date(r.security_patch).toISOString().slice(0, 10) : null, serialNumber: r.serial_number ?? null,
    agentVersionCode: Number(r.agent_version_code), agentVersionName: r.agent_version_name, adminActive: r.admin_active === true,
    knoxState: r.knox_state, keyStorage: r.key_storage, identityConflict: r.identity_conflict === true, enrollmentState: r.enrollment_state,
    lastPollAt: iso(r.last_poll_at), lastInventoryAt: iso(r.last_inventory_at), batteryLevel: typeof battery === 'number' ? battery : null,
    unknownSources: typeof unknown === 'boolean' ? unknown : null, revokedAt: iso(r.revoked_at), revokeReason: r.revoke_reason ?? null,
    enrolledAt: iso(r.enrolled_at) as string, groupId: r.group_id ?? null,
  };
}

function commandView(r: Record<string, any>): LegacyAgentCommandView {
  return {
    id: String(r.id).toLowerCase(), batchId: String(r.batch_id).toLowerCase(), deviceId: Number(r.device_id), type: r.request_type,
    params: jsonOf(r.params) ?? {}, origin: r.origin, state: r.state, holdReason: r.hold_reason ?? null, deliveryCount: Number(r.delivery_count ?? 0),
    createdAt: iso(r.created_at) as string, notBefore: iso(r.not_before), expiresAt: iso(r.expires_at) as string, deliveredAt: iso(r.delivered_at),
    completedAt: iso(r.completed_at), resultCode: r.result_code ?? null, resultDetail: jsonOf(r.result_detail), requestedBy: r.requested_by ?? null,
    reason: r.reason ?? null, guardActionUuid: r.guard_action_uuid ? String(r.guard_action_uuid).toLowerCase() : null,
  };
}

// GET /api/legacy-agent/devices?q=&conflict=1&adminInactive=1&silent=1&revoked=1
router.get('/devices', wrap(async (req, res) => {
  const tenantId = req.tenantId!;
  let q = agentsQuery(tenantId);
  const seen = await visible(req);
  if (seen !== 'all') q = q.whereRaw('d.id = ANY (?::int[])', [seen]);
  if (req.query.revoked !== '1') q = q.whereNull('a.revoked_at');
  if (req.query.conflict === '1') q = q.where('a.identity_conflict', true);
  if (req.query.adminInactive === '1') q = q.where('a.admin_active', false);
  if (req.query.silent === '1') q = q.where((w) => w.whereNull('a.last_poll_at').orWhere('a.last_poll_at', '<', new Date(Date.now() - 24 * 3_600_000)));
  const text = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 100) : '';
  if (text) {
    const like = `%${text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    q = q.where((w) => w.whereILike('d.label', like).orWhereILike('d.serial_number', like).orWhereILike('d.model', like));
  }
  const rows = await q.orderBy('d.id').limit(5000).select(DEVICE_COLUMNS) as Array<Record<string, any>>;
  res.json({ success: true, data: rows.map(deviceView) });
}));

// GET /api/legacy-agent/devices/:id
router.get('/devices/:id', wrap(async (req, res) => {
  const id = await deviceOf(req);
  const tenantId = req.tenantId!;
  const r = await agentsQuery(tenantId).where('d.id', id).first([...DEVICE_COLUMNS, 'a.android_id', 'a.claimed_serial', 'a.samsung_serial', 'a.imeis',
    'a.hints', 'a.knox_info', 'a.poll_seconds', 'a.clock_offset_s']) as Record<string, any> | undefined;
  if (!r) throw new AppError(404, 'Device not found');
  const status = await db('device_status_items').where({ tenant_id: tenantId, device_id: id }).where('item', 'like', 'agent.%').orderBy('item')
    .select('item', 'value', 'observed_at') as Array<{ item: string; value: unknown; observed_at: Date }>;
  const apps = await db('device_apps').where({ tenant_id: tenantId, device_id: id, source: 'agent_report' }).orderBy('identifier').limit(2000)
    .select('identifier', 'name', 'version', 'short_version', 'managed') as Array<Record<string, any>>;
  const detail: LegacyAgentDeviceDetail = {
    ...deviceView(r), androidId: r.android_id ?? null, claimedSerial: r.claimed_serial ?? null, samsungSerial: r.samsung_serial ?? null,
    imeis: Array.isArray(r.imeis) ? r.imeis : [], hints: jsonOf(r.hints), knoxInfo: jsonOf(r.knox_info), pollSeconds: r.poll_seconds ?? null,
    clockOffsetSeconds: r.clock_offset_s ?? null,
    status: status.map((s) => ({ item: s.item, value: jsonOf(s.value), observedAt: iso(s.observed_at) as string })),
    apps: apps.map((a) => ({ packageName: a.identifier, label: a.name ?? null, versionName: a.version ?? null, versionCode: a.short_version ?? null, managed: a.managed === true })),
  };
  res.json({ success: true, data: detail });
}));

// GET /api/legacy-agent/devices/:id/commands
router.get('/devices/:id/commands', wrap(async (req, res) => {
  const id = await deviceOf(req);
  const rows = await db('legacy_agent_commands').where({ tenant_id: req.tenantId!, device_id: id }).orderBy('created_at', 'desc').orderBy('id', 'desc')
    .limit(100).select('*') as Array<Record<string, any>>;
  res.json({ success: true, data: rows.map(commandView) });
}));

// ── Commands ─────────────────────────────────────────────────────────────────

const CommandBody = z.object({
  type: z.string().max(32), params: z.record(z.unknown()).optional(),
  reason: z.string().trim().max(500).optional(), ticket: z.string().trim().max(100).optional(),
}).strict();
const BulkBody = CommandBody.extend({ deviceIds: z.array(z.union([z.number(), z.string()])).min(1).max(500) }).strict();

/** The type of a console request and its full parameters: a package or a release of the tenant resolved here. */
async function consoleCommand(tenantId: number, type: string, raw: Record<string, unknown> | undefined): Promise<{ spec: CommandSpec; params: Record<string, unknown> }> {
  const spec = commandSpecOrNull(type);
  if (!spec) throw new AppError(422, 'Unknown command type', 'unknownRequestType');
  if (spec.guardedBy) throw new AppError(409, 'This command goes through its guarded action', 'guardedActionRequired', { actionKey: spec.guardedBy });
  if (!(LEGACY_AGENT_CONSOLE_TYPES as readonly string[]).includes(type)) throw new AppError(422, 'Unknown command type', 'unknownRequestType');
  let params: Record<string, unknown> = raw ?? {};
  if (type === 'app.install') {
    const packageId = String((raw ?? {}).packageId ?? '');
    if (!UUID_RE.test(packageId)) throw new AppError(422, 'app.install: packageId is required', 'invalidParams');
    const p = await db('legacy_agent_packages').where({ tenant_id: tenantId, id: packageId }).first() as Record<string, any> | undefined;
    if (!p) throw new AppError(404, 'Package not found');
    params = {
      packageId: String(p.id), packageName: p.package_name, versionCode: Number(p.version_code), sha256: p.sha256, size: Number(p.size_bytes),
      ...(p.signer_sha256 ? { signerSha256: p.signer_sha256 } : {}),
    };
  } else if (type === 'agent.update') {
    const releaseId = String((raw ?? {}).releaseId ?? '');
    if (!UUID_RE.test(releaseId)) throw new AppError(422, 'agent.update: releaseId is required', 'invalidParams');
    const r = await db('legacy_agent_releases').where({ id: releaseId }).whereNull('withdrawn_at').first() as Record<string, any> | undefined;
    if (!r) throw new AppError(404, 'Release not found');
    params = { releaseId: String(r.id), versionCode: Number(r.version_code), sha256: r.sha256, size: Number(r.size_bytes) };
  }
  const parsed = spec.params.safeParse(params);
  if (!parsed.success) throw new AppError(422, `${type}: ${parsed.error.issues[0]?.message ?? 'invalid parameters'}`, 'invalidParams');
  return { spec, params: parsed.data };
}

const enqueueResult = (o: EnqueueOutcome) => ({ batchId: o.batchId, commandIds: o.commandIds, targets: o.targets, refused: o.refused, held: o.held, replayed: o.replayed });

function idempotencyKey(req: Request): string | undefined {
  const v = req.header('Idempotency-Key');
  if (v === undefined) return undefined;
  if (!/^[A-Za-z0-9_.-]{8,100}$/.test(v)) throw new AppError(400, 'Idempotency-Key: 8 to 100 characters (letters, digits, . _ -)', 'invalidRequest');
  return `console:${req.session.userId}:${v}`;
}

// POST /api/legacy-agent/devices/:id/commands
router.post('/devices/:id/commands', enqueueLimiter, wrap(async (req, res) => {
  const id = await deviceOf(req);
  const b = body(CommandBody, req);
  const tenantId = req.tenantId!;
  const { spec, params } = await consoleCommand(tenantId, b.type, b.params);
  if ((await lacking(req, [id], spec.capability)).length > 0) throw new AppError(403, `Capability '${spec.capability}' not permitted for your team`, 'capabilityMissing');
  const key = idempotencyKey(req);
  if (spec.restrictionKey) {
    const ok = await applyRestriction(res, {
      req, actionKey: spec.restrictionKey, deviceIds: [id], approvalRequestType: 'legacy_agent_action',
      approvalDescription: `${spec.type} on 1 Android agent device`,
      approvalPayload: { action: 'legacy_agent.command', type: spec.type, deviceIds: [id], params, reason: b.reason ?? null, ticket: b.ticket ?? null },
    });
    if (!ok) return;
  }
  const auditCtx = await audit.fromRequest(req, tenantId);
  const o = await db.transaction((trx) => legacyAgentCommands.enqueue(trx, {
    tenantId, requestType: spec.type, deviceIds: [id], params, origin: 'console', actor: `u:${req.session.userId}`,
    requestedBy: req.session.userId!, reason: b.reason, ticket: b.ticket, idempotencyKey: key, auditCtx,
  }));
  if (o.targets === 0 && o.refused[0]) throw new AppError(422, `The command cannot be sent to this device (${o.refused[0].code})`, 'commandRefused', { refusal: o.refused[0].code });
  res.status(202).json({ success: true, data: enqueueResult(o) });
}));

// POST /api/legacy-agent/commands/bulk
router.post('/commands/bulk', bulkLimiter, wrap(async (req, res) => {
  const b = body(BulkBody, req);
  const tenantId = req.tenantId!;
  const parsed = b.deviceIds.map(parseRequestDeviceId);
  const ids = [...new Set(parsed.filter((n): n is number => n !== null))];
  if (parsed.some((n) => n === null) || ids.length === 0) throw new AppError(404, 'No matching devices in this tenant');
  const found = await db('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [ids]).pluck('id') as number[];
  const seen = await visible(req);
  if (found.length !== ids.length || (seen !== 'all' && ids.some((id) => !seen.includes(id)))) throw new AppError(404, 'No matching devices in this tenant');
  const { spec, params } = await consoleCommand(tenantId, b.type, b.params);
  const without = await lacking(req, ids, spec.capability);
  if (without.length > 0) throw new AppError(403, 'Capability not permitted on some devices', 'capabilityMissing', { count: without.length });
  const key = idempotencyKey(req);
  if (spec.restrictionKey) {
    const ok = await applyRestriction(res, {
      req, actionKey: spec.restrictionKey, deviceIds: ids, approvalRequestType: 'legacy_agent_action',
      approvalDescription: `${spec.type} on ${ids.length} Android agent device(s)`,
      approvalPayload: { action: 'legacy_agent.command', type: spec.type, deviceIds: ids, params, reason: b.reason ?? null, ticket: b.ticket ?? null },
    });
    if (!ok) return;
  }
  const auditCtx = await audit.fromRequest(req, tenantId);
  const o = await db.transaction((trx) => legacyAgentCommands.enqueue(trx, {
    tenantId, requestType: spec.type, deviceIds: ids, params, origin: 'bulk', actor: `u:${req.session.userId}`,
    requestedBy: req.session.userId!, reason: b.reason, ticket: b.ticket, idempotencyKey: key, auditCtx,
  }));
  res.status(202).json({ success: true, data: enqueueResult(o) });
}));

// POST /api/legacy-agent/commands/:commandId/cancel: a pending command the caller may send (or its author).
router.post('/commands/:commandId/cancel', wrap(async (req, res) => {
  const commandId = String(req.params.commandId ?? '');
  if (!UUID_RE.test(commandId)) throw new AppError(404, 'Command not found');
  const tenantId = req.tenantId!;
  const row = await db('legacy_agent_commands').where({ tenant_id: tenantId, id: commandId.toLowerCase() }).first('device_id', 'request_type', 'requested_by') as
    { device_id: number; request_type: string; requested_by: number | null } | undefined;
  if (!row) throw new AppError(404, 'Command not found');
  const seen = await visible(req);
  if (seen !== 'all' && !seen.includes(Number(row.device_id))) throw new AppError(404, 'Command not found');
  const spec = commandSpecOrNull(row.request_type);
  const author = Number(row.requested_by) === Number(req.session.userId);
  if (!author && (!spec || (await lacking(req, [Number(row.device_id)], spec.capability)).length > 0)) {
    throw new AppError(403, 'Insufficient permissions', 'capabilityMissing');
  }
  const auditCtx = await audit.fromRequest(req, tenantId);
  const r = await db.transaction((trx) => legacyAgentCommands.cancel(trx, tenantId, commandId, `u:${req.session.userId}`, { auditCtx }));
  if (r.result !== 'cancelled') throw new AppError(409, r.result === 'already_delivered' ? 'The command was already delivered' : 'The command is finished', 'notCancellable', { outcome: r.result });
  res.json({ success: true, data: r });
}));

// POST /api/legacy-agent/actions: lock or erase, through the guard engine (its floors, delays, confirmation, approval).
const ActionBody = z.object({
  action: z.enum(['device.lock', 'device.wipe']), deviceIds: z.array(z.union([z.number(), z.string()])).min(1).max(500),
  params: z.object({ wipeExternal: z.boolean().optional() }).strict().optional(),
  reason: z.string().max(500).optional(), ticket: z.string().max(100).optional(), confirm: z.string().max(200).optional(),
}).strict();

router.post('/actions', enqueueLimiter, async (req, res, next) => {
  try {
    const b = body(ActionBody, req);
    const tenantId = req.tenantId!;
    const parsed = b.deviceIds.map(parseRequestDeviceId);
    const ids = [...new Set(parsed.filter((n): n is number => n !== null))];
    if (parsed.some((n) => n === null) || ids.length === 0) throw new AppError(404, 'No matching devices in this tenant');
    const found = await db('devices').where({ tenant_id: tenantId, management_channel: 'legacy_agent' }).whereRaw('id = ANY (?::int[])', [ids]).pluck('id') as number[];
    const seen = await visible(req);
    if (found.length !== ids.length || (seen !== 'all' && ids.some((id) => !seen.includes(id)))) throw new AppError(404, 'No matching devices in this tenant');
    const outcome = await guard.request(req, {
      actionKey: b.action === 'device.wipe' ? ERASE_ACTION : LOCK_ACTION, selection: { deviceIds: ids },
      params: b.action === 'device.wipe' ? { ...(b.params?.wipeExternal !== undefined ? { wipeExternal: b.params.wipeExternal } : {}) } : {},
      reason: b.reason ?? '', ...(b.ticket ? { ticket: b.ticket } : {}), ...(b.confirm !== undefined ? { confirm: b.confirm } : {}),
    });
    res.status(202).json({ success: true, data: outcome });
  } catch (err) {
    if (err instanceof GuardStepUpError) { sendStepUpFailure(res, err.outcome); return; }
    next(asAppError(err) ?? err);
  }
});

// ── Revocation (§5.4) ────────────────────────────────────────────────────────

const RevokeBody = z.object({ reason: z.string().trim().min(3).max(500) }).strict();

/** The revocation itself, in one transaction of the tenant: the satellite, the open commands, the record. */
async function revokeDevice(tenantId: number, deviceId: number, reason: string, actorUserId: number, auditCtx: Awaited<ReturnType<typeof audit.fromRequest>>): Promise<boolean> {
  return db.transaction(async (trx) => {
    const sat = await trx('legacy_agent_devices').where({ tenant_id: tenantId, device_id: deviceId }).forUpdate().first('revoked_at') as { revoked_at: Date | null } | undefined;
    if (!sat) throw new AppError(404, 'Device not found');
    if (sat.revoked_at) return false;
    const now = new Date();
    await trx('legacy_agent_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({ revoked_at: now, revoke_reason: 'console', updated_at: now });
    const cancelled = await cancelOpenOfDevice(trx, tenantId, deviceId);
    await trx('devices').where({ tenant_id: tenantId, id: deviceId }).whereNot('enrollment_state', 'unenrolled')
      .update({ enrollment_state: 'unenrolled', enrollment_state_at: now, unenrolled_at: now, unenroll_reason: 'agent_revoked', updated_at: now });
    await audit.appendInTx(trx, {
      tenantId, action: 'legacy_agent.device_revoked', target: { type: 'device', id: String(deviceId), device: deviceId }, reason,
      details: { cancelledCommands: cancelled, by: actorUserId },
    }, auditCtx);
    return true;
  });
}

router.post('/devices/:id/revoke', wrap(async (req, res) => {
  const id = await deviceOf(req);
  const b = body(RevokeBody, req);
  const tenantId = req.tenantId!;
  if ((await lacking(req, [id], 'mdm:remove')).length > 0) throw new AppError(403, "Capability 'mdm:remove' not permitted for your team", 'capabilityMissing');
  const ok = await applyRestriction(res, {
    req, actionKey: 'legacy_agent.revoke', deviceIds: [id], approvalRequestType: 'legacy_agent_action',
    approvalDescription: 'Revoke 1 Android agent', approvalPayload: { action: 'legacy_agent.revoke', deviceIds: [id], reason: b.reason },
  });
  if (!ok) return;
  const changed = await revokeDevice(tenantId, id, b.reason, req.session.userId!, await audit.fromRequest(req, tenantId));
  res.json({ success: true, data: { revoked: changed } });
}));

// ── Enrollment tokens ────────────────────────────────────────────────────────

const TokenBody = z.object({
  label: z.string().trim().min(1).max(100), groupId: z.number().int().positive().nullable().optional(),
  days: z.number().int().min(1).max(LEGACY_AGENT_TOKEN_BOUNDS.daysMax).optional(),
  maxUses: z.number().int().min(1).max(LEGACY_AGENT_TOKEN_BOUNDS.maxUsesMax).optional(),
}).strict();

function tokenView(r: Record<string, any>): LegacyAgentTokenView {
  const now = Date.now();
  const state = r.revoked_at ? 'revoked' : new Date(r.expires_at).getTime() <= now ? 'expired' : Number(r.uses) >= Number(r.max_uses) ? 'used_up' : 'active';
  return {
    id: String(r.id), publicId: r.public_id, label: r.label, groupId: r.group_id ?? null, maxUses: Number(r.max_uses), uses: Number(r.uses),
    expiresAt: iso(r.expires_at) as string, revokedAt: iso(r.revoked_at), createdAt: iso(r.created_at) as string, lastUsedAt: iso(r.last_used_at), state,
  };
}

const TOKEN_COLUMNS = ['id', 'public_id', 'label', 'group_id', 'max_uses', 'uses', 'expires_at', 'revoked_at', 'created_at', 'last_used_at'];

router.get('/tokens', requireTenantCapability('mdm.enrollment.manage'), wrap(async (req, res) => {
  const rows = await db('legacy_agent_enrollment_tokens').where({ tenant_id: req.tenantId! }).orderBy('created_at', 'desc').limit(500).select(TOKEN_COLUMNS);
  res.json({ success: true, data: rows.map(tokenView) });
}));

router.post('/tokens', requireTenantCapability('mdm.enrollment.manage'), tokenLimiter, wrap(async (req, res) => {
  const b = body(TokenBody, req);
  const tenantId = req.tenantId!;
  if (b.groupId && !(await db('device_groups').where({ tenant_id: tenantId, id: b.groupId }).first('id'))) throw new AppError(404, 'Group not found');
  const key = await currentServerKey();
  if (!key) throw new AppError(503, 'The instance key of the Android agents is unavailable', 'serverKeyMissing');
  const publicId = randomBytes(16).toString('base64url');
  const secret = randomBytes(32).toString('base64url');
  const token = `OLE1.${publicId}.${secret}`;
  const days = b.days ?? LEGACY_AGENT_TOKEN_BOUNDS.daysDefault;
  const now = new Date();
  const auditCtx = await audit.fromRequest(req, tenantId);
  const row = await db.transaction(async (trx) => {
    const [r] = await trx('legacy_agent_enrollment_tokens').insert({
      tenant_id: tenantId, public_id: publicId, secret_sha256: sha256Hex(Buffer.from(secret, 'utf8')), label: b.label, group_id: b.groupId ?? null,
      max_uses: b.maxUses ?? LEGACY_AGENT_TOKEN_BOUNDS.maxUsesDefault, expires_at: new Date(now.getTime() + days * 86_400_000), created_by: req.session.userId!,
      created_at: now,
    }).returning(TOKEN_COLUMNS) as Array<Record<string, any>>;
    await audit.appendInTx(trx, {
      tenantId, action: 'legacy_agent.token_created', target: { type: 'legacy_agent_token', id: String(r.id) },
      details: { label: b.label, groupId: b.groupId ?? null, days, maxUses: Number(r.max_uses) },
    }, auditCtx);
    return r;
  });
  // §4.9: the configuration MobiControl deposits (JSON v1, base64url for the extra 'config'), shown once.
  const conf = { v: 1, server: config.apple.mdmPublicBase ?? '', token, serverKeySha256: key.sha256, knoxLicenseKey: null, hints: { deviceName: null, serial: null, imei: null } };
  const configJson = JSON.stringify(conf);
  const encoded = Buffer.from(configJson, 'utf8').toString('base64url');
  const pkg = LEGACY_AGENT_PACKAGE;
  const script = [
    `sendintent -b "intent:#Intent;action=${pkg}.action.CONFIGURE;package=${pkg};S.config=${encoded};end"`,
    `sendintent -a "intent:#Intent;action=${pkg}.action.ACTIVATE_ADMIN;package=${pkg};end"`,
  ].join('\n');
  const out: LegacyAgentTokenCreated = { ...tokenView(row), token, config: encoded, configJson, script };
  res.setHeader('Cache-Control', 'no-store');
  res.status(201).json({ success: true, data: out });
}));

router.post('/tokens/:tokenId/revoke', requireTenantCapability('mdm.enrollment.manage'), wrap(async (req, res) => {
  const tokenId = String(req.params.tokenId ?? '');
  if (!UUID_RE.test(tokenId)) throw new AppError(404, 'Token not found');
  const tenantId = req.tenantId!;
  const auditCtx = await audit.fromRequest(req, tenantId);
  const done = await db.transaction(async (trx) => {
    const n = await trx('legacy_agent_enrollment_tokens').where({ tenant_id: tenantId, id: tokenId }).whereNull('revoked_at')
      .update({ revoked_at: new Date(), revoked_by: req.session.userId! });
    const exists = n > 0 || !!(await trx('legacy_agent_enrollment_tokens').where({ tenant_id: tenantId, id: tokenId }).first('id'));
    if (!exists) throw new AppError(404, 'Token not found');
    if (n > 0) await audit.appendInTx(trx, { tenantId, action: 'legacy_agent.token_revoked', target: { type: 'legacy_agent_token', id: tokenId } }, auditCtx);
    return n > 0;
  });
  res.json({ success: true, data: { revoked: done } });
}));

// ── Packages (client APKs) ──────────────────────────────────────────────────

const PackageMeta = z.object({
  packageName: z.string().max(255).regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/),
  versionCode: z.string().regex(/^[1-9][0-9]{0,15}$/),
  versionName: z.string().trim().max(64).optional(),
  signerSha256: z.string().transform((s) => s.replace(/:/g, '').toLowerCase()).pipe(z.string().regex(SHA_RE)).optional(),
  label: z.string().trim().max(100).optional(),
}).strict();

function packageView(r: Record<string, any>): LegacyAgentPackageView {
  return {
    id: String(r.id), packageName: r.package_name, versionCode: String(r.version_code), versionName: r.version_name ?? null, sha256: r.sha256,
    sizeBytes: Number(r.size_bytes), signerSha256: r.signer_sha256 ?? null, label: r.label ?? null, createdAt: iso(r.created_at) as string,
  };
}

router.get('/packages', requireTenantCapability('mdm.apps.manage'), wrap(async (req, res) => {
  const rows = await db('legacy_agent_packages').where({ tenant_id: req.tenantId! }).orderBy('created_at', 'desc').limit(1000).select('*');
  res.json({ success: true, data: rows.map(packageView) });
}));

// POST /api/legacy-agent/packages?packageName=&versionCode=&versionName=&signerSha256=&label= (body: the APK)
router.post('/packages', requireTenantCapability('mdm.apps.manage'), uploadLimiter, wrap(async (req, res) => {
  const meta = PackageMeta.safeParse(req.query ?? {});
  if (!meta.success) throw new AppError(400, meta.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  const m = meta.data;
  if (m.packageName === LEGACY_AGENT_PACKAGE || m.packageName.startsWith(`${LEGACY_AGENT_PACKAGE}.`)) {
    throw new AppError(422, 'The agent is updated through its versions, not as a package', 'forbiddenPackage');
  }
  const tenantId = req.tenantId!;
  const file = await receiveApk(req);
  if (!(await looksLikeApk(file.sha256))) throw new AppError(422, 'This file is not an APK (ZIP archive)', 'notAnApk');
  const auditCtx = await audit.fromRequest(req, tenantId);
  const row = await db.transaction(async (trx) => {
    const existing = await trx('legacy_agent_packages').where({ tenant_id: tenantId, sha256: file.sha256 }).first();
    if (existing) return existing;
    const [r] = await trx('legacy_agent_packages').insert({
      tenant_id: tenantId, package_name: m.packageName, version_code: m.versionCode, version_name: m.versionName || null, sha256: file.sha256,
      size_bytes: file.size, signer_sha256: m.signerSha256 ?? null, label: m.label || null, created_by: req.session.userId!,
    }).returning('*') as Array<Record<string, any>>;
    await audit.appendInTx(trx, {
      tenantId, action: 'legacy_agent.package_uploaded', target: { type: 'legacy_agent_package', id: String(r.id) },
      details: { packageName: m.packageName, versionCode: m.versionCode, sha256: file.sha256, size: file.size },
    }, auditCtx);
    return r;
  });
  res.status(201).json({ success: true, data: packageView(row) });
}));

// GET /api/legacy-agent/releases: the versions of the agent an agent.update may name (not withdrawn).
router.get('/releases', wrap(async (_req, res) => {
  const rows = await db('legacy_agent_releases').whereNull('withdrawn_at').orderBy('version_code', 'desc').limit(100).select('*');
  res.json({ success: true, data: rows.map(releaseView) });
}));

export function releaseView(r: Record<string, any>): LegacyAgentReleaseView {
  return {
    id: String(r.id), versionCode: Number(r.version_code), versionName: r.version_name, sha256: r.sha256, sizeBytes: Number(r.size_bytes),
    signerSha256: r.signer_sha256, notes: r.notes ?? null, createdAt: iso(r.created_at) as string, withdrawnAt: iso(r.withdrawn_at),
  };
}

// ── Settings of the tenant: the Knox licence key (§6) ───────────────────────

router.get('/settings', requireTenantCapability('mdm.enrollment.manage'), wrap(async (req, res) => {
  const id = await knoxSecretIdOf(db, req.tenantId!);
  res.json({ success: true, data: { knoxLicenseSet: id !== null } });
}));

const KnoxBody = z.object({ licenseKey: z.string().trim().min(8).max(200).regex(/^[A-Za-z0-9_.:=+/-]+$/).nullable() }).strict();

router.put('/settings/knox', requireTenantCapability('mdm.enrollment.manage'), wrap(async (req, res) => {
  const b = body(KnoxBody, req);
  const tenantId = req.tenantId!;
  const auditCtx = await audit.fromRequest(req, tenantId);
  await db.transaction(async (trx) => {
    const ref = b.licenseKey === null ? null
      : { $secret: await vault.createTenantSecret(tenantId, KNOX_PURPOSE, b.licenseKey, { userId: req.session.userId! }, { trx }) };
    await trx('legacy_agent_settings').insert({ tenant_id: tenantId, knox_license: ref ? JSON.stringify(ref) : null, updated_by: req.session.userId!, updated_at: new Date() })
      .onConflict('tenant_id').merge(['knox_license', 'updated_by', 'updated_at']);
    await audit.appendInTx(trx, { tenantId, action: 'legacy_agent.knox_key_set', target: { type: 'tenant', id: String(tenantId) }, details: { set: ref !== null } }, auditCtx);
  });
  forgetKnoxKey(tenantId);
  res.json({ success: true, data: { knoxLicenseSet: b.licenseKey !== null } });
}));

/** The console API of the bridge agent, mounted at /api/legacy-agent (routes/index.ts), after requireTenant. */
export function createLegacyAgentRouter(): Router {
  return router;
}

// ── Approvals of the restricted commands and revocations (§5.4) ─────────────

/**
 * The executor of an approved 'legacy_agent_action' request: as the requester, whose rights and devices are read
 * again; a guarded type never goes this way.
 */
export async function executeLegacyAgentAction(x: ApprovalExecution): Promise<string | void> {
  const p = (x.payload ?? {}) as { action?: unknown; type?: unknown; deviceIds?: unknown; params?: unknown; reason?: unknown; ticket?: unknown };
  if (!Array.isArray(p.deviceIds)) refuse('Malformed request');
  const ids = [...new Set((p.deviceIds as unknown[]).map(parseRequestDeviceId).filter((n): n is number => n !== null))];
  if (ids.length === 0 || ids.length > 500) refuse('Malformed request');
  const requester = await activeRequester(x.requesterId);
  const auditCtx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  if (p.action === 'legacy_agent.revoke') {
    if (!requester.isPlatformAdmin && (await permissionService.devicesLackingCapability(x.requesterId, ids, 'mdm:remove')).length > 0) {
      refuse('The requester no longer holds the capability to remove these devices');
    }
    let n = 0;
    for (const id of ids) if (await revokeDevice(x.tenantId, id, typeof p.reason === 'string' ? p.reason : 'approved revocation', x.requesterId, auditCtx)) n++;
    return n === ids.length ? undefined : `${ids.length - n} device(s) already revoked`;
  }
  if (p.action !== 'legacy_agent.command' || typeof p.type !== 'string') refuse('Malformed request');
  const spec = commandSpecOrNull(p.type);
  if (!spec || spec.guardedBy || !(LEGACY_AGENT_CONSOLE_TYPES as readonly string[]).includes(spec.type)) refuse('This command type is no longer available');
  const s = spec as CommandSpec;
  const params = (p.params && typeof p.params === 'object' && !Array.isArray(p.params) ? p.params : {}) as Record<string, unknown>;
  if (!s.params.safeParse(params).success) refuse('The parameters of the command are no longer valid');
  const found = await db('devices').where({ tenant_id: x.tenantId }).whereRaw('id = ANY (?::int[])', [ids]).pluck('id') as number[];
  if (found.length !== ids.length) refuse('Some devices of this request are no longer in the tenant');
  if (!requester.isPlatformAdmin) {
    const without = new Set(await permissionService.devicesLackingCapability(x.requesterId, ids, s.capability));
    for (const id of ids) if (!without.has(id) && !(await permissionService.canWriteDevice(x.requesterId, id, false))) without.add(id);
    if (without.size > 0) refuse('The requester no longer holds the capability of this command on every device');
  }
  let o: EnqueueOutcome;
  try {
    o = await db.transaction((trx) => legacyAgentCommands.enqueue(trx, {
      tenantId: x.tenantId, requestType: s.type, deviceIds: ids, params, origin: 'approval', actor: `u:${x.requesterId}`,
      requestedBy: x.requesterId, reason: typeof p.reason === 'string' ? p.reason : undefined, ticket: typeof p.ticket === 'string' ? p.ticket : undefined,
      approvalId: x.approvalId, auditCtx, ...(x.approvalId ? { idempotencyKey: `approval:${x.approvalId}` } : {}),
    }));
  } catch (err) {
    const e = err as { statusCode?: number; message?: string; code?: string };
    if (e.statusCode && e.statusCode < 500) refuse(`${e.code ?? 'refused'}: ${e.message ?? 'the command was refused'}`);
    throw err;
  }
  if (o.targets === 0) refuse(`No device could take the command (${o.refused[0]?.code ?? 'refused'})`);
  if (o.refused.length > 0) return `${o.refused.length} device(s) set aside`;
  return undefined;
}

