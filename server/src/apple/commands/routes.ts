import { Router, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import type {
  DeviceCapability, MdmCommandView, MdmDeviceAction, MdmEnqueueResult, MdmRefusalCode, MdmTargetState, MdmTargetView, NanoEnrollType,
} from '@obligarth/shared';
import { MDM_COMMAND_ORIGINS, MDM_TARGET_STATES } from '@obligarth/shared';
import { audit } from '../../audit';
import { db } from '../../db';
import { userActor } from '../../db/context';
import { guard, GuardStepUpError } from '../../guard';
import { tenantFrozen as frozenFor } from '../../guard/frozen';
import { asAppError } from '../../guard/approvals';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { activeRequester, refuse, type ApprovalExecution } from '../../services/approval.service';
import { parseRequestDeviceId, resolveRequestDevice } from '../../services/deviceScope.service';
import { sendStepUpFailure } from '../../services/deviceKey/stepUpProof';
import { permissionService } from '../../services/permission.service';
import { applyRestriction } from '../../services/restriction.service';
import { config } from '../../config';
import { edgeActorOf } from '../actors';
import { resolveInTx } from '../alerts/service';
import { deviceTimeline } from '../devices/events';
import { privacyRulesFor } from '../devices/privacy';
import { appleEdge } from '../edge/instance';
import { rethrowForConsole } from '../edge/appError';
import { mdmCommands, refusalOf, type EnqueueOutcome } from './bus';
import { commandSpecList, commandSpecOrNull, guardedActionOf, REMOVE_MANAGEMENT_ACTION, type CommandSpec } from './catalog';
import { refreshInventoryNow } from './inventory';
import { PlistError, plistFromJson, type PlistDict } from './plist';
import { findSecrets, type SecretFinding } from './sensitive';
import { queueChannelOfDevice, queueChannelOfPlatform } from '../../mdm/registry/queueChannels';

// =============================================================================
// Console API of the command queue (docs: integration-apple-edge §8.12),
// mounted at /api/apple behind the session and the tenant (requireAuth,
// requireTenant): the commands act on the devices of the session's tenant
// only (a device out of reach answers like an unknown one, 404).
//   GET  /devices/:id/actions            the menu of a device, with what makes an action unavailable
//   POST /devices/:id/commands           capability of the type, restriction, step-up → 202
//   POST /commands/bulk                  the same on 500 devices at most
//   POST /devices/:id/remove-management  shortcut of the guarded action mdm.remove_management
//   POST /devices/:id/inventory-refresh  mdm:inventory; 429 within 5 minutes
//   POST /devices/:id/reenroll-allowance mdm:remove; one re-enrollment without proof allowed for 24 hours
//   DELETE /devices/:id/reenroll-allowance  the allowance withdrawn (AE-C0-R2bis, decision of 19/10/2026)
//   GET  /devices/:id/commands           the queue of a device
//   GET  /commands                       the queue of the tenant (devices.manage)
//   GET  /commands/:commandId            one command and its targets the caller sees
//   POST /commands/:commandId/cancel     capability of the type, or the author
//   POST /commands/:commandId/relaunch   capability of the type (network call, outside any transaction)
//   GET  /devices/:id/timeline           the unified timeline (§12.4)
// The guarded types (erase, lock, lost mode, removal of the enrollment profile)
// are refused here (409 guardedActionRequired): they go through the guard
// engine. Enqueueing never needs apple-edge (the submission is a job).
// The queue of every platform (android-amapi §11.5, lot AN-D): the lists and the
// views show the commands of the other platforms too (field platform, absent
// for Apple); a device of another channel (amapi) and a command of another
// platform go to the handlers its module registered (registerQueueChannel):
// creation, cancellation, relaunch (for Android: a new command for one in error).
// =============================================================================

const router = Router();

const keyOfUser = (req: Request): string => `u:${req.session?.userId ?? 'anonymous'}`;
const limited = (res: Response): void => { res.status(429).json({ success: false, error: 'Too many requests', code: 'rateLimited' }); };
/** 60 enqueues a minute and per user; 5 bulk requests a minute. */
const enqueueLimiter = rateLimit({ windowMs: 60_000, max: 60, keyGenerator: keyOfUser, standardHeaders: true, legacyHeaders: false, handler: (_q, res) => limited(res) });
const bulkLimiter = rateLimit({ windowMs: 60_000, max: 5, keyGenerator: keyOfUser, standardHeaders: true, legacyHeaders: false, handler: (_q, res) => limited(res) });

const REQUEST_TYPE = z.string().regex(/^[A-Za-z][A-Za-z0-9]{0,63}$/);
const CommandBody = z.object({
  requestType: REQUEST_TYPE, params: z.record(z.unknown()).optional(),
  reason: z.string().trim().max(500).optional(), ticket: z.string().trim().max(100).optional(),
}).strict();
const BulkBody = CommandBody.extend({ deviceIds: z.array(z.union([z.number(), z.string()])).min(1).max(500) }).strict();
const TargetsBody = z.object({ deviceIds: z.array(z.union([z.number(), z.string()])).min(1).max(10_000).optional() }).strict();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function body<S extends z.ZodTypeAny>(schema: S, req: Request): z.infer<S> {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  return parsed.data;
}

const REFUSAL_CODES: Record<MdmRefusalCode, string> = {
  not_apple: 'notApple', not_enrolled: 'notEnrolled', awaiting_configuration_only: 'awaitingConfigurationOnly', ownership: 'ownership',
  not_supervised: 'notSupervised', no_unlock_token: 'noUnlockToken', already_open: 'alreadyOpen', identity_unavailable: 'identityUnavailable',
  location_disabled: 'locationDisabledByPrivacy',
};

/** The answer for a request whose every device was set aside. */
function refusedError(code: MdmRefusalCode): AppError {
  const c = REFUSAL_CODES[code] ?? 'commandRefused';
  return new AppError(code === 'already_open' || code === 'location_disabled' ? 409 : 422, `The command cannot be sent to this device (${code})`, c);
}

/** The console's enqueue key from the Idempotency-Key header (console:<user>:<value>). */
function idempotencyKey(req: Request): string | undefined {
  const v = req.header('Idempotency-Key');
  if (v === undefined) return undefined;
  if (!/^[A-Za-z0-9_.-]{8,100}$/.test(v)) throw new AppError(400, 'Idempotency-Key: 8 to 100 characters (letters, digits, . _ -)', 'invalidRequest');
  return `console:${req.session.userId}:${v}`;
}

interface DeviceFacts {
  id: number;
  management_channel: string;
  enrollment_state: string;
  ownership: 'corporate' | 'corporate_personal' | 'personal';
  supervised: boolean;
  has_unlock_token: boolean;
  apple: number | null;
  nano_enroll_type: NanoEnrollType | null;
  lost_mode_state: 'off' | 'enabling' | 'on' | 'disabling';
}

async function deviceFacts(tenantId: number, ids: number[]): Promise<Map<number, DeviceFacts>> {
  const rows = await db('devices as d')
    .leftJoin('apple_devices as a', function joinSatellite() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereRaw('d.id = ANY (?::int[])', [ids])
    .select('d.id', 'd.management_channel', 'd.enrollment_state', 'd.ownership', 'd.supervised', 'd.lost_mode_state', 'a.has_unlock_token',
      'a.device_id as apple', 'a.nano_enroll_type') as DeviceFacts[];
  return new Map(rows.map((r) => [Number(r.id), { ...r, id: Number(r.id), has_unlock_token: r.has_unlock_token === true }]));
}

const prerequisite = (spec: CommandSpec<any>, d: DeviceFacts | undefined): MdmRefusalCode | null => refusalOf(spec, d && d.apple !== null ? d : undefined);

/** P0-13 (CNF-02): may the device be located (DeviceLocation), by the tenant's privacy profile of its ownership? Told
 *  before anything is asked of the user; the bus refuses it too (location_disabled), whatever the origin. */
async function locationAllowed(tenantId: number, d: DeviceFacts | undefined): Promise<boolean> {
  if (!d || d.apple === null || !d.nano_enroll_type) return true;   // not an Apple record: prerequisite() says why
  return (await privacyRulesFor(db, tenantId, d.ownership, d.nano_enroll_type)).lostModeLocation;
}

/** prerequisite(), then the privacy profile for a DeviceLocation. */
async function refusalFor(tenantId: number, spec: CommandSpec<any>, d: DeviceFacts | undefined): Promise<MdmRefusalCode | null> {
  const refusal = prerequisite(spec, d);
  if (refusal || spec.requestType !== 'DeviceLocation') return refusal;
  return (await locationAllowed(tenantId, d)) ? null : 'location_disabled';
}

/** Why the menu greys out a lost-mode command given the recorded state of the lost mode (null: nothing to say). */
function lostModeRefusal(requestType: string, state: DeviceFacts['lost_mode_state'] | undefined): 'lostModeOff' | 'lostModeOn' | null {
  if (state === undefined) return null;
  if (['PlayLostModeSound', 'DeviceLocation', 'DisableLostMode'].includes(requestType) && state === 'off') return 'lostModeOff';
  if (requestType === 'EnableLostMode' && (state === 'on' || state === 'enabling')) return 'lostModeOn';
  return null;
}

/** The freeze of the Apple commands (the engine's, or apple-edge's mirror: guard/frozen.ts, lot AN-P). */
const frozen = (tenantId: number): Promise<boolean> => frozenFor(null, tenantId, 'apple_mdm');

/** The device of a route, in the session's tenant (404 otherwise), with the capability asked (403 without it). */
async function deviceOf(req: Request, capability?: DeviceCapability, write = false): Promise<number> {
  const id = parseRequestDeviceId(req.params.id);
  if (id === null) throw new AppError(404, 'Device not found');
  const outcome = await resolveRequestDevice(req, id, capability ? { capability } : {});
  if (!outcome.ok) throw new AppError(outcome.status, outcome.error, outcome.status === 403 ? 'capabilityMissing' : undefined);
  if (Number(outcome.device.tenant_id) !== Number(req.tenantId)) throw new AppError(404, 'Device not found');
  if (write && !outcome.isAdmin && !(await permissionService.canWriteDevice(req.session.userId!, id, false))) {
    throw new AppError(403, 'Insufficient permissions', 'capabilityMissing');
  }
  return id;
}

/** The capability of a command on a device the caller sees, with write access to it (403 otherwise); a platform
 *  administrator passes. */
async function requireCapability(req: Request, deviceId: number, capability: DeviceCapability): Promise<void> {
  if (req.session.role === 'admin') return;
  const userId = req.session.userId!;
  if (!(await permissionService.canUseCapability(userId, deviceId, false, capability)) || !(await permissionService.canWriteDevice(userId, deviceId, false))) {
    throw new AppError(403, `Capability '${capability}' not permitted for your team`, 'capabilityMissing');
  }
}

/** The spec of a console request: a registered type with a console route, its parameters valid, not guarded. */
function consoleSpec(requestType: string, params: Record<string, unknown> | undefined): { spec: CommandSpec<any>; params: Record<string, unknown> } {
  const spec = commandSpecOrNull(requestType);
  if (!spec || spec.capability === null) throw new AppError(422, 'Unknown command type', 'unknownRequestType');
  const parsed = spec.params.safeParse(params ?? {});
  if (!parsed.success) throw new AppError(422, `${requestType}: ${parsed.error.issues[0]?.message ?? 'invalid parameters'}`, 'invalidParams');
  if (guardedActionOf(spec, parsed.data as Record<string, unknown>)) {
    throw new AppError(409, 'This command goes through its guarded action', 'guardedActionRequired', { actionKey: guardedActionOf(spec, parsed.data as Record<string, unknown>) });
  }
  // Parameters reserved to the system origins (a profile of a policy, the items a policy compiles), told at once, before
  // a step-up or a second approver is asked: the bus refuses them anyway (MDM-B5c-R7).
  if (spec.systemOnly?.(parsed.data)) throw new AppError(422, `${requestType}: these parameters are reserved to the policies`, 'invalidParams');
  // No secret in clear among the parameters (§8.8), told at once: the bus refuses the command anyway, but only once
  // a step-up or a second approver was asked, and a request for approval would keep the value in its payload
  // meanwhile (review of lot B4). The same rules as the bus, on what the caller typed; key names only in the answer.
  let secrets: SecretFinding[];
  try {
    secrets = findSecrets('', plistFromJson(parsed.data) as PlistDict);
  } catch (err) {
    if (err instanceof PlistError) throw new AppError(422, `${requestType}: ${err.message}`, 'invalidParams');
    throw err;
  }
  if (secrets.length > 0) {
    throw new AppError(422, 'The command would carry a secret in clear', 'secretInCommand', { where: secrets.slice(0, 5).map((s) => s.path.replace(/^Command\./, 'params.')) });
  }
  return { spec, params: params ?? {} };
}

function requireReason(spec: CommandSpec<any>, reason: string | undefined): void {
  if (spec.reasonRequired && (reason ?? '').trim().length < 10) throw new AppError(422, 'A reason of 10 characters at least is required', 'reasonRequired');
}

const result = (o: EnqueueOutcome): MdmEnqueueResult => ({
  batchId: o.batchId, commandIds: o.commandIds, targets: o.targets, refused: o.refused, held: o.held, notBefore: o.notBefore, replayed: o.replayed,
});

// ── Views ────────────────────────────────────────────────────────────────────

const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);

function targetView(r: Record<string, any>): MdmTargetView {
  const state = r.state as MdmTargetState;
  return {
    commandId: String(r.command_id).toLowerCase(), deviceId: Number(r.device_id), requestType: r.request_type, origin: r.origin, state,
    rejectCode: r.reject_code ?? null, lastStatus: r.last_status ?? null, holdReason: r.hold_reason ?? null,
    createdAt: iso(r.created_at) as string, notBefore: iso(r.not_before), expiresAt: iso(r.expires_at) as string,
    // queued_at is written when the submission starts: it is the time of the queueing only once apple-edge took the command.
    ...(r.platform && r.platform !== 'apple' ? { platform: String(r.platform) } : {}),
    queuedAt: state === 'pending' ? null : iso(r.queued_at), deliveredAt: iso(r.delivered_at), completedAt: iso(r.completed_at),
    pushCount: Number(r.push_count ?? 0), pushedAt: iso(r.pushed_at), pushOutcome: r.push_outcome ?? null,
    errorChain: Array.isArray(r.error_chain) ? r.error_chain.slice(0, 20).map((e: Record<string, unknown>) => ({
      code: Number(e.ErrorCode ?? e.code ?? 0), domain: String(e.ErrorDomain ?? e.domain ?? '').slice(0, 200),
      description: String(e.USEnglishDescription ?? e.LocalizedDescription ?? e.description ?? '').slice(0, 500),
    })) : null,
    requestedBy: r.requested_by ? { id: Number(r.requested_by), name: r.requested_by_name ?? `#${r.requested_by}` } : null,
    reason: r.reason ?? null,
  };
}

const TARGET_COLUMNS = ['t.command_id', 't.device_id', 't.state', 't.reject_code', 't.last_status', 't.hold_reason', 't.queued_at', 't.delivered_at',
  't.completed_at', 't.push_count', 't.pushed_at', 't.push_outcome', 't.error_chain', 'c.platform', 'c.request_type', 'c.origin', 'c.created_at', 'c.not_before',
  'c.expires_at', 'c.requested_by', 'c.reason', 'u.username as requested_by_name'];

function targetsQuery(tenantId: number) {
  return db('mdm_command_targets as t')
    .join('mdm_commands as c', function joinCommand() { this.on('c.id', '=', 't.command_id').andOn('c.tenant_id', '=', 't.tenant_id'); })
    .leftJoin('users as u', 'u.id', 'c.requested_by')
    .where('t.tenant_id', tenantId);
}

/** 'created_at|id' of the last row of a page. */
function cursorOf(raw: unknown): { at: Date; id: string } | null {
  if (typeof raw !== 'string' || raw === '') return null;
  const [at, id] = raw.split('|');
  const d = new Date(at);
  if (Number.isNaN(d.getTime()) || !UUID_RE.test(id ?? '')) throw new AppError(400, 'Invalid cursor', 'invalidRequest');
  return { at: d, id };
}

async function commandView(tenantId: number, row: Record<string, any>): Promise<MdmCommandView> {
  const counts = await db('mdm_command_targets').where({ tenant_id: tenantId, command_id: row.id }).groupBy('state')
    .select('state').count('* as n') as unknown as Array<{ state: MdmTargetState; n: string | number }>;
  return {
    id: String(row.id).toLowerCase(), batchId: row.batch_id ? String(row.batch_id).toLowerCase() : null,
    ...(row.platform && row.platform !== 'apple' ? { platform: String(row.platform) } : {}), requestType: row.request_type, origin: row.origin,
    createdAt: iso(row.created_at) as string, notBefore: iso(row.not_before), expiresAt: iso(row.expires_at) as string, submitState: row.submit_state,
    reason: row.reason ?? null, ticket: row.ticket ?? null,
    requestedBy: row.requested_by ? { id: Number(row.requested_by), name: row.requested_by_name ?? `#${row.requested_by}` } : null,
    approvalId: row.approval_id ?? null, guardActionUuid: row.guard_action_uuid ? String(row.guard_action_uuid).toLowerCase() : null,
    counts: Object.fromEntries(counts.map((c) => [c.state, Number(c.n)])) as MdmCommandView['counts'],
  };
}

const COMMAND_COLUMNS = ['c.id', 'c.batch_id', 'c.platform', 'c.request_type', 'c.origin', 'c.created_at', 'c.not_before', 'c.expires_at', 'c.submit_state', 'c.reason',
  'c.ticket', 'c.requested_by', 'c.approval_id', 'c.guard_action_uuid', 'u.username as requested_by_name'];

/** The devices of the tenant the caller sees ('all' for an administrator). */
async function visible(req: Request): Promise<number[] | 'all'> {
  if (req.session.role === 'admin') return 'all';
  return permissionService.getVisibleDeviceIds(req.session.userId!, false);
}

/** Does the caller hold `capability` on each of these devices of the tenant? The ids it lacks it on. */
async function lacking(req: Request, ids: number[], capability: DeviceCapability): Promise<number[]> {
  if (req.session.role === 'admin') return [];
  const userId = req.session.userId!;
  const out = new Set(await permissionService.devicesLackingCapability(userId, ids, capability));
  for (const id of ids) if (!out.has(id) && !(await permissionService.canWriteDevice(userId, id, false))) out.add(id);
  return [...out];
}

// ── Routes ───────────────────────────────────────────────────────────────────

// GET /api/apple/devices/:id/actions
router.get('/devices/:id/actions', async (req, res, next) => {
  try {
    const id = await deviceOf(req);
    const tenantId = req.tenantId!;
    const facts = (await deviceFacts(tenantId, [id])).get(id);
    const isFrozen = await frozen(tenantId);
    const isAdmin = req.session.role === 'admin';
    const canWrite = isAdmin || await permissionService.canWriteDevice(req.session.userId!, id, false);
    const actions: MdmDeviceAction[] = [];
    for (const spec of commandSpecList()) {
      if (spec.capability === null) continue;
      const hasCapability = canWrite && (isAdmin || await permissionService.canUseCapability(req.session.userId!, id, false, spec.capability));
      const refusal = await refusalFor(tenantId, spec, facts);
      const otherwise = !hasCapability ? 'capabilityMissing' : refusal ? REFUSAL_CODES[refusal] : isFrozen ? 'frozen' : null;
      // The menu only (the bus still accepts them: the recorded state may lag behind the device): the sound, the
      // location and the disabling need the lost mode on; enabling it again while it is on or coming is pointless.
      const unavailable = otherwise ?? lostModeRefusal(spec.requestType, facts?.lost_mode_state);
      actions.push({ requestType: spec.requestType, capability: spec.capability, restrictionKey: spec.restrictionKey, guarded: spec.guardedBy !== null,
        reasonRequired: spec.reasonRequired, available: unavailable === null, unavailable });
    }
    res.json({ data: actions });
  } catch (err) { next(err); }
});

// POST /api/apple/devices/:id/commands
router.post('/devices/:id/commands', enqueueLimiter, async (req, res, next) => {
  try {
    // The device first: one the caller does not see answers 404 whatever the request says (no oracle on a type or
    // a parameter); then the type, then the capability the type needs on this device (403).
    const id = await deviceOf(req);
    // A device of another channel goes to its module (lot AN-D: amapi), with its own types, capabilities and rules.
    const channel = queueChannelOfDevice(await channelOf(req.tenantId!, id));
    if (channel) { await channel.create(req, res, id); return; }
    const b = body(CommandBody, req);
    const { spec, params } = consoleSpec(b.requestType, b.params);
    await requireCapability(req, id, spec.capability as DeviceCapability);
    const tenantId = req.tenantId!;
    requireReason(spec, b.reason);
    const key = idempotencyKey(req);
    if (await frozen(tenantId)) throw new AppError(423, 'The commands of this tenant are frozen', 'tenantFrozen');
    // What the device cannot take is told before anything is asked of the user (a step-up, a second approver).
    const refusal = await refusalFor(tenantId, spec, (await deviceFacts(tenantId, [id])).get(id));
    if (refusal) throw refusedError(refusal);
    if (spec.restrictionKey) {
      const ok = await applyRestriction(res, {
        req, actionKey: spec.restrictionKey, deviceIds: [id], approvalRequestType: 'apple_action',
        approvalDescription: `${spec.requestType} on 1 device`,
        approvalPayload: { action: 'mdm.command', requestType: spec.requestType, deviceIds: [id], params, reason: b.reason ?? null, ticket: b.ticket ?? null },
      });
      if (!ok) return;
    }
    const auditCtx = await audit.fromRequest(req, tenantId);
    const o = await db.transaction((trx) => mdmCommands.enqueue(trx, {
      tenantId, requestType: spec.requestType, deviceIds: [id], params, origin: 'console', actor: `u:${req.session.userId}`,
      requestedBy: req.session.userId!, reason: b.reason, ticket: b.ticket, idempotencyKey: key, auditCtx,
    }));
    if (o.targets === 0 && o.refused[0]) throw refusedError(o.refused[0].code);
    res.status(202).json({ data: result(o) });
  } catch (err) { next(err); }
});

// POST /api/apple/commands/bulk
router.post('/commands/bulk', bulkLimiter, async (req, res, next) => {
  try {
    const b = body(BulkBody, req);
    const { spec, params } = consoleSpec(b.requestType, b.params);
    const tenantId = req.tenantId!;
    const parsed = b.deviceIds.map(parseRequestDeviceId);
    const ids = [...new Set(parsed.filter((n): n is number => n !== null))];
    if (parsed.some((n) => n === null) || ids.length === 0) throw new AppError(404, 'No matching devices in this tenant');
    if (ids.length > Math.min(500, spec.maxTargets)) throw new AppError(422, `${spec.requestType}: ${Math.min(500, spec.maxTargets)} device(s) at most per request`, 'tooManyTargets');
    const facts = await deviceFacts(tenantId, ids);
    const seen = await visible(req);
    if (facts.size !== ids.length || (seen !== 'all' && ids.some((id) => !seen.includes(id)))) throw new AppError(404, 'No matching devices in this tenant');
    const without = await lacking(req, ids, spec.capability as DeviceCapability);
    if (without.length > 0) throw new AppError(403, 'Capability not permitted on some devices', 'capabilityMissing', { count: without.length });
    requireReason(spec, b.reason);
    const key = idempotencyKey(req);
    if (await frozen(tenantId)) throw new AppError(423, 'The commands of this tenant are frozen', 'tenantFrozen');
    // P0-13 (CNF-02): no device of the request may be located: told before a step-up or an approval is asked (the bus
    // sets aside each device whose profile refuses it).
    if (spec.requestType === 'DeviceLocation') {
      let anyAllowed = false;
      for (const d of facts.values()) if (await locationAllowed(tenantId, d)) { anyAllowed = true; break; }
      if (!anyAllowed) throw refusedError('location_disabled');
    }
    if (spec.restrictionKey) {
      const ok = await applyRestriction(res, {
        req, actionKey: spec.restrictionKey, deviceIds: ids, approvalRequestType: 'apple_action',
        approvalDescription: `${spec.requestType} on ${ids.length} device(s)`,
        approvalPayload: { action: 'mdm.command', requestType: spec.requestType, deviceIds: ids, params, reason: b.reason ?? null, ticket: b.ticket ?? null },
      });
      if (!ok) return;
    }
    const auditCtx = await audit.fromRequest(req, tenantId);
    const o = await db.transaction((trx) => mdmCommands.enqueue(trx, {
      tenantId, requestType: spec.requestType, deviceIds: ids, params, origin: 'bulk', actor: `u:${req.session.userId}`,
      requestedBy: req.session.userId!, reason: b.reason, ticket: b.ticket, idempotencyKey: key, auditCtx,
    }));
    res.status(202).json({ data: result(o) });
  } catch (err) { next(err); }
});

// POST /api/apple/devices/:id/remove-management: the guarded action, its own rights, floors and confirmation.
router.post('/devices/:id/remove-management', async (req, res, next) => {
  try {
    const id = await deviceOf(req);                       // out of reach: 404, before the engine says anything
    const b = (req.body ?? {}) as { reason?: unknown; ticket?: unknown; confirm?: unknown };
    const outcome = await guard.request(req, {
      actionKey: REMOVE_MANAGEMENT_ACTION, selection: { deviceIds: [id] },
      reason: typeof b.reason === 'string' ? b.reason : '', ticket: typeof b.ticket === 'string' ? b.ticket : undefined, confirm: b.confirm,
    } as Parameters<typeof guard.request>[1]);
    res.status(202).json({ data: outcome });
  } catch (err) {
    if (err instanceof GuardStepUpError) { sendStepUpFailure(res, err.outcome); return; }
    next(asAppError(err) ?? err);
  }
});

// POST /api/apple/devices/:id/inventory-refresh
router.post('/devices/:id/inventory-refresh', enqueueLimiter, async (req, res, next) => {
  try {
    const id = await deviceOf(req, 'mdm:inventory', true);
    const tenantId = req.tenantId!;
    if (await frozen(tenantId)) throw new AppError(423, 'The commands of this tenant are frozen', 'tenantFrozen');
    const auditCtx = await audit.fromRequest(req, tenantId);
    const o = await db.transaction((trx) => refreshInventoryNow(trx, tenantId, id, req.session.userId!, auditCtx));
    if (o.commandIds.length === 0 && o.refused[0]) throw refusedError(o.refused[0].code);
    res.status(202).json({ data: { commandIds: o.commandIds } });
  } catch (err) { next(err); }
});

// ── Re-enrollment without proof (decision of the owners of 19/10/2026 on AE-C0-R2bis, option C of MDM-B2-R13) ──
// apple-edge refuses an Authenticate without ADE proof of an identifier active under another identity (a device erased
// without CheckOut, restored, or an impostor announcing its UDID). The operator who checked that it is the same
// device allows its re-enrollment: one Authenticate within 24 hours, consumed by it. Capability mdm:remove with write
// access to the device; critical entry of the journal; the alert enrollment.reenroll_refused of the record resolved.
const REENROLL_TTL_S = 86_400;

async function reenrollTarget(req: Request): Promise<{ id: number; key: string; enrollmentId: string }> {
  const id = await deviceOf(req, 'mdm:remove', true);       // out of reach: 404 first
  if (config.apple.mode !== 'on') throw new AppError(503, 'The Apple integration is turned off on this instance', 'appleIntegrationDisabled');
  const tenantId = req.tenantId!;
  const row = await db('apple_devices as a')
    .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId, 'a.device_id': id }).first('a.enrollment_id', 'd.enrollment_state') as
    { enrollment_id: string | null; enrollment_state: string } | undefined;
  if (!row?.enrollment_id) throw new AppError(422, 'The device is not an Apple device', 'notApple');
  if (row.enrollment_state === 'unenrolled') throw new AppError(409, 'The device is no longer under management: it enrolls again freely', 'notEnrolled');
  const t = await db('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
  if (!t?.mdm_key || !String(row.enrollment_id).startsWith(`${t.mdm_key}_`)) throw new AppError(409, 'The tenant is not provisioned at the device service', 'tenantNotProvisioned');
  return { id, key: t.mdm_key, enrollmentId: String(row.enrollment_id) };
}

// POST /api/apple/devices/:id/reenroll-allowance
router.post('/devices/:id/reenroll-allowance', enqueueLimiter, async (req, res, next) => {
  try {
    const tenantId = req.tenantId!;
    const target = await reenrollTarget(req);
    const actor = { actor: edgeActorOf(userActor(req.session.userId!)), requestId: req.requestId };
    const out = await audit.withIntent({
      tenantId, action: 'apple.reenroll_allowed', target: { type: 'device', id: String(target.id), device: target.id }, details: { hours: REENROLL_TTL_S / 3600 },
    }, await audit.fromRequest(req, tenantId), async () => {
      try { return await appleEdge.allowReenroll(target.key, target.enrollmentId, REENROLL_TTL_S, actor); } catch (err) { rethrowForConsole(err); }
    }, { resultDetails: (o) => ({ expiresAt: o.expires_at }) });
    await db.transaction((trx) => resolveInTx(trx, tenantId, 'enrollment.reenroll_refused', target.id));
    res.json({ data: { deviceId: target.id, expiresAt: out.expires_at } });
  } catch (err) { next(err); }
});

// DELETE /api/apple/devices/:id/reenroll-allowance
router.delete('/devices/:id/reenroll-allowance', enqueueLimiter, async (req, res, next) => {
  try {
    const tenantId = req.tenantId!;
    const target = await reenrollTarget(req);
    const actor = { actor: edgeActorOf(userActor(req.session.userId!)), requestId: req.requestId };
    let withdrawn: boolean;
    try { withdrawn = await appleEdge.withdrawReenroll(target.key, target.enrollmentId, actor); } catch (err) { rethrowForConsole(err); }
    if (withdrawn!) {
      await audit.append({ tenantId, action: 'apple.reenroll_allowance_withdrawn', target: { type: 'device', id: String(target.id), device: target.id }, details: {} },
        await audit.fromRequest(req, tenantId));
    }
    res.json({ data: { deviceId: target.id, withdrawn: withdrawn! } });
  } catch (err) { next(err); }
});

// GET /api/apple/devices/:id/commands?state=open|final|all&cursor=
router.get('/devices/:id/commands', async (req, res, next) => {
  try {
    const id = await deviceOf(req);
    const state = String(req.query.state ?? 'all');
    const cursor = cursorOf(req.query.cursor);
    let q = targetsQuery(req.tenantId!).where('t.device_id', id);
    if (state === 'open') q = q.whereIn('t.state', ['pending', 'queued', 'sent', 'notnow']);
    else if (state === 'final') q = q.whereNotIn('t.state', ['pending', 'queued', 'sent', 'notnow']);
    else if (state !== 'all') throw new AppError(400, 'state: open, final or all', 'invalidRequest');
    if (cursor) q = q.whereRaw('(c.created_at, c.id) < (?::timestamptz, ?::uuid)', [cursor.at, cursor.id]);
    const rows = await q.orderBy('c.created_at', 'desc').orderBy('c.id', 'desc').limit(50).select(TARGET_COLUMNS) as Array<Record<string, any>>;
    const last = rows[rows.length - 1];
    res.json({ data: rows.map(targetView), nextCursor: rows.length === 50 && last ? `${iso(last.created_at)}|${String(last.command_id).toLowerCase()}` : null });
  } catch (err) { next(err); }
});

// GET /api/apple/commands?state=&origin=&requestType=&cursor=
router.get('/commands', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const tenantId = req.tenantId!;
    const cursor = cursorOf(req.query.cursor);
    let q = db('mdm_commands as c').leftJoin('users as u', 'u.id', 'c.requested_by').where('c.tenant_id', tenantId);
    const origin = req.query.origin;
    if (typeof origin === 'string' && origin) {
      if (!(MDM_COMMAND_ORIGINS as readonly string[]).includes(origin)) throw new AppError(400, 'Unknown origin', 'invalidRequest');
      q = q.where('c.origin', origin);
    }
    const requestType = req.query.requestType;
    if (typeof requestType === 'string' && requestType) {
      if (!REQUEST_TYPE.safeParse(requestType).success) throw new AppError(400, 'Invalid requestType', 'invalidRequest');
      q = q.where('c.request_type', requestType);
    }
    const state = req.query.state;
    const seen = await visible(req);
    if ((typeof state === 'string' && state) || seen !== 'all') {
      if (typeof state === 'string' && state && !(MDM_TARGET_STATES as readonly string[]).includes(state)) throw new AppError(400, 'Unknown state', 'invalidRequest');
      // The scopes applied: a command with one target at least the caller sees (and in that state, when asked).
      q = q.whereExists(function hasTarget() {
        this.select(db.raw('1')).from('mdm_command_targets as t').whereRaw('t.command_id = c.id AND t.tenant_id = c.tenant_id');
        if (typeof state === 'string' && state) this.where('t.state', state);
        if (seen !== 'all') this.whereRaw('t.device_id = ANY (?::int[])', [seen]);
      });
    }
    if (cursor) q = q.whereRaw('(c.created_at, c.id) < (?::timestamptz, ?::uuid)', [cursor.at, cursor.id]);
    const rows = await q.orderBy('c.created_at', 'desc').orderBy('c.id', 'desc').limit(50).select(COMMAND_COLUMNS) as Array<Record<string, any>>;
    const data: MdmCommandView[] = [];
    for (const r of rows) data.push(await commandView(tenantId, r));
    const last = rows[rows.length - 1];
    res.json({ data, nextCursor: rows.length === 50 && last ? `${iso(last.created_at)}|${String(last.id).toLowerCase()}` : null });
  } catch (err) { next(err); }
});

/** A command of the tenant with the targets the caller sees; 404 when it sees none. */
async function commandOf(req: Request): Promise<{ row: Record<string, any>; deviceIds: number[]; spec: CommandSpec<any> | undefined }> {
  const id = String(req.params.commandId ?? '');
  if (!UUID_RE.test(id)) throw new AppError(404, 'Command not found');
  const tenantId = req.tenantId!;
  const row = await db('mdm_commands as c').leftJoin('users as u', 'u.id', 'c.requested_by').where({ 'c.tenant_id': tenantId, 'c.id': id }).first(COMMAND_COLUMNS) as
    Record<string, any> | undefined;
  if (!row) throw new AppError(404, 'Command not found');
  let deviceIds = (await db('mdm_command_targets').where({ tenant_id: tenantId, command_id: id }).pluck('device_id') as number[]).map(Number);
  const seen = await visible(req);
  if (seen !== 'all') deviceIds = deviceIds.filter((d) => seen.includes(d));
  if (deviceIds.length === 0) throw new AppError(404, 'Command not found');
  return { row, deviceIds, spec: commandSpecOrNull(row.request_type) };
}

// GET /api/apple/commands/:commandId?cursor=<device id>
router.get('/commands/:commandId', async (req, res, next) => {
  try {
    const { row, deviceIds } = await commandOf(req);
    const after = parseRequestDeviceId(req.query.cursor) ?? 0;
    const page = deviceIds.filter((d) => d > after).sort((a, b) => a - b).slice(0, 100);
    const rows = page.length === 0 ? [] : await targetsQuery(req.tenantId!).where('t.command_id', row.id).whereRaw('t.device_id = ANY (?::int[])', [page])
      .orderBy('t.device_id').select(TARGET_COLUMNS) as Array<Record<string, any>>;
    res.json({ data: { command: await commandView(req.tenantId!, row), targets: rows.map(targetView), nextCursor: page.length === 100 ? page[page.length - 1] : null } });
  } catch (err) { next(err); }
});

/** The management channel of a device of the tenant. */
async function channelOf(tenantId: number, deviceId: number): Promise<string | null> {
  const d = await db('devices').where({ tenant_id: tenantId, id: deviceId }).first('management_channel') as { management_channel: string } | undefined;
  return d?.management_channel ?? null;
}

/** A command of another platform the caller sees (404 otherwise), with the handlers of its module; null for Apple. */
async function otherPlatform(req: Request): Promise<{ channel: NonNullable<ReturnType<typeof queueChannelOfPlatform>>; commandId: string } | null> {
  const { row } = await commandOf(req);
  if (!row.platform || row.platform === 'apple') return null;
  const channel = queueChannelOfPlatform(row.platform);
  if (!channel) throw new AppError(404, 'Command not found');
  return { channel, commandId: String(row.id).toLowerCase() };
}

/** The targets of a request on a command: those asked among the visible ones, on which the caller holds the
 *  capability of the type (or every visible one for the author of the command, when `authorToo`). */
async function actionableTargets(req: Request, authorToo: boolean): Promise<{ row: Record<string, any>; deviceIds: number[] }> {
  const { row, deviceIds, spec } = await commandOf(req);
  const b = body(TargetsBody, req);
  let ids = deviceIds;
  if (b.deviceIds) {
    const wanted = new Set(b.deviceIds.map(parseRequestDeviceId));
    ids = ids.filter((d) => wanted.has(d));
    if (ids.length === 0) throw new AppError(404, 'Command not found');
  }
  const author = authorToo && Number(row.requested_by) === Number(req.session.userId);
  if (!author) {
    if (!spec?.capability) throw new AppError(403, 'Insufficient permissions', 'capabilityMissing');
    const without = await lacking(req, ids, spec.capability);
    if (without.length > 0) throw new AppError(403, 'Capability not permitted on some devices', 'capabilityMissing', { count: without.length });
  }
  return { row, deviceIds: ids };
}

// POST /api/apple/commands/:commandId/cancel
router.post('/commands/:commandId/cancel', async (req, res, next) => {
  try {
    const other = await otherPlatform(req);
    if (other) { await other.channel.cancel(req, res, other.commandId); return; }
    const { row, deviceIds } = await actionableTargets(req, true);
    const tenantId = req.tenantId!;
    const auditCtx = await audit.fromRequest(req, tenantId);
    const o = await db.transaction((trx) => mdmCommands.cancel(trx, tenantId, String(row.id), deviceIds, `u:${req.session.userId}`, { auditCtx }));
    res.status(202).json({ data: o });
  } catch (err) { next(err); }
});

// POST /api/apple/commands/:commandId/relaunch
router.post('/commands/:commandId/relaunch', enqueueLimiter, async (req, res, next) => {
  try {
    const other = await otherPlatform(req);
    if (other) { await other.channel.relaunch(req, res, other.commandId); return; }
    const { row, deviceIds } = await actionableTargets(req, false);
    const tenantId = req.tenantId!;
    if (await frozen(tenantId)) throw new AppError(423, 'The commands of this tenant are frozen', 'tenantFrozen');
    try {
      const o = await mdmCommands.relaunch(tenantId, String(row.id), deviceIds, `u:${req.session.userId}`,
        { auditCtx: await audit.fromRequest(req, tenantId), requestId: req.requestId });
      res.json({ data: o });
    } catch (err) {
      rethrowForConsole(err);
    }
  } catch (err) { next(err); }
});

// GET /api/apple/devices/:id/timeline?before=&limit=
router.get('/devices/:id/timeline', async (req, res, next) => {
  try {
    const id = await deviceOf(req);
    const before = typeof req.query.before === 'string' && req.query.before ? new Date(req.query.before) : null;
    if (before && Number.isNaN(before.getTime())) throw new AppError(400, 'Invalid date', 'invalidRequest');
    const limit = Math.min(200, Math.max(1, parseInt(String(req.query.limit ?? '50'), 10) || 50));
    res.json({ data: await deviceTimeline(db, req.tenantId!, id, { before, limit }) });
  } catch (err) { next(err); }
});

/** The console API of the command queue, mounted at /api/apple (routes/index.ts), after requireTenant. */
export function createAppleCommandsRouter(): Router {
  return router;
}

// ── Approvals of the restricted commands (§8.11) ─────────────────────────────

/**
 * The executor of an approved 'apple_action' request (a command the tenant's matrix holds at 'restricted'): as
 * the requester, whose rights and whose devices are read again; a guarded type never goes this way.
 */
export async function executeAppleAction(x: ApprovalExecution): Promise<string | void> {
  const p = (x.payload ?? {}) as { action?: unknown; requestType?: unknown; deviceIds?: unknown; params?: unknown; reason?: unknown; ticket?: unknown };
  if (p.action !== 'mdm.command' || typeof p.requestType !== 'string' || !Array.isArray(p.deviceIds)) refuse('Malformed command request');
  const spec = commandSpecOrNull(p.requestType as string);
  if (!spec || spec.capability === null) refuse('This command type is no longer available');
  const s = spec as CommandSpec<any>;
  const params = (p.params && typeof p.params === 'object' && !Array.isArray(p.params) ? p.params : {}) as Record<string, unknown>;
  const parsed = s.params.safeParse(params);
  if (!parsed.success) refuse('The parameters of the command are no longer valid');
  if (guardedActionOf(s, (parsed.data ?? {}) as Record<string, unknown>)) refuse('This command goes through its guarded action');
  const ids = [...new Set((p.deviceIds as unknown[]).map(parseRequestDeviceId).filter((n): n is number => n !== null))];
  if (ids.length === 0 || ids.length > 500) refuse('Malformed command request');
  const requester = await activeRequester(x.requesterId);
  const facts = await deviceFacts(x.tenantId, ids);
  if (facts.size !== ids.length) refuse('Some devices of this request are no longer in the tenant');
  if (!requester.isPlatformAdmin) {
    const without = new Set(await permissionService.devicesLackingCapability(x.requesterId, ids, s.capability as DeviceCapability));
    for (const id of ids) if (!without.has(id) && !(await permissionService.canWriteDevice(x.requesterId, id, false))) without.add(id);
    if (without.size > 0) refuse('The requester no longer holds the capability of this command on every device');
  }
  const reason = typeof p.reason === 'string' ? p.reason : undefined;
  const ticket = typeof p.ticket === 'string' ? p.ticket : undefined;
  let o: EnqueueOutcome;
  try {
    const auditCtx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
    o = await db.transaction((trx) => mdmCommands.enqueue(trx, {
      tenantId: x.tenantId, requestType: s.requestType, deviceIds: ids, params, origin: 'approval', actor: `u:${x.requesterId}`,
      requestedBy: x.requesterId, reason, ticket, approvalId: x.approvalId, auditCtx,
      ...(x.approvalId ? { idempotencyKey: `approval:${x.approvalId}` } : {}),
    }));
  } catch (err) {
    const e = err as { statusCode?: number; message?: string; code?: string };
    if (e.statusCode && e.statusCode < 500) refuse(`${e.code ?? 'refused'}: ${e.message ?? 'the command was refused'}`);
    throw err;
  }
  if (o.targets === 0) refuse(`No device could take the command (${o.refused[0]?.code ?? 'refused'})`);
  if (o.refused.length > 0) return `${o.refused.length} device(s) set aside (${[...new Set(o.refused.map((r) => r.code))].join(', ')})`;
  return undefined;
}
