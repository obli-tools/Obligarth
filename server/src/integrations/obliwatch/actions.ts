import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import type { Request, Response } from 'express';
import { z } from 'zod';
import {
  OBLIWATCH_ACTIONS, type ObliwatchAction, type ObliwatchActionRefusal, type ObliwatchActionRequestAccepted, type ObliwatchActionRequestView,
  type ObliwatchActionResult,
} from '@obligarth/shared';
import { audit, isAuditUnavailable } from '../../audit';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { guardedActionDef, type GuardedActionDef } from '../../guard';
import { tenantFrozen } from '../../guard/frozen';
import { cancelJob, executeJob, wakeExecutor } from '../../guard/jobs';
import { cooldownUntil, personFacts } from '../../guard/people';
import { targetsWithoutRights } from '../../guard/selection';
import { jobIdFor } from '../../jobs';
import { mdmCommands } from '../../apple/commands';
import { AndroidCommandError, enqueueAndroidCommands, lostModeBlocked } from '../../android/commands/bus';
import { refusalOf as androidRefusalOf, type AndroidCommandType } from '../../android/commands/catalog';
import { LOCK_ACTION } from '../../legacyAgent/commands';
import { AppError } from '../../middleware/errorHandler';
import { lostModeLocationAllowed } from '../../privacy/profiles';
import { permissionService } from '../../services/permission.service';
import { logger } from '../../utils/logger';
import { obliwatchCtx } from './audit';
import { sendError } from './auth';
import { OBLIWATCH_ACTOR } from './config';
import {
  REQUEST_COLUMNS, REQUEST_TTL_MS, auditStepInTx, prefixOf, recordEventInTx, trackNow, trackRequest, type RequestRow,
} from './actionTrack';

// =============================================================================
// The action requests of Obliwatch (brief GTH-04; lot L5), under /api/integrations/obliwatch/v1:
//   POST /action-requests            user token of the analyst (delegation obliwatch → obligarth, resolved to the LOCAL
//                                    account: 403 subject_unknown without one; that account is the requester the guard
//                                    engine revalidates and the journal names), consent 'actions' of the tenant
//   GET  /action-requests/:id        app or user token (the poller of Obliwatch), consent 'actions'
//   POST /action-requests/:id/cancel app or user token, consent 'actions': before the execution only
// Owner decision Q-L5a ("Obliwatch has the god mode"): NO human approval. A valid request is executed at once, without
// a second factor nor a second approver, whatever the tenant's matrix says, when OBLIWATCH_INTEGRATION=on and the tenant
// consented to the actions (actions_enabled, changed only through the consent's restriction: fresh second factor,
// critical entry). The safeguards that are not approvals stay:
//   - the whitelist of five actions, one device per request (a list of targets, an erase, a removal from management,
//     a passcode clearing or a password reset: 422 actionNotAllowed);
//   - the eligibility of the device (422: notSupported, supervisionRequired, ownershipForbidden — every personal
//     device —, lostModeRequired, lostModeCooldown, notEnrolled, locationDisabled), the emergency freeze of the tenant
//     (423 tenantFrozen), the rights of the requester on the device (403 rights_insufficient) and the 72-hour cooldown of
//     a new administrator (403 privilegeCooldown), as the guard engine checks them;
//   - the caps, under an advisory lock of the tenant: 5 open requests per requester, 20 open per tenant, 20 made per
//     tenant and 10 per requester in a sliding hour (429 too_many_requests {limit});
//   - idempotency by the request uuid (requestUuid of the body: the same uuid answers the request already recorded);
//   - the critical entries obliwatch.action.* of every step (prefix [Obliwatch, incident <ref>, requested by <user>]);
//     the guarded action carries the same prefix in its reason (guard.action_requested, executing, executed); a request
//     refused when it is made writes obliwatch.action.refused too (details.stage 'request'; the caps coalesced per
//     minute);
//   - the gate checked again when the action runs (actionGate.ts): the switch turned off or the consent to the actions
//     withdrawn closes the open requests (cancelled, integration_off / consent_revoked) and the guard engine refuses
//     their guarded actions (obliwatchIntegrationOff / obliwatchConsentOff).
// Execution:
//   - lock (Apple, AMAPI, bridge agent) and lost mode on (Apple, AMAPI): the guarded action of the key (mdm.device_lock,
//     mdm.lost_mode_enable, legacy_agent.device_lock), written 'scheduled' without delay with its job
//     actions.execute-delayed: the engine's executor revalidates (freeze, requester active and entitled, the device
//     still eligible) and dispatches, as for any guarded action. State 'accepted', then 'executing' once started;
//   - lost mode off (Apple, AMAPI), location and sound (Apple): a command of the queue, origin 'system', actor
//     i:obliwatch, requested_by the analyst, written in the request's transaction. State 'executing' at once.
//   - device_location on Android: refused (notSupported; owner decision Q-L5b): no command exists, and the lost mode
//     is NEVER turned on implicitly. play_sound on Android, anything but the lock on the bridge agent: notSupported.
// The phone number of the lost mode goes to the command (and the guarded action, as the console does) only, never to
// obliwatch_action_requests. The results (GTH-05) are pushed by actionResults.ts; the life of a request is actionTrack.ts.
// =============================================================================

const DESTRUCTIVE = new Set([
  'wipe', 'erase', 'erase_device', 'device_wipe', 'factory_reset', 'unenroll', 'remove_management', 'retire', 'clear_passcode',
  'reset_password', 'reset_passcode', 'relinquish_ownership', 'disable', 'delete', 'device_delete',
]);

const CAPS = { openPerRequester: 5, openPerTenant: 20, hourPerTenant: 20, hourPerRequester: 10 } as const;

const PHONE_RE = /^\+?[0-9 ().-]{3,30}$/;
const text = (min: number, max: number) => z.string().trim().min(min).max(max).refine((v) => !/[\u0000-\u001f\u007f]/.test(v), 'control characters');

const Body = z.object({
  deviceUuid: z.string().uuid(),
  action: z.string().min(1).max(64),
  params: z.record(z.unknown()).optional(),
  reason: text(10, 500),
  incidentRef: text(1, 200),
  requestUuid: z.string().uuid().optional(),
  requestedBy: text(1, 200).optional(),
}).strict();

const PARAMS: Record<ObliwatchAction, z.ZodTypeAny> = {
  lost_mode_enable: z.object({ message: text(1, 200), phone: text(3, 30).refine((v) => PHONE_RE.test(v), 'phone'), footnote: text(1, 200).optional() }).strict(),
  device_lock: z.object({ message: text(1, 200).optional(), phone: text(3, 30).refine((v) => PHONE_RE.test(v), 'phone').optional() }).strict(),
  lost_mode_disable: z.object({}).strict(),
  device_location: z.object({}).strict(),
  play_sound: z.object({}).strict(),
};

/** A refusal of the request, answered as {error, code, reason, message}. */
class Refusal extends Error {
  constructor(readonly status: number, readonly code: string, readonly reason: string, readonly extra: Record<string, unknown> = {}) {
    super(reason);
  }
}
const refuse = (code: ObliwatchActionRefusal, reason: string, extra: Record<string, unknown> = {}): never => { throw new Refusal(422, code, reason, extra); };

function sendRefusal(res: Response, r: Refusal): void {
  res.status(r.status).json({ error: r.code, code: r.code, reason: r.reason, message: r.reason, ...r.extra });
}

// ── The refusals journaled ─────────────────────────────────────────────────────────────────────────────────────
// Every request refused when it is made writes the critical entry obliwatch.action.refused (outcome denied) in the
// tenant's chain: without approvals, the journal is the tenant's only trace of an attempt (a wipe asked, a list of
// targets, a personal device, rights lacking, the caps). Prefix [Obliwatch, incident <ref>, requested by <user>] when the
// body was read; the action as sent (truncated), the code, the reason, the cap reached; never the parameters nor a phone
// number. The refusals of the caps (429) are coalesced: one entry per tenant, requester and minute (the others counted
// in the next one). Written before the answer; a journal that cannot be written never turns a refusal into a success.
const REFUSAL_COALESCED = new Map<string, { minute: number; dropped: number }>();
/** Tests: the coalescing of the refusals of the caps forgotten. */
export function _resetRefusalCoalescingForTests(): void { REFUSAL_COALESCED.clear(); }

interface RefusalFacts { action?: unknown; deviceUuid?: unknown; deviceId?: number; incidentRef?: string; reason?: string; requestId?: string }
type RefusalOf = { status: number; code: string; reason: string; extra?: Record<string, unknown> };

async function auditRefusal(req: Request, tenantId: number, user: { id: number; username: string } | undefined, label: string | null,
  r: RefusalOf, f: RefusalFacts): Promise<void> {
  let dropped = 0;
  if (r.status === 429) {
    const key = `${tenantId}|${user?.id ?? 0}`;
    const m = Math.floor(Date.now() / 60_000);
    const seen = REFUSAL_COALESCED.get(key);
    if (seen && seen.minute === m) { seen.dropped++; return; }
    dropped = seen?.dropped ?? 0;
    if (REFUSAL_COALESCED.size > 10_000) REFUSAL_COALESCED.clear();
    REFUSAL_COALESCED.set(key, { minute: m, dropped: 0 });
  }
  const prefix = f.incidentRef ? prefixOf({ incident_ref: f.incidentRef, requester_label: label }) : '[Obliwatch]';
  try {
    await asTenant(tenantId, OBLIWATCH_ACTOR, () => audit.append({
      tenantId, action: 'obliwatch.action.refused', outcome: 'denied',
      ...(f.deviceId ? { target: { type: 'device', id: String(f.deviceId), device: f.deviceId } } : {}),
      reason: `${prefix} ${f.reason ?? ''}`.trim().slice(0, 1000),
      details: {
        stage: 'request', requestId: f.requestId ?? null, code: r.code, refusal: r.reason.slice(0, 200), status: r.status,
        action: typeof f.action === 'string' ? f.action.slice(0, 64) : null,
        deviceUuid: typeof f.deviceUuid === 'string' ? f.deviceUuid.slice(0, 64) : null,
        ...(typeof r.extra?.detail === 'string' ? { detail: r.extra.detail } : {}),
        ...(typeof r.extra?.limit === 'string' ? { limit: r.extra.limit } : {}),
        ...(dropped ? { coalesced: dropped } : {}),
        requestedBy: user ? { userId: user.id, label } : null, azp: req.obliwatch?.azp ?? null,
      },
    }, obliwatchCtx(req)));
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, code: r.code }, 'obliwatch actions: refusal not journaled');
  }
}

type Facts = {
  id: number; uuid: string; management_channel: string; enrollment_state: string; ownership: string; management_mode: string;
  supervised: boolean; lost_mode_state: string; api_level: number | null; released_at: Date | null; amapi_name: string | null;
};

type Plan =
  | { path: 'guard'; key: string; def: GuardedActionDef<any>; params: Record<string, unknown> }
  | { path: 'command'; kind: 'apple'; requestType: string; params: Record<string, unknown> }
  | { path: 'command'; kind: 'android'; type: AndroidCommandType; params: Record<string, unknown> };

const clean = (o: Record<string, unknown>): Record<string, unknown> => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));

function guardPlan(key: string, channel: string, params: Record<string, unknown>): Plan {
  const def = guardedActionDef(key);
  if (!def || (def.channels && !(def.channels as readonly string[]).includes(channel))) {
    refuse('notSupported', `${key} is not available for this device`);
  }
  return { path: 'guard', key, def: def!, params };
}

/** What executes the action on this device, or the refusal (422). */
async function planFor(tenantId: number, action: ObliwatchAction, f: Facts, p: Record<string, unknown>): Promise<Plan> {
  if (f.enrollment_state !== 'enrolled') refuse('notEnrolled', 'The device is not enrolled');
  if (f.ownership === 'personal') refuse('ownershipForbidden', 'No action of Obliwatch on a personal device');
  const ch = f.management_channel;
  if (ch === 'legacy_agent') {
    if (action !== 'device_lock') refuse('notSupported', 'The bridge agent supports the lock only');
    return guardPlan(LOCK_ACTION, ch, {});
  }
  if (ch === 'amapi') {
    if (action === 'device_location') {
      refuse('notSupported', 'Android has no location command (positions come only while the lost mode is on; it is never turned on implicitly)');
    }
    if (action === 'play_sound') refuse('notSupported', 'Android has no sound command');
    if (action === 'device_lock') return guardPlan('mdm.device_lock', ch, {});
    const type: AndroidCommandType = action === 'lost_mode_enable' ? 'START_LOST_MODE' : 'STOP_LOST_MODE';
    const code = androidRefusalOf(type, {
      managementChannel: ch, enrollmentState: f.enrollment_state, released: f.released_at !== null || !f.amapi_name, ownership: f.ownership,
      mode: f.management_mode, apiLevel: f.api_level === null ? null : Number(f.api_level),
    });
    if (code === 'ownership') refuse('ownershipForbidden', 'The lost mode is refused for this ownership');
    if (code === 'not_enrolled') refuse('notEnrolled', 'The device is not enrolled');
    if (code) refuse('notSupported', `The lost mode is not available on this device (${code})`, { detail: code });
    if (action === 'lost_mode_enable') {
      if ((await lostModeBlocked(db, tenantId, [f.id])).has(f.id)) {
        refuse('lostModeCooldown', 'The lost mode is refused for 12 hours after the user left it or the password was reset');
      }
      return guardPlan('mdm.lost_mode_enable', ch, clean({ message: p.message, phoneNumber: p.phone }));
    }
    if (f.lost_mode_state === 'off') refuse('lostModeRequired', 'The lost mode of this device is off');
    return { path: 'command', kind: 'android', type, params: {} };
  }
  if (ch === 'apple_mdm') {
    if (action === 'device_lock') return guardPlan('mdm.device_lock', ch, clean({ message: p.message, phoneNumber: p.phone }));
    if (f.supervised !== true) refuse('supervisionRequired', 'The lost mode, the location and the sound need a supervised device');
    if (action === 'lost_mode_enable') {
      return guardPlan('mdm.lost_mode_enable', ch, clean({ message: p.message, phoneNumber: p.phone, footnote: p.footnote }));
    }
    if (action === 'lost_mode_disable') {
      if (f.lost_mode_state === 'off') refuse('lostModeRequired', 'The lost mode of this device is off');
      return { path: 'command', kind: 'apple', requestType: 'DisableLostMode', params: {} };
    }
    if (f.lost_mode_state !== 'on') refuse('lostModeRequired', 'The location and the sound need the lost mode on');
    if (action === 'device_location') {
      if (!(await lostModeLocationAllowed(db, tenantId, f.ownership))) {
        refuse('locationDisabled', 'The privacy profile of the tenant refuses the location of this device');
      }
      return { path: 'command', kind: 'apple', requestType: 'DeviceLocation', params: {} };
    }
    return { path: 'command', kind: 'apple', requestType: 'PlayLostModeSound', params: {} };
  }
  return refuse('notSupported', 'This device has no management channel for this action');
}

/** The rights of the requester on the device, as the guard engine and the command routes check them. */
async function checkRights(plan: Plan, userId: number, tenantId: number, deviceId: number): Promise<{ side: 'msp' | 'client' }> {
  const facts = await personFacts(userId, tenantId);
  if (!facts.exists || !facts.active) throw new Refusal(403, 'subject_inactive', 'The account of the requester is not active');
  let lacking: number[];
  if (plan.path === 'guard') {
    lacking = await targetsWithoutRights(plan.def, userId, facts.platformAdmin, tenantId, [deviceId]);
  } else if (facts.platformAdmin) {
    lacking = [];
  } else {
    lacking = await permissionService.devicesLackingCapability(userId, [deviceId], 'mdm:lost_mode');
    if (!lacking.length && !(await permissionService.canWriteDevice(userId, deviceId, false))) lacking = [deviceId];
  }
  if (lacking.length) throw new Refusal(403, 'rights_insufficient', 'The requester may not act on this device');
  const until = await cooldownUntil(userId, tenantId, ['platform_admin', 'tenant_admin']);
  if (until && until.getTime() > Date.now()) {
    throw new Refusal(403, 'privilegeCooldown', 'The administrator rights of the requester are too recent', { until: until.toISOString() });
  }
  return { side: facts.side };
}

/** The caps, under the advisory lock of the tenant's requests (in the creation's transaction). */
async function enforceCaps(trx: Knex.Transaction, tenantId: number, userId: number): Promise<void> {
  await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`obliwatch_actions:${tenantId}`]);
  const since = new Date(trackNow() - 3600_000);
  const row = await trx('obliwatch_action_requests').where({ tenant_id: tenantId }).first(
    trx.raw("count(*) FILTER (WHERE state IN ('accepted', 'executing'))::int AS open_tenant"),
    trx.raw("count(*) FILTER (WHERE state IN ('accepted', 'executing') AND requested_by = ?)::int AS open_user", [userId]),
    trx.raw('count(*) FILTER (WHERE created_at > ?)::int AS hour_tenant', [since]),
    trx.raw('count(*) FILTER (WHERE created_at > ? AND requested_by = ?)::int AS hour_user', [since, userId]),
  ) as { open_tenant: number; open_user: number; hour_tenant: number; hour_user: number };
  const over = row.open_user >= CAPS.openPerRequester ? 'open_per_requester'
    : row.open_tenant >= CAPS.openPerTenant ? 'open_per_tenant'
      : row.hour_user >= CAPS.hourPerRequester ? 'hour_per_requester'
        : row.hour_tenant >= CAPS.hourPerTenant ? 'hour_per_tenant' : null;
  if (over) throw new Refusal(429, 'too_many_requests', 'Too many action requests', { limit: over, caps: CAPS });
}

const viewOf = (r: RequestRow): ObliwatchActionRequestView => ({
  requestId: r.id, deviceUuid: String(r.device_uuid).toLowerCase(), action: r.action, state: r.state, seq: Number(r.seq),
  createdAt: new Date(r.created_at).toISOString(), updatedAt: new Date(r.updated_at).toISOString(),
  expiresAt: new Date(r.expires_at).toISOString(), result: (r.result as ObliwatchActionResult | null) ?? null,
});

const acceptedOf = (r: Pick<RequestRow, 'id' | 'state' | 'expires_at'>): ObliwatchActionRequestAccepted => ({
  requestId: r.id, state: r.state, expiresAt: new Date(r.expires_at).toISOString(), approvalRequired: false, approvalUrl: null,
});

async function readRequest(tenantId: number, id: string): Promise<RequestRow | undefined> {
  return asTenant(tenantId, OBLIWATCH_ACTOR, () => db('obliwatch_action_requests').where({ tenant_id: tenantId, id }).first(REQUEST_COLUMNS)) as
    Promise<RequestRow | undefined>;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ── POST /action-requests ──────────────────────────────────────────────────────────────────────────────────────

export async function createActionRequest(req: Request, res: Response): Promise<void> {
  const caller = req.obliwatch!;
  const tenantId = caller.tenantId;
  const user = caller.user!;
  const raw = (req.body ?? {}) as Record<string, unknown>;
  // What the journal of a refusal names (filled as the request is read).
  // Before the body is validated (a wipe is refused first), its texts only as bounded strings without control characters.
  const rawText = (v: unknown, max: number): string | undefined =>
    (typeof v === 'string' && v.trim() ? v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max) : undefined);
  const facts0: RefusalFacts = {
    action: raw.action, deviceUuid: raw.deviceUuid, incidentRef: rawText(raw.incidentRef, 200), reason: rawText(raw.reason, 500),
  };
  const rawBy = rawText(raw.requestedBy, 200);
  let label: string | null = user ? `${user.username}${rawBy ? ` (${rawBy})` : ''}`.slice(0, 200) : null;
  const refused = (r: RefusalOf): Promise<void> => auditRefusal(req, tenantId, user, label, r, facts0);
  try {
    // Never a list of targets, whatever its name; never an action outside the whitelist.
    if (Array.isArray(raw.deviceUuid) || ['deviceUuids', 'devices', 'targets', 'deviceIds', 'selection'].some((k) => k in raw)) {
      refuse('actionNotAllowed', 'One device per request: a list of targets is refused', { detail: 'batch_forbidden' });
    }
    if (typeof raw.action === 'string' && !(OBLIWATCH_ACTIONS as readonly string[]).includes(raw.action)) {
      refuse('actionNotAllowed', DESTRUCTIVE.has(raw.action.toLowerCase()) ? 'This action is never available to Obliwatch' : 'Unknown action',
        { detail: DESTRUCTIVE.has(raw.action.toLowerCase()) ? 'destructive_forbidden' : 'unknown_action' });
    }
    const parsed = Body.safeParse(raw);
    if (!parsed.success) { sendError(res, 400, 'body_invalid', parsed.error.issues[0]?.message ?? 'Invalid request'); return; }
    const b = parsed.data;
    const action = b.action as ObliwatchAction;
    facts0.incidentRef = b.incidentRef;
    facts0.reason = b.reason;
    if (b.requestUuid) facts0.requestId = b.requestUuid.toLowerCase();
    label = `${user.username}${b.requestedBy ? ` (${b.requestedBy})` : ''}`.slice(0, 200);
    const pp = PARAMS[action].safeParse(b.params ?? {});
    if (!pp.success) { sendError(res, 400, 'params_invalid', `${action}: ${pp.error.issues[0]?.path.join('.') || 'params'} ${pp.error.issues[0]?.message ?? ''}`.trim()); return; }
    const params = pp.data as Record<string, unknown>;
    const id = (b.requestUuid ?? randomUUID()).toLowerCase();
    const deviceUuid = b.deviceUuid.toLowerCase();

    // Idempotency: the request already recorded under this uuid.
    if (b.requestUuid) {
      const known = await readRequest(tenantId, id);
      if (known) {
        if (String(known.device_uuid).toLowerCase() !== deviceUuid || known.action !== action) {
          await refused({ status: 409, code: 'idempotency_conflict', reason: 'Another request was recorded under this uuid' });
          sendError(res, 409, 'idempotency_conflict', 'Another request was recorded under this uuid');
          return;
        }
        res.status(202).json(acceptedOf(known));
        return;
      }
    }

    const facts = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db('devices as d')
      .leftJoin('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
      .where({ 'd.tenant_id': tenantId, 'd.uuid': deviceUuid })
      .first('d.id', 'd.uuid', 'd.management_channel', 'd.enrollment_state', 'd.ownership', 'd.management_mode', 'd.supervised', 'd.lost_mode_state',
        'a.api_level', 'a.released_at', 'a.amapi_name')) as Facts | undefined;
    if (!facts) { sendError(res, 404, 'device_not_found', 'No such device in this tenant'); return; }
    const deviceId = Number(facts.id);
    facts0.deviceId = deviceId;

    const plan = await asTenant(tenantId, OBLIWATCH_ACTOR, () => planFor(tenantId, action, facts, params));
    if (await asTenant(tenantId, OBLIWATCH_ACTOR, () => tenantFrozen(null, tenantId, facts.management_channel as 'apple_mdm' | 'amapi' | 'legacy_agent'))) {
      throw new Refusal(423, 'tenantFrozen', 'The commands of this tenant are frozen');
    }
    const requester = await asTenant(tenantId, OBLIWATCH_ACTOR, () => checkRights(plan, user.id, tenantId, deviceId));

    const base: RequestRow = {
      id, tenant_id: tenantId, device_id: deviceId, device_uuid: deviceUuid, action, channel: facts.management_channel, path: plan.path,
      state: 'accepted', seq: 1, requested_by: user.id, requester_label: label, azp: caller.azp, reason: b.reason, incident_ref: b.incidentRef,
      pending_action_uuid: null, command_id: null, result: null, code: null,
      expires_at: new Date(trackNow() + REQUEST_TTL_MS), created_at: new Date(), updated_at: new Date(), closed_at: null,
    };
    const prefixed = `${prefixOf(base)} ${b.reason}`.slice(0, 500);
    // What the request table keeps of the parameters: never the phone number.
    const stored = clean({ message: params.message, footnote: params.footnote, phoneGiven: params.phone !== undefined ? true : undefined });
    const ctx = obliwatchCtx(req);

    const created = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction(async (trx) => {
      await enforceCaps(trx, tenantId, user.id);
      if (await trx('obliwatch_action_requests').where({ id }).first('id')) {
        throw new Refusal(409, 'idempotency_conflict', 'Another request was recorded under this uuid');
      }
      const row: RequestRow = { ...base };
      if (plan.path === 'guard') {
        const uuid = randomUUID();
        const now = new Date();
        const jobId = jobIdFor('actions.execute-delayed', uuid);
        await trx('pending_actions').insert({
          uuid, tenant_id: tenantId, action_key: plan.key, family: plan.def.family, requested_by: user.id, requester_side: requester.side,
          approver_fallback: false, selection: JSON.stringify({ deviceIds: [deviceId], mode: 'single', via: 'obliwatch', obliwatchRequest: id }),
          target_device_ids: [deviceId], target_count: 1, params: JSON.stringify(plan.params), reason: prefixed, ticket: b.incidentRef.slice(0, 64),
          delay_seconds: 0, state: 'scheduled', execute_after: now, job_id: jobId,
        });
        await executeJob().sendInTx(trx, { tenantId, actionUuid: uuid }, { id: jobId, startAfter: now, tenantId });
        await audit.appendInTx(trx, {
          tenantId, action: 'guard.action_requested', outcome: 'requested', reason: prefixed, ticket: b.incidentRef.slice(0, 64), links: { action: uuid },
          target: { type: 'device', id: String(deviceId), device: deviceId },
          details: { actionKey: plan.key, family: plan.def.family, level: 'none', delaySeconds: 0, bulk: false, via: 'obliwatch', obliwatchRequest: id },
        }, ctx);
        row.pending_action_uuid = uuid;
      } else if (plan.kind === 'apple') {
        const o = await mdmCommands.enqueue(trx, {
          tenantId, requestType: plan.requestType, deviceIds: [deviceId], params: plan.params, origin: 'system', actor: 'i:obliwatch',
          requestedBy: user.id, reason: prefixed, idempotencyKey: `obliwatch:${id}`, auditCtx: ctx,
        });
        if (!o.commandIds[0]) refuse(o.refused[0]?.code === 'not_supervised' ? 'supervisionRequired' : 'notSupported', `The device service refused the command (${o.refused[0]?.code ?? 'refused'})`, { detail: o.refused[0]?.code ?? 'refused' });
        row.command_id = String(o.commandIds[0]).toLowerCase();
      } else {
        let o;
        try {
          o = await enqueueAndroidCommands(trx, {
            tenantId, type: plan.type, deviceIds: [deviceId], params: plan.params, origin: 'system', actor: 'i:obliwatch', requestedBy: user.id,
            reason: prefixed, idempotencyKey: `obliwatch:${id}`, auditCtx: ctx,
          });
        } catch (err) {
          if (err instanceof AndroidCommandError && err.status < 500) refuse('notSupported', `The command was refused (${err.code})`, { detail: err.code });
          throw err;
        }
        const commandId = o.byDevice.get(deviceId);
        if (!commandId) refuse('notSupported', `The command was refused (${o.refused[0]?.code ?? 'refused'})`, { detail: o.refused[0]?.code ?? 'refused' });
        if (plan.type === 'STOP_LOST_MODE' && !o.replayed) {
          await trx('devices').where({ tenant_id: tenantId, id: deviceId, lost_mode_state: 'on' }).update({ lost_mode_state: 'disabling', lost_mode_changed_at: trx.fn.now() });
        }
        row.command_id = String(commandId).toLowerCase();
      }
      const at = new Date();
      const result: ObliwatchActionResult = { action };
      await trx('obliwatch_action_requests').insert({
        id, tenant_id: tenantId, device_id: deviceId, device_uuid: deviceUuid, action, channel: row.channel, path: row.path, state: 'accepted', seq: 1,
        requested_by: user.id, requester_label: label, azp: caller.azp, reason: b.reason, incident_ref: b.incidentRef, params: JSON.stringify(stored),
        pending_action_uuid: row.pending_action_uuid, command_id: row.command_id, result: JSON.stringify(result), expires_at: row.expires_at,
        created_at: at, updated_at: at,
      });
      await recordEventInTx(trx, row, 1, 'accepted', result, at);
      await auditStepInTx(trx, row, 'accepted', ctx, { params: stored });
      if (plan.path === 'command') {
        // The command is written: the request executes at once (a second transition, a second result).
        await trx('obliwatch_action_requests').where({ tenant_id: tenantId, id }).update({ state: 'executing', seq: 2, updated_at: at });
        row.state = 'executing';
        row.seq = 2;
        await recordEventInTx(trx, row, 2, 'executing', result, at);
        await auditStepInTx(trx, row, 'executing', ctx);
      }
      return row;
    }));
    if (plan.path === 'guard') wakeExecutor();
    res.status(202).json(acceptedOf(created));
  } catch (err) {
    if (err instanceof Refusal) { await refused(err); sendRefusal(res, err); return; }
    if (isAuditUnavailable(err)) { sendError(res, 503, 'audit_unavailable', 'The journal is unavailable: nothing was recorded'); return; }
    if (err instanceof AppError && err.statusCode < 500) {
      // A refusal of the queue (a frozen tenant, a command already open on the device, an invalid parameter).
      const r = new Refusal(err.statusCode === 423 ? 423 : 422, err.code ?? 'notSupported', err.message);
      await refused(r);
      sendRefusal(res, r);
      return;
    }
    if ((err as { code?: string })?.code === '23505') {
      await refused({ status: 409, code: 'idempotency_conflict', reason: 'Another request was recorded under this uuid' });
      sendError(res, 409, 'idempotency_conflict', 'Another request was recorded under this uuid');
      return;
    }
    throw err;
  }
}

// ── GET /action-requests/:id ───────────────────────────────────────────────────────────────────────────────────

export async function getActionRequest(req: Request, res: Response): Promise<void> {
  const tenantId = req.obliwatch!.tenantId;
  const id = String(req.params.id ?? '');
  if (!UUID_RE.test(id)) { sendError(res, 404, 'not_found', 'No such request'); return; }
  let row = await readRequest(tenantId, id.toLowerCase());
  if (!row) { sendError(res, 404, 'not_found', 'No such request'); return; }
  try {
    row = await trackRequest(row);
  } catch (err) {
    // The view of the last recorded state: the tracking runs again at the next read or minute.
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, requestId: id }, 'obliwatch actions: request not tracked on read');
  }
  res.json(viewOf(row));
}

// ── POST /action-requests/:id/cancel ───────────────────────────────────────────────────────────────────────────

/** Before the execution only: a guarded action still scheduled (or paused) is cancelled with its job. */
export async function cancelActionRequest(req: Request, res: Response): Promise<void> {
  const tenantId = req.obliwatch!.tenantId;
  const id = String(req.params.id ?? '').toLowerCase();
  if (!UUID_RE.test(id)) { sendError(res, 404, 'not_found', 'No such request'); return; }
  const row = await readRequest(tenantId, id);
  if (!row) { sendError(res, 404, 'not_found', 'No such request'); return; }
  if (row.state === 'cancelled') { res.json({ requestId: id, state: 'cancelled' }); return; }
  if (row.state !== 'accepted' || row.path !== 'guard') {
    res.status(409).json({ error: 'not_cancellable', message: 'The request is already executing or closed', state: row.state });
    return;
  }
  const ctx = obliwatchCtx(req);
  const by = req.obliwatch!.user ? `${req.obliwatch!.user.username}` : 'obliwatch';
  const reason = `Cancelled by Obliwatch (${by})`;
  try {
    const out = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction(async (trx) => {
      const cur = await trx('obliwatch_action_requests').where({ tenant_id: tenantId, id }).forUpdate().first(REQUEST_COLUMNS) as RequestRow | undefined;
      if (!cur || cur.state !== 'accepted') return { ok: false as const, state: cur?.state ?? 'closed' };
      const pa = await trx('pending_actions').where({ tenant_id: tenantId, uuid: cur.pending_action_uuid }).forUpdate()
        .first('id', 'state', 'job_id', 'requested_by') as { id: number; state: string; job_id: string | null; requested_by: number } | undefined;
      if (!pa || (pa.state !== 'scheduled' && pa.state !== 'paused')) return { ok: false as const, state: pa?.state === 'executing' ? 'executing' : cur.state };
      const now = new Date();
      await trx('pending_actions').where({ id: pa.id }).update({
        state: 'cancelled', cancelled_at: now, cancelled_by: pa.requested_by, cancel_reason: reason, updated_at: now,
      });
      await audit.appendInTx(trx, {
        tenantId, action: 'guard.action_cancelled', outcome: 'cancelled', reason, links: { action: String(cur.pending_action_uuid) },
        details: { from: pa.state, cancelledBy: pa.requested_by, via: 'obliwatch', obliwatchRequest: id },
      }, ctx);
      const result: ObliwatchActionResult = { action: cur.action, code: 'cancelled_by_obliwatch' };
      const next = cur.seq + 1;
      await trx('obliwatch_action_requests').where({ tenant_id: tenantId, id }).update({
        state: 'cancelled', seq: next, result: JSON.stringify(result), code: 'cancelled_by_obliwatch', updated_at: now, closed_at: now,
      });
      const r2: RequestRow = { ...cur, state: 'cancelled', seq: next };
      await recordEventInTx(trx, r2, next, 'cancelled', result, now);
      await auditStepInTx(trx, r2, 'cancelled', ctx, { code: 'cancelled_by_obliwatch', by });
      return { ok: true as const, jobId: pa.job_id };
    }));
    if (!out.ok) {
      res.status(409).json({ error: 'not_cancellable', message: 'The request is already executing or closed', state: out.state });
      return;
    }
    if (out.jobId) await cancelJob(out.jobId);
    res.json({ requestId: id, state: 'cancelled' });
  } catch (err) {
    if (isAuditUnavailable(err)) { sendError(res, 503, 'audit_unavailable', 'The journal is unavailable: nothing was cancelled'); return; }
    throw err;
  }
}

