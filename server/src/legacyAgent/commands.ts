import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import { z } from 'zod';
import {
  BENCH_OWNER_MIN_VERSION_CODE, LEGACY_AGENT_OWNER_COMMAND_TYPES, LEGACY_AGENT_PACKAGE, LEGACY_AGENT_RESULT_CODES, MDM_COMMAND_ORIGINS,
  type DeviceCapability, type LegacyAgentCommandState, type LegacyAgentCommandType, type MdmCommandOrigin,
} from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../audit';
import type { DbActor } from '../db/context';
import { lateCancelOf } from '../guard/types';
import { AppError } from '../middleware/errorHandler';
import { tenantFrozen as frozenFor } from '../guard/frozen';
import { legacyAgentRemote } from './remoteBridge';

/** The freeze of the queue of the bridge agent: the engine's, and apple-edge's mirror (decision PONT-R; guard/frozen.ts). */
const tenantFrozen = (trx: Knex.Transaction, tenantId: number): Promise<boolean> => frozenFor(trx, tenantId, 'legacy_agent');

// =============================================================================
// The queue of the Android bridge agents (docs: agent-pont-android §5.1 to
// §5.3, §4.5): the one writer of legacy_agent_commands.
//   catalogue  the v0 types, their strict parameters, capability, passage
//              (guarded action or restriction) and lifetime
//   enqueue    in the caller's transaction (the tenant's context): one row
//              per device; the guarded types only from the execution of their
//              guarded action (origin 'guard', the pending_actions row of the
//              same key 'executing', no late cancellation: I24), anything
//              else 409 guardedActionRequired; written even while the tenant
//              is frozen (hold_reason 'frozen'), simply not delivered
//   cancel     a 'pending' row only; 'sent' answers already_delivered
//   deliver    at an interrogation: nothing while the tenant is frozen (RS-3,
//              re-deliveries included); else 20 at most, erase first, lock,
//              then by age (RS-2); the 'sent' without result for
//              max(2 × pollSeconds, 600 s) are delivered again (same id)
//   results    applied by rank (a state never goes back, trigger of the
//              migration); a result of an unknown command or of another
//              device is ignored and counted, never told to the agent
// Never a call outside the database: the agent fetches its commands (a lock or
// an erase wakes its long wait after the commit, P0-15 §4.3: remoteBridge.ts).
// =============================================================================

export type LegacyCommandOrigin = MdmCommandOrigin;

export interface CommandSpec {
  type: LegacyAgentCommandType;
  params: z.ZodType<Record<string, unknown>>;
  capability: DeviceCapability;
  /** Key of the restrictions matrix the console request goes through; null: none (inventory) or guarded. */
  restrictionKey: string | null;
  /** Key of the guarded action that alone enqueues this type. */
  guardedBy: string | null;
  lifetimeSeconds: number;
}

const DAY = 86_400;
const SHA_RE = /^[0-9a-f]{64}$/;
const PACKAGE_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/;
const notAgent = (p: string): boolean => p !== LEGACY_AGENT_PACKAGE && !p.startsWith(`${LEGACY_AGENT_PACKAGE}.`);

export const ERASE_ACTION = 'legacy_agent.erase_device';
export const LOCK_ACTION = 'legacy_agent.device_lock';

const SPECS: Record<LegacyAgentCommandType, CommandSpec> = {
  'inventory.refresh': {
    type: 'inventory.refresh', params: z.object({}).strict(), capability: 'mdm:inventory', restrictionKey: null, guardedBy: null,
    lifetimeSeconds: 3 * DAY,
  },
  'device.message': {
    type: 'device.message',
    params: z.object({
      title: z.string().trim().min(1).max(80), text: z.string().trim().min(1).max(500),
      mode: z.enum(['notification', 'fullscreen']),
    }).strict(),
    capability: 'mdm:lock', restrictionKey: 'legacy_agent.message', guardedBy: null, lifetimeSeconds: 3 * DAY,
  },
  'device.lock': {
    type: 'device.lock', params: z.object({}).strict(), capability: 'mdm:lock', restrictionKey: null, guardedBy: LOCK_ACTION,
    lifetimeSeconds: 7 * DAY,
  },
  'device.wipe': {
    type: 'device.wipe', params: z.object({ wipeExternal: z.boolean() }).strict(), capability: 'mdm:wipe', restrictionKey: null,
    guardedBy: ERASE_ACTION, lifetimeSeconds: 7 * DAY,
  },
  'device.reboot': {
    type: 'device.reboot', params: z.object({}).strict(), capability: 'mdm:restart', restrictionKey: 'legacy_agent.restart', guardedBy: null,
    lifetimeSeconds: 3 * DAY,
  },
  'app.install': {
    type: 'app.install',
    params: z.object({
      packageId: z.string().uuid(), packageName: z.string().max(255).regex(PACKAGE_RE).refine(notAgent, 'the agent package is refused'),
      versionCode: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER), sha256: z.string().regex(SHA_RE),
      size: z.number().int().min(1).max(104_857_600), signerSha256: z.string().regex(SHA_RE).optional(),
    }).strict(),
    capability: 'mdm:apps', restrictionKey: 'legacy_agent.apps', guardedBy: null, lifetimeSeconds: 3 * DAY,
  },
  'app.uninstall': {
    type: 'app.uninstall',
    params: z.object({ packageName: z.string().max(255).regex(PACKAGE_RE).refine(notAgent, 'the agent package is refused') }).strict(),
    capability: 'mdm:apps', restrictionKey: 'legacy_agent.apps', guardedBy: null, lifetimeSeconds: 3 * DAY,
  },
  'agent.update': {
    type: 'agent.update',
    params: z.object({
      releaseId: z.string().uuid(), versionCode: z.number().int().min(1).max(2_000_000_000), sha256: z.string().regex(SHA_RE),
      size: z.number().int().min(1).max(104_857_600),
    }).strict(),
    capability: 'mdm:apps', restrictionKey: 'legacy_agent.update', guardedBy: null, lifetimeSeconds: 3 * DAY,
  },
  // P0-15 §4.3: a remote assistance session asked of the device (server/src/remote/sessions.ts alone enqueues it, origin
  // 'remote'; never a console request: consoleCommand answers 409 remoteSessionRequired). operator, operatorOrg and
  // controllerName are filled by the server; the agent tells the user by its notifications who opens the session
  // (§0.1 rule 2: nothing to accept). The reason is optional (§0.1 rule 3: absent when none was given). No secret: the
  // console lists the queue. The control is checked by the module (mdm:remote_control), not by the queue; the
  // restriction is taken by remote/routes.ts, not twice.
  'remote.open': {
    type: 'remote.open',
    params: z.object({
      sessionId: z.string().uuid(), mode: z.enum(['view', 'control']), operator: z.string().trim().min(1).max(80),
      operatorOrg: z.string().trim().min(1).max(120), controllerName: z.string().trim().min(1).max(200),
      reason: z.string().trim().min(1).max(200).optional(), maxMinutes: z.number().int().min(15).max(240),
    }).strict(),
    capability: 'mdm:remote_view', restrictionKey: null, guardedBy: null, lifetimeSeconds: 600,
  },
  // Agent 1.2.0: the APK of an installed app sent back by chunks to POST /agent/v1/pull/<commandId> (pull.ts), stored as a
  // package of the tenant. The agent's own package is refused (it has its versions).
  'app.pull': {
    type: 'app.pull',
    params: z.object({ packageName: z.string().max(255).regex(PACKAGE_RE).refine(notAgent, 'the agent package is refused') }).strict(),
    capability: 'mdm:apps', restrictionKey: 'legacy_agent.apps', guardedBy: null, lifetimeSeconds: DAY,
  },
  // Agent 1.3.0 (lot PONT-POL §8.5): the kiosk of the agent policy left for some minutes, and the policy applied again
  // from a full configuration. Both immediate on the device; the console also needs mdm.policies.manage (routes.ts). No
  // secret: the console lists the queue.
  'kiosk.suspend': {
    type: 'kiosk.suspend', params: z.object({ minutes: z.number().int().min(1).max(240) }).strict(),
    capability: 'mdm:profiles', restrictionKey: null, guardedBy: null, lifetimeSeconds: DAY,
  },
  'policy.reapply': {
    type: 'policy.reapply', params: z.object({}).strict(), capability: 'mdm:profiles', restrictionKey: null, guardedBy: null,
    lifetimeSeconds: DAY,
  },
  // Agent 1.4.0 (lot BANC §3.8, D15): the device given back by the owner agent (its policies, the owner, then the
  // administrator removed). Part of the revocation of a device the agent owns (legacy_agent.revoke, already sensitive),
  // never a console command of its own; refused to an agent older than 1.4.0 (422 agent_too_old).
  'agent.release': {
    type: 'agent.release', params: z.object({}).strict(), capability: 'mdm:remove', restrictionKey: 'legacy_agent.revoke', guardedBy: null,
    lifetimeSeconds: 7 * DAY,
  },
};

/** The command types of the agent policy (lot PONT-POL): the console also needs mdm.policies.manage, and an agent older
 *  than 1.3.0 does not know them (the menu greys them: agentTooOld). */
export const POLICY_COMMAND_TYPES: readonly string[] = ['kiosk.suspend', 'policy.reapply'];

/** The request of a remote assistance session (P0-15 §4.3): never a console command. */
export const REMOTE_OPEN = 'remote.open';

export function commandSpecOrNull(type: unknown): CommandSpec | null {
  return typeof type === 'string' && Object.prototype.hasOwnProperty.call(SPECS, type) ? SPECS[type as LegacyAgentCommandType] : null;
}

export const commandSpecList = (): CommandSpec[] => Object.values(SPECS);

// ── Enqueue ──────────────────────────────────────────────────────────────────

export type RefusalCode = 'not_agent' | 'not_enrolled' | 'revoked';

export interface EnqueueRequest {
  tenantId: number;
  requestType: string;
  /** 1 to 10 000 distinct devices of the tenant. */
  deviceIds: number[];
  params?: Record<string, unknown>;
  origin: LegacyCommandOrigin;
  /** DbActor token: 'u:12', 'j:<queue>', 'i:<name>'. */
  actor: string;
  requestedBy?: number;
  reason?: string;
  ticket?: string;
  approvalId?: number;
  /** A second enqueue with the same key returns the first outcome. */
  idempotencyKey?: string;
  guardActionUuid?: string;
  commandIdFor?: (deviceId: number) => string;
  expiresInSeconds?: number;
  delaySeconds?: number;
  auditCtx?: AuditWriteContext;
}

export interface EnqueueOutcome {
  batchId: string;
  commandIds: string[];
  targets: number;
  refused: Array<{ deviceId: number; code: RefusalCode }>;
  held: boolean;
  replayed: boolean;
}

export const MAX_REQUEST_DEVICES = 10_000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACTOR_RE = /^(u:[1-9][0-9]{0,9}|[jiea]:[a-z][a-z0-9_.:-]{0,65})$/;
const IDEMPOTENCY_RE = /^[A-Za-z0-9_.:@/-]{1,200}$/;

function invalid(message: string, code = 'invalidParams'): never {
  throw new AppError(422, message, code);
}

function guardRequired(): never {
  throw new AppError(409, 'This command goes through its guarded action', 'guardedActionRequired');
}

function jsonOf(v: unknown): unknown {
  if (typeof v !== 'string') return v ?? null;
  try { return JSON.parse(v); } catch { return null; }
}

function actorOfToken(token: string): DbActor {
  const [kind, name] = [token.slice(0, 1), token.slice(2)];
  if (kind === 'u') return { type: 'user', userId: Number(name) };
  if (kind === 'j') return { type: 'job', name };
  if (kind === 'i') return { type: 'integration', name };
  return { type: 'enrollment', name };
}

async function auditContext(req: { actor: string; tenantId: number; auditCtx?: AuditWriteContext }): Promise<AuditWriteContext> {
  return req.auditCtx ?? audit.fromDbActor(actorOfToken(req.actor), req.tenantId);
}

async function replayOf(trx: Knex.Transaction, tenantId: number, key: string): Promise<EnqueueOutcome | null> {
  const rows = await trx('legacy_agent_commands').where({ tenant_id: tenantId, idempotency_key: key }).orderBy('device_id')
    .select('id', 'batch_id', 'hold_reason') as Array<{ id: string; batch_id: string; hold_reason: string | null }>;
  if (rows.length === 0) return null;
  return {
    batchId: String(rows[0].batch_id).toLowerCase(), commandIds: rows.map((r) => String(r.id).toLowerCase()), targets: rows.length,
    refused: [], held: rows.some((r) => r.hold_reason === 'frozen'), replayed: true,
  };
}

/** The devices of the request that may take a command: an enrolled agent of the tenant, not revoked. */
async function eligible(trx: Knex.Transaction, tenantId: number, ids: number[]): Promise<{ kept: number[]; refused: EnqueueOutcome['refused'] }> {
  const rows = await trx('devices as d')
    .leftJoin('legacy_agent_devices as a', function joinSatellite() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereRaw('d.id = ANY (?::int[])', [ids])
    .forUpdate('d')
    .select('d.id', 'd.management_channel', 'd.enrollment_state', 'a.device_id as agent', 'a.revoked_at') as
    Array<{ id: number; management_channel: string; enrollment_state: string; agent: number | null; revoked_at: Date | null }>;
  const byId = new Map(rows.map((r) => [Number(r.id), r]));
  const kept: number[] = [];
  const refused: EnqueueOutcome['refused'] = [];
  for (const id of ids) {
    const r = byId.get(id);
    if (!r || r.management_channel !== 'legacy_agent' || r.agent === null) refused.push({ deviceId: id, code: 'not_agent' });
    else if (r.revoked_at) refused.push({ deviceId: id, code: 'revoked' });
    else if (r.enrollment_state !== 'enrolled') refused.push({ deviceId: id, code: 'not_enrolled' });
    else kept.push(id);
  }
  return { kept, refused };
}

/** The wake of the long waits of `deviceIds` once the outermost transaction committed (remoteBridge.ts); never on a
 *  rollback, never throws. */
export function wakeAfterCommit(trx: Knex.Transaction, tenantId: number, deviceIds: number[]): void {
  const bridge = legacyAgentRemote();
  if (!bridge) return;
  let outer = trx as Knex.Transaction & { parentTransaction?: Knex.Transaction };
  while (outer.parentTransaction) outer = outer.parentTransaction as typeof outer;
  outer.executionPromise?.then(() => bridge.wake(tenantId, deviceIds), () => { /* rolled back: nothing to wake */ });
}

async function enqueue(trx: Knex.Transaction, req: EnqueueRequest): Promise<EnqueueOutcome> {
  const tenantId = Number(req.tenantId);
  if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new Error('legacyAgentCommands.enqueue: tenantId');
  if (!(MDM_COMMAND_ORIGINS as readonly string[]).includes(req.origin)) throw new Error('legacyAgentCommands.enqueue: unknown origin');
  if (!ACTOR_RE.test(String(req.actor))) throw new Error('legacyAgentCommands.enqueue: actor token');
  if (req.idempotencyKey !== undefined && !IDEMPOTENCY_RE.test(req.idempotencyKey)) throw new Error('legacyAgentCommands.enqueue: idempotencyKey');

  if (req.idempotencyKey) {
    const earlier = await replayOf(trx, tenantId, req.idempotencyKey);
    if (earlier) return earlier;
  }

  const spec = commandSpecOrNull(req.requestType);
  if (!spec) throw new AppError(422, 'Unknown command type', 'unknownRequestType');
  const ids = [...new Set((req.deviceIds ?? []).map(Number))];
  if (ids.length === 0 || ids.length > MAX_REQUEST_DEVICES || ids.some((n) => !Number.isSafeInteger(n) || n <= 0)) {
    invalid(`deviceIds: 1 to ${MAX_REQUEST_DEVICES} devices`);
  }
  const parsed = spec.params.safeParse(req.params ?? {});
  if (!parsed.success) invalid(`${spec.type}: ${parsed.error.issues[0]?.message ?? 'invalid parameters'}`);
  const params = parsed.data as Record<string, unknown>;
  const reason = typeof req.reason === 'string' ? req.reason.trim() : '';
  if (reason.length > 500) invalid('reason: 500 characters at most');
  const ticket = typeof req.ticket === 'string' && req.ticket.trim() ? req.ticket.trim() : null;
  if (ticket && ticket.length > 100) invalid('ticket: 100 characters at most');
  const expiresIn = req.expiresInSeconds ?? spec.lifetimeSeconds;
  if (!Number.isInteger(expiresIn) || expiresIn < 60 || expiresIn > 30 * DAY) invalid('expiresInSeconds: 60 seconds to 30 days');
  const delay = req.delaySeconds ?? 0;
  if (!Number.isInteger(delay) || delay < 0 || delay > DAY) invalid('delaySeconds: 0 to 86 400');

  // The guarded types: the engine's execution alone (I24).
  if (spec.guardedBy) {
    if (req.origin !== 'guard' || !req.guardActionUuid || !UUID_RE.test(req.guardActionUuid)) guardRequired();
    const action = await trx('pending_actions').where({ tenant_id: tenantId, uuid: req.guardActionUuid as string }).forShare()
      .first('action_key', 'state', 'result') as { action_key: string; state: string; result: unknown } | undefined;
    if (!action || action.action_key !== spec.guardedBy || action.state !== 'executing' || lateCancelOf(jsonOf(action.result))) guardRequired();
  } else if (req.origin === 'guard' || req.guardActionUuid || req.commandIdFor) {
    invalid(`${spec.type} is not a guarded command`, 'notGuardedCommand');
  }
  // The request of a remote session: its session alone, one device (P0-15 §4.3); the origin 'remote' carries nothing else.
  if ((spec.type === REMOTE_OPEN) !== (req.origin === 'remote')) {
    if (spec.type === REMOTE_OPEN) throw new AppError(409, 'A remote session is opened through /api/remote-sessions', 'remoteSessionRequired');
    invalid('the origin remote carries remote.open only', 'invalidOrigin');
  }
  if (spec.type === REMOTE_OPEN && ids.length !== 1) invalid('remote.open: one device');

  const held = await tenantFrozen(trx, tenantId);
  const { kept, refused } = await eligible(trx, tenantId, ids);
  // Lot BANC §3.8: the commands of the owner agent are refused to an agent older than 1.4.0.
  if ((LEGACY_AGENT_OWNER_COMMAND_TYPES as readonly string[]).includes(spec.type) && kept.length > 0) {
    const old = await trx('legacy_agent_devices').where({ tenant_id: tenantId }).whereRaw('device_id = ANY (?::int[])', [kept])
      .where('agent_version_code', '<', BENCH_OWNER_MIN_VERSION_CODE).first('device_id');
    if (old) throw new AppError(422, `${spec.type}: the agent is older than 1.4.0`, 'agent_too_old');
  }
  const batchId = randomUUID();
  const outcome: EnqueueOutcome = { batchId, commandIds: [], targets: 0, refused, held, replayed: false };
  if (kept.length === 0) return outcome;

  const now = new Date();
  const notBefore = delay > 0 ? new Date(now.getTime() + delay * 1000) : null;
  const expiresAt = new Date(now.getTime() + (delay + expiresIn) * 1000);
  const rows = kept.map((deviceId) => {
    const imposed = req.commandIdFor ? req.commandIdFor(deviceId) : null;
    if (imposed !== null && !UUID_RE.test(imposed)) throw new Error('legacyAgentCommands.enqueue: commandIdFor must return a UUID');
    return {
      id: (imposed ?? randomUUID()).toLowerCase(), tenant_id: tenantId, batch_id: batchId, device_id: deviceId, request_type: spec.type,
      params: JSON.stringify(params), origin: req.origin, actor: req.actor,
      requested_by: Number.isSafeInteger(req.requestedBy) && (req.requestedBy as number) > 0 ? req.requestedBy : null,
      reason: reason || null, ticket, approval_id: Number.isSafeInteger(req.approvalId) ? req.approvalId : null,
      guard_action_uuid: spec.guardedBy ? (req.guardActionUuid as string).toLowerCase() : null,
      idempotency_key: req.idempotencyKey ?? null, not_before: notBefore, expires_at: expiresAt, state: 'pending', state_event_at: now,
      hold_reason: held ? 'frozen' : null, created_at: now, updated_at: now,
    };
  });
  for (let i = 0; i < rows.length; i += 500) {
    const slice = rows.slice(i, i + 500);
    if (req.idempotencyKey) {
      const ins = await trx('legacy_agent_commands').insert(slice)
        .onConflict(trx.raw('(tenant_id, device_id, idempotency_key) WHERE idempotency_key IS NOT NULL')).ignore().returning('id') as Array<{ id: string }>;
      if (ins.length !== slice.length) {
        // A concurrent request with the same key won: its batch is the answer (this transaction wrote nothing else).
        if (i === 0 && ins.length === 0) {
          const earlier = await replayOf(trx, tenantId, req.idempotencyKey);
          if (earlier) return earlier;
        }
        throw new AppError(409, 'This request is already being written', 'idempotencyConflict');
      }
    } else {
      await trx('legacy_agent_commands').insert(slice);
    }
  }
  outcome.commandIds = rows.map((r) => r.id);
  outcome.targets = rows.length;
  // P0-15 §4.3: a lock or an erase does not wait for the next interrogation: the long waits of these devices are woken
  // once the transaction committed (nothing while frozen: nothing would be delivered).
  if (!held && (spec.type === 'device.lock' || spec.type === 'device.wipe')) wakeAfterCommit(trx, tenantId, kept);
  const ctx = await auditContext(req);
  const entry = {
    tenantId, action: 'legacy_agent.command_queued',
    ...(kept.length === 1 ? { target: { type: 'device', id: String(kept[0]), device: kept[0] } } : { targets: { deviceIds: kept } }),
    ...(reason ? { reason } : {}), ...(ticket ? { ticket } : {}),
    ...(Number.isSafeInteger(req.approvalId) ? { approvalIds: [req.approvalId as number] } : {}),
    ...(spec.guardedBy ? { links: { action: req.guardActionUuid as string, ...(rows.length === 1 ? { command: rows[0].id } : {}) } }
      : rows.length === 1 ? { links: { command: rows[0].id } } : {}),
    details: { requestType: spec.type, origin: req.origin, batchId, targets: rows.length, refused: refused.length, held },
  };
  const collect = audit.collectorOf(trx);
  if (collect) collect(entry);
  else await audit.appendInTx(trx, entry, ctx, { onFailure: 'spool' });
  return outcome;
}

// ── Cancel ───────────────────────────────────────────────────────────────────

export type CancelResult = 'cancelled' | 'already_delivered' | 'completed';

async function cancel(trx: Knex.Transaction, tenantId: number, commandId: string, actor: string,
  opts: { allowGuarded?: boolean; auditCtx?: AuditWriteContext; silent?: boolean } = {}): Promise<{ deviceId: number; result: CancelResult }> {
  if (!UUID_RE.test(commandId)) throw new AppError(404, 'Command not found');
  const row = await trx('legacy_agent_commands').where({ tenant_id: tenantId, id: commandId.toLowerCase() }).forUpdate()
    .first('id', 'device_id', 'state', 'guard_action_uuid', 'request_type') as
    { id: string; device_id: number; state: LegacyAgentCommandState; guard_action_uuid: string | null; request_type: string } | undefined;
  if (!row) throw new AppError(404, 'Command not found');
  if (row.guard_action_uuid && !opts.allowGuarded) {
    throw new AppError(409, 'This command is cancelled through its guarded action', 'guardedActionRequired');
  }
  const deviceId = Number(row.device_id);
  if (row.state === 'sent') return { deviceId, result: 'already_delivered' };
  if (row.state !== 'pending') return { deviceId, result: 'completed' };
  const now = new Date();
  await trx('legacy_agent_commands').where({ tenant_id: tenantId, id: row.id })
    .update({ state: 'cancelled', state_event_at: now, cancel_requested_at: now, completed_at: now, result_code: 'cancelled', updated_at: now });
  if (!opts.silent) {
    const ctx = opts.auditCtx ?? await audit.fromDbActor(actorOfToken(actor), tenantId);
    await audit.appendInTx(trx, {
      tenantId, action: 'legacy_agent.command_cancelled', target: { type: 'device', id: String(deviceId), device: deviceId },
      links: { command: String(row.id) }, details: { requestType: row.request_type },
    }, ctx, { onFailure: 'spool' });
  }
  return { deviceId, result: 'cancelled' };
}

/** Cancels every open ('pending') command of a device (revocation); the 'sent' expire. Silent: part of the revocation. */
export async function cancelOpenOfDevice(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<number> {
  const now = new Date();
  return trx('legacy_agent_commands').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('state', ['pending', 'sent'])
    .update({ state: trx.raw("CASE WHEN state = 'pending' THEN 'cancelled' ELSE 'expired' END"), state_event_at: now, completed_at: now,
      cancel_requested_at: now, result_code: 'agent_revoked', updated_at: now });
}

// ── Delivery (§4.5) ──────────────────────────────────────────────────────────

export interface DeliveredCommand { id: string; type: string; params: Record<string, unknown>; issuedAt: number; expiresAt: number }

/** Delivery order (RS-2): erase, lock, the request of a remote session (P0-15 §4.3: the user waits for it), then by
 *  age. A constant: no value interpolated. */
const DELIVERY_ORDER_SQL = "CASE request_type WHEN 'device.wipe' THEN 0 WHEN 'device.lock' THEN 1 WHEN 'remote.open' THEN 2 ELSE 3 END, created_at, id";
export const MAX_DELIVERED = 20;

/**
 * Excludes an agent.update whose version was withdrawn, even when queued or delivered before the withdrawal: a bad
 * build is stopped at once (delivery and download). A constant: no value interpolated; the catalog is readable in
 * every context.
 */
export const WITHDRAWN_UPDATE_EXCLUDED_SQL = "NOT (request_type = 'agent.update' AND EXISTS (SELECT 1 FROM obligarth.legacy_agent_releases r "
  + "WHERE r.id::text = legacy_agent_commands.params->>'releaseId' AND r.withdrawn_at IS NOT NULL))";

/**
 * The commands an interrogation takes, in the tenant's transaction, the satellite already locked: nothing while the
 * tenant is frozen (RS-3: the pending get hold_reason 'frozen'); else at most 20, pending (not_before passed,
 * expires_at ahead) and sent without result for max(2 × pollSeconds, 600 s), erase first, then lock, then by age;
 * `onlyTypes` narrows them (agentTooOld: agent.update and inventory.refresh only).
 */
export async function deliver(trx: Knex.Transaction, tenantId: number, deviceId: number,
  o: {
    pollSeconds: number; frozen: boolean; onlyTypes?: readonly string[];
    /** P0-15 §4.3: the remote.open about to be handed, seen by their session (remoteBridge.ts): the withdrawn ones
     *  (session ended or past its deadline) are not delivered and leave the queue; the deferred ones (the agent took
     *  the session already) are not delivered and stay as they are. */
    admitRemote?: (commandIds: string[]) => Promise<{ withdraw: Set<string>; defer: Set<string> }>;
  }): Promise<DeliveredCommand[]> {
  const now = new Date();
  if (o.frozen) {
    await trx('legacy_agent_commands').where({ tenant_id: tenantId, device_id: deviceId, state: 'pending' }).whereNull('hold_reason')
      .update({ hold_reason: 'frozen', updated_at: now });
    return [];
  }
  const redeliverBefore = new Date(now.getTime() - Math.max(2 * o.pollSeconds, 600) * 1000);
  let q = trx('legacy_agent_commands').where({ tenant_id: tenantId, device_id: deviceId }).where('expires_at', '>', now)
    .where((w) => {
      w.where((p) => p.where('state', 'pending').where((nb) => nb.whereNull('not_before').orWhere('not_before', '<=', now)))
        .orWhere((s) => s.where('state', 'sent').where('delivered_at', '<', redeliverBefore));
    });
  if (o.onlyTypes) q = q.whereIn('request_type', o.onlyTypes as string[]);
  q = q.whereRaw(WITHDRAWN_UPDATE_EXCLUDED_SQL);
  let rows = await q.orderByRaw(DELIVERY_ORDER_SQL).limit(MAX_DELIVERED).forUpdate()
    .select('id', 'request_type', 'params', 'created_at', 'expires_at') as
    Array<{ id: string; request_type: string; params: unknown; created_at: Date; expires_at: Date }>;
  const remote = rows.filter((r) => r.request_type === REMOTE_OPEN).map((r) => String(r.id).toLowerCase());
  if (remote.length > 0 && o.admitRemote) {
    const { withdraw, defer } = await o.admitRemote(remote);
    if (defer.size > 0) rows = rows.filter((r) => !defer.has(String(r.id).toLowerCase()));
    if (withdraw.size > 0) {
      // A session that ended there may have withdrawn its pending command already (cancelled): the others leave the
      // queue here, never delivered (a 'sent' one, delivered before, expires).
      await trx('legacy_agent_commands').where({ tenant_id: tenantId }).whereIn('id', [...withdraw]).whereIn('state', ['pending', 'sent'])
        .update({
          state: trx.raw("CASE WHEN state = 'pending' THEN 'cancelled' ELSE 'expired' END"), state_event_at: now, completed_at: now,
          result_code: trx.raw("CASE WHEN state = 'pending' THEN 'cancelled' ELSE result_code END"), updated_at: now,
        });
      rows = rows.filter((r) => !withdraw.has(String(r.id).toLowerCase()));
    }
  }
  if (rows.length === 0) return [];
  await trx('legacy_agent_commands').where({ tenant_id: tenantId }).whereIn('id', rows.map((r) => r.id))
    .update({ state: 'sent', state_event_at: now, delivered_at: now, hold_reason: null, delivery_count: trx.raw('delivery_count + 1'), updated_at: now });
  return rows.map((r) => ({
    id: String(r.id).toLowerCase(), type: r.request_type, params: (jsonOf(r.params) ?? {}) as Record<string, unknown>,
    issuedAt: Math.floor(new Date(r.created_at).getTime() / 1000), expiresAt: Math.floor(new Date(r.expires_at).getTime() / 1000),
  }));
}

// ── Results (§4.5, §5.3) ─────────────────────────────────────────────────────

export interface AgentResult { commandId: string; status: 'acknowledged' | 'error' | 'rejected'; code: string; detail?: Record<string, unknown>; at: number }

const RESULT_CODES = new Set<string>(LEGACY_AGENT_RESULT_CODES);

/**
 * Applies the results of an interrogation to the device's own commands: a delivered command ('sent', or 'expired'
 * meanwhile) takes its final state; one already final keeps it (duplicate). Every result's id is accepted (the agent
 * empties its outbox); those of an unknown command or of another device are ignored and counted only.
 */
export async function applyResults(trx: Knex.Transaction, tenantId: number, deviceId: number, results: AgentResult[]):
  Promise<{ accepted: string[]; applied: number; ignored: number; applied_rows: Array<{ id: string; type: string; status: string; code: string }> }> {
  const accepted: string[] = [];
  const appliedRows: Array<{ id: string; type: string; status: string; code: string }> = [];
  let ignored = 0;
  const now = new Date();
  for (const r of results) {
    const id = r.commandId.toLowerCase();
    accepted.push(id);
    const row = await trx('legacy_agent_commands').where({ tenant_id: tenantId, id }).forUpdate()
      .first('id', 'device_id', 'state', 'request_type', 'delivered_at') as
      { id: string; device_id: number; state: string; request_type: string; delivered_at: Date | null } | undefined;
    if (!row || Number(row.device_id) !== deviceId || !row.delivered_at) { ignored++; continue; }
    if (row.state !== 'sent' && row.state !== 'expired') continue;
    // An expired command the agent refused (expired_on_device…) stays expired: 'rejected' has the rank of 'expired'
    // (3) and the trigger refuses a change between two final states of the same rank, which failed the whole
    // interrogation (503), again at every retry since the agent keeps the result in its outbox.
    if (row.state === 'expired' && r.status === 'rejected') continue;
    const code = RESULT_CODES.has(r.code) ? r.code : 'internal';
    let detail: string | null = null;
    if (r.detail && Object.keys(r.detail).length > 0) {
      const text = JSON.stringify(r.detail);
      detail = Buffer.byteLength(text, 'utf8') <= 2048 ? text : JSON.stringify({ truncated: true });
    }
    await trx('legacy_agent_commands').where({ tenant_id: tenantId, id: row.id }).update({
      state: r.status, state_event_at: now, completed_at: now, result_code: code, result_detail: detail, updated_at: now,
    });
    appliedRows.push({ id: row.id, type: row.request_type, status: r.status, code });
  }
  return { accepted, applied: appliedRows.length, ignored, applied_rows: appliedRows };
}

/** An agent.update is acknowledged as soon as an interrogation announces a versionCode at least its target's (§5.3). */
export async function acknowledgeUpdates(trx: Knex.Transaction, tenantId: number, deviceId: number, versionCode: number): Promise<number> {
  const now = new Date();
  return trx('legacy_agent_commands').where({ tenant_id: tenantId, device_id: deviceId, request_type: 'agent.update' })
    .whereIn('state', ['pending', 'sent', 'expired']).whereNotNull('delivered_at')
    .whereRaw("(params->>'versionCode')::bigint <= ?", [versionCode])
    .update({ state: 'acknowledged', state_event_at: now, completed_at: now, result_code: 'update_installed', updated_at: now });
}

/** The packages a successful app.install put on the device (device_apps.managed). */
export async function managedPackages(q: Knex | Knex.Transaction, tenantId: number, deviceId: number): Promise<Set<string>> {
  const rows = await q('legacy_agent_commands').where({ tenant_id: tenantId, device_id: deviceId, request_type: 'app.install', state: 'acknowledged' })
    .select(q.raw("params->>'packageName' AS p")) as Array<{ p: string | null }>;
  return new Set(rows.map((r) => r.p).filter((p): p is string => !!p));
}

/** Open commands whose lifetime passed: 'expired' (legacy_agent.commands-expire), in the tenant's transaction. */
export async function expireDue(trx: Knex.Transaction, tenantId: number, limit = 1000): Promise<number> {
  const now = new Date();
  const ids = await trx('legacy_agent_commands').where({ tenant_id: tenantId }).whereIn('state', ['pending', 'sent'])
    .where('expires_at', '<=', now).limit(limit).forUpdate().skipLocked().pluck('id') as string[];
  if (ids.length === 0) return 0;
  return trx('legacy_agent_commands').where({ tenant_id: tenantId }).whereIn('id', ids)
    .update({ state: 'expired', state_event_at: now, completed_at: now, updated_at: now });
}

export const legacyAgentCommands = { enqueue, cancel };
export type { LegacyAgentCommandState };
