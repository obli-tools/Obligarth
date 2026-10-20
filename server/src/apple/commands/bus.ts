import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import type {
  MdmCancelOutcome, MdmCommandOrigin, MdmRefusalCode, MdmRelaunchOutcome, MdmTargetState, NanoEnrollType, Ownership,
} from '@obligarth/shared';
import { MDM_COMMAND_ORIGINS } from '@obligarth/shared';
import { audit, type AuditEntryInput, type AuditWriteContext } from '../../audit';
import type { DbActor } from '../../db/context';
import { tenantFrozen as frozenFor } from '../../guard/frozen';
import { lateCancelOf } from '../../guard/types';
import { jobIdFor, type JobHandle } from '../../jobs';
import { AppError } from '../../middleware/errorHandler';
import { privacyRulesFor, type PrivacyRules } from '../devices/privacy';
import { realtime } from '../realtime';
import { commandSpecOrNull, guardedActionOf, type CommandDeviceContext, type CommandSpec } from './catalog';
import { PlistError, commandPlist, plistFingerprint, type PlistDict } from './plist';
import { findSecrets, installPayload, profileSource, type ResolvedProfile } from './sensitive';
import { afterCommit, finalizeTargets } from './targets';

// =============================================================================
// Bus of the MDM commands (docs: integration-apple-edge §8.1, §8.4, §8.7;
// modele-donnees-mdm §6.1, §6.2): the one writer of mdm_commands and of the
// creation of their targets.
//   enqueue  in the caller's transaction (the tenant's context already set):
//            the commands and their targets ('pending'), one job
//            mdm.commands.submit per command (sendInTx: it exists only if the
//            transaction commits), the audit entry mdm.command_requested of
//            the batch. NEVER a call to apple-edge (T-1): the submission is
//            the job's.
//   cancel   in the caller's transaction: the targets never submitted are
//            cancelled at once; those submitted are marked and the job
//            mdm.commands.cancel asks apple-edge.
//   relaunch a push for the open targets of a command (network: outside any
//            transaction; commands/submit.ts).
// One row of mdm_commands is one CommandUUID: a v4 UUID, or for a guarded
// action the deterministic one the engine imposes (an execution run again
// finds its commands). Its plist is frozen at its creation with its SHA-256:
// a retried submission sends the same bytes, which apple-edge takes as the
// same command. A request gives a batch: one command per device when the
// plist depends on the device, else one command for the devices whose
// Command dictionaries are equal, by slices of 5 000 targets.
// A guarded type (EraseDevice, DeviceLock, EnableLostMode, RemoveProfile of
// the enrollment profile) is enqueued only from the execution of its guarded
// action: origin 'guard' and the pending_actions row of the same action key
// and tenant in the state 'executing' (I24); anything else: 409
// guardedActionRequired.
// =============================================================================

export type CommandOrigin = MdmCommandOrigin;
export type TargetState = MdmTargetState;
export type RefusalCode = MdmRefusalCode;

export interface EnqueueRequest {
  tenantId: number;
  requestType: string;
  /** 1 to 10 000 distinct devices of the tenant. */
  deviceIds: number[];
  params?: Record<string, unknown>;
  /** Per-device parameters merged over params (perDevice specs, e.g. DeviceName). */
  deviceParams?: Record<number, Record<string, unknown>>;
  origin: CommandOrigin;
  /** DbActor token: 'u:12', 'j:<queue>', 'i:<name>', 'e:<flow>'. */
  actor: string;
  requestedBy?: number;
  reason?: string;
  ticket?: string;
  approvalId?: number;
  /** Unique per tenant; a second enqueue with the same key returns the first outcome. */
  idempotencyKey?: string;
  /** Technical deferral (inventory spreading): not_before = now() + delay; 0 to 86 400 seconds.
   *  Never used for the cancellable delays of destructive actions (the guard engine owns them: I24). */
  delaySeconds?: number;
  /** Guarded actions: the pending_actions row, which must be 'executing' in this transaction. */
  guardActionUuid?: string;
  /** Guarded actions: imposed CommandUUID per device (jobIdFor('mdm.command', '<action>:<device>')). */
  commandIdFor?: (deviceId: number) => string;
  expiresInSeconds?: number;
  push?: boolean;
  /** Who the audit entry names (a route: audit.fromRequest; a job: audit.fromJob); default: the actor's token. */
  auditCtx?: AuditWriteContext;
}

export interface EnqueueOutcome {
  batchId: string;
  commandIds: string[];
  targets: number;
  refused: Array<{ deviceId: number; code: RefusalCode }>;
  /** The tenant's commands are frozen: the commands wait (submit_state 'held'). */
  held: boolean;
  notBefore: string | null;
  /** True when idempotencyKey matched an earlier request. */
  replayed: boolean;
}

export type CancelOutcome = MdmCancelOutcome;
export type RelaunchOutcome = MdmRelaunchOutcome;

export interface CancelOptions {
  auditCtx?: AuditWriteContext;
  /** reject_code of the targets cancelled before their submission (default cancelled_by_user). */
  rejectCode?: 'cancelled_by_user' | 'setup_plan_cancelled';
  /** The caller is the guard engine, or the system on its behalf: a command of a guarded action may be cancelled. */
  allowGuarded?: boolean;
  /** No audit entry (a cancellation that is part of another journaled operation). */
  silent?: boolean;
}

export interface MdmCommandBus {
  /** Writes the commands and targets in trx and enqueues mdm.commands.submit with sendInTx. No network. */
  enqueue(trx: Knex.Transaction, req: EnqueueRequest): Promise<EnqueueOutcome>;
  cancel(trx: Knex.Transaction, tenantId: number, commandId: string, deviceIds: number[] | null, actor: string,
    opts?: CancelOptions): Promise<CancelOutcome>;
  /** Network call: outside any transaction. */
  relaunch(tenantId: number, commandId: string, deviceIds: number[] | null, actor: string,
    opts?: { auditCtx?: AuditWriteContext; requestId?: string }): Promise<RelaunchOutcome>;
}

/** Targets of one shared command (apple-edge takes 10 000). */
export const SHARED_COMMAND_TARGETS = 5_000;
export const MAX_REQUEST_DEVICES = 10_000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACTOR_RE = /^(u:[1-9][0-9]{0,9}|[jiea]:[a-z][a-z0-9_.:-]{0,65})$/;
const IDEMPOTENCY_RE = /^[A-Za-z0-9_.:@/-]{1,200}$/;
const USER_ORIGINS = new Set<CommandOrigin>(['console', 'bulk', 'approval', 'guard']);
const OPEN_STATES: readonly TargetState[] = ['pending', 'queued', 'sent', 'notnow'];

type SubmitPayload = { tenantId: number; commandId: string };
type CancelPayload = { tenantId: number; commandId: string; requestedAt: string };
let submitJob: JobHandle<SubmitPayload> | null = null;
let cancelJob: JobHandle<CancelPayload> | null = null;
let relaunchImpl: MdmCommandBus['relaunch'] | null = null;

/** commands/submit.ts hands its jobs and its network half at registration (no import cycle). */
export function bindCommandJobs(h: { submit: JobHandle<SubmitPayload>; cancel: JobHandle<CancelPayload>; relaunch: MdmCommandBus['relaunch'] }): void {
  submitJob = h.submit;
  cancelJob = h.cancel;
  relaunchImpl = h.relaunch;
}

function invalid(message: string, code = 'invalidParams', details?: Record<string, unknown>): never {
  throw new AppError(422, message, code, details);
}

function guardRequired(): never {
  throw new AppError(409, 'This command goes through its guarded action', 'guardedActionRequired');
}

/** A jsonb column as the driver gives it (an object), or as a text (parsed); anything else: null. */
function jsonOf(v: unknown): unknown {
  if (typeof v !== 'string') return v ?? null;
  try { return JSON.parse(v); } catch { return null; }
}

/** The database actor a token names (the audit's default context). */
function actorOfToken(token: string): DbActor {
  const [kind, name] = [token.slice(0, 1), token.slice(2)];
  if (kind === 'u') return { type: 'user', userId: Number(name) };
  if (kind === 'j') return { type: 'job', name };
  if (kind === 'i') return { type: 'integration', name };
  if (kind === 'e') return { type: 'enrollment', name };
  return { type: 'anonymous', name } as DbActor;
}

async function auditContext(req: { actor: string; tenantId: number; auditCtx?: AuditWriteContext }): Promise<AuditWriteContext> {
  return req.auditCtx ?? audit.fromDbActor(actorOfToken(req.actor), req.tenantId);
}

/**
 * The entry of a request or a cancellation, in the caller's transaction (it never blocks: spooled on a failure).
 * Rule G-7 (review INT-RC8; review of lot B4, INT-B4-R3): when the caller is a handler of the outbox (the follow-up
 * of a result, a hook of a final target), its transaction is the batch of the consumer; appending here would lock
 * the chain head of the tenant until the end of that batch, in the order of the events. The entry is then handed
 * to the collector the consumer bound to its transaction, which writes it at the end of the batch (ascending tenant
 * order, with the event's id, in the name of the consumer).
 */
async function journalInTx(trx: Knex.Transaction, entry: AuditEntryInput, who: { actor: string; tenantId: number; auditCtx?: AuditWriteContext }): Promise<void> {
  const collect = audit.collectorOf(trx);
  if (collect) {
    collect(entry);
    return;
  }
  await audit.appendInTx(trx, entry, await auditContext(who), { onFailure: 'spool' });
}

interface DeviceRow {
  id: number;
  management_channel: string;
  enrollment_state: string;
  ownership: Ownership;
  supervised: boolean;
  platform: string | null;
  os_version: string | null;
  enrollment_id: string;
  nano_enroll_type: NanoEnrollType;
  has_unlock_token: boolean;
  identity_cert_pem?: string | null;
}

/** The prerequisites of §8.3 for one device; null: the device takes the command. */
export function refusalOf(spec: CommandSpec<any>, d: Pick<DeviceRow, 'management_channel' | 'enrollment_state' | 'ownership' | 'supervised' | 'has_unlock_token'> | undefined):
  RefusalCode | null {
  if (!d || d.management_channel !== 'apple_mdm') return 'not_apple';
  const state = d.enrollment_state;
  if (!(spec.enrollmentStates as readonly string[]).includes(state)) {
    // A command of the setup assistant asked for a device that already left it.
    if (state === 'enrolled' && spec.enrollmentStates.length === 1 && spec.enrollmentStates[0] === 'awaiting_configuration') return 'awaiting_configuration_only';
    return 'not_enrolled';
  }
  if (!spec.ownership.includes(d.ownership)) return 'ownership';
  if (spec.supervised === 'required' && d.supervised !== true) return 'not_supervised';
  if (spec.requestType === 'ClearPasscode' && d.has_unlock_token !== true) return 'no_unlock_token';
  return null;
}

interface Planned {
  id: string;
  devices: DeviceRow[];
  plist: string;
  sha256: string;
  params: Record<string, unknown>;
}

async function replayOf(trx: Knex.Transaction, tenantId: number, key: string): Promise<EnqueueOutcome | null> {
  // The commands of the Apple platform only (lot AN-D: an Android command of the queue stores its key 'amapi:…').
  const first = await trx('mdm_commands').where({ tenant_id: tenantId, idempotency_key: key, platform: 'apple' }).first('id', 'batch_id', 'not_before', 'submit_state') as
    { id: string; batch_id: string | null; not_before: Date | null; submit_state: string } | undefined;
  if (!first) return null;
  const commands = first.batch_id
    ? await trx('mdm_commands').where({ tenant_id: tenantId, batch_id: first.batch_id, platform: 'apple' }).orderBy('created_at').orderBy('id').select('id', 'submit_state') as
      Array<{ id: string; submit_state: string }>
    : [{ id: first.id, submit_state: first.submit_state }];
  const ids = commands.map((c) => String(c.id).toLowerCase());
  const n = await trx('mdm_command_targets').where({ tenant_id: tenantId }).whereIn('command_id', ids).count('* as n').first() as { n: string | number } | undefined;
  return {
    batchId: String(first.batch_id ?? first.id).toLowerCase(), commandIds: ids, targets: Number(n?.n ?? 0), refused: [],
    held: commands.some((c) => c.submit_state === 'held'), notBefore: first.not_before ? new Date(first.not_before).toISOString() : null, replayed: true,
  };
}

/** The mirror of a freeze set at apple-edge (tenant_apple_edge.commands_frozen): the freeze mirror of the Apple channel
 *  (registerFreezeMirror, lot AN-P). */
export async function appleEdgeFrozen(q: Knex | Knex.Transaction, tenantId: number): Promise<boolean> {
  const m = await q('tenant_apple_edge').where({ tenant_id: tenantId }).first('commands_frozen') as { commands_frozen: boolean } | undefined;
  return m?.commands_frozen === true;
}

/** Is the tenant frozen for the Apple commands (the guard engine's emergency freeze, or the mirror of a freeze set at
 *  apple-edge)? The generic reader is guard/frozen.ts (tenantFrozen of a channel). */
export async function tenantFrozen(trx: Knex.Transaction, tenantId: number): Promise<boolean> {
  return frozenFor(trx, tenantId, 'apple_mdm');
}

async function enqueue(trx: Knex.Transaction, req: EnqueueRequest): Promise<EnqueueOutcome> {
  const tenantId = Number(req.tenantId);
  if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new Error('mdmCommands.enqueue: tenantId');
  if (!(MDM_COMMAND_ORIGINS as readonly string[]).includes(req.origin)) throw new Error('mdmCommands.enqueue: unknown origin');
  if (!ACTOR_RE.test(String(req.actor))) throw new Error('mdmCommands.enqueue: actor token');
  if (req.idempotencyKey !== undefined && !IDEMPOTENCY_RE.test(req.idempotencyKey)) throw new Error('mdmCommands.enqueue: idempotencyKey');
  if (!submitJob) throw new Error('mdm.commands.submit is not registered (registerAppleModule)');

  // 1. Idempotence: the batch of an earlier request with the same key.
  if (req.idempotencyKey) {
    const earlier = await replayOf(trx, tenantId, req.idempotencyKey);
    if (earlier) return earlier;
  }

  // 2. The type, its parameters, the bounds, the guarded types.
  const spec = commandSpecOrNull(req.requestType);
  if (!spec) throw new AppError(422, 'Unknown command type', 'unknownRequestType');
  const ids = [...new Set((req.deviceIds ?? []).map(Number))];
  if (ids.length === 0 || ids.length > MAX_REQUEST_DEVICES || ids.some((n) => !Number.isSafeInteger(n) || n <= 0)) {
    invalid(`deviceIds: 1 to ${MAX_REQUEST_DEVICES} devices`);
  }
  if (ids.length > spec.maxTargets) invalid(`${spec.requestType}: ${spec.maxTargets} device(s) at most per request`, 'tooManyTargets', { max: spec.maxTargets });
  const parse = (raw: Record<string, unknown>): Record<string, unknown> => {
    const p = spec.params.safeParse(raw ?? {});
    if (!p.success) invalid(`${spec.requestType}: ${p.error.issues[0]?.message ?? 'invalid parameters'}`);
    return p.data as Record<string, unknown>;
  };
  const baseParams = parse(req.params ?? {});
  const perDeviceParams = new Map<number, Record<string, unknown>>();
  if (req.deviceParams) {
    for (const id of ids) {
      const over = req.deviceParams[id];
      if (over) perDeviceParams.set(id, parse({ ...(req.params ?? {}), ...over }));
    }
  }
  const reason = typeof req.reason === 'string' ? req.reason.trim() : '';
  if (spec.reasonRequired && reason.length < 10) throw new AppError(422, 'A reason of 10 characters at least is required', 'reasonRequired');
  if (reason.length > 500) invalid('reason: 500 characters at most');
  const ticket = typeof req.ticket === 'string' && req.ticket.trim() ? req.ticket.trim() : null;
  if (ticket && ticket.length > 100) invalid('ticket: 100 characters at most');
  const delay = req.delaySeconds ?? 0;
  if (!Number.isInteger(delay) || delay < 0 || delay > 86_400) invalid('delaySeconds: 0 to 86 400');
  const expiresIn = req.expiresInSeconds ?? spec.expiresInSeconds;
  if (!Number.isInteger(expiresIn) || expiresIn < 60 || expiresIn > 90 * 86_400) invalid('expiresInSeconds: 60 seconds to 90 days');

  // Parameters a spec reserves to the system origins (the items a policy compiles for Settings) never come from a
  // user's request.
  if (spec.systemOnly && USER_ORIGINS.has(req.origin) && [baseParams, ...perDeviceParams.values()].some((p) => spec.systemOnly!(p))) {
    invalid(`${spec.requestType}: these parameters are reserved to the policies`);
  }

  const guardKeys = new Set<string>();
  for (const p of [baseParams, ...perDeviceParams.values()]) {
    const k = guardedActionOf(spec, p);
    guardKeys.add(k ?? '');
  }
  const guardKey = [...guardKeys].find((k) => k !== '') ?? null;
  if (guardKey) {
    if (guardKeys.size > 1 || req.origin !== 'guard' || !req.guardActionUuid || !UUID_RE.test(req.guardActionUuid)) guardRequired();
    // The action as the engine holds it: of this tenant, of this key, being executed, and not cancelled meanwhile.
    // Locked for the transaction: it cannot be closed or cancelled while its commands are written. A late
    // cancellation marks the action under the same row lock (guard/operations.ts): either it waits for these
    // commands and withdraws them, or its mark is read here and nothing is written.
    const action = await trx('pending_actions').where({ tenant_id: tenantId, uuid: req.guardActionUuid as string }).forShare()
      .first('action_key', 'state', 'result') as { action_key: string; state: string; result: unknown } | undefined;
    if (!action || action.action_key !== guardKey || action.state !== 'executing' || lateCancelOf(jsonOf(action.result))) guardRequired();
  } else if (req.origin === 'guard' || req.guardActionUuid || req.commandIdFor) {
    invalid(`${spec.requestType} is not a guarded command`, 'notGuardedCommand');
  }

  // 5 (first half). The freeze: a request of a user, an approval or a guarded action is refused, nothing is written.
  const frozen = await tenantFrozen(trx, tenantId);
  if (frozen && USER_ORIGINS.has(req.origin)) throw new AppError(423, 'The commands of this tenant are frozen', 'tenantFrozen');

  // 3. The devices, in one query; their satellites locked for a per-device command (two requests on one device
  //    are serialised). A device that is not an Apple record of the tenant is set aside like any other refusal.
  const needsIdentity = spec.requestType === 'InstallProfile';
  const cols = ['d.id', 'd.management_channel', 'd.enrollment_state', 'd.ownership', 'd.supervised', 'd.platform', 'd.os_version',
    'a.enrollment_id', 'a.nano_enroll_type', 'a.has_unlock_token', ...(needsIdentity ? ['a.identity_cert_pem'] : [])];
  let q = trx('devices as d')
    .join('apple_devices as a', function joinSatellite() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereRaw('d.id = ANY (?::int[])', [ids]);
  if (spec.perDevice) q = q.forUpdate('a');
  const rows = await q.select(cols) as DeviceRow[];
  const byId = new Map(rows.map((r) => [Number(r.id), { ...r, id: Number(r.id) }]));
  const refused: Array<{ deviceId: number; code: RefusalCode }> = [];
  let kept: DeviceRow[] = [];
  for (const id of ids) {
    const d = byId.get(id);
    const code = refusalOf(spec, d);
    if (code) refused.push({ deviceId: id, code });
    else kept.push(d as DeviceRow);
  }
  if (spec.singleOpen && kept.length > 0) {
    const open = await trx('mdm_command_targets as t')
      .join('mdm_commands as c', function joinCommand() { this.on('c.id', '=', 't.command_id').andOn('c.tenant_id', '=', 't.tenant_id'); })
      .where({ 't.tenant_id': tenantId, 'c.request_type': spec.requestType }).whereIn('t.state', OPEN_STATES as TargetState[])
      .whereRaw('t.device_id = ANY (?::int[])', [kept.map((d) => d.id)]).distinct('t.device_id') as Array<{ device_id: number }>;
    const busy = new Set(open.map((o) => Number(o.device_id)));
    if (busy.size > 0) {
      for (const d of kept) if (busy.has(d.id)) refused.push({ deviceId: d.id, code: 'already_open' });
      kept = kept.filter((d) => !busy.has(d.id));
    }
  }

  // 4. The plists: one per device, or one per group of equal Command dictionaries; no secret in clear (§8.8).
  const rulesCache = new Map<string, PrivacyRules>();
  const rulesOf = async (d: DeviceRow): Promise<PrivacyRules> => {
    const k = `${d.ownership}|${d.nano_enroll_type}`;
    let r = rulesCache.get(k);
    if (!r) {
      r = await privacyRulesFor(trx, tenantId, d.ownership, d.nano_enroll_type);
      rulesCache.set(k, r);
    }
    return r;
  };
  const batchId = randomUUID();
  const built: Array<{ device: DeviceRow; command: PlistDict; params: Record<string, unknown>; fingerprint: string }> = [];
  const supersede: Array<{ deviceId: number; identifier: string }> = [];
  for (const d of kept) {
    const params = perDeviceParams.get(d.id) ?? baseParams;
    const ctx: CommandDeviceContext = {
      deviceId: d.id, enrollmentId: d.enrollment_id, enrollmentType: d.nano_enroll_type, ownership: d.ownership, supervised: d.supervised,
      platform: d.platform, osVersion: d.os_version, privacy: await rulesOf(d), identityCertPem: d.identity_cert_pem ?? null,
    };
    let command: PlistDict;
    let stored = params;
    try {
      if (spec.requestType === 'InstallProfile') {
        const source = profileSource(String(params.source));
        if (!source) throw new AppError(422, 'Unknown profile source', 'unknownProfileSource');
        const resolved = await source.resolve(trx, tenantId, String(params.profileRef), ctx) as ResolvedProfile;
        const payload = installPayload(resolved, ctx);
        if (!payload.ok) { refused.push({ deviceId: d.id, code: payload.code }); continue; }
        command = { Payload: payload.payload };
        if (payload.identifier) {
          stored = { ...params, profileIdentifier: payload.identifier.slice(0, 255) };
          supersede.push({ deviceId: d.id, identifier: payload.identifier.slice(0, 255) });
        }
      } else {
        command = spec.build(params, ctx);
      }
    } catch (err) {
      if (err instanceof PlistError) invalid(`${spec.requestType}: ${err.message}`);
      throw err;
    }
    const secrets = findSecrets(spec.requestType, command);
    if (secrets.length > 0) {
      // Key names only: never a value.
      throw new AppError(422, 'The command would carry a secret in clear', 'secretInCommand', { where: secrets.slice(0, 5).map((s) => s.path) });
    }
    built.push({ device: d, command, params: stored, fingerprint: spec.perDevice ? `d:${d.id}` : plistFingerprint(command) });
  }

  const planned: Planned[] = [];
  const finish = (devices: DeviceRow[], command: PlistDict, params: Record<string, unknown>): void => {
    const imposed = req.commandIdFor ? req.commandIdFor(devices[0].id) : null;
    if (imposed !== null && !UUID_RE.test(imposed)) throw new Error('mdmCommands.enqueue: commandIdFor must return a UUID');
    const id = (imposed ?? randomUUID()).toLowerCase();
    try {
      const p = commandPlist(id, spec.requestType, command);
      planned.push({ id, devices, plist: p.plist, sha256: p.sha256, params });
    } catch (err) {
      if (err instanceof PlistError && err.code === 'too_large') throw new AppError(413, 'The command is too large', 'commandTooLarge');
      if (err instanceof PlistError) invalid(`${spec.requestType}: ${err.message}`);
      throw err;
    }
  };
  if (spec.perDevice || req.commandIdFor) {
    for (const b of built) finish([b.device], b.command, b.params);
  } else {
    const groups = new Map<string, typeof built>();
    for (const b of built) {
      const g = groups.get(b.fingerprint);
      if (g) g.push(b); else groups.set(b.fingerprint, [b]);
    }
    for (const g of groups.values()) {
      for (let i = 0; i < g.length; i += SHARED_COMMAND_TARGETS) {
        const slice = g.slice(i, i + SHARED_COMMAND_TARGETS);
        finish(slice.map((b) => b.device), slice[0].command, slice[0].params);
      }
    }
  }

  const held = frozen;                                  // the other origins wait for the unfreeze
  const now = new Date();
  const notBefore = delay > 0 ? new Date(now.getTime() + delay * 1000) : null;
  const outcome: EnqueueOutcome = {
    batchId, commandIds: planned.map((p) => p.id), targets: planned.reduce((n, p) => n + p.devices.length, 0), refused, held,
    notBefore: notBefore ? notBefore.toISOString() : null, replayed: false,
  };
  if (planned.length === 0) return outcome;

  // "Last state wins" (§8.3): an InstallProfile of the same profile identifier cancels the target of the previous
  // one that the device has not received yet.
  for (const s of supersede) {
    const earlier = await trx('mdm_command_targets as t')
      .join('mdm_commands as c', function joinCommand() { this.on('c.id', '=', 't.command_id').andOn('c.tenant_id', '=', 't.tenant_id'); })
      .where({ 't.tenant_id': tenantId, 't.device_id': s.deviceId, 'c.request_type': 'InstallProfile' })
      .whereIn('t.state', ['pending', 'queued']).whereRaw("c.params->>'profileIdentifier' = ?", [s.identifier])
      .select('t.command_id') as Array<{ command_id: string }>;
    for (const e of earlier) {
      await cancel(trx, tenantId, String(e.command_id), [s.deviceId], req.actor, { silent: true, allowGuarded: false });
    }
  }

  // 6. The commands and their targets, the submission jobs, the audit entry of the batch.
  const expiresAt = new Date(now.getTime() + (delay + expiresIn) * 1000);
  const first = planned[0];
  const row = (p: Planned, key: string | null) => ({
    id: p.id, tenant_id: tenantId, batch_id: batchId, platform: 'apple', request_type: spec.requestType, params: JSON.stringify(p.params),
    plist: p.plist, plist_sha256: p.sha256, origin: req.origin, actor: req.actor,
    requested_by: Number.isSafeInteger(req.requestedBy) && (req.requestedBy as number) > 0 ? req.requestedBy : null,
    reason: reason || null, ticket, approval_id: Number.isSafeInteger(req.approvalId) ? req.approvalId : null,
    guard_action_uuid: guardKey ? req.guardActionUuid : null, idempotency_key: key, push: req.push !== false,
    not_before: notBefore, expires_at: expiresAt, submit_state: held ? 'held' : 'pending', created_at: now, updated_at: now,
  });
  if (req.idempotencyKey) {
    // The keyed command first: a concurrent request with the same key waits here, then reads the batch it lost to.
    const ins = await trx('mdm_commands').insert(row(first, req.idempotencyKey))
      .onConflict(trx.raw('(tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL')).ignore().returning('id') as Array<{ id: string }>;
    if (ins.length === 0) {
      const earlier = await replayOf(trx, tenantId, req.idempotencyKey);
      if (earlier) return earlier;
      throw new AppError(409, 'This request is already being written', 'idempotencyConflict');
    }
  } else {
    await trx('mdm_commands').insert(row(first, null));
  }
  const rest = planned.slice(1);
  for (let i = 0; i < rest.length; i += 200) await trx('mdm_commands').insert(rest.slice(i, i + 200).map((p) => row(p, null)));
  for (const p of planned) {
    await trx.raw(`
      INSERT INTO obligarth.mdm_command_targets (command_id, tenant_id, device_id, enrollment_id, state, state_event_at, hold_reason)
      SELECT ?::uuid, ?, u.device_id, u.enrollment_id, 'pending', ?, ?
        FROM unnest(?::int[], ?::text[]) AS u(device_id, enrollment_id)`,
    [p.id, tenantId, now, held ? 'frozen' : null, p.devices.map((d) => d.id), p.devices.map((d) => d.enrollment_id)]);
  }
  if (!held) {
    for (const p of planned) {
      await submitJob.sendInTx(trx, { tenantId, commandId: p.id },
        { id: jobIdFor('mdm.commands.submit', p.id), tenantId, ...(notBefore ? { startAfter: notBefore } : {}) });
    }
  }
  const deviceIds = planned.flatMap((p) => p.devices.map((d) => d.id));
  await journalInTx(trx, {
    tenantId, action: 'mdm.command_requested',
    ...(deviceIds.length === 1 ? { target: { type: 'device', id: String(deviceIds[0]), device: deviceIds[0] } } : { targets: { deviceIds } }),
    ...(reason ? { reason } : {}), ...(ticket ? { ticket } : {}),
    ...(Number.isSafeInteger(req.approvalId) ? { approvalIds: [req.approvalId as number] } : {}),
    ...(guardKey ? { links: { action: req.guardActionUuid as string, ...(planned.length === 1 ? { command: planned[0].id } : {}) } }
      : planned.length === 1 ? { links: { command: planned[0].id } } : {}),
    details: { requestType: spec.requestType, origin: req.origin, batchId, commands: planned.length, targets: deviceIds.length,
      refused: refused.length, held, ...(notBefore ? { notBefore: notBefore.toISOString() } : {}) },
  }, req);
  afterCommit(trx, () => realtime.commandChanged(tenantId, planned.map((p) => p.id), deviceIds.slice(0, 500)));
  return outcome;
}

async function cancel(trx: Knex.Transaction, tenantId: number, commandId: string, deviceIds: number[] | null, actor: string,
  opts: CancelOptions = {}): Promise<CancelOutcome> {
  const none: CancelOutcome = { cancelled: 0, requested: 0, notCancellable: 0 };
  if (!UUID_RE.test(commandId)) throw new AppError(404, 'Command not found');
  const cmd = await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId }).forUpdate()
    .first('id', 'request_type', 'submit_state', 'submit_attempts', 'guard_action_uuid') as
    { id: string; request_type: string; submit_state: string; submit_attempts: number; guard_action_uuid: string | null } | undefined;
  if (!cmd) throw new AppError(404, 'Command not found');
  if (cmd.guard_action_uuid && !opts.allowGuarded) {
    throw new AppError(409, 'This command is cancelled through its guarded action', 'guardedActionRequired', { actionUuid: cmd.guard_action_uuid });
  }
  const wanted = deviceIds === null ? null : [...new Set(deviceIds.map(Number).filter((n) => Number.isSafeInteger(n) && n > 0))];
  if (wanted !== null && wanted.length === 0) return none;
  let tq = trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId }).forUpdate();
  if (wanted !== null) tq = tq.whereRaw('device_id = ANY (?::int[])', [wanted]);
  const targets = await tq.select('device_id', 'state') as Array<{ device_id: number; state: TargetState }>;
  const now = new Date();
  const pending = targets.filter((t) => t.state === 'pending').map((t) => Number(t.device_id));
  const atEdge = targets.filter((t) => t.state === 'queued' || t.state === 'sent' || t.state === 'notnow').map((t) => Number(t.device_id));
  const out: CancelOutcome = { cancelled: 0, requested: 0, notCancellable: targets.length - pending.length - atEdge.length };

  // A submission that started (an attempt counted) may have reached apple-edge although the command is not marked
  // submitted yet: its pending targets are cancelled here, and apple-edge is asked too.
  const maybeAtEdge = cmd.submit_state === 'submitted' || Number(cmd.submit_attempts) > 0;
  if (pending.length > 0) {
    const done = await finalizeTargets(trx, { tenantId, commandId, deviceIds: pending, from: ['pending'], to: 'cancelled',
      rejectCode: opts.rejectCode ?? 'cancelled_by_user', at: now });
    out.cancelled = done.length;
    const left = await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId, state: 'pending' }).count('* as n').first() as { n: string | number };
    if (Number(left.n) === 0 && (cmd.submit_state === 'pending' || cmd.submit_state === 'held')) {
      await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId }).update({ submit_state: 'cancelled', updated_at: now });
    }
  }
  const ask = [...atEdge, ...(maybeAtEdge ? pending : [])];
  if (ask.length > 0) {
    if (!cancelJob) throw new Error('mdm.commands.cancel is not registered (registerAppleModule)');
    await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId }).whereRaw('device_id = ANY (?::int[])', [ask])
      .update({ cancel_requested_at: now });
    await cancelJob.sendInTx(trx, { tenantId, commandId: String(cmd.id).toLowerCase(), requestedAt: now.toISOString() },
      { id: jobIdFor('mdm.commands.cancel', `${String(cmd.id).toLowerCase()}:${now.toISOString()}`), tenantId });
    out.requested = atEdge.length;
  }
  if (!opts.silent && (out.cancelled > 0 || out.requested > 0)) {
    const ids = [...pending, ...atEdge];
    // P4: the cancellation stands whatever the journal says.
    await journalInTx(trx, {
      tenantId, action: 'mdm.command_cancelled', links: { command: String(cmd.id).toLowerCase() },
      ...(ids.length === 1 ? { target: { type: 'device', id: String(ids[0]), device: ids[0] } } : { targets: { deviceIds: ids } }),
      details: { requestType: cmd.request_type, cancelled: out.cancelled, requested: out.requested, notCancellable: out.notCancellable },
    }, { actor, tenantId, auditCtx: opts.auditCtx });
  }
  if (out.cancelled > 0 || out.requested > 0) afterCommit(trx, () => realtime.commandChanged(tenantId, [String(cmd.id)], [...pending, ...atEdge].slice(0, 500)));
  return out;
}

export const mdmCommands: MdmCommandBus = {
  enqueue,
  cancel,
  relaunch(tenantId, commandId, deviceIds, actor, opts) {
    if (!relaunchImpl) throw new Error('the command jobs are not registered (registerAppleModule)');
    return relaunchImpl(tenantId, commandId, deviceIds, actor, opts);
  },
};
