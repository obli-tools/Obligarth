// The bus of the Android commands (sections 11.1 to 11.3, AN50), in files of its own until the junction AN-P (the bus
// of apple/commands/bus.ts becomes per platform there and these rows move to mdm_commands):
//   enqueue  in the caller's transaction (tenant context): the prerequisites of the catalogue per device, one row of
//            android_commands per device ('pending', batch_id), the newPassword of RESET_PASSWORD sealed at once in
//            secret_enc (never in params, amapi_command, a job payload, the audit nor a log), one job
//            android.commands.submit per command (sendInTx: it exists only if the transaction commits), the audit
//            entry mdm.command_requested. NEVER a call to Google (G-A1): the submission is the job's. A second command
//            of the same type to a device that has one pending or sent is refused (commandAlreadyPending, AN-RC4).
//            The guarded types (LOCK, RESET_PASSWORD, START_LOST_MODE, WIPE, RELINQUISH_OWNERSHIP) come from the guard
//            engine only (origin 'guard', 409 guardedActionRequired otherwise), and never for an action whose late
//            cancellation was asked (pending_actions read FOR SHARE, the mark of the engine). A destructive command
//            written while the tenant is frozen is held ('held', frozen): the gateway would refuse it anyway (AN15).
//   cancel   a command not yet submitted is cancelled at once (its secret wiped); a command sent goes through
//            cancelOperation (outside any transaction); 'already_done' at Google: the final state wins. The commands
//            of a guarded action are cancelled by the engine only (cancelAfterDispatch).
import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import { audit } from '../../audit';
import type { AuditEntryInput, AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { readSettings } from '../../guard/settings';
import { lateCancelOf } from '../../guard/types';
import { vault } from '../../vault';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { commandAdmitted } from '../gateway/commandStates';
import { AndroidError } from '../gateway/errors';
import type { AndroidGateway } from '../gateway/types';
import {
  ANDROID_COMMANDS, AndroidCommandParamError, checkNewPassword, commandBody, FINAL_STATES, finalStateOf, isAndroidCommandType, refusalOf,
  validateParams, type AndroidCommandType, type AndroidTargetState,
} from './catalog';
import { byodCommandRefusal } from '../byod/policy';

export const COMMAND_SECRET_COLUMN = { table: 'android_commands', column: 'secret_enc' } as const;
/** The guarded command types each guarded action key dispatches (table of §11.4). */
const GUARDED_TYPES_OF_KEY: Readonly<Record<string, readonly AndroidCommandType[]>> = Object.freeze({
  'mdm.erase_device': ['WIPE'], 'mdm.remove_management': ['WIPE', 'RELINQUISH_OWNERSHIP'], 'mdm.device_lock': ['LOCK'],
  'mdm.lost_mode_enable': ['START_LOST_MODE'], 'mdm.reset_password': ['RESET_PASSWORD'], 'mdm.relinquish_ownership': ['RELINQUISH_OWNERSHIP'],
});
export const COMMANDS_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.commands' }) as DbActor;

export class AndroidCommandError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message = code) {
    super(message);
    this.name = 'AndroidCommandError';
    this.status = status;
    this.code = code;
  }
}

// ── Senders and hooks ─────────────────────────────────────────────────────────

export interface CommandPayload { tenantId: number; commandId: string }
type Sender = (trx: Knex.Transaction, p: CommandPayload) => Promise<unknown>;
/** android.commands.submit (stately, one per command); bound by jobs.ts, replaced by recorders in the tests. */
export const commandSenders = { submit: (async () => undefined) as Sender };
export function setCommandSenders(s: Partial<typeof commandSenders>): void { Object.assign(commandSenders, s); }

export interface FinalTargetEvent {
  trx: Knex.Transaction;
  tenantId: number;
  deviceId: number;
  commandId: string;
  requestType: AndroidCommandType;
  state: Exclude<AndroidTargetState, 'pending' | 'sent'>;
  guardActionUuid: string | null;
}
/** onTargetFinal of section 11.3 (hooks of the model and of the actions), in the transaction that finalises. */
const finalHooks: Array<(e: FinalTargetEvent) => Promise<void>> = [];
export function registerAndroidCommandFinalHook(fn: (e: FinalTargetEvent) => Promise<void>): void { finalHooks.push(fn); }

/** Runs fn once the transaction of `trx` committed (never when it is rolled back); fn never throws out. */
export function afterCommit(trx: Knex.Transaction, fn: () => void | Promise<void>): void {
  const done = (trx as unknown as { executionPromise?: Promise<unknown> }).executionPromise;
  if (!done || typeof done.then !== 'function') return;
  done.then(() => { try { void Promise.resolve(fn()).catch(() => undefined); } catch { /* best effort */ } }, () => undefined);
}

const userOfActor = (actor: string): number | null => {
  const m = /^u:([1-9][0-9]{0,9})$/.exec(actor);
  return m ? Number(m[1]) : null;
};

async function journal(trx: Knex.Transaction, entry: AuditEntryInput, who: { actor: string; tenantId: number; auditCtx?: AuditWriteContext }): Promise<void> {
  const collect = audit.collectorOf(trx);
  if (collect) { collect(entry); return; }
  const userId = userOfActor(who.actor);
  const ctx = who.auditCtx ?? await audit.fromDbActor(userId ? { type: 'user', userId } : COMMANDS_ACTOR, who.tenantId);
  await audit.appendInTx(trx, entry, ctx, { onFailure: 'spool' });
}

// ── Reads ─────────────────────────────────────────────────────────────────────

export interface CommandRow {
  id: string;
  tenant_id: number;
  device_id: number;
  enterprise_id: number;
  enrollment_id: string;
  batch_id: string;
  request_type: AndroidCommandType;
  params: Record<string, unknown>;
  amapi_command: Record<string, unknown>;
  secret_enc: string | null;
  origin: 'console' | 'guard' | 'system';
  actor: string;
  guard_action_uuid: string | null;
  guard_action_key: string | null;
  expires_at: Date;
  submit_state: string;
  hold_reason: string | null;
  submit_attempts: number;
  amapi_submit_started_at: Date | null;
  amapi_operation: string | null;
  amapi_error_code: string | null;
  state: AndroidTargetState;
  reject_code: string | null;
  delivered_at: Date | null;
  completed_at: Date | null;
  cancel_requested_at: Date | null;
  next_poll_at: Date | null;
  poll_count: number;
  created_at: Date;
}

export const COMMAND_COLUMNS = ['id', 'tenant_id', 'device_id', 'enterprise_id', 'enrollment_id', 'batch_id', 'request_type', 'params', 'amapi_command',
  'secret_enc', 'origin', 'actor', 'guard_action_uuid', 'guard_action_key', 'expires_at', 'submit_state', 'hold_reason', 'submit_attempts',
  'amapi_submit_started_at', 'amapi_operation', 'amapi_error_code', 'state', 'reject_code', 'delivered_at', 'completed_at', 'cancel_requested_at',
  'next_poll_at', 'poll_count', 'created_at'];

interface TargetRow {
  id: number;
  management_channel: string;
  enrollment_state: string;
  ownership: string;
  management_mode: string;
  api_level: number | null;
  released_at: Date | null;
  amapi_name: string | null;
  enterprise_id: number | null;
}

async function targetRows(trx: Knex.Transaction, tenantId: number, deviceIds: number[]): Promise<Map<number, TargetRow>> {
  if (!deviceIds.length) return new Map();
  const rows = await trx('devices as d')
    .leftJoin('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereIn('d.id', deviceIds)
    .select('d.id', 'd.management_channel', 'd.enrollment_state', 'd.ownership', 'd.management_mode', 'a.api_level', 'a.released_at',
      'a.amapi_name', 'a.enterprise_id') as TargetRow[];
  return new Map(rows.map((r) => [Number(r.id), r]));
}

/** Lost mode refused before any call for 12 hours after a successful user exit (USAGE_LOGS StopLostModeUserAttemptEvent)
 *  or a password reset by the IT acknowledged by the device (§11.2; Google answers USER_EXIT_LOST_MODE_RECENTLY or
 *  RESET_PASSWORD_RECENTLY otherwise). Lot AN-F2. */
export const LOST_MODE_BLOCK_MS = 12 * 3_600_000;

async function lostModeBlocked(trx: Knex.Transaction, tenantId: number, deviceIds: number[]): Promise<Set<number>> {
  if (!deviceIds.length) return new Set();
  const since = new Date(Date.now() - LOST_MODE_BLOCK_MS);
  const exits = await trx('android_lost_mode_exits').where({ tenant_id: tenantId }).whereIn('device_id', deviceIds)
    .where('exited_at', '>', since).pluck('device_id') as number[];
  const resets = await trx('android_commands').where({ tenant_id: tenantId, request_type: 'RESET_PASSWORD', state: 'acknowledged' })
    .whereIn('device_id', deviceIds).where('completed_at', '>', since).pluck('device_id') as number[];
  return new Set([...exits, ...resets].map(Number));
}

// ── Enqueue ───────────────────────────────────────────────────────────────────

export interface EnqueueAndroidCommands {
  tenantId: number;
  type: AndroidCommandType;
  deviceIds: number[];
  params?: unknown;
  /** RESET_PASSWORD only: sealed at once in secret_enc of each command (the caller zeroes its own copy). */
  newPassword?: string;
  origin: 'console' | 'guard' | 'system';
  /** 'u:<id>' | 'j:<queue>'. */
  actor: string;
  requestedBy?: number | null;
  reason?: string;
  guardActionUuid?: string;
  guardActionKey?: string;
  /** Deterministic command id per device (guarded actions: the same ids when an execution runs again). */
  commandIdFor?: (deviceId: number) => string;
  idempotencyKey?: string;
  /** WIPE of a personal device as the removal from management (the profile only). */
  profileWipe?: boolean;
  auditCtx?: AuditWriteContext;
}

export interface EnqueueOutcome {
  batchId: string;
  /** The commands of the batch (new and replayed). */
  commandIds: string[];
  /** device id → command id, for the devices that hold a command of the batch. */
  byDevice: Map<number, string>;
  refused: Array<{ deviceId: number; code: string }>;
  held: number;
  replayed: number;
}

/**
 * Writes the commands of a request in the caller's transaction (tenant context). Throws AndroidCommandError for a
 * request refused as a whole (type, parameters, guard, enterprise); per device refusals are listed in `refused`.
 */
export async function enqueueAndroidCommands(trx: Knex.Transaction, req: EnqueueAndroidCommands): Promise<EnqueueOutcome> {
  const { tenantId } = req;
  if (!isAndroidCommandType(req.type)) throw new AndroidCommandError(422, 'androidUnknownCommand', 'unknown Android command type');
  const spec = ANDROID_COMMANDS[req.type];
  if (spec.guarded && (req.origin !== 'guard' || !req.guardActionUuid)) {
    throw new AndroidCommandError(409, 'guardedActionRequired', `${req.type} is requested through a guarded action only`);
  }
  if (req.origin === 'guard' && !req.guardActionUuid) throw new AndroidCommandError(409, 'guardedActionRequired');
  let params: Record<string, unknown>;
  let newPassword: string | null = null;
  try {
    params = validateParams(req.type, req.params);
    if (req.newPassword !== undefined) {
      if (req.type !== 'RESET_PASSWORD') throw new AndroidCommandParamError('secret_not_allowed');
      newPassword = checkNewPassword(req.newPassword);
      // The submission refuses a command marked so whose sealed part is gone (a lost secret never becomes a
      // RESET_PASSWORD without newPassword, which would clear the password).
      params = { ...params, passwordSealed: true };
    }
  } catch (err) {
    if (err instanceof AndroidCommandParamError) throw new AndroidCommandError(422, 'invalidCommandParams', err.code);
    throw err;
  }
  const deviceIds = [...new Set(req.deviceIds.map(Number))].filter((n) => Number.isSafeInteger(n) && n > 0);
  if (!deviceIds.length || deviceIds.length > 5000) throw new AndroidCommandError(422, 'invalidInput', 'one to 5000 devices');

  // A guarded action whose late cancellation was asked dispatches nothing more (the engine writes the mark under the
  // lock of the row; this read waits for it).
  if (req.guardActionUuid) {
    const action = await trx('pending_actions').where({ tenant_id: tenantId, uuid: req.guardActionUuid }).forShare().first('state', 'result', 'action_key') as
      { state: string; result: unknown; action_key: string } | undefined;
    if (!action) throw new AndroidCommandError(409, 'guardActionUnknown', 'unknown guarded action');
    if (lateCancelOf(action.result)) throw new AndroidCommandError(409, 'guardActionCancelled', 'the late cancellation of the action was asked');
    // Review AN-D1: only an action the engine is executing dispatches, and only the types of its key (§11.4): an
    // action awaiting approval, refused or of a lighter key (mdm.device_lock) never carries a WIPE.
    if (action.state !== 'executing') throw new AndroidCommandError(409, 'guardActionNotExecuting', 'the guarded action is not executing');
    if (spec.guarded && !(GUARDED_TYPES_OF_KEY[action.action_key] ?? []).includes(req.type)) {
      throw new AndroidCommandError(409, 'guardActionMismatch', `${req.type} is not dispatched by ${String(action.action_key).slice(0, 60)}`);
    }
  }
  const e = await readEnterprise(trx);
  // Review AN-H1 (H1R-1): while the enterprise is unlinking, only WIPE and RELINQUISH_OWNERSHIP (the guarded actions the
  // offboarding proposes) are admitted.
  if (!e || !commandAdmitted(req.type, e.state)) throw new AndroidCommandError(409, 'androidNotLinked', 'no linked Android enterprise');
  // Lot AN-E1 (§11.2, « managed apps only »): CLEAR_APP_DATA clears only apps of the tenant's catalog, never an app the
  // user installed in the personal profile nor a package the catalog does not know.
  if (req.type === 'CLEAR_APP_DATA') {
    const names = params.packageNames as string[];
    const known = await trx('apps').where({ tenant_id: tenantId, platform_family: 'android' }).whereNull('archived_at')
      .whereIn('identifier', names).pluck('identifier') as string[];
    if (known.length !== names.length) throw new AndroidCommandError(422, 'invalidCommandParams', 'app_not_managed');
  }
  const frozen = spec.destructive && !!(await readSettings(tenantId, trx)).frozen_at;

  const targets = await targetRows(trx, tenantId, deviceIds);
  const lostModeBlock = req.type === 'START_LOST_MODE' ? await lostModeBlocked(trx, tenantId, deviceIds) : new Set<number>();
  const batchId = randomUUID();
  const out: EnqueueOutcome = { batchId, commandIds: [], byDevice: new Map(), refused: [], held: 0, replayed: 0 };
  const now = Date.now();
  const expiresAt = new Date(now + spec.durationSeconds * 1000);
  const body = commandBody(req.type, params);
  const inserted: string[] = [];
  for (const deviceId of deviceIds) {
    const t = targets.get(deviceId);
    const code = refusalOf(req.type, t ? {
      managementChannel: t.management_channel, enrollmentState: t.enrollment_state, released: t.released_at !== null || !t.amapi_name,
      ownership: t.ownership, mode: t.management_mode, apiLevel: t.api_level === null ? null : Number(t.api_level),
    } : undefined, { profileWipe: req.profileWipe === true });
    if (code) { out.refused.push({ deviceId, code }); continue; }
    // Lot AN-F1 (EX-A7): a personal device never takes a WIPE with a wipe data flag (they act on the whole device).
    if (t!.ownership === 'personal' && byodCommandRefusal(body)) { out.refused.push({ deviceId, code: 'ownership' }); continue; }
    if (Number(t!.enterprise_id) !== e.id) { out.refused.push({ deviceId, code: 'not_amapi' }); continue; }
    if (lostModeBlock.has(deviceId)) { out.refused.push({ deviceId, code: 'lost_mode_recent' }); continue; }
    const id = (req.commandIdFor?.(deviceId) ?? randomUUID()).toLowerCase();
    let secretEnc: string | null = null;
    if (newPassword !== null) {
      secretEnc = await vault.seal({ ...COMMAND_SECRET_COLUMN, pk: id, tenantId }, newPassword, { trx, requestTenantId: tenantId });
    }
    const rows = await trx('android_commands').insert({
      id, tenant_id: tenantId, device_id: deviceId, enterprise_id: e.id, enrollment_id: t!.amapi_name, batch_id: batchId, request_type: req.type,
      params: JSON.stringify(params), amapi_command: JSON.stringify(body), secret_enc: secretEnc, origin: req.origin, actor: req.actor.slice(0, 70),
      requested_by: req.requestedBy ?? userOfActor(req.actor), reason: req.reason?.slice(0, 500) ?? null,
      guard_action_uuid: req.guardActionUuid ?? null, guard_action_key: req.guardActionKey ?? null, idempotency_key: req.idempotencyKey?.slice(0, 200) ?? null,
      expires_at: expiresAt, submit_state: frozen ? 'held' : 'pending', hold_reason: frozen ? 'frozen' : null,
    }).onConflict().ignore().returning('id') as Array<{ id: string }>;
    if (rows.length) {
      inserted.push(id);
      out.commandIds.push(id);
      out.byDevice.set(deviceId, id);
      if (frozen) out.held += 1;
      continue;
    }
    // Not written: the same command already exists (an execution or a request run again), or another open command of
    // the type holds the device (AN-RC4).
    const same = await trx('android_commands').where({ tenant_id: tenantId, id }).first('id', 'device_id', 'request_type') as
      { id: string; device_id: number; request_type: string } | undefined;
    const sameKey = !same && req.idempotencyKey
      ? await trx('android_commands').where({ tenant_id: tenantId, idempotency_key: req.idempotencyKey.slice(0, 200), device_id: deviceId }).first('id', 'request_type') as
        { id: string; request_type: string } | undefined
      : undefined;
    const replay = same && Number(same.device_id) === deviceId && same.request_type === req.type ? same.id
      : sameKey && sameKey.request_type === req.type ? sameKey.id : null;
    if (replay) {
      out.replayed += 1;
      out.commandIds.push(String(replay));
      out.byDevice.set(deviceId, String(replay));
    } else {
      out.refused.push({ deviceId, code: same || sameKey ? 'idempotency_conflict' : 'commandAlreadyPending' });
    }
  }
  for (const id of inserted) {
    if (!frozen) await commandSenders.submit(trx, { tenantId, commandId: id });
  }
  if (inserted.length) {
    const ids = [...out.byDevice.entries()].filter(([, c]) => inserted.includes(c)).map(([d]) => d);
    await journal(trx, {
      tenantId, action: 'mdm.command_requested',
      ...(ids.length === 1 ? { target: { type: 'device', id: String(ids[0]), device: ids[0] } } : { targets: { deviceIds: ids.slice(0, 1000) } }),
      ...(req.reason ? { reason: req.reason.slice(0, 500) } : {}),
      ...(req.guardActionUuid ? { links: { action: req.guardActionUuid, ...(inserted.length === 1 ? { command: inserted[0] } : {}) } }
        : inserted.length === 1 ? { links: { command: inserted[0] } } : {}),
      // never the parameters' values beyond the type and the flags: no password, no lost-mode text
      details: { channel: 'amapi', requestType: req.type, origin: req.origin, batchId, commands: inserted.length, refused: out.refused.length,
        held: out.held, ...(newPassword !== null ? { newPassword: 'sealed' } : {}) },
    }, req);
  }
  return out;
}

// ── Final states ──────────────────────────────────────────────────────────────

/**
 * Writes the final state of a command in `trx` (only from 'sent', or 'pending' for cancelled/expired/rejected),
 * wipes its secret, runs the final hooks and the audit. Returns false when the command was already final.
 */
export async function finalizeCommand(trx: Knex.Transaction, row: Pick<CommandRow, 'id' | 'tenant_id' | 'device_id' | 'request_type' | 'actor' | 'guard_action_uuid' | 'state'>,
  final: { state: Exclude<AndroidTargetState, 'pending' | 'sent'>; errorCode?: string | null; rejectCode?: string | null }): Promise<boolean> {
  const from: AndroidTargetState[] = final.state === 'acknowledged' || final.state === 'error' ? ['sent'] : ['pending', 'sent'];
  const n = await trx('android_commands').where({ tenant_id: row.tenant_id, id: row.id }).whereIn('state', from).update({
    state: final.state, amapi_error_code: final.errorCode ?? null, reject_code: final.rejectCode ?? null, secret_enc: null,
    completed_at: trx.fn.now(), state_event_at: trx.fn.now(), next_poll_at: null, updated_at: trx.fn.now(),
    ...(final.state === 'cancelled' ? { submit_state: trx.raw("CASE WHEN submit_state = 'submitted' THEN submit_state ELSE 'cancelled' END") } : {}),
    ...(final.state === 'rejected' ? { submit_state: 'failed', hold_reason: null } : {}),
    ...(final.state === 'expired' ? { hold_reason: null, submit_state: trx.raw("CASE WHEN submit_state = 'submitted' THEN submit_state ELSE 'failed' END") } : {}),
  });
  if (n !== 1) return false;
  for (const h of finalHooks) {
    await h({ trx, tenantId: row.tenant_id, deviceId: Number(row.device_id), commandId: row.id, requestType: row.request_type, state: final.state,
      guardActionUuid: row.guard_action_uuid });
  }
  const action = final.state === 'acknowledged' ? 'mdm.command_acknowledged' : final.state === 'cancelled' ? 'mdm.command_cancelled'
    : final.state === 'error' || final.state === 'rejected' ? 'mdm.command_failed' : null;
  if (action) {
    await journal(trx, {
      tenantId: row.tenant_id, action, target: { type: 'device', id: String(row.device_id), device: Number(row.device_id) },
      links: { command: row.id, ...(row.guard_action_uuid ? { action: row.guard_action_uuid } : {}) },
      details: { channel: 'amapi', requestType: row.request_type, state: final.state,
        ...(final.errorCode ? { errorCode: final.errorCode } : {}), ...(final.rejectCode ? { rejectCode: final.rejectCode } : {}) },
    }, { actor: final.state === 'cancelled' ? row.actor : 'j:android.commands', tenantId: row.tenant_id });
  }
  return true;
}

// ── Cancel ────────────────────────────────────────────────────────────────────

export type CancelResult = 'cancelled' | 'cancel_requested' | 'already_final' | 'completed';

/**
 * POST /api/mdm/commands/:id/cancel for an Android command (route widened at the junction): pending and never
 * submitted → cancelled at once; submission in flight (AN50 mark without an operation) → marked, the submission
 * cancels instead of issuing or cancels what it adopted; sent → cancelOperation, 'already_done' → the final state
 * of the operation wins. Guarded commands: the engine only (allowGuarded).
 */
export async function cancelAndroidCommand(tenantId: number, commandId: string, by: { actor: string; auditCtx?: AuditWriteContext },
  o: { allowGuarded?: boolean; gateway?: AndroidGateway } = {}): Promise<CancelResult> {
  if (!/^[0-9a-f-]{36}$/i.test(commandId)) throw new AndroidCommandError(404, 'notFound', 'command not found');
  const id = commandId.toLowerCase();
  const gw = o.gateway ?? androidGateway();
  const actorUser = userOfActor(by.actor);
  return asTenant(tenantId, actorUser ? { type: 'user', userId: actorUser } : COMMANDS_ACTOR, async () => {
    const step = await db.transaction(async (trx) => {
      const row = await trx('android_commands').where({ tenant_id: tenantId, id }).forUpdate().first(COMMAND_COLUMNS) as CommandRow | undefined;
      if (!row) throw new AndroidCommandError(404, 'notFound', 'command not found');
      if (row.guard_action_uuid && !o.allowGuarded) {
        throw new AndroidCommandError(409, 'guardedActionRequired', 'the commands of a guarded action are cancelled through the action');
      }
      if (FINAL_STATES.has(row.state)) return { kind: 'final' as const, row };
      if (row.state === 'pending' && !row.amapi_submit_started_at) {
        await finalizeCommand(trx, { ...row, actor: by.actor }, { state: 'cancelled' });
        return { kind: 'done' as const, row };
      }
      await trx('android_commands').where({ tenant_id: tenantId, id }).whereNull('cancel_requested_at')
        .update({ cancel_requested_at: trx.fn.now(), updated_at: trx.fn.now() });
      if (row.state === 'pending') {
        // in flight: the submission job decides (it sees the mark)
        if (row.submit_state === 'held') await trx('android_commands').where({ tenant_id: tenantId, id }).update({ submit_state: 'pending', hold_reason: null });
        await commandSenders.submit(trx, { tenantId, commandId: id });
        return { kind: 'requested' as const, row };
      }
      return { kind: 'sent' as const, row };
    });
    if (step.kind === 'final') return 'already_final';
    if (step.kind === 'done') return 'cancelled';
    if (step.kind === 'requested') return 'cancel_requested';
    return cancelSent(tenantId, step.row, by.actor, gw);
  });
}

/** cancelOperation of a command 'sent' (outside any transaction), then its final state. */
export async function cancelSent(tenantId: number, row: CommandRow, actor: string, gw: AndroidGateway): Promise<CancelResult> {
  const e = await readEnterprise();
  if (!e || !row.amapi_operation) throw new AndroidCommandError(409, 'androidNotLinked', 'no linked Android enterprise');
  await gw.cancelOperation(e, row.amapi_operation);
  // Accepted or already done, the operation tells the outcome: Google cancels asynchronously and on a best-effort
  // basis (google.longrunning: an operation cancelled ends done with error code 1; it may complete despite the
  // cancellation). Not finished yet: the command stays 'sent' with its cancellation asked, the polling or the COMMAND
  // notification gives its final state (review AN-D1: never 'cancelled' before Google says so).
  let op = null;
  try { op = await gw.getOperation(e, row.amapi_operation); } catch (err) { if (!(err instanceof AndroidError)) throw err; }
  const final = finalStateOf(op, { cancelRequested: true });
  if (!final) return 'cancel_requested';
  const changed = await db.transaction((trx) => finalizeCommand(trx, { ...row, actor }, { state: final.state, errorCode: final.errorCode }));
  return changed ? (final.state === 'cancelled' ? 'cancelled' : 'completed') : 'already_final';
}
