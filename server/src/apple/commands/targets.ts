import type { Knex } from 'knex';

// =============================================================================
// States of the targets of the MDM commands (docs: integration-apple-edge §8.2,
// I2; file-durable §7.5): one row of mdm_command_targets per (command,
// device), nine states ordered by a monotone rank (obligarth.
// mdm_target_state_rank):
//   pending 0 < queued 1 < sent, notnow 2 < expired, cancelled, rejected 3
//   < acknowledged, error 4
// A state never goes back: a change applies when its rank is higher, or for
// sent and notnow (same rank) when the event is newer than the state; within
// a final rank the first state written stays (a second Acknowledged, or an
// Error after an Acknowledged: a duplicate). An acknowledgement consumed after
// the expiry wins (the device did execute: apple-edge RC1). state_event_at
// takes the time of the event applied, never the time of the consumption.
// applyTargetState is the one writer of a target's state; a change to a final
// state runs the onTargetFinal hooks in the same transaction (the event's
// savepoint): setup plans, DDM, Apps and Books, guarded actions register
// theirs (lots B4, B5, C4). In the caller's transaction and tenant context.
// =============================================================================

export const TARGET_STATES = ['pending', 'queued', 'sent', 'notnow', 'expired', 'cancelled', 'rejected', 'acknowledged', 'error'] as const;
export type TargetState = typeof TARGET_STATES[number];
export type FinalTargetState = 'acknowledged' | 'error' | 'expired' | 'cancelled' | 'rejected';

const RANK: Record<TargetState, number> = {
  pending: 0, queued: 1, sent: 2, notnow: 2, expired: 3, cancelled: 3, rejected: 3, acknowledged: 4, error: 4,
};

/** The rank of a state (obligarth.mdm_target_state_rank). */
export function targetRank(state: string): number {
  return RANK[state as TargetState] ?? -1;
}

export function isFinalTargetState(state: string): state is FinalTargetState {
  return targetRank(state) >= 3;
}

/** Does `to` (at `at`) replace `from` (set at `fromAt`)? The rule of §8.2. */
export function targetTransitionApplies(from: string, fromAt: Date | null, to: TargetState, at: Date): boolean {
  const a = targetRank(from);
  const b = targetRank(to);
  if (b > a) return true;
  if (b === 2 && a === 2) return !fromAt || fromAt.getTime() < at.getTime();
  return false;
}

export interface TargetFinalContext {
  trx: Knex.Transaction;
  tenantId: number;
  deviceId: number;
  commandId: string;
  requestType: string;
  state: FinalTargetState;
}

type FinalHook = (ctx: TargetFinalContext) => Promise<void>;
const finalHooks: Array<{ name: string; fn: FinalHook }> = [];

/** A hook run in the transaction when a target reaches a final state (setup plans, DDM, VPP, guarded actions).
 *  Registered before jobs.start(); a name once. */
export function onTargetFinal(name: string, fn: FinalHook): void {
  if (finalHooks.some((h) => h.name === name)) throw new Error(`onTargetFinal ${name}: registered twice`);
  finalHooks.push({ name, fn });
}

export interface TargetChange {
  tenantId: number;
  /** mdm_commands.id: the CommandUUID, any case (compared as uuid). */
  commandId: string;
  /** The enrollment id of the target (snapshot written at the creation; the events carry it). */
  enrollmentId: string;
  to: TargetState;
  /** occurred_at of the event. */
  at: Date;
  /** Columns written with the state (last_status, completed_at, error_chain, result_summary, reject_code…). */
  set?: Record<string, unknown>;
}

export interface TargetChangeResult {
  /** The target exists (command and enrollment of this tenant). */
  found: boolean;
  applied: boolean;
  /** The state before the change (the current one when not applied). */
  previous: TargetState | null;
  deviceId: number | null;
  requestType: string | null;
  /** The command was created by a user (console or bulk): its failures alert (command.failed). */
  byUser: boolean;
  /** pending_actions.uuid of a guarded action, if the command is one's. */
  guardActionUuid: string | null;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Applies a state to the target (command, enrollment) of the tenant when the rule of §8.2 allows it (the row
 * locked: two events of one target are serialised), then runs the onTargetFinal hooks of a final state.
 */
export async function applyTargetState(trx: Knex.Transaction, c: TargetChange): Promise<TargetChangeResult> {
  const none: TargetChangeResult = { found: false, applied: false, previous: null, deviceId: null, requestType: null, byUser: false, guardActionUuid: null };
  if (!UUID_RE.test(c.commandId) || !(TARGET_STATES as readonly string[]).includes(c.to)) return none;
  const row = await trx('mdm_command_targets as t')
    .join('mdm_commands as c', function joinCommand() { this.on('c.id', '=', 't.command_id').andOn('c.tenant_id', '=', 't.tenant_id'); })
    .where({ 't.tenant_id': c.tenantId, 't.command_id': c.commandId, 't.enrollment_id': c.enrollmentId })
    .forUpdate('t')
    .first('t.device_id', 't.state', 't.state_event_at', 'c.request_type', 'c.origin', 'c.requested_by', 'c.guard_action_uuid') as
    { device_id: number; state: TargetState; state_event_at: Date | null; request_type: string; origin: string; requested_by: number | null;
      guard_action_uuid: string | null } | undefined;
  if (!row) return none;
  const base: TargetChangeResult = {
    found: true, applied: false, previous: row.state, deviceId: Number(row.device_id), requestType: row.request_type,
    byUser: row.requested_by !== null && (row.origin === 'console' || row.origin === 'bulk'),
    guardActionUuid: row.guard_action_uuid ?? null,
  };
  if (!targetTransitionApplies(row.state, row.state_event_at ? new Date(row.state_event_at) : null, c.to, c.at)) return base;
  await trx('mdm_command_targets')
    .where({ tenant_id: c.tenantId, command_id: c.commandId, device_id: row.device_id })
    .update({ ...(c.set ?? {}), state: c.to, state_event_at: c.at });
  if (isFinalTargetState(c.to)) await runFinalHooks(trx, c.tenantId, Number(row.device_id), c.commandId, row.request_type, c.to);
  return { ...base, applied: true };
}

async function runFinalHooks(trx: Knex.Transaction, tenantId: number, deviceId: number, commandId: string, requestType: string,
  state: FinalTargetState): Promise<void> {
  // A hook that fails fails the event (retried, the consumer logs it): its work belongs to the same transaction.
  for (const h of finalHooks) await h.fn({ trx, tenantId, deviceId, commandId: commandId.toLowerCase(), requestType, state });
}

/** Runs fn once the transaction of `trx` is committed (never when it is rolled back); fn never throws out. Used
 *  for the deferred MDM_COMMAND_CHANGED of a change written inside the caller's transaction. */
export function afterCommit(trx: Knex.Transaction, fn: () => void): void {
  const done = (trx as unknown as { executionPromise?: Promise<unknown> }).executionPromise;
  if (!done || typeof done.then !== 'function') return;
  done.then(() => { try { fn(); } catch { /* best effort */ } }, () => { /* rolled back: nothing happened */ });
}

export interface FinalizeTargets {
  tenantId: number;
  commandId: string;
  /** The targets concerned; null: every target of the command. */
  deviceIds: number[] | null;
  /** The states a target must be in for the change to apply (a subset of the states of rank below 3). */
  from: readonly TargetState[];
  to: 'cancelled' | 'rejected' | 'expired';
  rejectCode: string;
  at: Date;
}

/**
 * Closes targets of one command without a result (§8.2: cancellation before or after the submission, refusal of
 * a target by apple-edge, expiry before the submission) in one statement, then runs the onTargetFinal hooks of
 * each target changed. The rank rule holds: only the listed states of rank below 3 change. Returns the devices
 * changed.
 */
export async function finalizeTargets(trx: Knex.Transaction, f: FinalizeTargets): Promise<number[]> {
  if (!UUID_RE.test(f.commandId)) return [];
  const from = f.from.filter((s) => targetRank(s) >= 0 && targetRank(s) < 3);
  if (from.length === 0 || (f.deviceIds !== null && f.deviceIds.length === 0)) return [];
  const res = await trx.raw(`
    UPDATE obligarth.mdm_command_targets t
       SET state = ?, state_event_at = ?, reject_code = ?, completed_at = CASE WHEN ? = 'expired' THEN ?::timestamptz ELSE t.completed_at END
      FROM obligarth.mdm_commands c
     WHERE t.tenant_id = ? AND t.command_id = ?::uuid AND c.tenant_id = t.tenant_id AND c.id = t.command_id
       AND t.state = ANY (?::text[]) AND (?::int[] IS NULL OR t.device_id = ANY (?::int[]))
    RETURNING t.device_id, c.request_type`,
  [f.to, f.at, f.rejectCode.slice(0, 48), f.to, f.at, f.tenantId, f.commandId, from, f.deviceIds, f.deviceIds]) as
    { rows: Array<{ device_id: number; request_type: string }> };
  for (const r of res.rows) await runFinalHooks(trx, f.tenantId, Number(r.device_id), f.commandId, r.request_type, f.to);
  return res.rows.map((r) => Number(r.device_id));
}

/**
 * The open targets of a device are cancelled (§7.3, §8.2): the device left management ('unenrolled'), or started
 * a new enrollment cycle, whose Authenticate emptied its queue at apple-edge (then `createdBefore`: the commands
 * requested before that Authenticate only). The hooks of each target run; the commands changed are returned (the
 * caller emits MDM_COMMAND_CHANGED after its commit).
 */
export async function cancelOpenTargetsOfDevice(trx: Knex.Transaction, tenantId: number, deviceId: number, rejectCode: string, at: Date,
  createdBefore: Date | null = null): Promise<string[]> {
  const res = await trx.raw(`
    UPDATE obligarth.mdm_command_targets t
       SET state = 'cancelled', state_event_at = ?, reject_code = ?
      FROM obligarth.mdm_commands c
     WHERE t.tenant_id = ? AND t.device_id = ? AND c.tenant_id = t.tenant_id AND c.id = t.command_id
       AND t.state IN ('pending', 'queued', 'sent', 'notnow')
       AND (?::timestamptz IS NULL OR c.created_at < ?::timestamptz)
    RETURNING t.command_id, c.request_type`, [at, rejectCode.slice(0, 48), tenantId, deviceId, createdBefore, createdBefore]) as
    { rows: Array<{ command_id: string; request_type: string }> };
  for (const r of res.rows) await runFinalHooks(trx, tenantId, deviceId, String(r.command_id), r.request_type, 'cancelled');
  return res.rows.map((r) => String(r.command_id).toLowerCase());
}

/**
 * mdm.command_expired (§8.2): the listed targets of a command (enrollment ids) of rank below 3 become 'expired'
 * in one statement (a shared command may list thousands), completed_at = the event's time; the hooks run for
 * each target changed. Returns the devices changed.
 */
export async function expireTargets(trx: Knex.Transaction, tenantId: number, commandId: string, enrollmentIds: string[],
  at: Date): Promise<number[]> {
  if (!UUID_RE.test(commandId) || enrollmentIds.length === 0) return [];
  const res = await trx.raw(`
    UPDATE obligarth.mdm_command_targets t
       SET state = 'expired', state_event_at = ?, completed_at = ?
      FROM obligarth.mdm_commands c
     WHERE t.tenant_id = ? AND t.command_id = ?::uuid AND t.enrollment_id = ANY (?::text[])
       AND c.tenant_id = t.tenant_id AND c.id = t.command_id
       AND obligarth.mdm_target_state_rank(t.state) < 3
    RETURNING t.device_id, c.request_type`, [at, at, tenantId, commandId, enrollmentIds]) as
    { rows: Array<{ device_id: number; request_type: string }> };
  for (const r of res.rows) await runFinalHooks(trx, tenantId, Number(r.device_id), commandId, r.request_type, 'expired');
  return res.rows.map((r) => Number(r.device_id));
}
