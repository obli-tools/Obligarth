import type { Knex } from 'knex';
import { logger } from '../../utils/logger';
import { isFinalTargetState, type TargetFinalContext } from '../commands/targets';
import type { ResultIngestContext } from '../commands/results';
import { syncTokensBody } from './canonical';
import { computeSet, type ComputedSet } from './engine';
import { ddmMetrics } from './metrics';

// =============================================================================
// Synchronisation of a device with its declaration set (docs: integration-
// apple-edge §9.4, I7): the device learns that its set changed from a
// DeclarativeManagement command whose Data carries the synchronisation tokens
// (the canonical bytes the relay answers to `tokens`).
//   - one open DeclarativeManagement command per device at most
//     (apple_declaration_sets.sync_command_id): a set that changes while a
//     command is open sends nothing, the device reads the current tokens when
//     it handles that command; when the command ends, a set that changed
//     since is announced by a new one;
//   - acknowledged: the DDM is active on the device (ddm_enabled, and
//     ddm_enabled_at the first time); in error: nothing is sent again before
//     the set changes; a command that never reached the device (expired,
//     cancelled, refused) leaves the token unannounced: the daily
//     recomputation sends it again.
// The command itself belongs to the command queue (§8.4): this module hands
// it the request through the sender the queue registers
// (registerDdmSyncSender), in the caller's transaction, and never calls
// apple-edge. Without a sender, sets are computed and served, nothing is
// announced.
// =============================================================================

export const DDM_REQUEST_TYPE = 'DeclarativeManagement';

export interface DdmSyncCommand {
  tenantId: number;
  deviceId: number;
  /** The enrollment id of the device's current cycle ('<key>_<id>'). */
  enrollmentId: string;
  /** Command.Data: the canonical JSON of { SyncTokens: { DeclarationsToken, Timestamp } }, UTF-8 bytes. */
  data: Buffer;
  /** 'j:apple.ddm.device-sync'… (the actor of the request, for the command's record). */
  actor: string;
}

export type DdmSyncSendOutcome = { commandId: string } | { refused: string };

/**
 * Enqueues one DeclarativeManagement command (origin 'ddm') for the device, in `trx` (the tenant's context): the
 * command and its target exist if and only if the transaction commits. Never a network call. `refused`: the
 * queue's refusal code (not_enrolled, already_open…).
 */
export type DdmSyncSender = (trx: Knex.Transaction, command: DdmSyncCommand) => Promise<DdmSyncSendOutcome>;

let sender: DdmSyncSender | null = null;

/** The command queue registers its sender (before jobs.start()); once. */
export function registerDdmSyncSender(fn: DdmSyncSender): void {
  if (sender) throw new Error('DDM sync sender: registered twice');
  sender = fn;
}

export function hasDdmSyncSender(): boolean {
  return sender !== null;
}

/** Tests: another sender (or none). */
export function setDdmSyncSenderForTests(fn: DdmSyncSender | null): void {
  sender = fn;
}

export type SyncOutcome = 'no_record' | 'not_managed' | 'in_sync' | 'open_command' | 'sent' | 'refused' | 'no_sender';

export interface SyncResult {
  outcome: SyncOutcome;
  set: ComputedSet | null;
  commandId?: string;
  refusal?: string;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REFUSAL_RE = /^[a-z][a-z0-9_]{0,47}$/;

/**
 * Computes the set of a device and announces it when its token is not the one the device was told (§9.4,
 * synchronisation step 1). In the caller's transaction (the tenant's context). The satellite row is locked by
 * computeSet for the whole decision: two synchronisations of a device never send two commands.
 */
export async function syncDevice(trx: Knex.Transaction, tenantId: number, deviceId: number, actor: string, now = new Date()): Promise<SyncResult> {
  const d = await trx('devices as d')
    .join('apple_devices as a', function joinSat() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where({ 'd.tenant_id': tenantId, 'd.id': deviceId })
    .first('d.enrollment_state', 'a.enrollment_id', 'a.nano_enroll_type') as
    { enrollment_state: string; enrollment_id: string; nano_enroll_type: string } | undefined;
  if (!d) return { outcome: 'no_record', set: null };
  if ((d.enrollment_state !== 'enrolled' && d.enrollment_state !== 'awaiting_configuration')
    || (d.nano_enroll_type !== 'Device' && d.nano_enroll_type !== 'User Enrollment (Device)')) {
    return { outcome: 'not_managed', set: null };
  }
  const set = await computeSet(trx, tenantId, deviceId, now);
  if (!set) return { outcome: 'no_record', set: null };

  const row = await trx('apple_declaration_sets').where({ tenant_id: tenantId, device_id: deviceId })
    .first('sent_token', 'sync_command_id') as { sent_token: string | null; sync_command_id: string | null };
  let announced = row.sent_token;
  if (row.sync_command_id) {
    const target = await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: row.sync_command_id, device_id: deviceId })
      .first('state') as { state: string } | undefined;
    // An open command is not doubled: the device will read the current tokens when it handles it.
    if (target && !isFinalTargetState(target.state)) return { outcome: 'open_command', set, commandId: row.sync_command_id };
    // The command ended without the hook of its final state (a target cancelled by a direct statement, a command
    // purged): its token is held as announced only if the device answered it.
    if (!target || (target.state !== 'acknowledged' && target.state !== 'error')) announced = null;
  }
  if (announced === set.declarationsToken) return { outcome: 'in_sync', set };
  if (!sender) return { outcome: 'no_sender', set };

  const sent = await sender(trx, {
    tenantId, deviceId, enrollmentId: d.enrollment_id, actor,
    data: Buffer.from(syncTokensBody(set.declarationsToken, set.computedAt), 'utf8'),
  });
  if ('refused' in sent) {
    ddmMetrics.syncCommand('refused');
    return { outcome: 'refused', set, refusal: REFUSAL_RE.test(sent.refused) ? sent.refused : 'refused' };
  }
  if (!UUID_RE.test(sent.commandId)) throw new Error('DDM sync sender: the command id is not a UUID');
  await trx('apple_declaration_sets').where({ tenant_id: tenantId, device_id: deviceId })
    .update({ sent_token: set.declarationsToken, sync_command_id: sent.commandId.toLowerCase() });
  ddmMetrics.syncCommand('sent');
  return { outcome: 'sent', set, commandId: sent.commandId.toLowerCase() };
}

/** What the end of a synchronisation command asks of the jobs module (the queue is its own). */
export interface SyncFollowUp {
  /** A new synchronisation of the device, in the transaction. */
  requestSync(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<void>;
  /** The check of the reference capabilities, 15 minutes after the DDM was first activated (§9.3). */
  scheduleBaselineCheck(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<void>;
}

let followUp: SyncFollowUp | null = null;

export function setSyncFollowUp(f: SyncFollowUp): void {
  followUp = f;
}

/**
 * The ingestor of the result of a DeclarativeManagement command (§7.6, §9.4 step 3), inline in the event's
 * savepoint. Acknowledged: the DDM is active on the device. In error: logged and counted, ddm_enabled unchanged.
 */
export async function ingestDeclarativeManagement(ctx: ResultIngestContext): Promise<void> {
  const { trx, tenantId, deviceId } = ctx;
  if (ctx.status !== 'Acknowledged') {
    ddmMetrics.syncCommand('error');
    logger.info({ tenantId, deviceId, status: ctx.status }, 'DDM: DeclarativeManagement command refused by the device');
    return;
  }
  ddmMetrics.syncCommand('acknowledged');
  const first = await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('ddm_enabled_at')
    .update({ ddm_enabled: true, ddm_enabled_at: ctx.occurredAt, updated_at: new Date() });
  if (first === 0) {
    await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId, ddm_enabled: false }).update({ ddm_enabled: true, updated_at: new Date() });
    return;
  }
  // First activation: the device now reports its capabilities; failing that, the reference ones apply later.
  if (followUp) await followUp.scheduleBaselineCheck(trx, tenantId, deviceId);
}

/**
 * The hook of the final state of a target (§9.4 step 2), in the event's savepoint: the device's synchronisation
 * command ended. Acknowledged or in error with a set that changed meanwhile: a new synchronisation. A command
 * that never reached the device (expired, cancelled, refused by apple-edge): the token is no longer held as
 * announced, and nothing is sent at once (a refusal would loop): the next recomputation announces it.
 */
export async function onSyncTargetFinal(ctx: TargetFinalContext): Promise<void> {
  if (ctx.requestType !== DDM_REQUEST_TYPE) return;
  const { trx, tenantId, deviceId } = ctx;
  const set = await trx('apple_declaration_sets').where({ tenant_id: tenantId, device_id: deviceId, sync_command_id: ctx.commandId.toLowerCase() })
    .forUpdate().first('declarations_token', 'sent_token') as { declarations_token: string; sent_token: string | null } | undefined;
  if (!set) return;                                     // not the device's synchronisation command (or its set is gone)
  const delivered = ctx.state === 'acknowledged' || ctx.state === 'error';
  await trx('apple_declaration_sets').where({ tenant_id: tenantId, device_id: deviceId })
    .update(delivered ? { sync_command_id: null } : { sync_command_id: null, sent_token: null });
  if (delivered && set.sent_token !== set.declarations_token && followUp) await followUp.requestSync(trx, tenantId, deviceId);
}
