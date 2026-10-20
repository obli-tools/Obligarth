// Where an Android command lives (android-amapi §4.5, §11.1; lot AN-D): one row of mdm_commands (platform 'android',
// its AMAPI body without any secret, the sealed newPassword of RESET_PASSWORD) and its single row of
// mdm_command_targets (the device, the state of §11.3, the AN50 mark, the operation, the hold, the polling schedule).
// The bus, the submission, the polling and the routes read and write a command through these helpers, as one flat
// row (CommandRow, the names of the former android_commands); a patch is split between the two tables, under the
// lock of the row it checks first.
import type { Knex } from 'knex';
import type { AndroidCommandType, AndroidTargetState } from './catalog';

export interface CommandRow {
  id: string;
  tenant_id: number;
  device_id: number;
  /** The AMAPI device name at the creation (channel identity: enterprises/<e>/devices/<d>). */
  enrollment_id: string;
  batch_id: string;
  request_type: AndroidCommandType;
  params: Record<string, unknown>;
  amapi_command: Record<string, unknown>;
  secret_enc: string | null;
  origin: 'console' | 'guard' | 'system' | 'approval';
  actor: string;
  requested_by: number | null;
  guard_action_uuid: string | null;
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
  updated_at: Date;
}

/** The columns of a CommandRow, qualified (c: mdm_commands, t: mdm_command_targets). */
export const COMMAND_COLUMNS = [
  'c.id', 'c.tenant_id', 't.device_id', 't.enrollment_id', 'c.batch_id', 'c.request_type', 'c.params', 'c.amapi_command', 'c.secret_enc', 'c.origin',
  'c.actor', 'c.requested_by', 'c.guard_action_uuid', 'c.expires_at', 'c.submit_state', 't.hold_reason', 'c.submit_attempts',
  't.amapi_submit_started_at', 't.amapi_operation', 't.amapi_error_code', 't.state', 't.reject_code', 't.delivered_at', 't.completed_at',
  't.cancel_requested_at', 't.amapi_next_poll_at as next_poll_at', 't.amapi_poll_count as poll_count', 'c.created_at', 'c.updated_at',
];

/** The sealed newPassword of a RESET_PASSWORD (registered column of the vault, §22.9). */
export const COMMAND_SECRET_COLUMN = { table: 'mdm_commands', column: 'secret_enc' } as const;
/** Where android_commands sealed it (its AAD), until the boot backfill seals it again (migration android_commands_move). */
export const MOVED_SECRET_COLUMN = { table: 'android_commands', column: 'secret_enc' } as const;

/** The Android commands: mdm_commands c joined to their target t. */
export function commands(q: Knex | Knex.Transaction): Knex.QueryBuilder {
  return q('mdm_commands as c')
    .join('mdm_command_targets as t', function joinTarget() { this.on('t.command_id', '=', 'c.id').andOn('t.tenant_id', '=', 'c.tenant_id'); })
    .where('c.platform', 'android');
}

/** One command of the tenant (FOR UPDATE of both rows when `lock`). */
export async function readCommand(q: Knex | Knex.Transaction, tenantId: number, id: string, lock = false): Promise<CommandRow | undefined> {
  const b = commands(q).where({ 'c.tenant_id': tenantId, 'c.id': id.toLowerCase() }).first(COMMAND_COLUMNS);
  if (lock) b.forUpdate();
  return b as unknown as Promise<CommandRow | undefined>;
}

const TARGET_FIELDS: Readonly<Record<string, string>> = Object.freeze({
  state: 'state', state_event_at: 'state_event_at', hold_reason: 'hold_reason', reject_code: 'reject_code', delivered_at: 'delivered_at',
  completed_at: 'completed_at', cancel_requested_at: 'cancel_requested_at', amapi_operation: 'amapi_operation',
  amapi_error_code: 'amapi_error_code', amapi_submit_started_at: 'amapi_submit_started_at', next_poll_at: 'amapi_next_poll_at',
  poll_count: 'amapi_poll_count',
});
const COMMAND_FIELDS: ReadonlySet<string> = new Set(['submit_state', 'submit_attempts', 'last_submit_error', 'secret_enc', 'submitted_at', 'updated_at']);

/** Conditions a patch checks on the row, under its lock (absent: no condition). */
export interface PatchWhere {
  states?: readonly AndroidTargetState[];
  submitState?: string;
  holdReason?: string | readonly string[];
  operationNull?: boolean;
  cancelNotRequested?: boolean;
}

/**
 * Updates one command (both of its rows) when it still meets `where`: the row is locked and checked first, then the
 * target and the command are written; mdm_commands.updated_at is always refreshed. Returns 1 when written, else 0.
 * A value may be a raw expression of the column's own table (submit_attempts + 1 on mdm_commands).
 */
export async function patchCommand(trx: Knex.Transaction, tenantId: number, id: string, patch: Record<string, unknown>, where: PatchWhere = {}): Promise<number> {
  const cid = id.toLowerCase();
  const q = commands(trx).where({ 'c.tenant_id': tenantId, 'c.id': cid });
  if (where.states) q.whereIn('t.state', where.states as string[]);
  if (where.submitState) q.where('c.submit_state', where.submitState);
  if (where.holdReason !== undefined) {
    if (typeof where.holdReason === 'string') q.where('t.hold_reason', where.holdReason); else q.whereIn('t.hold_reason', where.holdReason as string[]);
  }
  if (where.operationNull) q.whereNull('t.amapi_operation');
  if (where.cancelNotRequested) q.whereNull('t.cancel_requested_at');
  const hit = await q.forUpdate().first('c.id');
  if (!hit) return 0;
  const target: Record<string, unknown> = {};
  const command: Record<string, unknown> = { updated_at: trx.fn.now() };
  for (const [k, v] of Object.entries(patch)) {
    if (k in TARGET_FIELDS) target[TARGET_FIELDS[k]] = v;
    else if (COMMAND_FIELDS.has(k)) command[k] = v;
    else throw new Error(`android commands: unknown field ${k}`);
  }
  if (Object.keys(target).length) await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: cid }).update(target);
  await trx('mdm_commands').where({ tenant_id: tenantId, id: cid }).update(command);
  return 1;
}

export interface NewCommand {
  id: string;
  tenantId: number;
  deviceId: number;
  enrollmentId: string;
  batchId: string;
  type: AndroidCommandType;
  params: Record<string, unknown>;
  body: Record<string, unknown>;
  secretEnc: string | null;
  origin: 'console' | 'guard' | 'system' | 'approval';
  actor: string;
  requestedBy: number | null;
  reason: string | null;
  approvalId?: number | null;
  guardActionUuid: string | null;
  idempotencyKey: string | null;
  expiresAt: Date;
  held: boolean;
}

/** The stored idempotency key of a device's command: the unique key of mdm_commands is per tenant, an Android request
 *  writes one command per device. */
export const storedKey = (deviceId: number, key: string): string => `amapi:${deviceId}:${key}`.slice(0, 200);

/**
 * Writes a command and its target; false when either exists already (the same id, the same stored key, or another
 * open command of the type on the device: AN-RC4), nothing written then.
 */
export async function insertCommand(trx: Knex.Transaction, n: NewCommand): Promise<boolean> {
  const now = new Date();
  const rows = await trx('mdm_commands').insert({
    id: n.id, tenant_id: n.tenantId, batch_id: n.batchId, platform: 'android', request_type: n.type, params: JSON.stringify(n.params),
    plist: null, plist_enc: null, plist_sha256: null, amapi_command: JSON.stringify(n.body), secret_enc: n.secretEnc, origin: n.origin,
    actor: n.actor.slice(0, 70), requested_by: n.requestedBy, reason: n.reason, approval_id: n.approvalId ?? null, guard_action_uuid: n.guardActionUuid,
    idempotency_key: n.idempotencyKey ? storedKey(n.deviceId, n.idempotencyKey) : null, push: false, expires_at: n.expiresAt,
    submit_state: n.held ? 'held' : 'pending', created_at: now, updated_at: now,
  }).onConflict().ignore().returning('id') as Array<{ id: string }>;
  if (!rows.length) return false;
  const t = await trx('mdm_command_targets').insert({
    command_id: n.id, tenant_id: n.tenantId, device_id: n.deviceId, enrollment_id: n.enrollmentId, state: 'pending', state_event_at: now,
    hold_reason: n.held ? 'frozen' : null, amapi_request_type: n.type,
  }).onConflict().ignore().returning('command_id') as Array<{ command_id: string }>;
  if (t.length) return true;
  // Another open command of the type holds the device: the command row goes too (same transaction).
  await trx('mdm_commands').where({ tenant_id: n.tenantId, id: n.id }).delete();
  return false;
}
