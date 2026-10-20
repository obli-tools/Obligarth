// The commands of the console that are not guarded (REBOOT, STOP_LOST_MODE, CLEAR_APP_DATA; android-amapi §11.2, §11.5;
// lot AN-D): their restriction keys of the tenant's matrix (mdm.reboot, mdm.lost_mode_disable, mdm.clear_app_data,
// floor 'sensitive'), the path of the level 'restricted' (a request for approval of type android_action, executed as
// the requester once a second person approved it: rights and devices read again), and the writing shared by the
// routes and that executor. The guarded types go through /api/guard/actions only.
import type { Knex } from 'knex';
import type { DeviceCapability } from '@obligarth/shared';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { userActor } from '../../db/context';
import { guardReviewerPolicy } from '../../guard/approvals';
import {
  activeRequester, refuse, registerApprovalRequestType, type ApprovalExecution, type ApprovalRequestType,
} from '../../services/approval.service';
import { permissionService } from '../../services/permission.service';
import { registerRestrictableActions } from '../../services/restriction.service';
import { ANDROID_COMMANDS, isAndroidCommandType, type AndroidCommandType } from './catalog';
import { AndroidCommandError, enqueueAndroidCommands, type EnqueueOutcome } from './bus';

/** The approval type of a command the matrix holds at 'restricted'. */
export const ANDROID_ACTION_APPROVAL = 'android_action' as ApprovalRequestType;

/** The capability of the device's team scope each command type needs (§22.8). */
export const ANDROID_COMMAND_CAPABILITY: Readonly<Record<AndroidCommandType, DeviceCapability>> = Object.freeze({
  LOCK: 'mdm:lock',
  RESET_PASSWORD: 'mdm:passcode',
  REBOOT: 'mdm:restart',
  START_LOST_MODE: 'mdm:lost_mode',
  STOP_LOST_MODE: 'mdm:lost_mode',
  WIPE: 'mdm:wipe',
  RELINQUISH_OWNERSHIP: 'mdm:remove',
  CLEAR_APP_DATA: 'mdm:apps',
});

/** The restriction key of each command of the console (§11.2: restriction 'sensitive'). */
export const ANDROID_COMMAND_RESTRICTION: Readonly<Partial<Record<AndroidCommandType, string>>> = Object.freeze({
  REBOOT: 'mdm.reboot',
  STOP_LOST_MODE: 'mdm.lost_mode_disable',
  CLEAR_APP_DATA: 'mdm.clear_app_data',
});

export const ANDROID_RESTRICTABLE_ACTIONS = [
  { key: 'mdm.reboot', label: 'Reboot Android devices', category: 'Android' },
  { key: 'mdm.lost_mode_disable', label: 'Disable the lost mode of Android devices', category: 'Android' },
  { key: 'mdm.clear_app_data', label: 'Clear the data of managed apps on Android devices', category: 'Android' },
] as const;

/** The types a console request may ask (not guarded). */
export function consoleType(raw: unknown): AndroidCommandType | null {
  return typeof raw === 'string' && isAndroidCommandType(raw) && !ANDROID_COMMANDS[raw].guarded ? raw : null;
}

export interface ConsoleCommand {
  tenantId: number;
  type: AndroidCommandType;
  deviceIds: number[];
  params?: Record<string, unknown>;
  reason?: string;
  userId: number;
  origin: 'console' | 'approval';
  approvalId?: number;
  idempotencyKey?: string;
  auditCtx?: AuditWriteContext;
}

/** Writes a console command in `trx` (STOP_LOST_MODE: the lost mode of the devices goes 'disabling'). */
export async function enqueueConsoleCommand(trx: Knex.Transaction, c: ConsoleCommand): Promise<EnqueueOutcome> {
  const out = await enqueueAndroidCommands(trx, {
    tenantId: c.tenantId, type: c.type, deviceIds: c.deviceIds, params: c.params, origin: c.origin, actor: `u:${c.userId}`, requestedBy: c.userId,
    ...(c.reason ? { reason: c.reason } : {}), ...(c.approvalId ? { approvalId: c.approvalId } : {}),
    ...(c.idempotencyKey ? { idempotencyKey: c.idempotencyKey } : {}), ...(c.auditCtx ? { auditCtx: c.auditCtx } : {}),
  });
  if (c.type === 'STOP_LOST_MODE' && out.byDevice.size && !out.replayed) {
    await trx('devices').where({ tenant_id: c.tenantId, lost_mode_state: 'on' }).whereIn('id', [...out.byDevice.keys()])
      .update({ lost_mode_state: 'disabling', lost_mode_changed_at: trx.fn.now() });
  }
  return out;
}

/**
 * The executor of an approved android_action request: as the requester, whose activity, capability of the type and
 * write access on each device are read again; the command is written with origin 'approval' and the approval's
 * idempotency key (an execution run again writes nothing more).
 */
export async function executeAndroidAction(x: ApprovalExecution): Promise<string | void> {
  const p = (x.payload ?? {}) as { action?: unknown; type?: unknown; deviceIds?: unknown; params?: unknown; reason?: unknown };
  const type = consoleType(p.type);
  if (p.action !== 'android.command' || !type || !Array.isArray(p.deviceIds)) refuse('Malformed command request');
  const ids = [...new Set((p.deviceIds as unknown[]).map(Number).filter((n) => Number.isSafeInteger(n) && n > 0))];
  if (ids.length === 0 || ids.length > 500) refuse('Malformed command request');
  const requester = await activeRequester(x.requesterId);
  const present = await db('devices').where({ tenant_id: x.tenantId }).whereIn('id', ids).pluck('id') as number[];
  if (present.length !== ids.length) refuse('Some devices of this request are no longer in the tenant');
  if (!requester.isPlatformAdmin) {
    const capability = ANDROID_COMMAND_CAPABILITY[type as AndroidCommandType];
    const without = new Set(await permissionService.devicesLackingCapability(x.requesterId, ids, capability));
    for (const id of ids) if (!without.has(id) && !(await permissionService.canWriteDevice(x.requesterId, id, false))) without.add(id);
    if (without.size > 0) refuse('The requester no longer holds the capability of this command on every device');
  }
  const params = (p.params && typeof p.params === 'object' && !Array.isArray(p.params) ? p.params : {}) as Record<string, unknown>;
  let o: EnqueueOutcome;
  try {
    const auditCtx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
    o = await db.transaction((trx) => enqueueConsoleCommand(trx, {
      tenantId: x.tenantId, type: type as AndroidCommandType, deviceIds: ids, params, userId: x.requesterId, origin: 'approval', auditCtx,
      ...(typeof p.reason === 'string' && p.reason ? { reason: p.reason } : {}),
      ...(x.approvalId ? { approvalId: x.approvalId, idempotencyKey: `approval:${x.approvalId}` } : {}),
    }));
  } catch (err) {
    if (err instanceof AndroidCommandError && err.status < 500) refuse(`${err.code}: ${err.message}`);
    throw err;
  }
  if (o.byDevice.size === 0) refuse(`No device could take the command (${o.refused[0]?.code ?? 'refused'})`);
  if (o.refused.length > 0) return `${o.refused.length} device(s) set aside (${[...new Set(o.refused.map((r) => r.code))].join(', ')})`;
  return undefined;
}

let registered = false;

/** Restriction keys (floors 'sensitive') and the approval type of the Android console commands: registerAndroidModule. */
export function registerAndroidConsoleCommands(): void {
  if (registered) return;
  registered = true;
  registerRestrictableActions(ANDROID_RESTRICTABLE_ACTIONS, {}, {
    'mdm.reboot': { level: 'sensitive' }, 'mdm.lost_mode_disable': { level: 'sensitive' }, 'mdm.clear_app_data': { level: 'sensitive' },
  });
  registerApprovalRequestType(ANDROID_ACTION_APPROVAL, executeAndroidAction, { expiryMinutes: 240, reviewerPolicy: guardReviewerPolicy, reviewerStepUp: 'strict' });
}
