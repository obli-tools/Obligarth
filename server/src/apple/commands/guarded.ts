import type { Knex } from 'knex';
import { z } from 'zod';
import { db } from '../../db';
import { registerGuardedAction, type GuardedActionDef, type GuardExecutionContext, type GuardTargetRefusal, type GuardTargetResult } from '../../guard';
import { jobIdFor } from '../../jobs';
import { AppError } from '../../middleware/errorHandler';
import { toAppError } from '../edge/appError';
import { isAppleEdgeError, type AppleEdgeError } from '../edge/errors';
import { mdmCommands, refusalOf } from './bus';
import { commandSpecOrNull, enrollmentProfileIdentifier, REMOVE_MANAGEMENT_ACTION } from './catalog';
import { startRetirementInTx } from '../devices/retire';
import { cancelAtEdge } from './submit';

// =============================================================================
// Guarded MDM actions (docs: integration-apple-edge §8.11, I24; audit-durci
// §10.2, §10.12): the erase, the lock, the lost mode and the removal from
// management are requested through the guard engine (floors, cancellable
// delays, client approver, hourly cap, freeze, cooldown, revalidation); this
// module gives the engine their MDM execution.
//   revalidate           per target, at execution: still an Apple record of
//                        the tenant, enrolled, of an ownership and a
//                        supervision the command allows (the prerequisites of
//                        the catalogue), then the action's own check
//   execute              one transaction of the tenant: the bus, origin
//                        'guard', one command per device whose CommandUUID is
//                        jobIdFor('mdm.command', '<action uuid>:<device id>'),
//                        idempotency key 'guard:<action uuid>'. Run again
//                        after a stop, it finds the same batch: neither the
//                        brain nor apple-edge creates a second command
//   cancelAfterDispatch  the commands of the action not yet delivered are
//                        withdrawn (apple-edge's answer per device). The
//                        engine calls it for a late cancellation, while the
//                        action is executed and after (its commands wait for
//                        their devices for days: 7 for an erase), until they
//                        expired (cancelWindowSeconds); the route of the
//                        command queue refuses to cancel these commands, the
//                        engine being their only way out too
// The bus refuses these request types from any other path (409
// guardedActionRequired): the engine is their only way in. It also refuses
// them for an action whose late cancellation was asked (the mark the engine
// writes under the lock of the action's row).
// =============================================================================

export type GuardedRequestType = 'EraseDevice' | 'RemoveProfile' | 'DeviceLock' | 'EnableLostMode';

/** What an action sees of a target when it revalidates it. */
export interface GuardedDevice {
  deviceId: number;
  ownership: string;
  supervised: boolean;
  enrollmentState: string;
  platform: string | null;
}

export interface GuardedMdmActionOptions<P> {
  requestType: GuardedRequestType;
  /** Command parameters (non-secret) built from the action's params. */
  commandParams(params: P, ctx: { tenantId: number; mdmKey: string | null }): Record<string, unknown>;
  /** Extra per-target check at execution, after the common ones (enrolled, Apple channel, ownership, supervision). */
  revalidateTarget?(device: GuardedDevice): 'ok' | GuardTargetRefusal;
  /** Command expiry counted from the execution (erase: 7 days, audit-durci §10.12). */
  expiresAfterSeconds: number;
  /** In the execution's transaction, after the commands are written (remove_management: apple.device-retire). */
  afterDispatch?(trx: Knex.Transaction, tenantId: number, actionUuid: string, deviceIds: number[]): Promise<void>;
}

interface TargetRow {
  id: number;
  management_channel: string;
  enrollment_state: string;
  ownership: 'corporate' | 'corporate_personal' | 'personal';
  supervised: boolean;
  platform: string | null;
  has_unlock_token: boolean | null;
  apple: number | null;
}

async function targetRows(tenantId: number, deviceIds: number[]): Promise<Map<number, TargetRow>> {
  if (deviceIds.length === 0) return new Map();
  const rows = await db('devices as d')
    .leftJoin('apple_devices as a', function joinSatellite() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereRaw('d.id = ANY (?::int[])', [deviceIds])
    .select('d.id', 'd.management_channel', 'd.enrollment_state', 'd.ownership', 'd.supervised', 'd.platform', 'a.has_unlock_token', 'a.device_id as apple') as TargetRow[];
  return new Map(rows.map((r) => [Number(r.id), r]));
}

/** The CommandUUID of a guarded action for one device (audit-durci §10.12), upper case. */
export function guardedCommandId(actionUuid: string, deviceId: number): string {
  return jobIdFor('mdm.command', `${actionUuid.toLowerCase()}:${deviceId}`).toUpperCase();
}

/** Completes a GuardedActionDef (audit-durci §10.2) with the MDM revalidate / execute / cancelAfterDispatch. */
export function defineGuardedMdmAction<P>(
  def: Omit<GuardedActionDef<P>, 'revalidate' | 'execute' | 'cancelAfterDispatch'>,
  opts: GuardedMdmActionOptions<P>,
): GuardedActionDef<P> {
  const specOf = () => {
    const spec = commandSpecOrNull(opts.requestType);
    if (!spec) throw new Error(`guarded action ${def.key}: the command type ${opts.requestType} is not registered`);
    return spec;
  };

  async function revalidate(ctx: GuardExecutionContext<P>): Promise<Map<number, 'ok' | GuardTargetRefusal>> {
    const spec = specOf();
    const rows = await targetRows(ctx.tenantId, ctx.deviceIds);
    const out = new Map<number, 'ok' | GuardTargetRefusal>();
    for (const id of ctx.deviceIds) {
      const r = rows.get(id);
      if (!r) { out.set(id, { code: 'not_found' }); continue; }
      const code = refusalOf(spec, r.apple === null ? undefined : { ...r, has_unlock_token: r.has_unlock_token === true });
      if (code) { out.set(id, { code }); continue; }
      if (def.refuseOwnership.includes(r.ownership)) { out.set(id, { code: 'ownership' }); continue; }
      out.set(id, opts.revalidateTarget
        ? opts.revalidateTarget({ deviceId: id, ownership: r.ownership, supervised: r.supervised === true, enrollmentState: r.enrollment_state, platform: r.platform })
        : 'ok');
    }
    return out;
  }

  async function execute(ctx: GuardExecutionContext<P>, deviceIds: number[]): Promise<Map<number, GuardTargetResult>> {
    const out = new Map<number, GuardTargetResult>();
    if (deviceIds.length === 0) return out;
    const { outcome, queued } = await db.transaction(async (trx) => {
      const t = await trx('tenants').where({ id: ctx.tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
      const o = await mdmCommands.enqueue(trx, {
        tenantId: ctx.tenantId, requestType: opts.requestType, deviceIds,
        params: opts.commandParams(ctx.params, { tenantId: ctx.tenantId, mdmKey: t?.mdm_key ?? null }),
        origin: 'guard', guardActionUuid: ctx.actionUuid,
        commandIdFor: (d) => guardedCommandId(ctx.actionUuid, d),
        idempotencyKey: `guard:${ctx.actionUuid.toLowerCase()}`,
        actor: `u:${ctx.requesterId}`, requestedBy: ctx.requesterId, reason: ctx.reason, ...(ctx.ticket ? { ticket: ctx.ticket } : {}),
        ...(ctx.approvalIds[0] ? { approvalId: ctx.approvalIds[0] } : {}),
        expiresInSeconds: opts.expiresAfterSeconds,
      });
      // The devices that hold a command of the batch (a replayed execution names no refusal: the batch tells).
      const has = o.commandIds.length === 0 ? [] : await trx('mdm_command_targets').where({ tenant_id: ctx.tenantId })
        .whereIn('command_id', o.commandIds).pluck('device_id') as number[];
      if (opts.afterDispatch && has.length > 0) await opts.afterDispatch(trx, ctx.tenantId, ctx.actionUuid, has.map(Number));
      return { outcome: o, queued: new Set(has.map(Number)) };
    });
    const refused = new Map(outcome.refused.map((r) => [r.deviceId, r.code as string]));
    for (const id of deviceIds) {
      if (queued.has(id)) out.set(id, { status: 'queued' });
      else out.set(id, { status: 'skipped', code: refused.get(id) ?? 'not_queued' });
    }
    return out;
  }

  async function cancelAfterDispatch(ctx: GuardExecutionContext<P>): Promise<Map<number, 'cancelled' | 'already_delivered' | 'completed'>> {
    const out = new Map<number, 'cancelled' | 'already_delivered' | 'completed'>();
    const commands = await db('mdm_commands').where({ tenant_id: ctx.tenantId, guard_action_uuid: ctx.actionUuid }).pluck('id') as string[];
    for (const raw of commands) {
      const commandId = String(raw).toLowerCase();
      // What never left the brain is cancelled at once; what apple-edge holds is asked for right away (the job the
      // bus sends finds nothing left, or finishes what apple-edge could not answer now).
      await db.transaction((trx) => mdmCommands.cancel(trx, ctx.tenantId, commandId, null, `u:${ctx.requesterId}`, { allowGuarded: true, silent: true }));
      try {
        await cancelAtEdge(ctx.tenantId, commandId, {}, { actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal });
      } catch (err) {
        if (isAppleEdgeError(err)) throw toAppError(err as AppleEdgeError);
        throw err;
      }
      const targets = await db('mdm_command_targets').where({ tenant_id: ctx.tenantId, command_id: commandId })
        .select('device_id', 'state', 'reject_code') as Array<{ device_id: number; state: string; reject_code: string | null }>;
      for (const t of targets) {
        const id = Number(t.device_id);
        if (t.state === 'acknowledged' || t.state === 'error') out.set(id, 'completed');
        else if (t.state === 'cancelled' && t.reject_code === 'cancel_after_delivery') out.set(id, 'already_delivered');
        else if (t.state === 'cancelled' || t.state === 'expired' || t.state === 'rejected') out.set(id, 'cancelled');
        else throw new AppError(503, 'The device service did not take the cancellation yet: it is retried', 'appleEdgeUnavailable');
      }
    }
    return out;
  }

  // Once its commands expired, nothing of the action waits for a device any more: no late cancellation beyond. The
  // channel of the action is apple_mdm (a device of another channel is refused at the request, PONT-R-RV4) unless
  // another module adds its own (guard/channels.ts, lot AN-P).
  return { ...def, channels: def.channels ?? ['apple_mdm'], revalidate, execute, cancelAfterDispatch, cancelWindowSeconds: opts.expiresAfterSeconds };
}

/** Serial numbers of the targets for the execution entry of the journal (J29); '' when not collected. */
async function serialsOf(tenantId: number, deviceIds: number[]): Promise<Map<number, string>> {
  if (deviceIds.length === 0) return new Map();
  const rows = await db('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [deviceIds]).select('id', 'serial_number') as
    Array<{ id: number; serial_number: string | null }>;
  return new Map(rows.map((r) => [Number(r.id), r.serial_number ?? '']));
}

const DAY = 86_400;
const CATEGORY = 'Apple MDM';

const EraseParams = z.object({ preserveDataPlan: z.boolean().optional(), disallowProximitySetup: z.boolean().optional() }).strict();
const LockParams = z.object({ message: z.string().trim().min(1).max(200).optional(), phoneNumber: z.string().trim().min(1).max(30).optional() }).strict();
const LostModeParams = z.object({
  message: z.string().trim().min(1).max(200).optional(), phoneNumber: z.string().trim().min(1).max(30).optional(),
  footnote: z.string().trim().min(1).max(200).optional(),
}).strict().refine((p) => p.message !== undefined || p.phoneNumber !== undefined, 'message or phoneNumber is required');
const NoParams = z.object({}).strict();

let registered = false;

/**
 * The guarded MDM actions of the MVP (annex E.15, decision of the owners for lot B: registered by the
 * integration with the values of audit-durci §10.2). After registerMvpCommandSpecs. Their floors are not stored in
 * a tenant's matrix (no defaultLevel): a floor holds for every tenant, whatever its matrix says. The verified retirement that
 * follows a removal from management (§13.3, apple.device-retire) starts in the execution's transaction (afterDispatch).
 * Their channel is apple_mdm; another module adds its own to the same key (registerGuardedActionChannel, lot AN-P:
 * the channel amapi, android-amapi §11.4); their Apple targets are handled as before.
 */
export function registerGuardedMdmActions(): void {
  if (registered) return;
  registered = true;
  const clean = <T extends Record<string, unknown>>(p: T): Record<string, unknown> => Object.fromEntries(Object.entries(p).filter(([, v]) => v !== undefined));

  // Erase: one or two devices 'sensitive' without the trusted-IP shortcut and 300 s; a batch 'restricted' and
  // 900 s; counted in the hourly cap; never a personal device; the whole fleet refused; typed confirmation.
  registerGuardedAction(defineGuardedMdmAction<z.infer<typeof EraseParams>>({
    key: 'mdm.erase_device', label: 'Erase devices', family: 'device_destruction', singleFloor: 'sensitive', singleStrictStepUp: true,
    bulkThreshold: 3, singleDelaySeconds: 300, bulkDelaySeconds: 900, hourlyCap: true, forbidWholeFleet: true, refuseOwnership: ['personal'],
    confirmation: 'typed', paramsSchema: EraseParams as z.ZodType<z.infer<typeof EraseParams>>, deviceCapability: 'mdm:wipe', category: CATEGORY,
    serialsOf,
  }, { requestType: 'EraseDevice', commandParams: (p) => clean(p), expiresAfterSeconds: 7 * DAY }));

  // Removal from management: RemoveProfile of the enrollment profile of the tenant; the only « deletion » allowed
  // on a personal device (it removes the work data, SEC-02).
  registerGuardedAction(defineGuardedMdmAction<Record<string, never>>({
    key: REMOVE_MANAGEMENT_ACTION, label: 'Remove devices from management', family: 'device_destruction', singleFloor: 'sensitive',
    singleStrictStepUp: false, bulkThreshold: 3, singleDelaySeconds: 0, bulkDelaySeconds: 900, hourlyCap: true, forbidWholeFleet: true,
    refuseOwnership: [], confirmation: 'typed', paramsSchema: NoParams as unknown as z.ZodType<Record<string, never>>, deviceCapability: 'mdm:remove',
    category: CATEGORY, serialsOf,
  }, {
    requestType: 'RemoveProfile',
    commandParams: (_p, c) => {
      if (!c.mdmKey) throw new AppError(409, 'This tenant is not provisioned at the device service yet', 'appleTenantNotProvisioned');
      return { identifier: enrollmentProfileIdentifier(c.mdmKey) };
    },
    expiresAfterSeconds: 14 * DAY,
    afterDispatch: (trx, tenantId, actionUuid, deviceIds) => startRetirementInTx(trx, tenantId, actionUuid, deviceIds),
  }));

  // Lock: 'sensitive', no delay; a batch 'restricted'.
  registerGuardedAction(defineGuardedMdmAction<z.infer<typeof LockParams>>({
    key: 'mdm.device_lock', label: 'Lock devices', family: 'device_control', singleFloor: 'sensitive', singleStrictStepUp: false,
    bulkThreshold: 3, singleDelaySeconds: 0, bulkDelaySeconds: 0, hourlyCap: false, forbidWholeFleet: true, refuseOwnership: ['personal'],
    confirmation: 'none', paramsSchema: LockParams as z.ZodType<z.infer<typeof LockParams>>, deviceCapability: 'mdm:lock', category: CATEGORY,
    serialsOf,
  }, { requestType: 'DeviceLock', commandParams: (p) => clean(p), expiresAfterSeconds: 7 * DAY }));

  // Lost mode: 'sensitive', a reason (the engine asks one for every action), never a personal device.
  registerGuardedAction(defineGuardedMdmAction<z.infer<typeof LostModeParams>>({
    key: 'mdm.lost_mode_enable', label: 'Enable the lost mode', family: 'device_privacy', singleFloor: 'sensitive', singleStrictStepUp: false,
    bulkThreshold: 3, singleDelaySeconds: 0, bulkDelaySeconds: 0, hourlyCap: false, forbidWholeFleet: true, refuseOwnership: ['personal'],
    confirmation: 'none', paramsSchema: LostModeParams as unknown as z.ZodType<z.infer<typeof LostModeParams>>, deviceCapability: 'mdm:lost_mode',
    category: CATEGORY, serialsOf,
  }, { requestType: 'EnableLostMode', commandParams: (p) => clean(p), expiresAfterSeconds: 30 * DAY }));
}
