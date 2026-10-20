import { z } from 'zod';
import { db } from '../db';
import {
  registerGuardedAction, type GuardedActionDef, type GuardExecutionContext, type GuardTargetRefusal, type GuardTargetResult,
} from '../guard';
import { jobIdFor } from '../jobs';
import { ERASE_ACTION, LOCK_ACTION, legacyAgentCommands } from './commands';

// =============================================================================
// Guarded actions of the bridge agent (docs: agent-pont-android §5.4, PB6):
// the erase and the lock are requested through the guard engine (floors,
// cancellable delays, hourly cap, whole fleet refused, freeze, approval), with
// the values of their Apple counterparts (mdm.erase_device, mdm.device_lock,
// apple/commands/guarded.ts, audit-durci §10.2). This module gives the engine
// their execution:
//   revalidate           per target: a record of the tenant, channel
//                        legacy_agent, enrolled, satellite not revoked,
//                        corporate, administrator active (else admin_inactive)
//   execute              one transaction: the queue, origin 'guard', command id
//                        jobIdFor('legacy_agent.command', '<action>:<device>'),
//                        idempotency key 'guard:<action uuid>': run again, it
//                        finds the same rows
//   cancelAfterDispatch  pending → cancelled; sent → already_delivered; final
//                        → completed; within the lifetime of the commands
// The removal (legacy_agent.remove_management, agent.retire) is v1 (§15.4).
// =============================================================================

const DAY = 86_400;
const CATEGORY = 'Android agent';
/** The channel of the agent's actions (decisions of the owners of 20/10/2026): a request on a device of another channel
 *  is refused at once (PONT-R-RV4); the whole fleet and the hourly cap are also those of the agent's devices (RV3). */
const CHANNELS = ['legacy_agent'] as const;

export function guardedCommandId(actionUuid: string, deviceId: number): string {
  return jobIdFor('legacy_agent.command', `${actionUuid.toLowerCase()}:${deviceId}`);
}

interface TargetRow {
  id: number;
  management_channel: string;
  enrollment_state: string;
  ownership: string;
  agent: number | null;
  revoked_at: Date | null;
  admin_active: boolean | null;
}

async function targetRows(tenantId: number, deviceIds: number[]): Promise<Map<number, TargetRow>> {
  if (deviceIds.length === 0) return new Map();
  const rows = await db('devices as d')
    .leftJoin('legacy_agent_devices as a', function joinSatellite() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereRaw('d.id = ANY (?::int[])', [deviceIds])
    .select('d.id', 'd.management_channel', 'd.enrollment_state', 'd.ownership', 'a.device_id as agent', 'a.revoked_at', 'a.admin_active') as TargetRow[];
  return new Map(rows.map((r) => [Number(r.id), r]));
}

async function serialsOf(tenantId: number, deviceIds: number[]): Promise<Map<number, string>> {
  if (deviceIds.length === 0) return new Map();
  const rows = await db('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [deviceIds]).select('id', 'serial_number') as
    Array<{ id: number; serial_number: string | null }>;
  return new Map(rows.map((r) => [Number(r.id), r.serial_number ?? '']));
}

function defineAction<P extends Record<string, unknown>>(
  def: Omit<GuardedActionDef<P>, 'revalidate' | 'execute' | 'cancelAfterDispatch'>,
  o: { requestType: 'device.wipe' | 'device.lock'; commandParams(p: P): Record<string, unknown>; lifetimeSeconds: number },
): GuardedActionDef<P> {
  async function revalidate(ctx: GuardExecutionContext<P>): Promise<Map<number, 'ok' | GuardTargetRefusal>> {
    const rows = await targetRows(ctx.tenantId, ctx.deviceIds);
    const out = new Map<number, 'ok' | GuardTargetRefusal>();
    for (const id of ctx.deviceIds) {
      const r = rows.get(id);
      if (!r) out.set(id, { code: 'not_found' });
      else if (r.management_channel !== 'legacy_agent' || r.agent === null) out.set(id, { code: 'not_agent' });
      else if (r.revoked_at) out.set(id, { code: 'revoked' });
      else if (r.enrollment_state !== 'enrolled') out.set(id, { code: 'not_enrolled' });
      else if (r.ownership !== 'corporate') out.set(id, { code: 'ownership' });
      else if (r.admin_active !== true) out.set(id, { code: 'admin_inactive' });
      else out.set(id, 'ok');
    }
    return out;
  }

  async function execute(ctx: GuardExecutionContext<P>, deviceIds: number[]): Promise<Map<number, GuardTargetResult>> {
    const out = new Map<number, GuardTargetResult>();
    if (deviceIds.length === 0) return out;
    const { refused, queued } = await db.transaction(async (trx) => {
      const r = await legacyAgentCommands.enqueue(trx, {
        tenantId: ctx.tenantId, requestType: o.requestType, deviceIds, params: o.commandParams(ctx.params),
        origin: 'guard', guardActionUuid: ctx.actionUuid, commandIdFor: (d) => guardedCommandId(ctx.actionUuid, d),
        idempotencyKey: `guard:${ctx.actionUuid.toLowerCase()}`,
        actor: `u:${ctx.requesterId}`, requestedBy: ctx.requesterId, reason: ctx.reason, ...(ctx.ticket ? { ticket: ctx.ticket } : {}),
        ...(ctx.approvalIds[0] ? { approvalId: ctx.approvalIds[0] } : {}),
        expiresInSeconds: o.lifetimeSeconds,
      });
      const has = r.commandIds.length === 0 ? [] : await trx('legacy_agent_commands').where({ tenant_id: ctx.tenantId })
        .whereIn('id', r.commandIds).pluck('device_id') as number[];
      return { refused: new Map(r.refused.map((x) => [x.deviceId, x.code as string])), queued: new Set(has.map(Number)) };
    });
    for (const id of deviceIds) {
      if (queued.has(id)) out.set(id, { status: 'queued' });
      else out.set(id, { status: 'skipped', code: refused.get(id) ?? 'not_queued' });
    }
    return out;
  }

  async function cancelAfterDispatch(ctx: GuardExecutionContext<P>): Promise<Map<number, 'cancelled' | 'already_delivered' | 'completed'>> {
    const out = new Map<number, 'cancelled' | 'already_delivered' | 'completed'>();
    const ids = await db('legacy_agent_commands').where({ tenant_id: ctx.tenantId, guard_action_uuid: ctx.actionUuid.toLowerCase() }).pluck('id') as string[];
    for (const id of ids) {
      const r = await db.transaction((trx) => legacyAgentCommands.cancel(trx, ctx.tenantId, String(id), `u:${ctx.requesterId}`, { allowGuarded: true, silent: true }));
      out.set(r.deviceId, r.result);
    }
    return out;
  }

  return { ...def, revalidate, execute, cancelAfterDispatch, cancelWindowSeconds: o.lifetimeSeconds };
}

const EraseParams = z.object({ wipeExternal: z.boolean().optional() }).strict();
const NoParams = z.object({}).strict();

let registered = false;

/** The guarded actions of the bridge agent (§5.4): the values of mdm.erase_device and mdm.device_lock. */
export function registerLegacyAgentGuardedActions(): void {
  if (registered) return;
  registered = true;
  // Erase: one or two devices 'sensitive' without the trusted-IP shortcut and 300 s; a batch 'restricted' and 900 s;
  // counted in the hourly cap; never a personal device; the whole fleet refused; typed confirmation.
  registerGuardedAction(defineAction<z.infer<typeof EraseParams>>({
    key: ERASE_ACTION, label: 'Erase Android agent devices', family: 'device_destruction', singleFloor: 'sensitive', singleStrictStepUp: true,
    bulkThreshold: 3, singleDelaySeconds: 300, bulkDelaySeconds: 900, hourlyCap: true, forbidWholeFleet: true, refuseOwnership: ['personal'],
    confirmation: 'typed', paramsSchema: EraseParams as z.ZodType<z.infer<typeof EraseParams>>, deviceCapability: 'mdm:wipe', category: CATEGORY,
    serialsOf, channels: CHANNELS,
  }, { requestType: 'device.wipe', commandParams: (p) => ({ wipeExternal: p.wipeExternal === true }), lifetimeSeconds: 7 * DAY }));

  // Lock: 'sensitive', no delay; a batch 'restricted'.
  registerGuardedAction(defineAction<Record<string, never>>({
    key: LOCK_ACTION, label: 'Lock Android agent devices', family: 'device_control', singleFloor: 'sensitive', singleStrictStepUp: false,
    bulkThreshold: 3, singleDelaySeconds: 0, bulkDelaySeconds: 0, hourlyCap: false, forbidWholeFleet: true, refuseOwnership: ['personal'],
    confirmation: 'none', paramsSchema: NoParams as unknown as z.ZodType<Record<string, never>>, deviceCapability: 'mdm:lock', category: CATEGORY,
    serialsOf, channels: CHANNELS,
  }, { requestType: 'device.lock', commandParams: () => ({}), lifetimeSeconds: 7 * DAY }));
}
