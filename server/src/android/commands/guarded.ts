// The channel amapi of the guarded device actions (section 11.4, AN14, AN15, AN30). Since the junction AN-P, the four
// keys shared with Apple take the channel amapi through the registry of the guard engine (registerGuardedActionChannel,
// guard/channels.ts: the targets split by channel at execution, the amapi ones to androidGuardedChannel below; the
// channel apple_mdm keeps its behaviour); besides:
//   - the actions that exist only for Android (mdm.reset_password, mdm.relinquish_ownership, mdm.android_disable) are
//     complete GuardedActionDef registered by registerAndroidGuardedActions() (new restriction keys, no existing file);
//   - defineAndroidGuardedAction() builds the Android-only definition of any key of the table (the testbed registers
//     the four shared keys with it when the Apple module is not loaded; the mixed action is the junction's).
// Per key (table of §11.4): erase_device → WIPE (corporate only); remove_management → WIPE of the profile (personal),
// RELINQUISH_OWNERSHIP (corporate_personal; mode 'wipe' for a factory reset), refused for a corporate device
// (use_erase); device_lock → LOCK; lost_mode_enable → START_LOST_MODE; reset_password → RESET_PASSWORD;
// relinquish_ownership → RELINQUISH_OWNERSHIP; android_disable → devices.patch state DISABLED (params.enable: ACTIVE).
// Commands: one per device, id jobIdFor('mdm.command', '<action uuid>:<device id>'), idempotency key
// 'guard:<action uuid>': an execution run again after a stop finds its commands (no second command). newPassword:
// sealed in the tenant's vault at the request (prepareResetPasswordParams, purpose android.reset_password; params
// carry {"$secret": "<uuid>"} only: pending_actions.params is clear JSON shown to the console and the approvers,
// COH-7), read by the execution, sealed in secret_enc of each command, then destroyed; a refused, expired or cancelled
// action loses it to the sweep of the maintenance (sweepResetPasswordSecrets).
import type { Knex } from 'knex';
import { z } from 'zod';
import { audit } from '../../audit';
import { db } from '../../db';
import {
  registerGuardedAction, registerGuardedActionChannel, type GuardedActionDef, type GuardedChannelImpl, type GuardExecutionContext, type GuardTargetRefusal,
  type GuardTargetResult,
} from '../../guard';
import { jobIdFor } from '../../jobs';
import { findSecretRefs, vault, VaultError } from '../../vault';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { AndroidError } from '../gateway/errors';
import { parseOwnedName } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { AppError } from '../../middleware/errorHandler';
import { ANDROID_COMMANDS, AndroidCommandParamError, checkNewPassword, refusalOf, type AndroidCommandType } from './catalog';
import { AndroidCommandError, cancelAndroidCommand, enqueueAndroidCommands, registerAndroidCommandFinalHook, type FinalTargetEvent } from './bus';
import { RESET_PASSWORD_PURPOSE } from './submit';

export type AndroidGuardedKey =
  | 'mdm.erase_device' | 'mdm.remove_management' | 'mdm.device_lock' | 'mdm.lost_mode_enable'
  | 'mdm.reset_password' | 'mdm.relinquish_ownership' | 'mdm.android_disable';

export const ANDROID_GUARDED_KEYS: readonly AndroidGuardedKey[] = [
  'mdm.erase_device', 'mdm.remove_management', 'mdm.device_lock', 'mdm.lost_mode_enable', 'mdm.reset_password', 'mdm.relinquish_ownership',
  'mdm.android_disable',
];

type Plan = { kind: 'command'; type: AndroidCommandType; profileWipe?: boolean } | { kind: 'state'; enable: boolean };

/** What the execution does for one device of a key, or the refusal of §11.4. */
export function planFor(key: AndroidGuardedKey, ownership: string, params: Record<string, unknown>): Plan | GuardTargetRefusal {
  switch (key) {
    case 'mdm.erase_device':
      return ownership === 'personal' ? { code: 'ownership' } : { kind: 'command', type: 'WIPE' };
    case 'mdm.remove_management':
      if (ownership === 'personal') return { kind: 'command', type: 'WIPE', profileWipe: true };
      if (ownership === 'corporate_personal') return params.mode === 'wipe' ? { kind: 'command', type: 'WIPE' } : { kind: 'command', type: 'RELINQUISH_OWNERSHIP' };
      return { code: 'use_erase', message: 'a corporate device leaves management by an erase' };
    case 'mdm.device_lock': return { kind: 'command', type: 'LOCK' };
    case 'mdm.lost_mode_enable': return ownership === 'personal' ? { code: 'ownership' } : { kind: 'command', type: 'START_LOST_MODE' };
    case 'mdm.reset_password': return ownership === 'personal' ? { code: 'ownership' } : { kind: 'command', type: 'RESET_PASSWORD' };
    case 'mdm.relinquish_ownership': return { kind: 'command', type: 'RELINQUISH_OWNERSHIP' };
    case 'mdm.android_disable': return { kind: 'state', enable: params.enable === true };
    default: return { code: 'unknown_action' };
  }
}

const isRefusal = (p: Plan | GuardTargetRefusal): p is GuardTargetRefusal => 'code' in p;

/** The command parameters of a plan, from the action's (validated) parameters: never newPassword. */
function commandParams(type: AndroidCommandType, params: Record<string, unknown>): Record<string, unknown> {
  if (type === 'WIPE') {
    const out: Record<string, unknown> = {};
    if (Array.isArray(params.wipeDataFlags)) out.wipeDataFlags = params.wipeDataFlags;
    if (typeof params.wipeReason === 'string') out.wipeReason = params.wipeReason;
    return out;
  }
  if (type === 'START_LOST_MODE') {
    const keys = ['message', 'phoneNumber', 'email', 'streetAddress', 'organization'];
    return Object.fromEntries(keys.filter((k) => typeof params[k] === 'string').map((k) => [k, params[k]]));
  }
  if (type === 'RESET_PASSWORD') return Array.isArray(params.flags) ? { flags: params.flags } : {};
  return {};
}

/** The command id of a guarded action for one device (lower case, the uuid column). */
export function guardedAndroidCommandId(actionUuid: string, deviceId: number): string {
  return jobIdFor('mdm.command', `${actionUuid.toLowerCase()}:${deviceId}`).toLowerCase();
}

interface Facts {
  id: number; management_channel: string; enrollment_state: string; ownership: string; management_mode: string;
  api_level: number | null; released_at: Date | null; amapi_name: string | null;
}

async function facts(tenantId: number, deviceIds: number[], q: Knex | Knex.Transaction = db): Promise<Map<number, Facts>> {
  if (!deviceIds.length) return new Map();
  const rows = await q('devices as d')
    .leftJoin('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereIn('d.id', deviceIds)
    .select('d.id', 'd.management_channel', 'd.enrollment_state', 'd.ownership', 'd.management_mode', 'a.api_level', 'a.released_at', 'a.amapi_name') as Facts[];
  return new Map(rows.map((r) => [Number(r.id), r]));
}

// ── Reset password: the secret of the request ─────────────────────────────────

/**
 * At the request of mdm.reset_password, in the transaction of the request (point of junction of the guard route,
 * AN-P): newPassword checked and sealed in the tenant's vault (purpose android.reset_password); the params kept in
 * pending_actions carry {"$secret": "<uuid>"} only.
 */
export async function prepareResetPasswordParams(trx: Knex.Transaction, tenantId: number, raw: unknown, userId: number | null): Promise<Record<string, unknown>> {
  const p = (raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  if (p.flags !== undefined) out.flags = p.flags;
  if (p.newPassword !== undefined) {
    const value = checkNewPassword(p.newPassword);
    out.newPassword = { $secret: await vault.createTenantSecret(tenantId, RESET_PASSWORD_PURPOSE, value, { userId }, { trx }) };
  }
  return out;
}

async function readResetSecret(trx: Knex.Transaction, tenantId: number, params: Record<string, unknown>): Promise<{ ref: string | null; value: string | null; missing: boolean }> {
  const refs = findSecretRefs(params.newPassword);
  if (!refs.length) return { ref: null, value: null, missing: false };
  const ref = refs[0];
  const row = await trx('tenant_secrets').where({ tenant_id: tenantId, id: ref }).first('purpose') as { purpose: string } | undefined;
  if (!row || row.purpose !== RESET_PASSWORD_PURPOSE) return { ref, value: null, missing: true };
  try {
    const buf = await vault.readTenantSecret(tenantId, ref, { trx });
    try { return { ref, value: buf.toString('utf8'), missing: false }; } finally { buf.fill(0); }
  } catch (err) {
    if (err instanceof VaultError) return { ref, value: null, missing: true };
    throw err;
  }
}

// ── The channel ───────────────────────────────────────────────────────────────

const DISABLED_REASON = {
  defaultMessage: 'This device was disabled by your organization.',
  localizedMessages: { fr: 'Cet appareil a été désactivé par votre organisation.' },
};

export const androidGuardedChannel = {
  /** Revalidation of the amapi targets at execution: still a managed Android device of the tenant, allowed by §11.4. */
  async revalidate(key: AndroidGuardedKey, ctx: GuardExecutionContext<Record<string, unknown>>, deviceIds = ctx.deviceIds):
    Promise<Map<number, 'ok' | GuardTargetRefusal>> {
    const rows = await facts(ctx.tenantId, deviceIds);
    const out = new Map<number, 'ok' | GuardTargetRefusal>();
    for (const id of deviceIds) {
      const r = rows.get(id);
      if (!r) { out.set(id, { code: 'not_found' }); continue; }
      if (r.management_channel !== 'amapi') { out.set(id, { code: 'not_amapi' }); continue; }
      const plan = planFor(key, r.ownership, ctx.params ?? {});
      if (isRefusal(plan)) { out.set(id, plan); continue; }
      if (plan.kind === 'state') {
        out.set(id, r.enrollment_state === 'enrolled' && !r.released_at && r.amapi_name ? 'ok' : { code: 'not_enrolled' });
        continue;
      }
      const code = refusalOf(plan.type, {
        managementChannel: r.management_channel, enrollmentState: r.enrollment_state, released: r.released_at !== null || !r.amapi_name,
        ownership: r.ownership, mode: r.management_mode, apiLevel: r.api_level === null ? null : Number(r.api_level),
      }, { profileWipe: plan.profileWipe === true });
      out.set(id, code ? { code } : 'ok');
    }
    return out;
  },

  /** Execution for the amapi targets (idempotent: deterministic command ids). */
  async execute(key: AndroidGuardedKey, ctx: GuardExecutionContext<Record<string, unknown>>, deviceIds: number[], o: { gateway?: AndroidGateway } = {}):
    Promise<Map<number, GuardTargetResult>> {
    const out = new Map<number, GuardTargetResult>();
    if (!deviceIds.length) return out;
    const params = ctx.params ?? {};
    if (key === 'mdm.android_disable') return executeState(ctx, deviceIds, params.enable === true, o.gateway ?? androidGateway());
    const rows = await facts(ctx.tenantId, deviceIds);
    const groups = new Map<string, { type: AndroidCommandType; profileWipe: boolean; ids: number[] }>();
    for (const id of deviceIds) {
      const plan = planFor(key, rows.get(id)?.ownership ?? '', params);
      if (isRefusal(plan) || plan.kind !== 'command') { out.set(id, { status: 'skipped', code: isRefusal(plan) ? plan.code : 'not_queued' }); continue; }
      const k = `${plan.type}:${plan.profileWipe ? 1 : 0}`;
      const g = groups.get(k) ?? { type: plan.type, profileWipe: plan.profileWipe === true, ids: [] };
      g.ids.push(id);
      groups.set(k, g);
    }
    await db.transaction(async (trx) => {
      const secret = key === 'mdm.reset_password' ? await readResetSecret(trx, ctx.tenantId, params) : null;
      for (const g of groups.values()) {
        let ids = g.ids;
        if (secret?.missing) {
          // The secret is gone (an execution already sealed it and destroyed it): only the commands already written
          // are replayed; never a RESET_PASSWORD without its password (it would clear the password).
          const existing = new Set((await trx('android_commands').where({ tenant_id: ctx.tenantId })
            .whereIn('id', ids.map((d) => guardedAndroidCommandId(ctx.actionUuid, d))).pluck('device_id') as number[]).map(Number));
          for (const d of ids) if (!existing.has(d)) out.set(d, { status: 'skipped', code: 'secret_unavailable' });
          ids = ids.filter((d) => existing.has(d));
          if (!ids.length) continue;
        }
        try {
          const r = await enqueueAndroidCommands(trx, {
            tenantId: ctx.tenantId, type: g.type, deviceIds: ids, params: commandParams(g.type, params), origin: 'guard',
            actor: `u:${ctx.requesterId}`, requestedBy: ctx.requesterId, reason: ctx.reason, guardActionUuid: ctx.actionUuid, guardActionKey: key,
            commandIdFor: (d) => guardedAndroidCommandId(ctx.actionUuid, d), idempotencyKey: `guard:${ctx.actionUuid.toLowerCase()}`,
            profileWipe: g.profileWipe, ...(secret?.value ? { newPassword: secret.value } : {}),
          });
          const refused = new Map(r.refused.map((x) => [x.deviceId, x.code]));
          for (const d of ids) out.set(d, r.byDevice.has(d) ? { status: 'queued' } : { status: 'skipped', code: refused.get(d) ?? 'not_queued' });
          if (key === 'mdm.lost_mode_enable' && r.byDevice.size) {
            await trx('devices').where({ tenant_id: ctx.tenantId }).whereIn('id', [...r.byDevice.keys()]).whereNot('ownership', 'personal')
              .update({ lost_mode_state: 'enabling', lost_mode_changed_at: trx.fn.now() });
          }
        } catch (err) {
          if (!(err instanceof AndroidCommandError)) throw err;
          for (const d of ids) out.set(d, { status: 'skipped', code: err.code });
        }
      }
      // The password now lives in secret_enc of the commands only: its vault copy is destroyed.
      if (secret?.ref && !secret.missing) await trx('tenant_secrets').where({ tenant_id: ctx.tenantId, id: secret.ref }).delete();
    });
    return out;
  },

  /** Late cancellation (engine only): the commands of the action not yet acknowledged are withdrawn. */
  async cancelAfterDispatch(_key: AndroidGuardedKey, ctx: GuardExecutionContext<Record<string, unknown>>, o: { gateway?: AndroidGateway } = {}):
    Promise<Map<number, 'cancelled' | 'already_delivered' | 'completed'>> {
    const out = new Map<number, 'cancelled' | 'already_delivered' | 'completed'>();
    const cmds = await db('android_commands').where({ tenant_id: ctx.tenantId, guard_action_uuid: ctx.actionUuid }).select('id', 'device_id') as
      Array<{ id: string; device_id: number }>;
    for (const c of cmds) {
      await cancelAndroidCommand(ctx.tenantId, String(c.id), { actor: `u:${ctx.requesterId}` }, { allowGuarded: true, ...(o.gateway ? { gateway: o.gateway } : {}) });
      const r = await db('android_commands').where({ tenant_id: ctx.tenantId, id: c.id }).first('state') as { state: string };
      if (r.state === 'acknowledged' || r.state === 'error') out.set(Number(c.device_id), 'completed');
      else if (r.state === 'cancelled' || r.state === 'expired' || r.state === 'rejected') out.set(Number(c.device_id), 'cancelled');
      else throw new AndroidCommandError(503, 'androidGoogleUnavailable', 'the cancellation is not confirmed yet: it is retried');
    }
    return out;
  },
};

/** mdm.android_disable: devices.patch state (outside any transaction), then the operator's control recorded. */
async function executeState(ctx: GuardExecutionContext<Record<string, unknown>>, deviceIds: number[], enable: boolean, gw: AndroidGateway):
  Promise<Map<number, GuardTargetResult>> {
  const out = new Map<number, GuardTargetResult>();
  const e = await readEnterprise();
  if (!e || e.state !== 'linked') { for (const d of deviceIds) out.set(d, { status: 'skipped', code: 'androidNotLinked' }); return out; }
  const rows = await facts(ctx.tenantId, deviceIds);
  const message = typeof ctx.params?.message === 'string' ? { defaultMessage: ctx.params.message } : DISABLED_REASON;
  // Review AN-D1: an execution run again (a device of the batch out of reach) never disables twice the devices this
  // action already disabled: each devices.patch DISABLED counts in the last-resort cap, which freezes the tenant (A1).
  const done = enable ? new Set<number>() : new Set((await db('android_device_controls').where({ tenant_id: ctx.tenantId, guard_action_uuid: ctx.actionUuid })
    .whereIn('device_id', deviceIds).pluck('device_id') as number[]).map(Number));
  for (const id of deviceIds) {
    const r = rows.get(id);
    if (done.has(id)) { out.set(id, { status: 'done' }); continue; }
    if (!r?.amapi_name || r.released_at) { out.set(id, { status: 'skipped', code: 'not_enrolled' }); continue; }
    const p = parseOwnedName(e, r.amapi_name);
    if (p.kind !== 'device') { out.set(id, { status: 'skipped', code: 'not_amapi' }); continue; }
    try {
      const d = await gw.patchDevice(e, p.deviceId, enable ? { state: 'ACTIVE' } : { state: 'DISABLED', disabledReason: message });
      await db.transaction(async (trx) => {
        if (enable) await trx('android_device_controls').where({ tenant_id: ctx.tenantId, device_id: id }).delete();
        else {
          await trx('android_device_controls').insert({ tenant_id: ctx.tenantId, device_id: id, disabled_by: ctx.requesterId, guard_action_uuid: ctx.actionUuid })
            .onConflict('device_id').merge(['disabled_at', 'disabled_by', 'guard_action_uuid']);
        }
        await trx('android_devices').where({ tenant_id: ctx.tenantId, device_id: id })
          .update({ state: typeof d?.state === 'string' ? d.state : enable ? 'ACTIVE' : 'DISABLED', updated_at: trx.fn.now() });
        await audit.appendInTx(trx, {
          tenantId: ctx.tenantId, action: enable ? 'android.device_enabled' : 'android.device_disabled',
          target: { type: 'device', id: String(id), device: id }, links: { action: ctx.actionUuid }, details: { channel: 'amapi' },
        }, await audit.fromDbActor({ type: 'user', userId: ctx.requesterId }, ctx.tenantId), { onFailure: 'spool' });
      });
      out.set(id, { status: 'done' });
    } catch (err) {
      if (!(err instanceof AndroidError)) throw err;
      if (err.retryable) throw err;
      out.set(id, { status: 'failed', code: err.kind === 'destructive_cap' ? 'gateway_cap' : err.kind });
    }
  }
  return out;
}

// ── Definitions ───────────────────────────────────────────────────────────────

const UUID_REF = z.object({ $secret: z.string().uuid() }).strict();
const WIPE_FLAG = z.enum(['PRESERVE_RESET_PROTECTION_DATA', 'WIPE_EXTERNAL_STORAGE', 'WIPE_ESIMS']);
export const ANDROID_GUARDED_PARAMS: Record<AndroidGuardedKey, z.ZodTypeAny> = {
  'mdm.erase_device': z.object({ wipeDataFlags: z.array(WIPE_FLAG).max(3).optional(), wipeReason: z.string().trim().min(1).max(200).optional() }).strict(),
  'mdm.remove_management': z.object({ mode: z.literal('wipe').optional() }).strict(),
  'mdm.device_lock': z.object({}).strict(),
  'mdm.lost_mode_enable': z.object({
    message: z.string().trim().min(1).max(200).optional(), phoneNumber: z.string().trim().min(3).max(30).optional(),
    email: z.string().trim().min(3).max(254).optional(), streetAddress: z.string().trim().min(1).max(300).optional(),
    organization: z.string().trim().min(1).max(100).optional(),
  }).strict().refine((p) => p.message !== undefined || p.phoneNumber !== undefined || p.email !== undefined || p.streetAddress !== undefined,
    'a message, a phone number, an e-mail or an address is required'),
  // newPassword: a reference to the tenant's vault ONLY (a clear password in the params is refused).
  'mdm.reset_password': z.object({
    newPassword: UUID_REF.optional(), flags: z.array(z.enum(['REQUIRE_ENTRY', 'DO_NOT_ASK_CREDENTIALS_ON_BOOT', 'LOCK_NOW'])).max(3).optional(),
  }).strict(),
  'mdm.relinquish_ownership': z.object({}).strict(),
  'mdm.android_disable': z.object({ enable: z.boolean().optional(), message: z.string().trim().min(1).max(200).optional() }).strict(),
};

const DAY = 86_400;
const CATEGORY = 'Android';

/** Floors, delays and caps of audit-durci §10.2 (D23) for each key, Android side. */
export const ANDROID_GUARDED_DEFAULTS: Record<AndroidGuardedKey, Omit<GuardedActionDef<Record<string, unknown>>, 'key' | 'paramsSchema' | 'revalidate' | 'execute' | 'cancelAfterDispatch'>> = {
  'mdm.erase_device': { label: 'Erase devices', family: 'device_destruction', singleFloor: 'sensitive', singleStrictStepUp: true, bulkThreshold: 3,
    singleDelaySeconds: 300, bulkDelaySeconds: 900, hourlyCap: true, forbidWholeFleet: true, refuseOwnership: ['personal'], confirmation: 'typed',
    deviceCapability: 'mdm:wipe', category: CATEGORY },
  'mdm.remove_management': { label: 'Remove devices from management', family: 'device_destruction', singleFloor: 'sensitive', singleStrictStepUp: false,
    bulkThreshold: 3, singleDelaySeconds: 0, bulkDelaySeconds: 900, hourlyCap: true, forbidWholeFleet: true, refuseOwnership: [], confirmation: 'typed',
    deviceCapability: 'mdm:remove', category: CATEGORY },
  'mdm.device_lock': { label: 'Lock devices', family: 'device_control', singleFloor: 'sensitive', singleStrictStepUp: false, bulkThreshold: 3,
    singleDelaySeconds: 0, bulkDelaySeconds: 0, hourlyCap: false, forbidWholeFleet: true, refuseOwnership: [], confirmation: 'none',
    deviceCapability: 'mdm:lock', category: CATEGORY },
  'mdm.lost_mode_enable': { label: 'Enable the lost mode', family: 'device_privacy', singleFloor: 'sensitive', singleStrictStepUp: false, bulkThreshold: 3,
    singleDelaySeconds: 0, bulkDelaySeconds: 0, hourlyCap: false, forbidWholeFleet: true, refuseOwnership: ['personal'], confirmation: 'none',
    deviceCapability: 'mdm:lost_mode', category: CATEGORY },
  'mdm.reset_password': { label: 'Reset the password of Android devices', family: 'device_control', singleFloor: 'sensitive', singleStrictStepUp: true,
    bulkThreshold: 3, singleDelaySeconds: 0, bulkDelaySeconds: 0, hourlyCap: false, forbidWholeFleet: true, refuseOwnership: ['personal'],
    confirmation: 'none', deviceCapability: 'mdm:passcode', category: CATEGORY },
  'mdm.relinquish_ownership': { label: 'Relinquish the ownership of Android devices', family: 'device_destruction', singleFloor: 'sensitive',
    singleStrictStepUp: false, bulkThreshold: 3, singleDelaySeconds: 0, bulkDelaySeconds: 900, hourlyCap: true, forbidWholeFleet: true,
    refuseOwnership: ['personal', 'corporate'], confirmation: 'typed', deviceCapability: 'mdm:remove', category: CATEGORY },
  // SEC-AN-15: from 3 devices, the bulk threshold applies.
  'mdm.android_disable': { label: 'Disable or enable Android devices', family: 'device_control', singleFloor: 'sensitive', singleStrictStepUp: false,
    bulkThreshold: 3, singleDelaySeconds: 0, bulkDelaySeconds: 0, hourlyCap: false, forbidWholeFleet: true, refuseOwnership: [], confirmation: 'none',
    deviceCapability: 'mdm:lock', category: CATEGORY },
};

const WINDOW: Partial<Record<AndroidGuardedKey, number>> = {
  'mdm.erase_device': 7 * DAY, 'mdm.remove_management': 7 * DAY, 'mdm.device_lock': DAY, 'mdm.lost_mode_enable': DAY,
  'mdm.reset_password': DAY, 'mdm.relinquish_ownership': 7 * DAY,
};

/** The Android-only definition of a key (channel amapi only). */
export function defineAndroidGuardedAction(key: AndroidGuardedKey, o: { gateway?: () => AndroidGateway } = {}): GuardedActionDef<Record<string, unknown>> {
  const gw = () => (o.gateway ? o.gateway() : androidGateway());
  const def: GuardedActionDef<Record<string, unknown>> = {
    key, ...ANDROID_GUARDED_DEFAULTS[key], paramsSchema: ANDROID_GUARDED_PARAMS[key] as z.ZodType<Record<string, unknown>>,
    // A key of the channel amapi only: refused at the request on another channel's device, whole fleet and hourly cap
    // also on the channel's fleet (decisions of the owners of 20/10/2026, PONT-R-RV3 and RV4).
    channels: ['amapi'],
    revalidate: (ctx) => androidGuardedChannel.revalidate(key, ctx),
    execute: (ctx, ids) => androidGuardedChannel.execute(key, ctx, ids, { gateway: gw() }),
  };
  if (key !== 'mdm.android_disable') {
    def.cancelAfterDispatch = (ctx) => androidGuardedChannel.cancelAfterDispatch(key, ctx, { gateway: gw() });
    def.cancelWindowSeconds = WINDOW[key] ?? ANDROID_COMMANDS.WIPE.durationSeconds;
  }
  if (key === 'mdm.reset_password') {
    // The request may type the new password (checked, then sealed in the tenant's vault in its transaction: the
    // stored and journaled parameters carry its reference only); a reference stays accepted as it is.
    def.requestParamsSchema = RESET_PASSWORD_REQUEST;
    def.prepareParams = async (trx, tenantId, params, userId) => {
      // A reference already sealed goes as it is (its purpose and its tenant are checked by the execution).
      if (params.newPassword !== undefined && typeof params.newPassword !== 'string') return params;
      try {
        return await prepareResetPasswordParams(trx, tenantId, params, userId);
      } catch (err) {
        if (err instanceof AndroidCommandParamError) throw new AppError(400, 'Invalid parameters for this action', 'invalidParams', { reason: err.code });
        throw err;
      }
    };
  }
  return def;
}

const RESET_PASSWORD_REQUEST = z.object({
  newPassword: z.union([z.string().max(4096), UUID_REF]).optional(),
  flags: z.array(z.enum(['REQUIRE_ENTRY', 'DO_NOT_ASK_CREDENTIALS_ON_BOOT', 'LOCK_NOW'])).max(3).optional(),
}).strict();

/** The four keys Apple and Android share (§11.4): the actions of the Apple module take the channel amapi. */
export const SHARED_GUARDED_KEYS: ReadonlySet<string> = new Set(['mdm.erase_device', 'mdm.remove_management', 'mdm.device_lock', 'mdm.lost_mode_enable']);

/**
 * The channel amapi of a key shared with Apple (§11.4; lot AN-P, guard/channels.ts): its parameters, its revalidation
 * and its execution for the amapi targets of the action (the Apple targets stay with the Apple definition). Its late
 * cancellation only when the action dispatched Android commands.
 */
export function amapiGuardedChannel(key: AndroidGuardedKey, o: { gateway?: () => AndroidGateway } = {}): GuardedChannelImpl {
  const gw = () => (o.gateway ? o.gateway() : androidGateway());
  return {
    channel: 'amapi',
    paramsSchema: ANDROID_GUARDED_PARAMS[key],
    revalidate: (ctx, ids) => androidGuardedChannel.revalidate(key, ctx, ids),
    execute: (ctx, ids) => androidGuardedChannel.execute(key, ctx, ids, { gateway: gw() }),
    async cancelAfterDispatch(ctx) {
      const mine = await db('android_commands').where({ tenant_id: ctx.tenantId, guard_action_uuid: ctx.actionUuid }).first('id');
      return mine ? androidGuardedChannel.cancelAfterDispatch(key, ctx, { gateway: gw() }) : new Map();
    },
  };
}

/**
 * The lost mode of a device follows its commands (section 11.2): START_LOST_MODE acknowledged → on, otherwise back to
 * off from enabling; STOP_LOST_MODE acknowledged → off, otherwise back to on from disabling.
 */
export async function lostModeFinalHook(e: FinalTargetEvent): Promise<void> {
  if (e.requestType !== 'START_LOST_MODE' && e.requestType !== 'STOP_LOST_MODE') return;
  const start = e.requestType === 'START_LOST_MODE';
  const ok = e.state === 'acknowledged';
  const from = start ? 'enabling' : 'disabling';
  const to = ok ? (start ? 'on' : 'off') : (start ? 'off' : 'on');
  await e.trx('devices').where({ tenant_id: e.tenantId, id: e.deviceId, lost_mode_state: from }).whereNot('ownership', 'personal')
    .update({ lost_mode_state: to, lost_mode_changed_at: e.trx.fn.now() });
}

let registered = false;

/** The guarded actions that exist only for Android (new restriction keys), and the channel amapi of the four keys shared
 *  with Apple (§11.4, lot AN-P): registered by registerAndroidModule. */
export function registerAndroidGuardedActions(): void {
  if (registered) return;
  registered = true;
  registerAndroidCommandFinalHook(lostModeFinalHook);
  for (const key of ['mdm.reset_password', 'mdm.relinquish_ownership', 'mdm.android_disable'] as const) registerGuardedAction(defineAndroidGuardedAction(key));
  for (const key of SHARED_GUARDED_KEYS) registerGuardedActionChannel(key, amapiGuardedChannel(key as AndroidGuardedKey));
}
