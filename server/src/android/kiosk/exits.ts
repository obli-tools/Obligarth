// Kiosk exits of dedicated devices (android-amapi §9.7; lot AN-G1). The exit of a kiosk lifts its lock for a while:
// the person at the device reaches the Settings app, the other apps and the system bars, as with the « exit kiosk »
// of other EMMs; AMAPI has no exit code typed on the device, so Obligarth pushes the device's own policy without its
// lock (compile.ts, kiosk.ts: stripKioskLock), then pushes it back with the lock at the end.
//   - Start: guarded action mdm.android_kiosk_exit (new restriction key, floor sensitive, bulk from 3 devices, never
//     the whole fleet, refused under a freeze by the engine): per device, still a managed dedicated device of the
//     tenant, approved; one running exit per device; 5 minutes to 8 hours (a CHECK of the base as the last barrier);
//     audited android.kiosk_exit_started (critical); the push of the device and the end job are sent in the
//     transaction. Idempotent: a run of the execution again finds its rows (one per action and device).
//   - End: by the operator (endKioskExit, route DELETE /devices/:id/kiosk-exit, audited android.kiosk_exit_ended), at
//     expires_at by the job android.kiosk-exit-end, or by android.maintenance (android_kiosk_due) when the job is lost
//     or the device left management. The compilation reads an exit as running only while ended_at is null AND
//     expires_at is in the future: a push after the end restores the lock even when nothing ended the row.
// Review AN-G1 (G1-R1): under a freeze the gateway refuses any policies.patch that carries a wipe-capable setting
// (AN15), the policy that locks a kiosk again included. Hence:
//   - an exit is refused at its start when the device's policy carries such a setting (kiosk_wipe_policy; policy_error
//     when it does not compile), and the compiler never lifts the lock of such a policy: an exit whose policy comes
//     to carry one ends (wipe_policy) and the lock is pushed;
//   - a freeze ends the running exits of the tenant (frozen; the safest state first): android.maintenance does it
//     within the minute (android_kiosk_due), and endKioskExitsOnFreeze is the Android handler of the freeze list of
//     actions.freeze-sync at the junction AN-P;
//   - the end of an exit is not the return of the lock: lock_restored_at (audit android.kiosk_lock_restored) is set
//     when Google accepted the policy that holds the lock again (push.ts); until then readKioskState says the lock
//     pending, and android.maintenance sends the push again every 15 minutes.
// Second review AN-G1 (G1-S1, G1-S2): the return of the lock is never blocked by a freeze. A wipe-capable setting can
// still reach the policy of a kiosk whose lock is pending (a publication or an assignment, neither looks at the
// freeze; or a push still queued when the freeze came): under a freeze, push.ts then pushes the locked policy without
// its wipe-capable paths, which passes the freeze lock of AN15 without easing it (kioskLockPendingUnderFreeze is the
// only gate of that degraded rendering); markKioskLockRestored records it (wipe_withheld_at, audit
// android.kiosk_wipe_settings_withheld, critical, the paths only), readKioskState says wipeSettingsWithheld, and
// after the unfreeze android.maintenance sends the push of the full policy again every 15 minutes until Google
// accepts it (markKioskWipeSettingsApplied, audit android.kiosk_wipe_settings_applied).
import type { Knex } from 'knex';
import { z } from 'zod';
import {
  ANDROID_KIOSK_EXIT_ACTION, ANDROID_KIOSK_EXIT_MINUTES, type AndroidKioskExitEndReason, type AndroidKioskExitView, type AndroidKioskState,
} from '@obligarth/shared';
import { randomUUID } from 'node:crypto';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { registerGuardedAction, type GuardedActionDef, type GuardExecutionContext, type GuardTargetRefusal, type GuardTargetResult } from '../../guard';
import { readSettings } from '../../guard/settings';
import { androidSenders } from '../enrollment/senders';
import { kioskExitPolicyRefusal } from '../policies/push';

export const KIOSK_EXIT_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.kiosk-exit-end' }) as DbActor;

export class KioskExitError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message = code) {
    super(message);
    this.name = 'KioskExitError';
    this.status = status;
    this.code = code;
  }
}

/** The end job of an exit, at its expiry (bound to the durable job by jobs.ts; the tests record it). */
export type KioskExitEndSender = (trx: Knex.Transaction, p: { tenantId: number; exitId: string; expiresAt: Date }) => Promise<unknown>;
let endSender: KioskExitEndSender = async () => undefined;
export function setKioskExitEndSender(fn: KioskExitEndSender): void { endSender = fn; }

interface Facts {
  id: number; management_channel: string; enrollment_state: string; ownership: string; management_mode: string; usage: string;
  approval_state: string | null; released_at: Date | null; amapi_name: string | null;
}

async function facts(q: Knex | Knex.Transaction, tenantId: number, deviceIds: number[]): Promise<Map<number, Facts>> {
  if (!deviceIds.length) return new Map();
  const rows = await q('devices as d')
    .leftJoin('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereIn('d.id', deviceIds)
    .select('d.id', 'd.management_channel', 'd.enrollment_state', 'd.ownership', 'd.management_mode', 'd.usage', 'a.approval_state',
      'a.released_at', 'a.amapi_name') as Facts[];
  return new Map(rows.map((r) => [Number(r.id), r]));
}

/** Why a device cannot leave its kiosk (null: it can). */
export function kioskExitRefusal(r: Facts | undefined): GuardTargetRefusal | null {
  if (!r) return { code: 'not_found' };
  if (r.management_channel !== 'amapi') return { code: 'not_amapi' };
  if (r.enrollment_state !== 'enrolled' || r.released_at || !r.amapi_name) return { code: 'not_enrolled' };
  if (r.usage !== 'kiosk' || r.management_mode !== 'dedicated' || r.ownership !== 'corporate') return { code: 'not_kiosk' };
  if (r.approval_state === 'pending' || r.approval_state === 'rejected') return { code: 'pending_approval' };
  return null;
}

const minutesOf = (params: Record<string, unknown> | undefined): number => {
  const m = params?.durationMinutes;
  return typeof m === 'number' && Number.isInteger(m) ? m : ANDROID_KIOSK_EXIT_MINUTES.dflt;
};

/** Execution of mdm.android_kiosk_exit for the targets left (idempotent: one row per action and device). */
export async function startKioskExits(ctx: GuardExecutionContext<Record<string, unknown>>, deviceIds: number[]): Promise<Map<number, GuardTargetResult>> {
  const out = new Map<number, GuardTargetResult>();
  if (!deviceIds.length) return out;
  const minutes = minutesOf(ctx.params);
  if (minutes < ANDROID_KIOSK_EXIT_MINUTES.min || minutes > ANDROID_KIOSK_EXIT_MINUTES.max) {
    for (const d of deviceIds) out.set(d, { status: 'skipped', code: 'invalid_duration' });
    return out;
  }
  const auditCtx = await audit.fromDbActor({ type: 'user', userId: ctx.requesterId }, ctx.tenantId);
  for (const deviceId of deviceIds) {
    const r = await db.transaction(async (trx) => {
      // Serialises with an end and another start on the same device.
      const dev = await trx('devices').where({ tenant_id: ctx.tenantId, id: deviceId }).forUpdate().first('id');
      if (!dev) return { status: 'skipped' as const, code: 'not_found' };
      const mine = await trx('android_kiosk_exits').where({ tenant_id: ctx.tenantId, guard_action_uuid: ctx.actionUuid, device_id: deviceId }).first('id');
      if (mine) return { status: 'done' as const };
      const refusal = kioskExitRefusal((await facts(trx, ctx.tenantId, [deviceId])).get(deviceId));
      if (refusal) return { status: 'skipped' as const, code: refusal.code };
      const open = await trx('android_kiosk_exits').where({ tenant_id: ctx.tenantId, device_id: deviceId }).whereNull('ended_at')
        .where('expires_at', '>', trx.fn.now()).first('id');
      if (open) return { status: 'skipped' as const, code: 'kiosk_exit_running' };
      // G1-R1: never an exit on a policy with a wipe-capable setting (it could not be locked again under a freeze).
      const policyRefusal = await kioskExitPolicyRefusal(trx, ctx.tenantId, deviceId);
      if (policyRefusal) return { status: 'skipped' as const, code: policyRefusal };
      // A running row past its end (the end job not run yet) is closed before the new one.
      const stale = await trx('android_kiosk_exits').where({ tenant_id: ctx.tenantId, device_id: deviceId }).whereNull('ended_at')
        .select('id', 'device_id') as Array<{ id: string; device_id: number }>;
      if (stale.length) await closeExits(trx, ctx.tenantId, stale, 'expired', auditCtx, null, false);
      const id = randomUUID();
      const [row] = await trx('android_kiosk_exits').insert({
        id, tenant_id: ctx.tenantId, device_id: deviceId, guard_action_uuid: ctx.actionUuid, requested_by: ctx.requesterId,
        started_at: trx.fn.now(), expires_at: trx.raw('now() + make_interval(mins => ?)', [minutes]),
      }).returning(['expires_at']) as Array<{ expires_at: Date }>;
      await audit.appendInTx(trx, {
        tenantId: ctx.tenantId, action: 'android.kiosk_exit_started', target: { type: 'device', id: String(deviceId), device: deviceId },
        links: { action: ctx.actionUuid }, details: { exitId: id, durationMinutes: minutes, channel: 'amapi' },
      }, auditCtx, { onFailure: 'spool' });
      await androidSenders.push(trx, { tenantId: ctx.tenantId, deviceId });
      await endSender(trx, { tenantId: ctx.tenantId, exitId: id, expiresAt: new Date(row.expires_at) });
      return { status: 'done' as const };
    });
    out.set(deviceId, r);
  }
  return out;
}

async function closeExits(trx: Knex.Transaction, tenantId: number, rows: Array<{ id: string; device_id: number }>, reason: AndroidKioskExitEndReason,
  auditCtx: AuditWriteContext, endedBy: number | null, push = true): Promise<number[]> {
  const devices: number[] = [];
  for (const k of rows) {
    const n = await trx('android_kiosk_exits').where({ tenant_id: tenantId, id: k.id }).whereNull('ended_at')
      .update({ ended_at: trx.fn.now(), end_reason: reason, ended_by: endedBy, lock_retry_at: reason === 'device_left' ? null : trx.raw("now() + interval '15 minutes'") });
    if (!n) continue;
    devices.push(Number(k.device_id));
    await audit.appendInTx(trx, {
      tenantId, action: 'android.kiosk_exit_ended', target: { type: 'device', id: String(k.device_id), device: Number(k.device_id) },
      details: { exitId: k.id, reason, channel: 'amapi' },
    }, auditCtx, { onFailure: 'spool' });
    // The lock comes back with the next push (a device that left management receives nothing); it is said restored
    // only when Google accepts it (markKioskLockRestored).
    if (push && reason !== 'device_left') await androidSenders.push(trx, { tenantId, deviceId: Number(k.device_id) });
  }
  return devices;
}

/** Ends the running exit of a device now (the operator; capability of the route). 404 when none runs. */
export async function endKioskExit(tenantId: number, userId: number, deviceId: number, auditCtx: AuditWriteContext): Promise<'ended'> {
  return asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
    const rows = await trx('android_kiosk_exits').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('ended_at').forUpdate()
      .select('id', 'device_id') as Array<{ id: string; device_id: number }>;
    if (!rows.length) throw new KioskExitError(404, 'androidKioskExitNotFound');
    await closeExits(trx, tenantId, rows, 'operator', auditCtx, userId);
    return 'ended' as const;
  }));
}

/** Ends the exits of a tenant past their end, those of devices that left management and, the tenant frozen, all its
 *  running exits; sends the push of the locks still pending (job and maintenance). */
export async function expireKioskExits(tenantId: number, actor: DbActor = KIOSK_EXIT_ACTOR):
  Promise<{ expired: number; left: number; frozen: number; lockRetried: number; wipeRetried: number }> {
  return asTenant(tenantId, actor, () => db.transaction(async (trx) => {
    const ctx = audit.fromJob({ name: 'android.kiosk-exit-end', requestId: `android-kiosk-${tenantId}-${Date.now()}` });
    const due = await trx('android_kiosk_exits as k')
      .leftJoin('android_devices as a', function j() { this.on('a.device_id', '=', 'k.device_id').andOn('a.tenant_id', '=', 'k.tenant_id'); })
      .where('k.tenant_id', tenantId).whereNull('k.ended_at')
      .where((q) => q.where('k.expires_at', '<=', trx.fn.now()).orWhereNull('a.device_id').orWhereNotNull('a.released_at'))
      .forUpdate('k')
      .select('k.id', 'k.device_id', 'k.expires_at', 'a.device_id as sat', 'a.released_at') as
      Array<{ id: string; device_id: number; expires_at: Date; sat: number | null; released_at: Date | null }>;
    const left = due.filter((k) => k.sat === null || k.released_at !== null);
    const expired = due.filter((k) => !left.includes(k));
    await closeExits(trx, tenantId, left, 'device_left', ctx, null);
    await closeExits(trx, tenantId, expired, 'expired', ctx, null);
    // A frozen tenant: its running exits end now (the safest state first; the junction AN-P also calls
    // endKioskExitsOnFreeze from the freeze list).
    let frozen = 0;
    if ((await readSettings(tenantId, trx)).frozen_at) frozen = await closeRunning(trx, tenantId, 'frozen', ctx);
    // Locks still pending past their retry time: the push again (a device with a new running exit waits for it).
    const pending = await trx('android_kiosk_exits as k')
      .join('android_devices as a', function j() { this.on('a.device_id', '=', 'k.device_id').andOn('a.tenant_id', '=', 'k.tenant_id'); })
      .where('k.tenant_id', tenantId).whereNotNull('k.ended_at').whereNull('k.lock_restored_at').whereNot('k.end_reason', 'device_left')
      .whereNull('a.released_at')
      .whereRaw("COALESCE(k.lock_retry_at, k.ended_at + interval '10 minutes') <= now()")
      .forUpdate('k').select('k.id', 'k.device_id') as Array<{ id: string; device_id: number }>;
    const devices = new Set<number>();
    for (const p of pending) {
      await trx('android_kiosk_exits').where({ tenant_id: tenantId, id: p.id }).update({ lock_retry_at: trx.raw("now() + interval '15 minutes'") });
      devices.add(Number(p.device_id));
    }
    // G1-S1: locks restored under a freeze without their wipe-capable settings, the tenant no longer frozen: the push
    // of the full policy again (every 15 minutes until Google accepts it).
    let wipeRetried = 0;
    if (!(await readSettings(tenantId, trx)).frozen_at) {
      const withheld = await trx('android_kiosk_exits as k')
        .join('android_devices as a', function j() { this.on('a.device_id', '=', 'k.device_id').andOn('a.tenant_id', '=', 'k.tenant_id'); })
        .where('k.tenant_id', tenantId).whereNotNull('k.wipe_withheld_at').whereNull('a.released_at')
        .whereRaw('COALESCE(k.lock_retry_at, k.wipe_withheld_at) <= now()')
        .forUpdate('k').select('k.id', 'k.device_id') as Array<{ id: string; device_id: number }>;
      for (const w of withheld) {
        await trx('android_kiosk_exits').where({ tenant_id: tenantId, id: w.id }).update({ lock_retry_at: trx.raw("now() + interval '15 minutes'") });
        if (!devices.has(Number(w.device_id))) { devices.add(Number(w.device_id)); wipeRetried += 1; }
      }
    }
    for (const d of devices) {
      if (!(await runningKioskExit(trx, tenantId, d))) await androidSenders.push(trx, { tenantId, deviceId: d });
    }
    return { expired: expired.length, left: left.length, frozen, lockRetried: devices.size - wipeRetried, wipeRetried };
  }));
}

async function closeRunning(trx: Knex.Transaction, tenantId: number, reason: 'frozen', auditCtx: AuditWriteContext): Promise<number> {
  const rows = await trx('android_kiosk_exits').where({ tenant_id: tenantId }).whereNull('ended_at').forUpdate()
    .select('id', 'device_id') as Array<{ id: string; device_id: number }>;
  return (await closeExits(trx, tenantId, rows, reason, auditCtx, null)).length;
}

/**
 * A freeze of the tenant ends its running kiosk exits (the safest state first; review AN-G1). The Android handler of
 * the freeze list of actions.freeze-sync at the junction AN-P (registerEdgeFreezeHandler becomes a list there; same
 * signature as EdgeFreezeHandler, tenant and frozen); until then android.maintenance does it within the minute.
 * Nothing on an unfreeze.
 */
export async function endKioskExitsOnFreeze(tenantId: number, frozen: boolean, actor: DbActor = KIOSK_EXIT_ACTOR): Promise<number> {
  if (!frozen) return 0;
  return asTenant(tenantId, actor, () => db.transaction(async (trx) => {
    if (!(await readSettings(tenantId, trx)).frozen_at) return 0;
    const ctx = audit.fromJob({ name: 'android.kiosk-exit-end', requestId: 'android-kiosk-freeze-' + tenantId + '-' + Date.now() });
    return closeRunning(trx, tenantId, 'frozen', ctx);
  }));
}

/**
 * The running exit of a device ends because its policy came to carry a wipe-capable setting (push.ts: the compiler
 * kept the lock; G1-R1). Tenant context of the caller; the caller pushes the lock itself.
 */
export async function endKioskExitForWipePolicy(tenantId: number, deviceId: number): Promise<number> {
  return db.transaction(async (trx) => {
    await trx('devices').where({ tenant_id: tenantId, id: deviceId }).forUpdate().first('id');
    const rows = await trx('android_kiosk_exits').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('ended_at').forUpdate()
      .select('id', 'device_id') as Array<{ id: string; device_id: number }>;
    if (!rows.length) return 0;
    const ctx = audit.fromJob({ name: 'android.policies.push-device', requestId: 'android-kiosk-wipe-' + tenantId + '-' + deviceId + '-' + Date.now() });
    return (await closeExits(trx, tenantId, rows, 'wipe_policy', ctx, null, false)).length;
  });
}

/**
 * Is the kiosk lock of a device pending under a freeze of its tenant (second review AN-G1, G1-S1)? The tenant frozen
 * (read now, in a short transaction of its own, as the gateway does), an ended exit of the device whose lock Google has
 * not accepted yet, and no running exit. The only gate of the degraded rendering of push.ts (the locked policy
 * without its wipe-capable paths). Tenant context of the caller.
 */
export async function kioskLockPendingUnderFreeze(tenantId: number, deviceId: number): Promise<boolean> {
  return db.transaction(async (trx) => {
    if (!(await readSettings(tenantId, trx)).frozen_at) return false;
    const pending = await trx('android_kiosk_exits').where({ tenant_id: tenantId, device_id: deviceId }).whereNotNull('ended_at')
      .whereNull('lock_restored_at').whereNot('end_reason', 'device_left').first('id');
    if (!pending) return false;
    return !(await runningKioskExit(trx, tenantId, deviceId));
  });
}

/**
 * Google accepted (or already holds) the device's policy with its kiosk lock: the ended exits whose lock was pending
 * are restored (lock_restored_at, audit android.kiosk_lock_restored). `wipeWithheld`: the paths of the wipe-capable
 * settings left out of that policy under a freeze (G1-S1): wipe_withheld_at is set (the full policy is pushed again
 * after the unfreeze) and audited android.kiosk_wipe_settings_withheld (the paths, never their values). Tenant context
 * of the caller (push.ts).
 */
export async function markKioskLockRestored(tenantId: number, deviceId: number, o: { wipeWithheld?: readonly string[] } = {}): Promise<number> {
  const withheld = o.wipeWithheld && o.wipeWithheld.length ? [...o.wipeWithheld] : null;
  return db.transaction(async (trx) => {
    const rows = await trx('android_kiosk_exits').where({ tenant_id: tenantId, device_id: deviceId }).whereNotNull('ended_at')
      .whereNull('lock_restored_at').whereNot('end_reason', 'device_left').forUpdate()
      .select('id', 'end_reason') as Array<{ id: string; end_reason: string }>;
    if (!rows.length) return 0;
    // A running exit (started after the read of the push) keeps the older rows pending: the lock is not held now.
    if (await runningKioskExit(trx, tenantId, deviceId)) return 0;
    const ctx = audit.fromJob({ name: 'android.policies.push-device', requestId: 'android-kiosk-lock-' + tenantId + '-' + deviceId + '-' + Date.now() });
    for (const r of rows) {
      await trx('android_kiosk_exits').where({ tenant_id: tenantId, id: r.id }).update({
        lock_restored_at: trx.fn.now(), lock_retry_at: withheld ? trx.fn.now() : null, ...(withheld ? { wipe_withheld_at: trx.fn.now() } : {}),
      });
      await audit.appendInTx(trx, {
        tenantId, action: 'android.kiosk_lock_restored', target: { type: 'device', id: String(deviceId), device: deviceId },
        details: { exitId: r.id, reason: r.end_reason, channel: 'amapi', ...(withheld ? { wipeSettingsWithheld: true } : {}) },
      }, ctx, { onFailure: 'spool' });
      if (withheld) {
        await audit.appendInTx(trx, {
          tenantId, action: 'android.kiosk_wipe_settings_withheld', target: { type: 'device', id: String(deviceId), device: deviceId },
          details: { exitId: r.id, reason: r.end_reason, paths: withheld, channel: 'amapi' },
        }, ctx, { onFailure: 'spool' });
      }
    }
    return rows.length;
  });
}

/**
 * Google accepted (or already holds) the device's full policy, rendered without any degradation: the wipe-capable
 * settings withheld under a freeze are applied (wipe_withheld_at back to null, audit
 * android.kiosk_wipe_settings_applied). Tenant context of the caller (push.ts).
 */
export async function markKioskWipeSettingsApplied(tenantId: number, deviceId: number): Promise<number> {
  return db.transaction(async (trx) => {
    const rows = await trx('android_kiosk_exits').where({ tenant_id: tenantId, device_id: deviceId }).whereNotNull('wipe_withheld_at').forUpdate()
      .select('id') as Array<{ id: string }>;
    if (!rows.length) return 0;
    const ctx = audit.fromJob({ name: 'android.policies.push-device', requestId: 'android-kiosk-wipe-applied-' + tenantId + '-' + deviceId + '-' + Date.now() });
    for (const r of rows) {
      await trx('android_kiosk_exits').where({ tenant_id: tenantId, id: r.id }).update({ wipe_withheld_at: null, lock_retry_at: null });
      await audit.appendInTx(trx, {
        tenantId, action: 'android.kiosk_wipe_settings_applied', target: { type: 'device', id: String(deviceId), device: deviceId },
        details: { exitId: r.id, channel: 'amapi' },
      }, ctx, { onFailure: 'spool' });
    }
    return rows.length;
  });
}

/** The running exit of a device for the compilation (null: none, or past its end). */
export async function runningKioskExit(q: Knex | Knex.Transaction, tenantId: number, deviceId: number): Promise<{ id: string; expires_at: Date } | null> {
  const row = await q('android_kiosk_exits').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('ended_at')
    .where('expires_at', '>', q.fn.now()).first('id', 'expires_at') as { id: string; expires_at: Date } | undefined;
  return row ?? null;
}

const view = (r: Record<string, unknown>): AndroidKioskExitView => ({
  id: String(r.id), deviceId: Number(r.device_id), actionUuid: String(r.guard_action_uuid),
  requestedBy: r.requested_by === null || r.requested_by === undefined ? null : Number(r.requested_by),
  startedAt: new Date(r.started_at as string).toISOString(), expiresAt: new Date(r.expires_at as string).toISOString(),
  endedAt: r.ended_at ? new Date(r.ended_at as string).toISOString() : null, endReason: (r.end_reason as AndroidKioskExitEndReason | null) ?? null,
  lockRestoredAt: r.lock_restored_at ? new Date(r.lock_restored_at as string).toISOString() : null,
  wipeWithheldAt: r.wipe_withheld_at ? new Date(r.wipe_withheld_at as string).toISOString() : null,
});
const VIEW_COLUMNS = ['id', 'device_id', 'guard_action_uuid', 'requested_by', 'started_at', 'expires_at', 'ended_at', 'end_reason', 'lock_restored_at',
  'wipe_withheld_at'];

/** The kiosk state of a device of the tenant (route GET /devices/:id/kiosk); null when the device is unknown. */
export async function readKioskState(tenantId: number, userId: number, deviceId: number): Promise<AndroidKioskState | null> {
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    const r = (await facts(db, tenantId, [deviceId])).get(deviceId);
    if (!r || r.management_channel !== 'amapi') return null;
    const exit = await db('android_kiosk_exits').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('ended_at')
      .where('expires_at', '>', db.fn.now()).first(VIEW_COLUMNS);
    // G1-R1: an exit ended (or past its end) whose lock Google has not accepted yet: the lock is pending.
    const pending = exit ? undefined : await db('android_kiosk_exits').where({ tenant_id: tenantId, device_id: deviceId })
      .whereNull('lock_restored_at').where((q) => q.where((w) => w.whereNotNull('ended_at').whereNot('end_reason', 'device_left'))
        .orWhere((w) => w.whereNull('ended_at').where('expires_at', '<=', db.fn.now())))
      .orderBy('started_at', 'desc').first(VIEW_COLUMNS);
    const managed = r.enrollment_state === 'enrolled' && !r.released_at;
    // G1-S1: the lock back under a freeze without the policy's wipe-capable settings (withheld until the unfreeze).
    const withheld = managed
      ? await db('android_kiosk_exits').where({ tenant_id: tenantId, device_id: deviceId }).whereNotNull('wipe_withheld_at').first('id') : undefined;
    return {
      deviceId, dedicated: r.usage === 'kiosk' && r.management_mode === 'dedicated', exit: exit ? view(exit) : null,
      lockPending: !!pending && managed, lockPendingExit: pending && managed ? view(pending) : null, wipeSettingsWithheld: !!withheld,
    };
  });
}

// ── The guarded action ────────────────────────────────────────────────────────

export const KIOSK_EXIT_PARAMS = z.object({
  durationMinutes: z.number().int().min(ANDROID_KIOSK_EXIT_MINUTES.min).max(ANDROID_KIOSK_EXIT_MINUTES.max).optional(),
}).strict();

/** mdm.android_kiosk_exit: floor sensitive, bulk from 3 devices, never the whole fleet, corporate devices only. */
export function defineKioskExitAction(): GuardedActionDef<Record<string, unknown>> {
  return {
    key: ANDROID_KIOSK_EXIT_ACTION, label: 'Let Android kiosks leave their lock for a while', family: 'device_control',
    singleFloor: 'sensitive', singleStrictStepUp: false, bulkThreshold: 3, singleDelaySeconds: 0, bulkDelaySeconds: 0, hourlyCap: false,
    forbidWholeFleet: true, refuseOwnership: ['personal', 'corporate_personal'], confirmation: 'none', deviceCapability: 'mdm:lock',
    category: 'Android', paramsSchema: KIOSK_EXIT_PARAMS as z.ZodType<Record<string, unknown>>,
    // The channel amapi only (PONT-R-RV3, RV4): another channel's device refused at the request; whole fleet of the channel.
    channels: ['amapi'],
    async revalidate(ctx) {
      const rows = await facts(db, ctx.tenantId, ctx.deviceIds);
      const out = new Map<number, 'ok' | GuardTargetRefusal>();
      for (const id of ctx.deviceIds) out.set(id, kioskExitRefusal(rows.get(id)) ?? 'ok');
      // G1-R1: refused at the request already when the device's policy carries a wipe-capable setting.
      const candidates = ctx.deviceIds.filter((id) => out.get(id) === 'ok');
      if (candidates.length) {
        await db.transaction(async (trx) => {
          for (const id of candidates) {
            const code = await kioskExitPolicyRefusal(trx, ctx.tenantId, id);
            if (code) out.set(id, { code });
          }
        });
      }
      return out;
    },
    execute: (ctx, ids) => startKioskExits(ctx, ids),
  };
}

let registered = false;

/** The guarded action of the kiosk exit (registered by registerAndroidModule). */
export function registerAndroidKioskActions(): void {
  if (registered) return;
  registered = true;
  registerGuardedAction(defineKioskExitAction());
}
