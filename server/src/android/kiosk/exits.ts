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
import type { Knex } from 'knex';
import { z } from 'zod';
import {
  ANDROID_KIOSK_EXIT_ACTION, ANDROID_KIOSK_EXIT_MINUTES, type AndroidKioskExitEndReason, type AndroidKioskExitView, type AndroidKioskState,
} from '@obligarth/shared/dist/android/kiosk.js';
import { randomUUID } from 'node:crypto';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { registerGuardedAction, type GuardedActionDef, type GuardExecutionContext, type GuardTargetRefusal, type GuardTargetResult } from '../../guard';
import { androidSenders } from '../enrollment/senders';

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
      .update({ ended_at: trx.fn.now(), end_reason: reason, ended_by: endedBy });
    if (!n) continue;
    devices.push(Number(k.device_id));
    await audit.appendInTx(trx, {
      tenantId, action: 'android.kiosk_exit_ended', target: { type: 'device', id: String(k.device_id), device: Number(k.device_id) },
      details: { exitId: k.id, reason, channel: 'amapi' },
    }, auditCtx, { onFailure: 'spool' });
    // The lock comes back with the next push (a device that left management receives nothing).
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

/** Ends the exits of a tenant past their end, and those of devices that left management (job and maintenance). */
export async function expireKioskExits(tenantId: number, actor: DbActor = KIOSK_EXIT_ACTOR): Promise<{ expired: number; left: number }> {
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
    return { expired: expired.length, left: left.length };
  }));
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
});

/** The kiosk state of a device of the tenant (route GET /devices/:id/kiosk); null when the device is unknown. */
export async function readKioskState(tenantId: number, userId: number, deviceId: number): Promise<AndroidKioskState | null> {
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    const r = (await facts(db, tenantId, [deviceId])).get(deviceId);
    if (!r || r.management_channel !== 'amapi') return null;
    const exit = await db('android_kiosk_exits').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('ended_at')
      .where('expires_at', '>', db.fn.now()).first('id', 'device_id', 'guard_action_uuid', 'requested_by', 'started_at', 'expires_at', 'ended_at', 'end_reason');
    return { deviceId, dedicated: r.usage === 'kiosk' && r.management_mode === 'dedicated', exit: exit ? view(exit) : null };
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
    async revalidate(ctx) {
      const rows = await facts(db, ctx.tenantId, ctx.deviceIds);
      const out = new Map<number, 'ok' | GuardTargetRefusal>();
      for (const id of ctx.deviceIds) out.set(id, kioskExitRefusal(rows.get(id)) ?? 'ok');
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
