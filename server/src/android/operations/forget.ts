// Forget of an Android device (lot AN-H1; android-amapi §13.1, §22.5, AN36, RR-4, RR-11): the AMAPI resource of a
// device that no longer corresponds to anything is deleted at Google, so that it stops counting in the quota of the
// project (shared by every tenant), and the device leaves management.
//   - Automatic, at 270 days without a status report (presumed_gone): devices.delete with purpose 'cleanup'. The gateway
//     does not believe the label: it reads the device again and admits the cleanup only for appliedState DELETED or
//     more than 270 days without a report (RR-4); a device that reported meanwhile is refused (cleanup_refused) and its
//     mark is cleared at the next reconciliation. The cleanups are spread (at most ANDROID_FORGET_PER_RUN per run; the
//     gateway caps them at 100 per hour and per enterprise): one past the cap is deferred one hour, never refused for
//     good. The rule of the 270 days is [NV] (RR-11): if AN-J refutes it, setAutomaticForget(false) makes the forget an
//     operator's proposal only.
//   - By the operator: guarded action android.device_forget (restriction key of the specification), on a device
//     presumed gone or whose approval was refused: devices.delete with purpose 'operator' (freeze lock and last-resort
//     caps of the gateway), floor sensitive, typed confirmation, bulk from 3 devices, never the whole fleet.
// Both audit android.device_forgotten (critical: device, motif) and delete the device's own policy d-<uuid>.
import { z } from 'zod';
import { ANDROID_FORGET_ACTION } from '@obligarth/shared/dist/android/operations.js';
import { audit } from '../../audit';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { registerGuardedAction, type GuardedActionDef, type GuardExecutionContext, type GuardTargetRefusal, type GuardTargetResult } from '../../guard';
import { logger } from '../../utils/logger';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { AndroidError } from '../gateway/errors';
import { parseOwnedName, type AndroidEnterpriseRef } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { exitManagement } from './exit';

export const FORGET_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.reconcile-tenant' }) as DbActor;

let automatic = true;
/** RR-11: the automatic forget at 270 days stays on until AN-J refutes the rule. */
export function setAutomaticForget(on: boolean): void { automatic = on; }
export function automaticForgetEnabled(): boolean { return automatic; }

const deviceIdOf = (e: AndroidEnterpriseRef, amapiName: string): string => {
  const p = parseOwnedName(e, amapiName);
  if (p.kind !== 'device') throw new Error('android: not a device name');
  return p.deviceId;
};

/** Deletes the own policy of a device (best effort: absent, or still referenced at Google, it stays for later). */
export async function deleteDevicePolicy(gw: AndroidGateway, e: AndroidEnterpriseRef, uuid: string): Promise<boolean> {
  try {
    await gw.deletePolicy(e, `d-${uuid}`);
    return true;
  } catch (err) {
    if (err instanceof AndroidError && (err.kind === 'not_found' || err.kind === 'request')) return false;
    throw err;
  }
}

export type ForgetOutcome = 'forgotten' | 'refused' | 'deferred' | 'frozen' | 'not_open';

/**
 * Automatic forget of a device presumed gone for 270 days (tenant context of the caller). The resource is deleted at
 * Google first (outside any transaction), then the device leaves management in one transaction with its audit entry.
 */
export async function forgetPresumedGone(tenantId: number, deviceId: number, o: { gateway?: AndroidGateway } = {}): Promise<ForgetOutcome> {
  const gw = o.gateway ?? androidGateway();
  const row = await db('android_presumed_gone as p')
    .join('android_devices as a', function j() { this.on('a.device_id', '=', 'p.device_id').andOn('a.tenant_id', '=', 'p.tenant_id'); })
    .join('devices as d', function j() { this.on('d.id', '=', 'p.device_id').andOn('d.tenant_id', '=', 'p.tenant_id'); })
    .where({ 'p.tenant_id': tenantId, 'p.device_id': deviceId, 'p.state': 'open' }).whereNull('a.released_at')
    .where('p.forget_due_at', '<=', db.fn.now())
    .first('p.id', 'a.amapi_name', 'd.uuid') as { id: number; amapi_name: string; uuid: string } | undefined;
  if (!row) return 'not_open';
  const e = await readEnterprise();
  if (!e || e.state !== 'linked') return 'not_open';
  const later = async (code: string, minutes: number) => {
    await db('android_presumed_gone').where({ id: row.id, state: 'open' }).update({
      forget_attempts: db.raw('forget_attempts + 1'), last_forget_error: code,
      next_forget_at: db.raw('now() + make_interval(mins => ?)', [minutes]),
    });
  };
  try {
    await gw.deleteDevice(e, deviceIdOf(e, row.amapi_name), { purpose: 'cleanup' });
  } catch (err) {
    if (err instanceof AndroidError) {
      if (err.kind === 'not_found') { /* already gone at Google: the device leaves management */ }
      else if (err.kind === 'destructive_cap' || err.kind === 'rate_limited' || err.kind === 'unavailable') { await later(err.kind, 60); return 'deferred'; }
      else if (err.kind === 'frozen') { await later('frozen', 60); return 'frozen'; }
      else if (err.kind === 'request') { await later('cleanup_refused', 24 * 60); return 'refused'; }
      else throw err;
    } else throw err;
  }
  const ctx = audit.fromJob({ name: 'android.reconcile-tenant', requestId: `android-forget-${tenantId}-${deviceId}` });
  await db.transaction(async (trx) => {
    if (!(await exitManagement(trx, tenantId, deviceId, 'presumed_gone'))) return;
    await audit.appendInTx(trx, {
      tenantId, action: 'android.device_forgotten', target: { type: 'device', id: String(deviceId), device: deviceId },
      details: { deviceId, motif: 'presumed_gone', channel: 'amapi' },
    }, ctx, { onFailure: 'spool' });
  });
  await deleteDevicePolicy(gw, e, row.uuid).catch((err) => logger.warn({ android: { forget: 'policy', tenantId, kind: (err as AndroidError)?.kind } }, 'android: policy of a forgotten device kept'));
  return 'forgotten';
}

// ── The operator's forget (guarded action) ───────────────────────────────────

interface ForgetFacts { id: number; management_channel: string; enrollment_state: string; released_at: Date | null; amapi_name: string | null;
  approval_state: string | null; presumed: boolean; uuid: string }

async function forgetFacts(tenantId: number, ids: number[]): Promise<Map<number, ForgetFacts>> {
  if (!ids.length) return new Map();
  const rows = await db('devices as d')
    .leftJoin('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereIn('d.id', ids)
    .select('d.id', 'd.uuid', 'd.management_channel', 'd.enrollment_state', 'a.released_at', 'a.amapi_name', 'a.approval_state',
      db.raw("EXISTS (SELECT 1 FROM android_presumed_gone p WHERE p.tenant_id = d.tenant_id AND p.device_id = d.id AND p.state = 'open') AS presumed")) as ForgetFacts[];
  return new Map(rows.map((r) => [Number(r.id), r]));
}

/** Why a device cannot be forgotten by the operator (null: it can). */
export function forgetRefusal(r: ForgetFacts | undefined): GuardTargetRefusal | null {
  if (!r) return { code: 'not_found' };
  if (r.management_channel !== 'amapi') return { code: 'not_amapi' };
  if (r.released_at || !r.amapi_name) return { code: 'not_enrolled' };
  if (!r.presumed && r.approval_state !== 'rejected') return { code: 'not_presumed_gone' };
  return null;
}

/** Execution of android.device_forget for the targets left (idempotent: a device already released is done). */
export async function executeForget(ctx: GuardExecutionContext<Record<string, unknown>>, deviceIds: number[], o: { gateway?: AndroidGateway } = {}):
  Promise<Map<number, GuardTargetResult>> {
  const gw = o.gateway ?? androidGateway();
  const out = new Map<number, GuardTargetResult>();
  const e = await readEnterprise();
  const facts = await forgetFacts(ctx.tenantId, deviceIds);
  const auditCtx = await audit.fromDbActor({ type: 'user', userId: ctx.requesterId }, ctx.tenantId);
  for (const id of deviceIds) {
    const f = facts.get(id);
    if (f && f.released_at) { out.set(id, { status: 'done' }); continue; }
    const refusal = forgetRefusal(f);
    if (refusal || !e || !f) { out.set(id, { status: 'skipped', code: refusal?.code ?? 'not_linked' }); continue; }
    try {
      await gw.deleteDevice(e, deviceIdOf(e, String(f.amapi_name)), { purpose: 'operator' });
    } catch (err) {
      if (!(err instanceof AndroidError && err.kind === 'not_found')) {
        out.set(id, { status: 'failed', code: err instanceof AndroidError ? err.kind : 'error' });
        continue;
      }
    }
    await db.transaction(async (trx) => {
      if (!(await exitManagement(trx, ctx.tenantId, id, 'forgotten'))) return;
      await audit.appendInTx(trx, {
        tenantId: ctx.tenantId, action: 'android.device_forgotten', target: { type: 'device', id: String(id), device: id },
        links: { action: ctx.actionUuid }, details: { deviceId: id, motif: 'operator', channel: 'amapi' },
      }, auditCtx, { onFailure: 'spool' });
    });
    await deleteDevicePolicy(gw, e, f.uuid).catch(() => false);
    out.set(id, { status: 'done' });
  }
  return out;
}

export function defineForgetAction(o: { gateway?: () => AndroidGateway } = {}): GuardedActionDef<Record<string, unknown>> {
  return {
    key: ANDROID_FORGET_ACTION, label: 'Forget Android devices presumed gone', family: 'device_destruction',
    singleFloor: 'sensitive', singleStrictStepUp: true, bulkThreshold: 3, singleDelaySeconds: 0, bulkDelaySeconds: 900, hourlyCap: true,
    forbidWholeFleet: true, refuseOwnership: [], confirmation: 'typed', deviceCapability: 'mdm:remove', category: 'Android',
    paramsSchema: z.object({}).strict() as z.ZodType<Record<string, unknown>>,
    async revalidate(ctx) {
      const rows = await forgetFacts(ctx.tenantId, ctx.deviceIds);
      const out = new Map<number, 'ok' | GuardTargetRefusal>();
      for (const id of ctx.deviceIds) out.set(id, forgetRefusal(rows.get(id)) ?? 'ok');
      return out;
    },
    execute: (ctx, ids) => executeForget(ctx, ids, { gateway: o.gateway?.() }),
  };
}

let registered = false;
/** The guarded action of the operator's forget (registered by registerAndroidModule). */
export function registerAndroidForgetAction(): void {
  if (registered) return;
  registered = true;
  registerGuardedAction(defineForgetAction());
}

/** The devices presumed gone of a tenant, for the console (identifiers and dates only). */
export async function listPresumedGone(tenantId: number, userId: number): Promise<Array<{ deviceId: number; since: string; lastReportAt: string | null; forgetDueAt: string }>> {
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    const rows = await db('android_presumed_gone').where({ tenant_id: tenantId, state: 'open' }).orderBy('since')
      .limit(1000).select('device_id', 'since', 'last_report_at', 'forget_due_at') as Array<{ device_id: number; since: Date; last_report_at: Date | null; forget_due_at: Date }>;
    return rows.map((r) => ({
      deviceId: Number(r.device_id), since: new Date(r.since).toISOString(),
      lastReportAt: r.last_report_at ? new Date(r.last_report_at).toISOString() : null, forgetDueAt: new Date(r.forget_due_at).toISOString(),
    }));
  });
}
