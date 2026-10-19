import type { Knex } from 'knex';
import { z } from 'zod';
import { config } from '../../config';
import { jobIdFor, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { releaseDeviceLicenses } from '../../mdm/apps/licensing';
import { lateCancelOf } from '../../guard/types';
import { isFinalTargetState } from '../commands/targets';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import { realtime } from '../realtime';
import { deviceEvents } from './events';
import { sendUnenrollCleanup } from './jobs';
import { onUnenrolled } from './lifecycle';

// =============================================================================
// Verified retirement of a device (docs: integration-apple-edge §13.3, ENR-17):
// the execution of the guarded action mdm.remove_management enqueues
// RemoveProfile and, through afterDispatch, starts apple.device-retire (tenant,
// standard, id jobIdFor('apple.device-retire', '<action uuid>:<device id>'),
// not redrivable), a chain of steps (motif M7: the step in the payload, each
// step a job of its own whose id names it):
//   1. removal of management  the RemoveProfile of the action ends (its target
//                             final), the device checked out, or 24 hours
//                             passed: the step waits by sending itself later
//   2. licences               the device licences of Apps and Books
//                             disassociated (releaseDeviceLicenses)
//   3. release                appleEdge.releaseEnrollment (certificates revoked,
//                             identifiers released; 404 accepted)
//   4. record                 onUnenrolled('retired') unless the device already
//                             left, devices.unenroll-cleanup
//   5. manual points          release in Apple Business, activation lock: ticked
//                             by the operator (POST …/retirement/manual)
// The late cancellation of the action (guard §10.5: result.lateCancel of its
// pending action, then cancelAfterDispatch) stops the chain before anything
// irreversible (finding INT-C5-R1): steps 1 to 3 look for it and, unless the
// device already acknowledged the RemoveProfile or checked out, the step writes
// its entry with the outcome 'cancelled' and sends no next step. A RemoveProfile
// cancelled before its delivery stops the chain the same way, mark or not; once
// delivered (cancel_after_delivery) with the mark, the chain stops too and the
// CheckOut, if the device obeys, records the leaving.
// Each step writes its entry of the device's timeline (retire_*), from which the
// console draws the checklist (retirementOf). The state "retired" is seen on
// the server side (P9): the record leaves management at the release, whether
// the CheckOut comes or not.
// =============================================================================

const RetirePayload = z.object({
  tenantId: z.number().int().positive(),
  deviceId: z.number().int().positive(),
  actionUuid: z.string().uuid(),
  step: z.number().int().min(1).max(4),
  /** Start of step 1 (ISO): its 24 hours are counted from it. */
  since: z.string().max(40),
  /** Rounds of the waiting step 1. */
  round: z.number().int().min(0).max(1_000),
}).strict();
type RetireJob = z.infer<typeof RetirePayload>;

/** Step 1 waits at most this long for the RemoveProfile (then the release goes on). */
export const REMOVE_WAIT_MS = 24 * 3_600_000;
/** Step 1 looks again this often. */
export const REMOVE_POLL_SECONDS = 15 * 60;

export const RETIRE_EVENT_KINDS = ['retire_requested', 'retire_management_removed', 'retire_licenses_released', 'retire_released', 'retired',
  'retire_manual_apple_business', 'retire_manual_activation_lock'] as const;
export const RETIRE_MANUAL_ITEMS = ['apple_business', 'activation_lock'] as const;
export type RetireManualItem = typeof RETIRE_MANUAL_ITEMS[number];

let retireJob: JobHandle<RetireJob> | null = null;

function handle(): JobHandle<RetireJob> {
  if (!retireJob) throw new Error('apple.device-retire is not registered (registerAppleModule)');
  return retireJob;
}

const stepId = (p: Pick<RetireJob, 'actionUuid' | 'deviceId' | 'step' | 'round'>): string => (p.step === 1 && p.round === 0
  ? jobIdFor('apple.device-retire', `${p.actionUuid.toLowerCase()}:${p.deviceId}`)
  : jobIdFor('apple.device-retire', `${p.actionUuid.toLowerCase()}:${p.deviceId}:${p.step}:${p.round}`));

/** afterDispatch of mdm.remove_management, in the execution's transaction: the chain of each device. */
export async function startRetirementInTx(trx: Knex.Transaction, tenantId: number, actionUuid: string, deviceIds: number[]): Promise<void> {
  const since = new Date();
  for (const deviceId of deviceIds) {
    const p: RetireJob = { tenantId, deviceId, actionUuid: actionUuid.toLowerCase(), step: 1, since: since.toISOString(), round: 0 };
    await handle().sendInTx(trx, p, { id: stepId(p), tenantId });
    await deviceEvents.add(trx, tenantId, deviceId, 'retire_requested', since, stepId(p), { action: actionUuid.toLowerCase() });
  }
}

async function next(ctx: JobContext<RetireJob>, step: number, round = 0, startAfter?: number): Promise<void> {
  const p: RetireJob = { ...ctx.payload, step, round };
  await handle().send(p, { id: stepId(p), tenantId: p.tenantId, ...(startAfter ? { startAfter } : {}) });
}

interface Facts {
  key: string | null; enrollmentId: string | null; state: string | null; released: boolean; target: string | null;
  /** reject_code of the target (cancel_after_delivery: cancelled once delivered). */
  rejectCode: string | null;
  /** The late cancellation of the action was asked (result.lateCancel of its pending action). */
  lateCancel: boolean;
}

async function factsOf(ctx: JobContext<RetireJob>): Promise<Facts> {
  const { tenantId, deviceId, actionUuid } = ctx.payload;
  return ctx.withTenant(async (trx) => {
    const r = await trx('devices as d')
      .leftJoin('apple_devices as a', function joinSatellite() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
      .join('tenants as t', 't.id', 'd.tenant_id')
      .where({ 'd.tenant_id': tenantId, 'd.id': deviceId })
      .first('t.mdm_key', 'a.enrollment_id', 'a.id_released_at', 'd.enrollment_state') as
      { mdm_key: string | null; enrollment_id: string | null; id_released_at: Date | null; enrollment_state: string } | undefined;
    const target = await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: jobIdFor('mdm.command', `${actionUuid.toLowerCase()}:${deviceId}`).toLowerCase(), device_id: deviceId })
      .first('state', 'reject_code') as { state: string; reject_code: string | null } | undefined;
    const action = await trx('pending_actions').where({ tenant_id: tenantId, uuid: actionUuid.toLowerCase() }).first('result') as
      { result: unknown } | undefined;
    return { key: r?.mdm_key ?? null, enrollmentId: r?.enrollment_id ?? null, state: r?.enrollment_state ?? null, released: !!r?.id_released_at,
      target: target?.state ?? null, rejectCode: target?.reject_code ?? null, lateCancel: lateCancelOf(action?.result) !== null };
  });
}

/**
 * Whether the retirement stops (INT-C5-R1): the action's late cancellation was asked and the device neither
 * acknowledged the RemoveProfile nor checked out, or the RemoveProfile was cancelled before its delivery.
 */
export function retirementCancelled(f: Pick<Facts, 'state' | 'target' | 'rejectCode' | 'lateCancel'>): boolean {
  if (f.state === 'unenrolled' || f.target === 'acknowledged') return false;
  if (f.lateCancel) return true;
  return f.target === 'cancelled' && f.rejectCode !== 'cancel_after_delivery';
}

/** The step stops the chain: its entry says 'cancelled', no next step. */
async function stopCancelled(ctx: JobContext<RetireJob>, kind: 'retire_management_removed' | 'retire_licenses_released' | 'retire_released'): Promise<JobResult> {
  await mark(ctx, kind, { outcome: 'cancelled' });
  realtime.deviceChanged(ctx.payload.tenantId, ctx.payload.deviceId);
  return { output: { step: ctx.payload.step, outcome: 'cancelled' } };
}

async function mark(ctx: JobContext<RetireJob>, kind: typeof RETIRE_EVENT_KINDS[number], details: Record<string, string | number | boolean> = {}): Promise<void> {
  const { tenantId, deviceId } = ctx.payload;
  await ctx.withTenant((trx) => deviceEvents.add(trx, tenantId, deviceId, kind, new Date(), ctx.jobId, details));
}

/** apple.device-retire. */
async function retire(ctx: JobContext<RetireJob>): Promise<JobResult> {
  const { tenantId, deviceId, step } = ctx.payload;
  const f = await factsOf(ctx);
  if (f.state === null) return { output: { step, skipped: 'no_record' } };
  switch (step) {
    case 1: {
      if (retirementCancelled(f)) return stopCancelled(ctx, 'retire_management_removed');
      const since = new Date(ctx.payload.since).getTime();
      const waited = Number.isFinite(since) ? Date.now() - since : REMOVE_WAIT_MS;
      const ended = f.state === 'unenrolled' ? 'checked_out' : f.target && isFinalTargetState(f.target) ? `command_${f.target}`
        : f.target === null ? 'no_command' : waited >= REMOVE_WAIT_MS ? 'timeout' : null;
      if (!ended) {
        await next(ctx, 1, ctx.payload.round + 1, REMOVE_POLL_SECONDS);
        return { output: { step, waiting: true } };
      }
      await mark(ctx, 'retire_management_removed', { outcome: ended });
      await next(ctx, 2);
      return { output: { step, outcome: ended } };
    }
    case 2: {
      if (retirementCancelled(f)) return stopCancelled(ctx, 'retire_licenses_released');
      const n = await ctx.withTenant((trx) => releaseDeviceLicenses(trx, tenantId, deviceId));
      await mark(ctx, 'retire_licenses_released', { count: n });
      await next(ctx, 3);
      return { output: { step, licenses: n } };
    }
    case 3: {
      // Last look before the irreversible release (a cancellation asked while steps 1 and 2 ran, a stale job).
      if (!f.released && retirementCancelled(f)) return stopCancelled(ctx, 'retire_released');
      let outcome = 'released';
      if (f.released) outcome = 'already';
      else if (config.apple.mode !== 'on') outcome = 'apple_edge_off';
      else if (!f.key || !f.enrollmentId || !f.enrollmentId.startsWith(`${f.key}_`)) outcome = 'no_enrollment';
      else {
        try {
          await appleEdge.releaseEnrollment(f.key, f.enrollmentId, { actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal });
        } catch (err) {
          if (isAppleEdgeError(err) && (err.code === 'enrollment_not_found' || err.status === 404)) outcome = 'not_found';
          else throw err;                                // retried by the queue
        }
      }
      await mark(ctx, 'retire_released', { outcome });
      await next(ctx, 4);
      return { output: { step, outcome } };
    }
    case 4:
    default: {
      const r = await ctx.withTenant(async (trx) => {
        let left = false;
        if (f.enrollmentId && f.state !== 'unenrolled') {
          const u = await onUnenrolled(trx, tenantId, f.enrollmentId, 'retired', new Date(), ctx.jobId);
          left = u.outcome === 'unenrolled';
        }
        const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).first('unenrolled_at') as { unenrolled_at: Date | null } | undefined;
        if (d?.unenrolled_at) await sendUnenrollCleanup(trx, tenantId, deviceId, new Date(d.unenrolled_at));
        await deviceEvents.add(trx, tenantId, deviceId, 'retired', new Date(), ctx.jobId, { unenrolledNow: left });
        return left;
      });
      realtime.deviceChanged(tenantId, deviceId);
      return { output: { step: 4, unenrolled: r } };
    }
  }
}

export interface RetirementView {
  /** The last retirement started for the device (null: none). */
  startedAt: string | null;
  steps: Array<{ step: 'management_removed' | 'licenses_released' | 'released' | 'retired'; at: string | null; outcome: string | null }>;
  /** The late cancellation of the action stopped this retirement (INT-C5-R1): nothing more is done. */
  cancelled: boolean;
  manual: Array<{ item: RetireManualItem; at: string | null }>;
}

/** The checklist of the last retirement of a device (the console's card), from its timeline. */
export async function retirementOf(q: Knex | Knex.Transaction, tenantId: number, deviceId: number): Promise<RetirementView> {
  const rows = await q('apple_device_events').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('kind', RETIRE_EVENT_KINDS as unknown as string[])
    .orderBy([{ column: 'occurred_at', order: 'asc' }, { column: 'id', order: 'asc' }]).select('kind', 'occurred_at', 'details') as
    Array<{ kind: string; occurred_at: Date; details: Record<string, unknown> | null }>;
  const lastStart = [...rows].reverse().find((r) => r.kind === 'retire_requested');
  const from = lastStart ? new Date(lastStart.occurred_at).getTime() : null;
  const after = rows.filter((r) => from !== null && new Date(r.occurred_at).getTime() >= from);
  const at = (kind: string) => after.find((r) => r.kind === kind);
  const iso = (r: { occurred_at: Date } | undefined) => (r ? new Date(r.occurred_at).toISOString() : null);
  const outcome = (r: { details: Record<string, unknown> | null } | undefined) => (r?.details && typeof r.details.outcome === 'string' ? r.details.outcome : null);
  const map: Array<[RetirementView['steps'][number]['step'], string]> = [
    ['management_removed', 'retire_management_removed'], ['licenses_released', 'retire_licenses_released'], ['released', 'retire_released'], ['retired', 'retired'],
  ];
  const steps = map.map(([step, kind]) => ({ step, at: iso(at(kind)), outcome: outcome(at(kind)) }));
  return {
    startedAt: iso(lastStart),
    steps,
    cancelled: steps.some((s) => s.outcome === 'cancelled'),
    manual: RETIRE_MANUAL_ITEMS.map((item) => ({ item, at: iso(at(`retire_manual_${item}`)) })),
  };
}

/** The operator ticks a manual point of the retirement (in the caller's transaction, tenant context). */
export async function tickRetirementItem(trx: Knex.Transaction, tenantId: number, deviceId: number, item: RetireManualItem, userId: number): Promise<void> {
  await deviceEvents.add(trx, tenantId, deviceId, `retire_manual_${item}`, new Date(), null, { by: userId });
}

let registered = false;

export function registerRetireJob(): void {
  if (registered) return;
  registered = true;
  retireJob = registerJob({
    name: 'apple.device-retire',
    scope: 'tenant',
    description: 'Verified retirement of a device: removal of management, licences, release at apple-edge, record',
    payload: RetirePayload,
    policy: 'standard',
    retry: { limit: 8, delaySeconds: 60, backoff: true, maxDelaySeconds: 3_600 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: 300,
    redrivable: false,
    handler: retire,
  });
}
