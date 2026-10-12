import type { Knex } from 'knex';
import { z } from 'zod';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../../audit';
import { config } from '../../config';
import { db } from '../../db';
import { currentDbContext } from '../../db/context';
import { forEachTenant } from '../../db/tenantContext';
import { JobError, defaultRuntime, jobIdFor, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { logger } from '../../utils/logger';
import { raiseAlert } from '../alerts/service';
import { edgeActorOf } from '../actors';
import type { EdgeCancelOutcome } from '../edge/client';
import { isAppleEdgeError, type AppleEdgeError } from '../edge/errors';
import { edgeHealth } from '../edge/health';
import { appleEdge } from '../edge/instance';
import type { EdgePushOutcome } from '../edge/wire';
import { appleMetrics } from '../metrics';
import { realtime } from '../realtime';
import { upsertMirror } from '../tenants/registry';
import { bindCommandJobs, tenantFrozen, type RelaunchOutcome } from './bus';
import { finalizeTargets } from './targets';

// =============================================================================
// Jobs of the command queue (docs: integration-apple-edge §8.6, §8.7, annex B):
//   mdm.commands.submit         one per command: hands the frozen plist to
//                               apple-edge (same UUID, same bytes, same
//                               targets at every attempt: idempotent there),
//                               then applies its answer to the targets
//   mdm.commands.cancel         one per cancellation of a submitted command
//   mdm.commands.resubmit-held  the held commands of a tenant whose cause is
//                               gone (unfreeze, apple-edge back)
//   mdm.commands.resubmit-all   every 5 minutes: the tenants with held commands
//   mdm.commands.relaunch-all   every 5 minutes: the tenants with open targets
//   mdm.commands.relaunch       the push relaunches of a tenant (EX-06:
//                               apple-edge relaunches nothing by itself)
//   mdm.commands.expire-pending every 5 minutes: commands never submitted
//                               whose expiry passed
// No network call inside a transaction (T-1): read and mark in one, call, then
// apply in another. The set of targets of a submission is fixed by its first
// attempt (queued_at is written then, the state stays 'pending' until
// apple-edge accepts): an attempt whose answer was lost may have been taken
// by apple-edge, which refuses the same UUID with other targets, so a retry
// sends the very same set, and what was closed meanwhile on the brain's side
// (cancelled, device gone) is then withdrawn at apple-edge.
// Payloads: internal identifiers only. Logs: never an enrollment id.
// =============================================================================

const SUBMIT_QUEUE = 'mdm.commands.submit';
const CANCEL_QUEUE = 'mdm.commands.cancel';
const RESUBMIT_QUEUE = 'mdm.commands.resubmit-held';
const RELAUNCH_QUEUE = 'mdm.commands.relaunch';

const SubmitPayload = z.object({ tenantId: z.number().int().positive(), commandId: z.string().uuid() }).strict();
const CancelPayload = z.object({ tenantId: z.number().int().positive(), commandId: z.string().uuid(), requestedAt: z.string().datetime() }).strict();
const TenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();
const Empty = z.object({}).strict();
type Submit = z.infer<typeof SubmitPayload>;
type Cancel = z.infer<typeof CancelPayload>;
type Tenant = z.infer<typeof TenantPayload>;

let submitJob: JobHandle<Submit> | null = null;
let cancelJob: JobHandle<Cancel> | null = null;
let resubmitJob: JobHandle<Tenant> | null = null;
let relaunchJob: JobHandle<Tenant> | null = null;
let resubmitAllJob: JobHandle<Record<string, never>> | null = null;

/** The worker of `queue` fetches again as soon as the running job ends: several jobs born in one transaction are
 *  announced once (file-durable, note of lot B5b). */
function fetchNext(queue: string): void {
  try { defaultRuntime.wake(queue); } catch { /* the runtime is stopping */ }
}

const PUSH_OUTCOMES = new Set(['sent', 'deferred', 'disabled', 'error', 'not_requested']);
const pushOutcome = (v: unknown): EdgePushOutcome => (typeof v === 'string' && PUSH_OUTCOMES.has(v) ? v as EdgePushOutcome : 'error');
/** An expiry this close is not worth a submission. */
const EXPIRY_MARGIN_MS = 30_000;
const LOCAL_FINAL_WITHOUT_RESULT = ['cancelled', 'rejected', 'expired'];

interface CommandRow {
  id: string;
  request_type: string;
  plist: string | null;
  plist_enc: string | null;
  push: boolean;
  not_before: Date | null;
  expires_at: Date;
  submit_state: string;
  submit_attempts: number;
}

type Prepared =
  | { kind: 'skip'; why: string }
  | { kind: 'done'; output: Record<string, string | number | boolean | null>; devices: number[] }
  | { kind: 'call'; key: string; cmd: CommandRow; targets: Array<{ deviceId: number; enrollmentId: string }> };

async function setHeld(trx: Knex.Transaction, tenantId: number, commandId: string, reason: 'frozen' | 'edge_unavailable', error: string | null): Promise<void> {
  await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId })
    .update({ submit_state: 'held', last_submit_error: error, updated_at: new Date() });
  await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId, state: 'pending' }).update({ hold_reason: reason });
}

async function setFailed(trx: Knex.Transaction, tenantId: number, commandId: string, error: string, rejectCode: string | null): Promise<number[]> {
  await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId })
    .update({ submit_state: 'failed', last_submit_error: error.slice(0, 64), updated_at: new Date() });
  if (!rejectCode) return [];
  return finalizeTargets(trx, { tenantId, commandId, deviceIds: null, from: ['pending'], to: 'rejected', rejectCode, at: new Date() });
}

/** The targets of the submitted set closed on the brain's side (cancelled, refused, expired): apple-edge is asked to
 *  drop them (mdm.commands.cancel). It answers 404 when it never took the command: nothing to drop then. */
async function withdrawClosedTargets(trx: Knex.Transaction, tenantId: number, commandId: string, now: Date): Promise<void> {
  const stray = await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId }).whereNotNull('queued_at')
    .whereIn('state', LOCAL_FINAL_WITHOUT_RESULT).pluck('device_id') as number[];
  if (stray.length === 0) return;
  await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId }).whereRaw('device_id = ANY (?::int[])', [stray.map(Number)])
    .update({ cancel_requested_at: now });
  await (cancelJob as JobHandle<Cancel>).sendInTx(trx, { tenantId, commandId, requestedAt: now.toISOString() },
    { id: jobIdFor(CANCEL_QUEUE, `${commandId}:${now.toISOString()}`), tenantId });
}

/** Step 1 (§8.6): the command locked, what stops a submission checked, the set of targets fixed, one attempt counted. */
async function prepare(trx: Knex.Transaction, ctx: JobContext<Submit>): Promise<Prepared> {
  const tenantId = ctx.tenantId as number;
  const commandId = ctx.payload.commandId;
  const cmd = await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId }).forUpdate()
    .first('id', 'request_type', 'plist', 'plist_enc', 'push', 'not_before', 'expires_at', 'submit_state', 'submit_attempts') as CommandRow | undefined;
  if (!cmd) return { kind: 'skip', why: 'not_found' };
  if (cmd.submit_state !== 'pending' && cmd.submit_state !== 'held') {
    // Cancelled while an attempt was in flight: the cancellation asked apple-edge at once, perhaps before the request
    // of that attempt reached it (it found nothing to drop then, and the answer of the attempt was lost). No attempt
    // is running any more: apple-edge is asked again, so that it never keeps active a command the console shows
    // cancelled (review of lot B4).
    if (cmd.submit_state === 'cancelled' && Number(cmd.submit_attempts) > 0) await withdrawClosedTargets(trx, tenantId, commandId, new Date());
    return { kind: 'skip', why: cmd.submit_state };
  }
  const now = Date.now();
  if (cmd.not_before && new Date(cmd.not_before).getTime() > now + 1000) {
    // Started too early (a manual run, a redrive): back to its time.
    await (submitJob as JobHandle<Submit>).sendInTx(trx, { tenantId, commandId },
      { id: jobIdFor(SUBMIT_QUEUE, `${commandId}:nb:${new Date(cmd.not_before).getTime()}:${ctx.jobId}`), tenantId, startAfter: new Date(cmd.not_before) });
    return { kind: 'skip', why: 'not_before' };
  }
  if (await tenantFrozen(trx, tenantId)) {
    await setHeld(trx, tenantId, commandId, 'frozen', null);
    return { kind: 'done', output: { held: 'frozen' }, devices: [] };
  }
  if (new Date(cmd.expires_at).getTime() <= now + EXPIRY_MARGIN_MS) {
    const devices = await finalizeTargets(trx, { tenantId, commandId, deviceIds: null, from: ['pending'], to: 'expired',
      rejectCode: 'expired_before_submit', at: new Date() });
    await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId })
      .update({ submit_state: 'failed', last_submit_error: 'expired_before_submit', updated_at: new Date() });
    return { kind: 'done', output: { expired: devices.length }, devices };
  }
  const t = await trx('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
  if (config.apple.mode !== 'on' || !t?.mdm_key) {
    await setHeld(trx, tenantId, commandId, 'edge_unavailable', config.apple.mode !== 'on' ? 'apple_edge_off' : 'tenant_not_provisioned');
    return { kind: 'done', output: { held: 'edge_unavailable' }, devices: [] };
  }
  if (!cmd.plist) {
    // plist_enc is reserved to the v1 commands that carry a secret no device key can protect (§8.8, 4): no type
    // of the MVP writes one.
    const devices = await setFailed(trx, tenantId, commandId, 'sealed_plist_unsupported', 'invalid_command');
    return { kind: 'done', output: { failed: 'sealed_plist_unsupported' }, devices };
  }
  const changed: number[] = [];
  if (Number(cmd.submit_attempts) === 0) {
    // First attempt: the pending targets whose device left management meanwhile are refused, the others make the set.
    const gone = await trx('mdm_command_targets as t')
      .join('devices as d', function joinDevice() { this.on('d.id', '=', 't.device_id').andOn('d.tenant_id', '=', 't.tenant_id'); })
      .where({ 't.tenant_id': tenantId, 't.command_id': commandId, 't.state': 'pending' })
      .whereNotIn('d.enrollment_state', ['enrolled', 'awaiting_configuration']).pluck('t.device_id') as number[];
    if (gone.length > 0) {
      changed.push(...await finalizeTargets(trx, { tenantId, commandId, deviceIds: gone.map(Number), from: ['pending'], to: 'rejected',
        rejectCode: 'not_enrolled', at: new Date() }));
    }
    await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId, state: 'pending' }).update({ queued_at: new Date(), hold_reason: null });
  }
  const set = await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId }).whereNotNull('queued_at')
    .select('device_id', 'enrollment_id', 'state') as Array<{ device_id: number; enrollment_id: string; state: string }>;
  if (!set.some((s) => s.state === 'pending')) {
    // Nothing left to submit (all refused, or cancelled before any attempt: the cancellation asks apple-edge itself).
    const left = await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId, state: 'cancelled' }).count('* as n').first() as { n: string | number };
    await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId })
      .update({ submit_state: Number(left.n) > 0 ? 'cancelled' : 'failed', last_submit_error: 'no_target', updated_at: new Date() });
    return { kind: 'done', output: { skipped: 'no_target' }, devices: changed };
  }
  await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId })
    .update({ submit_state: 'pending', submit_attempts: trx.raw('submit_attempts + 1'), updated_at: new Date() });
  return { kind: 'call', key: t.mdm_key, cmd, targets: set.map((s) => ({ deviceId: Number(s.device_id), enrollmentId: s.enrollment_id })) };
}

/** Step 3, the accepted submission: the targets of the set still pending become 'queued' with their push outcome;
 *  those closed meanwhile on the brain's side are withdrawn at apple-edge. */
async function applyAccepted(trx: Knex.Transaction, tenantId: number, commandId: string, results: Record<string, { queued: boolean; push: string }>,
  set: Array<{ deviceId: number; enrollmentId: string }>): Promise<number[]> {
  const now = new Date();
  await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId })
    .update({ submit_state: 'submitted', submitted_at: trx.raw('COALESCE(submitted_at, ?::timestamptz)', [now]), last_submit_error: null, updated_at: now });
  const ids = set.map((s) => s.enrollmentId);
  const pushes = set.map((s) => pushOutcome(results[s.enrollmentId]?.push));
  const res = await trx.raw(`
    UPDATE obligarth.mdm_command_targets t
       SET state = 'queued', state_event_at = ?, queued_at = ?, hold_reason = NULL, push_outcome = u.push,
           pushed_at = CASE WHEN u.push IN ('sent', 'deferred') THEN ?::timestamptz ELSE t.pushed_at END,
           push_count = CASE WHEN u.push IN ('sent', 'deferred') THEN 1 ELSE t.push_count END
      FROM unnest(?::text[], ?::text[]) AS u(enrollment_id, push)
     WHERE t.tenant_id = ? AND t.command_id = ?::uuid AND t.enrollment_id = u.enrollment_id AND t.state = 'pending'
    RETURNING t.device_id`, [now, now, now, ids, pushes, tenantId, commandId]) as { rows: Array<{ device_id: number }> };
  // Closed on the brain's side while the submission was in flight (cancelled, device gone): apple-edge now holds
  // them, it is asked to drop them. Also when a cancellation already asked: it may have run before apple-edge took
  // the command (an attempt that never arrived), and found nothing to drop then.
  await withdrawClosedTargets(trx, tenantId, commandId, now);
  return res.rows.map((r) => Number(r.device_id));
}

/** 422 target_outside_tenant: nothing was enqueued. The targets apple-edge no longer holds as enabled leave the
 *  set; true when the set shrank (the caller submits again). */
async function shrinkSet(ctx: JobContext<Submit>, key: string, commandId: string, set: Array<{ deviceId: number; enrollmentId: string }>): Promise<{ left: typeof set; changed: number[] }> {
  const tenantId = ctx.tenantId as number;
  const call = { actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal };
  const enabled = new Set<string>();
  if (set.length <= 50) {
    for (const s of set) {
      try {
        const e = await appleEdge.getEnrollment(key, s.enrollmentId, call);
        if (e.enrollment.enabled) enabled.add(s.enrollmentId);
      } catch (err) {
        if (!(isAppleEdgeError(err) && (err.code === 'enrollment_not_found' || err.status === 404 || err.code === 'target_outside_tenant'))) throw err;
      }
    }
  } else {
    let cursor: string | undefined;
    for (let page = 0; page < 1000; page++) {
      const r = await appleEdge.listEnrollments(key, { cursor, limit: 1000 }, call);
      for (const e of r.items) if (e.enabled) enabled.add(e.enrollment_id);
      if (!r.nextCursor) break;
      cursor = r.nextCursor;
    }
  }
  const out = set.filter((s) => !enabled.has(s.enrollmentId));
  if (out.length === 0) return { left: set, changed: [] };
  const changed = await ctx.withTenant(async (trx) => {
    const ids = out.map((s) => s.deviceId);
    const done = await finalizeTargets(trx, { tenantId, commandId, deviceIds: ids, from: ['pending'], to: 'rejected', rejectCode: 'not_enrolled', at: new Date() });
    // Out of the set, whatever their state: apple-edge never took them.
    await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId }).whereRaw('device_id = ANY (?::int[])', [ids]).update({ queued_at: null });
    return done;
  });
  return { left: set.filter((s) => enabled.has(s.enrollmentId)), changed };
}

/** mdm.commands.submit (§8.6). */
async function submit(ctx: JobContext<Submit>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const commandId = ctx.payload.commandId;
  try {
    const step = await ctx.withTenant((trx) => prepare(trx, ctx));
    if (step.kind === 'skip') return { output: { skipped: step.why } };
    if (step.kind === 'done') {
      if (step.devices.length > 0) realtime.commandChanged(tenantId, [commandId], step.devices.slice(0, 500));
      return { output: step.output };
    }
    const { key, cmd } = step;
    let set = step.targets;
    const changed: number[] = [];
    const fail = async (error: string, rejectCode: string | null, alert?: string): Promise<JobResult> => {
      const devices = await ctx.withTenant((trx) => setFailed(trx, tenantId, commandId, error, rejectCode));
      if (alert) {
        logger.error({ tenantId, requestType: cmd.request_type, code: alert }, 'apple-edge refused a command of the brain (programming defect)');
        await raiseAlert(ctx.dbActor, MASTER_TENANT_ID, 'mdm.command_invalid', { discriminant: commandId, params: { requestType: cmd.request_type, code: alert } });
      }
      realtime.commandChanged(tenantId, [commandId], [...changed, ...devices].slice(0, 500));
      appleMetrics.commandSubmission('failed');
      return { output: { failed: error, rejected: devices.length } };
    };
    for (let round = 1; ; round++) {
      ctx.throwIfAborted();
      try {
        const r = await appleEdge.enqueueCommand(key, {
          command_uuid: commandId, command_plist_b64: Buffer.from(cmd.plist as string, 'utf8').toString('base64'),
          targets: set.map((s) => s.enrollmentId), push: cmd.push !== false, expires_at: new Date(cmd.expires_at).toISOString(),
        }, { actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal });
        const queued = await ctx.withTenant((trx) => applyAccepted(trx, tenantId, commandId, r.result.targets, set));
        realtime.commandChanged(tenantId, [commandId], [...changed, ...queued].slice(0, 500));
        appleMetrics.commandSubmission('submitted');
        return { output: { submitted: set.length, queued: queued.length, created: r.created } };
      } catch (err) {
        if (!isAppleEdgeError(err)) throw err;
        const e = err as AppleEdgeError;
        if (e.code === 'target_outside_tenant') {
          // Two rounds at most in one run (§8.6); a set that changes again is taken up by the next attempt.
          if (round >= 2) throw new JobError('target_outside_tenant', 'the targets of the command changed again at apple-edge');
          const s = await shrinkSet(ctx, key, commandId, set);
          changed.push(...s.changed);
          if (s.left.length === set.length) throw new JobError('target_outside_tenant', 'apple-edge refuses a target it reports as enabled');
          set = s.left;
          if (set.length === 0) {
            await ctx.withTenant((trx) => trx('mdm_commands').where({ tenant_id: tenantId, id: commandId })
              .update({ submit_state: 'failed', last_submit_error: 'no_target', updated_at: new Date() }));
            realtime.commandChanged(tenantId, [commandId], changed.slice(0, 500));
            return { output: { failed: 'no_target', rejected: changed.length } };
          }
          continue;
        }
        if (e.code === 'secret_unavailable') return fail('secret_unavailable', 'unlock_token_unavailable');
        if (e.code === 'command_uuid_conflict') return fail('command_uuid_conflict', 'uuid_conflict', 'command_uuid_conflict');
        if (e.code === 'tenant_not_live') {
          await ctx.withTenant((trx) => upsertMirror(trx, tenantId, { last_error_code: 'tenant_not_live' }));
          return fail('tenant_not_live', 'tenant_not_live');
        }
        if (e.code === 'tenant_not_found') {
          await ctx.withTenant(async (trx) => {
            await setHeld(trx, tenantId, commandId, 'edge_unavailable', 'tenant_not_found');
            await upsertMirror(trx, tenantId, { edge_state: 'missing', last_error_code: 'tenant_not_found' });
          });
          const name = await ctx.withTenant((trx) => trx('tenants').where({ id: tenantId }).first('name')) as { name: string } | undefined;
          await raiseAlert(ctx.dbActor, MASTER_TENANT_ID, 'tenant.edge_missing', { discriminant: tenantId, params: { tenantName: name?.name ?? `#${tenantId}` } });
          appleMetrics.commandSubmission('held');
          return { output: { held: 'edge_unavailable', code: 'tenant_not_found' } };
        }
        if (e.code === 'commands_frozen') {
          await ctx.withTenant(async (trx) => {
            await setHeld(trx, tenantId, commandId, 'frozen', 'commands_frozen');
            await upsertMirror(trx, tenantId, { commands_frozen: true });          // the freeze was set elsewhere
          });
          appleMetrics.commandSubmission('held');
          return { output: { held: 'frozen' } };
        }
        if (e.status === 400 || e.status === 413 || e.status === 422) {
          // invalid_request, payload_too_large, validation_failed, secret_in_command: a defect of the brain (§8.6).
          return fail(String(e.code).slice(0, 64), 'invalid_command', String(e.code).slice(0, 64));
        }
        // 5xx, transport, timeout, circuit open, incompatible, disabled: later. So is any other refusal, which says
        // nothing against the command itself: 401 (the token of the brain is misconfigured, §5.4: the probe raises
        // edge.auth_failed), 403, 429, an unknown 404 or 409 (review of lot B4: such an answer closed every command
        // submitted meanwhile as 'failed', its targets 'rejected').
        if (!ctx.isLastAttempt) {
          appleMetrics.commandSubmission('retried');
          throw new JobError('edge_unavailable', 'apple-edge did not take the command');
        }
        await ctx.withTenant((trx) => setHeld(trx, tenantId, commandId, 'edge_unavailable', String(e.code).slice(0, 64)));
        appleMetrics.commandSubmission('held');
        return { output: { held: 'edge_unavailable' } };
      }
    }
  } finally {
    fetchNext(SUBMIT_QUEUE);
  }
}

// ── Cancellation at apple-edge (§8.7) ──────────────────────────────────────────

export type CancelAtEdgeOutcome = 'cancelled' | 'already_delivered' | 'completed' | 'expired' | 'not_submitted';

/**
 * Asks apple-edge to drop targets of a command and applies its answers (§8.7): 'cancelled' and
 * 'already_delivered' close the target as cancelled (the second with cancel_after_delivery: a later result
 * still wins), 'completed' changes nothing (the result comes through the outbox), 'expired' expires it.
 * Network: outside any transaction, in the database context of the tenant (a job's inTenant, a route's
 * asTargetTenant). `only`: the targets marked at that time (the job of one cancellation); `deviceIds`: those
 * devices; neither: every target of the command.
 */
export async function cancelAtEdge(tenantId: number, commandId: string, sel: { requestedAt?: Date; deviceIds?: number[] },
  call: { actor: string; requestId?: string; signal?: AbortSignal }): Promise<Map<number, CancelAtEdgeOutcome>> {
  const out = new Map<number, CancelAtEdgeOutcome>();
  const read = await db.transaction(async (trx) => {
    const cmd = await trx('mdm_commands as c').join('tenants as t', 't.id', 'c.tenant_id').where({ 'c.tenant_id': tenantId, 'c.id': commandId })
      .first('c.submit_state', 'c.submit_attempts', 't.mdm_key') as { submit_state: string; submit_attempts: number; mdm_key: string | null } | undefined;
    if (!cmd) return null;
    let q = trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId }).whereNotNull('queued_at');
    if (sel.requestedAt) q = q.where('cancel_requested_at', sel.requestedAt);
    if (sel.deviceIds) q = q.whereRaw('device_id = ANY (?::int[])', [sel.deviceIds]);
    const targets = await q.select('device_id', 'enrollment_id', 'state') as Array<{ device_id: number; enrollment_id: string; state: string }>;
    return { cmd, targets };
  });
  if (!read) return out;
  const { cmd, targets } = read;
  const open = targets.filter((t) => t.state !== 'acknowledged' && t.state !== 'error');
  for (const t of targets) if (t.state === 'acknowledged' || t.state === 'error') out.set(Number(t.device_id), 'completed');
  if (open.length === 0) return out;
  if (!cmd.mdm_key || (cmd.submit_state !== 'submitted' && Number(cmd.submit_attempts) === 0)) {
    for (const t of open) out.set(Number(t.device_id), 'not_submitted');
    return out;
  }
  let answers: Record<string, EdgeCancelOutcome> = {};
  try {
    answers = await appleEdge.cancelCommand(cmd.mdm_key, commandId, open.map((t) => t.enrollment_id), call);
  } catch (err) {
    if (isAppleEdgeError(err) && err.code === 'command_not_found') {
      // apple-edge never took the command: nothing to drop there.
      for (const t of open) out.set(Number(t.device_id), 'not_submitted');
      return out;
    }
    throw err;
  }
  const byEnrollment = new Map(open.map((t) => [t.enrollment_id, Number(t.device_id)]));
  const groups: Record<'cancelled' | 'already_delivered' | 'expired', number[]> = { cancelled: [], already_delivered: [], expired: [] };
  for (const [enrollmentId, answer] of Object.entries(answers)) {
    const deviceId = byEnrollment.get(enrollmentId);
    if (deviceId === undefined) continue;
    if (answer === 'cancelled' || answer === 'already_delivered' || answer === 'expired') groups[answer].push(deviceId);
    out.set(deviceId, answer === 'cancelled' || answer === 'already_delivered' || answer === 'expired' ? answer : 'completed');
  }
  const now = new Date();
  const changed = await db.transaction(async (trx) => {
    const done: number[] = [];
    const from = ['pending', 'queued', 'sent', 'notnow'] as const;
    done.push(...await finalizeTargets(trx, { tenantId, commandId, deviceIds: groups.cancelled, from, to: 'cancelled', rejectCode: 'cancelled_by_user', at: now }));
    done.push(...await finalizeTargets(trx, { tenantId, commandId, deviceIds: groups.already_delivered, from, to: 'cancelled', rejectCode: 'cancel_after_delivery', at: now }));
    done.push(...await finalizeTargets(trx, { tenantId, commandId, deviceIds: groups.expired, from, to: 'expired', rejectCode: 'expired_at_edge', at: now }));
    if (groups.already_delivered.length > 0) {
      // Cancelled on the brain's side before apple-edge answered: the device had it already.
      await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId, state: 'cancelled', reject_code: 'cancelled_by_user' })
        .whereRaw('device_id = ANY (?::int[])', [groups.already_delivered]).update({ reject_code: 'cancel_after_delivery' });
    }
    return done;
  });
  if (changed.length > 0) realtime.commandChanged(tenantId, [commandId], changed.slice(0, 500));
  return out;
}

/** mdm.commands.cancel. */
async function cancelJobHandler(ctx: JobContext<Cancel>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  try {
    if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
    let res: Map<number, CancelAtEdgeOutcome>;
    try {
      res = await ctx.inTenant(() => cancelAtEdge(tenantId, ctx.payload.commandId, { requestedAt: new Date(ctx.payload.requestedAt) },
        { actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal }));
    } catch (err) {
      if (isAppleEdgeError(err) && err.retryable) throw new JobError('edge_unavailable', 'apple-edge did not take the cancellation');
      if (isAppleEdgeError(err)) return { output: { failed: String(err.code).slice(0, 64) } };
      throw err;
    }
    const n = (o: CancelAtEdgeOutcome): number => [...res.values()].filter((v) => v === o).length;
    return { output: { cancelled: n('cancelled'), alreadyDelivered: n('already_delivered'), completed: n('completed'), expired: n('expired') } };
  } finally {
    fetchNext(CANCEL_QUEUE);
  }
}

// ── Held commands (§8.6) ───────────────────────────────────────────────────────

/** Sends mdm.commands.resubmit-held of a tenant (the unfreeze, apple-edge back, an operator). */
export async function requestResubmitHeld(tenantId: number, trx?: Knex.Transaction): Promise<void> {
  if (!resubmitJob) return;
  const opts = { singletonKey: `t:${tenantId}`, tenantId };
  if (trx) await resubmitJob.sendInTx(trx, { tenantId }, opts);
  else await resubmitJob.send({ tenantId }, opts);
}

/** Runs the sweep of the held commands now (apple-edge answers again: §8.6); one run at a time (exclusive). */
export async function requestResubmitAll(): Promise<void> {
  if (resubmitAllJob) await resubmitAllJob.send({});
}

/** mdm.commands.resubmit-held: the held commands whose cause is gone go back to their submission. */
async function resubmitHeld(ctx: JobContext<Tenant>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
  if (edgeHealth().up === false || appleEdge.circuitOpen()) return { output: { skipped: 'edge_unavailable' } };
  const sent = await ctx.withTenant(async (trx) => {
    if (await tenantFrozen(trx, tenantId)) return -1;
    const t = await trx('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
    if (!t?.mdm_key) return -2;
    const held = await trx('mdm_commands').where({ tenant_id: tenantId, submit_state: 'held' }).orderBy('created_at').limit(500).forUpdate().skipLocked()
      .select('id', 'not_before') as Array<{ id: string; not_before: Date | null }>;
    const now = Date.now();
    for (const c of held) {
      const id = String(c.id).toLowerCase();
      await trx('mdm_commands').where({ tenant_id: tenantId, id }).update({ submit_state: 'pending', updated_at: new Date() });
      await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: id, state: 'pending' }).update({ hold_reason: null });
      const later = c.not_before && new Date(c.not_before).getTime() > now ? { startAfter: new Date(c.not_before) } : {};
      await (submitJob as JobHandle<Submit>).sendInTx(trx, { tenantId, commandId: id }, { id: jobIdFor(SUBMIT_QUEUE, `${id}:held:${ctx.jobId}`), tenantId, ...later });
    }
    return held.length;
  });
  if (sent === -1) return { output: { skipped: 'frozen' } };
  if (sent === -2) return { output: { skipped: 'tenant_not_provisioned' } };
  return { output: { resubmitted: sent } };
}

/** mdm.commands.resubmit-all. */
async function resubmitAll(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
  let tenants = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const held = await db('mdm_commands').where({ tenant_id: tenantId, submit_state: 'held' }).first('id');
    if (!held) return;
    await requestResubmitHeld(tenantId);
    tenants++;
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { tenants } };
}

// ── Expiry before the submission (§8.7) ────────────────────────────────────────

/** mdm.commands.expire-pending: apple-edge expires what it holds; the brain only what it never submitted. */
async function expirePending(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let expired = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const due = await db('mdm_commands').where({ tenant_id: tenantId }).whereIn('submit_state', ['pending', 'held'])
      .where('expires_at', '<=', new Date()).limit(500).pluck('id') as string[];
    for (const id of due) {
      const commandId = String(id).toLowerCase();
      const devices = await db.transaction(async (trx) => {
        const cmd = await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId }).whereIn('submit_state', ['pending', 'held']).forUpdate().first('id');
        if (!cmd) return [] as number[];
        const done = await finalizeTargets(trx, { tenantId, commandId, deviceIds: null, from: ['pending'], to: 'expired', rejectCode: 'expired_before_submit', at: new Date() });
        await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId })
          .update({ submit_state: 'failed', last_submit_error: 'expired_before_submit', updated_at: new Date() });
        return done;
      });
      expired += devices.length;
      if (devices.length > 0) realtime.commandChanged(tenantId, [commandId], devices.slice(0, 500));
    }
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { expired } };
}

// ── Push relaunches (§8.7, EX-06) ──────────────────────────────────────────────

/** Devices relaunched per run of a tenant (one call of apple-edge takes 10 000). */
const RELAUNCH_BATCH = 10_000;

interface DueDevice { device_id: number; enrollment_id: string }

/**
 * The devices of a tenant with an open target due for a relaunch (§8.7): 'queued' by the steps
 * (APPLE_PUSH_RELAUNCH_STEPS: 15 min after the 1st push, 1 h after the 2nd, 4 h after the 3rd, then every 24 h),
 * 'sent' without a result 1 h after the delivery then every 24 h, 'notnow' never before 24 h after the last
 * NotNow; APPLE_PUSH_MAX_PER_TARGET pushes at most. Left out: a push that cannot reach the device, a device
 * that connected since the last push (it will take its commands by itself), a command without push or expired.
 */
async function dueDevices(trx: Knex.Transaction, tenantId: number, limit: number, only?: { commandId: string; deviceIds: number[] | null }): Promise<DueDevice[]> {
  const steps = config.apple.pushRelaunchSteps;
  // The wait after the n-th push (index n, 1 to 4), in seconds: the steps, the last one repeated; a target never
  // pushed (its push was disabled or failed at the enqueueing) waits the first step.
  const waits = [0, 1, 2, 3].map((i) => Math.floor(steps[Math.min(i, steps.length - 1)] ?? 900));
  const res = await trx.raw(`
    SELECT DISTINCT t.device_id, a.enrollment_id
      FROM obligarth.mdm_command_targets t
      JOIN obligarth.mdm_commands c ON c.id = t.command_id AND c.tenant_id = t.tenant_id
      JOIN obligarth.devices d ON d.id = t.device_id AND d.tenant_id = t.tenant_id
      JOIN obligarth.apple_devices a ON a.device_id = t.device_id AND a.tenant_id = t.tenant_id
     WHERE t.tenant_id = ? AND t.state IN ('queued', 'sent', 'notnow')
       AND c.push AND c.expires_at > now() AND t.push_count < ?
       AND a.enrollment_id = t.enrollment_id
       AND a.push_state NOT IN ('invalid_token', 'inactive', 'disabled')
       AND d.enrollment_state IN ('enrolled', 'awaiting_configuration')
       AND (d.last_checkin_at IS NULL OR d.last_checkin_at <= COALESCE(t.pushed_at, t.queued_at, t.state_event_at))
       AND (?::uuid IS NULL OR t.command_id = ?::uuid)
       AND (?::int[] IS NULL OR t.device_id = ANY (?::int[]))
       AND CASE t.state
             WHEN 'queued' THEN COALESCE(t.pushed_at, t.queued_at, t.state_event_at)
                                + make_interval(secs => (?::int[])[GREATEST(1, LEAST(t.push_count, 4))]) <= now()
             WHEN 'sent' THEN CASE WHEN t.pushed_at IS NULL OR t.pushed_at < COALESCE(t.delivered_at, t.state_event_at)
                                   THEN COALESCE(t.delivered_at, t.state_event_at) + interval '1 hour'
                                   ELSE t.pushed_at + interval '24 hours' END <= now()
             ELSE GREATEST(t.state_event_at, COALESCE(t.pushed_at, t.state_event_at)) + interval '24 hours' <= now()
           END
     LIMIT ?`,
  [tenantId, config.apple.pushMaxPerTarget, only?.commandId ?? null, only?.commandId ?? null, only?.deviceIds ?? null, only?.deviceIds ?? null, waits, limit]) as
    { rows: DueDevice[] };
  return res.rows.map((r) => ({ device_id: Number(r.device_id), enrollment_id: r.enrollment_id }));
}

/** Why a tenant gets no relaunch at all; null: it may. */
async function relaunchBlocked(trx: Knex.Transaction, tenantId: number): Promise<{ code: string } | { key: string }> {
  if (await tenantFrozen(trx, tenantId)) return { code: 'frozen' };
  const t = await trx('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
  if (!t?.mdm_key) return { code: 'tenant_not_provisioned' };
  const cert = await trx('tenant_apple_push').where({ tenant_id: tenantId, state: 'active' }).first('id');
  if (!cert) return { code: 'no_push_certificate' };
  return { key: t.mdm_key };
}

/** One push per device, written on every open target of the device (its commands share the wake-up). */
async function pushAndRecord(tenantId: number, key: string, due: DueDevice[], call: { actor: string; requestId?: string; signal?: AbortSignal }): Promise<Map<number, EdgePushOutcome>> {
  const out = new Map<number, EdgePushOutcome>();
  if (due.length === 0) return out;
  const results = await appleEdge.pushRequests(key, due.map((d) => d.enrollment_id), call);
  const devices: number[] = [];
  const outcomes: string[] = [];
  for (const d of due) {
    const o = pushOutcome(results[d.enrollment_id]);
    appleMetrics.pushRelaunched(o);
    out.set(d.device_id, o);
    devices.push(d.device_id);
    outcomes.push(o);
  }
  const now = new Date();
  const changed = await db.transaction(async (trx) => {
    const res = await trx.raw(`
      UPDATE obligarth.mdm_command_targets t
         SET pushed_at = ?, push_count = t.push_count + 1, push_outcome = u.outcome
        FROM unnest(?::int[], ?::text[]) AS u(device_id, outcome)
       WHERE t.tenant_id = ? AND t.device_id = u.device_id AND t.state IN ('queued', 'sent', 'notnow')
      RETURNING t.command_id`, [now, devices, outcomes, tenantId]) as { rows: Array<{ command_id: string }> };
    return [...new Set(res.rows.map((r) => String(r.command_id)))];
  });
  if (changed.length > 0) realtime.commandChanged(tenantId, changed.slice(0, 500), devices.slice(0, 500));
  return out;
}

/** mdm.commands.relaunch. */
async function relaunchTenant(ctx: JobContext<Tenant>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
  const plan = await ctx.withTenant(async (trx) => {
    const b = await relaunchBlocked(trx, tenantId);
    if ('code' in b) return b;
    return { key: b.key, due: await dueDevices(trx, tenantId, RELAUNCH_BATCH) };
  });
  if ('code' in plan) return { output: { skipped: plan.code } };
  if (plan.due.length === 0) return { output: { pushed: 0 } };
  try {
    const res = await ctx.inTenant(() => pushAndRecord(tenantId, plan.key, plan.due, { actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal }));
    return { output: { pushed: [...res.values()].filter((o) => o === 'sent' || o === 'deferred').length, devices: plan.due.length } };
  } catch (err) {
    if (isAppleEdgeError(err)) throw new JobError('edge_unavailable', 'apple-edge did not take the push requests', err.retryable);
    throw err;
  }
}

/** mdm.commands.relaunch-all. */
async function relaunchAll(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
  let tenants = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const open = await db('mdm_command_targets').where({ tenant_id: tenantId }).whereIn('state', ['queued', 'sent', 'notnow']).first('device_id');
    if (!open) return;
    await (relaunchJob as JobHandle<Tenant>).send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
    tenants++;
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { tenants } };
}

/** Polling of the three sweeps (every 5 minutes, staggered): a run may start up to this late. */
const SWEEP_POLL_SECONDS = 120;
/** The options a schedule would default: the same queue whether APPLE_EDGE_MODE schedules the sweep or not. */
const SWEEP_OPTIONS = { deadLetter: false, trackStatus: 'queue', manualRun: true, keepFinishedSeconds: 172_800, keepPendingSeconds: 86_400 } as const;

/** A manual relaunch is refused to a target pushed less than this ago. */
const MANUAL_RELAUNCH_GAP_MS = 5 * 60_000;

/**
 * Manual relaunch of a command (§8.7): a push for its open targets, with the exclusions of the automatic
 * relaunches but the steps (one per target and per 5 minutes at most). In the tenant's database context,
 * outside any transaction.
 */
async function relaunch(tenantId: number, commandId: string, deviceIds: number[] | null, actor: string,
  opts: { auditCtx?: AuditWriteContext; requestId?: string } = {}): Promise<RelaunchOutcome> {
  const dbActor = currentDbContext()?.actor;
  const plan = await db.transaction(async (trx) => {
    const cmd = await trx('mdm_commands').where({ tenant_id: tenantId, id: commandId }).first('id', 'request_type', 'push', 'expires_at') as
      { id: string; request_type: string; push: boolean; expires_at: Date } | undefined;
    if (!cmd) return null;
    let q = trx('mdm_command_targets as t')
      .join('devices as d', function joinDevice() { this.on('d.id', '=', 't.device_id').andOn('d.tenant_id', '=', 't.tenant_id'); })
      .join('apple_devices as a', function joinSatellite() { this.on('a.device_id', '=', 't.device_id').andOn('a.tenant_id', '=', 't.tenant_id'); })
      .where({ 't.tenant_id': tenantId, 't.command_id': commandId });
    if (deviceIds) q = q.whereRaw('t.device_id = ANY (?::int[])', [deviceIds]);
    const targets = await q.select('t.device_id', 't.state', 't.pushed_at', 't.push_count', 't.enrollment_id', 'a.enrollment_id as current_enrollment_id',
      'a.push_state', 'd.enrollment_state') as Array<{ device_id: number; state: string; pushed_at: Date | null; push_count: number; enrollment_id: string;
        current_enrollment_id: string; push_state: string; enrollment_state: string }>;
    const blocked = await relaunchBlocked(trx, tenantId);
    return { cmd, targets, blocked };
  });
  if (!plan) return { pushed: 0, skipped: [] };
  const skipped: Array<{ deviceId: number; code: string }> = [];
  const due: DueDevice[] = [];
  const now = Date.now();
  for (const t of plan.targets) {
    const deviceId = Number(t.device_id);
    let code: string | null = null;
    if (!['queued', 'sent', 'notnow'].includes(t.state)) code = 'not_open';
    else if ('code' in plan.blocked) code = plan.blocked.code;
    else if (config.apple.mode !== 'on') code = 'apple_edge_off';
    else if (!plan.cmd.push || new Date(plan.cmd.expires_at).getTime() <= now) code = 'expired';
    else if (t.enrollment_id !== t.current_enrollment_id || !['enrolled', 'awaiting_configuration'].includes(t.enrollment_state)) code = 'not_enrolled';
    else if (['invalid_token', 'inactive', 'disabled'].includes(t.push_state)) code = 'push_unavailable';
    else if (Number(t.push_count) >= config.apple.pushMaxPerTarget) code = 'push_limit';
    else if (t.pushed_at && now - new Date(t.pushed_at).getTime() < MANUAL_RELAUNCH_GAP_MS) code = 'too_soon';
    if (code) skipped.push({ deviceId, code });
    else due.push({ device_id: deviceId, enrollment_id: t.enrollment_id });
  }
  let pushed = 0;
  if (due.length > 0 && 'key' in plan.blocked) {
    const res = await pushAndRecord(tenantId, plan.blocked.key, due, { actor: dbActor ? edgeActorOf(dbActor) : actor, requestId: opts.requestId });
    for (const [deviceId, o] of res) {
      if (o === 'sent' || o === 'deferred') pushed++;
      else skipped.push({ deviceId, code: `push_${o}` });
    }
    const ids = due.map((d) => d.device_id);
    const ctx = opts.auditCtx ?? (dbActor ? await audit.fromDbActor(dbActor, tenantId) : null);
    if (ctx) {
      await audit.append({
        tenantId, action: 'mdm.command_relaunched', links: { command: commandId.toLowerCase() },
        ...(ids.length === 1 ? { target: { type: 'device', id: String(ids[0]), device: ids[0] } } : { targets: { deviceIds: ids } }),
        details: { requestType: plan.cmd.request_type, pushed, skipped: skipped.length },
      }, ctx);
    }
  }
  return { pushed, skipped };
}

let registered = false;

/** The jobs of the command queue (registerAppleModule). */
export function registerCommandJobs(): void {
  if (registered) return;
  registered = true;
  // APPLE_EDGE_MODE=off: nothing is submitted nor pushed, the three sweeps are not scheduled (file-durable L3); their
  // queues exist, so an operator may still run one by hand.
  const on = config.apple.mode === 'on';
  submitJob = registerJob({
    name: SUBMIT_QUEUE,
    scope: 'tenant',
    description: 'Submit an MDM command to the device service (idempotent: same identifier, same bytes, same targets)',
    payload: SubmitPayload,
    policy: 'standard',
    retry: { limit: 8, delaySeconds: 15, backoff: true, maxDelaySeconds: 900 },
    timeoutSeconds: 60,
    notify: true,
    // Woken by NOTIFY for a command to submit now; the poll picks up the deferred ones (not_before) and the retries.
    pollSeconds: 60,
    concurrency: { local: 2, perTenant: 2 },
    redrivable: true,
    handler: submit,
  });
  cancelJob = registerJob({
    name: CANCEL_QUEUE,
    scope: 'tenant',
    description: 'Ask the device service to drop the targets of a cancelled MDM command',
    payload: CancelPayload,
    policy: 'standard',
    retry: { limit: 5, delaySeconds: 15, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 60,
    notify: true,
    pollSeconds: 300,
    handler: cancelJobHandler,
  });
  resubmitJob = registerJob({
    name: RESUBMIT_QUEUE,
    scope: 'tenant',
    description: 'Submit again the held MDM commands of a tenant once their cause is gone (unfreeze, device service back)',
    payload: TenantPayload,
    policy: 'exclusive',
    retry: { limit: 3, delaySeconds: 30, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 300,
    notify: true,
    pollSeconds: 300,
    handler: resubmitHeld,
  });
  resubmitAllJob = registerJob({
    name: 'mdm.commands.resubmit-all',
    scope: 'platform',
    description: 'Every 5 minutes: the tenants that have held MDM commands',
    payload: Empty,
    policy: 'exclusive',
    ...(on ? { schedule: { cron: '*/5 * * * *' } } : {}),
    retry: { limit: 0, delaySeconds: 0, backoff: false },
    timeoutSeconds: 240,
    pollSeconds: SWEEP_POLL_SECONDS,
    ...SWEEP_OPTIONS,
    handler: resubmitAll,
  });
  relaunchJob = registerJob({
    name: RELAUNCH_QUEUE,
    scope: 'tenant',
    description: 'Relaunch the push of the devices of a tenant whose MDM commands stay undelivered or unanswered',
    payload: TenantPayload,
    policy: 'exclusive',
    retry: { limit: 1, delaySeconds: 60, backoff: false },
    timeoutSeconds: 300,
    notify: true,
    pollSeconds: 300,
    handler: relaunchTenant,
  });
  registerJob({
    name: 'mdm.commands.relaunch-all',
    scope: 'platform',
    description: 'Every 5 minutes: the tenants with open MDM command targets to relaunch',
    payload: Empty,
    policy: 'exclusive',
    ...(on ? { schedule: { cron: '2-59/5 * * * *' } } : {}),
    retry: { limit: 0, delaySeconds: 0, backoff: false },
    timeoutSeconds: 240,
    pollSeconds: SWEEP_POLL_SECONDS,
    ...SWEEP_OPTIONS,
    handler: relaunchAll,
  });
  registerJob({
    name: 'mdm.commands.expire-pending',
    scope: 'platform',
    description: 'Every 5 minutes: expire the MDM commands never submitted whose expiry passed',
    payload: Empty,
    policy: 'exclusive',
    ...(on ? { schedule: { cron: '4-59/5 * * * *' } } : {}),
    retry: { limit: 0, delaySeconds: 0, backoff: false },
    timeoutSeconds: 240,
    pollSeconds: SWEEP_POLL_SECONDS,
    ...SWEEP_OPTIONS,
    handler: expirePending,
  });
  bindCommandJobs({ submit: submitJob, cancel: cancelJob, relaunch });
}
