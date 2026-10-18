// Submission and follow-up of the Android commands (section 11.3, AN50):
//   android.commands.submit (one command, stately)
//     T1 (committed BEFORE the call): the command still pending, not expired, not cancelled; tenant frozen and command
//        destructive → held (frozen); otherwise the AN50 mark amapi_submit_started_at (refreshed before a new issue).
//     A mark already there without an operation (the instance stopped between the call and T2): the operations of the
//        device are listed without a filter (pagination, listOperations: never exposed to a route, AMAPI-R16) and the
//        one of the same type created since the mark minus 5 s is adopted; none: issued again. Only type, device and
//        time are compared: no fingerprint of a body that carries a secret is stored (§22.9).
//     issueCommand (outside any transaction): the body of amapi_command, its duration set to what remains of the
//        command's life, newPassword opened from secret_enc in memory only (the buffer zeroed after the call).
//     T2: the operation, 'sent', delivered_at, secret_enc = NULL (the password then exists only at Google and on the
//        device), first poll in 2 minutes.
//     Refusals: frozen (AndroidFrozenError) → held frozen; last-resort cap (AndroidDestructiveCapError) → held
//        gateway_cap (the gateway froze the tenant, A1); 400, 404, ownership, access lost → rejected; Google out of
//        reach (429, 5xx, cut, delay) → the job tries again and the recovery above runs (never a blind retry).
//   android.operations-poll (one tenant): operations sent and due (2, 7, 12, 15 minutes, 1 h, 6 h, then every 6 h),
//     expiry of what is past its end (pending never issued: expired; sent: a last read, then expired).
//   amapi.command (inbox handler): the final state of the operation a COMMAND notification carries, in the event's
//     transaction; an operation not yet recorded while a submission of the device is in flight: missing prerequisite
//     (retried), any other unknown operation: nothing.
import type { Knex } from 'knex';
import { audit } from '../../audit';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { readSettings } from '../../guard/settings';
import { findSecretRefs, vault } from '../../vault';
import { logger } from '../../utils/logger';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { commandAdmitted } from '../gateway/commandStates';
import { AndroidError } from '../gateway/errors';
import { parseOwnedName, type AndroidEnterpriseRef } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { MissingPrerequisite, registerAndroidEventHandler, type AndroidEventContext } from '../inbox/handlers';
import { OperationSchema } from '../inbox/schemas';
import type { z } from 'zod';
import { adoptableOperations, ANDROID_COMMANDS, finalStateOf, nextPollAt, withDuration, type AndroidCommandType } from './catalog';
import {
  cancelSent, COMMAND_COLUMNS, COMMAND_SECRET_COLUMN, commandSenders, finalizeCommand, type CommandRow,
} from './bus';

export const SUBMIT_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.commands.submit' }) as DbActor;
export const POLL_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.operations-poll' }) as DbActor;
/** Pages of listOperations read by one recovery at most (100 operations a page). */
const RECOVERY_MAX_PAGES = 20;

export type SubmitResult = 'sent' | 'adopted' | 'held' | 'rejected' | 'expired' | 'cancelled' | 'skipped';

const deviceIdOf = (e: AndroidEnterpriseRef, name: string): string => {
  const p = parseOwnedName(e, name);
  if (p.kind !== 'device') throw new Error('android: malformed device name');
  return p.deviceId;
};

async function readRow(trx: Knex.Transaction, tenantId: number, id: string, lock = true): Promise<CommandRow | undefined> {
  const q = trx('android_commands').where({ tenant_id: tenantId, id }).first(COMMAND_COLUMNS);
  if (lock) q.forUpdate();
  return q as unknown as Promise<CommandRow | undefined>;
}

/** Records the operation Google returned (T2): 'sent', the secret wiped. False when the command changed meanwhile. */
async function recordOperation(tenantId: number, id: string, operation: string): Promise<boolean> {
  const now = new Date();
  return db.transaction(async (trx) => {
    const n = await trx('android_commands').where({ tenant_id: tenantId, id, state: 'pending' }).whereNull('amapi_operation').update({
      state: 'sent', submit_state: 'submitted', hold_reason: null, amapi_operation: operation, delivered_at: now, secret_enc: null,
      next_poll_at: nextPollAt(now, 0), poll_count: 0, state_event_at: now, last_submit_error: null, updated_at: now,
    });
    return n === 1;
  });
}

async function hold(tenantId: number, id: string, reason: 'frozen' | 'gateway_cap' | 'google_unavailable', clearMark: boolean): Promise<void> {
  await db.transaction((trx) => trx('android_commands').where({ tenant_id: tenantId, id, state: 'pending' }).update({
    submit_state: 'held', hold_reason: reason, updated_at: trx.fn.now(), ...(clearMark ? { amapi_submit_started_at: null } : {}),
  }));
}

/** Lists the operations of a device (AN50 recovery only), every page up to the bound. */
async function listDeviceOperations(gw: AndroidGateway, e: AndroidEnterpriseRef, deviceId: string) {
  const all = [];
  let pageToken: string | undefined;
  for (let i = 0; i < RECOVERY_MAX_PAGES; i++) {
    const page = await gw.listOperations(e, deviceId, pageToken);
    all.push(...page.items);
    if (!page.nextPageToken) return all;
    pageToken = page.nextPageToken;
  }
  return all;
}

/** android.commands.submit for one command. */
export async function submitAndroidCommand(tenantId: number, commandId: string, o: { gateway?: AndroidGateway; now?: () => Date } = {}): Promise<SubmitResult> {
  const gw = o.gateway ?? androidGateway();
  const clock = o.now ?? (() => new Date());
  const id = commandId.toLowerCase();
  return asTenant(tenantId, SUBMIT_ACTOR, async () => {
    // T1, committed before any call.
    const t1 = await db.transaction(async (trx) => {
      const row = await readRow(trx, tenantId, id);
      if (!row || row.state !== 'pending' || row.amapi_operation) return { kind: 'skip' as const };
      if (row.submit_state === 'held' && row.hold_reason === 'gateway_cap') return { kind: 'skip' as const };
      const e = await readEnterprise(trx);
      const mark = row.amapi_submit_started_at ? new Date(row.amapi_submit_started_at) : null;
      // A mark without an operation: the recovery comes first, whatever the expiry or the cancellation (an
      // operation may exist at Google).
      if (mark) {
        if (row.submit_state === 'held') await trx('android_commands').where({ tenant_id: tenantId, id }).update({ submit_state: 'pending', hold_reason: null });
        return { kind: 'recover' as const, row, e, mark };
      }
      if (row.cancel_requested_at) {
        await finalizeCommand(trx, row, { state: 'cancelled' });
        return { kind: 'done' as const, result: 'cancelled' as const };
      }
      if (new Date(row.expires_at).getTime() <= clock().getTime()) {
        await finalizeCommand(trx, row, { state: 'expired' });
        return { kind: 'done' as const, result: 'expired' as const };
      }
      if (!e || !commandAdmitted(row.request_type, e.state) || e.id !== Number(row.enterprise_id)) {
        await finalizeCommand(trx, row, { state: 'rejected', rejectCode: 'enterprise_not_linked' });
        return { kind: 'done' as const, result: 'rejected' as const };
      }
      if (row.params?.passwordSealed === true && !row.secret_enc) {
        await finalizeCommand(trx, row, { state: 'rejected', rejectCode: 'secret_lost' });
        return { kind: 'done' as const, result: 'rejected' as const };
      }
      if (ANDROID_COMMANDS[row.request_type].destructive && (await readSettings(tenantId, trx)).frozen_at) {
        await trx('android_commands').where({ tenant_id: tenantId, id }).update({ submit_state: 'held', hold_reason: 'frozen', updated_at: trx.fn.now() });
        return { kind: 'done' as const, result: 'held' as const };
      }
      const at = clock();
      await trx('android_commands').where({ tenant_id: tenantId, id }).update({
        amapi_submit_started_at: at, submit_state: 'pending', hold_reason: null, submit_attempts: trx.raw('submit_attempts + 1'), updated_at: trx.fn.now(),
      });
      return { kind: 'issue' as const, row, e };
    });
    if (t1.kind === 'skip') return 'skipped';
    if (t1.kind === 'done') return t1.result;
    if (!t1.e) return 'skipped';
    const e = t1.e;
    const row = t1.row;
    const device = deviceIdOf(e, row.enrollment_id);

    if (t1.kind === 'recover') {
      const candidates = adoptableOperations(await listDeviceOperations(gw, e, device), row.request_type, t1.mark);
      // An operation another command already recorded is never adopted (a command of the same type finished just
      // before this one was written: the residue AN-RC4 narrowed to the operations nobody owns).
      const owned = candidates.length
        ? new Set(await db('android_commands').whereIn('amapi_operation', candidates.map((c) => c.name)).pluck('amapi_operation') as string[])
        : new Set<string>();
      const ops = candidates.filter((c) => !owned.has(c.name))
        .sort((a, b) => Date.parse(String(a.metadata?.createTime)) - Date.parse(String(b.metadata?.createTime)));
      if (ops.length) {
        const adopted = await recordOperation(tenantId, id, ops[0].name);
        logger.info({ android: { command: id, tenantId, recovery: 'adopted', candidates: ops.length } }, 'android: interrupted command adopted');
        if (adopted && row.cancel_requested_at) {
          const fresh = await db.transaction((trx) => readRow(trx, tenantId, id, false));
          if (fresh) await cancelSent(tenantId, fresh, fresh.actor, gw);
        }
        return 'adopted';
      }
      // None at Google: the command was never issued. Cancelled or expired meanwhile: closed here; otherwise issued
      // again under a fresh mark.
      const again = await db.transaction(async (trx) => {
        const cur = await readRow(trx, tenantId, id);
        if (!cur || cur.state !== 'pending' || cur.amapi_operation) return 'skipped' as const;
        if (cur.cancel_requested_at) { await finalizeCommand(trx, cur, { state: 'cancelled' }); return 'cancelled' as const; }
        if (new Date(cur.expires_at).getTime() <= clock().getTime()) { await finalizeCommand(trx, cur, { state: 'expired' }); return 'expired' as const; }
        if (ANDROID_COMMANDS[cur.request_type].destructive && (await readSettings(tenantId, trx)).frozen_at) {
          await trx('android_commands').where({ tenant_id: tenantId, id }).update({ submit_state: 'held', hold_reason: 'frozen', amapi_submit_started_at: null, updated_at: trx.fn.now() });
          return 'held' as const;
        }
        await trx('android_commands').where({ tenant_id: tenantId, id }).update({
          amapi_submit_started_at: clock(), submit_attempts: trx.raw('submit_attempts + 1'), updated_at: trx.fn.now(),
        });
        return 'issue' as const;
      });
      if (again !== 'issue') return again;
    }

    // The call, outside any transaction.
    let secret: Buffer | null = null;
    try {
      if (row.secret_enc) secret = await vault.open({ ...COMMAND_SECRET_COLUMN, pk: id, tenantId }, row.secret_enc, { requestTenantId: tenantId });
      const remaining = (new Date(row.expires_at).getTime() - clock().getTime()) / 1000;
      const body = withDuration(row.amapi_command, remaining) as { type: AndroidCommandType; duration: string; [k: string]: unknown };
      if (secret) body.newPassword = secret.toString('utf8');
      let operation: string;
      try {
        ({ operation } = await gw.issueCommand(e, device, body));
      } finally {
        if (secret) delete body.newPassword;
      }
      const recorded = await recordOperation(tenantId, id, operation);
      if (!recorded) return 'skipped';
      const fresh = await db.transaction((trx) => readRow(trx, tenantId, id, false));
      if (fresh?.cancel_requested_at) await cancelSent(tenantId, fresh, fresh.actor, gw);
      return 'sent';
    } catch (err) {
      if (!(err instanceof AndroidError)) throw err;
      if (err.kind === 'frozen') { await hold(tenantId, id, 'frozen', true); return 'held'; }
      if (err.kind === 'destructive_cap') { await hold(tenantId, id, 'gateway_cap', true); return 'held'; }
      if (err.kind === 'request' || err.kind === 'not_found' || err.kind === 'ownership' || err.kind === 'access_lost' || err.kind === 'disabled') {
        const code = err.kind === 'request' ? 'amapi_rejected' : err.kind;
        await db.transaction(async (trx) => {
          const cur = await readRow(trx, tenantId, id);
          if (cur) await finalizeCommand(trx, cur, { state: 'rejected', rejectCode: code });
        });
        return 'rejected';
      }
      // Google out of reach: the call may have reached it. The mark stays; the job tries again through the recovery.
      await db.transaction((trx) => trx('android_commands').where({ tenant_id: tenantId, id })
        .update({ last_submit_error: err.kind.slice(0, 64), updated_at: trx.fn.now() }));
      throw err;
    } finally {
      secret?.fill(0);
    }
  });
}

// ── Polling and expiry ────────────────────────────────────────────────────────

export interface PollResult { polled: number; finished: number; expired: number; resubmitted: number }

/** android.operations-poll for one tenant. */
export async function pollAndroidOperations(tenantId: number, o: { gateway?: AndroidGateway; now?: () => Date; limit?: number } = {}): Promise<PollResult> {
  const gw = o.gateway ?? androidGateway();
  const clock = o.now ?? (() => new Date());
  const out: PollResult = { polled: 0, finished: 0, expired: 0, resubmitted: 0 };
  return asTenant(tenantId, POLL_ACTOR, async () => {
    const now = clock();
    // Pending past their end: never issued → expired; issued (a mark): the submission recovers or expires them.
    out.expired += await db.transaction(async (trx) => {
      const rows = await trx('android_commands').where({ tenant_id: tenantId, state: 'pending' }).where('expires_at', '<=', now)
        .limit(500).forUpdate().select(COMMAND_COLUMNS) as CommandRow[];
      let n = 0;
      for (const r of rows) {
        if (r.amapi_submit_started_at) { await commandSenders.submit(trx, { tenantId, commandId: r.id }); out.resubmitted += 1; continue; }
        if (await finalizeCommand(trx, r, { state: 'expired' })) n += 1;
      }
      return n;
    });
    const due = await db('android_commands').where({ tenant_id: tenantId, state: 'sent' })
      .where((q) => q.where('next_poll_at', '<=', now).orWhere('expires_at', '<=', now))
      .orderBy('next_poll_at').limit(o.limit ?? 100).select(COMMAND_COLUMNS) as CommandRow[];
    if (!due.length) return out;
    const e = await readEnterprise();
    if (!e) return out;
    for (const r of due) {
      let op = null;
      try {
        op = await gw.getOperation(e, String(r.amapi_operation));
      } catch (err) {
        if (!(err instanceof AndroidError) || err.retryable) throw err;
      }
      out.polled += 1;
      const final = finalStateOf(op, { cancelRequested: !!r.cancel_requested_at });
      const expired = new Date(r.expires_at).getTime() <= now.getTime();
      await db.transaction(async (trx) => {
        if (final) {
          if (await finalizeCommand(trx, r, { state: final.state, errorCode: final.errorCode })) out.finished += 1;
        } else if (expired || op === null) {
          // past its end without execution (or vanished at Google): expired [NV: form of an expired operation, AN-J]
          if (await finalizeCommand(trx, r, { state: 'expired' })) out.expired += 1;
        } else {
          const count = Number(r.poll_count) + 1;
          const next = nextPollAt(new Date(r.delivered_at ?? now), count);
          const end = new Date(r.expires_at);
          await trx('android_commands').where({ tenant_id: tenantId, id: r.id, state: 'sent' }).update({
            poll_count: count, next_poll_at: next.getTime() > end.getTime() ? end : next, updated_at: trx.fn.now(),
          });
        }
      });
    }
    return out;
  });
}

/**
 * Held commands to submit again (android.maintenance; at the junction, also the Android handler of the freeze list of
 * actions.freeze-sync): held frozen while the tenant is no longer frozen, held google_unavailable. Held gateway_cap
 * stay held: the operator releases them (releaseHeldCommand) once the freeze A1 is lifted.
 */
export async function resumeHeldCommands(tenantId: number, actor: DbActor = POLL_ACTOR): Promise<number> {
  return asTenant(tenantId, actor, () => db.transaction(async (trx) => {
    const frozen = !!(await readSettings(tenantId, trx)).frozen_at;
    const q = trx('android_commands').where({ tenant_id: tenantId, state: 'pending', submit_state: 'held' });
    if (frozen) q.where({ hold_reason: 'google_unavailable' }); else q.whereIn('hold_reason', ['frozen', 'google_unavailable']);
    const ids = await q.forUpdate().limit(500).pluck('id') as string[];
    for (const id of ids) {
      await trx('android_commands').where({ tenant_id: tenantId, id }).update({ submit_state: 'pending', hold_reason: null, updated_at: trx.fn.now() });
      await commandSenders.submit(trx, { tenantId, commandId: String(id) });
    }
    return ids.length;
  }));
}

/** The operator releases a command held by the last-resort cap (gateway_cap), the tenant no longer frozen. */
export async function releaseHeldCommand(tenantId: number, commandId: string, actor: DbActor): Promise<'released' | 'not_held' | 'frozen'> {
  return asTenant(tenantId, actor, () => db.transaction(async (trx) => {
    if ((await readSettings(tenantId, trx)).frozen_at) return 'frozen' as const;
    const n = await trx('android_commands').where({ tenant_id: tenantId, id: commandId.toLowerCase(), state: 'pending', submit_state: 'held', hold_reason: 'gateway_cap' })
      .update({ submit_state: 'pending', hold_reason: null, updated_at: trx.fn.now() });
    if (n !== 1) return 'not_held' as const;
    await commandSenders.submit(trx, { tenantId, commandId: commandId.toLowerCase() });
    // Review AN-D1: the release of a command the last-resort cap held is traced (who, which command).
    const c = await trx('android_commands').where({ tenant_id: tenantId, id: commandId.toLowerCase() }).first('device_id', 'request_type', 'guard_action_uuid') as
      { device_id: number; request_type: string; guard_action_uuid: string | null };
    await audit.appendInTx(trx, {
      tenantId, action: 'android.command_released', target: { type: 'device', id: String(c.device_id), device: Number(c.device_id) },
      links: { command: commandId.toLowerCase(), ...(c.guard_action_uuid ? { action: c.guard_action_uuid } : {}) },
      details: { channel: 'amapi', requestType: c.request_type, holdReason: 'gateway_cap' },
    }, await audit.fromDbActor(actor, tenantId), { onFailure: 'spool' });
    return 'released' as const;
  }));
}

/** Pending commands not submitted for 2 minutes (a lost job, an interrupted submission): their job again. */
export async function resubmitStaleCommands(tenantId: number, actor: DbActor = POLL_ACTOR): Promise<number> {
  return asTenant(tenantId, actor, () => db.transaction(async (trx) => {
    const ids = await trx('android_commands').where({ tenant_id: tenantId, state: 'pending', submit_state: 'pending' })
      .where('updated_at', '<', trx.raw("now() - interval '2 minutes'")).limit(500).pluck('id') as string[];
    for (const id of ids) await commandSenders.submit(trx, { tenantId, commandId: String(id) });
    return ids.length;
  }));
}

/**
 * The newPassword secrets of mdm.reset_password (tenant_secrets, purpose android.reset_password) that no open
 * guarded action holds any more (refused, expired, cancelled, failed, done): destroyed (section 11.4). The execution
 * destroys its own once sealed in the command; this sweep covers the other ends of an action.
 */
export async function sweepResetPasswordSecrets(tenantId: number, actor: DbActor = POLL_ACTOR): Promise<number> {
  return asTenant(tenantId, actor, () => db.transaction(async (trx) => {
    const secrets = await trx('tenant_secrets').where({ tenant_id: tenantId, purpose: RESET_PASSWORD_PURPOSE })
      .where('created_at', '<', trx.raw("now() - interval '5 minutes'")).pluck('id') as string[];
    if (!secrets.length) return 0;
    const open = await trx('pending_actions').where({ tenant_id: tenantId })
      .whereIn('state', ['awaiting_approval', 'scheduled', 'paused', 'executing']).pluck('params') as unknown[];
    const held = new Set(open.flatMap((p) => findSecretRefs(p)));
    const gone = secrets.filter((s) => !held.has(String(s)));
    if (gone.length) await trx('tenant_secrets').where({ tenant_id: tenantId }).whereIn('id', gone).delete();
    return gone.length;
  }));
}

export const RESET_PASSWORD_PURPOSE = 'android.reset_password';

// ── COMMAND notifications ─────────────────────────────────────────────────────

async function onCommand(ctx: AndroidEventContext<z.infer<typeof OperationSchema>>): Promise<void> {
  const op = ctx.event.payload;
  const row = await ctx.trx('android_commands').where({ tenant_id: ctx.tenantId, amapi_operation: op.name }).forUpdate().first(COMMAND_COLUMNS) as CommandRow | undefined;
  if (!row) {
    // The notification may arrive before T2 of the submission: a submission of this device in flight → retried.
    const device = op.name.split('/operations/')[0];
    const inFlight = await ctx.trx('android_commands').where({ tenant_id: ctx.tenantId, enrollment_id: device, state: 'pending' })
      .whereNotNull('amapi_submit_started_at').whereNull('amapi_operation')
      .modify((q) => { if (op.metadata?.type) q.where({ request_type: op.metadata.type }); }).first('id');
    if (inFlight) throw new MissingPrerequisite('operation not recorded yet');
    return;
  }
  if (row.state !== 'sent') return;
  const final = finalStateOf(op, { cancelRequested: !!row.cancel_requested_at });
  if (!final) return;
  await finalizeCommand(ctx.trx, row, { state: final.state, errorCode: final.errorCode });
}

let registered = false;

export function registerCommandHandler(): void {
  if (registered) return;
  registered = true;
  registerAndroidEventHandler({ type: 'amapi.command', payload: OperationSchema, async handle(ctx) { await onCommand(ctx); } });
}
