// Delayed execution of the guarded actions (docs: audit-durci §10.5) and the
// other jobs of the engine.
//
// Execution (job actions.execute-delayed, in the tenant's context, actor
// j:actions.execute-delayed, X-Request-ID job-<id>):
//   1. revalidation, the row locked: still scheduled and still this job's;
//      not frozen (else paused, 'frozen'); the requester active and keeping
//      their rights on each target; the hourly cap (else paused, 'cap', and
//      an anomaly); the action's own revalidation per target. Targets set
//      aside are listed in the result; none left: refused. Then 'executing'
//      with its entry guard.action_executing (P1: targets and, when the
//      action gives them, serial numbers, J29), committed;
//   2. execution OUTSIDE any transaction (calls to apple-edge allowed),
//      idempotent: a run found 'executing' (crash) runs it again;
//   3. 'done', 'partial' or 'failed', executed_at, result, then the entry
//      guard.action_executed (P3).
import type { Knex } from 'knex';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit, type AuditEntryInput, type AuditWriteContext } from '../audit';
import { db } from '../db';
import { asIdentity, asNone, asTenant } from '../db/context';
import { forEachTenant } from '../db/tenantContext';
import { JobError, type JobContext, type JobResult } from '../jobs';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';
import { quotaOf } from './cap';
import { edgeFreezeOf, guardedActionDef } from './catalog';
import { guardMetrics } from './metrics';
import { alertTenantAndMsp, alertTenants, notifyAction } from './notify';
import { personFacts } from './people';
import { capAllows } from './policy';
import { checkAnomalies } from './refusals';
import { targetsWithoutRights } from './selection';
import { readSettings } from './settings';
import { ACTION_COLUMNS, findAction, normaliseRow, toDto, toDtos, type PendingActionRow } from './store';
import type { GuardExecutionContext, GuardResultSummary, GuardTargetResult, GuardedActionDef } from './types';

const MAX_LISTED = 200;

/** The execution context of an action for its definition's hooks. */
export function executionContext(row: PendingActionRow, deviceIds: number[], o: { requestId: string; actor: string; signal?: AbortSignal }):
  GuardExecutionContext<any> {
  return {
    tenantId: row.tenant_id,
    actionUuid: row.uuid,
    actionKey: row.action_key,
    params: row.params,
    requesterId: row.requested_by,
    approvalIds: row.approval_id ? [row.approval_id] : [],
    reason: row.reason,
    ticket: row.ticket,
    deviceIds,
    requestId: o.requestId,
    actor: o.actor,
    signal: o.signal,
  };
}

/** Common fields of the entries of an action. */
export function actionEntry(row: PendingActionRow, action: string, extra: Partial<AuditEntryInput> = {}): AuditEntryInput {
  return {
    tenantId: row.tenant_id,
    action,
    links: { action: row.uuid },
    reason: row.reason,
    ticket: row.ticket ?? undefined,
    ...(row.approval_id ? { approvalIds: [row.approval_id] } : {}),
    ...(row.requester_side === 'msp' && row.tenant_id !== MASTER_TENANT_ID ? { onBehalfOf: row.tenant_id } : {}),
    ...extra,
    details: { actionKey: row.action_key, family: row.family, requestedBy: row.requested_by, ...(extra.details ?? {}) },
  };
}

type Step =
  | { kind: 'skip'; why: string }
  | { kind: 'paused'; row: PendingActionRow; code: 'frozen' | 'cap' }
  | { kind: 'refused'; row: PendingActionRow; code: string; summary: GuardResultSummary }
  | { kind: 'execute'; row: PendingActionRow; def: GuardedActionDef<any>; retained: number[]; summary: GuardResultSummary };

/** The retained targets of an action found 'executing' (a run after a crash). */
function retainedOf(row: PendingActionRow): number[] {
  const r = (row.result as { retained?: unknown } | null)?.retained;
  return Array.isArray(r) ? r.map(Number).filter((n) => Number.isSafeInteger(n) && n > 0) : row.target_device_ids;
}

async function closeRefused(trx: Knex.Transaction, row: PendingActionRow, code: string, summary: GuardResultSummary): Promise<Step> {
  await trx('pending_actions').where({ id: row.id }).update({
    state: 'refused', result: JSON.stringify({ ...summary, code }), updated_at: new Date(),
  });
  return { kind: 'refused', row, code, summary };
}

/** Step 1, in one transaction of the tenant, the row locked. */
async function revalidate(trx: Knex.Transaction, ctx: JobContext<{ tenantId: number; actionUuid: string }>, auditCtx: AuditWriteContext): Promise<Step> {
  const tenantId = ctx.tenantId as number;
  const row = await findAction(ctx.payload.actionUuid, { trx, forUpdate: true, tenantId });
  if (!row) return { kind: 'skip', why: 'not_found' };
  if (row.job_id && row.job_id.toLowerCase() !== ctx.jobId.toLowerCase()) return { kind: 'skip', why: 'superseded' };
  const def = guardedActionDef(row.action_key);
  if (row.state === 'executing') {
    if (!def) return { kind: 'skip', why: 'unknown_action' };
    return { kind: 'execute', row, def, retained: retainedOf(row), summary: (row.result ?? { done: 0, failed: 0, skipped: 0 }) as GuardResultSummary };
  }
  if (row.state !== 'scheduled') return { kind: 'skip', why: row.state };
  const empty: GuardResultSummary = { done: 0, failed: 0, skipped: 0 };
  if (!def) return closeRefused(trx, row, 'unknownAction', empty);

  const settings = await readSettings(tenantId, trx);
  if (settings.frozen_at) {
    await trx('pending_actions').where({ id: row.id }).update({ state: 'paused', paused_at: new Date(), updated_at: new Date() });
    return { kind: 'paused', row, code: 'frozen' };
  }
  const requester = await personFacts(row.requested_by, tenantId);
  if (!requester.exists || !requester.active) return closeRefused(trx, row, 'requesterInactive', empty);

  const setAside: Array<{ id: number; code: string }> = [];
  const lacking = new Set(await targetsWithoutRights(def, row.requested_by, requester.platformAdmin, tenantId, row.target_device_ids));
  for (const id of lacking) setAside.push({ id, code: 'rights' });
  let candidates = row.target_device_ids.filter((id) => !lacking.has(id));

  if (def.hourlyCap && candidates.length) {
    const quota = await quotaOf(tenantId, { trx, excludeUuid: row.uuid });
    if (!capAllows(quota.cap, quota.used, candidates.length)) {
      await trx('pending_actions').where({ id: row.id }).update({ state: 'paused', paused_at: new Date(), updated_at: new Date() });
      return { kind: 'paused', row, code: 'cap' };
    }
  }
  if (candidates.length) {
    const checked = await def.revalidate(executionContext(row, candidates, { requestId: ctx.requestId, actor: ctx.actor, signal: ctx.signal }));
    const kept: number[] = [];
    for (const id of candidates) {
      const v = checked.get(id);
      if (v === 'ok') kept.push(id);
      else setAside.push({ id, code: v && typeof v === 'object' && typeof v.code === 'string' ? v.code.slice(0, 64) : 'revalidation' });
    }
    candidates = kept;
  }
  const summary: GuardResultSummary = { done: 0, failed: 0, skipped: setAside.length, ...(setAside.length ? { setAside: setAside.slice(0, MAX_LISTED) } : {}) };
  if (!candidates.length) return closeRefused(trx, row, 'noTargets', summary);

  const serials = def.serialsOf ? await def.serialsOf(tenantId, candidates) : null;
  await trx('pending_actions').where({ id: row.id }).update({
    state: 'executing', result: JSON.stringify({ ...summary, retained: candidates }), updated_at: new Date(),
  });
  // P1, last statement: the execution and its entry, or neither.
  await audit.appendInTx(trx, actionEntry(row, 'guard.action_executing', {
    outcome: 'requested',
    targets: { deviceIds: candidates, ...(serials ? { serials: candidates.map((id) => serials.get(id) ?? '') } : {}) },
    details: { params: row.params, setAside: setAside.length, delaySeconds: row.delay_seconds },
  }), auditCtx);
  return { kind: 'execute', row: { ...row, state: 'executing' }, def, retained: candidates, summary };
}

/** Steps 3: the final state and its entry. */
async function finish(tenantId: number, row: PendingActionRow, retained: number[], before: GuardResultSummary,
  results: Map<number, GuardTargetResult> | null, failure: string | null, auditCtx: AuditWriteContext): Promise<PendingActionRow> {
  let done = 0;
  let failed = 0;
  let skipped = Number(before.skipped) || 0;
  const failures: Array<{ id: number; code: string }> = [];
  for (const id of retained) {
    const r = results?.get(id);
    if (r && (r.status === 'done' || r.status === 'queued')) done++;
    else if (r && r.status === 'skipped') { skipped++; failures.push({ id, code: (r.code ?? 'skipped').slice(0, 64) }); }
    else { failed++; failures.push({ id, code: (r?.code ?? failure ?? 'not_executed').slice(0, 64) }); }
  }
  const state = done === 0 ? 'failed' : (failed > 0 || skipped > 0 ? 'partial' : 'done');
  const summary: GuardResultSummary = {
    done, failed, skipped,
    ...(before.setAside ? { setAside: before.setAside } : {}),
    ...(failures.length ? { failures: failures.slice(0, MAX_LISTED) } : {}),
  };
  await asTenant(tenantId, { type: 'job', name: 'actions.execute-delayed' }, () => db('pending_actions').where({ id: row.id })
    .update({ state, executed_at: new Date(), result: JSON.stringify(summary), updated_at: new Date() }));
  // P3: after the fact.
  await asTenant(tenantId, { type: 'job', name: 'actions.execute-delayed' }, () => audit.append(actionEntry(row, 'guard.action_executed', {
    outcome: state === 'failed' ? 'failure' : 'success',
    details: { state, done, failed, skipped, ...(failure ? { error: failure } : {}) },
  }), auditCtx));
  guardMetrics.inc('obligarth_guard_executions_total', { action: row.action_key, state });
  return { ...row, state, result: summary, executed_at: new Date() };
}

/** actions.execute-delayed. */
export async function executeDelayed(ctx: JobContext<{ tenantId: number; actionUuid: string }>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const auditCtx = audit.fromJob({ name: ctx.name, requestId: ctx.requestId });
  const step = await ctx.withTenant((trx) => revalidate(trx, ctx, auditCtx));
  if (step.kind === 'skip') return { output: { skipped: step.why } };
  if (step.kind === 'paused') {
    // P4: the pause stands whatever the journal says.
    await ctx.inTenant(() => audit.append(actionEntry(step.row, 'guard.action_paused', { outcome: 'success', details: { code: step.code } }), auditCtx));
    const fresh = await ctx.inTenant(() => findAction(step.row.uuid, { tenantId }));
    if (fresh) await ctx.inTenant(async () => notifyAction(await toDto(fresh), { code: step.code }));
    if (step.code === 'cap') {
      guardMetrics.inc('obligarth_guard_refusals_total', { code: 'hourlyCapExceeded' });
      await checkAnomalies(tenantId);
    }
    return { output: { paused: step.code } };
  }
  if (step.kind === 'refused') {
    await ctx.inTenant(() => audit.append(actionEntry(step.row, 'guard.action_refused', {
      outcome: 'denied', details: { code: step.code, setAside: step.summary.skipped },
    }), auditCtx));
    const fresh = await ctx.inTenant(() => findAction(step.row.uuid, { tenantId }));
    if (fresh) await ctx.inTenant(async () => notifyAction(await toDto(fresh), { code: step.code }));
    return { output: { refused: step.code } };
  }
  await ctx.inTenant(async () => notifyAction(await toDto(step.row)));
  ctx.throwIfAborted();
  let results: Map<number, GuardTargetResult> | null = null;
  let failure: string | null = null;
  try {
    results = await ctx.inTenant(() => step.def.execute(
      executionContext(step.row, step.retained, { requestId: ctx.requestId, actor: ctx.actor, signal: ctx.signal }), step.retained));
  } catch (err) {
    // Retried while attempts remain (the execution is idempotent); then failed.
    if (!ctx.isLastAttempt) throw err;
    failure = err instanceof JobError ? err.code : 'execution_failed';
    logger.error({ err: safeErr(err), action: step.row.action_key, uuid: step.row.uuid }, 'guard: execution failed on its last attempt');
  }
  const final = await finish(tenantId, step.row, step.retained, step.summary, results, failure, auditCtx);
  await ctx.inTenant(async () => notifyAction(await toDto(final)));
  return { output: { state: final.state, done: final.result?.done ?? 0, failed: final.result?.failed ?? 0 } };
}

/** actions.expire-paused: pauses older than 24 h expire; an action still
 *  awaiting an approval that was closed meanwhile follows it. */
export async function expirePaused(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  const auditCtx = audit.fromJob({ name: ctx.name, requestId: ctx.requestId });
  let expired = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const rows = await db('pending_actions').where({ tenant_id: tenantId, state: 'paused' })
      .andWhere('paused_at', '<', db.raw("now() - interval '24 hours'"))
      .update({ state: 'expired', updated_at: new Date() }).returning(ACTION_COLUMNS) as Array<Record<string, unknown>>;
    // A request closed without its hook having closed the action (a crash in
    // between); an approved request whose execution failed, after an hour.
    const stale = await db('pending_actions as a').join('pending_approvals as p', 'p.id', 'a.approval_id')
      .where({ 'a.tenant_id': tenantId, 'a.state': 'awaiting_approval' })
      .andWhere((q) => q.whereIn('p.status', ['denied', 'cancelled', 'expired'])
        .orWhere((q2) => q2.where('p.status', 'approved').andWhere('p.reviewed_at', '<', db.raw("now() - interval '1 hour'"))))
      .select('a.uuid', 'p.status') as Array<{ uuid: string; status: string }>;
    for (const r of rows.map(normaliseRow)) {
      expired++;
      await audit.append(actionEntry(r, 'guard.action_expired', { outcome: 'success', details: { code: 'pause_expired' } }), auditCtx);
      await notifyAction(await toDto(r));
    }
    for (const s of stale) {
      const status = s.status === 'denied' ? 'denied' : s.status === 'cancelled' ? 'cancelled' : 'expired';
      const { closeAwaiting } = await import('./approvals');
      await closeAwaiting(tenantId, s.uuid, status === 'denied' ? 'refused' : status === 'cancelled' ? 'cancelled' : 'expired', null, auditCtx);
    }
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { expired } };
}

/** actions.edge-freeze-sync: the freeze (or its end) at apple-edge. */
export async function edgeFreezeSync(ctx: JobContext<{ tenantId: number }>): Promise<JobResult> {
  const handler = edgeFreezeOf();
  if (!handler) return { output: { skipped: 'apple_edge_off' } };
  const tenantId = ctx.tenantId as number;
  const frozen = (await ctx.inTenant(() => readSettings(tenantId))).frozen_at !== null;
  try {
    const r = await handler(tenantId, frozen);
    return { output: r === 'no_edge_tenant' ? { skipped: 'no_edge_tenant' } : { frozen } };
  } catch (err) {
    await ctx.inTenant(() => alertTenantAndMsp(tenantId, {
      severity: 'critical',
      title: frozen ? 'Freeze not applied at apple-edge yet' : 'Unfreeze not applied at apple-edge yet',
      message: 'apple-edge did not take the change of the commands freeze; it is retried every minute.',
      stableKey: `guard:edge-freeze:${tenantId}`,
    }));
    throw new JobError('edge_unreachable', 'apple-edge did not take the freeze');
  }
}

/** actions.privilege-watch: an alert per privilege grant (platform
 *  administrator, tenant administrator, approver), whatever its path, in the
 *  master tenant and the tenant concerned (once per grant). */
export async function privilegeWatch(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  const rows = await asIdentity(ctx.dbActor, () => db('privilege_grants as g')
    .leftJoin('users as u', 'u.id', 'g.user_id')
    .where('g.source', 'change')
    .andWhere('g.granted_at', '>', db.raw("now() - interval '15 minutes'"))
    .select('g.id', 'g.user_id', 'g.tenant_id', 'g.kind', 'u.username')) as
    Array<{ id: number; user_id: number; tenant_id: number | null; kind: string; username: string | null }>;
  let alerted = 0;
  for (const g of rows) {
    const done = await ctx.once(`grant:${g.id}`, 7 * 86_400, async () => {
      const what = g.kind === 'platform_admin' ? 'platform administrator' : g.kind === 'tenant_admin' ? 'tenant administrator' : 'approver';
      await alertTenants(g.tenant_id ? [MASTER_TENANT_ID, Number(g.tenant_id)] : [MASTER_TENANT_ID], {
        severity: 'warning',
        title: 'New privilege granted',
        message: `${g.username ?? `Account #${g.user_id}`} became ${what}: 72-hour cooldown before destructive actions.`,
        stableKey: `guard:grant:${g.id}`,
        navigateTo: '/admin/security?tab=guard',
      });
    });
    if (done === 'done') alerted++;
  }
  return { output: { grants: rows.length, alerted } };
}

/** actions.purge: obligarth.guard_purge() (reserved to this job's actor). */
export async function purge(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  const res = await asNone(ctx.dbActor, () => db.raw('SELECT actions, grants FROM obligarth.guard_purge()')) as
    { rows: Array<{ actions: string | number; grants: string | number }> };
  return { output: { actions: Number(res.rows[0]?.actions ?? 0), grants: Number(res.rows[0]?.grants ?? 0) } };
}

/**
 * After a restore (§7.5 step 2; T18): every action awaiting approval,
 * scheduled or executing is paused (motif 'restore') and every pending
 * approval request expires: no destructive action prior to the restore runs
 * without being confirmed again. Returns the counts.
 */
export async function restoreReconcile(actor: { type: 'job'; name: string }, requestId: string): Promise<{ paused: number; approvalsExpired: number; tenants: number }> {
  const auditCtx = audit.fromJob({ name: actor.name, requestId });
  let paused = 0;
  let approvalsExpired = 0;
  const { approvalService } = await import('../services/approval.service');
  const { ok, failed } = await forEachTenant(actor, async (tenantId) => {
    const rows = await db('pending_actions').where({ tenant_id: tenantId }).whereIn('state', ['awaiting_approval', 'scheduled', 'executing'])
      .update({ state: 'paused', paused_at: new Date(), updated_at: new Date() }).returning(ACTION_COLUMNS) as Array<Record<string, unknown>>;
    for (const r of rows.map(normaliseRow)) {
      paused++;
      await audit.append(actionEntry(r, 'guard.action_paused', { outcome: 'success', details: { code: 'restore' } }), auditCtx);
    }
    const ids = await db('pending_approvals').where({ tenant_id: tenantId, status: 'pending' }).pluck('id') as number[];
    approvalsExpired += await approvalService._expire(ids.map(Number), { actor: `job:${actor.name}`, jobId: requestId });
    for (const dto of await toDtos(rows.map(normaliseRow))) await notifyAction(dto, { code: 'restore' });
  });
  if (failed > 0) throw new Error(`restore-reconcile: ${failed} tenant(s) failed, ${ok} done`);
  return { paused, approvalsExpired, tenants: ok };
}
