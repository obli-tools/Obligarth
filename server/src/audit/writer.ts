// The writer of the hardened journal (docs: audit-durci §4, §5): every entry
// goes through obligarth.audit_append(body), which checks the body and the
// database context, locks the chain head of the tenant until the end of the
// transaction, chains and inserts. Classes (§5.1): 'critical' is written
// before its action and refuses it when it cannot be written
// (AuditUnavailableError, 503); 'protective' and 'standard' never block, and
// fall back on the local spool.
//
// Where an entry is written (rls-tenant §4.5; review of lot A5): in the
// context of the chain's tenant, with the actor of the entry.
//   - the current context is that tenant's: there;
//   - an entry of the master tenant: from 'none' or 'identity' as such; from
//     another context only for a platform actor (job, integration, active
//     platform administrator);
//   - an entry of another tenant from a context without tenant: for a job,
//     an integration, a member of that tenant or an active platform
//     administrator (checked by the database); never from another tenant's
//     context (an action of the MSP on a client is written from
//     asTargetTenant, in the client's context).
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import type { Knex } from 'knex';
import { MASTER_TENANT_ID, type AuditCriticality } from '@obligarth/shared';
import { config } from '../config';
import { db } from '../db';
import {
  DbContextDeniedError, DbContextMissingError, actorToken, asNone, asTenant, currentDbContext, type DbActor,
} from '../db/context';
import { withTenantInTransaction } from '../db/tenantContext';
import { logger } from '../utils/logger';
import { dbActorOf } from './actor';
import { buildBody, buildEntryGroup, lateText, type BuiltBody } from './body';
import { effectiveCriticality, isDeclaredAction } from './catalog';
import { registerCoreAuditActions } from './coreActions';
import { AuditBodyError, AuditUnavailableError } from './errors';
import { auditMetrics } from './metrics';
import { rejectEntries, spoolEntries, type SpoolLine } from './spool';
import type {
  AuditAppendOptions, AuditAppendResult, AuditEntryInput, AuditInTxOptions, AuditWriteContext,
} from './types';

registerCoreAuditActions();

/** Transient failures (§5.4): retried twice when the write is isolated. */
const TRANSIENT_CODES = new Set(['55P03', '40P01', '40001', '57014', '53100', '57P01', '57P02', '57P03']);
/** A body or a context the database refuses: a defect of the calling code.
 *  Any data exception, integrity or access error (classes 22, 23, 42) is one
 *  too: it would fail the same way at every attempt and at every replay. */
const MALFORMED_CODES = new Set(['22023', '22P02', '42501', '23503']);
const MALFORMED_CLASS_RE = /^(22|23|42)/;
const RETRY_DELAYS_MS = [50, 250];
const SAVEPOINT = 'obligarth_audit';

type FailureKind = 'transient' | 'malformed';

function pgCode(err: unknown): string | null {
  const c = (err as { code?: unknown } | null)?.code;
  return typeof c === 'string' && /^[0-9A-Z]{5}$/.test(c) ? c : null;
}

function failureKind(err: unknown): FailureKind {
  const code = pgCode(err);
  if (code) {
    if (TRANSIENT_CODES.has(code) || code.startsWith('08')) return 'transient';
    if (MALFORMED_CODES.has(code) || MALFORMED_CLASS_RE.test(code)) return 'malformed';
    return 'transient';
  }
  if (err instanceof AuditBodyError || err instanceof DbContextDeniedError || err instanceof DbContextMissingError) return 'malformed';
  return 'transient';
}

/** What a log line and a metric may name of a failure. */
function failureCode(err: unknown): string {
  const code = pgCode(err);
  if (code) return code;
  if (err instanceof AuditBodyError) return 'body';
  if (err instanceof DbContextDeniedError) return 'context_denied';
  if (err instanceof DbContextMissingError) return 'context_missing';
  const name = (err as { name?: unknown } | null)?.name;
  return typeof name === 'string' && /^[A-Za-z]{1,40}$/.test(name) ? name : 'error';
}

const digest = (text: string): string => createHash('sha256').update(text).digest('hex').slice(0, 16);

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** First critical failure: an alert of the master tenant (deduplicated), in
 *  the background (the database may be what fails). */
function alertCriticalFailure(code: string): void {
  void import('../jobs/alerts').then(({ raiseJobAlert }) => raiseJobAlert({ type: 'job', name: 'audit.writer' }, {
    stableKey: 'audit:write-failed',
    severity: 'critical',
    title: 'Audit log unavailable: critical actions refused',
    message: `A critical audit entry could not be written (${code}); the action was refused. See the audit log status.`,
  })).catch(() => undefined);
}

// ── Catalogue checks ────────────────────────────────────────────────────────

const warnedUndeclared = new Set<string>();

/** An undeclared action: refused in strict mode, a warning otherwise. */
function checkDeclared(action: string): void {
  if (isDeclaredAction(action)) return;
  auditMetrics.inc('obligarth_audit_undeclared_total', { action });
  if (config.audit.strictCatalog) {
    logger.error({ code: 'AUDIT_UNDECLARED_ACTION', action }, 'audit: undeclared action (registerAuditAction)');
    throw new AuditBodyError(`undeclared action ${action}`);
  }
  if (!warnedUndeclared.has(action)) {
    warnedUndeclared.add(action);
    logger.warn({ code: 'AUDIT_UNDECLARED_ACTION', action }, 'audit: undeclared action, written as standard');
  }
}

// ── Contexts ────────────────────────────────────────────────────────────────

const isPlatformActorType = (a: DbActor): boolean => a.type === 'job' || a.type === 'integration';

/** May `actor` write in the chain of `tenantId` (or only the master's, with
 *  platformOnly)? Asked to the database in the actor's 'none' context. */
async function actorMayWrite(actor: DbActor, tenantId: number, platformOnly: boolean): Promise<boolean> {
  if (isPlatformActorType(actor)) return true;
  if (actor.type !== 'user') return false;
  const res = await asNone(actor, () => db.raw(
    'SELECT obligarth.ctx_actor_is_platform_admin() AS admin, ?::integer = ANY (obligarth.actor_member_tenant_ids()) AS member',
    [tenantId],
  )) as { rows: Array<{ admin: boolean; member: boolean }> };
  const r = res.rows[0];
  return r?.admin === true || (!platformOnly && r?.member === true);
}

/** Runs fn (its own lease) in the context where the chain of `tenantId`
 *  takes an entry of `actor`, or throws DbContextDeniedError. */
async function inEntryContext<T>(tenantId: number, actor: DbActor, fn: () => Promise<T>): Promise<T> {
  const cur = currentDbContext();
  if (!cur) throw new DbContextMissingError('audit entry without a database context');
  if (cur.kind === 'tenant' && cur.tenantId === tenantId) return asTenant(tenantId, actor, fn);
  if (tenantId === MASTER_TENANT_ID) {
    if (cur.kind === 'none' || cur.kind === 'identity') return asNone(actor, fn);
    if (!(await actorMayWrite(actor, tenantId, true))) {
      throw new DbContextDeniedError(`audit entry of the master tenant from the context of tenant ${cur.tenantId ?? cur.kind}: not a platform actor`);
    }
    return asNone(actor, fn);
  }
  if (cur.kind === 'tenant') {
    // From the master tenant's context, a platform actor writes for the
    // client it acts on (what asTargetTenant admits from the global view).
    if (cur.tenantId !== MASTER_TENANT_ID || !(await actorMayWrite(actor, tenantId, true))) {
      throw new DbContextDeniedError(`audit entry of tenant ${tenantId} from the context of tenant ${cur.tenantId}`);
    }
    return asTenant(tenantId, actor, fn);
  }
  if (!(await actorMayWrite(actor, tenantId, false))) {
    throw new DbContextDeniedError(`audit entry of tenant ${tenantId}: the actor does not act there`);
  }
  return asTenant(tenantId, actor, fn);
}

/** Inside a transaction: may the lease's actor write in another chain? */
async function assertMayWriteFromLease(trx: Knex.Transaction, tenantId: number, actor: DbActor): Promise<void> {
  const cur = currentDbContext();
  if (!cur) throw new DbContextMissingError('audit entry without a database context');
  if (cur.kind === 'member' || cur.kind === 'platform') throw new DbContextDeniedError('audit entry from a read-only context');
  // From a client tenant's context: the master's chain only (a platform
  // actor); from the master tenant's: any chain, for a platform actor.
  const fromClient = cur.kind === 'tenant' && cur.tenantId !== MASTER_TENANT_ID;
  if (fromClient && tenantId !== MASTER_TENANT_ID) {
    throw new DbContextDeniedError(`audit entry of tenant ${tenantId} from the context of tenant ${cur.tenantId}`);
  }
  if (isPlatformActorType(actor)) return;
  if (actor.type !== 'user' || actorToken(actor) !== actorToken(cur.actor)) {
    throw new DbContextDeniedError('audit entry of another chain for another actor than the lease\'s');
  }
  const res = await trx.raw(
    'SELECT obligarth.ctx_actor_is_platform_admin() AS admin, ?::integer = ANY (obligarth.actor_member_tenant_ids()) AS member',
    [tenantId],
  ) as { rows: Array<{ admin: boolean; member: boolean }> };
  const r = res.rows[0];
  const ok = r?.admin === true || (cur.kind !== 'tenant' && r?.member === true);
  if (!ok) throw new DbContextDeniedError(`audit entry of tenant ${tenantId}: the actor does not act there`);
}

// ── Writes ──────────────────────────────────────────────────────────────────

type AppendRow = { entry_id: string | number; entry_seq: string | number; entry_hash: string; appended_at: Date | string };

async function writeBodies(q: Knex | Knex.Transaction, group: readonly BuiltBody[]): Promise<AuditAppendResult[]> {
  const out: AuditAppendResult[] = [];
  for (const b of group) {
    const res = await q.raw('SELECT entry_id, entry_seq, entry_hash, appended_at FROM obligarth.audit_append(?)', [b.text]) as { rows: AppendRow[] };
    const r = res.rows[0];
    out.push({
      id: Number(r.entry_id),
      uuid: b.uuid,
      seq: Number(r.entry_seq),
      hash: String(r.entry_hash),
      appendedAt: (r.appended_at instanceof Date ? r.appended_at : new Date(r.appended_at)).toISOString(),
    });
  }
  return out;
}

/** In the caller's transaction: the lease's chain directly, another chain
 *  under withTenantInTransaction (its own SAVEPOINT). */
async function writeInLease(trx: Knex.Transaction, tenantId: number, actor: DbActor, group: readonly BuiltBody[]): Promise<AuditAppendResult[]> {
  const cur = currentDbContext();
  if (!cur) throw new DbContextMissingError('audit entry without a database context');
  const same = (cur.kind === 'tenant' && cur.tenantId === tenantId)
    || (tenantId === MASTER_TENANT_ID && (cur.kind === 'none' || cur.kind === 'identity'));
  if (same) return writeBodies(trx, group);
  await assertMayWriteFromLease(trx, tenantId, actor);
  return withTenantInTransaction(trx, tenantId, actor, () => writeBodies(trx, group));
}

function counted(group: readonly BuiltBody[], outcome: string, ms: number): void {
  auditMetrics.observeAppend(ms);
  for (const b of group) auditMetrics.inc('obligarth_audit_appends_total', { criticality: b.criticality, outcome });
}

/** A write that failed for good: critical → AuditUnavailableError; otherwise
 *  the entries are spooled (or kept aside when malformed), never thrown. */
function settleFailure(err: unknown, crit: AuditCriticality, action: string, group: readonly BuiltBody[]): null {
  const kind = failureKind(err);
  const code = failureCode(err);
  auditMetrics.inc('obligarth_audit_write_failures_total', { criticality: crit, code: kind === 'malformed' ? 'malformed' : code });
  if (crit === 'critical') {
    logger.error({ code: 'AUDIT_UNAVAILABLE', action, failure: code, body: group[0] ? digest(group[0].text) : undefined },
      'critical audit entry not written: the action is refused');
    alertCriticalFailure(code);
    throw new AuditUnavailableError(code);
  }
  if (!group.length) {
    logger.error({ code: 'AUDIT_ENTRY_LOST', action, failure: code }, 'audit entry not written (malformed)');
    return null;
  }
  const now = new Date().toISOString();
  const lines: SpoolLine[] = group.map((b) => ({ tenant: b.tenantId, body: lateText(b), firstError: code, spooledAt: now }));
  try {
    if (kind === 'malformed') {
      rejectEntries(lines);
      logger.error({ code: 'AUDIT_ENTRY_REJECTED', action, failure: code, body: digest(group[0].text) },
        'audit entry refused (malformed or out of context): kept aside, never replayed');
    } else {
      spoolEntries(lines);
      logger.warn({ code: 'AUDIT_ENTRY_SPOOLED', action, failure: code, body: digest(group[0].text) }, 'audit entry spooled');
    }
  } catch (spoolErr) {
    logger.error({ code: 'AUDIT_ENTRY_LOST', action, failure: code, spool: failureCode(spoolErr) }, 'audit entry lost: the spool refused it');
  }
  return null;
}

/** The bodies of an entry, or the settled failure (critical: throws). */
function buildOrSettle(entry: AuditEntryInput, ctx: AuditWriteContext, crit: AuditCriticality): BuiltBody[] | null {
  try {
    checkDeclared(String(entry?.action ?? ''));
    return buildEntryGroup(entry, ctx, { criticality: crit });
  } catch (err) {
    settleFailure(err, crit, String(entry?.action ?? ''), []);
    return null;
  }
}

/** Own transaction, retries of the transient failures. */
async function appendWithClass(entry: AuditEntryInput, ctx: AuditWriteContext, crit: AuditCriticality): Promise<AuditAppendResult | null> {
  const group = buildOrSettle(entry, ctx, crit);
  if (!group) return null;
  const actor = dbActorOf(ctx.actor);
  const t0 = performance.now();
  let lastErr: unknown;
  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
    try {
      const results = await inEntryContext(entry.tenantId, actor, () => db.transaction((trx) => writeBodies(trx, group)));
      counted(group, entry.outcome ?? 'success', performance.now() - t0);
      return results[0];
    } catch (err) {
      lastErr = err;
      if (failureKind(err) !== 'transient' || attempt === RETRY_DELAYS_MS.length) break;
      await sleep(RETRY_DELAYS_MS[attempt]);
    }
  }
  return settleFailure(lastErr, crit, entry.action, group);
}

/** Own transaction (§5.3). 'critical': throws AuditUnavailableError when not
 *  written; otherwise never throws (spool). */
export async function append(entry: AuditEntryInput, ctx: AuditWriteContext, o: AuditAppendOptions & { postHoc?: boolean } = {}): Promise<AuditAppendResult | null> {
  const crit = effectiveCriticality(String(entry?.action ?? ''), o.criticality);
  if (o.postHoc && crit === 'critical') {
    // A critical action written after the fact (the compatibility facade):
    // a conversion defect (§5.7), counted and reported.
    auditMetrics.inc('obligarth_audit_post_hoc_critical_total', { action: entry.action });
    logger.error({ code: 'AUDIT_POST_HOC_CRITICAL', action: entry.action }, 'audit: critical action written after the fact');
  }
  return appendWithClass(entry, ctx, crit);
}

/** In the caller's transaction (P1). 'throw' (default): a failure aborts it,
 *  AuditUnavailableError. 'spool': under a SAVEPOINT, spooled, never throws. */
export async function appendInTx(trx: Knex.Transaction, entry: AuditEntryInput, ctx: AuditWriteContext,
  o: AuditInTxOptions & AuditAppendOptions = {}): Promise<AuditAppendResult | null> {
  const out = await appendManyInTx(trx, [entry], ctx, o);
  return out[0] ?? null;
}

/** Several chains in one transaction, written in ascending tenant order (no
 *  lock-order deadlock between two transactions, §4.6). */
export async function appendManyInTx(trx: Knex.Transaction, entries: readonly AuditEntryInput[], ctx: AuditWriteContext,
  o: AuditInTxOptions & AuditAppendOptions = {}): Promise<AuditAppendResult[]> {
  const spool = o.onFailure === 'spool';
  const order = entries.map((e, i) => ({ e, i })).sort((a, b) => Number(a.e.tenantId) - Number(b.e.tenantId) || a.i - b.i);
  const prepared: Array<{ i: number; entry: AuditEntryInput; crit: AuditCriticality; group: BuiltBody[] }> = [];
  for (const { e, i } of order) {
    const crit = effectiveCriticality(String(e?.action ?? ''), o.criticality);
    if (spool) {
      const group = buildOrSettle(e, ctx, crit);
      if (group) prepared.push({ i, entry: e, crit, group });
      continue;
    }
    try {
      checkDeclared(String(e?.action ?? ''));
      prepared.push({ i, entry: e, crit, group: buildEntryGroup(e, ctx, { criticality: crit }) });
    } catch (err) {
      auditMetrics.inc('obligarth_audit_write_failures_total', { criticality: crit, code: 'malformed' });
      logger.error({ code: 'AUDIT_UNAVAILABLE', action: e?.action, failure: failureCode(err) }, 'audit entry refused: the transaction is aborted');
      throw new AuditUnavailableError(failureCode(err));
    }
  }
  const actor = dbActorOf(ctx.actor);
  const results: AuditAppendResult[] = new Array(entries.length);
  const t0 = performance.now();
  if (spool) {
    if (!prepared.length) return [];
    await trx.raw(`SAVEPOINT ${SAVEPOINT}`);
    try {
      for (const p of prepared) results[p.i] = (await writeInLease(trx, p.entry.tenantId, actor, p.group))[0];
      await trx.raw(`RELEASE SAVEPOINT ${SAVEPOINT}`);
    } catch (err) {
      await trx.raw(`ROLLBACK TO SAVEPOINT ${SAVEPOINT}`).catch(() => undefined);
      for (const p of prepared) {
        try { settleFailure(err, p.crit === 'critical' ? 'standard' : p.crit, p.entry.action, p.group); } catch { /* never in spool mode */ }
      }
      return [];
    }
    for (const p of prepared) counted(p.group, p.entry.outcome ?? 'success', performance.now() - t0);
    return results.filter(Boolean);
  }
  for (const p of prepared) {
    try {
      results[p.i] = (await writeInLease(trx, p.entry.tenantId, actor, p.group))[0];
    } catch (err) {
      const code = failureCode(err);
      auditMetrics.inc('obligarth_audit_write_failures_total', { criticality: p.crit, code: failureKind(err) === 'malformed' ? 'malformed' : code });
      logger.error({ code: 'AUDIT_UNAVAILABLE', action: p.entry.action, failure: code, body: digest(p.group[0].text) },
        'audit entry not written in its transaction: the action is refused');
      if (p.crit === 'critical') alertCriticalFailure(code);
      throw new AuditUnavailableError(code);
    }
  }
  for (const p of prepared) counted(p.group, p.entry.outcome ?? 'success', performance.now() - t0);
  return results.filter(Boolean);
}

/** A short code of an action's failure, for its result entry. */
function errorCodeOf(err: unknown): string {
  const e = err as { code?: unknown; statusCode?: unknown; status?: unknown } | null;
  for (const v of [e?.code, e?.statusCode, e?.status]) {
    if ((typeof v === 'string' || typeof v === 'number') && /^[A-Za-z0-9_.-]{1,64}$/.test(String(v))) return String(v);
  }
  return 'error';
}

/** P2: the critical intent (outcome 'requested') is written before fn, which
 *  runs only if it was (AuditUnavailableError otherwise); then the result,
 *  'success' or 'failure' with the error's code, in class standard, linked
 *  by links.intent. */
export async function withIntent<T>(entry: AuditEntryInput, ctx: AuditWriteContext, fn: () => Promise<T>,
  o: { resultDetails?: (result: T) => Record<string, unknown> } = {}): Promise<T> {
  const intent = await appendWithClass({ ...entry, outcome: 'requested' }, ctx, 'critical');
  if (!intent) throw new AuditUnavailableError('intent');
  const links = { ...(entry.links ?? {}), intent: intent.uuid };
  let result: T;
  try {
    result = await fn();
  } catch (err) {
    await appendWithClass({
      ...entry, outcome: 'failure', links, details: { ...(entry.details ?? {}), error: errorCodeOf(err) },
    }, ctx, 'standard');
    throw err;
  }
  let extra: Record<string, unknown> = {};
  try { extra = o.resultDetails ? o.resultDetails(result) : {}; } catch { extra = {}; }
  await appendWithClass({
    ...entry, outcome: entry.outcome && entry.outcome !== 'requested' ? entry.outcome : 'success', links,
    details: { ...(entry.details ?? {}), ...extra },
  }, ctx, 'standard');
  return result;
}

/** A body built and checked, not written: for the SQL functions that append
 *  it themselves (retention, legal hold). Throws AuditBodyError. */
export function prepare(entry: AuditEntryInput, ctx: AuditWriteContext, o: AuditAppendOptions = {}): { text: string; uuid: string } {
  checkDeclared(String(entry?.action ?? ''));
  const crit = effectiveCriticality(String(entry?.action ?? ''), o.criticality);
  const b = buildBody(entry, ctx, { criticality: crit });
  return { text: b.text, uuid: b.uuid };
}
