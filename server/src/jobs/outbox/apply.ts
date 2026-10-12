import type { Knex } from 'knex';
import type { Logger } from 'pino';
import { bindTxAuditCollector } from '../../audit/collector';
import type { AuditEntryInput } from '../../audit/types';
import type { DbActor } from '../../db/context';
import { tenantContextStatement } from '../../db/tenantContext';
import { logger } from '../../utils/logger';
import { safeErr, sanitizeError } from '../errors';
import { outboxHandlerFor, type OutboxEvent, type OutboxScope } from './handlers';

// =============================================================================
// Application of one outbox event (docs: file-durable §7.3 to §7.5), shared
// by the consumer (consumer.ts, inside its batch transaction) and the redrive
// of a dead letter (deadLetters.ts). In order (§7.4):
//   schema_version ≠ 1                   → dead letter unsupported_schema_version
//   no handler for (scope, type)         → dead letter unknown_type
//   payload refused by its schema        → dead letter invalid_payload
//   tenant event whose enrollment_id is not prefixed by <tenant_key>_
//                                        → dead letter tenant_mismatch (security alert)
//   tenant_key unknown to the brain      → retried (unknown_tenant), dead letter at the 5th failure
//   PermanentJobError, permanent PostgreSQL error
//                                        → dead letter permanent_error
//   any other error of the handler       → retried (handler_error, its code kept),
//                                          dead letter at the 5th failure
//   foreign key violation (23503) while the event's tenant was deleted during
//   the batch                            → consumed without effect (the event is moot)
// The handler runs in a savepoint of the caller's transaction, in the event's
// tenant context ('none' for a platform event), set in that savepoint: a
// rolled-back savepoint drops everything the handler wrote, the jobs it sent,
// its afterCommit effects and its audit entries. While the handler runs, the
// event's audit collector is bound to the transaction (audit/collector.ts):
// what the handler reaches and would journal in its caller's transaction (a
// command enqueued by the follow-up of a result) hands its entry to it too,
// and no chain head is locked before the end of the batch (review FD-RC6,
// INT-RC8; review of lot B4, INT-B4-R3). One round trip per event
// (file-durable L2, EventScope): the savepoint of an applied event is
// released by the statement that opens the next one, joined to the next
// event's context; the consumer's own statements (attempts, dead letters,
// tenant lookups, the end of the batch) first take back its context ('none').
// Never logs the payload (device data); the enrollment id only in debug.
// =============================================================================

/** The consumer's database actor (context 'none'): handlers' writes and the tenant contexts it sets. */
export const CONSUMER_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'apple-edge.outbox-consumer' }) as DbActor;
/** Contract version of the outbox (apple-edge §5.5). */
export const SUPPORTED_SCHEMA_VERSION = 1;
/** Failures of one event before its dead letter (apple-edge §5.5). */
export const MAX_ATTEMPTS = 5;
/** Waits after the failure n (1 to 4), seconds: about 36 minutes and 5 attempts in all (file-durable F7). */
export const RETRY_DELAYS_S: readonly number[] = [10, 60, 300, 1_800];

export type DeadLetterReason =
  | 'unknown_type' | 'unsupported_schema_version' | 'invalid_payload' | 'tenant_mismatch'
  | 'unknown_tenant' | 'handler_error' | 'permanent_error';

/** A row of apple_edge.outbox (or the copy kept in the dead letters). */
export interface OutboxRow {
  seq: string;
  event_id: string;
  schema_version: number;
  scope: string;
  tenant_key: string | null;
  type: string;
  enrollment_id: string | null;
  command_uuid: string | null;
  request_id: string | null;
  occurred_at: Date;
  payload: unknown;
}

export type EventOutcome =
  | { kind: 'applied' }
  | { kind: 'retry'; reason: 'unknown_tenant' | 'handler_error'; code: string; attempts: number; delaySeconds: number }
  | { kind: 'dead_letter'; reason: DeadLetterReason; code: string; attempts: number };

/** What the events of one transaction collected, used after their savepoints released. */
export interface EventCollector {
  /** afterCommit effects, in event order. */
  effects: Array<() => void | Promise<void>>;
  /** Audit entries (ctx.audit), written at the end of the transaction. */
  audits: AuditEntryInput[];
}

export interface ApplyOptions {
  /** Failures already counted for this event (apple_edge_inbox_attempts). */
  priorAttempts: number;
  /** tenants.id of a tenant key, or null when the brain does not know it (in the consumer's context:
   *  scope.toNone() first when it queries). */
  resolveTenant: (key: string) => Promise<number | null>;
  /** Applied from the dead letters by an administrator. */
  redrive: boolean;
  collector: EventCollector;
  /** The savepoints and contexts of the transaction's events. */
  scope: EventScope;
}

const SAVEPOINT = 'obligarth_outbox_event';

/**
 * The savepoint and the database context of each event of one transaction,
 * one statement per event (file-durable L2: a round trip costs about 1 ms on
 * the Windows bench):
 *   enter(t)   [RELEASE SAVEPOINT of the event applied before;] SAVEPOINT;
 *              context of the tenant t (null: 'none', a platform event)
 *   applied()  the event's savepoint stays open until the next statement
 *   failed()   ROLLBACK TO SAVEPOINT; RELEASE SAVEPOINT (never a stale
 *              savepoint of the same name: a handler that broke its own would
 *              otherwise roll back to an earlier event's, silently dropping
 *              the work in between); the consumer's context
 *   toNone()   [RELEASE SAVEPOINT;] the consumer's context, before its own
 *              statements and at the end of the batch
 * Every event starts in the context set for it, whatever the handler before
 * it left. A statement that fails (a handler released the savepoint itself,
 * the connection was cut) fails the transaction: the batch fails.
 */
export class EventScope {
  private readonly trx: Knex.Transaction;
  private readonly actor: DbActor;
  /** The savepoint of the last event applied is still open. */
  private pending = false;
  /** The transaction is in the consumer's context. */
  private none = true;

  constructor(trx: Knex.Transaction, actor: DbActor = CONSUMER_ACTOR) {
    this.trx = trx;
    this.actor = actor;
  }

  async enter(tenantId: number | null): Promise<void> {
    const release = this.pending ? `RELEASE SAVEPOINT ${SAVEPOINT}; ` : '';
    this.pending = false;
    this.none = false;
    await this.trx.raw(`${release}SAVEPOINT ${SAVEPOINT}; ${tenantContextStatement(tenantId, this.actor)}`);
  }

  applied(): void {
    this.pending = true;
    this.none = false;                                   // the handler's context, whatever it is now
  }

  async failed(): Promise<void> {
    this.none = false;
    await this.trx.raw(`ROLLBACK TO SAVEPOINT ${SAVEPOINT}; RELEASE SAVEPOINT ${SAVEPOINT}; ${tenantContextStatement(null, this.actor)}`);
    this.none = true;
  }

  async toNone(): Promise<void> {
    if (!this.pending && this.none) return;
    const release = this.pending ? `RELEASE SAVEPOINT ${SAVEPOINT}; ` : '';
    this.pending = false;
    await this.trx.raw(`${release}${tenantContextStatement(null, this.actor)}`);
    this.none = true;
  }
}

const toDate = (v: unknown): Date => (v instanceof Date ? v : new Date(String(v)));

/** The event a handler sees (payload already validated by its schema). */
export function toEvent(row: OutboxRow, payload: unknown): OutboxEvent {
  return Object.freeze({
    seq: String(row.seq),
    eventId: String(row.event_id),
    schemaVersion: Number(row.schema_version),
    scope: row.scope as OutboxScope,
    tenantKey: row.tenant_key ?? null,
    type: String(row.type),
    enrollmentId: row.enrollment_id ?? null,
    commandUuid: row.command_uuid ?? null,
    requestId: row.request_id ?? null,
    occurredAt: toDate(row.occurred_at),
    payload,
  });
}

/** A failure that may heal (unknown tenant, retryable handler error): retried after its delay, or a dead
 *  letter at the 5th failure. */
function failure(reason: 'unknown_tenant' | 'handler_error', code: string, priorAttempts: number): EventOutcome {
  const attempts = priorAttempts + 1;
  if (attempts >= MAX_ATTEMPTS) return { kind: 'dead_letter', reason, code, attempts };
  return { kind: 'retry', reason, code, attempts, delaySeconds: RETRY_DELAYS_S[Math.min(attempts, RETRY_DELAYS_S.length) - 1] };
}

const deadLetter = (reason: DeadLetterReason, code: string, priorAttempts: number): EventOutcome =>
  ({ kind: 'dead_letter', reason, code, attempts: priorAttempts + 1 });

/** Is `enrollmentId` an enrollment of the tenant `key` ('<key>_<id>', or a user channel '<key>_<id>:<user>')? */
export function enrollmentOfTenant(key: string | null, enrollmentId: string | null): boolean {
  if (enrollmentId === null) return true;
  return typeof key === 'string' && key !== '' && enrollmentId.startsWith(`${key}_`) && enrollmentId.length > key.length + 1;
}

/** Applies one event in `trx`, through `o.scope`. Never throws for a failure of the event itself (its
 *  outcome says it); throws only when the transaction itself fails (a savepoint that cannot be released or
 *  rolled back: the batch fails). Before its own statements, the caller takes back its context
 *  (o.scope.toNone()). */
export async function applyEvent(trx: Knex.Transaction, row: OutboxRow, o: ApplyOptions): Promise<{ outcome: EventOutcome; tenantId: number | null }> {
  const seq = String(row.seq);
  const base = { eventId: String(row.event_id), seq, type: String(row.type) };
  if (Number(row.schema_version) !== SUPPORTED_SCHEMA_VERSION) {
    return { outcome: deadLetter('unsupported_schema_version', 'unsupported_schema_version', o.priorAttempts), tenantId: null };
  }
  const def = outboxHandlerFor(String(row.scope), String(row.type));
  if (!def) return { outcome: deadLetter('unknown_type', 'unknown_type', o.priorAttempts), tenantId: null };
  const parsed = def.payload.safeParse(row.payload);
  if (!parsed.success) return { outcome: deadLetter('invalid_payload', 'invalid_payload', o.priorAttempts), tenantId: null };
  if (row.scope === 'tenant' && !enrollmentOfTenant(row.tenant_key, row.enrollment_id)) {
    return { outcome: deadLetter('tenant_mismatch', 'tenant_mismatch', o.priorAttempts), tenantId: null };
  }
  let tenantId: number | null = null;
  if (row.scope === 'tenant') {
    tenantId = row.tenant_key ? await o.resolveTenant(row.tenant_key) : null;
    if (tenantId === null) return { outcome: failure('unknown_tenant', 'unknown_tenant', o.priorAttempts), tenantId: null };
  }

  const log: Logger = logger.child({ ...base, tenantId });
  const effects: Array<() => void | Promise<void>> = [];
  const audits: AuditEntryInput[] = [];
  const event = toEvent(row, parsed.data);
  const collectAudit = (entry: AuditEntryInput): void => {
    audits.push({ ...entry, details: { ...(entry.details ?? {}), eventId: event.eventId } });
  };
  await o.scope.enter(tenantId);
  const release = bindTxAuditCollector(trx, collectAudit);
  try {
    await def.handle({
      event,
      tenantId,
      trx,
      actor: CONSUMER_ACTOR,
      log,
      redrive: o.redrive,
      afterCommit: (fn) => { effects.push(fn); },
      audit: collectAudit,
    });
  } catch (err) {
    release();
    // The rollback drops the handler's writes and jobs; the consumer's
    // context again. A failure here fails the batch.
    await o.scope.failed();
    const s = sanitizeError(err);
    if (tenantId !== null && s.code === 'pg_23503' && !(await tenantExists(trx, tenantId))) {
      // The tenant's deletion committed during the batch (README §5): a row
      // that names it can no longer be written, and the event is moot.
      log.info('outbox event of a tenant deleted meanwhile: consumed without effect');
      return { outcome: { kind: 'applied' }, tenantId };
    }
    log[s.retryable ? 'warn' : 'error']({ err: safeErr(err), code: s.code, attempt: o.priorAttempts + 1 }, 'outbox event failed');
    if (!s.retryable) return { outcome: deadLetter('permanent_error', s.code, o.priorAttempts), tenantId };
    return { outcome: failure('handler_error', s.code, o.priorAttempts), tenantId };
  }
  release();
  o.scope.applied();
  o.collector.effects.push(...effects);
  o.collector.audits.push(...audits);
  if (row.enrollment_id) log.debug({ enrollmentId: row.enrollment_id }, 'outbox event applied');
  return { outcome: { kind: 'applied' }, tenantId };
}

// ── Bookkeeping (in the caller's transaction, context 'none' of the consumer) ──

/** A retryable failure: counted, the event waits for its delay. */
export async function recordAttempt(trx: Knex.Transaction | Knex, row: Pick<OutboxRow, 'event_id' | 'seq' | 'type'>,
  attempts: number, delaySeconds: number, code: string): Promise<void> {
  await trx.raw(
    `INSERT INTO obligarth.apple_edge_inbox_attempts
            (event_id, seq, type, attempts, first_failed_at, last_failed_at, next_attempt_at, last_error_code)
     VALUES (?, ?, ?, ?, now(), now(), now() + make_interval(secs => ?), ?)
     ON CONFLICT (event_id) DO UPDATE
        SET attempts = EXCLUDED.attempts, last_failed_at = now(),
            next_attempt_at = EXCLUDED.next_attempt_at, last_error_code = EXCLUDED.last_error_code`,
    [row.event_id, row.seq, String(row.type).slice(0, 64), attempts, delaySeconds, code.slice(0, 64)],
  );
}

/** The copy of an abandoned event (its payload included: device data, platform administrators only). */
export async function recordDeadLetter(trx: Knex.Transaction | Knex, row: OutboxRow, tenantId: number | null,
  reason: DeadLetterReason, attempts: number, code: string): Promise<void> {
  await trx.raw(
    `INSERT INTO obligarth.apple_edge_dead_letters
            (event_id, seq, schema_version, scope, tenant_key, tenant_id, type, enrollment_id,
             command_uuid, request_id, occurred_at, payload, reason, attempts, last_error_code)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?)
     ON CONFLICT (event_id) DO NOTHING`,
    [
      row.event_id, row.seq, Math.max(-32768, Math.min(32767, Number(row.schema_version) || 0)),
      row.scope === 'platform' ? 'platform' : 'tenant',
      row.tenant_key ? String(row.tenant_key).slice(0, 16) : null, tenantId, String(row.type).slice(0, 64),
      row.enrollment_id, row.command_uuid ? String(row.command_uuid).slice(0, 64) : null,
      row.request_id ? String(row.request_id).slice(0, 64) : null, toDate(row.occurred_at),
      JSON.stringify(row.payload ?? {}), reason, attempts, code.slice(0, 64),
    ],
  );
  await trx.raw('DELETE FROM obligarth.apple_edge_inbox_attempts WHERE event_id = ?', [row.event_id]);
}

/** A success after earlier failures: the attempts are forgotten. */
export async function clearAttempts(trx: Knex.Transaction | Knex, eventId: string): Promise<void> {
  await trx.raw('DELETE FROM obligarth.apple_edge_inbox_attempts WHERE event_id = ?', [eventId]);
}

/** Does the tenant still exist (context 'none' of the consumer: the registry is readable)? */
export async function tenantExists(trx: Knex.Transaction | Knex, tenantId: number): Promise<boolean> {
  const res = await trx.raw('SELECT 1 FROM obligarth.tenants WHERE id = ?', [tenantId]) as { rows: unknown[] };
  return res.rows.length > 0;
}

/** tenants.id of each known key (context 'none' of a job: the registry is readable). */
export async function tenantIdsOfKeys(trx: Knex.Transaction | Knex, keys: string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const wanted = [...new Set(keys.filter((k) => typeof k === 'string' && /^[a-km-np-z2-9]{16}$/.test(k)))];
  if (wanted.length === 0) return out;
  const res = await trx.raw('SELECT id, mdm_key FROM obligarth.tenants WHERE mdm_key = ANY (?::text[])', [wanted]) as
    { rows: Array<{ id: number; mdm_key: string }> };
  for (const r of res.rows) out.set(r.mdm_key, Number(r.id));
  return out;
}
