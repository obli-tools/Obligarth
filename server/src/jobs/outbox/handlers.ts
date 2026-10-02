import type { Knex } from 'knex';
import type { Logger } from 'pino';
import { z } from 'zod';
import type { AuditEntryInput } from '../../audit/types';
import type { DbActor } from '../../db/context';
import { JOB_MODULES } from '../registry';

// =============================================================================
// Registry of the handlers of the apple-edge outbox (docs: file-durable §7.3;
// integration-apple-edge §7.1, §7.2). The consumer (consumer.ts) applies each
// event through the handler registered for its (scope, type), in the event's
// savepoint of the batch transaction; the module that owns the data delivers
// the handler (integration §7.4). Rules checked at registration (a failure
// throws: the server does not start):
//   - one handler per (scope, type); type `<family>.<name>`;
//   - the payload schema is NOT strict (unknown fields of apple-edge ignored:
//     apple-edge §5.5);
//   - registered before jobs.start() (the registry is then frozen).
// Rules of a handler: writes through ctx.trx only, no network call, no nested
// transaction (savepoints would pile up past the subtransaction cache), about
// 50 ms at most; durable follow-up work is a job sent with sendInTx(ctx.trx,
// …); Socket.io through ctx.afterCommit; the audit through ctx.audit (written
// by the consumer at the end of the batch, ascending tenant order).
// =============================================================================

export type OutboxScope = 'tenant' | 'platform';

export interface OutboxEvent<P = unknown> {
  readonly seq: string;
  readonly eventId: string;
  readonly schemaVersion: number;
  readonly scope: OutboxScope;
  readonly tenantKey: string | null;
  readonly type: string;
  readonly enrollmentId: string | null;
  readonly commandUuid: string | null;
  readonly requestId: string | null;
  readonly occurredAt: Date;
  readonly payload: P;
}

export interface OutboxHandlerContext<P> {
  readonly event: OutboxEvent<P>;
  /** Tenant of a 'tenant' event, resolved from tenants.mdm_key; null for 'platform'. */
  readonly tenantId: number | null;
  /** The event's savepoint: everything written through it commits with consumed_at. The database context
   *  is the event's tenant (a 'tenant' event) or 'none' (a 'platform' event, which sets the context of the
   *  tenant it resolves itself: applyTenantContext(ctx.trx, tenantId, ctx.actor)). */
  readonly trx: Knex.Transaction;
  /** The consumer's actor (j:apple-edge.outbox-consumer): the actor of a context a handler sets itself. */
  readonly actor: DbActor;
  /** Child logger { eventId, seq, type, tenantId }: never log the payload (device data). */
  readonly log: Logger;
  /** True when applied from the dead letters by an administrator. */
  readonly redrive: boolean;
  /** Runs fn once the batch transaction has committed; dropped if this event's savepoint is rolled back or
   *  the batch fails. Best effort and not durable: Socket.io emissions only. Errors are logged, never
   *  retried. A durable effect is a job enqueued with sendInTx(ctx.trx, …) (integration I13). */
  afterCommit(fn: () => void | Promise<void>): void;
  /** Audit entry kept with this event's savepoint (dropped if it rolls back) and written by the consumer at
   *  the end of the batch, in ascending tenant order, with its details.eventId (review FD-RC6, INT-RC8). */
  audit(entry: AuditEntryInput): void;
}

export interface OutboxHandlerDefinition<S extends z.ZodTypeAny> {
  /** Event type of apple-edge §5.6, e.g. 'mdm.authenticate'. */
  type: string;
  scope: OutboxScope;
  /** Owning module (file-durable §5.1). */
  module: string;
  /** NOT strict: unknown fields are ignored (apple-edge §5.5). */
  payload: S;
  handle(ctx: OutboxHandlerContext<z.infer<S>>): Promise<void>;
}

/** A registered handler (the payload type erased). */
export interface RegisteredOutboxHandler {
  readonly type: string;
  readonly scope: OutboxScope;
  readonly module: string;
  readonly payload: z.ZodTypeAny;
  readonly handle: (ctx: OutboxHandlerContext<any>) => Promise<void>;
}

/** Event types: `<family>.<name>` (apple-edge §5.6). */
export const EVENT_TYPE_RE = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;

export class OutboxHandlerRegistrationError extends Error {
  constructor(scope: string, type: string, message: string) {
    super(`outbox handler ${scope}/${type}: ${message}`);
    this.name = 'OutboxHandlerRegistrationError';
  }
}

const handlers = new Map<string, RegisteredOutboxHandler>();
let frozen = false;

const keyOf = (scope: string, type: string): string => `${scope}|${type}`;

/** Declares the handler of an event type and scope (before jobs.start()). */
export function registerOutboxHandler<S extends z.ZodTypeAny>(def: OutboxHandlerDefinition<S>): void {
  const scope = String(def?.scope ?? '');
  const type = String(def?.type ?? '');
  const fail = (message: string): never => { throw new OutboxHandlerRegistrationError(scope, type, message); };
  if (frozen) fail('registered after jobs.start(): register every handler before the start');
  if (scope !== 'tenant' && scope !== 'platform') fail('scope must be "tenant" or "platform"');
  if (!EVENT_TYPE_RE.test(type) || type.length > 64) fail('invalid event type (<family>.<name>, 64 characters at most)');
  if (!JOB_MODULES.includes(String(def.module))) fail(`unknown module "${String(def.module)}" (jobs/registry.ts JOB_MODULES)`);
  if (typeof def.handle !== 'function') fail('handle missing');
  const schema = def.payload as z.ZodTypeAny;
  if (!schema || typeof (schema as { safeParse?: unknown }).safeParse !== 'function') fail('payload must be a zod schema');
  if (schema instanceof z.ZodObject && (schema._def as { unknownKeys?: string }).unknownKeys === 'strict') {
    fail('payload must not be strict: the unknown fields of apple-edge are ignored (apple-edge §5.5)');
  }
  if (handlers.has(keyOf(scope, type))) fail('registered twice');
  handlers.set(keyOf(scope, type), Object.freeze({
    type, scope: scope as OutboxScope, module: def.module, payload: schema, handle: def.handle as RegisteredOutboxHandler['handle'],
  }));
}

/** The handler of (scope, type), if any. */
export function outboxHandlerFor(scope: string, type: string): RegisteredOutboxHandler | undefined {
  return handlers.get(keyOf(scope, type));
}

/** Every registered handler (admin API, tests). */
export function outboxHandlers(): RegisteredOutboxHandler[] {
  return [...handlers.values()].sort((a, b) => a.type.localeCompare(b.type) || a.scope.localeCompare(b.scope));
}

/** Called by jobs.start(): no registration afterwards. */
export function freezeOutboxHandlers(): void {
  frozen = true;
}
