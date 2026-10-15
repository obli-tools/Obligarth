// Registry of the handlers of the Android notifications (android_inbox). Same rules as the outbox handlers: writes
// through ctx.trx only (the event's savepoint, tenant context), no network call (follow-ups are jobs sent with
// sendInTx), about 50 ms, real-time effects through afterCommit, monotonic by occurred_at.
import type { Knex } from 'knex';
import type { Logger } from 'pino';
import type { z } from 'zod';
import type { AuditEntryInput } from '../../audit/types';
import type { AndroidEventType } from './schemas';

export interface AndroidInboxEvent<P> {
  readonly id: number;
  readonly messageId: string;
  readonly type: AndroidEventType;
  readonly enterpriseName: string;
  readonly resourceName: string | null;
  readonly publishedAt: Date;
  readonly occurredAt: Date;
  readonly payload: P;
  readonly attempts: number;
  readonly receivedAt: Date;
}

export interface AndroidEventContext<P> {
  readonly event: AndroidInboxEvent<P>;
  readonly tenantId: number;
  readonly enterpriseId: number;
  readonly trx: Knex.Transaction;
  /** { inboxId, type, tenantId }: never the payload. */
  readonly log: Logger;
  afterCommit(fn: () => void | Promise<void>): void;
  audit(entry: AuditEntryInput): void;
}

export interface AndroidEventHandler<S extends z.ZodTypeAny> {
  type: AndroidEventType;
  /** NOT strict (AMAPI adds fields every month), but bounded. */
  payload: S;
  handle(ctx: AndroidEventContext<z.infer<S>>): Promise<void>;
}

/** A prerequisite is missing (a STATUS_REPORT before its ENROLLMENT): retried without counting a failure, 30 min. */
export class MissingPrerequisite extends Error {
  constructor(message = 'missing prerequisite') {
    super(message);
    this.name = 'MissingPrerequisite';
  }
}

const handlers = new Map<string, AndroidEventHandler<z.ZodTypeAny>>();
let frozen = false;

export function registerAndroidEventHandler<S extends z.ZodTypeAny>(def: AndroidEventHandler<S>): void {
  if (frozen) throw new Error(`android handler ${def.type}: registered after the start`);
  if (handlers.has(def.type)) throw new Error(`android handler ${def.type}: registered twice`);
  if (def.type === 'amapi.unknown') throw new Error('android handler: amapi.unknown has no handler (skipped)');
  handlers.set(def.type, def as unknown as AndroidEventHandler<z.ZodTypeAny>);
}

export function androidEventHandler(type: string): AndroidEventHandler<z.ZodTypeAny> | undefined {
  return handlers.get(type);
}

export function freezeAndroidEventHandlers(): void {
  frozen = true;
}

/** Test hook: removes a handler registered by a test. */
export function unregisterAndroidEventHandler(type: string): void {
  handlers.delete(type);
}
