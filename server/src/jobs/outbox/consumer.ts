import pg from 'pg';
import { config } from '../../config';
import { db } from '../../db';
import { asNone } from '../../db/context';
import { audit } from '../../audit';
import { logger } from '../../utils/logger';
import { raiseJobAlert } from '../alerts';
import { safeErr } from '../errors';
import type { JobsMode } from '../types';
import {
  applyEvent, clearAttempts, CONSUMER_ACTOR, EventScope, MAX_ATTEMPTS, RETRY_DELAYS_S, recordAttempt, recordDeadLetter,
  tenantIdsOfKeys, type EventCollector, type OutboxRow,
} from './apply';
import { outboxMetrics } from './metrics';

// =============================================================================
// Consumer of the apple-edge outbox (docs: file-durable §7.2, §7.4, §7.7;
// apple-edge §5.5): one loop per instance in JOBS_MODE=all, started by
// jobs.startWorkers() when OUTBOX_CONSUMER is 'on', or 'auto' and the table
// exists; stopped by jobs.stop() (the batch in progress finishes).
//
// A pass (drainOnce), in one transaction of the consumer (context 'none',
// actor j:apple-edge.outbox-consumer; statement_timeout 30 s, lock_timeout
// 5 s):
//   1. lock the head of the queue (FOR UPDATE OF o SKIP LOCKED, ORDER BY seq,
//      LIMIT batch size), events whose next attempt is due only — never an
//      upper bound by seq (apple-edge RC1);
//   2. load the prefix that fits 16 MiB of stored payload (one row at least);
//   3. apply them sorted by (occurred_at, seq), one savepoint each (apply.ts),
//      within a budget of 5 s (the rest is released, taken again at once);
//   4. write the audit entries the handlers collected, ascending tenant order,
//      one savepoint, spooled on failure (review FD-RC6);
//   5. mark what was applied or dead-lettered (consumed_at), commit; then run
//      the afterCommit effects, in order.
// A failure of the pass itself (connection, commit) counts nothing: at the
// second in a row the batches drop to one event, at the third an attempt
// (batch_failure) is recorded for the head event in its own transaction, so
// that the rule of the 5 failures removes it. Woken by NOTIFY apple_edge_outbox
// on a dedicated connection (outside the pool, never recycled: apple-edge RC5),
// polled every OUTBOX_POLL_MS besides: a notification sent during a cut is lost.
// =============================================================================

export type OutboxConsumerState = 'disabled' | 'waiting_schema' | 'running' | 'degraded' | 'stopped';

/** The consumer's name (actor j:<name>, audit entries, logs). */
const CONSUMER_NAME = 'apple-edge.outbox-consumer';
/** Stored payload loaded by one pass (pg_column_size), one row at least. */
const MAX_BATCH_BYTES = 16 * 1024 * 1024;
/** Time budget of one pass: the rest of the locked events is released. */
const TIME_BUDGET_MS = 5_000;
/** Wait between two checks of the table (OUTBOX_CONSUMER=on, table missing). */
const SCHEMA_WAIT_MS = 30_000;
/** Longest wait after a failed pass. */
const MAX_FAILURE_WAIT_MS = 30_000;

/** A wait that a notification, a stop or its delay ends; a wake while no one waits ends the next wait at once. */
class Wakeup {
  private resolve: (() => void) | null = null;
  private timer: NodeJS.Timeout | null = null;
  private pending = false;

  wait(ms: number): Promise<void> {
    if (this.pending) {
      this.pending = false;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.resolve = resolve;
      this.timer = setTimeout(() => this.fire(), Math.max(0, ms));
      this.timer.unref?.();
    });
  }

  wake(): void {
    if (this.resolve) this.fire();
    else this.pending = true;
  }

  private fire(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const r = this.resolve;
    this.resolve = null;
    r?.();
  }
}

/** LISTEN apple_edge_outbox on a dedicated connection: heartbeat every 30 s (5 s to answer), reconnection
 *  with a growing wait (1 s, doubled, 30 s at most), then an immediate pass (the notifications lost). */
class OutboxListener {
  private client: pg.Client | null = null;
  private connecting = false;
  private stopped = false;
  private retryMs = 1_000;
  private retryAt = 0;
  private beat: NodeJS.Timeout | null = null;
  private retry: NodeJS.Timeout | null = null;
  connected = false;

  constructor(private readonly connectionString: string, private readonly onWake: () => void) {}

  /** Starts a connection when none is up and the reconnection wait is over; never blocks. */
  ensure(): void {
    if (this.stopped || this.connected || this.connecting || Date.now() < this.retryAt) return;
    this.connecting = true;
    void this.connect().finally(() => { this.connecting = false; });
  }

  private async connect(): Promise<void> {
    const client = new pg.Client({ connectionString: this.connectionString, application_name: 'obligarth-outbox-listen', keepAlive: true });
    client.on('error', (err) => this.lost(client, err));
    client.on('end', () => this.lost(client, null));
    client.on('notification', (msg) => { if (msg.channel === 'apple_edge_outbox') this.onWake(); });
    try {
      await client.connect();
      await client.query('LISTEN apple_edge_outbox');
    } catch (err) {
      this.lost(client, err);
      return;
    }
    if (this.stopped) { await client.end().catch(() => undefined); return; }
    this.client = client;
    this.connected = true;
    this.retryMs = 1_000;
    this.schedule();
    logger.debug('outbox: listening for apple-edge notifications');
    this.onWake();                                        // what was sent during the cut
  }

  private schedule(): void {
    if (this.beat) clearTimeout(this.beat);
    this.beat = setTimeout(() => void this.heartbeat(), 30_000);
    this.beat.unref?.();
  }

  private async heartbeat(): Promise<void> {
    const client = this.client;
    if (!client || this.stopped) return;
    let timer: NodeJS.Timeout | null = null;
    try {
      await Promise.race([
        client.query('SELECT 1'),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('outbox listener heartbeat timed out')), 5_000); }),
      ]);
      this.schedule();
    } catch (err) {
      this.lost(client, err);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private lost(client: pg.Client, err: unknown): void {
    if (this.client && this.client !== client) return;
    if (this.beat) clearTimeout(this.beat);
    this.beat = null;
    const wasConnected = this.connected;
    this.client = null;
    this.connected = false;
    client.removeAllListeners('notification');
    void client.end().catch(() => undefined);
    if (this.stopped) return;
    if (err && wasConnected) logger.warn({ err: safeErr(err) }, 'outbox: notification connection lost, reconnecting');
    this.retryAt = Date.now() + this.retryMs;
    // Reconnection on its own (the loop may wait its whole poll), then an immediate pass.
    if (!this.retry) {
      this.retry = setTimeout(() => { this.retry = null; this.ensure(); }, this.retryMs);
      this.retry.unref?.();
    }
    this.retryMs = Math.min(this.retryMs * 2, 30_000);
  }

  async close(): Promise<void> {
    this.stopped = true;
    if (this.beat) clearTimeout(this.beat);
    if (this.retry) clearTimeout(this.retry);
    this.beat = null;
    this.retry = null;
    const client = this.client;
    this.client = null;
    this.connected = false;
    if (client) await client.end().catch(() => undefined);
  }
}

export interface OutboxConsumerStatus {
  state: OutboxConsumerState;
  lastLoopAt: number;
  lastSuccessAt: number;
  degradedSince: number | null;
  listening: boolean;
  batchSize: number;
  failuresInARow: number;
}

/** What one pass did. */
export interface DrainResult {
  locked: number;
  applied: number;
  retried: number;
  deadLettered: number;
}

const HEAD_SQL = `
  SELECT o.seq::text AS seq, COALESCE(a.attempts, 0) AS attempts, pg_column_size(o.payload) AS bytes
    FROM apple_edge.outbox o
    LEFT JOIN obligarth.apple_edge_inbox_attempts a ON a.event_id = o.event_id
   WHERE o.consumed_at IS NULL
     AND (a.next_attempt_at IS NULL OR a.next_attempt_at <= now())
   ORDER BY o.seq
   LIMIT ?
     FOR UPDATE OF o SKIP LOCKED`;

const LOAD_SQL = `
  SELECT seq::text AS seq, event_id::text AS event_id, schema_version, scope, tenant_key, type, enrollment_id,
         command_uuid, request_id, occurred_at, payload
    FROM apple_edge.outbox
   WHERE seq = ANY (?::bigint[])`;

const DUE_SQL = `
  SELECT EXISTS (
    SELECT 1 FROM apple_edge.outbox o
      LEFT JOIN obligarth.apple_edge_inbox_attempts a ON a.event_id = o.event_id
     WHERE o.consumed_at IS NULL AND (a.next_attempt_at IS NULL OR a.next_attempt_at <= now())) AS due`;

const MARK_SQL = `UPDATE apple_edge.outbox SET consumed_at = now() WHERE seq = ANY (?::bigint[]) AND consumed_at IS NULL`;

/** Is apple_edge.outbox there and usable by the runtime role (SELECT, UPDATE (consumed_at))? Catalogs only:
 *  never an error for a schema the role cannot use. */
export async function outboxTableReady(): Promise<boolean> {
  return asNone(CONSUMER_ACTOR, async () => {
    const res = await db.raw(`
      SELECT COALESCE((SELECT has_schema_privilege(n.oid, 'USAGE') AND has_table_privilege(c.oid, 'SELECT')
                              AND has_column_privilege(c.oid, 'consumed_at', 'UPDATE')
                         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'apple_edge' AND c.relname = 'outbox' AND c.relkind IN ('r', 'p')), false) AS ready`) as
      { rows: Array<{ ready: boolean }> };
    return res.rows[0]?.ready === true;
  });
}

const byOccurrence = (a: OutboxRow, b: OutboxRow): number => {
  const d = new Date(a.occurred_at).getTime() - new Date(b.occurred_at).getTime();
  if (d !== 0) return d;
  const x = BigInt(a.seq);
  const y = BigInt(b.seq);
  return x < y ? -1 : x > y ? 1 : 0;
};

export interface OutboxConsumerOptions {
  connectionString?: string;
  batchSize?: number;
  pollMs?: number;
  /** LISTEN for apple-edge's notifications (default true). */
  listen?: boolean;
  /** Tests: base of the wait after a failed pass (1 000 ms: 2 s, 4 s, 8 s… 30 s at most). */
  failureWaitBaseMs?: number;
}

export class OutboxConsumer {
  state: OutboxConsumerState = 'disabled';
  lastLoopAt = 0;
  lastSuccessAt = 0;
  degradedSince: number | null = null;
  private stopping = false;
  private failuresInARow = 0;
  /** Failed checks of the table in a row (the database unreachable). */
  private checkFailures = 0;
  private readonly normalBatchSize: number;
  private batchSize: number;
  private readonly pollMs: number;
  private readonly failureWaitBaseMs: number;
  private readonly wake = new Wakeup();
  private listener: OutboxListener | null = null;
  private loop: Promise<void> | null = null;

  constructor(private readonly opts: OutboxConsumerOptions = {}) {
    this.normalBatchSize = opts.batchSize ?? config.outbox.batchSize;
    this.batchSize = this.normalBatchSize;
    this.pollMs = opts.pollMs ?? config.outbox.pollMs;
    this.failureWaitBaseMs = opts.failureWaitBaseMs ?? 1_000;
  }

  status(): OutboxConsumerStatus {
    return {
      state: this.state, lastLoopAt: this.lastLoopAt, lastSuccessAt: this.lastSuccessAt, degradedSince: this.degradedSince,
      listening: this.listener?.connected ?? false, batchSize: this.batchSize, failuresInARow: this.failuresInARow,
    };
  }

  /** Starts the loop (not awaited by the caller). */
  start(): void {
    if (this.loop) return;
    this.stopping = false;
    if (this.opts.listen !== false) {
      this.listener = new OutboxListener(this.opts.connectionString ?? config.databaseUrl, () => this.wake.wake());
    }
    this.state = 'running';
    outboxMetrics.setConsumerUp(true);
    this.loop = this.run().catch((err) => {
      logger.error({ err: safeErr(err) }, 'outbox consumer loop stopped');
    }).finally(() => {
      this.state = 'stopped';
      outboxMetrics.setConsumerUp(false);
    });
    logger.info({ batchSize: this.normalBatchSize, pollMs: this.pollMs }, 'outbox consumer started');
  }

  /** Wakes the loop now (a notification, a test). */
  poke(): void {
    this.wake.wake();
  }

  /** The batch in progress finishes; then the loop and the notification connection stop. Idempotent. */
  async stop(): Promise<void> {
    this.stopping = true;
    this.wake.wake();
    if (this.loop) await this.loop;
    this.loop = null;
    if (this.listener) await this.listener.close();
    this.listener = null;
    if (this.state !== 'disabled') this.state = 'stopped';
  }

  private async run(): Promise<void> {
    let tableReady = false;
    while (!this.stopping) {
      this.lastLoopAt = Date.now();
      if (!tableReady) {
        try {
          tableReady = await outboxTableReady();
          this.checkFailures = 0;
        } catch (err) {
          // The database fails, not the table (the check reads the catalogs
          // only): degraded, checked again after the wait of a failed pass,
          // not after the 30 s of a missing schema.
          this.checkFailures += 1;
          if (this.state !== 'degraded') this.degradedSince = Date.now();
          this.state = 'degraded';
          logger.warn({ err: safeErr(err), checkFailures: this.checkFailures }, 'outbox: table check failed');
          await this.wake.wait(Math.min(MAX_FAILURE_WAIT_MS, this.failureWaitBaseMs * 2 ** Math.min(this.checkFailures, 16)));
          continue;
        }
        if (!tableReady) {
          if (this.state !== 'waiting_schema') logger.warn('outbox: apple_edge.outbox missing or not usable by the runtime role: waiting');
          this.state = 'waiting_schema';
          await this.wake.wait(SCHEMA_WAIT_MS);
          continue;
        }
      }
      this.listener?.ensure();
      let locked = 0;
      try {
        // Idle: one probe per poll, no transaction (file-durable L3).
        if (await this.hasDueEvents()) locked = (await this.drainOnce(this.batchSize)).locked;
        this.failuresInARow = 0;
        this.batchSize = this.normalBatchSize;
        this.state = 'running';
        this.degradedSince = null;
        this.lastSuccessAt = Date.now();
      } catch (err) {
        this.failuresInARow += 1;
        if (this.state !== 'degraded') this.degradedSince = Date.now();
        this.state = 'degraded';
        tableReady = false;                                          // checked again before the next pass
        logger.error({ err: safeErr(err), failuresInARow: this.failuresInARow }, 'outbox batch failed');
        if (this.failuresInARow >= 2) this.batchSize = 1;          // isolate the culprit
        if (this.failuresInARow >= 3) await this.recordHeadFailure();
        await this.wake.wait(Math.min(MAX_FAILURE_WAIT_MS, this.failureWaitBaseMs * 2 ** Math.min(this.failuresInARow, 16)));
        continue;
      }
      this.lastLoopAt = Date.now();
      if (locked < this.batchSize && !this.stopping) await this.wake.wait(this.pollMs);
    }
  }

  /** Is an event due (not consumed, its next attempt reached)? One statement, no lock. */
  private async hasDueEvents(): Promise<boolean> {
    const res = await asNone(CONSUMER_ACTOR, () => db.raw(DUE_SQL)) as { rows: Array<{ due: boolean }> };
    return res.rows[0]?.due === true;
  }

  /** One pass (see the header). Throws when the pass itself fails. */
  async drainOnce(batchSize = this.batchSize): Promise<DrainResult> {
    const t0 = Date.now();
    const collector: EventCollector = { effects: [], audits: [] };
    const counted: Array<{ type: string; outcome: 'applied' | 'retry' | 'dead_letter'; reason?: string }> = [];
    let mismatches = 0;
    const result: DrainResult = { locked: 0, applied: 0, retried: 0, deadLettered: 0 };
    await asNone(CONSUMER_ACTOR, () => db.transaction(async (trx) => {
      await trx.raw("SET LOCAL statement_timeout = '30s'; SET LOCAL lock_timeout = '5s'");
      const head = (await trx.raw(HEAD_SQL, [Math.max(1, Math.floor(batchSize))]) as
        { rows: Array<{ seq: string; attempts: number; bytes: number }> }).rows;
      result.locked = head.length;
      if (head.length === 0) return;
      const take: string[] = [];
      let bytes = 0;
      for (const h of head) {
        const b = Number(h.bytes) || 0;
        if (take.length > 0 && bytes + b > MAX_BATCH_BYTES) break;
        take.push(String(h.seq));
        bytes += b;
      }
      const prior = new Map(head.map((h) => [String(h.seq), Number(h.attempts) || 0]));
      const rows = ((await trx.raw(LOAD_SQL, [take]) as { rows: OutboxRow[] }).rows).sort(byOccurrence);
      const tenants = await tenantIdsOfKeys(trx, rows.map((r) => r.tenant_key ?? ''));
      const scope = new EventScope(trx, CONSUMER_ACTOR);
      const resolveTenant = async (key: string): Promise<number | null> => {
        const known = tenants.get(key);
        if (known !== undefined) return known;
        // A tenant.created applied earlier in this batch may have set the key.
        await scope.toNone();
        const again = await tenantIdsOfKeys(trx, [key]);
        const id = again.get(key) ?? null;
        if (id !== null) tenants.set(key, id);
        return id;
      };
      const consumed: string[] = [];
      for (const row of rows) {
        if (Date.now() - t0 > TIME_BUDGET_MS) break;
        const priorAttempts = prior.get(String(row.seq)) ?? 0;
        const { outcome, tenantId } = await applyEvent(trx, row, { priorAttempts, resolveTenant, redrive: false, collector, scope });
        if (outcome.kind === 'applied') {
          if (priorAttempts > 0) {
            await scope.toNone();
            await clearAttempts(trx, row.event_id);
          }
          consumed.push(String(row.seq));
          result.applied += 1;
          counted.push({ type: row.type, outcome: 'applied' });
        } else if (outcome.kind === 'retry') {
          await scope.toNone();
          await recordAttempt(trx, row, outcome.attempts, outcome.delaySeconds, outcome.code);
          result.retried += 1;
          counted.push({ type: row.type, outcome: 'retry' });
          logger.warn({ eventId: row.event_id, seq: row.seq, type: row.type, tenantId, reason: outcome.reason, code: outcome.code,
            attempts: outcome.attempts }, 'outbox event retried later');
        } else {
          await scope.toNone();
          await recordDeadLetter(trx, row, tenantId, outcome.reason, outcome.attempts, outcome.code);
          consumed.push(String(row.seq));
          result.deadLettered += 1;
          if (outcome.reason === 'tenant_mismatch') mismatches += 1;
          counted.push({ type: row.type, outcome: 'dead_letter', reason: outcome.reason });
          logger.error({ eventId: row.event_id, seq: row.seq, type: row.type, tenantId, reason: outcome.reason, code: outcome.code,
            attempts: outcome.attempts }, 'outbox event moved to the dead letters');
        }
      }
      // The consumer's context again (the last savepoint released) for its own statements.
      await scope.toNone();
      if (collector.audits.length > 0) {
        await audit.appendManyInTx(trx, collector.audits,
          audit.fromJob({ name: CONSUMER_NAME, requestId: `batch-${rows[0].seq}` }),
          { onFailure: 'spool' });
      }
      if (consumed.length > 0) await trx.raw(MARK_SQL, [consumed]);
    }));
    // Committed: metrics, effects (in order), alerts.
    for (const c of counted) {
      outboxMetrics.event(c.type, c.outcome);
      if (c.reason) outboxMetrics.deadLetter(c.reason);
    }
    outboxMetrics.batch(Date.now() - t0);
    await runEffects(collector.effects);
    if (mismatches > 0) {
      await raiseJobAlert(CONSUMER_ACTOR, {
        stableKey: 'outbox:tenant-mismatch',
        severity: 'critical',
        title: 'apple-edge event outside its tenant',
        message: `${mismatches} event(s) of apple-edge named an enrollment of another tenant: moved to the dead letters (defect or forgery).`,
      });
    }
    return result;
  }

  /** Third failed pass in a row: an attempt (batch_failure) for the head event, in its own transaction; at
   *  the 5th, its dead letter. */
  private async recordHeadFailure(): Promise<void> {
    try {
      await asNone(CONSUMER_ACTOR, () => db.transaction(async (trx) => {
        await trx.raw("SET LOCAL statement_timeout = '30s'; SET LOCAL lock_timeout = '5s'");
        const head = (await trx.raw(HEAD_SQL, [1]) as { rows: Array<{ seq: string; attempts: number }> }).rows[0];
        if (!head) return;
        const row = ((await trx.raw(LOAD_SQL, [[head.seq]]) as { rows: OutboxRow[] }).rows)[0];
        if (!row) return;
        const attempts = (Number(head.attempts) || 0) + 1;
        if (attempts >= MAX_ATTEMPTS) {
          const tenantId = row.tenant_key ? (await tenantIdsOfKeys(trx, [row.tenant_key])).get(row.tenant_key) ?? null : null;
          await recordDeadLetter(trx, row, tenantId, 'handler_error', attempts, 'batch_failure');
          await trx.raw(MARK_SQL, [[String(row.seq)]]);
          outboxMetrics.deadLetter('handler_error');
          logger.error({ eventId: row.event_id, seq: row.seq, type: row.type, attempts }, 'outbox event that fails its batch moved to the dead letters');
        } else {
          await recordAttempt(trx, row, attempts, RETRY_DELAYS_S[attempts - 1], 'batch_failure');
          logger.warn({ eventId: row.event_id, seq: row.seq, type: row.type, attempts }, 'outbox: attempt recorded for the head event of failed batches');
        }
      }));
    } catch (err) {
      logger.error({ err: safeErr(err) }, 'outbox: the failure of the head event could not be recorded');
    }
  }
}

/** afterCommit effects, in order; an error is logged, never retried. */
export async function runEffects(effects: Array<() => void | Promise<void>>): Promise<void> {
  for (const fn of effects) {
    try {
      await fn();
    } catch (err) {
      logger.warn({ err: safeErr(err) }, 'outbox: an effect after the commit failed');
    }
  }
}

// ── The consumer of this process ──────────────────────────────────────────────

export const outboxConsumer = new OutboxConsumer();

/** jobs.startWorkers(): OUTBOX_CONSUMER 'on' starts the loop (waiting for the table if needed), 'auto' when
 *  the table exists, 'off' never; only where jobs run (JOBS_MODE=all). */
export async function startOutboxConsumer(jobsMode: JobsMode): Promise<OutboxConsumerState> {
  const mode = config.outbox.consumer;
  if (mode === 'off' || jobsMode !== 'all') {
    outboxConsumer.state = 'disabled';
    return 'disabled';
  }
  if (mode === 'auto' && !(await outboxTableReady().catch(() => false))) {
    outboxConsumer.state = 'disabled';
    logger.info('outbox consumer: OUTBOX_CONSUMER=auto and no apple_edge.outbox: not started');
    return 'disabled';
  }
  outboxConsumer.start();
  return outboxConsumer.state;
}
