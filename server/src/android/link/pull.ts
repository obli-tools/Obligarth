// The pull loop android.pubsub-pull (section 7.1): one per instance (advisory lock on a dedicated connection),
// synchronous pull of the project's subscription, routing of each message by its enterprise, write into the inbox of
// the enterprise's tenant, acknowledgement after the commit only.
//   - 'test' messages: counted, acknowledged without any write (platform proof, last_test_message_at);
//   - no extractable enterprise: acknowledged, counted (unparsable);
//   - enterprise unknown to the instance or unlinked: acknowledged without any write, counted, platform security
//     alert above 10 per hour; the payload is never written nor logged;
//   - over ANDROID_INBOX_MAX_BYTES: a reduced event amapi.oversized { type, resource_name };
//   - per tenant, one transaction: INSERT … ON CONFLICT (tenant_id, message_id) DO NOTHING, then the drain job of the
//     tenant (sendInTx, singletonKey t:<id>); a tenant whose write fails keeps its messages unacknowledged.
// A failure of the database acknowledges nothing (the deadline expires, Pub/Sub delivers again). After an absence of
// more than 7 days, seek first (AN37). The only timer of the module (G-A5), like the outbox consumer.
import type { Knex } from 'knex';
import pg from 'pg';
import type { PubsubReceived } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { asNone, asTenant, type DbActor } from '../../db/context';
import { logger } from '../../utils/logger';
import { raiseAndroidPlatformAlert } from '../alerts';
import { androidConfig, type AndroidConfig } from '../config';
import { readPlatformState, updatePlatformState } from '../enterprises/registry';
import { AndroidError, AndroidResponseTooLargeError } from '../gateway/errors';
import { androidGateway } from '../gateway';
import type { AndroidGateway } from '../gateway/types';
import { classifyMessage } from '../inbox/schemas';
import { androidMetrics } from '../metrics';
import { androidWait } from '../wait';

export const PULL_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.pubsub-pull' }) as DbActor;
const SEEK_AFTER_MS = 7 * 86_400_000;
const FOREIGN_ALERT_PER_HOUR = 10;

/** Sends the drain job of a tenant inside the inbox transaction (jobs.ts sets it; tests may replace it). */
type DrainSender = (trx: Knex.Transaction, tenantId: number) => Promise<unknown>;
let drainSender: DrainSender = async () => undefined;
export function setDrainSender(fn: DrainSender): void { drainSender = fn; }
/** Sends the android.inbox-drain of a tenant in `trx` (the reconciliation writes reports to the inbox too: lot AN-H1). */
export function sendDrainInTx(trx: Knex.Transaction, tenantId: number): Promise<unknown> { return drainSender(trx, tenantId); }

export interface PullOutcome {
  received: number;
  written: number;
  duplicates: number;
  tests: number;
  foreign: number;
  unparsable: number;
  oversized: number;
  acknowledged: number;
  failedTenants: number[];
}

const foreignTimes: number[] = [];
let lastPullStamp = 0;

function noteForeign(): void {
  const now = Date.now();
  foreignTimes.push(now);
  while (foreignTimes.length && now - foreignTimes[0] > 3_600_000) foreignTimes.shift();
  if (foreignTimes.length > FOREIGN_ALERT_PER_HOUR) {
    void raiseAndroidPlatformAlert('android.pubsub_foreign_message', { lastHour: foreignTimes.length }, new Date().toISOString().slice(0, 13));
  }
}

interface Row {
  tenant_id: number;
  message_id: string;
  event_type: string;
  enterprise_name: string;
  resource_name: string | null;
  published_at: Date;
  occurred_at: Date;
  payload: string | null;
  payload_bytes: number;
}

/** One pull: returns what it did. Throws on a database failure (nothing acknowledged). */
export async function pullOnce(o: { gateway?: AndroidGateway; cfg?: AndroidConfig; maxMessages?: number; signal?: AbortSignal } = {}): Promise<PullOutcome> {
  const gw = o.gateway ?? androidGateway();
  const cfg = o.cfg ?? androidConfig();
  const out: PullOutcome = { received: 0, written: 0, duplicates: 0, tests: 0, foreign: 0, unparsable: 0, oversized: 0, acknowledged: 0, failedTenants: [] };
  const messages: PubsubReceived[] = await asNone(PULL_ACTOR, () => gw.pull({ maxMessages: o.maxMessages ?? cfg.pullMaxMessages, signal: o.signal }));
  out.received = messages.length;
  if (Date.now() - lastPullStamp > 60_000 || messages.length) {
    lastPullStamp = Date.now();
    await asNone(PULL_ACTOR, () => updatePlatformState(db, { last_pull_at: new Date() }));
  }
  if (!messages.length) return out;
  const ackIds = messages.map((m) => m.ackId).filter((a) => typeof a === 'string');
  if (messages.length > 1) await gw.modifyAckDeadline(ackIds, 60).catch(() => undefined);

  const toAck: string[] = [];
  const perTenant = new Map<number, { rows: Row[]; acks: string[] }>();
  let lastTest: Date | null = null;
  await asNone(PULL_ACTOR, async () => {
    const lookups = new Map<string, number | null>();
    for (const m of messages) {
      const msg = m.message ?? ({} as PubsubReceived['message']);
      const publishTime = Number.isFinite(Date.parse(msg.publishTime)) ? new Date(msg.publishTime) : new Date();
      const type = msg.attributes?.notificationType;
      const raw = typeof msg.data === 'string' ? Buffer.from(msg.data, 'base64') : Buffer.alloc(0);
      const oversized = raw.length > cfg.inboxMaxBytes;
      let decoded: unknown = null;
      if (!oversized) {
        try { decoded = JSON.parse(raw.toString('utf8')); } catch { decoded = null; }
      } else {
        // Only the head is read, to find the resource name; the rest is never kept.
        const m2 = /"(?:name|device|enterprise)"\s*:\s*"(enterprises\/[A-Za-z0-9_/-]{1,300})"/.exec(raw.subarray(0, 4096).toString('utf8'));
        decoded = m2 ? { name: m2[1] } : null;
      }
      raw.fill(0);
      const c = classifyMessage(type, decoded, publishTime);
      if (c.kind === 'test') {
        out.tests += 1;
        androidMetrics.event('test', 'acknowledged');
        lastTest = publishTime;
        toAck.push(m.ackId);
        continue;
      }
      if (c.kind === 'unparsable' || typeof msg.messageId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(msg.messageId)) {
        out.unparsable += 1;
        androidMetrics.event(c.eventType, 'unparsable');
        toAck.push(m.ackId);
        continue;
      }
      const name = c.enterpriseName as string;
      if (!lookups.has(name)) {
        const r = await db.raw('SELECT obligarth.android_enterprise_lookup(?) AS t', [name]) as { rows: Array<{ t: number | null }> };
        lookups.set(name, r.rows[0]?.t ?? null);
      }
      const tenantId = lookups.get(name) ?? null;
      if (tenantId === null) {
        out.foreign += 1;
        androidMetrics.event(c.eventType, 'foreign_enterprise');
        noteForeign();
        toAck.push(m.ackId);
        continue;
      }
      let payload: string | null;
      let eventType: string = c.eventType;
      if (oversized) {
        out.oversized += 1;
        eventType = 'amapi.oversized';
        payload = JSON.stringify({ type: c.eventType, resource_name: c.resourceName });
      } else {
        payload = JSON.stringify(c.payload);
      }
      const entry = perTenant.get(tenantId) ?? { rows: [], acks: [] };
      entry.rows.push({
        tenant_id: tenantId, message_id: msg.messageId, event_type: eventType, enterprise_name: name, resource_name: c.resourceName,
        published_at: publishTime, occurred_at: c.occurredAt, payload, payload_bytes: payload ? Buffer.byteLength(payload) : 0,
      });
      entry.acks.push(m.ackId);
      perTenant.set(tenantId, entry);
    }
  });

  let maxPublish: Date | null = null;
  for (const [tenantId, entry] of perTenant) {
    try {
      const inserted = await asTenant(tenantId, PULL_ACTOR, () => db.transaction(async (trx) => {
        const r = await trx('android_inbox').insert(entry.rows.map((row) => ({ ...row, payload: row.payload === null ? null : trx.raw('?::jsonb', [row.payload]) })))
          .onConflict(['tenant_id', 'message_id']).ignore().returning('id');
        await drainSender(trx, tenantId);
        return r.length;
      }));
      out.written += inserted;
      out.duplicates += entry.rows.length - inserted;
      for (const row of entry.rows) {
        androidMetrics.event(row.event_type, 'written');
        if (!maxPublish || row.published_at > maxPublish) maxPublish = row.published_at;
      }
      toAck.push(...entry.acks);
    } catch (err) {
      out.failedTenants.push(tenantId);
      logger.warn({ tenantId, err: (err as { code?: string }).code ?? (err as Error)?.name }, 'android: inbox write failed, messages left unacknowledged');
    }
  }
  if (out.failedTenants.length === perTenant.size && perTenant.size > 0 && out.written === 0 && toAck.length === 0) {
    throw new Error('android: inbox writes failed');
  }
  await asNone(PULL_ACTOR, async () => {
    const patch: Record<string, Date> = {};
    if (lastTest) patch.last_test_message_at = lastTest;
    if (Object.keys(patch).length) await updatePlatformState(db, patch);
    if (maxPublish) {
      await db.raw(
        `INSERT INTO android_platform_state (id, last_applied_publish_at) VALUES (1, ?)
         ON CONFLICT (id) DO UPDATE SET last_applied_publish_at = GREATEST(android_platform_state.last_applied_publish_at, EXCLUDED.last_applied_publish_at),
           updated_at = now()`, [maxPublish]);
    }
  });
  if (toAck.length) {
    try {
      await gw.acknowledge(toAck);
      out.acknowledged = toAck.length;
    } catch (err) {
      // Harmless: the messages come back and are deduplicated by message_id.
      logger.warn({ err: (err as AndroidError)?.kind ?? 'error' }, 'android: acknowledge failed');
    }
  }
  return out;
}

/** Seek after an absence of more than 7 days (AN37): to the last applied publishTime minus one hour. */
export async function seekIfAbsent(gw: AndroidGateway = androidGateway(), now = Date.now()): Promise<Date | null> {
  const state = await asNone(PULL_ACTOR, () => readPlatformState());
  if (!state.last_pull_at || now - new Date(state.last_pull_at).getTime() <= SEEK_AFTER_MS || !state.last_applied_publish_at) return null;
  const target = new Date(new Date(state.last_applied_publish_at).getTime() - 3_600_000);
  if (now - new Date(state.last_pull_at).getTime() > 3 * 86_400_000) {
    void raiseAndroidPlatformAlert('android.retention_risk', { days: Math.floor((now - new Date(state.last_pull_at).getTime()) / 86_400_000) });
  }
  await asNone(PULL_ACTOR, () => gw.seek(target));
  logger.info({ android: { seek: target.toISOString() } }, 'android: subscription seeked after an absence');
  return target;
}

export type PullLoopState = 'stopped' | 'waiting_lock' | 'running' | 'degraded';

/** The loop of this process (started by registerAndroidModule's start task in google and fake modes). */
export class AndroidPullLoop {
  private running = false;
  private lockClient: pg.Client | null = null;
  private abort: AbortController | null = null;
  private loopDone: Promise<void> | null = null;
  private batch: number;
  state: PullLoopState = 'stopped';
  failures = 0;
  lastSuccessAt = 0;

  constructor(private readonly o: { gateway?: AndroidGateway; cfg?: AndroidConfig; connectionString?: string; idleWaitMs?: number } = {}) {
    this.batch = (o.cfg ?? androidConfig()).pullMaxMessages;
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.abort = new AbortController();
    this.loopDone = this.run();
  }

  private async tryLock(): Promise<boolean> {
    if (this.lockClient) return true;
    const client = new pg.Client({ connectionString: this.o.connectionString ?? config.databaseUrl, application_name: 'obligarth-android-pull' });
    try {
      await client.connect();
      const r = await client.query("SELECT pg_try_advisory_lock(hashtext('android.pubsub-pull')) AS ok");
      if (r.rows[0]?.ok === true) {
        client.on('error', () => { this.lockClient = null; });
        this.lockClient = client;
        return true;
      }
    } catch { /* retried */ }
    await client.end().catch(() => undefined);
    return false;
  }

  private async run(): Promise<void> {
    const signal = this.abort!.signal;
    while (this.running) {
      if (!(await this.tryLock())) {
        this.state = 'waiting_lock';
        await androidWait(30_000, signal);
        continue;
      }
      if (this.state !== 'running' && this.state !== 'degraded') {
        try { await seekIfAbsent(this.o.gateway); } catch (err) { logger.warn({ err: (err as AndroidError)?.kind ?? 'error' }, 'android: seek failed'); }
      }
      try {
        const r = await pullOnce({ gateway: this.o.gateway, cfg: this.o.cfg, maxMessages: this.batch, signal });
        this.failures = 0;
        this.lastSuccessAt = Date.now();
        this.state = 'running';
        this.batch = (this.o.cfg ?? androidConfig()).pullMaxMessages;
        if (r.received === 0) await androidWait(this.o.idleWaitMs ?? 1_000, signal);
      } catch (err) {
        if (!this.running) break;
        if (err instanceof AndroidResponseTooLargeError) {
          this.batch = this.batch > 10 ? 10 : 1;
          continue;
        }
        this.failures += 1;
        this.state = 'degraded';
        if (err instanceof AndroidError && err.kind === 'auth') void raiseAndroidPlatformAlert('android.google_auth_failed', {});
        else if (this.failures >= 5) void raiseAndroidPlatformAlert('android.google_unreachable', { failures: this.failures });
        await androidWait(Math.min(30_000, 1_000 * 2 ** Math.min(5, this.failures - 1)), signal);
      }
    }
  }

  async stop(): Promise<void> {
    this.running = false;
    this.abort?.abort();
    await this.loopDone?.catch(() => undefined);
    this.state = 'stopped';
    const c = this.lockClient;
    this.lockClient = null;
    if (c) await c.end().catch(() => undefined);
  }

  status() {
    return { state: this.state, failures: this.failures, lastSuccessAt: this.lastSuccessAt, batch: this.batch, locked: this.lockClient !== null };
  }
}

