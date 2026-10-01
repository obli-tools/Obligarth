// The SIEM exporter (docs: audit-durci §8.5): a continuous loop of the server
// (not a job), started by a start task when JOBS_MODE=all and AUDIT_EXPORT is
// not 'off', stopped by a stop task. One active per instance: a session
// advisory lock on a dedicated connection, which also LISTENs on
// obligarth_audit and reads no table (RLS §4.4). Woken by a notification or
// every 5 s (every minute while no destination is enabled: creating one
// writes an entry, whose notification wakes the loop). For each enabled
// destination not waiting: the chains of its
// scope whose head is beyond its cursor, round-robin between tenants, 500
// entries at most per tenant and pass, each chain read in its tenant's
// context (a deleted tenant's remaining entries too); a `gap` first when the
// cursor is below the anchor; on success the cursor moves; on failure the
// destination waits (5 s, 30 s, 2 min, then 10 min). Then the seals beyond
// last_seal_seq (include_seals). A cursor beyond the head (truncated chain,
// base restored without restore-reconcile) sends nothing, is counted and
// alerted, and is never moved back automatically.
import pg from 'pg';
import { config } from '../../config';
import { db } from '../../db';
import { asNone, asPlatform, asTenant, type DbActor } from '../../db/context';
import { openPlatformGrant, type PlatformGrant } from '../../db/platformAccess';
import { logger } from '../../utils/logger';
import { auditMetrics } from '../metrics';
import { instanceId } from '../seal';
import { listDestinationRows, openSecrets, type DestinationRow } from './destinations';
import { entryMessage, gapMessage, sealMessageOf, testMessage, type SealMessageLeaf } from './message';
import { openSyslog, syslogFrame, type SyslogConnection, type SyslogTlsSettings } from './syslog';
import { batchSize, postWebhook, type WebhookSecrets, type WebhookSettings } from './webhook';

export const EXPORT_ACTOR: DbActor = { type: 'job', name: 'audit.export' };
const LOCK_SQL = "SELECT pg_try_advisory_lock(hashtext('obligarth.audit_export')) AS ok";
const PER_TENANT = 500;
const WAKE_MS = 5_000;
/** Without any enabled destination, the periodic pass every minute only (a
 *  destination created anywhere writes an entry: its NOTIFY wakes the loop). */
const IDLE_TICKS = 12;
const LOCK_RETRY_MS = 30_000;
const GRANT_RENEW_MS = 14 * 60_000;
const RETRY_DELAYS_MS = [5_000, 30_000, 120_000, 600_000];
const ERROR_RETRY_MS = 600_000;
const SEALS_PER_PASS = 50;

interface DestState {
  failures: number;
  nextAttemptAt: number;
  syslog?: SyslogConnection;
  rr: number;
  alerted?: boolean;
}

type Delivery = { ok: true } | { ok: false; retryable: boolean; code: string };

/** Sends messages to one destination (one batch). */
async function deliver(dest: DestinationRow, state: DestState, instance: string, messages: Array<{ text: string; msgid: 'audit' | 'seal' | 'gap' | 'test'; ts: string }>): Promise<Delivery> {
  const cfg = (typeof dest.config === 'string' ? JSON.parse(dest.config) : dest.config) as Record<string, unknown>;
  const secrets = await openSecrets(dest).catch(() => null);
  if (secrets === null) return { ok: false, retryable: true, code: 'secrets_unreadable' };
  if (dest.kind === 'webhook') {
    const w = cfg as unknown as WebhookSettings;
    if (!('hmacSecret' in secrets) || !secrets.hmacSecret) return { ok: false, retryable: false, code: 'secrets_missing' };
    let i = 0;
    const texts = messages.map((m) => m.text);
    while (i < texts.length) {
      const n = batchSize(texts.slice(i), { maxBatch: Number(w.maxBatch ?? 200), maxBatchBytes: Number(w.maxBatchBytes ?? 1_048_576) });
      const r = await postWebhook({ ...w, maxBatch: Number(w.maxBatch ?? 200), maxBatchBytes: Number(w.maxBatchBytes ?? 1_048_576), timeoutSeconds: Number(w.timeoutSeconds ?? 10), includeEvent: w.includeEvent !== false },
        secrets as WebhookSecrets, instance, texts.slice(i, i + n), { allowLoopback: config.audit.siemAllowLoopback });
      if (!r.ok) return r;
      i += n;
    }
    return { ok: true };
  }
  const s = cfg as unknown as SyslogTlsSettings;
  try {
    if (!state.syslog || state.syslog.closed) {
      state.syslog = await openSyslog(s, secrets as { clientKeyPem?: string }, { allowLoopback: config.audit.siemAllowLoopback });
    }
    const hostname = s.hostname || (() => { try { return new URL(config.appUrl || 'http://obligarth.invalid').hostname; } catch { return 'obligarth'; } })();
    await state.syslog.send(messages.map((m) => syslogFrame(m.text, { hostname, msgid: m.msgid, timestamp: m.ts })));
    return { ok: true };
  } catch (err) {
    state.syslog?.close();
    state.syslog = undefined;
    const code = (err as { code?: unknown }).code;
    return { ok: false, retryable: true, code: typeof code === 'string' ? code.slice(0, 64) : 'network' };
  }
}

function tsOfBody(body: string): string {
  const m = /"ts":"([0-9T:.\-]+Z)"/.exec(body);
  return m ? m[1] : new Date().toISOString();
}

export class AuditExporter {
  private conn: pg.Client | null = null;
  private timer: NodeJS.Timeout | null = null;
  private lockTimer: NodeJS.Timeout | null = null;
  private running = false;
  private idle = false;
  private idleTicks = 0;
  private current: Promise<void> | null = null;
  private again = false;
  private stopped = false;
  private states = new Map<number, DestState>();
  private grant: { grant: PlatformGrant; at: number } | null = null;
  private slugs = new Map<number, string | null>();

  /** Takes the instance's lock (or waits for it), listens, and starts the loop. */
  async start(): Promise<void> {
    this.stopped = false;
    await this.tryLock();
  }

  private async tryLock(): Promise<void> {
    if (this.stopped) return;
    try {
      const client = new pg.Client({ connectionString: config.databaseUrl, application_name: 'obligarth-audit-exporter' });
      client.on('error', (err) => {
        logger.warn({ err: { code: (err as { code?: string }).code } }, 'audit exporter: connection lost');
        this.dropConnection();
        this.retryLock();
      });
      await client.connect();
      const res = await client.query(LOCK_SQL);
      if (!res.rows[0]?.ok) {
        await client.end().catch(() => undefined);
        this.retryLock();
        return;
      }
      await client.query('LISTEN obligarth_audit');
      client.on('notification', () => this.wake());
      this.conn = client;
      this.timer = setInterval(() => this.tick(), WAKE_MS);
      logger.info('audit exporter started');
      this.wake();
    } catch (err) {
      logger.warn({ err: { code: (err as { code?: string }).code, name: (err as Error).name } }, 'audit exporter: lock not taken, retrying');
      this.dropConnection();
      this.retryLock();
    }
  }

  /** Another attempt at the lock in 30 s (another instance holds it, or the
   *  connection was lost). */
  private retryLock(): void {
    if (this.stopped || this.lockTimer) return;
    this.lockTimer = setTimeout(() => { this.lockTimer = null; void this.tryLock(); }, LOCK_RETRY_MS);
  }

  private dropConnection(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    const c = this.conn;
    this.conn = null;
    if (c) void c.end().catch(() => undefined);
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.lockTimer) { clearTimeout(this.lockTimer); this.lockTimer = null; }
    this.dropConnection();
    for (const s of this.states.values()) s.syslog?.close();
    this.states.clear();
    // The pass under way ends by itself (its deliveries have their timeouts).
    if (this.current) await this.current;
  }

  /** Is this instance the active exporter? */
  isActive(): boolean {
    return this.conn !== null && !this.stopped;
  }

  /** The periodic wake: every 5 s, every minute while no destination is enabled. */
  private tick(): void {
    if (this.idle && ++this.idleTicks < IDLE_TICKS) return;
    this.idleTicks = 0;
    this.wake();
  }

  wake(): void {
    if (this.stopped || !this.conn) return;
    if (this.running) { this.again = true; return; }
    this.running = true;
    this.current = asNone(EXPORT_ACTOR, () => this.pass()).catch((err) => {
      logger.error({ err: { name: (err as Error).name, code: (err as { code?: unknown }).code } }, 'audit exporter: pass failed');
    }).finally(() => {
      this.running = false;
      this.current = null;
      if (this.again && !this.stopped) { this.again = false; this.wake(); }
    });
  }

  /** One pass over every enabled destination (exposed for the tests). */
  async pass(): Promise<void> {
    const dests = (await listDestinationRows()).filter((d) => d.enabled);
    auditMetrics.set('obligarth_audit_export_destinations', dests.length, { state: 'enabled' });
    this.idle = dests.length === 0;
    if (!dests.length) return;
    const instance = await instanceId();
    const chains = (await db.raw('SELECT tenant_id, last_seq, anchor_seq, tenant_exists FROM obligarth.audit_chains()') as {
      rows: Array<{ tenant_id: number; last_seq: string | number; anchor_seq: string | number; tenant_exists: boolean }>;
    }).rows.map((c) => ({ tenantId: Number(c.tenant_id), head: Number(c.last_seq), anchor: Number(c.anchor_seq) }));
    for (const d of dests) {
      if (this.stopped) return;
      const state = this.states.get(d.id) ?? { failures: 0, nextAttemptAt: 0, rr: 0 };
      this.states.set(d.id, state);
      if (state.nextAttemptAt > Date.now()) continue;
      await this.serve(d, state, instance, chains);
    }
  }

  private async tenantSlug(tenantId: number): Promise<string | null> {
    if (this.slugs.has(tenantId)) return this.slugs.get(tenantId) ?? null;
    const r = await db('tenants').where({ id: tenantId }).first('slug') as { slug: string } | undefined;
    this.slugs.set(tenantId, r?.slug ?? null);
    return r?.slug ?? null;
  }

  private failed(d: DestinationRow, state: DestState, r: { retryable: boolean; code: string }): Promise<unknown> {
    state.failures++;
    const delay = r.retryable ? RETRY_DELAYS_MS[Math.min(state.failures - 1, RETRY_DELAYS_MS.length - 1)] : ERROR_RETRY_MS;
    state.nextAttemptAt = Date.now() + delay;
    auditMetrics.inc('obligarth_audit_export_errors_total', { destination: d.id, code: r.code });
    logger.warn({ destination: d.id, code: r.code, retryInMs: delay }, 'audit exporter: delivery failed');
    const work = db('audit_export_destinations').where({ id: d.id })
      .update({ last_error_at: db.fn.now(), last_error_code: r.code.slice(0, 64) });
    if ((!r.retryable || state.failures >= 4) && !state.alerted) {
      state.alerted = true;
      void import('../../jobs/alerts').then(({ raiseJobAlert }) => raiseJobAlert(EXPORT_ACTOR, {
        stableKey: `audit:export-failing:${d.id}`, severity: 'warning',
        title: 'SIEM destination failing',
        message: `The audit export to destination ${d.id} fails (${r.code}).`,
      })).catch(() => undefined);
    }
    return work;
  }

  private async succeeded(d: DestinationRow, state: DestState): Promise<void> {
    state.failures = 0;
    state.nextAttemptAt = 0;
    state.alerted = false;
    await db('audit_export_destinations').where({ id: d.id }).update({ last_success_at: db.fn.now() });
  }

  private async serve(d: DestinationRow, state: DestState, instance: string,
    chains: Array<{ tenantId: number; head: number; anchor: number }>): Promise<void> {
    const cfg = (typeof d.config === 'string' ? JSON.parse(d.config) : d.config) as Record<string, unknown>;
    const includeEvent = cfg.includeEvent !== false;
    const maxBytes = d.kind === 'syslog_tls' ? Number(cfg.maxMessageBytes ?? 65_536) : undefined;
    const scoped = d.scope_tenant_id != null ? Number(d.scope_tenant_id) : null;
    const mine = chains.filter((c) => scoped === null || c.tenantId === scoped);
    const cursors = new Map((await db('audit_export_cursors').where({ destination_id: d.id }).select('tenant_id', 'last_seq') as
      Array<{ tenant_id: number; last_seq: string | number }>).map((c) => [Number(c.tenant_id), Number(c.last_seq)]));
    const n = mine.length;
    let delivered = false;
    for (let k = 0; k < n; k++) {
      if (this.stopped) return;
      const c = mine[(state.rr + k) % n];
      let cursor = cursors.get(c.tenantId) ?? 0;
      if (cursor > c.head) {
        auditMetrics.inc('obligarth_audit_export_cursor_ahead_total', { destination: d.id });
        logger.error({ code: 'AUDIT_EXPORT_CURSOR_AHEAD', destination: d.id, tenantId: c.tenantId, cursor, head: c.head },
          'audit exporter: cursor beyond the head of the chain (truncated chain or restored base)');
        void import('../../jobs/alerts').then(({ raiseJobAlert }) => raiseJobAlert(EXPORT_ACTOR, {
          stableKey: `audit:cursor-ahead:${d.id}:${c.tenantId}`, severity: 'critical',
          title: 'Audit chain behind its SIEM copy',
          message: `The SIEM destination ${d.id} received entries of tenant ${c.tenantId} the database no longer has: truncation or restore.`,
        })).catch(() => undefined);
        continue;
      }
      if (cursor >= c.head) continue;
      const messages: Array<{ text: string; msgid: 'audit' | 'seal' | 'gap' | 'test'; ts: string }> = [];
      let gapTo: number | null = null;
      if (cursor < c.anchor) {
        messages.push({ text: gapMessage(instance, c.tenantId, cursor + 1, c.anchor), msgid: 'gap', ts: new Date().toISOString() });
        gapTo = c.anchor;
        cursor = c.anchor;
      }
      const slug = await this.tenantSlug(c.tenantId);
      const rows = await asTenant(c.tenantId, EXPORT_ACTOR, () => db('audit_logs')
        .where('tenant_id', c.tenantId).andWhere('chain_seq', '>', cursor)
        .orderBy('chain_seq').limit(PER_TENANT).select('chain_seq', 'prev_hash', 'hash', 'body')) as
        Array<{ chain_seq: string | number; prev_hash: Buffer; hash: Buffer; body: string }>;
      for (const r of rows) {
        messages.push({
          text: entryMessage({ instance, tenant: c.tenantId, tenantSlug: slug, seq: Number(r.chain_seq), prev: r.prev_hash.toString('hex'), hash: r.hash.toString('hex'), body: r.body },
            { includeEvent, maxBytes }),
          msgid: 'audit', ts: tsOfBody(r.body),
        });
      }
      if (!messages.length) continue;
      const res = await deliver(d, state, instance, messages);
      if (!res.ok) { await this.failed(d, state, res); return; }
      delivered = true;
      const last = rows.length ? Number(rows[rows.length - 1].chain_seq) : (gapTo ?? cursor);
      await db('audit_export_cursors').insert({ destination_id: d.id, tenant_id: c.tenantId, last_seq: last, last_sent_at: db.fn.now() })
        .onConflict(['destination_id', 'tenant_id']).merge();
      auditMetrics.inc('obligarth_audit_exported_total', { destination: d.id }, rows.length);
    }
    state.rr = n ? (state.rr + 1) % n : 0;
    if (d.include_seals) {
      const sent = await this.serveSeals(d, state, instance, scoped);
      if (sent === null) return;
      if (sent > 0) delivered = true;
    }
    if (delivered || state.failures > 0) await this.succeeded(d, state);
  }

  private async platformGrant(): Promise<PlatformGrant> {
    if (!this.grant || Date.now() - this.grant.at > GRANT_RENEW_MS) {
      this.grant = { grant: await openPlatformGrant({ actor: EXPORT_ACTOR, reason: 'job:audit.export' }), at: Date.now() };
    }
    return this.grant.grant;
  }

  /** Seals sent (0: none to send), or null on a failure. */
  private async serveSeals(d: DestinationRow, state: DestState, instance: string, scoped: number | null): Promise<number | null> {
    const fresh = await db('audit_export_destinations').where({ id: d.id }).first('last_seal_seq') as { last_seal_seq: string | number };
    const seals = await db('audit_seals').where('seal_seq', '>', Number(fresh?.last_seal_seq ?? 0)).orderBy('seal_seq').limit(SEALS_PER_PASS) as
      Array<{ id: string | number; seal_seq: string | number; sealed_at: Date; leaf_count: number; merkle_root: Buffer; prev_seal_hash: Buffer;
        seal_hash: Buffer; key_id: string; signature: Buffer; tsa_status: string; tsa_token: Buffer | null; tsa_gen_time: Date | null }>;
    if (!seals.length) return 0;
    const ids = seals.map((s) => s.id);
    type LeafRow = { seal_id: string | number; tenant_id: number; leaf_index: number; chain_seq: string | number; chain_hash: Buffer; proof: Buffer[] };
    const leafRows = scoped === null
      ? await asPlatform(await this.platformGrant(), () => db('audit_seal_leaves').whereIn('seal_id', ids).orderBy(['seal_id', 'leaf_index'])) as LeafRow[]
      : await asTenant(scoped, EXPORT_ACTOR, () => db('audit_seal_leaves').whereIn('seal_id', ids).andWhere('tenant_id', scoped)) as LeafRow[];
    const messages = seals.map((s) => {
      const leafList: SealMessageLeaf[] = leafRows.filter((l) => String(l.seal_id) === String(s.id)).map((l) => ({
        tenant: Number(l.tenant_id), index: Number(l.leaf_index), seq: Number(l.chain_seq), hash: l.chain_hash.toString('hex'),
        proof: (l.proof ?? []).map((p) => Buffer.from(p).toString('hex')),
      }));
      return {
        text: sealMessageOf({
          instance, seq: Number(s.seal_seq), sealedAt: new Date(s.sealed_at).toISOString(), leaves: Number(s.leaf_count),
          root: s.merkle_root.toString('hex'), prev: s.prev_seal_hash.toString('hex'), hash: s.seal_hash.toString('hex'), keyId: s.key_id,
          signature: s.signature.toString('hex'),
          tsa: { status: s.tsa_status, genTime: s.tsa_gen_time ? new Date(s.tsa_gen_time).toISOString() : null, token: s.tsa_token ? s.tsa_token.toString('base64') : null },
          leafList,
        }, scoped),
        msgid: 'seal' as const,
        ts: new Date(s.sealed_at).toISOString(),
      };
    });
    const res = await deliver(d, state, instance, messages);
    if (!res.ok) { await this.failed(d, state, res); return null; }
    await db('audit_export_destinations').where({ id: d.id }).update({ last_seal_seq: Number(seals[seals.length - 1].seal_seq) });
    return seals.length;
  }

  /** A `test` message to one destination (POST /destinations/:id/test). */
  async test(d: DestinationRow): Promise<Delivery> {
    const instance = await instanceId();
    const state: DestState = { failures: 0, nextAttemptAt: 0, rr: 0 };
    try {
      return await deliver(d, state, instance, [{ text: testMessage(instance, d.uuid), msgid: 'test', ts: new Date().toISOString() }]);
    } finally {
      state.syslog?.close();
    }
  }
}

/** The exporter of this process. */
export const auditExporter = new AuditExporter();

/** Age of the oldest entry a destination has not received (seconds), for the
 *  monitor; null when it is up to date. */
export async function exportLagSeconds(d: DestinationRow): Promise<number | null> {
  const scoped = d.scope_tenant_id != null ? Number(d.scope_tenant_id) : null;
  const chains = (await db.raw('SELECT tenant_id, last_seq, anchor_seq FROM obligarth.audit_chains()') as {
    rows: Array<{ tenant_id: number; last_seq: string | number; anchor_seq: string | number }>;
  }).rows.filter((c) => scoped === null || Number(c.tenant_id) === scoped);
  const cursors = new Map((await db('audit_export_cursors').where({ destination_id: d.id }).select('tenant_id', 'last_seq') as
    Array<{ tenant_id: number; last_seq: string | number }>).map((c) => [Number(c.tenant_id), Number(c.last_seq)]));
  let oldest: number | null = null;
  for (const c of chains) {
    const cursor = Math.max(cursors.get(Number(c.tenant_id)) ?? 0, Number(c.anchor_seq));
    if (cursor >= Number(c.last_seq)) continue;
    const r = await asTenant(Number(c.tenant_id), EXPORT_ACTOR, () => db('audit_logs').where('tenant_id', Number(c.tenant_id))
      .andWhere('chain_seq', '>', cursor).orderBy('chain_seq').first('created_at')) as { created_at: Date } | undefined;
    if (r && (oldest === null || new Date(r.created_at).getTime() < oldest)) oldest = new Date(r.created_at).getTime();
  }
  return oldest === null ? null : Math.max(0, Math.round((Date.now() - oldest) / 1000));
}

/** Largest lag of the enabled destinations that receive a tenant's chain
 *  (seconds; null when none receives it). Read as the exporter (the
 *  destinations are no reading of a tenant: no reader role grant). */
export async function chainExportLag(tenantId: number): Promise<number | null> {
  return asNone(EXPORT_ACTOR, async () => {
    const dests = (await listDestinationRows()).filter((d) => d.enabled
      && (d.scope_tenant_id === null || Number(d.scope_tenant_id) === tenantId));
    if (!dests.length) return null;
    let lag = 0;
    for (const d of dests) {
      const l = await exportLagSeconds(d).catch(() => null);
      if (l !== null && l > lag) lag = l;
    }
    return lag;
  });
}
