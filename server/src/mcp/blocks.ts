import { MASTER_TENANT_ID, type McpBlockSource, type McpBlockView, type McpObliguardStatus } from '@obligarth/shared';
import { config } from '../config';
import { db } from '../db';
import { asIdentity } from '../db/context';
import { appConfigService } from '../services/appConfig.service';
import { obligateService } from '../services/obligate.service';
import { hasLiveSessionAt } from '../security/liveSessionAddresses';
import { isNonPublic, isPrefixRow } from '../security/neverBlock';
import { ObliguardClient, PushQueue, type ObliguardResult } from '../security/obliguard';
import { logger } from '../utils/logger';
import { appendQuiet, systemCtx } from './audit';
import { inetText, prefix64 } from './ipUtil';
import { MCP_ACTOR, mcpSettings } from './settings';
import type { AuditWriteContext } from '../audit';

// =============================================================================
// Local blocks of /mcp (docs: specs mcp-server §3.6, §3.7): an address, or an
// IPv6 /64 once enough addresses of it were blocked within an hour. Kept in
// memory (loaded at boot, refreshed by the minute step) so that the gate of a
// request never queries the database; written in mcp_ip_blocks (identity
// context). At most max_new_blocks_per_min new rows per minute: the surplus is
// answered 403 from memory and written by the next minute step. Each new block
// is reported to Obliguard through a queue (concurrency 1, 30 per minute),
// unless the reporting guard skips it; the status stays on the row.
// =============================================================================

interface MemBlock { id: number | null; until: number | null }

const blocked = new Map<string, MemBlock>();
/** Blocks over the per-minute cap, not written yet. */
const deferred = new Map<string, { source: McpBlockSource; reason: string; until: Date | null; firstSeen: Date; hits: number; ctx: AuditWriteContext }>();
/** Plain IPv6 addresses blocked per /64, with the time of each block (prefix_block_threshold within an hour). */
const prefixHits = new Map<string, number[]>();
let minuteKey = 0;
let createdThisMinute = 0;

export const obliguardQueue = new PushQueue(30);
export const obliguard = new ObliguardClient(async () => {
  const s = await mcpSettings();
  const raw = await asIdentity(MCP_ACTOR, () => appConfigService.getObligateRaw());
  return {
    manualUrl: s.obliguardUrl,
    obligate: raw.url && raw.apiKey ? { url: raw.url, apiKey: raw.apiKey } : null,
    connectedApps: async () => (await obligateService.getConnectedApps()).map((a) => a as { appType?: string; name?: string; baseUrl?: string }),
  };
});

const live = (b: MemBlock | undefined, now: number): boolean => !!b && (b.until === null || b.until > now);

// Bounds of the memory (an address spray, IPv6 above all, must not grow it without end): the blocks in memory, the
// blocks deferred by the per-minute cap (the surplus is dropped and counted: in strict mode the gate refuses an
// address outside the lists whatever the memory holds) and the per-/64 counters (their stale entries evicted).
const BLOCKED_MAX = 200_000;
const DEFERRED_MAX = 10_000;
const PREFIX_HITS_MAX = 10_000;
let droppedDeferred = 0;
let lastBlockedPrune = 0;

/**
 * A block into memory, within BLOCKED_MAX: blocks past their end go first (one scan a minute at most, never one per
 * request of a spray); a full memory keeps what it has.
 */
function rememberBlock(key: string, b: MemBlock, now: number): void {
  if (!blocked.has(key) && blocked.size >= BLOCKED_MAX) {
    if (now - lastBlockedPrune >= 60_000) {
      lastBlockedPrune = now;
      for (const [k, v] of blocked) if (!live(v, now)) blocked.delete(k);
    }
    if (blocked.size >= BLOCKED_MAX) return;
  }
  blocked.set(key, b);
}

/** The per-/64 counters: entries without a hit within the hour go, then the oldest until back under the bound. */
function prunePrefixHits(now: number): void {
  for (const [k, hits] of prefixHits) if (!hits.some((t) => now - t < 3_600_000)) prefixHits.delete(k);
  for (const k of prefixHits.keys()) { if (prefixHits.size <= PREFIX_HITS_MAX) break; prefixHits.delete(k); }
}

/** Is the address (or its /64) blocked now? Memory only. */
export function isBlocked(ip: string, now = Date.now()): boolean {
  if (live(blocked.get(ip), now)) return true;
  const p = prefix64(ip);
  return p !== null && live(blocked.get(p), now);
}

/** The active blocks of the table, into memory (boot, minute step). */
export async function loadBlocks(): Promise<number> {
  const rows = await asIdentity(MCP_ACTOR, () => db('mcp_ip_blocks').where({ active: true })
    .select('id', 'ip', 'blocked_until')) as Array<{ id: number; ip: string; blocked_until: Date | null }>;
  const next = new Map<string, MemBlock>();
  for (const r of rows) {
    const key = isPrefixRow(String(r.ip)) ? String(r.ip) : inetText(String(r.ip)) ?? String(r.ip);
    next.set(key, { id: Number(r.id), until: r.blocked_until ? new Date(r.blocked_until).getTime() : null });
  }
  // Deferred blocks stay in memory until written.
  for (const [ip, d] of deferred) next.set(ip, { id: null, until: d.until ? d.until.getTime() : null });
  blocked.clear();
  for (const [k, v] of next) blocked.set(k, v);
  return rows.length;
}

function proxyHostDomain(): string | null {
  try { return config.clientOrigin ? new URL(config.clientOrigin).host : null; } catch { return null; }
}

/** The address carries a trusted 2FA window of a user (the reporting guard: never a network-wide ban of a known office). */
async function knownToUsers(ip: string): Promise<boolean> {
  try {
    const row = await asIdentity(MCP_ACTOR, () => db('tfa_trusted_sessions').where({ ip_address: ip })
      .where('trusted_until', '>', new Date()).first('user_id'));
    return !!row;
  } catch {
    return true;   // unknown: never reported (fail safe)
  }
}

async function setObliguardStatus(id: number, status: McpObliguardStatus, error: string | null): Promise<void> {
  await asIdentity(MCP_ACTOR, () => db('mcp_ip_blocks').where({ id }).update({
    obliguard_status: status, obliguard_error: error ? error.slice(0, 500) : null,
    ...(status === 'sent' ? { obliguard_sent_at: new Date() } : {}),
  }));
}

function pushBan(row: { id: number; ip: string; source: McpBlockSource; reason: string; first_seen_at: Date; hit_count: number; blocked_until: Date | null }): boolean {
  return obliguardQueue.push(async () => {
    const r: ObliguardResult = await obliguard.sendBan({
      ip: row.ip, source: 'obligarth', reason: row.reason.slice(0, 300), proxy_host_domain: proxyHostDomain(),
      source_type: row.source === 'mcp_strict' ? 'mcp-strict' : row.source === 'manual' ? 'mcp-manual' : 'mcp-failures',
      first_seen_at: new Date(row.first_seen_at).toISOString(), hit_count: row.hit_count,
      banned_until: row.blocked_until ? new Date(row.blocked_until).toISOString() : null,
    });
    await setObliguardStatus(row.id, r.ok ? 'sent' : 'failed', r.ok ? null : r.error).catch(() => undefined);
    if (!r.ok) logger.warn({ ip: row.ip, error: r.error }, 'mcp: block not reported to Obliguard');
  });
}

/** The reporting guard: a /64 row, a non-public address, an address with a live web session or a trusted 2FA address. */
async function neverReported(ip: string): Promise<boolean> {
  return isPrefixRow(ip) || isNonPublic(ip) || hasLiveSessionAt(ip) || (await knownToUsers(ip));
}

/** The Obliguard status of a new row: disabled, skipped by the reporting guard, or pending (queued). */
async function obliguardStatusFor(ip: string): Promise<McpObliguardStatus> {
  const s = await mcpSettings();
  if (!s.obliguardEnabled) return 'disabled';
  return (await neverReported(ip)) ? 'skipped' : 'pending';
}

export interface NewBlock {
  ip: string;
  source: McpBlockSource;
  reason: string;
  /** null: permanent. */
  until: Date | null;
  firstSeen?: Date;
  hits?: number;
  ctx?: AuditWriteContext;
}

/**
 * Blocks an address (or a /64) locally, at once in memory; the row is written now, or by the next minute step when
 * the per-minute cap is reached. Audited (mcp.ip.blocked), reported to Obliguard unless skipped. Never throws.
 */
export async function blockAddress(b: NewBlock): Promise<void> {
  const now = Date.now();
  rememberBlock(b.ip, { id: null, until: b.until ? b.until.getTime() : null }, now);
  try {
    const s = await mcpSettings();
    const m = Math.floor(now / 60_000);
    if (m !== minuteKey) { minuteKey = m; createdThisMinute = 0; }
    if (createdThisMinute >= s.maxNewBlocksPerMinute) {
      if (!deferred.has(b.ip) && deferred.size >= DEFERRED_MAX) { droppedDeferred++; return; }
      deferred.set(b.ip, { source: b.source, reason: b.reason, until: b.until, firstSeen: b.firstSeen ?? new Date(now), hits: b.hits ?? 1, ctx: b.ctx ?? systemCtx() });
      return;
    }
    createdThisMinute++;
    await writeBlock(b);
    // An IPv6 flood: once prefix_block_threshold addresses of one /64 are blocked within an hour, the /64 itself.
    const p = b.source === 'mcp_prefix' ? null : prefix64(b.ip);
    if (p && !live(blocked.get(p), now)) {
      const hits = (prefixHits.get(p) ?? []).filter((t) => now - t < 3_600_000);
      hits.push(now);
      prefixHits.delete(p);
      prefixHits.set(p, hits);
      if (prefixHits.size > PREFIX_HITS_MAX) prunePrefixHits(now);
      if (hits.length >= s.prefixBlockThreshold) {
        prefixHits.delete(p);
        await blockAddress({
          ip: p, source: 'mcp_prefix', reason: `${hits.length} addresses of this /64 blocked within an hour`,
          until: b.until === null ? null : new Date(now + s.blockSeconds * 1000), ctx: b.ctx,
        });
      }
    }
  } catch (err) {
    logger.error({ err, ip: b.ip }, 'mcp: block not written (kept in memory)');
  }
}

async function writeBlock(b: NewBlock): Promise<void> {
  const status = await obliguardStatusFor(b.ip);
  const row = await asIdentity(MCP_ACTOR, async () => {
    const [r] = await db('mcp_ip_blocks').insert({
      ip: b.ip, source: b.source, reason: b.reason.slice(0, 300), first_seen_at: b.firstSeen ?? new Date(), last_seen_at: new Date(),
      hit_count: Math.max(1, b.hits ?? 1), blocked_until: b.until, active: true, obliguard_status: status,
    }).onConflict(db.raw('(ip) WHERE active')).merge({ last_seen_at: new Date(), blocked_until: b.until })
      .returning(['id', 'ip', 'source', 'reason', 'first_seen_at', 'hit_count', 'blocked_until', 'obliguard_status']) as Array<Record<string, any>>;
    return r;
  });
  if (!row) return;
  const key = isPrefixRow(String(row.ip)) ? String(row.ip) : inetText(String(row.ip)) ?? b.ip;
  rememberBlock(key, { id: Number(row.id), until: row.blocked_until ? new Date(row.blocked_until).getTime() : null }, Date.now());
  await appendQuiet({
    tenantId: MASTER_TENANT_ID, action: 'mcp.ip.blocked', target: { type: 'mcp_ip_block', id: String(row.id) },
    details: { ip: key, source: b.source, reason: b.reason.slice(0, 300), permanent: b.until === null, until: b.until ? b.until.toISOString() : null, obliguard: status },
  }, b.ctx ?? systemCtx({ ip: key }));
  if (status === 'pending') {
    pushBan({ id: Number(row.id), ip: key, source: b.source, reason: String(row.reason), first_seen_at: row.first_seen_at, hit_count: Number(row.hit_count), blocked_until: row.blocked_until });
  }
}

/** Writes the blocks deferred by the per-minute cap (minute step). */
export async function flushDeferred(): Promise<number> {
  const s = await mcpSettings();
  if (droppedDeferred > 0) {
    logger.warn({ dropped: droppedDeferred, deferred: deferred.size }, 'mcp: blocks over the deferred backlog dropped (address spray)');
    droppedDeferred = 0;
  }
  let n = 0;
  for (const [ip, d] of [...deferred]) {
    if (n >= s.maxNewBlocksPerMinute) break;
    deferred.delete(ip);
    try {
      await writeBlock({ ip, source: d.source, reason: d.reason, until: d.until, firstSeen: d.firstSeen, hits: d.hits, ctx: d.ctx });
      n++;
    } catch (err) {
      logger.warn({ err, ip }, 'mcp: deferred block not written');
    }
  }
  return n;
}

/** Blocks past their end become inactive (minute step); memory reloaded. */
export async function expireBlocks(): Promise<number> {
  const n = await asIdentity(MCP_ACTOR, () => db('mcp_ip_blocks').where({ active: true }).whereNotNull('blocked_until')
    .where('blocked_until', '<=', new Date()).update({ active: false, unblocked_at: new Date() }));
  await loadBlocks();
  return Number(n);
}

/** Resends at most 100 rows pending or failed through the queue (every 5 minutes). */
export async function retryObliguard(): Promise<number> {
  const s = await mcpSettings();
  if (!s.obliguardEnabled) return 0;
  const rows = await asIdentity(MCP_ACTOR, () => db('mcp_ip_blocks').where({ active: true }).whereIn('obliguard_status', ['pending', 'failed'])
    .orderBy('id').limit(100).select('id', 'ip', 'source', 'reason', 'first_seen_at', 'hit_count', 'blocked_until')) as Array<Record<string, any>>;
  let n = 0;
  for (const r of rows) {
    const ip = inetText(String(r.ip)) ?? String(r.ip);
    // The whole guard again: the address may have become known (a session, a trusted 2FA) since the block.
    if (isPrefixRow(String(r.ip)) || (await neverReported(ip))) { await setObliguardStatus(Number(r.id), 'skipped', null); continue; }
    if (pushBan({ id: Number(r.id), ip, source: r.source, reason: String(r.reason), first_seen_at: r.first_seen_at, hit_count: Number(r.hit_count), blocked_until: r.blocked_until })) n++;
  }
  return n;
}

/** Lifts a block (an administrator, after a step-up): inactive, out of memory, withdrawn from Obliguard if it was sent. */
export async function unblock(id: number, byUserId: number, ctx: AuditWriteContext): Promise<boolean> {
  const row = await asIdentity(MCP_ACTOR, async () => {
    const [r] = await db('mcp_ip_blocks').where({ id, active: true }).update({ active: false, unblocked_at: new Date(), unblocked_by: byUserId })
      .returning(['id', 'ip', 'obliguard_status']) as Array<Record<string, any>>;
    return r;
  });
  if (!row) return false;
  const key = isPrefixRow(String(row.ip)) ? String(row.ip) : inetText(String(row.ip)) ?? String(row.ip);
  blocked.delete(key);
  deferred.delete(key);
  let withdrawn: boolean | null = null;
  if (row.obliguard_status === 'sent') {
    const r = await obliguard.deleteBan(key);
    withdrawn = r.ok;
    await setObliguardStatus(Number(row.id), r.ok ? 'withdrawn' : 'failed', r.ok ? null : `withdrawal: ${r.error}`).catch(() => undefined);
  }
  await asIdentity(MCP_ACTOR, async () => {
    const { audit } = await import('../audit');
    await audit.append({
      tenantId: MASTER_TENANT_ID, action: 'mcp.ip.unblocked', target: { type: 'mcp_ip_block', id: String(id) },
      details: { ip: key, obliguardWithdrawn: withdrawn },
    }, ctx);
  });
  return true;
}

export function blockView(r: Record<string, any>): McpBlockView {
  const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);
  const ip = String(r.ip);
  return {
    id: Number(r.id), ip: isPrefixRow(ip) ? ip : inetText(ip) ?? ip, source: r.source, reason: r.reason,
    firstSeenAt: iso(r.first_seen_at) as string, lastSeenAt: iso(r.last_seen_at) as string, hitCount: Number(r.hit_count),
    blockedUntil: iso(r.blocked_until), active: r.active === true, unblockedAt: iso(r.unblocked_at),
    obliguardStatus: r.obliguard_status, obliguardError: r.obliguard_error ?? null,
  };
}

/** For the tests and the admin view: the size of the in-memory state. */
export function blockState(): { blocked: number; deferred: number } {
  return { blocked: blocked.size, deferred: deferred.size };
}
