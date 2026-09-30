import type { Knex } from 'knex';
import { db } from '../db';
import { logger } from '../utils/logger';
import { getIO } from '../socket';
import { SocketEvents, isMasterTenant } from '@obliance/shared';
import type { Command, CommandPriority } from '@obliance/shared';
import { commandService } from './command.service';

// ── Agent update rollout ────────────────────────────────────────────────────
//
// `update_agent` (admin-triggered: agents no longer self-update) is special:
//
//  1. It WAITS for its device. No expires_at while pending: a device that is
//     offline when the admin clicks gets the update on its first contact
//     (HTTP push, WS heartbeat, WS reconnect drain, command poll — every pull
//     path goes through claimPendingCommands below). A claimed update that
//     could not be written to the socket goes back to pending
//     (requeueUndelivered), and a delivered one never confirmed is handed out
//     again (UPDATE_AGENT_MAX_REDELIVERIES) — a lost HTTP response or a
//     socket closing mid-send never loses it.
//  2. ONE outstanding (pending or sent) update per device, enforced by the
//     partial unique index of migration 131 + INSERT … ON CONFLICT DO NOTHING
//     on every enqueue path (device page, bulk, approvals, "update all").
//  3. Decided at DELIVERY time, not at enqueue time: a device that already
//     runs the version this server ships gets nothing (the command is closed
//     'cancelled' with result.reason 'already_up_to_date'); otherwise
//     payload.version is refreshed to the server's current build (the agent
//     installs whatever the server serves anyway: the version is a label).
//  4. Paced: at most UPDATE_AGENT_ROLLOUT_MAX_PER_WINDOW updates handed out
//     per UPDATE_AGENT_ROLLOUT_WINDOW_MS, fleet-wide (2000+ agents each
//     downloading a 10-20 MB MSI in the same minute would saturate the
//     server's uplink). The others stay pending and are delivered on later
//     contacts. Other command types are not affected: they are fetched and
//     delivered exactly as before.
//
// Throttle design (why this one):
//  - The CAP is exact: the updates handed out in the window are counted in
//    command_queue itself (sent_at, partial index of migration 131) and the
//    claim is confirmed under a transaction-scoped advisory lock — exact
//    across concurrent pushes and server processes, survives restarts, no
//    timer, no new column, no extra state.
//  - The ORDER is "the head of the queue": the first CAP waiting updates of
//    REACHABLE devices (pushed within UPDATE_AGENT_REACHABLE_MS), by
//    priority (a single-device click is 'high', the dashboard rollout
//    'normal'), then age (created_at, id). Any of them may take a free slot.
//    A band of CAP devices rather than strictly the next one: each device
//    only calls in once per push interval, so a strict "next in line" rule
//    leaves freed slots idle until that one device pushes (half the cap in
//    practice); with a band, one of CAP devices calls in within seconds and
//    the rollout runs at the cap. Offline devices hold no place (nobody
//    starves behind them); within the band, order is by arrival (no
//    starvation: each freed slot goes to the next band device to call in,
//    so every band device is reached within about one push interval). A
//    device calling in after a long absence is placed by its rank at once
//    (first contact), not held back until the cached head sees it.
//  - COST is bounded: the head is read once per HEAD_CACHE_MS per process
//    (LIMIT CAP, walking the tiny partial unique index of pending updates)
//    and re-read after each claim; a waiting device outside the head costs
//    two indexed lookups + a set lookup per contact; `windowFullUntil`
//    skips the window count while the window is known to be full.
//  - A delivered update that is never acknowledged (the agent restarts into
//    the new version, its HTTP ack is often lost) is closed by the command
//    sweeper (sweep below): 'success' as soon as the device reports the
//    target version; otherwise handed out again after
//    UPDATE_AGENT_DELIVERY_TIMEOUT_MS (at most UPDATE_AGENT_MAX_REDELIVERIES
//    times), then 'timeout' — the device's slot always frees.

/** Updates handed out per window, fleet-wide (all tenants). */
export const UPDATE_AGENT_ROLLOUT_MAX_PER_WINDOW = 25;
/** Rolling window of the throttle. */
export const UPDATE_AGENT_ROLLOUT_WINDOW_MS = 60_000;
/** A delivered update not acknowledged within this delay is handed out again
 *  (or closed 'timeout'), unless the device already reports the target
 *  version → 'success'. */
export const UPDATE_AGENT_DELIVERY_TIMEOUT_MS = 30 * 60_000;
/** A waiting update of a device that pushed within this delay is in line. */
export const UPDATE_AGENT_REACHABLE_MS = 3 * 60_000;
/** A delivered update never confirmed is handed out again at most this many
 *  times (lost HTTP response, socket closed mid-send, silent MSI failure). */
export const UPDATE_AGENT_MAX_REDELIVERIES = 2;
/** The head of the queue is re-read at most this often (per process). */
const HEAD_CACHE_MS = 5_000;
/** Command events pushed to the admin UI one by one up to this count per
 *  operation (a fleet-wide rollout would flood every open admin socket). */
const BULK_EMIT_MAX = 100;
const BULK_CHUNK = 500;
/** pg_advisory_xact_lock key of the throttle (arbitrary, unique to it). */
const ROLLOUT_LOCK_KEY = 1310131001;
const DELIVERY_TIMEOUT_MINUTES = UPDATE_AGENT_DELIVERY_TIMEOUT_MS / 60_000;

/** Statuses where the agent is pushing (memory: devices.status encodes the
 *  metric severity — never test status = 'online' alone). */
export const AGENT_REACHABLE_STATUSES = ['online', 'warning', 'critical', 'updating'];
/** Device states that never receive an agent update. */
const NOT_ELIGIBLE_STATUSES = ['suspended', 'pending_uninstall'];

const OUTSTANDING = ['pending', 'sent'];

/** Queue order key: priority first (enum order low < normal < high <
 *  urgent), then age, then id — the ORDER BY of the head query. */
type QueueKey = { prio: number; at: number; id: string };
const PRIORITY_RANK: Record<string, number> = { low: 0, normal: 1, high: 2, urgent: 3 };
function queueKey(row: { priority?: string; created_at: unknown; id: string }): QueueKey {
  return { prio: PRIORITY_RANK[String(row.priority ?? 'normal')] ?? 1, at: new Date(row.created_at as any).getTime(), id: String(row.id) };
}
/** < 0 when `a` comes before `b` in the queue. */
function compareKeys(a: QueueKey, b: QueueKey): number {
  if (a.prio !== b.prio) return b.prio - a.prio;
  if (a.at !== b.at) return a.at - b.at;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}
/** The head of the queue: the first CAP waiting updates of reachable
 *  devices. `full` = CAP of them; `last` = the key of the last one. */
type Head = { ids: Set<string>; full: boolean; last: QueueKey | null };

let windowFullUntil = 0;
let head: (Head & { at: number }) | null = null;
let headLoading: Promise<Head> | null = null;
let headGen = 0;
/** The head of the queue changed (enqueue, claim, requeue, cancel): the next
 *  delivery check re-reads it (a load in flight does not store its result). */
function dropHead(): void { head = null; headLoading = null; headGen++; }

async function currentAgentVersion(): Promise<string> {
  // Lazy: device.service imports this module.
  const { getAgentVersion } = await import('./device.service');
  return getAgentVersion();
}

function parsePayload(v: unknown): Record<string, any> {
  if (v == null) return {};
  if (typeof v === 'string') { try { return JSON.parse(v) ?? {}; } catch { return {}; } }
  return v as Record<string, any>;
}

function emitCommand(row: any, adminOnly = false): void {
  try {
    const room = adminOnly ? `tenant:${row.tenant_id}:admin` : `tenant:${row.tenant_id}`;
    getIO().to(room).emit(SocketEvents.COMMAND_UPDATED, commandService.rowToCommand(row));
  } catch { /* socket not ready */ }
}

function emitCapped(rows: any[], adminOnly = false): void {
  if (rows.length <= BULK_EMIT_MAX) for (const row of rows) emitCommand(row, adminOnly);
}

function rowsOf(r: any): any[] {
  return Array.isArray(r) ? r : (r?.rows ?? []);
}

/** Per-tenant counts of `rows` (tenant_id), ascending tenant id. */
function countByTenant(rows: Array<{ tenant_id: number }>): Map<number, number> {
  const m = new Map<number, number>();
  for (const r of rows) m.set(Number(r.tenant_id), (m.get(Number(r.tenant_id)) ?? 0) + 1);
  return m;
}

/** Devices targeted by "update all agents": approved, not suspended / being
 *  uninstalled, modern agent, reporting a version different from the one
 *  this server ships (same test as the dashboard "outdated" figure and
 *  Device.updateAvailable). Master tenant: every tenant; any other tenant:
 *  its own devices only. */
function outdatedQuery(scopeTenantId: number, current: string) {
  const q = db('devices')
    .where('devices.approval_status', 'approved')
    .whereNotIn('devices.status', NOT_ELIGIBLE_STATUSES)
    .whereNotNull('devices.agent_version')
    .whereNot('devices.agent_version', current)
    .where((w) => w.whereNull('devices.agent_flavor').orWhereNot('devices.agent_flavor', 'legacy'));
  if (!isMasterTenant(scopeTenantId)) q.where('devices.tenant_id', scopeTenantId);
  return q;
}

export interface UpdateAllPreview {
  /** Agents the action would update (queued now or already queued). */
  targets: number;
  /** …of which reachable right now (the others: when they come back). */
  online: number;
  offline: number;
  /** …of which already have an update waiting / in flight. */
  alreadyQueued: number;
  latestVersion: string;
  /** Master tenant: every tenant's agents. */
  allTenants: boolean;
  /** The tenant the figures were computed for (the request's): the client
   *  sends it back with the action, which is refused if the session's
   *  tenant changed in between (another tab). */
  scopeTenantId: number;
  /** Agent updates still waiting in the scope (any origin): what "stop the
   *  rollout" would cancel. */
  pendingInScope: number;
  /** Pace of the rollout (fleet-wide cap). */
  ratePerMinute: number;
}

export interface UpdateAllResult extends UpdateAllPreview {
  /** New update_agent commands created by this call. */
  queued: number;
  /** Per tenant of the targets (audit of a master-scope action). */
  byTenant: Array<{ tenantId: number; targets: number; queued: number; alreadyQueued: number }>;
}

export const agentUpdateRollout = {
  /** One device (POST /api/commands, approvals). No expiry; returns the
   *  already outstanding update instead of a second one. */
  async enqueue(data: {
    deviceId: number;
    tenantId: number;
    createdBy?: number;
    priority?: CommandPriority;
    sourceType?: string;
    sourceId?: string;
  }): Promise<{ command: Command; created: boolean }> {
    const current = await currentAgentVersion();
    for (let attempt = 0; attempt < 3; attempt++) {
      const [row] = await db('command_queue').insert({
        device_id: data.deviceId,
        tenant_id: data.tenantId,
        type: 'update_agent',
        payload: JSON.stringify(current ? { version: current } : {}),
        status: 'pending',
        priority: data.priority || 'normal',
        max_retries: 0,
        expires_at: null,
        source_type: data.sourceType,
        source_id: data.sourceId,
        created_by: data.createdBy,
      }).onConflict().ignore().returning('*');
      if (row) {
        dropHead(); // a 'high' single-device update goes straight to the head
        emitCommand(row, true);
        return { command: commandService.rowToCommand(row), created: true };
      }
      const existing = await db('command_queue')
        .where({ device_id: data.deviceId, type: 'update_agent' })
        .whereIn('status', OUTSTANDING)
        .first();
      if (existing) return { command: commandService.rowToCommand(existing), created: false };
      // The outstanding one ended between the insert and the read: retry.
    }
    throw new Error('Could not queue the agent update (concurrent changes), try again');
  },

  /** Many devices at once (batch, approvals, "update all"): chunked
   *  INSERT … ON CONFLICT DO NOTHING — one statement per 500 devices, each
   *  row carrying the DEVICE's tenant. */
  async enqueueBulk(devices: Array<{ id: number; tenant_id: number }>, opts: {
    createdBy?: number;
    priority?: CommandPriority;
    sourceType?: string;
  } = {}): Promise<{ created: any[]; alreadyQueuedDeviceIds: number[] }> {
    const seen = new Set<number>();
    const list = devices.filter((d) => {
      const id = Number(d.id);
      if (!Number.isInteger(id) || id <= 0 || seen.has(id)) return false;
      seen.add(id);
      return true;
    });
    if (!list.length) return { created: [], alreadyQueuedDeviceIds: [] };
    const current = await currentAgentVersion();
    const payload = JSON.stringify(current ? { version: current } : {});
    const created: any[] = [];
    for (let i = 0; i < list.length; i += BULK_CHUNK) {
      const chunk = list.slice(i, i + BULK_CHUNK);
      const rows = await db('command_queue').insert(chunk.map((d) => ({
        device_id: d.id,
        tenant_id: d.tenant_id,
        type: 'update_agent',
        payload,
        status: 'pending',
        priority: opts.priority || 'normal',
        max_retries: 0,
        expires_at: null,
        source_type: opts.sourceType,
        created_by: opts.createdBy,
      }))).onConflict().ignore().returning('*');
      created.push(...rows);
    }
    if (created.length) dropHead();
    // Admin feeds: one event per command for a normal selection; pages
    // reload their lists after a fleet-wide rollout.
    emitCapped(created, true);
    const createdIds = new Set(created.map((r) => Number(r.device_id)));
    return { created, alreadyQueuedDeviceIds: list.map((d) => d.id).filter((id) => !createdIds.has(id)) };
  },

  async preview(scopeTenantId: number): Promise<UpdateAllPreview> {
    const current = await currentAgentVersion();
    const allTenants = isMasterTenant(scopeTenantId);
    const pendingQ = db('command_queue').where({ type: 'update_agent', status: 'pending' });
    if (!allTenants) pendingQ.where('tenant_id', scopeTenantId);
    const pendingRow = await pendingQ.first(db.raw('count(*)::int AS n')) as { n: number } | undefined;
    const base = {
      latestVersion: current,
      allTenants,
      scopeTenantId,
      pendingInScope: Number(pendingRow?.n ?? 0),
      ratePerMinute: Math.round((UPDATE_AGENT_ROLLOUT_MAX_PER_WINDOW * 60_000) / UPDATE_AGENT_ROLLOUT_WINDOW_MS),
    };
    if (!current) return { targets: 0, online: 0, offline: 0, alreadyQueued: 0, ...base };
    const row = await outdatedQuery(scopeTenantId, current).first(
      db.raw('count(*)::int AS targets'),
      db.raw(`count(*) FILTER (WHERE devices.status IN (${AGENT_REACHABLE_STATUSES.map(() => '?').join(', ')}))::int AS online`, AGENT_REACHABLE_STATUSES),
      db.raw(`count(*) FILTER (WHERE EXISTS (
        SELECT 1 FROM command_queue c
         WHERE c.device_id = devices.id AND c.type = 'update_agent' AND c.status IN ('pending', 'sent')
      ))::int AS already_queued`),
    ) as { targets: number; online: number; already_queued: number } | undefined;
    const targets = Number(row?.targets ?? 0);
    const online = Number(row?.online ?? 0);
    return { targets, online, offline: targets - online, alreadyQueued: Number(row?.already_queued ?? 0), ...base };
  },

  /** Tenants owning at least one target of "update all agents" in this scope
   *  (the restriction level of a master-scope action is the strictest of
   *  theirs). */
  async outdatedTenantIds(scopeTenantId: number): Promise<number[]> {
    const current = await currentAgentVersion();
    if (!current) return [];
    const rows = await outdatedQuery(scopeTenantId, current).distinct('devices.tenant_id') as Array<{ tenant_id: number }>;
    return rows.map((r) => Number(r.tenant_id)).sort((a, b) => a - b);
  },

  /** "Update all agents": re-resolves the outdated set NOW (at approval
   *  execution too), scope = the given tenant (master: every tenant). */
  async updateAllOutdated(scopeTenantId: number, createdBy?: number): Promise<UpdateAllResult> {
    const current = await currentAgentVersion();
    if (!current) {
      throw Object.assign(new Error('Cannot determine the latest agent version (agent/VERSION missing).'), { status: 409 });
    }
    const targets = await outdatedQuery(scopeTenantId, current)
      .select('devices.id', 'devices.tenant_id', 'devices.status') as Array<{ id: number; tenant_id: number; status: string }>;
    const { created, alreadyQueuedDeviceIds } = await this.enqueueBulk(targets, {
      createdBy, priority: 'normal', sourceType: 'update_all_agents',
    });
    const online = targets.filter((d) => AGENT_REACHABLE_STATUSES.includes(d.status)).length;
    const targetsBy = countByTenant(targets);
    const queuedBy = countByTenant(created);
    const alreadySet = new Set(alreadyQueuedDeviceIds);
    const alreadyBy = countByTenant(targets.filter((d) => alreadySet.has(d.id)));
    const preview = await this.preview(scopeTenantId);
    return {
      ...preview,
      targets: targets.length,
      online,
      offline: targets.length - online,
      alreadyQueued: alreadyQueuedDeviceIds.length,
      queued: created.length,
      latestVersion: current,
      byTenant: [...targetsBy.keys()].sort((a, b) => a - b).map((tenantId) => ({
        tenantId,
        targets: targetsBy.get(tenantId) ?? 0,
        queued: queuedBy.get(tenantId) ?? 0,
        alreadyQueued: alreadyBy.get(tenantId) ?? 0,
      })),
    };
  },

  /** "Stop the rollout": cancels every agent update still WAITING in the
   *  scope (master: every tenant), whatever queued it (dashboard, device
   *  pages, bulk, approvals). Updates already handed to an agent cannot be
   *  recalled. */
  async cancelPending(scopeTenantId: number, userId?: number): Promise<{ cancelled: number; byTenant: Array<{ tenantId: number; cancelled: number }> }> {
    const now = new Date();
    const q = db('command_queue').where({ type: 'update_agent', status: 'pending' });
    if (!isMasterTenant(scopeTenantId)) q.where('tenant_id', scopeTenantId);
    const rows = await q.update({
      status: 'cancelled',
      finished_at: now,
      updated_at: now,
      result: JSON.stringify({ skipped: true, reason: 'rollout_stopped', message: 'Agent update cancelled: the rollout was stopped by an administrator', cancelledBy: userId ?? null }),
    }).returning('*') as any[];
    if (rows.length) dropHead();
    emitCapped(rows);
    const by = countByTenant(rows);
    return {
      cancelled: rows.length,
      byTenant: [...by.keys()].sort((a, b) => a - b).map((tenantId) => ({ tenantId, cancelled: by.get(tenantId) ?? 0 })),
    };
  },

  /**
   * The device's waiting update, if it may be handed out now: closed instead
   * when the device already runs the current version (or is a legacy agent),
   * kept pending when the rollout window is full or the update is not at the
   * head of the queue. Returns the row, marked 'sent' with the refreshed
   * payload and its delivery deadline, or null.
   */
  async claimForDelivery(deviceId: number): Promise<any | null> {
    // At most one pending update per device (unique index): an index lookup.
    const row = await db('command_queue')
      .where({ device_id: deviceId, type: 'update_agent', status: 'pending' })
      .first();
    if (!row) return null;
    const current = await currentAgentVersion();
    if (!current) return null; // unknown build: keep waiting
    const dev = await db('devices').where({ id: deviceId })
      .first('agent_version', 'agent_flavor', 'status', 'approval_status') as
      { agent_version: string | null; agent_flavor: string | null; status: string; approval_status: string } | undefined;
    if (!dev) return null;
    if (dev.agent_flavor === 'legacy') {
      await this._close(row, { reason: 'legacy_agent', message: 'The legacy agent cannot update itself — nothing sent' });
      return null;
    }
    if (dev.agent_version && dev.agent_version === current) {
      await this._close(row, { reason: 'already_up_to_date', message: `Agent already up to date (${current}) — nothing sent`, agentVersion: current });
      return null;
    }
    if (dev.approval_status !== 'approved' || NOT_ELIGIBLE_STATUSES.includes(dev.status)) return null;
    if (Date.now() < windowFullUntil) return null;
    // Only the head of the queue may claim (read from the per-process cache:
    // most waiting devices stop here without any further query). A device
    // back after a long absence is not in the cached head (its last push was
    // old when it was read) but is reachable now: it may claim when it would
    // rank in the head — first contact, no extra push interval.
    const h = await this._head(current);
    const inHead = h.ids.has(String(row.id)) || !h.full || (h.last != null && compareKeys(queueKey(row), h.last) < 0);
    if (!inHead) return null;

    // Room checked once without the lock, then again under the lock to claim.
    if (!(await this._hasRoom(db))) return null;
    const claimed = await db.transaction(async (trx) => {
      await trx.raw('SELECT pg_advisory_xact_lock(?)', [ROLLOUT_LOCK_KEY]);
      if (!(await this._hasRoom(trx))) return null;
      const now = Date.now();
      const deadline = now + UPDATE_AGENT_DELIVERY_TIMEOUT_MS;
      const payload = { ...parsePayload(row.payload), version: current };
      const [done] = await trx('command_queue')
        .where({ id: row.id, status: 'pending' })
        .update({
          status: 'sent',
          sent_at: new Date(now),
          expires_at: new Date(deadline),
          payload: JSON.stringify(payload),
          updated_at: new Date(now),
        })
        .returning('*');
      return done ?? null;
    });
    if (claimed) {
      dropHead(); // the next ones move up
      emitCommand(claimed);
    }
    return claimed;
  },

  /** Pending commands to hand to a device now (every pull path: HTTP push,
   *  WS heartbeat, WS reconnect drain, command poll). Other types exactly as
   *  before (max `limit`, priority then age, marked 'sent'); the device's
   *  agent update, if any, goes through the rollout gate and comes last. */
  async claimPendingCommands(deviceId: number, opts: { limit?: number; updateAgentPending?: boolean } = {}): Promise<any[]> {
    const rows = await db('command_queue')
      .where({ device_id: deviceId, status: 'pending' })
      .whereNot({ type: 'update_agent' })
      .orderBy([{ column: 'priority', order: 'desc' }, { column: 'created_at', order: 'asc' }])
      .limit(opts.limit ?? 5);
    if (rows.length > 0) {
      const now = new Date();
      await db('command_queue')
        .whereIn('id', rows.map((c: any) => c.id))
        .update({ status: 'sent', sent_at: now, updated_at: now });
    }
    if (opts.updateAgentPending !== false) {
      try {
        const upd = await this.claimForDelivery(deviceId);
        if (upd) rows.push(upd);
      } catch (err) {
        logger.error({ err, deviceId }, 'agent update rollout: delivery check failed');
      }
    }
    return rows;
  },

  /** Claimed agent updates that never left the server (socket closed or
   *  send failed): back to pending, so the device gets them on its next
   *  contact instead of after a 30-min timeout. Other command types are left
   *  as they are. */
  async requeueUndelivered(rows: Array<{ id: string; type?: string }>): Promise<number> {
    const ids = rows.filter((r) => r && r.type === 'update_agent').map((r) => r.id);
    if (!ids.length) return 0;
    const back = await db('command_queue')
      .whereIn('id', ids)
      .where('status', 'sent')
      .update({
        status: 'pending',
        sent_at: null,
        // Waits for the device again.
        expires_at: null,
        updated_at: new Date(),
      })
      .returning('*') as any[];
    if (back.length) dropHead();
    for (const b of back) emitCommand(b);
    return back.length;
  },

  /** Right after an admin queued it (POST /api/commands): hand the update
   *  over the live command channel when the device holds one and the
   *  rollout allows it now. Back to 'pending' if the socket send fails. */
  async deliverNow(deviceId: number): Promise<boolean> {
    const { agentHub } = await import('./agentHub.service');
    if (!agentHub.isConnected(deviceId)) return false;
    const claimed = await this.claimForDelivery(deviceId);
    if (!claimed) return false;
    const pushed = agentHub.push(deviceId, {
      type: 'command',
      id: claimed.id,
      commandType: 'update_agent',
      payload: parsePayload(claimed.payload),
    });
    if (pushed) return true;
    await this.requeueUndelivered([claimed]);
    return false;
  },

  /**
   * Command sweeper (every minute; the generic expiry pass leaves
   * update_agent to this one). One statement per step, dates kept honest
   * (a row closed late — server down, historical row — is dated at its
   * deadline, not at the sweep, so the change timeline does not get a burst
   * of events at deploy time):
   *  1. delivered + the device reports the target version → 'success';
   *  2. delivered, never acknowledged, deadline passed → handed out again
   *     (≤ UPDATE_AGENT_MAX_REDELIVERIES);
   *  3. otherwise delivered and deadline passed → 'timeout'.
   */
  async sweep(): Promise<{ confirmed: number; redelivered: number; timedOut: number }> {
    const deadline = `LEAST(now(), COALESCE(c.sent_at, c.created_at) + interval '${DELIVERY_TIMEOUT_MINUTES} minutes')`;
    const confirmed = rowsOf(await db.raw(`
      UPDATE command_queue c
         SET status = 'success',
             acked_at = COALESCE(c.acked_at, ${deadline}),
             finished_at = ${deadline},
             updated_at = now(),
             result = jsonb_build_object(
               'message', 'Agent now reports version ' || d.agent_version,
               'agentVersion', d.agent_version,
               'inferred', true)
        FROM devices d
       WHERE d.id = c.device_id
         AND c.type = 'update_agent' AND c.status = 'sent'
         AND d.agent_version IS NOT NULL AND d.agent_version = c.payload->>'version'
      RETURNING c.*`));
    const redelivered = rowsOf(await db.raw(`
      UPDATE command_queue c
         SET status = 'pending', sent_at = NULL, expires_at = NULL,
             retry_count = c.retry_count + 1, updated_at = now(),
             result = jsonb_build_object(
               'redelivery', c.retry_count + 1,
               'message', 'No confirmation from the agent — handed out again at its next contact')
       WHERE c.type = 'update_agent' AND c.status = 'sent'
         AND c.expires_at < now() AND c.acked_at IS NULL
         AND c.retry_count < ?
      RETURNING c.*`, [UPDATE_AGENT_MAX_REDELIVERIES]));
    const timedOut = rowsOf(await db.raw(`
      UPDATE command_queue c
         SET status = 'timeout',
             finished_at = LEAST(now(), c.expires_at),
             updated_at = now(),
             result = COALESCE(c.result, '{}'::jsonb) || jsonb_build_object('message',
               'No confirmation from the agent — the device still reports an older version')
       WHERE c.type = 'update_agent' AND c.status = 'sent'
         AND c.expires_at < now()
      RETURNING c.*`));
    if (redelivered.length) dropHead();
    emitCapped([...confirmed, ...redelivered, ...timedOut]);
    return { confirmed: confirmed.length, redelivered: redelivered.length, timedOut: timedOut.length };
  },

  /** The first CAP waiting updates of reachable, eligible devices — priority
   *  first, then age. Cached per process for HEAD_CACHE_MS (one query per
   *  period whatever the number of waiting devices; concurrent callers share
   *  it); dropped on enqueue, claim and requeue. */
  async _head(current: string): Promise<Head> {
    if (head && Date.now() - head.at < HEAD_CACHE_MS) return head;
    if (headLoading) return headLoading;
    const gen = headGen;
    const loading = (async () => {
      const now = Date.now();
      const rows = await db('command_queue as c')
        .join('devices as d', 'd.id', 'c.device_id')
        .where('c.type', 'update_agent')
        .where('c.status', 'pending')
        .where('d.last_push_at', '>=', new Date(now - UPDATE_AGENT_REACHABLE_MS))
        .where('d.approval_status', 'approved')
        .whereNotIn('d.status', NOT_ELIGIBLE_STATUSES)
        .where((w) => w.whereNull('d.agent_flavor').orWhereNot('d.agent_flavor', 'legacy'))
        .where((w) => w.whereNull('d.agent_version').orWhereNot('d.agent_version', current))
        .orderBy([{ column: 'c.priority', order: 'desc' }, { column: 'c.created_at', order: 'asc' }, { column: 'c.id', order: 'asc' }])
        .limit(UPDATE_AGENT_ROLLOUT_MAX_PER_WINDOW)
        .select('c.id', 'c.priority', 'c.created_at') as Array<{ id: string; priority: string; created_at: Date }>;
      const out: Head = {
        ids: new Set(rows.map((r) => String(r.id))),
        full: rows.length >= UPDATE_AGENT_ROLLOUT_MAX_PER_WINDOW,
        last: rows.length ? queueKey(rows[rows.length - 1]) : null,
      };
      if (gen === headGen) head = { ...out, at: now };
      return out;
    })();
    headLoading = loading;
    try { return await loading; } finally { if (headLoading === loading) headLoading = null; }
  },

  /** Room left in the rolling window (updates handed out in the last
   *  UPDATE_AGENT_ROLLOUT_WINDOW_MS, partial sent_at index). */
  async _hasRoom(q: Knex | Knex.Transaction): Promise<boolean> {
    const now = Date.now();
    const recent = await q('command_queue')
      .where({ type: 'update_agent' })
      .where('sent_at', '>=', new Date(now - UPDATE_AGENT_ROLLOUT_WINDOW_MS))
      .first(db.raw('count(*)::int AS n'), db.raw('min(sent_at) AS oldest')) as { n: number; oldest: Date | string | null } | undefined;
    if (Number(recent?.n ?? 0) < UPDATE_AGENT_ROLLOUT_MAX_PER_WINDOW) return true;
    if (recent?.oldest) windowFullUntil = new Date(recent.oldest).getTime() + UPDATE_AGENT_ROLLOUT_WINDOW_MS;
    return false;
  },

  async _close(row: any, result: Record<string, unknown>): Promise<void> {
    const now = new Date();
    const [done] = await db('command_queue')
      .where({ id: row.id, status: 'pending' })
      .update({ status: 'cancelled', finished_at: now, updated_at: now, result: JSON.stringify({ skipped: true, ...result }) })
      .returning('*');
    if (!done) return;
    emitCommand(done);
  },

  /** Tests only. */
  __resetForTests(): void { windowFullUntil = 0; dropHead(); },
};
