import type { Knex } from 'knex';
import { db } from '../db';
import { logger } from '../utils/logger';

/**
 * Offline command queue of an ObliReach agent (oblireach_devices.pending_command).
 *
 * The column (jsonb) used to hold ONE command, overwritten by the next one:
 * a second session started while the agent was offline silently replaced the
 * first. It now holds a JSON ARRAY of commands, each with an `expiresAt`
 * (epoch ms). Rows written by older servers (a single object) are read as a
 * one-element array. jsonb comes back from pg already parsed; a string (text
 * column, tests) is parsed here — never JSON.parse an object.
 *
 * Delivery skips expired entries and, for open_remote_tunnel, sessions that
 * are no longer waiting for their agent (a command drained 4 minutes later
 * would otherwise open a stream nobody watches).
 *
 * An entry WITHOUT expiresAt (a row written by an older server) is expired:
 * those rows were never cleared (the old drain threw on the parsed jsonb),
 * and months-old manual "update" commands would all have been delivered —
 * MSI reinstall + service restart — at the first reconnect after the deploy.
 * An `update` is also dropped when the agent already runs that version.
 */

/** A command delivered from server → ObliReach agent (same shape as OrCommand). */
export interface QueuedOrCommand {
  type: string;
  id: string;
  payload: Record<string, unknown>;
  /** Epoch ms after which the entry is dropped (absent on rows written by older servers). */
  expiresAt?: number;
}

/** open_remote_tunnel waits at most this long for an offline agent. */
export const OR_QUEUE_TUNNEL_TTL_MS = 5 * 60_000;
/** Manual / automatic update commands. */
export const OR_QUEUE_UPDATE_TTL_MS = 24 * 60 * 60_000;
/** Hard cap on queued entries per device (oldest dropped first). */
export const OR_QUEUE_MAX = 20;

const OPEN_SESSION_STATUSES = ['waiting', 'connecting'];

function isCommand(v: unknown): v is QueuedOrCommand {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const c = v as Record<string, unknown>;
  return typeof c.type === 'string' && c.type.length > 0 && typeof c.id === 'string';
}

/** Parse the column: array (current), single object (older rows), string (text / tests) or null. */
export function parseOrQueue(raw: unknown): QueuedOrCommand[] {
  if (raw == null || raw === '') return [];
  let value: unknown = raw;
  if (typeof raw === 'string') {
    try { value = JSON.parse(raw); } catch { return []; }
  }
  const list = Array.isArray(value) ? value : [value];
  return list.filter(isCommand).map((c) => ({
    type: c.type,
    id: c.id,
    payload: c.payload && typeof c.payload === 'object' ? c.payload : {},
    ...(typeof c.expiresAt === 'number' && Number.isFinite(c.expiresAt) ? { expiresAt: c.expiresAt } : {}),
  }));
}

/** Value to write to the jsonb column (a JSON string — never a JS array, pg would send an ARRAY literal). */
export function serializeOrQueue(queue: QueuedOrCommand[]): string | null {
  return queue.length > 0 ? JSON.stringify(queue) : null;
}

/** Expired — or written by an older server (no expiresAt: never delivered). */
export function isExpired(cmd: QueuedOrCommand, now: number): boolean {
  return typeof cmd.expiresAt !== 'number' || cmd.expiresAt <= now;
}

/** `current` strictly older than `target` (x.y.z; false when either is not a version). */
export function isOlderVersion(current: string, target: string): boolean {
  const parse = (v: string) => {
    const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(v.trim());
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
  };
  const c = parse(current);
  const t = parse(target);
  if (!c || !t) return false;
  for (let i = 0; i < 3; i++) if (c[i] !== t[i]) return c[i] < t[i];
  return false;
}

/** An `update` to a version the agent already runs (or a newer one). */
function isUselessUpdate(cmd: QueuedOrCommand, agentVersion: string | null | undefined): boolean {
  if (cmd.type !== 'update' || !agentVersion) return false;
  const target = typeof cmd.payload?.version === 'string' ? cmd.payload.version : '';
  if (!/^v?\d+\.\d+\.\d+/.test(target) || !/^v?\d+\.\d+\.\d+/.test(agentVersion.trim())) return false; // 'latest': deliver
  return !isOlderVersion(agentVersion, target);
}

/** Queue + cmd: expired entries and a previous entry with the same id dropped, capped. */
export function appendToOrQueue(
  queue: QueuedOrCommand[],
  cmd: { type: string; id: string; payload: Record<string, unknown> },
  now: number,
  ttlMs: number,
): QueuedOrCommand[] {
  const next = queue.filter((c) => !isExpired(c, now) && c.id !== cmd.id);
  next.push({ type: cmd.type, id: cmd.id, payload: cmd.payload, expiresAt: now + ttlMs });
  return next.length > OR_QUEUE_MAX ? next.slice(next.length - OR_QUEUE_MAX) : next;
}

function tunnelToken(cmd: QueuedOrCommand): string | null {
  if (cmd.type !== 'open_remote_tunnel') return null;
  const token = cmd.payload?.sessionToken;
  return typeof token === 'string' && token ? token : null;
}

/**
 * Entries still worth delivering: not expired, for open_remote_tunnel whose
 * session is still waiting for its agent (`openTokens`, see
 * openTunnelTokens), for update not to a version the agent already runs.
 */
export function deliverableOrCommands(
  queue: QueuedOrCommand[],
  now: number,
  openTokens: ReadonlySet<string>,
  agentVersion?: string | null,
): QueuedOrCommand[] {
  return queue.filter((c) => {
    if (isExpired(c, now)) return false;
    const token = tunnelToken(c);
    if (c.type === 'open_remote_tunnel') return !!token && openTokens.has(token);
    if (isUselessUpdate(c, agentVersion)) return false;
    return true;
  });
}

/** Tokens of the queue's open_remote_tunnel entries whose session is still waiting / connecting. */
async function openTunnelTokens(queue: QueuedOrCommand[], trx: Knex = db): Promise<Set<string>> {
  const tokens = queue.map(tunnelToken).filter((t): t is string => !!t);
  if (tokens.length === 0) return new Set();
  const rows = await trx('remote_sessions')
    .whereIn('session_token', tokens)
    .whereIn('status', OPEN_SESSION_STATUSES)
    .select('session_token') as Array<{ session_token: string }>;
  return new Set(rows.map((r) => r.session_token));
}

/**
 * Append a command to a device's queue. Returns the number of rows updated
 * (0 = no oblireach_devices row for this uuid + tenant: nothing will ever
 * deliver it — logged).
 */
export async function enqueueOrCommand(
  deviceUuid: string,
  tenantId: number,
  cmd: { type: string; id: string; payload: Record<string, unknown> },
  ttlMs: number = cmd.type === 'open_remote_tunnel' ? OR_QUEUE_TUNNEL_TTL_MS : OR_QUEUE_UPDATE_TTL_MS,
): Promise<number> {
  const updated = await db.transaction(async (trx) => {
    const row = await trx('oblireach_devices')
      .where({ device_uuid: deviceUuid, tenant_id: tenantId })
      .forUpdate()
      .first('id', 'pending_command');
    if (!row) return 0;
    const next = appendToOrQueue(parseOrQueue(row.pending_command), cmd, Date.now(), ttlMs);
    return trx('oblireach_devices').where({ id: row.id }).update({ pending_command: serializeOrQueue(next) });
  });
  const n = typeof updated === 'number' ? updated : Number(updated) || 0;
  if (n === 0) {
    logger.warn({ deviceUuid, tenantId, cmdType: cmd.type },
      'ObliReach: command not queued — no oblireach_devices row for this device (agent not installed, or registered under another uuid / tenant)');
  }
  return n;
}

/**
 * Take (and clear) every deliverable command of a device's queue, oldest
 * first. Expired entries and tunnels of sessions no longer waiting are
 * dropped (logged).
 */
export async function takeOrQueue(deviceUuid: string, tenantId: number): Promise<QueuedOrCommand[]> {
  return db.transaction(async (trx) => {
    const row = await trx('oblireach_devices')
      .where({ device_uuid: deviceUuid, tenant_id: tenantId })
      .forUpdate()
      .first('id', 'pending_command', 'version');
    if (!row || row.pending_command == null) return [];
    const queue = parseOrQueue(row.pending_command);
    await trx('oblireach_devices').where({ id: row.id }).update({ pending_command: null });
    const open = await openTunnelTokens(queue, trx);
    const keep = deliverableOrCommands(queue, Date.now(), open, row.version);
    if (keep.length !== queue.length) {
      logger.info({ deviceUuid, dropped: queue.length - keep.length }, 'ObliReach: stale queued commands dropped (expired, session no longer waiting, or update already applied)');
    }
    return keep;
  });
}

/**
 * HTTP push path (agents without the WS channel get ONE command per push):
 * take the first deliverable command, keep the other deliverable ones
 * queued. Read-modify-write under the row lock (SELECT … FOR UPDATE, like
 * enqueueOrCommand): working on a snapshot read earlier by the route lost a
 * session enqueued in between.
 */
export async function takeFirstOrCommand(rowId: number): Promise<QueuedOrCommand | null> {
  return db.transaction(async (trx) => {
    const row = await trx('oblireach_devices').where({ id: rowId }).forUpdate().first('id', 'pending_command', 'version');
    if (!row || row.pending_command == null) return null;
    const queue = parseOrQueue(row.pending_command);
    if (queue.length === 0) {
      await trx('oblireach_devices').where({ id: rowId }).update({ pending_command: null });
      return null;
    }
    const open = await openTunnelTokens(queue, trx);
    const keep = deliverableOrCommands(queue, Date.now(), open, row.version);
    const [first, ...rest] = keep;
    await trx('oblireach_devices').where({ id: rowId }).update({ pending_command: serializeOrQueue(rest) });
    return first ?? null;
  });
}

/** The wire shape (expiresAt is server-side bookkeeping). */
export function toWire(cmd: QueuedOrCommand): { type: string; id: string; payload: Record<string, unknown> } {
  return { type: cmd.type, id: cmd.id, payload: cmd.payload };
}
