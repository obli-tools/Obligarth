import type { Server as SocketIOServer } from 'socket.io';
import type { Knex } from 'knex';
import { db } from '../db';
import { SocketEvents } from '@obligarth/shared';


let _io: SocketIOServer | null = null;

export function setLiveAlertIO(io: SocketIOServer): void {
  _io = io;
}

// The DB column is `alert_severity` ENUM ('info','warning','critical')
// — the previous typing claimed 'down' / 'up' which would have
// triggered a Postgres enum-cast error if anything ever inserted them.
// 'critical' is used for outages and crit-threshold alerts; 'warning'
// for warn-threshold; 'info' for benign offline alerts / reminders.
export type LiveAlertSeverity = 'info' | 'warning' | 'critical';

export interface LiveAlertRow {
  id: number;
  tenantId: number;
  tenantName?: string;
  severity: LiveAlertSeverity;
  title: string;
  message: string;
  navigateTo: string | null;
  stableKey: string | null;
  // ISO timestamp when the user marked it read, or null when unread.
  // MUST be `readAt` (not `read`) to match the shared LiveAlert contract
  // the client reads — the client checks `!alert.readAt`. A previous
  // `read: boolean` field meant `readAt` was always undefined client-side,
  // so every alert came back unread on every reload.
  readAt: string | null;
  createdAt: string; // ISO
}

function rowToAlert(row: Record<string, unknown>): LiveAlertRow {
  return {
    id: row.id as number,
    tenantId: row.tenant_id as number,
    tenantName: row.tenant_name as string | undefined,
    severity: row.severity as LiveAlertRow['severity'],
    title: row.title as string,
    message: row.message as string,
    navigateTo: row.navigate_to as string | null,
    stableKey: row.stable_key as string | null,
    readAt: row.read_at ? new Date(row.read_at as string | Date).toISOString() : null,
    createdAt: (row.created_at as Date).toISOString(),
  };
}

// ─── Incidents ───────────────────────────────────────────────────────────────
// An incident = one device + one alert kind that has a recovery
// counterpart. While the problem lasts, at most ONE row of the incident is
// active (`resolved_at IS NULL`). The recovery resolves it instead of
// adding a "back to normal" row, so a flapping device leaves nothing but
// its current problem in the web bell and the mobile "À traiter". Resolved
// rows are hidden from every list (never deleted here: the per-tenant trim
// below still applies).
//
//   kind                stable keys (all severities = one incident)       recovery
//   metric              device:{id}:metric:warning|critical               alertable level back to ok (handlePush), metric
//                                                                          muted (re-baseline), push not evaluated (all-metrics
//                                                                          switch off, evaluation failed: levels reset to ok),
//                                                                          and every push whose alertable level is ok while a
//                                                                          row is still active (self-healing, handlePush)
//   offline             device:{id}:offline                               push / WS command channel after 'offline'
//   diskhealth          device:{id}:diskhealth:caution|bad                worst SMART status back to 'good'
//   duplicate_agent_id  device:{id}:duplicate_agent_id                    duplicate flag cleared (re-evaluation, acknowledge)
//   (every kind)                                                          device deleted (deleteDevice, bulkDelete, cleanOrphans)
//
// These four kinds were raised and resolved by the agent channel (push
// handling, command channel, disk health, identity checks), now removed, and
// so was their raise path (raiseIncident, which re-read the device's status
// and metric levels under the incident lock). Only the resolution stays: a
// row already stored leaves with its device (last line). An incident of the
// MDM brings its own raise path, with the device state it needs.
//
// add() handles every stable key the same way: dedup on an unread active row
// of the same tenant + key, never resolved by add() itself.
export type LiveAlertIncidentKind = 'metric' | 'offline' | 'diskhealth' | 'duplicate_agent_id';

const INCIDENT_KEY_SUFFIXES: Record<LiveAlertIncidentKind, readonly string[]> = {
  metric: ['metric:warning', 'metric:critical'],
  offline: ['offline'],
  diskhealth: ['diskhealth:caution', 'diskhealth:bad'],
  duplicate_agent_id: ['duplicate_agent_id'],
};

/** Every stable key of the incident `kind` of a device (all severities). */
export function incidentStableKeys(kind: LiveAlertIncidentKind, deviceId: number): string[] {
  return INCIDENT_KEY_SUFFIXES[kind].map((suffix) => `device:${deviceId}:${suffix}`);
}

const INCIDENT_KINDS = Object.keys(INCIDENT_KEY_SUFFIXES) as LiveAlertIncidentKind[];

/**
 * Every incident stable key, all kinds (for SQL `~`). Kept in step with
 * INCIDENT_KEY_SUFFIXES.
 */
const INCIDENT_KEY_REGEX = '^device:[0-9]{1,9}:(metric:(warning|critical)|offline|diskhealth:(caution|bad)|duplicate_agent_id)$';

/**
 * Incidents per resolve transaction: one advisory lock and ≤ 2 stable keys
 * each, well under the bind limit and the shared lock table.
 */
const RESOLVE_CHUNK = 200;

type IncidentRef = { kind: LiveAlertIncidentKind; deviceId: number };

/** Advisory-lock key of an incident: the resolutions of one incident run one at a time. */
function incidentLockKey(kind: LiveAlertIncidentKind, deviceId: number): string {
  return `live_alert_incident:${kind}:${deviceId}`;
}

/**
 * Take the advisory locks of several incidents in the current transaction,
 * sorted by lock id (the hash): every multi-incident transaction takes them
 * in the same order, so two of them can never deadlock (a raise holds a
 * single one). unnest() of an array yields its elements in order.
 */
async function lockIncidents(trx: Knex.Transaction, lockKeys: string[]): Promise<void> {
  if (lockKeys.length === 0) return;
  await trx.raw(
    `SELECT count(pg_advisory_xact_lock(h)) FROM unnest(
       (SELECT array_agg(DISTINCT hashtext(k) ORDER BY hashtext(k)) FROM unnest(?::text[]) AS k)
     ) AS h`,
    [lockKeys],
  );
}

type TenantRow = { id: number; tenant_id: number };

function groupByTenant(rows: TenantRow[]): Map<number, number[]> {
  const byTenant = new Map<number, number[]>();
  for (const r of rows) {
    const list = byTenant.get(r.tenant_id) ?? [];
    list.push(r.id);
    byTenant.set(r.tenant_id, list);
  }
  return byTenant;
}

/**
 * Tell the open clients of each tenant that these rows left the lists:
 * NOTIFICATION_RESOLVED `{ ids }`, same room as NOTIFICATION_NEW.
 */
function emitResolved(rows: TenantRow[]): void {
  if (!_io || rows.length === 0) return;
  for (const [tenantId, ids] of groupByTenant(rows)) {
    _io.to(`tenant:${tenantId}:notifications`).emit(SocketEvents.NOTIFICATION_RESOLVED, { ids });
  }
}

/**
 * Resolve every active row of these incidents, in ANY tenant. Each chunk
 * holds the incidents' advisory locks (the raise path of an MDM incident
 * must take the same lock). NOTIFICATION_RESOLVED is emitted per chunk.
 * Returns the resolved ids.
 */
async function resolveIncidentRefs(refs: IncidentRef[]): Promise<number[]> {
  const ids: number[] = [];
  for (let i = 0; i < refs.length; i += RESOLVE_CHUNK) {
    const chunk = refs.slice(i, i + RESOLVE_CHUNK);
    const rows = await db.transaction(async (trx) => {
      await lockIncidents(trx, chunk.map((r) => incidentLockKey(r.kind, r.deviceId)));
      return await trx('live_alerts')
        .whereIn('stable_key', chunk.flatMap((r) => incidentStableKeys(r.kind, r.deviceId)))
        .whereNull('resolved_at')
        .update({ resolved_at: new Date() })
        .returning(['id', 'tenant_id']) as TenantRow[];
    });
    emitResolved(rows);
    ids.push(...rows.map((r) => r.id));
  }
  return ids;
}

type AddOpts = {
  severity: LiveAlertSeverity;
  title: string;
  message: string;
  navigateTo?: string | null;
  stableKey?: string | null;
};

function insertValues(tenantId: number, opts: AddOpts): Record<string, unknown> {
  return {
    tenant_id: tenantId,
    severity: opts.severity,
    title: opts.title,
    message: opts.message,
    navigate_to: opts.navigateTo ?? null,
    stable_key: opts.stableKey ?? null,
  };
}

/**
 * Keep only the newest 200 rows per tenant. Active rows are kept first so
 * the hidden (resolved) history of a flapping device can never push a
 * still-open alert out. (Active rows of a deleted device do not pile up:
 * device deletion and cleanOrphans resolve them.)
 */
async function trimTenant(tenantId: number): Promise<void> {
  const res = await db.raw(
    `DELETE FROM live_alerts WHERE tenant_id = ? AND id NOT IN (
       SELECT id FROM live_alerts WHERE tenant_id = ?
        ORDER BY (resolved_at IS NULL) DESC, id DESC
        LIMIT 200
     ) RETURNING id, tenant_id, resolved_at`,
    [tenantId, tenantId],
  ) as { rows?: Array<{ id: number; tenant_id: number; resolved_at: Date | null }> };
  // Only when a tenant holds more than 200 ACTIVE alerts: the dropped
  // still-active rows leave the open web bells and the app at once.
  const droppedActive = (res.rows ?? []).filter((r) => r.resolved_at == null);
  emitResolved(droppedActive.map((r) => ({ id: r.id, tenant_id: r.tenant_id })));
}

/** Enrich with the tenant name and broadcast NOTIFICATION_NEW. */
async function announce(row: Record<string, unknown>, tenantId: number): Promise<LiveAlertRow> {
  const alert = rowToAlert(row);
  const tenantRow = await db('tenants').where({ id: tenantId }).select('name').first() as { name: string } | undefined;
  const enriched: LiveAlertRow = { ...alert, tenantName: tenantRow?.name ?? '' };
  // Emit to all users subscribed to this tenant's notifications
  if (_io) {
    _io.to(`tenant:${tenantId}:notifications`).emit(SocketEvents.NOTIFICATION_NEW, enriched);
  }
  return enriched;
}

export const liveAlertService = {
  /**
   * Add a new live alert. Returns the inserted row (NOTIFICATION_NEW is
   * emitted), or null when nothing was inserted: skipped when an unread
   * active alert with the same (tenant_id, stable_key) already exists.
   */
  async add(tenantId: number, opts: AddOpts): Promise<LiveAlertRow | null> {
    // Dedup: skip if an unread alert with the same stable_key already exists for this tenant
    if (opts.stableKey) {
      const existing = await db('live_alerts')
        .where({ tenant_id: tenantId, stable_key: opts.stableKey })
        .whereNull('read_at')
        .whereNull('resolved_at')
        .first();
      if (existing) return null;
    }

    const [row] = await db('live_alerts').insert(insertValues(tenantId, opts)).returning('*');
    await trimTenant(tenantId);
    return announce(row, tenantId);
  },

  /**
   * Recovery: resolve every active row of the incident `kind` of these
   * devices, in ANY tenant (a device transferred to another tenant left its
   * alerts in the source tenant). Nothing is inserted: the "back to normal"
   * message only goes to the notification channels. Emits
   * NOTIFICATION_RESOLVED per tenant and returns the resolved ids. Internal
   * callers only (never with ids taken from a request).
   */
  async resolveIncidents(kind: LiveAlertIncidentKind, deviceIds: number[]): Promise<number[]> {
    return resolveIncidentRefs([...new Set(deviceIds)].map((deviceId) => ({ kind, deviceId })));
  },

  /**
   * The devices are gone (deleted): every incident of theirs is over, in
   * every tenant. Without this their active rows would stay listed for
   * good (no recovery can ever come, and the trim keeps active rows).
   * Internal callers only. Returns the resolved ids.
   */
  async resolveDeviceIncidents(deviceIds: number[]): Promise<number[]> {
    const refs = [...new Set(deviceIds)].flatMap((deviceId) => INCIDENT_KINDS.map((kind) => ({ kind, deviceId })));
    return resolveIncidentRefs(refs);
  },

  /**
   * Self-healing (deviceService.cleanOrphans): resolve the active incident
   * rows whose device no longer exists (deleted by a path that did not
   * resolve them, or before resolution existed). Returns the resolved ids.
   */
  async resolveOrphanIncidents(): Promise<number[]> {
    const res = await db.raw(
      `SELECT DISTINCT x.device_id FROM (
         SELECT CASE WHEN stable_key ~ ? THEN split_part(stable_key, ':', 2)::int END AS device_id
           FROM live_alerts WHERE resolved_at IS NULL AND stable_key LIKE 'device:%'
       ) x
       WHERE x.device_id IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.id = x.device_id)`,
      [INCIDENT_KEY_REGEX],
    );
    const deviceIds = ((res?.rows ?? []) as Array<{ device_id: number }>).map((r) => Number(r.device_id));
    if (deviceIds.length === 0) return [];
    return liveAlertService.resolveDeviceIncidents(deviceIds);
  },

  /**
   * Fetch the ACTIVE alerts of a single tenant (newest first). Ordered by
   * id — the serial the web and the phone use as high-water mark — not by
   * created_at: an incident row gets its created_at at the start of its
   * transaction but its id at INSERT time, so the two orders can differ by
   * a few ms between concurrent raises, and a 200-row window cut by date
   * could skip an id newer than its oldest row.
   */
  async getForTenant(tenantId: number, limit = 100): Promise<LiveAlertRow[]> {
    const rows = await db('live_alerts')
      .where({ tenant_id: tenantId })
      .whereNull('resolved_at')
      .orderBy('id', 'desc')
      .limit(limit);
    return rows.map(rowToAlert);
  },

  /**
   * Fetch the ACTIVE alerts of all of the given tenants, enriched with the
   * tenant name (newest id first, see getForTenant). Used for the
   * multi-tenant notification panel and the app.
   */
  async getForTenants(tenantIds: number[], limit = 200): Promise<LiveAlertRow[]> {
    if (tenantIds.length === 0) return [];
    const rows = await db('live_alerts')
      .join('tenants', 'live_alerts.tenant_id', 'tenants.id')
      .whereIn('live_alerts.tenant_id', tenantIds)
      .whereNull('live_alerts.resolved_at')
      .orderBy('live_alerts.id', 'desc')
      .limit(limit)
      .select('live_alerts.*', 'tenants.name as tenant_name');
    return rows.map(rowToAlert);
  },

  /**
   * Ids of EVERY active alert of the given tenants (not capped like
   * getForTenants). The app uses it to withdraw the phone notification of
   * an alert that left a full 200-row list (`activeIds` of GET /all).
   */
  async getActiveIds(tenantIds: number[]): Promise<number[]> {
    if (tenantIds.length === 0) return [];
    const ids = await db('live_alerts')
      .whereIn('tenant_id', tenantIds)
      .whereNull('resolved_at')
      .pluck('id') as Array<number | string>;
    return ids.map(Number);
  },

  async markRead(id: number, tenantId: number): Promise<void> {
    await db('live_alerts').where({ id, tenant_id: tenantId }).update({ read_at: new Date() });
  },

  async markAllRead(tenantId: number): Promise<void> {
    await db('live_alerts')
      .where({ tenant_id: tenantId })
      .whereNull('read_at')
      .whereNull('resolved_at')
      .update({ read_at: new Date() });
  },

  async deleteAlert(id: number): Promise<void> {
    await db('live_alerts').where({ id }).delete();
  },

  async clearAll(tenantId: number): Promise<void> {
    await db('live_alerts').where({ tenant_id: tenantId }).delete();
  },

  /** Periodic cleanup: remove alerts older than daysOld. */
  async cleanup(daysOld = 30): Promise<void> {
    await db('live_alerts')
      .where('created_at', '<', new Date(Date.now() - daysOld * 86_400_000))
      .delete();
  },
};
