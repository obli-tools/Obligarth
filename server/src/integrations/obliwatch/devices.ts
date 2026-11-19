import type { Request, Response } from 'express';
import type {
  CollectedField, ObliwatchDeviceAppItem, ObliwatchDeviceAppsResponse, ObliwatchDeviceView, ObliwatchDevicesResponse, Ownership,
} from '@obligarth/shared';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { privacyRulesFor } from '../../apple/devices/privacy';
import { nanoTypeOfMode, recordPrivacy } from '../../privacy/collected';
import { dropIdentifierKeys } from '../../privacy/mask';
import { auditRead } from './audit';
import { sendError } from './auth';
import { OBLIWATCH_ACTOR } from './config';
import { appsCoverage, coverageOf, type CoverageFacts } from './coverage';
import { decodeCursor, encodeCursor } from './cursor';

// =============================================================================
// The devices of the tenant of `ost` (brief GTH-03, GTH-09; plan L2), consent 'read' required (router):
//   GET /devices?updatedSince=<ISO 8601>&limit=1..500&cursor=   {items: DeviceView[], nextCursor}
//   GET /devices/:uuid                                         DeviceView (404 not_found outside the tenant)
//   GET /devices/:uuid/apps                                    {items, coverage, collectedAt}
// The view is a STRICT WHITELIST built column by column: the query never selects a serial number, IMEI, UDID, phone
// number, MAC, IP, location, the last logged-in user, the hardware or network information, the Android id nor the
// internal id (the identifiers are only compared, in the database, with the device's names: nameOf); dropIdentifierKeys
// (privacy/mask.ts) is then ALWAYS applied, whatever the token, as a last line. The order of the list is the change
// marker devices.signal_updated_at (migration 20261118100100), then the uuid; the cursor is that position, signed and
// bound to the tenant and the endpoint (cursor.ts). Every query runs as the tenant of `ost` (asTenant, i:obliwatch).
// Owner decisions: hostname for a corporate-owned device only (Q-L2c); integrity 'unknown' for an AMAPI device without
// posture (Q-L2b). primaryUpn is the end user's e-mail until end_users.upn exists (lot L4).
// =============================================================================

const LIST_ENDPOINT = 'devices';
const MAX_LIMIT = 500;
const MAX_APPS = 5000;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** ISO 8601 with a time and a zone (what Obliwatch sends back from updatedAt). */
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:?\d{2})$/;
/** The position in a cursor: the marker at the microsecond, UTC. */
const POS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);
const text = (v: unknown, max = 255): string | null => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);

/** A text folded for comparison: lower case, without whitespace, '-', ':' nor '.'. */
const fold = (expr: string): string => String.raw`regexp_replace(lower(${expr}), '[\s:.-]+', '', 'g')`;

/**
 * A device's name, for a corporate-owned device only (Q-L2c), and NULL when it carries an identifier (brief §3): any
 * identifier the database holds for the device (folded, 4 characters or more: the serial numbers of devices, of the
 * bridge agent's Build and Samsung, of its hints and of AMAPI's hardware, the IMEIs of the bridge agent, of its hints,
 * of Apple and of AMAPI, the UDID) or a run of 14 digits or more (an IMEI never stored when the profile drops it).
 */
const nameOf = (col: string): string => String.raw`
       CASE WHEN d.ownership IN ('corporate', 'corporate_personal')
             AND NULLIF(btrim(${col}), '') IS NOT NULL
             AND ${fold(col)} !~ '[0-9]{14,}'
             AND NOT EXISTS (SELECT 1 FROM unnest(idn.ids) AS i(v) WHERE strpos(${fold(col)}, i.v) > 0)
            THEN btrim(${col}) END`;

/**
 * The columns of the view (positional bindings only: the to_char formats hold colons). The identifiers of the
 * LATERAL `idn` are only compared, in the database, with the device's names: never selected.
 */
const SELECT = String.raw`
SELECT d.id, d.uuid::text AS uuid, d.platform, d.management_channel, d.ownership, d.management_mode, d.supervised,
       d.enrollment_state, d.os_version, d.compliance_state, d.compliance_reasons, d.lost_mode_state, d.last_checkin_at,
       ${nameOf('d.display_name')} AS admin_name,
       ${nameOf('d.device_name')} AS reported_name,
       eu.email AS end_user_email,
       to_char(an.security_patch_level, 'YYYY-MM-DD') AS amapi_patch,
       CASE WHEN an.released_at IS NULL THEN an.security_posture END AS amapi_posture,
       an.last_status_report_at AS amapi_report_at,
       to_char(la.security_patch, 'YYYY-MM-DD') AS agent_patch,
       la.last_inventory_at AS agent_inventory_at,
       ap.last_apps_at AS apple_apps_at, ap.last_managed_apps_at AS apple_managed_apps_at,
       EXISTS (SELECT 1 FROM obligarth.device_apps x WHERE x.tenant_id = d.tenant_id AND x.device_id = d.id) AS has_apps,
       d.signal_updated_at,
       to_char(d.signal_updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS marker_pos
  FROM obligarth.devices d
  LEFT JOIN obligarth.end_users eu ON eu.tenant_id = d.tenant_id AND eu.id = d.end_user_id
  LEFT JOIN obligarth.android_devices an ON an.tenant_id = d.tenant_id AND an.device_id = d.id
  LEFT JOIN obligarth.legacy_agent_devices la ON la.tenant_id = d.tenant_id AND la.device_id = d.id
  LEFT JOIN obligarth.apple_devices ap ON ap.tenant_id = d.tenant_id AND ap.device_id = d.id
  LEFT JOIN LATERAL (
    SELECT array_agg(DISTINCT f.v) AS ids
      FROM unnest(ARRAY[d.serial_number::text, la.claimed_serial::text, la.samsung_serial::text, la.hints->>'serial',
                        la.hints->>'imei', ap.udid::text, ap.imei::text, an.hardware_info->>'serialNumber',
                        an.network_info->>'imei', an.network_info->>'meid'] || COALESCE(la.imeis, '{}'::text[])) AS x(raw)
     CROSS JOIN LATERAL (SELECT ${fold('x.raw')} AS v) f
     WHERE x.raw IS NOT NULL AND length(f.v) >= 4
  ) idn ON true
 WHERE d.tenant_id = ?`;

/** One device of the tenant by its uuid (bound). */
const BY_UUID_SQL = `${SELECT} AND d.uuid = ?::uuid`;

/** Devices of the tenant by their internal ids (bound): the push of the signals (lot L3), never answered as is. */
const BY_IDS_SQL = `${SELECT} AND d.id = ANY (?::int[])`;

type Row = Record<string, any>;

/** What the privacy profile collects of a device, cached per request by (channel, ownership, mode). */
class CollectedCache {
  private readonly cache = new Map<string, Promise<CollectedField[]>>();
  constructor(private readonly tenantId: number) {}
  get(channel: string, ownership: string, mode: string): Promise<CollectedField[]> {
    const key = `${channel}|${ownership}|${mode}`;
    let p = this.cache.get(key);
    if (!p) {
      p = privacyRulesFor(db, this.tenantId, ownership as Ownership, nanoTypeOfMode(mode))
        .then((apple) => recordPrivacy(db, channel, this.tenantId, ownership, apple))
        .then((r) => r.collected);
      this.cache.set(key, p);
    }
    return p;
  }
}

const factsOf = (r: Row): CoverageFacts => ({
  channel: String(r.management_channel), posture: r.amapi_posture ?? null, amapiReportAt: r.amapi_report_at,
  agentInventoryAt: r.agent_inventory_at, appleAppsAt: r.apple_apps_at, appleManagedAppsAt: r.apple_managed_apps_at,
  hasApps: r.has_apps === true,
});

function postureOf(v: unknown): { posture: string | null; risks: string[] | null } {
  if (!v || typeof v !== 'object') return { posture: null, risks: null };
  const o = v as { devicePosture?: unknown; risks?: unknown };
  return {
    posture: text(o.devicePosture, 40),
    risks: Array.isArray(o.risks) ? o.risks.filter((x): x is string => typeof x === 'string').map((x) => x.slice(0, 60)).slice(0, 20) : [],
  };
}

function codesOf(v: unknown): string[] {
  const list = Array.isArray(v) ? v : [];
  const codes = list.map((x) => (x && typeof x === 'object' ? (x as { code?: unknown }).code : null))
    .filter((c): c is string => typeof c === 'string' && /^[a-z_]{1,40}$/.test(c));
  return [...new Set(codes)].slice(0, 20);
}

/** The DeviceView of a row: the whitelist, field by field. */
export async function deviceView(r: Row, collected: CollectedCache): Promise<ObliwatchDeviceView> {
  const channel = String(r.management_channel);
  const ownership = String(r.ownership) as ObliwatchDeviceView['ownership'];
  const fields = await collected.get(channel, ownership, String(r.management_mode));
  const p = channel === 'amapi' ? postureOf(r.amapi_posture) : { posture: null, risks: null };
  const email = text(r.end_user_email, 320);
  const view: ObliwatchDeviceView = {
    uuid: String(r.uuid),
    platform: String(r.platform),
    ownership,
    managementMode: String(r.management_mode),
    supervised: r.platform === 'android' ? null : r.supervised === true,
    enrollmentState: String(r.enrollment_state),
    // Corporate-owned only (the SQL); the reported name only when the profile collects it.
    hostname: text(r.admin_name) ?? (fields.includes('deviceName') ? text(r.reported_name) : null),
    osVersion: text(r.os_version, 32),
    securityPatchLevel: channel === 'amapi' ? (r.amapi_patch ?? null) : channel === 'legacy_agent' ? (r.agent_patch ?? null) : null,
    complianceState: String(r.compliance_state),
    complianceCodes: codesOf(r.compliance_reasons),
    integrityPosture: p.posture,
    integrityRisks: p.risks,
    lostModeState: String(r.lost_mode_state),
    lastCheckinAt: iso(r.last_checkin_at),
    primaryUpn: email,
    primaryUpnSource: email ? 'email' : 'none',
    coverage: coverageOf(factsOf(r), fields),
    updatedAt: iso(r.signal_updated_at) as string,
  };
  // The always-on mask (brief §3): a key naming an identifier never leaves, whatever the view grows into.
  return dropIdentifierKeys(view);
}

interface Position { t: string; u: string }

function limitOf(req: Request, res: Response): number | null {
  const raw = req.query.limit;
  const n = raw === undefined ? MAX_LIMIT : typeof raw === 'string' && /^\d{1,4}$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isInteger(n) || n < 1 || n > MAX_LIMIT) { sendError(res, 400, 'limit_invalid', `limit: 1 to ${MAX_LIMIT}`); return null; }
  return n;
}

/** GET /devices?updatedSince=&limit=&cursor= */
export async function listDevices(req: Request, res: Response): Promise<void> {
  const caller = req.obliwatch!;
  const limit = limitOf(req, res);
  if (limit === null) return;
  let since: string | null = null;
  if (req.query.updatedSince !== undefined) {
    const s = req.query.updatedSince;
    if (typeof s !== 'string' || s.length > 40 || !ISO_RE.test(s) || !Number.isFinite(Date.parse(s))) {
      sendError(res, 400, 'updated_since_invalid', 'updatedSince: an ISO 8601 date and time with a zone');
      return;
    }
    since = s;
  }
  let after: Position | null = null;
  if (req.query.cursor !== undefined) {
    const pos = typeof req.query.cursor === 'string' ? decodeCursor<Position>(caller.tenantId, LIST_ENDPOINT, req.query.cursor) : null;
    if (!pos || typeof pos.t !== 'string' || typeof pos.u !== 'string' || !POS_RE.test(pos.t) || !UUID_RE.test(pos.u)) {
      sendError(res, 400, 'cursor_invalid');
      return;
    }
    after = pos;
  }

  const { items, more, last } = await asTenant(caller.tenantId, OBLIWATCH_ACTOR, async () => {
    const bindings: unknown[] = [caller.tenantId];
    // Constant fragments only (SELECT, the two optional bounds, the order); every value bound.
    let sql = SELECT;
    if (since) { sql += ' AND d.signal_updated_at >= ?::timestamptz'; bindings.push(since); }
    if (after) { sql += ' AND (d.signal_updated_at, d.uuid) > (?::timestamptz, ?::uuid)'; bindings.push(after.t, after.u); }
    sql += ' ORDER BY d.signal_updated_at ASC, d.uuid ASC LIMIT ?';
    bindings.push(limit + 1);
    const rows = (await db.raw(sql, bindings as any[]) as { rows: Row[] }).rows;
    const page = rows.slice(0, limit);
    const collected = new CollectedCache(caller.tenantId);
    const views: ObliwatchDeviceView[] = [];
    for (const r of page) views.push(await deviceView(r, collected));
    const tail = page[page.length - 1];
    return { items: views, more: rows.length > limit, last: tail ? { t: String(tail.marker_pos), u: String(tail.uuid) } : null };
  });

  const body: ObliwatchDevicesResponse = {
    items,
    nextCursor: more && last ? encodeCursor(caller.tenantId, LIST_ENDPOINT, last satisfies Position) : null,
  };
  // Never a device identifier in the audit of a page (plan L2): the count only.
  auditRead(req, caller.tenantId, LIST_ENDPOINT, { count: items.length, incremental: since !== null });
  res.json(body);
}

/** The row of one device of the tenant, by its uuid; null when it is not there (or the uuid is malformed). */
async function rowOf(tenantId: number, uuid: string): Promise<Row | null> {
  if (!UUID_RE.test(uuid)) return null;
  const rows = (await db.raw(BY_UUID_SQL, [tenantId, uuid]) as { rows: Row[] }).rows;
  return rows[0] ?? null;
}

/**
 * The DeviceView of devices of the tenant by internal id, for the push of the signals (lot L3: asset.hostname, asset.os
 * and user.upn come from it, so the name follows the read API's rule exactly). In the caller's database context (the
 * tenant's). The key of the map is internal: it never leaves.
 */
export async function deviceViewsOf(tenantId: number, deviceIds: number[]): Promise<Map<number, ObliwatchDeviceView>> {
  const ids = [...new Set(deviceIds.map(Number).filter((n) => Number.isSafeInteger(n) && n > 0))];
  const out = new Map<number, ObliwatchDeviceView>();
  if (ids.length === 0) return out;
  const rows = (await db.raw(BY_IDS_SQL, [tenantId, ids]) as { rows: Row[] }).rows;
  const collected = new CollectedCache(tenantId);
  for (const r of rows) out.set(Number(r.id), await deviceView(r, collected));
  return out;
}

/** GET /devices/:uuid */
export async function getDevice(req: Request, res: Response): Promise<void> {
  const caller = req.obliwatch!;
  const uuid = String(req.params.uuid ?? '');
  const view = await asTenant(caller.tenantId, OBLIWATCH_ACTOR, async () => {
    const r = await rowOf(caller.tenantId, uuid);
    return r ? deviceView(r, new CollectedCache(caller.tenantId)) : null;
  });
  if (!view) { sendError(res, 404, 'not_found', 'Not found'); return; }
  auditRead(req, caller.tenantId, 'devices/:uuid', { count: 1, device: view.uuid });
  res.json(view);
}

/** GET /devices/:uuid/apps */
export async function getDeviceApps(req: Request, res: Response): Promise<void> {
  const caller = req.obliwatch!;
  const uuid = String(req.params.uuid ?? '');
  const out = await asTenant(caller.tenantId, OBLIWATCH_ACTOR, async (): Promise<ObliwatchDeviceAppsResponse | null> => {
    const r = await rowOf(caller.tenantId, uuid);
    if (!r) return null;
    const channel = String(r.management_channel);
    const fields = await new CollectedCache(caller.tenantId).get(channel, String(r.ownership), String(r.management_mode));
    const coverage = appsCoverage(factsOf(r), fields);
    const collectedAt = channel === 'amapi' ? iso(r.amapi_report_at)
      : channel === 'legacy_agent' ? iso(r.agent_inventory_at)
        : iso([r.apple_apps_at, r.apple_managed_apps_at].filter(Boolean).map((v) => new Date(v)).sort((a, b) => b.getTime() - a.getTime())[0] ?? null);
    if (coverage === 'none') return { items: [], coverage, collectedAt };
    const q = db('device_apps').where({ tenant_id: caller.tenantId, device_id: Number(r.id) })
      .orderBy('identifier', 'asc').limit(MAX_APPS)
      .select('identifier', 'version', 'short_version', 'managed');
    // The ingestion already keeps the managed apps only where the profile says so (mdm/inventory/views.ts): refiltered
    // here all the same, never a personal app.
    if (coverage !== 'full') q.where('managed', true);
    const rows = await q as Row[];
    const items: ObliwatchDeviceAppItem[] = rows.map((a) => ({
      identifier: String(a.identifier), version: text(a.version, 64), shortVersion: text(a.short_version, 64), managed: a.managed === true,
    }));
    return dropIdentifierKeys({ items, coverage, collectedAt });
  });
  if (!out) { sendError(res, 404, 'not_found', 'Not found'); return; }
  auditRead(req, caller.tenantId, 'devices/:uuid/apps', { count: out.items.length, device: uuid.toLowerCase() });
  res.json(out);
}
