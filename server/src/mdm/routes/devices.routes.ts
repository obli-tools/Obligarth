import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import {
  DEVICE_LIST_SORT_KEYS, type DeviceAppsMeta, type DeviceLocationPoint, type DeviceLocations, type DeviceSummary,
} from '@obligarth/shared';
import { db } from '../../db';
import { audit } from '../../audit';
import { asTargetTenant, globalViewRead, globalViewScope } from '../../middleware/dbContext';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { deviceService, type DeviceListFilters } from '../../services/device.service';
import {
  deviceListFilters, deviceListFiltersVersion, deviceListQueryShape, parseError,
} from '../../services/deviceListFilters';
import { deviceViewNotFound, deviceViewService, mergeViewFilters, parseViewRef } from '../views/deviceViewService';
import { hasGlobalView, parseRequestDeviceId, resolveRequestDevice } from '../../services/deviceScope.service';
import { permissionService } from '../../services/permission.service';
import { launchChromium } from '../../utils/chromium';
import { listEpisodes } from '../registry/episodes';
import { assignEndUser } from '../registry/endUsers';
import { changeOwnership } from '../registry/ownership';
import { changeDevicesGroup } from '../policies/deviceMove';
import { deviceAppIcon, deviceApps, deviceCertificates, deviceProfiles } from '../inventory/views';
import { retentionDays } from '../../privacy/retention';
import { lostModeLocationAllowed } from '../../privacy/profiles';
import { deviceConfiguration } from '../policies/configuration';
import { requestDeviceResolution } from '../policies/triggers';
import { requestGroupEvaluation } from '../groups/triggers';
import { changeDeviceFacts } from '../groups/governance';
import { DevicePatchBody } from '../registry/devicePatch';

// =============================================================================
// Console API of the device registry (docs: modele-donnees-mdm §10.6, §11.1):
// mounted at /api/mdm, in the tenant of the session (requireTenant), with the
// guards of the core (capabilities, team scopes of the devices, restrictions,
// guarded action device.delete) and the audit. Reads accept the master
// tenant's global view (platform administrators: context 'platform'); a write
// from it goes to the device's own tenant (asTargetTenant, one tenant per
// request). A device out of reach answers like an unknown one (404).
// The commands, the queue, the actions and the timeline of a device are the
// integration's (/api/apple/…); the policies and assignments are in
// policies.routes.ts (lot B5b), the apps come with their lot (C4).
// =============================================================================

const router = Router();
/** ?dryRun=true (or 1): the preview of a change only, nothing written. */
const isDryRun = (req: Request): boolean => req.query.dryRun === 'true' || req.query.dryRun === '1';

// ── Query and body schemas ─────────────────────────────────────────────────

const intOpt = z.preprocess((v) => (v === undefined || v === '' ? undefined : Number(v)), z.number().int().positive().optional());

/** What the list and the export take besides the filters of the registry (services/deviceListFilters.ts): the global
 *  view's tenants, the sort, the page, the format, and a saved view (id or uuid; P0-5 T2). */
const LIST_BASE = {
  tenantIds: z.preprocess((v) => (v === undefined || v === '' ? undefined : (Array.isArray(v) ? v : String(v).split(',')).map(Number)),
    z.array(z.number().int().positive()).max(200).optional()),
  sortBy: z.enum(DEVICE_LIST_SORT_KEYS).optional(),
  sortOrder: z.enum(['asc', 'desc']).optional(),
  page: intOpt,
  pageSize: intOpt,
  format: z.enum(['csv', 'xlsx', 'pdf']).optional(),
  viewId: z.string().max(36).optional(),
};
const LIST_PARAMS = new Set(['tenantIds', 'sortBy', 'sortOrder']);

/** The schema of the list's query: the filters registered (rebuilt when a lot registers one) and LIST_BASE. */
let listQuery: { version: number; schema: z.ZodTypeAny } | null = null;
function listQuerySchema(): z.ZodTypeAny {
  const v = deviceListFiltersVersion();
  if (listQuery?.version !== v) listQuery = { version: v, schema: z.object({ ...deviceListQueryShape(), ...LIST_BASE }).passthrough() };
  return listQuery.schema;
}

/**
 * The filters of a list or export request: its parameters (the filters of the registry, the tenants, the sort), over
 * the definition of the saved view ?viewId= names when it does (a view the caller sees: theirs, or a shared one of the
 * session's tenant; 404 deviceViewNotFound otherwise), the explicit parameters winning (deviceViewService.mergeViewFilters); then the
 * page and the team scopes. ?rule= is the advanced filter (invalidRule: the issues).
 */
async function listFiltersOf(req: Request): Promise<{ filters: DeviceListFilters; format?: 'csv' | 'xlsx' | 'pdf' }> {
  const parsed = listQuerySchema().safeParse(req.query);
  if (!parsed.success) throw parseError(parsed.error);
  const q = parsed.data as Record<string, unknown> & z.infer<z.ZodObject<typeof LIST_BASE>>;
  const filterKeys = new Set<string>(deviceListFilters().map((d) => d.key));
  const explicit: DeviceListFilters = {};
  for (const [k, v] of Object.entries(q)) {
    if (v !== undefined && (filterKeys.has(k) || LIST_PARAMS.has(k))) (explicit as Record<string, unknown>)[k] = v;
  }
  let filters = explicit;
  if (q.viewId !== undefined) {
    const ref = parseViewRef(q.viewId);
    const stored = ref ? await deviceViewService.definitionFor(req.tenantId!, Number(req.session.userId), ref) : null;
    if (stored === null) throw deviceViewNotFound();
    filters = mergeViewFilters(stored, explicit);
  }
  return {
    filters: { ...filters, page: q.page, pageSize: q.pageSize, visibleIds: await visibleIdsOf(req) },
    format: q.format,
  };
}

/** The devices a non-administrator sees through their teams (undefined: every device, an administrator). */
async function visibleIdsOf(req: Request): Promise<number[] | 'all' | undefined> {
  if (req.session.role === 'admin') return undefined;
  return permissionService.getVisibleDeviceIds(req.session.userId!, false);
}

/** The operator's fields of a record (mdm/registry/devicePatch.ts: the governed change of the facts parses it again). */
const PatchBody = DevicePatchBody;

const GroupBody = z.object({ groupId: z.number().int().positive().nullable() }).strict();
const BatchGroupBody = z.object({
  deviceIds: z.array(z.union([z.number(), z.string()])).min(1).max(10_000),
  groupId: z.number().int().positive().nullable(),
}).strict();
const EndUserBody = z.object({ endUserId: z.number().int().positive().nullable() }).strict();
const OwnershipBody = z.object({
  to: z.enum(['corporate', 'corporate_personal']),
  reason: z.string().trim().min(1).max(500),
  ticket: z.string().trim().max(100).nullable().optional(),
}).strict();

function body<S extends z.ZodTypeAny>(schema: S, req: Request): z.infer<S> {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  return parsed.data;
}

// ── Device of a route (:id) ────────────────────────────────────────────────

declare module 'express-serve-static-core' {
  interface Request {
    /** The device of an /api/mdm/devices/:id route, once resolved (its own tenant). */
    mdmDevice?: { id: number; tenantId: number };
  }
}

/**
 * The device of the route, with the REST tenant rule (resolveRequestDevice): the session's tenant, any
 * tenant for the global view, through a team of the caller for a non-administrator; 404 out of reach.
 * `write`: write access too (rw scope; 403 otherwise).
 */
function resolveDevice(write: boolean) {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const id = parseRequestDeviceId(req.params.id);
      if (id === null) { next(new AppError(404, 'Device not found')); return; }
      const outcome = await globalViewRead(req, () => resolveRequestDevice(req, id));
      if (!outcome.ok) { next(new AppError(outcome.status, outcome.error)); return; }
      if (write && !outcome.isAdmin && !(await permissionService.canWriteDevice(req.session.userId!, id, false))) {
        next(new AppError(403, 'Insufficient permissions'));
        return;
      }
      req.mdmDevice = { id, tenantId: Number(outcome.device.tenant_id) };
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** Write access on a group of the session's tenant, for a non-administrator (403 otherwise). */
async function requireGroupWriteOn(req: Request, groupId: number | null): Promise<void> {
  if (groupId === null || req.session.role === 'admin') return;
  if (!(await permissionService.canWriteGroup(req.session.userId!, groupId, false))) {
    throw new AppError(403, 'No write permission on target group');
  }
}

// ── Collection routes (before /:id) ────────────────────────────────────────

// GET /api/mdm/devices
router.get('/devices', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const { filters } = await listFiltersOf(req);
    res.json({ data: await deviceService.listDevices(req.tenantId!, filters, { globalView: hasGlobalView(req) }) });
  } catch (err) { next(err); }
});

// GET /api/mdm/devices/facets
router.get('/devices/facets', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    res.json({ data: await deviceService.getFacets(req.tenantId!, { globalView: hasGlobalView(req) }, await visibleIdsOf(req)) });
  } catch (err) { next(err); }
});

// GET /api/mdm/devices/export?format=csv|xlsx|pdf: the filtered list, the collected columns only.
router.get('/devices/export', requireTenantCapability('reports'), globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const { filters, format } = await listFiltersOf(req);
    const fmt = format ?? 'csv';
    const devices = await deviceService.exportDevices(req.tenantId!, filters, { globalView: hasGlobalView(req) });
    await sendExport(res, fmt, devices);
  } catch (err) { next(err); }
});

// GET /api/mdm/fleet/summary, /fleet/timeseries?days=14, /fleet/hourly?hours=24 (dashboard)
router.get('/fleet/summary', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    res.json({ data: await deviceService.getFleetSummary(req.tenantId!, { globalView: hasGlobalView(req) }) });
  } catch (err) { next(err); }
});
router.get('/fleet/timeseries', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const days = Math.min(90, Math.max(1, parseInt(String(req.query.days ?? '14'), 10) || 14));
    res.json({ data: await deviceService.getFleetTimeseries(req.tenantId!, days, { globalView: hasGlobalView(req) }) });
  } catch (err) { next(err); }
});
router.get('/fleet/hourly', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const hours = Math.min(168, Math.max(2, parseInt(String(req.query.hours ?? '24'), 10) || 24));
    res.json({ data: await deviceService.getFleetHourlySeries(req.tenantId!, hours, { globalView: hasGlobalView(req) }) });
  } catch (err) { next(err); }
});

// POST /api/mdm/devices/batch/group[?dryRun=true] — { deviceIds, groupId }: devices of the session's tenant only (an
// id of another tenant, or unknown: 404, nothing moved); write on the target group. What the devices inherit follows
// their group (S12; decision of the owners of 15/10/2026): previewed, and guarded like a change of assignments (a
// step-up when a configuration changes, a second approver beyond the thresholds of DM23: 202), with the restriction
// device.bulk_group_change beyond one device (mdm/policies/deviceMove.ts).
router.post('/devices/batch/group', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const b = body(BatchGroupBody, req);
    const parsed = b.deviceIds.map(parseRequestDeviceId);
    const ids = [...new Set(parsed.filter((n): n is number => n !== null))];
    if (parsed.some((n) => n === null) || ids.length === 0) throw new AppError(404, 'No matching devices in this tenant');
    const inTenant = (await db('devices').whereIn('id', ids).andWhere({ tenant_id: req.tenantId! }).pluck('id') as number[]).map(Number);
    if (inTenant.length !== ids.length) throw new AppError(404, 'No matching devices in this tenant');
    if (b.groupId !== null && !(await db('device_groups').where({ id: b.groupId, tenant_id: req.tenantId! }).first('id'))) {
      throw new AppError(404, 'Group not found');
    }
    await requireGroupWriteOn(req, b.groupId);
    const out = await changeDevicesGroup(req, req.tenantId!, ids, b.groupId, isDryRun(req));
    const data = (out.body as { data?: { changedIds?: number[] } }).data;
    if (out.status === 200 && data?.changedIds) {
      deviceService.emitChanged(req.tenantId!, data.changedIds);
      delete data.changedIds;
    }
    if (out.headers) res.set(out.headers);
    res.status(out.status).json(out.body);
  } catch (err) { next(err); }
});

// DELETE /api/mdm/devices/batch — { deviceIds, reason, ticket?, confirm }: guarded action device.delete.
router.delete('/devices/batch', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const b = (req.body ?? {}) as { deviceIds?: unknown; ids?: unknown; reason?: unknown; ticket?: unknown; confirm?: unknown };
    const raw = b.deviceIds ?? b.ids;
    if (!Array.isArray(raw) || raw.length === 0) throw new AppError(400, 'deviceIds required', 'invalidRequest');
    await guardedDeletion(req, res, next, raw, b);
  } catch (err) { next(err); }
});

// ── One device (:id) ───────────────────────────────────────────────────────

// GET /api/mdm/devices/:id
router.get('/devices/:id', globalViewScope('console.devices'), resolveDevice(false), async (req, res, next) => {
  try {
    const device = await deviceService.getDeviceById(req.mdmDevice!.id, req.tenantId!, { globalView: hasGlobalView(req) });
    if (!device) throw new AppError(404, 'Device not found');
    res.json({ data: device });
  } catch (err) { next(err); }
});

// PATCH /api/mdm/devices/:id[?dryRun=true] — the operator's fields (name, description, tags, custom fields, asset).
// A change that makes the device enter or leave a dynamic group an assignment targets (P0-5 T7, D11) needs
// devices.manage (403 deviceFactsGoverned) and goes through the governed preview (groups/governance.ts): ?dryRun=true
// answers it, a step-up when the configuration of the device changes, a second approver beyond the thresholds (202).
router.patch('/devices/:id', resolveDevice(true), async (req, res, next) => {
  try {
    const patch = body(PatchBody, req);
    const { id, tenantId } = req.mdmDevice!;
    const out = await asTargetTenant(req, tenantId, () => changeDeviceFacts(req, tenantId, id, patch, isDryRun(req)));
    if (out) {
      if (out.headers) res.set(out.headers);
      res.status(out.status).json(out.body);
      return;
    }
    const device = await asTargetTenant(req, tenantId, () => deviceService.getDeviceById(id, tenantId));
    if (!device) throw new AppError(404, 'Device not found');
    deviceService.emitChanged(tenantId, [id], hasGlobalView(req) && tenantId !== req.tenantId ? req.tenantId! : null);
    // The name of the device is a variable of the policies ({{device.name}}): what is rendered with it follows.
    // The name and the custom fields are variables of the policies (custom fields: the bridge agent's templates, lot PONT-POL).
  if (patch.displayName !== undefined || patch.customFields !== undefined) await asTargetTenant(req, tenantId, () => requestDeviceResolution(null, tenantId, [id]));
    // The dynamic groups: the name, the tags, the custom fields and the asset statuses the base marked (P0-5 T5).
    await asTargetTenant(req, tenantId, () => requestGroupEvaluation(null, tenantId, [id]));
    // Filed in the device's tenant (from the global view: the client's log, rls-tenant EX-08): the fields
    // changed, never their values.
    await asTargetTenant(req, tenantId, async () => audit.append({
      tenantId, action: 'device.updated', target: { type: 'device', id: String(id), device: id },
      details: { fields: Object.keys(patch).slice(0, 20) },
    }, await audit.fromRequest(req, tenantId)));
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/mdm/devices/:id/group[?dryRun=true] — { groupId }: a group of the DEVICE's tenant the caller can write
// (from the global view too: written in the device's tenant, asTargetTenant); another tenant's group answers like an
// unknown one (404). Previewed and guarded like the batch (S12): a step-up when the configuration of the device
// changes, a second approver beyond the thresholds (202).
router.post('/devices/:id/group', requireTenantCapability('devices.manage'), resolveDevice(true), async (req, res, next) => {
  try {
    const { groupId } = body(GroupBody, req);
    const { id, tenantId } = req.mdmDevice!;
    const out = await asTargetTenant(req, tenantId, async () => {
      if (groupId !== null && !(await db('device_groups').where({ id: groupId, tenant_id: tenantId }).first('id'))) {
        throw new AppError(404, 'Group not found');
      }
      await requireGroupWriteOn(req, groupId);
      return changeDevicesGroup(req, tenantId, [id], groupId, isDryRun(req));
    });
    if (out.headers) res.set(out.headers);
    const data = (out.body as { data?: { outcome?: string; changed?: number; changedIds?: number[] } }).data;
    if (out.status !== 200 || !data || data.outcome === 'preview') { res.status(out.status).json(out.body); return; }
    const changed = (data.changedIds ?? []).length > 0;
    if (changed) deviceService.emitChanged(tenantId, [id], tenantId !== req.tenantId ? req.tenantId! : null);
    res.json({ data: { changed } });
  } catch (err) { next(err); }
});

// POST /api/mdm/devices/:id/end-user — { endUserId | null }: an end user of the device's tenant.
router.post('/devices/:id/end-user', requireTenantCapability('devices.manage'), resolveDevice(true), async (req, res, next) => {
  try {
    const { endUserId } = body(EndUserBody, req);
    const { id, tenantId } = req.mdmDevice!;
    if (tenantId !== req.tenantId) throw new AppError(404, 'Device not found');
    const ok = await db.transaction((trx) => assignEndUser(trx, tenantId, id, endUserId));
    if (!ok) throw new AppError(404, 'End user not found');
    await audit.append({
      tenantId, action: 'device.end_user_assigned', target: { type: 'device', id: String(id), device: id },
      details: { endUserId },
    }, await audit.fromRequest(req, tenantId));
    deviceService.emitChanged(tenantId, [id]);
    res.json({ data: { endUserId } });
  } catch (err) { next(err); }
});

// POST /api/mdm/devices/:id/ownership — { to, reason, ticket }: between corporate and corporate_personal,
// under the restriction device.change_ownership ('restricted' by default: a second approver).
router.post('/devices/:id/ownership', requireTenantCapability('devices.manage'), resolveDevice(true), async (req, res, next) => {
  try {
    const b = body(OwnershipBody, req);
    const { id, tenantId } = req.mdmDevice!;
    if (tenantId !== req.tenantId) throw new AppError(404, 'Device not found');
    const d = await db('devices').where({ tenant_id: tenantId, id }).first('ownership', 'management_mode', 'enrollment_state') as
      { ownership: string; management_mode: string; enrollment_state: string };
    const allowed = ['corporate', 'corporate_personal'].includes(d.ownership) && d.ownership !== b.to
      && d.management_mode === 'device' && d.enrollment_state !== 'unenrolled';
    if (!allowed) {
      throw new AppError(409, 'The ownership changes between corporate and corporate_personal only, on a managed device in device mode; any other change is a new enrollment',
        'ownershipChangeNotAllowed', { from: d.ownership, to: b.to });
    }
    if (d.ownership === 'corporate_personal' && b.to === 'corporate' && !b.ticket) {
      throw new AppError(400, 'A ticket is required to widen the collection of a device', 'invalidRequest', { field: 'ticket' });
    }
    const { applyRestriction } = await import('../../services/restriction.service');
    const describe = await import('../../services/approvalDescribe');
    const approved = await applyRestriction(res, {
      req, actionKey: 'device.change_ownership', deviceIds: [id], approvalRequestType: 'batch_command',
      approvalDescription: `Change the ownership to ${b.to} — ${await describe.deviceList(tenantId, [id])}`,
      approvalPayload: { action: 'change_ownership', deviceIds: [id], params: { to: b.to, reason: b.reason, ticket: b.ticket ?? null } },
    });
    if (!approved) return;
    const ctx = await audit.fromRequest(req, tenantId);
    const r = await db.transaction((trx) => changeOwnership(trx, tenantId, id, b.to, ctx, b.reason, b.ticket ?? null));
    deviceService.emitChanged(tenantId, [id]);
    res.json({ data: r });
  } catch (err) { next(err); }
});

// DELETE /api/mdm/devices/:id — { reason, ticket?, confirm }: guarded action device.delete on one record.
router.delete('/devices/:id', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseRequestDeviceId(req.params.id);
    if (id === null) throw new AppError(404, 'Device not found');
    await guardedDeletion(req, res, next, [id], (req.body ?? {}) as Record<string, unknown>);
  } catch (err) { next(err); }
});

// GET /api/mdm/devices/:id/enrollments — the enrollment episodes.
router.get('/devices/:id/enrollments', globalViewScope('console.devices'), resolveDevice(false), async (req, res, next) => {
  try {
    res.json({ data: await listEpisodes(req.mdmDevice!.tenantId, req.mdmDevice!.id) });
  } catch (err) { next(err); }
});

const LocationsQuery = z.object({
  limit: z.preprocess((v) => (v === undefined || v === '' ? undefined : Number(v)), z.number().int().min(1).max(50).optional()),
}).passthrough();

// GET /api/mdm/devices/:id/locations?limit=20 — the last lost-mode positions (SEC-05: "only during the lost mode"):
// only while the lost mode is on (or changing) on a device under management, never for a personal device (the table
// is not even read), never when the tenant's privacy profile of the device's ownership refuses the location (P0-13,
// CNF-02: the table is not read either), and only for whoever may use the lost mode on the device (mdm:lost_mode,
// write scope); otherwise an empty answer that says why. A read is journaled in the device's tenant (audit-durci §3.4, P2): the critical
// intent before the read — no coordinate leaves when it cannot be written (503 auditUnavailable) — then the count.
router.get('/devices/:id/locations', globalViewScope('console.devices'), resolveDevice(false), async (req, res, next) => {
  try {
    const parsed = LocationsQuery.safeParse(req.query);
    if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid query', 'invalidRequest');
    const limit = parsed.data.limit ?? 20;
    const { id, tenantId } = req.mdmDevice!;
    // The tenant's retention of the positions (P0-13 T4, CNF-04): shown, and a position received or observed longer ago
    // than the value in force is due (the purge removes it at its next run: never shown meanwhile); one kept longer by
    // an increase shows at once (its purge_at follows at the next run: realignLostModePurgeDates).
    const keptDays = await retentionDays(db, tenantId, 'lost_mode_location_days');
    const empty = (unavailable: NonNullable<DeviceLocations['unavailable']>): DeviceLocations =>
      ({ available: false, unavailable, points: [], retentionDays: keptDays });
    res.setHeader('Cache-Control', 'no-store');
    const d = await db('devices').where({ tenant_id: tenantId, id }).first('ownership', 'enrollment_state', 'lost_mode_state') as
      { ownership: string; enrollment_state: string; lost_mode_state: string } | undefined;
    if (!d) throw new AppError(404, 'Device not found');
    if (d.ownership === 'personal') { res.json({ data: empty('personal') }); return; }
    if (d.enrollment_state === 'unenrolled') { res.json({ data: empty('unenrolled') }); return; }
    if (!(await lostModeLocationAllowed(db, tenantId, d.ownership))) { res.json({ data: empty('locationDisabledByPrivacy') }); return; }
    if (d.lost_mode_state === 'off') { res.json({ data: empty('lostModeOff') }); return; }
    const isAdmin = req.session.role === 'admin';
    const userId = req.session.userId!;
    const allowed = isAdmin || ((await permissionService.canWriteDevice(userId, id, false))
      && (await permissionService.canUseCapability(userId, id, false, 'mdm:lost_mode')));
    if (!allowed) { res.json({ data: empty('capabilityMissing') }); return; }
    const num = (v: unknown): number | null => (v === null || v === undefined || !Number.isFinite(Number(v)) ? null : Number(v));
    const read = async (): Promise<DeviceLocationPoint[]> => {
      const cutoff = new Date(Date.now() - keptDays * 86_400_000);
      const rows = await db('lost_mode_locations').where({ tenant_id: tenantId, device_id: id }).where('received_at', '>', cutoff)
        .where('observed_at', '>', cutoff)
        .orderBy('observed_at', 'desc').orderBy('id', 'desc').limit(limit)
        .select('latitude', 'longitude', 'horizontal_accuracy', 'altitude', 'speed', 'course', 'observed_at', 'command_id') as
        Array<Record<string, unknown>>;
      return rows.map((r) => ({
        latitude: Number(r.latitude), longitude: Number(r.longitude),
        horizontalAccuracy: num(r.horizontal_accuracy), altitude: num(r.altitude), speed: num(r.speed), course: num(r.course),
        observedAt: (r.observed_at instanceof Date ? r.observed_at : new Date(String(r.observed_at))).toISOString(),
        source: r.command_id ? 'apple_command' : 'android_lost_mode',
      }));
    };
    // Filed in the device's tenant (from the global view: the client's log); the result carries the count only.
    const points = await asTargetTenant(req, tenantId, async () => audit.withIntent({
      tenantId, action: 'lost_mode.location_viewed', target: { type: 'device', id: String(id), device: id },
    }, await audit.fromRequest(req, tenantId), read, { resultDetails: (p) => ({ count: p.length }) }));
    res.json({ data: { available: true, unavailable: null, points, retentionDays: keptDays } satisfies DeviceLocations });
  } catch (err) { next(err); }
});

// GET /api/mdm/devices/:id/apps, /profiles, /certificates — the inventory.
router.get('/devices/:id/apps', globalViewScope('console.devices'), resolveDevice(false), async (req, res, next) => {
  try {
    const { apps, collectedAt } = await deviceApps(req.mdmDevice!.tenantId, req.mdmDevice!.id);
    res.json({ data: apps, meta: { collectedAt } satisfies DeviceAppsMeta });
  } catch (err) { next(err); }
});
// GET /api/mdm/devices/:id/app-icons/:sha256 — the icon a device of the tenant sent for an app of THIS device (a
// canonical PNG re-encoded by the server, mdm/inventory/pngIcon.ts): image/png whatever the bytes, nosniff, a
// sandboxed CSP, immutable by its hash. No extension in the URL (the static regex of the nginx of the client must
// not take it). Anything else, a malformed hash included: 404.
router.get('/devices/:id/app-icons/:sha256', globalViewScope('console.devices'), resolveDevice(false), async (req, res, next) => {
  try {
    const sha = String(req.params.sha256 ?? '');
    const bytes = /^[0-9a-f]{64}$/.test(sha) ? await deviceAppIcon(req.mdmDevice!.tenantId, req.mdmDevice!.id, sha) : null;
    if (!bytes) throw new AppError(404, 'Icon not found');
    const etag = `"${sha}"`;
    res.setHeader('ETag', etag);
    res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    const match = String(req.headers['if-none-match'] ?? '').split(',').map((s) => s.trim().replace(/^W\//, ''));
    if (match.includes(etag)) { res.status(304).end(); return; }
    res.status(200);
    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Content-Length', String(bytes.length));
    res.end(bytes);
  } catch (err) { next(err); }
});
router.get('/devices/:id/profiles', globalViewScope('console.devices'), resolveDevice(false), async (req, res, next) => {
  try { res.json({ data: await deviceProfiles(req.mdmDevice!.tenantId, req.mdmDevice!.id) }); } catch (err) { next(err); }
});
router.get('/devices/:id/certificates', globalViewScope('console.devices'), resolveDevice(false), async (req, res, next) => {
  try { res.json({ data: await deviceCertificates(req.mdmDevice!.tenantId, req.mdmDevice!.id) }); } catch (err) { next(err); }
});

// GET /api/mdm/devices/:id/configuration — the effective configuration: keys, values (never a secret), provenance,
// availability with its reason, conflicts; the artifacts and their state (modele §10.6, criterion 9).
router.get('/devices/:id/configuration', globalViewScope('console.devices'), resolveDevice(false), async (req, res, next) => {
  try {
    const { id, tenantId } = req.mdmDevice!;
    res.json({ data: await asTargetTenant(req, tenantId, () => deviceConfiguration(tenantId, id)) });
  } catch (err) { next(err); }
});

/**
 * device.delete through the guard engine (audit-durci §10.2): 202 GuardOutcome, or the engine's refusal.
 * The session's tenant only, for everyone (a list with an id of another tenant, or unknown, answers 404 and
 * nothing is done); a record still under management is never deleted (409 deviceUnderManagement: it leaves
 * management first, ENR-17).
 */
async function guardedDeletion(req: Request, res: Response, next: NextFunction, rawIds: unknown[],
  b: { reason?: unknown; ticket?: unknown; confirm?: unknown }): Promise<void> {
  const parsed = rawIds.map(parseRequestDeviceId);
  const ids = [...new Set(parsed.filter((n): n is number => n !== null))];
  if (parsed.some((n) => n === null) || ids.length === 0) throw new AppError(404, 'No matching devices in this tenant');
  const rows = await db('devices').whereIn('id', ids).andWhere({ tenant_id: req.tenantId! }).select('id', 'enrollment_state') as
    Array<{ id: number; enrollment_state: string }>;
  if (rows.length !== ids.length) throw new AppError(404, 'No matching devices in this tenant');
  const managed = rows.filter((r) => r.enrollment_state !== 'unenrolled').map((r) => Number(r.id));
  if (managed.length) {
    throw new AppError(409, 'A device under management leaves management before its record is deleted', 'deviceUnderManagement',
      { deviceIds: managed.slice(0, 50) });
  }
  const { guard, GuardStepUpError } = await import('../../guard');
  try {
    const outcome = await guard.request(req, {
      actionKey: 'device.delete',
      selection: { deviceIds: ids },
      reason: typeof b.reason === 'string' ? b.reason : '',
      ticket: typeof b.ticket === 'string' ? b.ticket : undefined,
      confirm: typeof b.confirm === 'string' ? b.confirm : undefined,
    });
    res.status(202).json({ data: outcome });
  } catch (err) {
    if (err instanceof GuardStepUpError) {
      const { sendStepUpFailure } = await import('../../services/deviceKey/stepUpProof');
      sendStepUpFailure(res, err.outcome);
      return;
    }
    next(err);
  }
}

// ── Export (INV-04, RPT-01): CSV, XLSX, PDF of the collected columns ─────────

/** A CSV cell that starts like a formula (=, +, -, @, tab, carriage return) is prefixed by an apostrophe: a
 *  spreadsheet then shows the text instead of evaluating it. */
export function csvText(v: string): string {
  return /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
}

async function sendExport(res: Response, fmt: 'csv' | 'xlsx' | 'pdf', devices: DeviceSummary[]): Promise<void> {
  const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
  const baseName = `obligarth-devices-${ts}`;
  const withSerial = devices.some((d) => d.serialNumber !== undefined);
  const columns: Array<{ header: string; key: string; width: number; pdf?: boolean }> = [
    { header: 'Name', key: 'label', width: 26 },
    { header: 'Platform', key: 'platform', width: 10 },
    { header: 'OS Version', key: 'osVersion', width: 12 },
    { header: 'Model', key: 'model', width: 20 },
    { header: 'Ownership', key: 'ownership', width: 18 },
    { header: 'Enrollment', key: 'enrollmentState', width: 16 },
    { header: 'Contact', key: 'contactState', width: 10 },
    { header: 'Compliance', key: 'complianceState', width: 14 },
    { header: 'Configuration', key: 'configState', width: 14, pdf: false },
    { header: 'Group', key: 'groupName', width: 20 },
    { header: 'End user', key: 'endUser', width: 22 },
    ...(withSerial ? [{ header: 'Serial Number', key: 'serialNumber', width: 16 }] : []),
    { header: 'Tags', key: 'tags', width: 20, pdf: false },
    { header: 'Enrolled', key: 'enrolledAt', width: 22, pdf: false },
    { header: 'Last contact', key: 'lastCheckinAt', width: 22 },
    { header: 'Warranty expiry', key: 'warrantyExpiry', width: 14, pdf: false },
    { header: 'UUID', key: 'uuid', width: 38, pdf: false },
  ];
  const rows = devices.map((d) => ({
    label: d.label, platform: d.platform, osVersion: d.osVersion ?? '', model: d.modelName ?? d.model ?? '',
    ownership: d.ownership, enrollmentState: d.enrollmentState, contactState: d.contactState,
    complianceState: d.complianceState, configState: d.configState, groupName: d.groupName ?? '',
    endUser: d.endUser?.displayName ?? d.endUser?.email ?? '', serialNumber: d.serialNumber ?? '',
    tags: d.tags.join(', '), enrolledAt: d.enrolledAt ?? '', lastCheckinAt: d.lastCheckinAt ?? '', warrantyExpiry: d.warrantyExpiry ?? '', uuid: d.uuid,
  }));
  const ExcelJS = (await import('exceljs')).default;
  if (fmt === 'csv' || fmt === 'xlsx') {
    const wb = new ExcelJS.Workbook();
    wb.creator = 'Obligarth';
    const ws = wb.addWorksheet('Devices');
    ws.columns = columns;
    // CSV: a text a spreadsheet would read as a formula is neutralised (MDM-B2-R10). The label, the model, the
    // tags and the name of the end user come from the device or from an import; an XLSX cell written as a string
    // is never evaluated.
    rows.forEach((r) => ws.addRow(fmt === 'csv'
      ? Object.fromEntries(Object.entries(r).map(([k, v]) => [k, typeof v === 'string' ? csvText(v) : v]))
      : r));
    if (fmt === 'csv') {
      const buffer = await wb.csv.writeBuffer();
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${baseName}.csv"`);
      res.send(Buffer.from(buffer as ArrayBuffer));
      return;
    }
    ws.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
    ws.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F2937' } };
    ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
    const buffer = await wb.xlsx.writeBuffer();
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${baseName}.xlsx"`);
    res.send(Buffer.from(buffer as ArrayBuffer));
    return;
  }
  const pdfColumns = columns.filter((c) => c.pdf !== false);
  const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Devices</title><style>
body { font-family: -apple-system, Segoe UI, sans-serif; font-size: 9px; color: #111; margin: 20px; }
h1 { font-size: 14px; margin: 0 0 12px; } .meta { font-size: 8px; color: #666; margin-bottom: 12px; }
table { width: 100%; border-collapse: collapse; } th, td { border: 1px solid #ddd; padding: 4px 6px; text-align: left; vertical-align: top; }
th { background: #1f2937; color: white; font-weight: 600; } tr:nth-child(even) td { background: #f9fafb; }
</style></head><body><h1>Obligarth — Devices export</h1>
<div class="meta">${devices.length} devices · generated ${new Date().toISOString()}</div>
<table><thead><tr>${pdfColumns.map((c) => `<th>${esc(c.header)}</th>`).join('')}</tr></thead><tbody>
${rows.map((r) => `<tr>${pdfColumns.map((c) => `<td>${esc(String((r as Record<string, unknown>)[c.key] ?? ''))}</td>`).join('')}</tr>`).join('')}
</tbody></table></body></html>`;
  const browser = await launchChromium();
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'domcontentloaded' });
    const pdf = await page.pdf({ format: 'A4', landscape: true, margin: { top: '15mm', bottom: '15mm', left: '10mm', right: '10mm' }, printBackground: true });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${baseName}.pdf"`);
    res.send(pdf);
  } finally {
    await browser.close();
  }
}

export default router;
