import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import {
  COMPLIANCE_STATES, CONFIG_STATES, ENROLLMENT_STATES, OWNERSHIPS, PLATFORMS, type DeviceSummary,
} from '@obligarth/shared';
import { db } from '../../db';
import { audit } from '../../audit';
import { asTargetTenant, globalViewRead, globalViewScope } from '../../middleware/dbContext';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { deviceService, type DeviceListFilters } from '../../services/device.service';
import { hasGlobalView, parseRequestDeviceId, resolveRequestDevice } from '../../services/deviceScope.service';
import { permissionService } from '../../services/permission.service';
import { launchChromium } from '../../utils/chromium';
import { listEpisodes } from '../registry/episodes';
import { assignEndUser } from '../registry/endUsers';
import { changeOwnership, moveToGroup } from '../registry/ownership';
import { deviceApps, deviceCertificates, deviceProfiles } from '../inventory/views';
import { deviceConfiguration } from '../policies/configuration';
import { requestDeviceResolution } from '../policies/triggers';

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

// ── Query and body schemas ─────────────────────────────────────────────────

/** A list in the query: repeated parameter or comma-separated. */
const listOf = <T extends string>(values: readonly T[]) => z.preprocess((v) => {
  if (v === undefined || v === '') return undefined;
  const arr = Array.isArray(v) ? v : String(v).split(',');
  return arr.map((s) => String(s).trim()).filter(Boolean);
}, z.array(z.enum(values as unknown as [T, ...T[]])).max(20).optional());
const intOpt = z.preprocess((v) => (v === undefined || v === '' ? undefined : Number(v)), z.number().int().positive().optional());
const boolOpt = z.preprocess((v) => (v === undefined || v === '' ? undefined : v === true || v === 'true'), z.boolean().optional());

const ListQuery = z.object({
  platform: listOf(PLATFORMS),
  ownership: listOf(OWNERSHIPS),
  enrollmentState: listOf(ENROLLMENT_STATES),
  contact: listOf(['never', 'recent', 'quiet', 'stale'] as const),
  compliance: listOf(COMPLIANCE_STATES),
  config: listOf(CONFIG_STATES),
  osBelow: z.string().max(20).optional(),
  supervised: boolOpt,
  groupId: intOpt,
  includeSubgroups: boolOpt,
  ungrouped: boolOpt,
  tags: z.preprocess((v) => (v === undefined || v === '' ? undefined : (Array.isArray(v) ? v : String(v).split(',')).map((s) => String(s).trim()).filter(Boolean)),
    z.array(z.string().max(100)).max(20).optional()),
  endUserId: intOpt,
  q: z.string().max(200).optional(),
  tenantIds: z.preprocess((v) => (v === undefined || v === '' ? undefined : (Array.isArray(v) ? v : String(v).split(',')).map(Number)),
    z.array(z.number().int().positive()).max(200).optional()),
  sortBy: z.enum(['name', 'platform', 'os', 'lastCheckin', 'enrolledAt', 'group', 'state', 'compliance', 'ownership', 'model']).optional(),
  sortOrder: z.enum(['asc', 'desc']).optional(),
  page: intOpt,
  pageSize: intOpt,
  format: z.enum(['csv', 'xlsx', 'pdf']).optional(),
}).passthrough();

function parseList(req: Request): z.infer<typeof ListQuery> {
  const parsed = ListQuery.safeParse(req.query);
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid query', 'invalidRequest');
  return parsed.data;
}

/** The devices a non-administrator sees through their teams (undefined: every device, an administrator). */
async function visibleIdsOf(req: Request): Promise<number[] | 'all' | undefined> {
  if (req.session.role === 'admin') return undefined;
  return permissionService.getVisibleDeviceIds(req.session.userId!, false);
}

const PatchBody = z.object({
  displayName: z.string().max(500).nullable().optional(),
  description: z.string().max(10_000).nullable().optional(),
  tags: z.array(z.string().max(100)).max(50).optional(),
  customFields: z.record(z.string().max(100), z.string().max(1000)).optional(),
  purchaseDate: z.string().max(40).nullable().optional(),
  warrantyExpiry: z.string().max(40).nullable().optional(),
  warrantyVendor: z.string().max(200).nullable().optional(),
  warrantyStatus: z.enum(['active', 'expired', 'unknown']).nullable().optional(),
  expectedLifetimeYears: z.number().int().min(0).max(100).nullable().optional(),
  lifecycleStatus: z.enum(['active', 'aging', 'end_of_life', 'retired', 'unknown']).nullable().optional(),
}).strict();

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
    const q = parseList(req);
    const filters: DeviceListFilters = { ...q, visibleIds: await visibleIdsOf(req) };
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
    const q = parseList(req);
    const fmt = q.format ?? 'csv';
    const devices = await deviceService.exportDevices(req.tenantId!, { ...q, visibleIds: await visibleIdsOf(req) }, { globalView: hasGlobalView(req) });
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

// POST /api/mdm/devices/batch/group — { deviceIds, groupId }: devices of the session's tenant only (an id of
// another tenant, or unknown: 404, nothing moved); write on the target group; restriction
// device.bulk_group_change beyond one device (second approver at 'restricted': approval change_group).
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
    if (ids.length > 1) {
      const { applyRestriction } = await import('../../services/restriction.service');
      const describe = await import('../../services/approvalDescribe');
      const approved = await applyRestriction(res, {
        req, actionKey: 'device.bulk_group_change', deviceIds: ids, approvalRequestType: 'batch_command',
        approvalDescription: `Move to ${await describe.groupLabel(req.tenantId!, b.groupId)} — ${await describe.deviceList(req.tenantId!, ids)}`,
        approvalPayload: { action: 'change_group', deviceIds: ids, params: { groupId: b.groupId } },
      });
      if (!approved) return;
    }
    const changed = await db.transaction((trx) => moveToGroup(trx, req.tenantId!, ids, b.groupId));
    await audit.append({
      tenantId: req.tenantId!, action: ids.length > 1 ? 'device.bulk_group_changed' : 'device.group_changed',
      target: ids.length > 1 ? { type: 'device', id: ids.join(',').slice(0, 200) } : { type: 'device', id: String(ids[0]), device: ids[0] },
      details: { count: ids.length, changed: changed.length, toGroupId: b.groupId },
    }, await audit.fromRequest(req, req.tenantId!));
    deviceService.emitChanged(req.tenantId!, changed);
    res.json({ data: { updated: ids.length, changed: changed.length } });
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

// PATCH /api/mdm/devices/:id — the operator's fields (name, description, tags, custom fields, asset).
router.patch('/devices/:id', resolveDevice(true), async (req, res, next) => {
  try {
    const patch = body(PatchBody, req);
    const { id, tenantId } = req.mdmDevice!;
    const view = { globalView: hasGlobalView(req) };
    const device = await asTargetTenant(req, tenantId, () => deviceService.updateDevice(id, req.tenantId!, patch, view));
    if (!device) throw new AppError(404, 'Device not found');
    // The name of the device is a variable of the policies ({{device.name}}): what is rendered with it follows.
    if (patch.displayName !== undefined) await asTargetTenant(req, tenantId, () => requestDeviceResolution(null, tenantId, [id]));
    // Filed in the device's tenant (from the global view: the client's log, rls-tenant EX-08): the fields
    // changed, never their values.
    await asTargetTenant(req, tenantId, async () => audit.append({
      tenantId, action: 'device.updated', target: { type: 'device', id: String(id), device: id },
      details: { fields: Object.keys(patch).slice(0, 20) },
    }, await audit.fromRequest(req, tenantId)));
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/mdm/devices/:id/group — { groupId }: a group of the DEVICE's tenant the caller can write (from
// the global view too: written in the device's tenant, asTargetTenant); another tenant's group answers like an
// unknown one (404).
router.post('/devices/:id/group', requireTenantCapability('devices.manage'), resolveDevice(true), async (req, res, next) => {
  try {
    const { groupId } = body(GroupBody, req);
    const { id, tenantId } = req.mdmDevice!;
    const changed = await asTargetTenant(req, tenantId, async () => {
      if (groupId !== null && !(await db('device_groups').where({ id: groupId, tenant_id: tenantId }).first('id'))) {
        throw new AppError(404, 'Group not found');
      }
      await requireGroupWriteOn(req, groupId);
      const moved = await db.transaction((trx) => moveToGroup(trx, tenantId, [id], groupId));
      if (moved.length) {
        await audit.append({
          tenantId, action: 'device.group_changed', target: { type: 'device', id: String(id), device: id },
          details: { toGroupId: groupId },
        }, await audit.fromRequest(req, tenantId));
      }
      return moved;
    });
    if (changed.length) deviceService.emitChanged(tenantId, [id], tenantId !== req.tenantId ? req.tenantId! : null);
    res.json({ data: { changed: changed.length > 0 } });
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

// GET /api/mdm/devices/:id/apps, /profiles, /certificates — the inventory.
router.get('/devices/:id/apps', globalViewScope('console.devices'), resolveDevice(false), async (req, res, next) => {
  try { res.json({ data: await deviceApps(req.mdmDevice!.tenantId, req.mdmDevice!.id) }); } catch (err) { next(err); }
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
    { header: 'UUID', key: 'uuid', width: 38, pdf: false },
  ];
  const rows = devices.map((d) => ({
    label: d.label, platform: d.platform, osVersion: d.osVersion ?? '', model: d.modelName ?? d.model ?? '',
    ownership: d.ownership, enrollmentState: d.enrollmentState, contactState: d.contactState,
    complianceState: d.complianceState, configState: d.configState, groupName: d.groupName ?? '',
    endUser: d.endUser?.displayName ?? d.endUser?.email ?? '', serialNumber: d.serialNumber ?? '',
    tags: d.tags.join(', '), enrolledAt: d.enrolledAt ?? '', lastCheckinAt: d.lastCheckinAt ?? '', uuid: d.uuid,
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
