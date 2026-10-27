import { Router, type Request } from 'express';
import type { z } from 'zod';
import type { DeviceView } from '@obligarth/shared';
import { db } from '../../db';
import { audit } from '../../audit';
import { parseError } from '../../services/deviceListFilters';
import {
  DeviceViewCreateBody, DeviceViewDefaultBody, DeviceViewPatchBody, deviceViewNotFound, deviceViewService, parseViewRef,
  type DeviceViewRef, type ViewCaller,
} from '../views/deviceViewService';

// =============================================================================
// Saved views of the device list (P0-5 T2, §4.1, D6): mounted at /api/mdm/device-views, in the tenant of the session.
// Membership of the tenant only (no capability): a view narrows what the list already shows the caller, never more
// (the list keeps its team scopes). A view of another user that is not shared, of another tenant, or unknown, answers
// 404 alike (deviceViewNotFound); a shared view the caller may not change, 403. Audit: nothing for a private view (D6); for a shared view
// (shared at its creation, shared or unshared by the change, or deleted while shared), device_view.shared_created,
// device_view.shared_updated and device_view.shared_deleted (standard): identifiers and names of the fields only.
// =============================================================================

const router = Router();

function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.infer<S> {
  const parsed = schema.safeParse(value ?? {});
  if (!parsed.success) throw parseError(parsed.error);
  return parsed.data;
}

const refOf = (req: Request): DeviceViewRef => {
  const ref = parseViewRef(req.params.id);
  if (!ref) throw deviceViewNotFound();
  return ref;
};

/** Is the caller an administrator of the tenant (platform administrator, or tenant role admin)? */
async function isTenantAdmin(req: Request): Promise<boolean> {
  if (req.session.role === 'admin') return true;
  const ut = await db('user_tenants').where({ user_id: req.session.userId, tenant_id: req.tenantId }).first('role') as { role: string } | undefined;
  return ut?.role === 'admin';
}

async function callerOf(req: Request): Promise<ViewCaller> {
  return { tenantId: req.tenantId!, userId: Number(req.session.userId), isAdmin: await isTenantAdmin(req) };
}

async function auditShared(req: Request, action: string, view: DeviceView, details: Record<string, unknown> = {}): Promise<void> {
  await audit.append({
    tenantId: req.tenantId!, action, target: { type: 'device_view', id: String(view.id) },
    details: { viewUuid: view.uuid, ...details },
  }, await audit.fromRequest(req, req.tenantId!));
}

// GET /api/mdm/device-views — the caller's views and the shared ones of the tenant.
router.get('/', async (req, res, next) => {
  try {
    res.json({ data: await deviceViewService.list(await callerOf(req)) });
  } catch (err) { next(err); }
});

// PUT /api/mdm/device-views/default — { viewId: id | uuid | null }: the caller's default view (one they see).
router.put('/default', async (req, res, next) => {
  try {
    const { viewId } = parse(DeviceViewDefaultBody, req.body);
    const ref = viewId === null ? null : parseViewRef(String(viewId));
    if (viewId !== null && !ref) throw deviceViewNotFound();
    const view = await deviceViewService.setDefault(await callerOf(req), ref);
    res.json({ data: { viewId: view?.id ?? null, viewUuid: view?.uuid ?? null } });
  } catch (err) { next(err); }
});

// GET /api/mdm/device-views/:id — one view (id or uuid).
router.get('/:id', async (req, res, next) => {
  try {
    const view = await deviceViewService.get(await callerOf(req), refOf(req));
    if (!view) throw deviceViewNotFound();
    res.json({ data: view });
  } catch (err) { next(err); }
});

// POST /api/mdm/device-views — { name, description?, shared?, definition }.
router.post('/', async (req, res, next) => {
  try {
    const b = parse(DeviceViewCreateBody, req.body);
    const view = await deviceViewService.create(await callerOf(req), b);
    if (view.shared) await auditShared(req, 'device_view.shared_created', view);
    res.status(201).json({ data: view });
  } catch (err) { next(err); }
});

// PATCH /api/mdm/device-views/:id — the fields to change (the owner; a tenant administrator for a shared view).
router.patch('/:id', async (req, res, next) => {
  try {
    const b = parse(DeviceViewPatchBody, req.body);
    const ref = refOf(req);
    const { before, after, fields } = await deviceViewService.update(await callerOf(req), ref, b);
    if (fields.length > 0 && (before.shared || after.shared)) {
      await auditShared(req, 'device_view.shared_updated', after, { fields, shared: after.shared });
    }
    res.json({ data: after });
  } catch (err) { next(err); }
});

// DELETE /api/mdm/device-views/:id
router.delete('/:id', async (req, res, next) => {
  try {
    const view = await deviceViewService.remove(await callerOf(req), refOf(req));
    if (view.shared) await auditShared(req, 'device_view.shared_deleted', view);
    res.json({ data: { deleted: true } });
  } catch (err) { next(err); }
});

export default router;
