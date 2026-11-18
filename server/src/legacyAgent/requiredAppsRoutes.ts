import { Router } from 'express';
import type { LegacyAgentRequiredAppPackageView } from '@obligarth/shared';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { requireTenantCapability } from '../middleware/rbac';
import { deviceRequiredApps, requiredAppsTenantState } from './requiredApps';
import { deviceOf, wrap } from './routes';

// =============================================================================
// Console API of the required apps of the bridge agent policies, mounted with
// the bridge agent's routes at /api/legacy-agent (createLegacyAgentRouter):
//   GET /policy/required-app-packages  the tenant's packages a policy author may
//                                      require (mdm.policies.manage: GET /packages
//                                      needs mdm.apps.manage), newest first
//   GET /policy/required-apps-tenant   what of the tenant sets every required
//                                      app aside (privacy profile managed_only,
//                                      restrictions matrix legacy_agent.apps):
//                                      any member, as the reads of a policy
//   GET /devices/:id/required-apps     the required apps of a device and their
//                                      state, computed as the job decides them
//                                      (the visibility of the device, as
//                                      /devices/:id/policy); 404 for a device
//                                      that is not a bridge device
// Reads only, in the request's database context.
// =============================================================================

const iso = (v: unknown): string => new Date(v as string | Date).toISOString();

export function requiredAppsRouter(): Router {
  const router = Router();

  router.get('/policy/required-app-packages', requireTenantCapability('mdm.policies.manage'), wrap(async (req, res) => {
    const rows = await db('legacy_agent_packages').where({ tenant_id: req.tenantId! }).orderBy('created_at', 'desc').orderBy('id').limit(1000)
      .select('id', 'package_name', 'version_code', 'version_name', 'label', 'size_bytes', 'created_at', 'confirmed_at') as Array<Record<string, any>>;
    const data: LegacyAgentRequiredAppPackageView[] = rows.map((r) => ({
      id: String(r.id).toLowerCase(), packageName: String(r.package_name), versionCode: String(r.version_code), versionName: r.version_name ?? null,
      label: r.label ?? null, sizeBytes: Number(r.size_bytes), createdAt: iso(r.created_at), confirmed: !!r.confirmed_at,
    }));
    res.json({ success: true, data });
  }));

  router.get('/policy/required-apps-tenant', wrap(async (req, res) => {
    res.json({ success: true, data: await requiredAppsTenantState(req.tenantId!) });
  }));

  router.get('/devices/:id/required-apps', wrap(async (req, res) => {
    const id = await deviceOf(req);
    const tenantId = req.tenantId!;
    const sat = await db('legacy_agent_devices').where({ tenant_id: tenantId, device_id: id }).first('device_id');
    if (!sat) throw new AppError(404, 'Device not found');
    res.json({ success: true, data: await deviceRequiredApps(tenantId, id, null) });
  }));

  return router;
}
