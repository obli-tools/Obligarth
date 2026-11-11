import { Router, type NextFunction, type Request, type Response } from 'express';
import { db } from '../../db';
import { audit } from '../../audit';
import { requireTenantCapability } from '../../middleware/rbac';
import { archiveApp, createApp, getApp, listApps, parseAppId, patchApp } from '../apps/appCatalogService';
import { emitPolicyChanged } from '../policies/publish';

// =============================================================================
// Console API of the catalog of apps (docs: modele-donnees-mdm §8, §10.6; lot
// C4), mounted at /api/mdm in the tenant of the session. Reads: any member;
// writes: mdm.apps.manage. The assignments of an app go through
// POST /api/mdm/assignments/changes (resourceType 'app', with its options),
// the impact preview and the restriction mdm.policy_publish, like a policy's.
//   GET  /apps?archived=1&q=     the catalog (licences of every live token)
//   POST /apps                   from a licence of the tenant, or by App Store id
//   GET  /apps/:id               the page: installs (counts), delivery by state
//   PATCH /apps/:id              name, publisher, icon, platforms (none withdrawn while assignments remain), minimum OS
//   POST /apps/:id/archive       refused while assignments remain
// =============================================================================

const router = Router();
const manage = requireTenantCapability('mdm.apps.manage');

type Handler = (req: Request, res: Response) => Promise<void>;
function h(fn: Handler) {
  return (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };
}

router.get('/apps', h(async (req, res) => {
  res.json({ data: await listApps(db, req.tenantId!, { archived: req.query.archived === '1', q: typeof req.query.q === 'string' ? req.query.q : undefined }) });
}));

router.post('/apps', manage, h(async (req, res) => {
  const tenantId = req.tenantId!;
  const ctx = await audit.fromRequest(req, tenantId);
  const entry = await db.transaction((trx) => createApp(trx, tenantId, req.session.userId ?? null, req.body));
  await audit.append({
    tenantId, action: 'app.created', target: { type: 'app', id: String(entry.id) }, details: { kind: entry.kind, storeId: entry.storeId },
  }, ctx);
  res.status(201).json({ data: entry });
}));

router.get('/apps/:id', h(async (req, res) => {
  res.json({ data: await getApp(db, req.tenantId!, parseAppId(req.params.id)) });
}));

router.patch('/apps/:id', manage, h(async (req, res) => {
  const tenantId = req.tenantId!;
  const id = parseAppId(req.params.id);
  const { requestTenantResolution } = await import('../policies/triggers');
  const { entry, fields } = await db.transaction(async (trx) => {
    const out = await patchApp(trx, tenantId, id, req.body);
    // The platforms change the availability of the app on the devices it is assigned to (a platform withdrawn is
    // refused while assignments remain): resolved again, requested with the change itself.
    if (out.fields.includes('supported_platforms')) await requestTenantResolution(trx, tenantId);
    return out;
  });
  if (fields.length) {
    await audit.append({ tenantId, action: 'app.updated', target: { type: 'app', id: String(id) }, details: { fields } }, await audit.fromRequest(req, tenantId));
    if (fields.includes('supported_platforms')) emitPolicyChanged(tenantId, []);
  }
  res.json({ data: entry });
}));

router.post('/apps/:id/archive', manage, h(async (req, res) => {
  const tenantId = req.tenantId!;
  const id = parseAppId(req.params.id);
  const entry = await db.transaction((trx) => archiveApp(trx, tenantId, id));
  await audit.append({ tenantId, action: 'app.archived', target: { type: 'app', id: String(id) }, details: {} }, await audit.fromRequest(req, tenantId));
  res.json({ data: entry });
}));

export default router;
