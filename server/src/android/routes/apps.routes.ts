// /api/android (tenant router: requireAuth, requireTenant), Android apps (sections 9.6, 12.3; lot AN-E1):
//   GET    /apps                     the Android apps of the tenant's catalog
//   GET    /apps/:id                 the page of an app (uuid): its managed configuration schema, its assignments (lot AN-E)
//   POST   /apps                     adds an app chosen in the iframe (package; kind checked against Google), audited
//   POST   /apps/:id/refresh         reads its metadata at Google again (5 minutes after the previous read at least)
//   POST   /apps/:id/options/check   checks the options of an assignment of the app (the editor; nothing stored)
//   DELETE /apps/:id                 archives it (refused while assigned), audited
//   POST   /web-tokens               a token for one iframe of the console (screen, page), audited, never stored
// The assignments themselves go through POST /api/mdm/assignments/changes (preview, step-up, approval): junction
// AN-A2/AN-P (apps/assignments.ts). Capability: mdm.apps.manage (AN41, §22.8). Mounted under /api/android by
// routes/index.ts (lot AN-A2) (the common catalog, POST /api/mdm/apps,
// calls the same functions for the family android). A web token is in the body of the answer only, no-store.
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { ANDROID_APP_KINDS } from '@obligarth/shared';
import { audit } from '../../audit';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { AndroidAppOptionsError, checkAndroidAppAssignment } from '../apps/assignments';
import { AndroidAppError, addAndroidApp, androidAppDetail, archiveAndroidApp, listAndroidApps, readAndroidApp, refreshAndroidAppMetadata } from '../apps/catalog';
import { createIframeToken } from '../apps/webTokens';
import { toRouteError } from './enterprise.routes';

const AddBody = z.object({
  packageName: z.string().min(3).max(255),
  kind: z.enum(ANDROID_APP_KINDS).optional(),
  languageCode: z.string().max(16).optional(),
}).strict();
const TokenBody = z.object({
  screen: z.string().max(32),
  parentPath: z.string().max(200),
  appId: z.string().uuid().optional(),
  locale: z.string().max(16).optional(),
}).strict();
const CheckBody = z.object({ options: z.unknown() }).strict();
const UUID = z.string().uuid();
const FORCED_REFRESH_MIN_AGE_MS = 5 * 60_000;

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function routeError(err: unknown): unknown {
  if (err instanceof AndroidAppOptionsError) return new AppError(err.status, err.message, err.code, { issues: err.issues.slice(0, 100) });
  if (err instanceof AndroidAppError) return new AppError(err.status, err.message, err.code);
  return toRouteError(err);
}

export function createAndroidAppsRouter(): Router {
  const router = Router();
  const capability = requireTenantCapability('mdm.apps.manage');

  router.get('/apps', capability, wrap(async (req, res) => {
    const tenantId = Number(req.tenantId);
    res.json({ success: true, data: await listAndroidApps(tenantId, { type: 'user', userId: Number(req.session.userId) }) });
  }));

  router.get('/apps/:id', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const tenantId = Number(req.tenantId);
    const r = await asTenant(tenantId, { type: 'user', userId: Number(req.session.userId) }, () => androidAppDetail(db, tenantId, id.data));
    if (!r) throw new AppError(404, 'Not found', 'notFound');
    res.json({ success: true, data: r });
  }));

  router.post('/apps', capability, wrap(async (req, res) => {
    const parsed = AddBody.safeParse(req.body);
    if (!parsed.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    const tenantId = Number(req.tenantId);
    try {
      const r = await addAndroidApp(tenantId, Number(req.session.userId), parsed.data, await audit.fromRequest(req, tenantId));
      res.status(r.created ? 201 : 200).json({ success: true, data: r });
    } catch (err) { throw routeError(err); }
  }));

  router.post('/apps/:id/refresh', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const tenantId = Number(req.tenantId);
    const actor = { type: 'user' as const, userId: Number(req.session.userId) };
    try {
      const row = await asTenant(tenantId, actor, () => readAndroidApp(db, tenantId, id.data));
      if (!row) throw new AndroidAppError(404, 'notFound', 'app not found');
      const r = await refreshAndroidAppMetadata(tenantId, Number(row.id), { force: true, minAgeMs: FORCED_REFRESH_MIN_AGE_MS, actor });
      res.json({ success: true, data: { result: r } });
    } catch (err) { throw routeError(err); }
  }));

  router.post('/apps/:id/options/check', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    const parsed = CheckBody.safeParse(req.body);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    if (!parsed.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    const tenantId = Number(req.tenantId);
    const actor = { type: 'user' as const, userId: Number(req.session.userId) };
    const r = await asTenant(tenantId, actor, async () => {
      const row = await readAndroidApp(db, tenantId, id.data);
      return row ? checkAndroidAppAssignment(db, tenantId, Number(row.id), parsed.data.options) : null;
    });
    if (!r) throw new AppError(404, 'Not found', 'notFound');
    // Paths and codes only: never a value of the options (a secret typed in) in the answer.
    res.json({ success: true, data: { issues: r.issues, warnings: r.warnings, secrets: r.secrets.map((s) => ({ path: s.path.join('.'), kind: s.kind })) } });
  }));

  router.delete('/apps/:id', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const tenantId = Number(req.tenantId);
    try {
      const r = await archiveAndroidApp(tenantId, Number(req.session.userId), id.data, await audit.fromRequest(req, tenantId));
      res.json({ success: true, data: { result: r } });
    } catch (err) { throw routeError(err); }
  }));

  router.post('/web-tokens', capability, wrap(async (req, res) => {
    const parsed = TokenBody.safeParse(req.body);
    if (!parsed.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    const tenantId = Number(req.tenantId);
    try {
      const t = await createIframeToken(tenantId, Number(req.session.userId), parsed.data, await audit.fromRequest(req, tenantId));
      res.setHeader('Cache-Control', 'no-store');
      res.status(201).json({ success: true, data: t });
    } catch (err) { throw routeError(err); }
  }));
  return router;
}
