// /api/admin/android (tenant router; master tenant only, platform administrators):
//   POST /google-credentials   deposit of the service account key (vault_key mode): strict step-up, escrow guard,
//                              checks before any write; answers the fingerprint and the account, never the key
//   GET  /health               health of the link (section 5.6)
// Mounted under /api/admin/android by routes/index.ts (lot AN-A2).
import { Router, type NextFunction, type Request, type Response } from 'express';
import { isMasterTenant, MASTER_TENANT_ID } from '@obligarth/shared';
import { audit } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import { checkSecondFactor, sendStepUpFailure } from '../../services/deviceKey/stepUpProof';
import { vault } from '../../vault';
import { AndroidCredentialError } from '../google/credentials';
import { androidHealth } from '../health';
import { depositServiceAccountKey } from '../identity';
import { toRouteError } from './enterprise.routes';

export function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!isMasterTenant(req.tenantId)) { next(new AppError(404, 'Not found')); return; }
  if (req.session?.role !== 'admin') { next(new AppError(403, 'Insufficient permissions')); return; }
  next();
}

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

export function createAndroidAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  router.get('/health', wrap(async (_req, res) => {
    res.json({ success: true, data: await androidHealth() });
  }));

  router.post('/google-credentials', wrap(async (req, res) => {
    const key = (req.body as { key?: unknown })?.key;
    if (typeof key !== 'string' || key.length > 16 * 1024) throw new AppError(400, 'key: the JSON key of the service account, as text', 'invalidInput');
    const step = await checkSecondFactor(req, { actionKey: 'android.google_credentials', allowTrustedIp: false, allowDevice: true });
    if (!step.ok) { sendStepUpFailure(res, step); return; }
    await vault.requireEscrow();
    try {
      const r = await depositServiceAccountKey(key, Number(req.session.userId), await audit.fromRequest(req, MASTER_TENANT_ID));
      res.status(201).json({ success: true, data: r });
    } catch (err) {
      if (err instanceof AndroidCredentialError) throw new AppError(422, err.message, `androidCredential_${err.code}`);
      throw toRouteError(err);
    }
  }));
  return router;
}
