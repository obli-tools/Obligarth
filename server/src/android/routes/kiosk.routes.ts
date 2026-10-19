// /api/android (tenant router: requireAuth, requireTenant), kiosks of dedicated devices (section 9.7, lot AN-G1):
//   GET    /devices/:id/kiosk        the kiosk state of a device (dedicated, running exit, lock pending: review AN-G1)
//   DELETE /devices/:id/kiosk-exit   ends the running kiosk exit of a device now (the lock is pushed back), audited
// The exit itself is the guarded action mdm.android_kiosk_exit, requested by POST /api/guard/actions (restriction
// matrix, step-up and approvals of the guard engine), never by a route of this module. Capability devices.manage on
// each route. Mounted under /api/android by routes/index.ts (lot AN-A2).
import { Router, type NextFunction, type Request, type Response } from 'express';
import { audit } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { endKioskExit, KioskExitError, readKioskState } from '../kiosk/exits';
import { toRouteError } from './enterprise.routes';
import { androidDeviceOf } from './deviceAccess';

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

export function createAndroidKioskRouter(): Router {
  const router = Router();
  const capability = requireTenantCapability('devices.manage');

  // A device the caller sees in the tenant (team scopes), else 404; ending an exit takes mdm:lock on it, the capability
  // of the exit itself (review AN-A2).
  router.get('/devices/:id/kiosk', capability, wrap(async (req, res) => {
    const deviceId = await androidDeviceOf(req, req.params.id);
    const state = await readKioskState(Number(req.tenantId), Number(req.session.userId), deviceId);
    if (!state) throw new AppError(404, 'Not found', 'notFound');
    res.json({ success: true, data: state });
  }));

  router.delete('/devices/:id/kiosk-exit', capability, wrap(async (req, res) => {
    const deviceId = await androidDeviceOf(req, req.params.id, 'mdm:lock');
    const tenantId = Number(req.tenantId);
    try {
      const r = await endKioskExit(tenantId, Number(req.session.userId), deviceId, await audit.fromRequest(req, tenantId));
      res.json({ success: true, data: { result: r } });
    } catch (err) {
      if (err instanceof KioskExitError) throw new AppError(err.status, err.message, err.code);
      throw toRouteError(err);
    }
  }));
  return router;
}
