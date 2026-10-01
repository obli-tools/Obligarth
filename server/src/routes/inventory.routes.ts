import { Router, Request, Response, NextFunction } from 'express';
import { inventoryService } from '../services/inventory.service';
import { resolveRequestDevice } from '../services/deviceScope.service';
import { AppError } from '../middleware/errorHandler';

const router = Router();

// All inventory routes require read access to the device, with the REST
// tenant rule (resolveRequestDevice): a device of the session's tenant (of
// any tenant for the master tenant's global view), seen through one of the
// caller's teams for a non-admin. A device out of reach answers like an
// unknown one (404) — a team scope left on a device that moved to another
// tenant opens nothing here.
router.param('deviceId', async (req: Request, _res: Response, next: NextFunction, val: string) => {
  try {
    const outcome = await resolveRequestDevice(req, val);
    if (!outcome.ok) return next(new AppError(outcome.status, outcome.error));
    next();
  } catch (err) {
    next(err);
  }
});

router.get('/:deviceId/hardware', async (req, res, next) => {
  try {
    const hw = await inventoryService.getHardware(parseInt(req.params.deviceId));
    if (!hw) return res.status(404).json({ error: 'No hardware inventory' });
    res.json({ data: hw });
  } catch (err) { next(err); }
});

router.get('/:deviceId/software', async (req, res, next) => {
  try {
    const items = await inventoryService.getSoftware(
      parseInt(req.params.deviceId), req.query.search as string
    );
    res.json({ data: { items, total: items.length } });
  } catch (err) { next(err); }
});

export default router;
