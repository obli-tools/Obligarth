import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
import { obligateService } from '../services/obligate.service';
import { db } from '../db';

const router = Router();

/**
 * GET /api/obliance/link?uuid={uuid}
 *
 * Called by other Obli* apps (server-side proxy) to look up a device
 * by its machine UUID and return the Obliance page path for that device.
 *
 * Auth: Bearer token — the secret Obligate presents to this server (the
 * inbound secret when one is set, else the Obligate API key). Constant-time,
 * fails closed when nothing is configured.
 */
router.get('/link', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    if (!(await obligateService.verifyInboundBearer(req.headers.authorization))) {
      res.status(401).json({ success: false, error: 'Unauthorized' });
      return;
    }

    const { uuid } = req.query as { uuid?: string };
    if (!uuid) {
      res.status(400).json({ success: false, error: 'uuid is required' });
      return;
    }

    const device = await db('devices')
      .where({ uuid })
      .select('id')
      .first() as { id: number } | undefined;

    if (!device) {
      res.status(404).json({ success: false, error: 'Not found' });
      return;
    }

    res.json({ success: true, data: { path: `/devices/${device.id}` } });
  } catch (err) {
    next(err);
  }
});

export default router;
