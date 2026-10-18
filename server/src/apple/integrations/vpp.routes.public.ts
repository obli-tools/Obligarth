import express, { type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { VPP_LIMITS } from '@obligarth/shared';
import { asTenant } from '../../db/context';
import { VPP_INTEGRATION } from '../actors';
import { receiveNotification } from './vpp.service';

// =============================================================================
// POST /t/:key/vpp/:ref/notify (docs: integration-apple-edge §11.3, I6,
// §10.8): the notifications of Apps and Books, mounted by the device surface
// (enrollment/surface.ts) after its resolution of the tenant of the key
// (context 'none'); the token of the reference is looked for in that tenant
// only (asTenant, actor i:apple-vpp): another tenant's reference answers the
// uniform 404. JSON body of 1 MiB at most, 120 requests a minute and per
// reference, an empty answer (200, 401, 404, 400) in well under 500 ms: the
// follow-up is a job's.
// =============================================================================

const json = express.json({ limit: VPP_LIMITS.notificationBytes, type: () => true, strict: true });

const perReference: RequestHandler = rateLimit({
  windowMs: 60_000, limit: 120, standardHeaders: false, legacyHeaders: false,
  keyGenerator: (req) => `vpp:${String(req.params.ref ?? '').slice(0, 40)}`,
  handler: (_req, res) => { res.status(429).end(); },
  validate: { xForwardedForHeader: false, trustProxy: false },
});

/** The handlers of the route, after the surface's tenant resolution (`tenantOf` reads it from res.locals). */
export function vppNotifyHandlers(tenantOf: (res: Response) => number): RequestHandler[] {
  const handler: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    const tenantId = tenantOf(res);
    asTenant(tenantId, VPP_INTEGRATION, () => receiveNotification(tenantId, String(req.params.ref ?? ''), req.headers.authorization, req.body))
      .then((status) => { if (!res.headersSent) res.status(status).end(); })
      .catch(next);
  };
  return [perReference, json, handler];
}
