import express, { type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { VPP_LIMITS } from '@obligarth/shared';
import { asTenant } from '../../db/context';
import { VPP_INTEGRATION } from '../actors';
import { acceptNotification, authenticateNotification, isNotificationRef, type NotificationToken } from './vpp.service';

// =============================================================================
// POST /t/:key/vpp/:ref/notify (docs: integration-apple-edge §11.3, I6,
// §10.8): the notifications of Apps and Books, mounted by the device surface
// (enrollment/surface.ts) after its resolution of the tenant of the key
// (context 'none'); the token of the reference is looked for in that tenant
// only (asTenant, actor i:apple-vpp): another tenant's reference answers the
// uniform 404. JSON body of 1 MiB at most, an empty answer (200, 401, 404, 400)
// in well under 500 ms: the follow-up is a job's.
// Review F017: the key is public (it is in every enrollment link), so the
// limits do not rest on a value the caller picks alone: 300 requests a minute
// per (key, address) first, then 1 200 per key for the well-formed references
// (whatever the addresses), then 120 per well-formed reference; the reference
// and its secret are checked BEFORE the body is read, so that only Apple, with
// the secret of a live token, gets a body parsed.
// =============================================================================

const json = express.json({ limit: VPP_LIMITS.notificationBytes, type: () => true, strict: true });

const tooMany = (_req: Request, res: Response): void => { res.status(429).end(); };

const perKeyAddress: RequestHandler = rateLimit({
  windowMs: 60_000, limit: 300, standardHeaders: false, legacyHeaders: false,
  keyGenerator: (req) => `vppka:${String(req.params.key ?? '').slice(0, 64)}|${req.ip ?? 'unknown'}`,
  handler: tooMany,
  validate: { xForwardedForHeader: false, trustProxy: false },
});

// A ceiling per key alone (whatever the addresses), counted for well-formed references only: a caller spread over
// many addresses still makes at most this many reads of tokens per minute for a tenant.
const perKey: RequestHandler = rateLimit({
  windowMs: 60_000, limit: 1200, standardHeaders: false, legacyHeaders: false,
  keyGenerator: (req) => `vppk:${String(req.params.key ?? '').slice(0, 64)}`,
  handler: tooMany,
  validate: { xForwardedForHeader: false, trustProxy: false },
});

const perReference: RequestHandler = rateLimit({
  windowMs: 60_000, limit: 120, standardHeaders: false, legacyHeaders: false,
  keyGenerator: (req) => `vpp:${String(req.params.ref ?? '').slice(0, 40)}`,
  handler: tooMany,
  validate: { xForwardedForHeader: false, trustProxy: false },
});

/** A malformed reference answers the uniform 404 before any limiter of its own or any read. */
const wellFormed: RequestHandler = (req, res, next) => {
  if (!isNotificationRef(String(req.params.ref ?? ''))) { res.status(404).end(); return; }
  next();
};

const TOKEN = Symbol('vppNotificationToken');
type WithToken = Response & { [TOKEN]?: NotificationToken };

/** The handlers of the route, after the surface's tenant resolution (`tenantOf` reads it from res.locals). */
export function vppNotifyHandlers(tenantOf: (res: Response) => number): RequestHandler[] {
  const authenticate: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    const tenantId = tenantOf(res);
    asTenant(tenantId, VPP_INTEGRATION, () => authenticateNotification(tenantId, String(req.params.ref ?? ''), req.headers.authorization))
      .then((auth) => {
        if ('status' in auth) { if (!res.headersSent) res.status(auth.status).end(); return; }
        (res as WithToken)[TOKEN] = auth.token;
        next();
      })
      .catch(next);
  };
  const handler: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    const tenantId = tenantOf(res);
    const token = (res as WithToken)[TOKEN];
    if (!token) { res.status(404).end(); return; }
    asTenant(tenantId, VPP_INTEGRATION, () => acceptNotification(tenantId, token, req.body))
      .then((status) => { if (!res.headersSent) res.status(status).end(); })
      .catch(next);
  };
  return [perKeyAddress, wellFormed, perKey, perReference, authenticate, json, handler];
}
