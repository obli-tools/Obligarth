import { randomUUID } from 'node:crypto';
import express, { Router, type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import { OBLIWATCH_API_VERSION, type ObliwatchPingResponse } from '@obligarth/shared';
import { logger } from '../../utils/logger';
import { listAccessKeys } from './accessKeys';
import { aiSummary } from './aiApps';
import { cancelActionRequest, createActionRequest, getActionRequest } from './actions';
import { getDevice, getDeviceApps, listDevices } from './devices';
import { auditRead } from './audit';
import { obliwatchAuth, sendError } from './auth';
import { OBLIWATCH_JSON_LIMIT } from './config';
import { readConsent, requireConsent } from './consent';

// =============================================================================
// The read API of Obliwatch, /api/integrations/obliwatch/v1 (brief GTH-03, GTH-07; plan §0 F3). Mounted by app.ts
// BEFORE cors, the parsers, the cookies, the session and the console's database context, like /mcp, and only when
// OBLIWATCH_INTEGRATION=on: no session exists here, nothing can write one nor set a cookie (a request carrying a
// cookie is refused, a Set-Cookie is never sent), no-store on every answer, its own JSON parser (64 KB), a JSON 404
// for anything not listed below. Every query runs in an explicit context (asIdentity / asTenant of i:obliwatch).
//
//   GET /ping            app token; served WITHOUT consent (diagnostic of the link): the tenant and its consent
//   GET /access-keys     app token + consent 'read' (GTH-07)
//   GET /devices         app token + consent 'read' (GTH-03): ?updatedSince=&limit=1..500&cursor= (devices.ts)
//   GET /devices/:uuid   app token + consent 'read' (GTH-03, GTH-09 coverage)
//   GET /devices/:uuid/apps  app token + consent 'read' (GTH-03): managed apps only unless the profile collects all
//   GET /apps/ai-summary     app token + consent 'read' (GTH-06, lot L4): AI apps of Obliwatch's catalog, aggregates;
//                            ?nominative=1 with the consent nominativeAiApps and Obliwatch's attestation (aiApps.ts)
//   POST /action-requests             user token (the analyst) + consent 'actions' (GTH-04, lot L5; actions.ts): executed
//                                     without approval (owner decision Q-L5a), 202 {requestId, state, expiresAt}
//   GET  /action-requests/:id         app or user token + consent 'actions': the state and result (no coordinate)
//   POST /action-requests/:id/cancel  app or user token + consent 'actions': before the execution only (else 409)
//
// =============================================================================

const wrap = (fn: (req: Request, res: Response) => Promise<void>): RequestHandler =>
  (req, res, next) => { fn(req, res).catch(next); };

/** The chain of a read route: app token (rate limit, jti burned), then the tenant's consent to be read. */
export const APP_READ: RequestHandler[] = [obliwatchAuth('app'), requireConsent('read')];

export function createObliwatchRouter(): Router {
  const router = Router();

  router.use((req, res, next) => {
    req.requestId = req.requestId ?? randomUUID();
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Never a cookie, either way: server-to-server only.
    const setHeader = res.setHeader.bind(res);
    res.setHeader = ((name: string, value: unknown) => (name.toLowerCase() === 'set-cookie' ? res : setHeader(name, value as string))) as typeof res.setHeader;
    if (req.headers.cookie) { sendError(res, 400, 'cookie_refused', 'Cookies are not accepted here'); return; }
    next();
  });
  router.use(express.json({ limit: OBLIWATCH_JSON_LIMIT, type: 'application/json' }));

  router.get('/ping', obliwatchAuth('app'), wrap(async (req, res) => {
    const caller = req.obliwatch!;
    const c = await readConsent(caller.tenantId);
    const body: ObliwatchPingResponse = {
      ok: true, tenant: caller.ost, consent: { read: c.read, push: c.push, actions: c.actions }, apiVersion: OBLIWATCH_API_VERSION,
    };
    auditRead(req, caller.tenantId, 'ping');
    res.json(body);
  }));

  router.get('/access-keys', ...APP_READ, wrap(listAccessKeys));
  router.get('/devices', ...APP_READ, wrap(listDevices));
  router.get('/devices/:uuid', ...APP_READ, wrap(getDevice));
  router.get('/devices/:uuid/apps', ...APP_READ, wrap(getDeviceApps));
  router.get('/apps/ai-summary', ...APP_READ, wrap(aiSummary));
  router.post('/action-requests', obliwatchAuth('user', 'request'), requireConsent('actions'), wrap(createActionRequest));
  router.get('/action-requests/:id', obliwatchAuth('either'), requireConsent('actions'), wrap(getActionRequest));
  router.post('/action-requests/:id/cancel', obliwatchAuth('either'), requireConsent('actions'), wrap(cancelActionRequest));

  router.use((_req, res) => { sendError(res, 404, 'not_found', 'Not found'); });

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  router.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const status = (err as { status?: number; type?: string })?.status;
    if (status === 413) { sendError(res, 413, 'body_too_large', 'Body too large'); return; }
    if (status === 400 && (err as { type?: string }).type === 'entity.parse.failed') { sendError(res, 400, 'body_invalid', 'Invalid JSON'); return; }
    logger.error({ err: { message: (err as Error)?.message?.slice(0, 200) } }, '[obliwatch] request failed');
    if (!res.headersSent) sendError(res, 503, 'internal_error');
  });

  return router;
}
