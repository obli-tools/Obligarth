// GET /api/android/signup/callback (AN48): public and mute. No session (the customer's administrator may have no
// Obligarth account), 10 requests per minute per address, Cache-Control no-store, Referrer-Policy no-referrer, a
// redirection to a fixed page of the console, never to a received URL; the request (s, enterpriseToken) is never
// logged. Mounted on the public router (before requireAuth) at lot AN-A2.
import { Router, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { clientIp } from '../../utils/clientIp';
import { logger } from '../../utils/logger';
import { handleSignupCallback } from '../enterprises/signup';
import { CALLBACK_HEADERS, CALLBACK_RATE_PER_MINUTE, callbackRedirect } from './callbackPolicy';

export function createAndroidSignupCallbackRouter(): Router {
  const router = Router();
  const limiter = rateLimit({
    windowMs: 60_000,
    max: CALLBACK_RATE_PER_MINUTE,
    standardHeaders: false,
    legacyHeaders: false,
    keyGenerator: (req) => clientIp(req),
    handler: (_req: Request, res: Response) => {
      for (const [k, v] of Object.entries(CALLBACK_HEADERS)) res.setHeader(k, v);
      res.status(429).type('text/plain').send('Too many requests');
    },
  });
  router.get('/callback', limiter, (req: Request, res: Response) => {
    for (const [k, v] of Object.entries(CALLBACK_HEADERS)) res.setHeader(k, v);
    const query = { s: req.query.s, enterpriseToken: req.query.enterpriseToken };
    handleSignupCallback(query)
      .then((r) => res.redirect(302, callbackRedirect(r.result)))
      .catch((err) => {
        logger.error({ android: { callback: 'failed', code: (err as { code?: string })?.code ?? (err as Error)?.name } }, 'android: signup callback failed');
        res.redirect(302, callbackRedirect('error'));
      });
  });
  return router;
}
