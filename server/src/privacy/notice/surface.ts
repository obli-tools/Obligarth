import { Router, type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { NOTICE_LOCALES, NOTICE_PLATFORMS, type NoticePlatform } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { appleTenants } from '../../apple/tenants/registry';
import { isMdmKey } from '../../apple/tenants/key';
import { pickLocale } from '../../apple/enrollment/i18n';
import { androidEnabled } from '../../android/config';
import { logger } from '../../utils/logger';
import { isNoticeIncomplete } from './errors';
import { fill } from './i18n';
import { NOTICE_PAGE_CSP, noticeMessagePage, noticePageTexts, noticePublicPage, noticeQueryOf, publicNoticeChoices } from './page';
import { publicNoticeFor } from './provider';

// =============================================================================
// The public page of the notice of the employees (P0-13 T6, USR-01, D6), on the device surface (mdm.<domain>, relayed
// by the edge proxy: location /t/<key>/notice of client/edge-proxy/mdm.conf), mounted at /t/:key/notice by app.ts
// before the Apple surface (which answers nothing while APPLE_EDGE_MODE is off: this page serves the Android notice
// too):
//   GET /t/:key/notice?platform=&ownership=&lang=    the notice in force of the tenant: the one an enrollment shows now,
//                                                    the same version (publicNoticeFor: published as at an enrollment
//                                                    page when its content changed)
// The combinations are those shown at an enrollment on this instance (noticeDisplayed, D13): Apple's three ownerships
// while APPLE_EDGE_MODE=on, the personal Android devices while ANDROID_MODE is not off. A parameter absent takes its
// default (the first platform, the company device on Apple and the personal one on Android, the language of
// Accept-Language); a value that is not one of them, an unknown or malformed key, another path or method → the same
// 404 without a body. A notice not complete outside the laboratory (D7) → a page "notice unavailable" (503).
// As the enrollment pages: no session, no cookie, no write but the version of a changed content; Cache-Control
// no-store, nosniff, no-referrer, its own CSP (no script, no form); the address keys the limiter only, never logged;
// the log line names the route template, the status, the duration and the tenant, never the URL (the key).
// No personal data: the name of the organisation and the notice only.
// =============================================================================

/** The database actor of the page. */
export const NOTICE_PUBLIC_ACTOR: DbActor = Object.freeze({ type: 'enrollment', name: 'notice' }) as DbActor;

/** Requests a minute and per address (before the key is resolved). */
export const NOTICE_PAGE_PER_MINUTE = 30;

/** The platforms whose notice this instance shows (their enrollments are served). */
export function publicNoticePlatforms(): NoticePlatform[] {
  return NOTICE_PLATFORMS.filter((p) => (p === 'apple' ? config.apple.mode === 'on' : androidEnabled()));
}

/** Does this instance serve the public page of the notice? */
export const publicNoticeServed = (): boolean => publicNoticePlatforms().length > 0;

interface Locals { route: string; tenant?: { tenantId: number; name: string } }
const locals = (res: Response): Locals => res.locals as Locals;

function notFound(res: Response): void {
  if (!res.headersSent) res.status(404).end();
}

function sendPage(res: Response, status: number, html: string): void {
  res.status(status).type('text/html; charset=utf-8').setHeader('Content-Security-Policy', NOTICE_PAGE_CSP);
  res.send(html);
}

const asyncHandler = (fn: (req: Request, res: Response) => Promise<void>): RequestHandler =>
  (req, res, next) => { fn(req, res).catch(next); };

export function createNoticePublicSurface(): Router {
  const router = Router({ mergeParams: true });

  // Headers, log line, nothing served while no enrollment is.
  router.use((req: Request, res: Response, next: NextFunction) => {
    const started = process.hrtime.bigint();
    locals(res).route = 'unknown';
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      logger.info({ surface: locals(res).route, method: req.method, status: res.statusCode, ms: Math.round(ms), tenantId: locals(res).tenant?.tenantId ?? null },
        'device surface request');
    });
    if (!publicNoticeServed()) { notFound(res); return; }
    next();
  });

  // Before the key is resolved (the resolution reads the base): every request of an address, whatever the key.
  router.use(rateLimit({
    windowMs: 60_000, limit: NOTICE_PAGE_PER_MINUTE, standardHeaders: false, legacyHeaders: false,
    keyGenerator: (req) => `np:${req.ip ?? 'unknown'}`,
    handler: (req, res) => {
      const t = noticePageTexts(pickLocale(req.headers['accept-language'], 'fr'));
      sendPage(res, 429, noticeMessagePage(t, t.tooMany, t.tooMany));
    },
    validate: { xForwardedForHeader: false, trustProxy: false },
  }));

  router.get('/', (_req, res, next) => { locals(res).route = 'GET /t/:key/notice'; next(); }, asyncHandler(async (req, res) => {
    const platforms = publicNoticePlatforms();
    const asked = noticeQueryOf(req.query as Record<string, unknown>, req.headers['accept-language'], platforms);
    const key = String(req.params.key ?? '');
    if (!asked || !isMdmKey(key)) { notFound(res); return; }
    const tenantId = await appleTenants.tenantOfKey(key, NOTICE_PUBLIC_ACTOR);
    if (tenantId === null) { notFound(res); return; }
    const t = await asTenant(tenantId, NOTICE_PUBLIC_ACTOR, () => db('tenants').where({ id: tenantId }).first('name')) as { name: string } | undefined;
    if (!t) { notFound(res); return; }
    const name = String(t.name);
    locals(res).tenant = { tenantId, name };
    const { choice, locale } = asked;
    const notice = await asTenant(tenantId, NOTICE_PUBLIC_ACTOR,
      () => publicNoticeFor(db, tenantId, choice.platform, choice.ownership, locale, name));
    sendPage(res, 200, noticePublicPage({
      t: noticePageTexts(locale), organization: name, current: choice, choices: publicNoticeChoices(platforms), locales: NOTICE_LOCALES,
      notice: notice.content,
    }));
  }));

  // Anything else (path, method): the uniform 404.
  router.use((_req: Request, res: Response) => { notFound(res); });

  // Errors: no detail, never the URL. The notice not complete outside the laboratory (D7): the page says so.
  router.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    if (isNoticeIncomplete(err)) {
      const lang = req.query.lang === 'en' || req.query.lang === 'fr' ? req.query.lang : pickLocale(req.headers['accept-language'], 'fr');
      const t = noticePageTexts(lang);
      if (!res.headersSent) sendPage(res, 503, noticeMessagePage(t, t.unavailableTitle, fill(t.unavailableBody, { org: locals(res).tenant?.name ?? '' })));
      return;
    }
    logger.error({ surface: locals(res).route, tenantId: locals(res).tenant?.tenantId ?? null, code: (err as { code?: unknown })?.code,
      name: (err as Error)?.name ?? null }, 'device surface request failed');
    if (!res.headersSent) res.status(500).end();
  });
  return router;
}
