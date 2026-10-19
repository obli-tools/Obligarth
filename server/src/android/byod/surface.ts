// The Android BYOD routes of the device surface (lot AN-F1, section 10.5; COH-21: the BYOD notice is served by the
// public surface mdm.), in the form of the device surface of lot C (apple/enrollment/surface.ts on main): its own
// parsers and limiters, no session, no cookie; Cache-Control no-store, nosniff, no-referrer, the CSP of pages.ts; an
// unknown or malformed key, an unknown route, a method not allowed → the same 404 without a body; the log line names
// the route template, the status, the duration and the tenant, never the URL nor the form (the code, the Google link).
//   GET  /a/:key/byod   the notice of a personal device and the invitation code (writes nothing: link previews of
//                       messaging apps consume nothing)
//   POST /a/:key/byod   the code and the acknowledgement → 303 to Google's enrollment page (the token of the
//                       invitation); a wrong code, a changed notice, a missing acknowledgement → the page again
// Mounted at /a/:key by app.ts (junction AN-A2), right after helmet like /t/:key; the key is the tenant's MDM key
// (tenants.mdm_key, lookup function of context none), resolved by the resolver the junction may replace
// (setByodKeyResolver).
import express, { Router, type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { appleTenants } from '../../apple/tenants/registry';
import { isMdmKey } from '../../apple/tenants/key';
import { logger } from '../../utils/logger';
import { androidConfig } from '../config';
import { acknowledgeInvitation, BYOD_ACTOR, byodNotice, tenantFactsOf, type TenantFacts } from './invitations';
import { byodTexts, fill, pickByodLocale, type ByodLocale } from './i18n';
import { BYOD_PAGE_CSP, byodMessagePage, byodPage, GOOGLE_ENROLL_ORIGIN } from './pages';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let keyResolver: (key: string) => Promise<number | null> = (key) => appleTenants.tenantOfKey(key, BYOD_ACTOR);
/** The junction may replace the resolution of the key (the surface of lot C shares its cache). */
export function setByodKeyResolver(fn: (key: string) => Promise<number | null>): void { keyResolver = fn; }

interface Locals { tenant?: TenantFacts; route: string }
const locals = (res: Response): Locals => res.locals as Locals;

function notFound(res: Response): void {
  if (!res.headersSent) res.status(404).end();
}

function sendPage(res: Response, status: number, html: string): void {
  res.status(status).type('text/html; charset=utf-8').setHeader('Content-Security-Policy', BYOD_PAGE_CSP);
  res.send(html);
}

const tooMany = (req: Request, res: Response): void => {
  const t = byodTexts(pickByodLocale(req.headers['accept-language'], 'fr'));
  sendPage(res, 429, byodMessagePage(t, t.tooMany, t.tooMany));
};

/** A limiter of `max` requests a minute and per address (the address keys the limiter only, never logged). */
const perAddress = (max: number): RequestHandler => rateLimit({
  windowMs: 60_000, limit: max, standardHeaders: false, legacyHeaders: false,
  keyGenerator: (req) => `ab:${req.ip ?? 'unknown'}`, handler: tooMany,
  validate: { xForwardedForHeader: false, trustProxy: false },
});

const route = (template: string): RequestHandler => (_req, res, next) => { locals(res).route = template; next(); };
const asyncHandler = (fn: (req: Request, res: Response) => Promise<void>): RequestHandler =>
  (req, res, next) => { fn(req, res).catch(next); };

/** Is the redirect target Google's enrollment page (never anywhere else)? */
export const isGoogleEnrollUrl = (u: string): boolean => u.startsWith(`${GOOGLE_ENROLL_ORIGIN}/android/enroll?`);

export function createAndroidByodSurface(): Router {
  const router = Router({ mergeParams: true });
  const form = express.urlencoded({ extended: false, limit: '8kb', parameterLimit: 20 });

  router.use((req: Request, res: Response, next: NextFunction) => {
    const started = process.hrtime.bigint();
    locals(res).route = 'unknown';
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      logger.info({ surface: locals(res).route, method: req.method, status: res.statusCode, ms: Math.round(ms), tenantId: locals(res).tenant?.tenantId ?? null },
        'android device surface request');
    });
    if (androidConfig().mode === 'off') { notFound(res); return; }
    next();
  });

  router.use((req: Request, res: Response, next: NextFunction) => {
    const resolve = async (): Promise<boolean> => {
      const key = String(req.params.key ?? '');
      if (!isMdmKey(key)) return false;
      const tenantId = await keyResolver(key);
      if (tenantId === null) return false;
      const facts = await tenantFactsOf(tenantId);
      if (!facts) return false;
      locals(res).tenant = facts;
      return true;
    };
    resolve().then((ok) => { if (ok) next(); else notFound(res); }).catch(next);
  });

  const show = async (res: Response, t: TenantFacts, locale: ByodLocale, status: number, flags: { wrongCode?: boolean; noticeChanged?: boolean } = {}) => {
    const tx = byodTexts(locale);
    const notice = await byodNotice(t, locale);
    if (!notice) { sendPage(res, 503, byodMessagePage(tx, tx.unavailableTitle, fill(tx.unavailableBody, { org: t.name }))); return; }
    sendPage(res, status, byodPage({ t: tx, organization: t.name, notice, action: 'byod', ...flags }));
  };

  router.get('/byod', route('GET /a/:key/byod'), perAddress(30), asyncHandler(async (req, res) => {
    const t = locals(res).tenant!;
    await show(res, t, pickByodLocale(req.headers['accept-language'], 'fr'), 200);
  }));

  router.post('/byod', route('POST /a/:key/byod'), perAddress(10), form, asyncHandler(async (req, res) => {
    const t = locals(res).tenant!;
    const b = (req.body ?? {}) as Record<string, unknown>;
    const fallback = pickByodLocale(req.headers['accept-language'], 'fr');
    const locale: ByodLocale = b.lang === 'en' || b.lang === 'fr' ? b.lang : fallback;
    const versionId = typeof b.notice_version_id === 'string' && UUID_RE.test(b.notice_version_id) ? b.notice_version_id.toLowerCase() : '';
    const tx = byodTexts(locale);
    // The acknowledgement is required: without it nothing is read nor counted.
    if (b.ack !== '1' || !versionId) { await show(res, t, locale, 400); return; }
    // The address counts the wrong codes first (F1R-4); never stored in clear.
    const out = await acknowledgeInvitation(t, { code: b.code, noticeVersionId: versionId, locale, address: req.ip ?? 'unknown' });
    switch (out.kind) {
      case 'redirect':
        if (!isGoogleEnrollUrl(out.url)) { sendPage(res, 503, byodMessagePage(tx, tx.retryTitle, tx.retryBody)); return; }
        res.redirect(303, out.url);
        return;
      case 'wrong_code': await show(res, t, locale, 400, { wrongCode: true }); return;
      case 'notice_changed': await show(res, t, locale, 409, { noticeChanged: true }); return;
      case 'flood': case 'address_flood': sendPage(res, 429, byodMessagePage(tx, tx.tooMany, tx.tooMany)); return;
      case 'busy': case 'retry': sendPage(res, 503, byodMessagePage(tx, tx.retryTitle, tx.retryBody)); return;
      default: sendPage(res, 503, byodMessagePage(tx, tx.unavailableTitle, fill(tx.unavailableBody, { org: t.name })));
    }
  }));

  // Anything else: the uniform 404.
  router.use((_req: Request, res: Response) => { notFound(res); });
  return router;
}
