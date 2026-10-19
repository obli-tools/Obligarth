// The sign-in URL routes of the device surface (lot AN-F2, section 10.5; COH-21: the sign-in URL is served by the
// public surface mdm., like the BYOD notice), in the form of the BYOD surface (byod/surface.ts): its own parsers and
// limiters, no session; Cache-Control no-store, nosniff, no-referrer, the CSP of pages.ts; one cookie only, the nonce
// that binds the answer of Obligate to the browser that asked (HttpOnly, SameSite=Lax, scoped to the sign-in path of
// the tenant, 15 minutes); an unknown or malformed key, an unknown route, a method not allowed → the same 404 without a
// body; the log line names the route template, the status, the duration and the tenant, never the URL (the
// provisioning id, the state, the code) nor the Location of a redirect.
//   GET  /a/:key/signin?provisioningInfo=<id>   opened by the device (signinDetails): a company device goes to
//                                               Obligate (303), a personal device sees the notice first
//   POST /a/:key/signin                         the acknowledgement of the notice (personal device) → 303 to Obligate
//   GET  /a/:key/signin/callback?code&state     the answer of Obligate → 303 to Google's enrollment page (the token),
//                                               or to Google's invalid page
// Mounted at /a/:key by app.ts (junction AN-A2), beside the BYOD surface. Limiters: per key BEFORE the resolution of the key (F1R-8), then per address.
import express, { Router, type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { appleTenants } from '../../apple/tenants/registry';
import { isMdmKey } from '../../apple/tenants/key';
import { logger } from '../../utils/logger';
import { androidConfig } from '../config';
import { byodTexts, fill, pickByodLocale, type ByodLocale } from '../byod/i18n';
import { tenantFactsOf, type TenantFacts } from '../byod/invitations';
import { signinSurfaceBase } from './config';
import { acknowledgeSigninNotice, completeSignin, SIGNIN_ACTOR, SIGNIN_INVALID_URL, startSignin } from './flow';
import { signinIdentity } from './identity';
import { signinMessagePage, signinNoticePage, signinPageCsp, signinTexts } from './pages';
import { isRandomToken, SIGNIN_COOKIE, signinCallbackOf } from './rules';
import { ENROLL_URL } from '../enrollment/methods';
import { ANDROID_SIGNIN_TTL_SECONDS } from '@obligarth/shared';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let keyResolver: (key: string) => Promise<number | null> = (key) => appleTenants.tenantOfKey(key, SIGNIN_ACTOR);
/** The junction may replace the resolution of the key (the surface of lot C shares its cache). */
export function setSigninKeyResolver(fn: (key: string) => Promise<number | null>): void { keyResolver = fn; }

interface Locals { tenant?: TenantFacts; route: string; key?: string }
const locals = (res: Response): Locals => res.locals as Locals;

function notFound(res: Response): void {
  if (!res.headersSent) res.status(404).end();
}

async function sendPage(res: Response, status: number, html: string): Promise<void> {
  const origin = await signinIdentity().origin().catch(() => null);
  res.status(status).type('text/html; charset=utf-8').setHeader('Content-Security-Policy', signinPageCsp(origin));
  res.send(html);
}

const localeOf = (req: Request): ByodLocale => pickByodLocale(req.headers['accept-language'], 'fr');

const tooMany = (req: Request, res: Response): void => {
  const t = byodTexts(localeOf(req));
  void sendPage(res, 429, signinMessagePage(t.lang, t.tooMany, t.tooMany));
};

const limiter = (prefix: string, max: number, key: (req: Request) => string): RequestHandler => rateLimit({
  windowMs: 60_000, limit: max, standardHeaders: false, legacyHeaders: false,
  keyGenerator: (req) => `${prefix}:${key(req)}`, handler: tooMany,
  validate: { xForwardedForHeader: false, trustProxy: false },
});
/** Per key: the key is in the URL (public): a flood of one tenant never reaches the database nor Google. */
const perKey = (max: number): RequestHandler => limiter('sk', max, (req) => String(req.params.key ?? '').slice(0, 40));
/** Per address (the address keys the limiter only, never logged). */
const perAddress = (max: number): RequestHandler => limiter('sa', max, (req) => req.ip ?? 'unknown');

const route = (template: string): RequestHandler => (_req, res, next) => { locals(res).route = template; next(); };
const asyncHandler = (fn: (req: Request, res: Response) => Promise<void>): RequestHandler =>
  (req, res, next) => { fn(req, res).catch(next); };

/** The nonce of the browser, from its Cookie header (no cookie parser on the surface). */
export function nonceOfCookie(header: unknown): string | null {
  if (typeof header !== 'string' || header.length > 4096) return null;
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === SIGNIN_COOKIE) {
      const value = v.join('=');
      return isRandomToken(value) ? value : null;
    }
  }
  return null;
}

function setNonce(res: Response, key: string, nonce: string | null, secure: boolean): void {
  const attrs = [`Path=/a/${key}/signin`, 'HttpOnly', 'SameSite=Lax', nonce ? `Max-Age=${ANDROID_SIGNIN_TTL_SECONDS}` : 'Max-Age=0'];
  if (secure) attrs.push('Secure');
  res.setHeader('Set-Cookie', `${SIGNIN_COOKIE}=${nonce ?? ''}; ${attrs.join('; ')}`);
}

/** Is the target the authorization page of the identity provider (its origin), and nowhere else? */
async function isIdentityUrl(url: string): Promise<boolean> {
  const origin = await signinIdentity().origin();
  if (!origin) return false;
  try {
    return new URL(url).origin === origin;
  } catch {
    return false;
  }
}

const isGoogleTarget = (u: string): boolean => u.startsWith(`${ENROLL_URL}?et=`) || u === SIGNIN_INVALID_URL;

export function createAndroidSigninSurface(): Router {
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

  const resolveTenant: RequestHandler = (req, res, next) => {
    const resolve = async (): Promise<boolean> => {
      const key = String(req.params.key ?? '');
      if (!isMdmKey(key)) return false;
      const tenantId = await keyResolver(key);
      if (tenantId === null) return false;
      const facts = await tenantFactsOf(tenantId);
      if (!facts) return false;
      locals(res).tenant = facts;
      locals(res).key = key;
      return true;
    };
    resolve().then((ok) => { if (ok) next(); else notFound(res); }).catch(next);
  };

  /** The redirect_uri of the tenant, or null when the surface has no public base. */
  const callbackOf = (res: Response): string | null => {
    const base = signinSurfaceBase();
    return base ? signinCallbackOf(base, locals(res).key!) : null;
  };
  const secure = (): boolean => (signinSurfaceBase() ?? '').startsWith('https://');
  const unavailable = async (res: Response, locale: ByodLocale): Promise<void> => {
    const t = byodTexts(locale);
    await sendPage(res, 503, signinMessagePage(locale, t.unavailableTitle, fill(t.unavailableBody, { org: locals(res).tenant!.name })));
  };
  const toGoogle = (res: Response, url: string): void => { res.redirect(303, isGoogleTarget(url) ? url : SIGNIN_INVALID_URL); };

  router.get('/signin', route('GET /a/:key/signin'), perKey(120), perAddress(20), resolveTenant, asyncHandler(async (req, res) => {
    const t = locals(res).tenant!;
    const locale = localeOf(req);
    const callback = callbackOf(res);
    if (!callback) { await unavailable(res, locale); return; }
    const out = await startSignin(t, { provisioningInfo: req.query.provisioningInfo, locale, callback });
    switch (out.kind) {
      case 'authorize':
        if (!(await isIdentityUrl(out.url))) { await unavailable(res, locale); return; }
        setNonce(res, locals(res).key!, out.nonce, secure());
        res.redirect(303, out.url);
        return;
      case 'notice':
        setNonce(res, locals(res).key!, out.nonce, secure());
        await sendPage(res, 200, signinNoticePage({ byod: byodTexts(locale), t: signinTexts(locale), organization: t.name, notice: out.notice,
          state: out.state, action: 'signin' }));
        return;
      case 'invalid': toGoogle(res, SIGNIN_INVALID_URL); return;
      default: await unavailable(res, locale);
    }
  }));

  router.post('/signin', route('POST /a/:key/signin'), perKey(60), perAddress(10), resolveTenant, form, asyncHandler(async (req, res) => {
    const t = locals(res).tenant!;
    const b = (req.body ?? {}) as Record<string, unknown>;
    const locale: ByodLocale = b.lang === 'en' || b.lang === 'fr' ? b.lang : localeOf(req);
    const versionId = typeof b.notice_version_id === 'string' && UUID_RE.test(b.notice_version_id) ? b.notice_version_id.toLowerCase() : '';
    const callback = callbackOf(res);
    if (!callback) { await unavailable(res, locale); return; }
    if (b.ack !== '1' || !versionId) {
      // Without the acknowledgement nothing moves: the page again (its state, if it is one, is shown back as is).
      const tx = signinTexts(locale);
      await sendPage(res, 400, signinMessagePage(locale, tx.invalidTitle, byodTexts(locale).noticeChanged));
      return;
    }
    const out = await acknowledgeSigninNotice(t, { state: b.s, nonce: nonceOfCookie(req.headers.cookie), noticeVersionId: versionId, locale, callback });
    switch (out.kind) {
      case 'authorize':
        if (!(await isIdentityUrl(out.url))) { await unavailable(res, locale); return; }
        res.redirect(303, out.url);
        return;
      case 'notice_changed':
        if (!out.notice) { await unavailable(res, locale); return; }
        await sendPage(res, 409, signinNoticePage({ byod: byodTexts(locale), t: signinTexts(locale), organization: t.name, notice: out.notice,
          state: out.state, action: 'signin', noticeChanged: true }));
        return;
      case 'invalid': setNonce(res, locals(res).key!, null, secure()); toGoogle(res, SIGNIN_INVALID_URL); return;
      default: await unavailable(res, locale);
    }
  }));

  router.get('/signin/callback', route('GET /a/:key/signin/callback'), perKey(60), perAddress(10), resolveTenant, asyncHandler(async (req, res) => {
    const t = locals(res).tenant!;
    const callback = callbackOf(res);
    if (!callback) { await unavailable(res, localeOf(req)); return; }
    const out = await completeSignin(t, { state: req.query.state, code: req.query.code, nonce: nonceOfCookie(req.headers.cookie), callback });
    // The cookie served its purpose whatever the outcome.
    setNonce(res, locals(res).key!, null, secure());
    toGoogle(res, out.kind === 'redirect' ? out.url : SIGNIN_INVALID_URL);
  }));

  // Anything else: the uniform 404.
  router.use((_req: Request, res: Response) => { notFound(res); });
  return router;
}
