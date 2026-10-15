import express, { Router, type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../../config';
import { logger } from '../../utils/logger';
import { ENROLL_OTA } from '../actors';
import { appleTenants } from '../tenants/registry';
import { isMdmKey } from '../tenants/key';
import {
  acknowledgeLink, consumeNonce, findUsableLink, issueOtaProfile, noticeOf, tenantFacts, type TenantFacts,
} from './flow';
import { fill, pickLocale, textsFor, type SurfaceLocale } from './i18n';
import { PROFILE_CONTENT_TYPE, PROFILE_FILENAME } from './mobileconfig';
import { invitePage, messagePage, noticePage, PAGE_CSP } from './pages';
import { isLinkToken, isNonce } from './tokens';
import { db } from '../../db';
import { asTenant } from '../../db/context';

// =============================================================================
// Device surface of the brain (docs: integration-apple-edge §10.8, I5),
// mounted at /t/:key in app.ts right after helmet, before cors, the JSON
// parser, the cookies, the session, the limiter of the API and
// deviceKeySession: its own parsers, limits and limiters; no session, no
// cookie. Reachable through the edge proxy only (mdm.<domain>).
//   GET  /t/:key/enroll/:token                 OTA: notice page (no write)
//   POST /t/:key/enroll/:token                 OTA: acknowledgement → 303
//   GET  /t/:key/enroll/s/:sessionId/profile   OTA: the profile (single-use nonce)
//   GET  /t/:key/byod/invite                   instructions of an invitation
// The ADE, account-driven and Apps and Books routes come with lots C2 and C4.
// Common rules: a key out of the alphabet or unknown, an unknown route, a
// method not allowed → the same 404, no body; an invalid link of the tenant →
// the same translated page (404), whatever the reason (unknown, another
// tenant's, revoked, expired, used up); Cache-Control: no-store, nosniff,
// no-referrer, CSP of pages.ts; the address (X-Forwarded-For set by the edge
// proxy, req.ip under trust proxy 1) keys the limiters only, never logged;
// the log line: route template, status, duration, tenant — never the URL (it
// carries the token or the nonce).
// =============================================================================

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface SurfaceLocals {
  tenant: TenantFacts;
  route: string;
}
const locals = (res: Response): SurfaceLocals => res.locals as SurfaceLocals;

/** The uniform 404: no body, no detail. */
function notFound(res: Response): void {
  if (res.headersSent) return;
  res.status(404).end();
}

function sendPage(res: Response, status: number, html: string): void {
  res.status(status).type('text/html; charset=utf-8').setHeader('Content-Security-Policy', PAGE_CSP);
  res.send(html);
}

const tooManyHandler = (req: Request, res: Response): void => {
  const t = textsFor(pickLocale(req.headers['accept-language'], 'fr'));
  sendPage(res, 429, messagePage(t, t.tooMany, t.tooMany));
};

/** A limiter of `max` requests a minute and per address. */
const perAddress = (max: number): RequestHandler => rateLimit({
  windowMs: 60_000, limit: max, standardHeaders: false, legacyHeaders: false,
  keyGenerator: (req) => `ip:${req.ip ?? 'unknown'}`, handler: tooManyHandler,
  validate: { xForwardedForHeader: false, trustProxy: false },
});

/** Marks the route template of the request (the log line names it, never the URL). */
const route = (template: string): RequestHandler => (_req, res, next) => { locals(res).route = template; next(); };

const asyncHandler = (fn: (req: Request, res: Response) => Promise<void>): RequestHandler =>
  (req, res, next) => { fn(req, res).catch(next); };

const pathOf = (key: string, ...parts: string[]): string => `/t/${key}/${parts.map((p) => encodeURIComponent(p)).join('/')}`;

export function createAppleDeviceSurface(): Router {
  const router = Router({ mergeParams: true });
  const form = express.urlencoded({ extended: false, limit: '8kb', parameterLimit: 20 });

  // Headers, log line, refusal by default.
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
    if (config.apple.mode !== 'on') { notFound(res); return; }
    next();
  });

  // The tenant of the key (context 'none', cached 60 s); unknown or malformed: the uniform 404.
  router.use((req: Request, res: Response, next: NextFunction) => {
    const resolve = async (): Promise<boolean> => {
      const key = String(req.params.key ?? '');
      if (!isMdmKey(key)) return false;
      const tenantId = await appleTenants.tenantOfKey(key, ENROLL_OTA);
      if (tenantId === null) return false;
      const facts = await tenantFacts(tenantId, key, ENROLL_OTA);
      if (!facts) return false;
      locals(res).tenant = facts;
      return true;
    };
    resolve().then((ok) => { if (ok) next(); else notFound(res); }).catch(next);
  });

  const invalidLink = (req: Request, res: Response, locale: SurfaceLocale): void => {
    const t = textsFor(locale);
    sendPage(res, 404, messagePage(t, t.invalidTitle, t.invalidBody));
  };

  // ── OTA: the profile (single-use download nonce) ────────────────────────────
  router.get('/enroll/s/:sessionId/profile', route('GET /t/:key/enroll/s/:sessionId/profile'), perAddress(10), asyncHandler(async (req, res) => {
    const t = locals(res).tenant;
    const sessionId = String(req.params.sessionId ?? '');
    const nonce = req.query.n;
    const fallback = pickLocale(req.headers['accept-language'], 'fr');
    if (!UUID_RE.test(sessionId) || !isNonce(nonce)) { invalidLink(req, res, fallback); return; }
    const consumed = await consumeNonce(t, sessionId.toLowerCase(), nonce, ENROLL_OTA);
    if (consumed.kind === 'invalid') { invalidLink(req, res, fallback); return; }
    if (consumed.kind === 'expired') {
      const tx = textsFor(consumed.locale);
      sendPage(res, 410, messagePage(tx, tx.expiredTitle, tx.expiredBody));
      return;
    }
    const s = consumed.session;
    const tx = textsFor(s.locale);
    const out = await issueOtaProfile(t, s, ENROLL_OTA);
    const retryLink = (n: string | null) => (n ? { href: `${pathOf(t.key, 'enroll', 's', s.id, 'profile')}?n=${encodeURIComponent(n)}`, label: tx.retryButton } : undefined);
    switch (out.kind) {
      case 'profile':
        res.status(200);
        res.setHeader('Content-Type', PROFILE_CONTENT_TYPE);
        res.setHeader('Content-Disposition', `attachment; filename="${PROFILE_FILENAME}"`);
        res.end(out.body);
        return;
      case 'not_ready':
        sendPage(res, 503, messagePage(tx, tx.notReadyTitle, fill(tx.notReadyBody, { org: t.name }), retryLink(out.nonce)));
        return;
      case 'ended':
        invalidLink(req, res, s.locale);
        return;
      case 'signing_unavailable':
        sendPage(res, 503, messagePage(tx, tx.signingTitle, tx.signingBody));
        return;
      default:
        sendPage(res, 503, messagePage(tx, tx.retryTitle, tx.retryBody, retryLink(out.nonce)));
    }
  }));

  // ── OTA: notice page (no write) ─────────────────────────────────────────────
  router.get('/enroll/:token', route('GET /t/:key/enroll/:token'), perAddress(30), asyncHandler(async (req, res) => {
    const t = locals(res).tenant;
    const token = String(req.params.token ?? '');
    const link = isLinkToken(token) ? await asTenant(t.tenantId, ENROLL_OTA, () => findUsableLink(db, t.tenantId, token)) : null;
    if (!link) { invalidLink(req, res, pickLocale(req.headers['accept-language'], 'fr')); return; }
    const locale = pickLocale(req.headers['accept-language'], link.locale);
    const notice = await asTenant(t.tenantId, ENROLL_OTA, () => noticeOf(db, t, link, locale));
    if (!notice) { invalidLink(req, res, locale); return; }
    const tx = textsFor(locale);
    sendPage(res, 200, noticePage({ t: tx, organization: t.name, ownershipLabel: tx.ownership[link.ownership], notice, action: pathOf(t.key, 'enroll', token) }));
  }));

  router.post('/enroll/:token', route('POST /t/:key/enroll/:token'), perAddress(10), form, asyncHandler(async (req, res) => {
    const t = locals(res).tenant;
    const token = String(req.params.token ?? '');
    const b = (req.body ?? {}) as Record<string, unknown>;
    const fallback = pickLocale(req.headers['accept-language'], 'fr');
    if (!isLinkToken(token)) { invalidLink(req, res, fallback); return; }
    const locale: SurfaceLocale = b.lang === 'en' || b.lang === 'fr' ? b.lang : fallback;
    const versionId = typeof b.notice_version_id === 'string' && UUID_RE.test(b.notice_version_id) ? b.notice_version_id.toLowerCase() : '';
    const tx = textsFor(locale);
    const reshow = async (status: number, changed: boolean): Promise<void> => {
      const link = await asTenant(t.tenantId, ENROLL_OTA, () => findUsableLink(db, t.tenantId, token));
      const notice = link ? await asTenant(t.tenantId, ENROLL_OTA, () => noticeOf(db, t, link, locale)) : null;
      if (!link || !notice) { invalidLink(req, res, locale); return; }
      sendPage(res, status, noticePage({ t: tx, organization: t.name, ownershipLabel: tx.ownership[link.ownership], notice,
        action: pathOf(t.key, 'enroll', token), noticeChanged: changed }));
    };
    if (b.ack !== '1' || !versionId) { await reshow(400, false); return; }
    const out = await acknowledgeLink(t, token, locale, versionId, ENROLL_OTA);
    if (out.kind === 'invalid') { invalidLink(req, res, locale); return; }
    if (out.kind === 'notice_changed') { await reshow(409, true); return; }
    res.redirect(303, `${pathOf(t.key, 'enroll', 's', out.sessionId, 'profile')}?n=${encodeURIComponent(out.nonce)}`);
  }));

  // ── Invitation (account-driven enrollment): the instructions, no data ──────────
  router.get('/byod/invite', route('GET /t/:key/byod/invite'), perAddress(30), (req, res) => {
    const t = locals(res).tenant;
    const tx = textsFor(pickLocale(req.headers['accept-language'], 'fr'));
    sendPage(res, 200, invitePage(tx, t.name, { intro: fill(tx.inviteIntro, { org: t.name }) }));
  });

  // Anything else (route, method): the uniform 404.
  router.use((_req: Request, res: Response) => { notFound(res); });

  // Errors: a body too large or malformed, a failure of the database: no detail, never the URL.
  router.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const status = Number((err as { status?: unknown })?.status ?? (err as { statusCode?: unknown })?.statusCode);
    if (status === 413 || status === 400) { if (!res.headersSent) res.status(status).end(); return; }
    logger.error({ surface: locals(res).route, tenantId: locals(res).tenant?.tenantId ?? null, code: (err as { code?: unknown })?.code,
      name: (err as Error)?.name ?? null }, 'device surface request failed');
    if (!res.headersSent) res.status(500).end();
  });
  return router;
}

