import express, { raw as rawBodyParser, Router, type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../../config';
import { logger } from '../../utils/logger';
import { ENROLL_ADE_WEB, ENROLL_BYOD, ENROLL_OTA } from '../actors';
import { appleTenants } from '../tenants/registry';
import { isMdmKey } from '../tenants/key';
import {
  acknowledgeLink, consumeNonce, findUsableLink, issueOtaProfile, noticeOf, tenantFacts, type TenantFacts,
} from './flow';
import { fill, pickLocale, textsFor, type SurfaceLocale } from './i18n';
import { PROFILE_CONTENT_TYPE, PROFILE_FILENAME } from './mobileconfig';
import { byodAuthPage, invitePage, messagePage, noticePage, PAGE_CSP } from './pages';
import { isAccessToken, isLinkToken, isNonce } from './tokens';
import {
  adeAcknowledgeWeb, adeEnroll, adeIssueAfterWeb, adeNotice, adeOpenWebSession, checkMachineInfo, findAdeProfile,
  MAX_MACHINE_INFO_BYTES, type AdeIssueOutcome, type AdeProfileFacts,
} from './ade';
import { byodAuthenticate, byodEnroll, byodNotice, byodServes, checkFormToken, newFormToken, normalizeAccount } from './byod';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { vppNotifyHandlers } from '../integrations/vpp.routes.public';
import { isNoticeIncomplete } from '../../privacy/notice/errors';

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
//   POST /t/:key/ade/:profileId/enroll         ADE: the MachineInfo → the profile, 403 (lot C2)
//   GET  /t/:key/ade/:profileId/web            ADE: the web view of the setup assistant (notice)
//   POST /t/:key/ade/:profileId/web            ADE: acknowledgement → the profile
//   GET  /t/:key/byod/discovery                BYOD: Apple-hosted discovery (JSON)
//   POST /t/:key/byod/enroll                   BYOD: 401 (sign in) or, with the bearer, the profile
//   GET  /t/:key/byod/auth, POST               BYOD: web view of the device (notice, invitation code) → 303
//   POST /t/:key/vpp/:ref/notify              Apps and Books: notifications (lot C4, vpp.routes.public.ts)
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
  /** The request carried a valid MachineInfo, access token or web session (decision C2 B of 19/10/2026): it does not
   *  count against the cap of the key. */
  credentialOk?: boolean;
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

/** The cap of a key is this many times the budget of one address (decision C2 A of 19/10/2026). */
export const KEY_CAP_FACTOR = 10;

/**
 * The limiters of the ADE and BYOD routes (§10.8; owners' decision of 19/10/2026 on the review of lot C2, options A
 * and B): the key is public, so a limiter per key alone let one third party block the enrollments of the whole
 * tenant (429).
 *   A. `max` requests a minute per (key, address): a third party exhausts its own budget only;
 *   B. a cap per key, KEY_CAP_FACTOR times higher, that counts only the requests without a valid MachineInfo, access
 *      token or web session (res.locals.credentialOk, set by the route once checked): the enrollments that succeed
 *      never fill it; only many addresses sending invalid requests together reach it.
 * The address keys the limiters only, never logged.
 */
const perKey = (max: number): RequestHandler[] => [
  rateLimit({
    windowMs: 60_000, limit: max, standardHeaders: false, legacyHeaders: false,
    keyGenerator: (req) => `ka:${String(req.params.key ?? '')}|${req.ip ?? 'unknown'}`, handler: (_req, res) => { res.status(429).end(); },
    validate: { xForwardedForHeader: false, trustProxy: false },
  }),
  rateLimit({
    windowMs: 60_000, limit: max * KEY_CAP_FACTOR, standardHeaders: false, legacyHeaders: false,
    keyGenerator: (req) => `k:${String(req.params.key ?? '')}`, handler: (_req, res) => { res.status(429).end(); },
    skipSuccessfulRequests: true,
    requestWasSuccessful: (_req, res) => locals(res).credentialOk === true,
    validate: { xForwardedForHeader: false, trustProxy: false },
  }),
];

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

  // ── ADE (§10.4): the url of the profile, its web view ───────────────────────────
  const raw64 = rawBodyParser({ type: () => true, limit: MAX_MACHINE_INFO_BYTES, inflate: false });
  const forbidden = (res: Response): void => { if (!res.headersSent) res.status(403).end(); };
  const unavailable = (res: Response): void => { if (!res.headersSent) res.status(503).end(); };
  const sendProfile = (res: Response, body: Buffer): void => {
    res.status(200);
    res.setHeader('Content-Type', PROFILE_CONTENT_TYPE);
    res.setHeader('Content-Disposition', `attachment; filename="${PROFILE_FILENAME}"`);
    res.end(body);
  };
  /** The setup assistant offers the update (§10.4 step 2) [J1, J-4]. */
  const osUpdate = (req: Request, res: Response, profile: AdeProfileFacts, required: string): void => {
    const tx = textsFor(pickLocale(req.headers['accept-language'], profile.locale));
    res.status(403).type('application/json').send(JSON.stringify({
      code: 'com.apple.softwareupdate.required', description: tx.osUpdateRequired, details: { OSVersion: required },
    }));
  };
  const adeProfileOf = async (req: Request, res: Response): Promise<AdeProfileFacts | null> => {
    const p = await findAdeProfile(locals(res).tenant.tenantId, String(req.params.profileId ?? ''), ENROLL_ADE_WEB);
    if (!p) notFound(res);
    return p;
  };
  const restartPage = (res: Response, locale: SurfaceLocale): void => {
    const tx = textsFor(locale);
    sendPage(res, 410, messagePage(tx, tx.adeRestartTitle, tx.adeRestartBody));
  };

  router.post('/ade/:profileId/enroll', route('POST /t/:key/ade/:profileId/enroll'), ...perKey(60), raw64, asyncHandler(async (req, res) => {
    const t = locals(res).tenant;
    const profile = await adeProfileOf(req, res);
    if (!profile) return;
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    if (body.length === 0) { forbidden(res); return; }
    const mi = await checkMachineInfo(t, profile, body.toString('base64'), ENROLL_ADE_WEB);
    if (mi.kind === 'refused') { forbidden(res); return; }
    locals(res).credentialOk = true;
    if (mi.kind === 'unavailable') { unavailable(res); return; }
    if (mi.kind === 'os_update') { osUpdate(req, res, profile, mi.required); return; }
    const out: AdeIssueOutcome = await adeEnroll(t, profile, mi, pickLocale(req.headers['accept-language'], profile.locale), ENROLL_ADE_WEB);
    if (out.kind === 'profile') { sendProfile(res, out.body); return; }
    if (out.kind === 'forbidden') { forbidden(res); return; }
    unavailable(res);
  }));

  router.get('/ade/:profileId/web', route('GET /t/:key/ade/:profileId/web'), ...perKey(60), asyncHandler(async (req, res) => {
    const t = locals(res).tenant;
    const profile = await adeProfileOf(req, res);
    if (!profile) return;
    const header = req.headers['x-apple-aspen-deviceinfo'];
    const b64 = typeof header === 'string' ? header.trim() : '';
    if (!b64 || b64.length > Math.ceil(MAX_MACHINE_INFO_BYTES / 3) * 4 + 4) { forbidden(res); return; }
    const mi = await checkMachineInfo(t, profile, b64, ENROLL_ADE_WEB);
    if (mi.kind === 'refused') { forbidden(res); return; }
    locals(res).credentialOk = true;
    if (mi.kind === 'unavailable') { unavailable(res); return; }
    if (mi.kind === 'os_update') { osUpdate(req, res, profile, mi.required); return; }
    const locale = pickLocale(req.headers['accept-language'], profile.locale);
    const notice = await adeNotice(t, profile, locale, ENROLL_ADE_WEB);
    if (!notice) { forbidden(res); return; }
    const opened = await adeOpenWebSession(t, profile, mi, locale, ENROLL_ADE_WEB);
    const tx = textsFor(locale);
    sendPage(res, 200, noticePage({ t: tx, organization: t.name, ownershipLabel: tx.ownership[profile.ownership], notice,
      action: pathOf(t.key, 'ade', profile.id, 'web'), hidden: { session: opened.sessionId, form_token: opened.formToken } }));
  }));

  router.post('/ade/:profileId/web', route('POST /t/:key/ade/:profileId/web'), ...perKey(30), form, asyncHandler(async (req, res) => {
    const t = locals(res).tenant;
    const profile = await adeProfileOf(req, res);
    if (!profile) return;
    const b = (req.body ?? {}) as Record<string, unknown>;
    const locale: SurfaceLocale = b.lang === 'en' || b.lang === 'fr' ? b.lang : pickLocale(req.headers['accept-language'], profile.locale);
    const sessionId = typeof b.session === 'string' && UUID_RE.test(b.session) ? b.session.toLowerCase() : '';
    const formToken = isNonce(b.form_token) ? b.form_token : '';
    const versionId = typeof b.notice_version_id === 'string' && UUID_RE.test(b.notice_version_id) ? b.notice_version_id.toLowerCase() : '';
    if (!sessionId || !formToken) { restartPage(res, locale); return; }
    const tx = textsFor(locale);
    if (b.ack !== '1' || !versionId) {
      // Not acknowledged: the page again, with the same session (its token is still the one of the page).
      const notice = await adeNotice(t, profile, locale, ENROLL_ADE_WEB);
      if (!notice) { forbidden(res); return; }
      sendPage(res, 400, noticePage({ t: tx, organization: t.name, ownershipLabel: tx.ownership[profile.ownership], notice,
        action: pathOf(t.key, 'ade', profile.id, 'web'), hidden: { session: sessionId, form_token: formToken } }));
      return;
    }
    const ack = await adeAcknowledgeWeb(t, profile, sessionId, formToken, versionId, locale, ENROLL_ADE_WEB);
    if (ack.kind === 'invalid' || ack.kind === 'expired') { restartPage(res, locale); return; }
    locals(res).credentialOk = true;
    if (ack.kind === 'notice_changed') {
      if (!ack.notice) { forbidden(res); return; }
      sendPage(res, 409, noticePage({ t: tx, organization: t.name, ownershipLabel: tx.ownership[profile.ownership], notice: ack.notice,
        action: pathOf(t.key, 'ade', profile.id, 'web'), hidden: { session: sessionId, form_token: ack.formToken }, noticeChanged: true }));
      return;
    }
    const out = await adeIssueAfterWeb(t, ack.session, ENROLL_ADE_WEB);
    switch (out.kind) {
      case 'profile': sendProfile(res, out.body); return;
      case 'restart': case 'forbidden': restartPage(res, locale); return;
      case 'not_ready': sendPage(res, 503, messagePage(tx, tx.notReadyTitle, fill(tx.notReadyBody, { org: t.name }))); return;
      case 'signing_unavailable': sendPage(res, 503, messagePage(tx, tx.signingTitle, tx.signingBody)); return;
      default: sendPage(res, 503, messagePage(tx, tx.retryTitle, tx.adeRestartBody));
    }
  }));

  // ── Account-driven enrollment (§10.5) ───────────────────────────────────────
  const byodGate = async (res: Response): Promise<boolean> => {
    const ok = config.apple.mdmPublicBase !== null && await byodServes(locals(res).tenant.tenantId, ENROLL_BYOD);
    if (!ok) notFound(res);
    return ok;
  };
  const surfaceUrl = (key: string, ...parts: string[]): string => `${config.apple.mdmPublicBase}${pathOf(key, ...parts)}`;

  router.get('/byod/discovery', route('GET /t/:key/byod/discovery'), ...perKey(120), asyncHandler(async (_req, res) => {
    const t = locals(res).tenant;
    if (!(await byodGate(res))) return;
    res.status(200).type('application/json')
      .send(JSON.stringify({ Servers: [{ Version: 'mdm-byod', BaseURL: surfaceUrl(t.key, 'byod', 'enroll') }] }));
  }));

  router.post('/byod/enroll', route('POST /t/:key/byod/enroll'), ...perKey(60), raw64, asyncHandler(async (req, res) => {
    const t = locals(res).tenant;
    if (!(await byodGate(res))) return;
    const signIn = (): void => {
      res.setHeader('WWW-Authenticate', `Bearer method="apple-as-web" url="${surfaceUrl(t.key, 'byod', 'auth')}"`);
      res.status(401).end();
    };
    const m = /^Bearer\s+(\S+)$/.exec(String(req.headers.authorization ?? ''));
    if (!m || !isAccessToken(m[1])) { signIn(); return; }
    const out = await byodEnroll(t, m[1], ENROLL_BYOD);
    if (out.kind === 'unauthorized') { signIn(); return; }
    locals(res).credentialOk = true;
    if (out.kind === 'profile') { sendProfile(res, out.body); return; }
    unavailable(res);
  }));

  const byodAuthLimiter = perAddress(10);
  const byodPage = async (res: Response, status: number, o: { locale: SurfaceLocale; account: string | null; wrongCode?: boolean; noticeChanged?: boolean }) => {
    const t = locals(res).tenant;
    const notice = await byodNotice(t, o.locale, ENROLL_BYOD);
    if (!notice) { notFound(res); return; }
    const tx = textsFor(o.locale);
    sendPage(res, status, byodAuthPage({ t: tx, organization: t.name, ownershipLabel: tx.ownership.personal, notice,
      action: pathOf(t.key, 'byod', 'auth'), account: o.account, formToken: newFormToken(t.key, o.account),
      wrongCode: o.wrongCode, noticeChanged: o.noticeChanged }));
  };

  router.get('/byod/auth', route('GET /t/:key/byod/auth'), byodAuthLimiter, asyncHandler(async (req, res) => {
    if (!(await byodGate(res))) return;
    const account = normalizeAccount(req.query['user-identifier']);
    await byodPage(res, 200, { locale: pickLocale(req.headers['accept-language'], 'fr'), account });
  }));

  router.post('/byod/auth', route('POST /t/:key/byod/auth'), byodAuthLimiter, form, asyncHandler(async (req, res) => {
    const t = locals(res).tenant;
    if (!(await byodGate(res))) return;
    const b = (req.body ?? {}) as Record<string, unknown>;
    const locale: SurfaceLocale = b.lang === 'en' || b.lang === 'fr' ? b.lang : pickLocale(req.headers['accept-language'], 'fr');
    const account = normalizeAccount(b.user_identifier);
    const versionId = typeof b.notice_version_id === 'string' && UUID_RE.test(b.notice_version_id) ? b.notice_version_id.toLowerCase() : '';
    // The form token binds the account of the web view (or none: typed in the page) to this answer.
    const tokenOk = !!account && (checkFormToken(b.form_token, t.key, account) || checkFormToken(b.form_token, t.key, null));
    if (!account || !tokenOk || b.ack !== '1' || !versionId) { await byodPage(res, 400, { locale, account }); return; }
    // The address counts the wrong codes per invitation (decision of 19/10/2026); it is never stored in clear.
    const out = await byodAuthenticate(t, { account, code: b.code, noticeVersionId: versionId, locale, address: req.ip ?? 'unknown' }, ENROLL_BYOD);
    if (out.kind === 'address_locked') { tooManyHandler(req, res); return; }
    if (out.kind === 'notice_changed') { await byodPage(res, 409, { locale, account, noticeChanged: true }); return; }
    if (out.kind === 'wrong_code') { await byodPage(res, 400, { locale, account, wrongCode: true }); return; }
    // The bearer goes back to the device by the redirection only (no body that would repeat it).
    res.status(303).setHeader('Location', `apple-remotemanagement-user-login://authentication-results?access-token=${encodeURIComponent(out.accessToken)}`);
    res.end();
  }));

  // ── Apps and Books: the notifications of Apple (lot C4) ───────────────────
  router.post('/vpp/:ref/notify', route('POST /t/:key/vpp/:ref/notify'), ...vppNotifyHandlers((res) => locals(res).tenant.tenantId));

  // Anything else (route, method): the uniform 404.
  router.use((_req: Request, res: Response) => { notFound(res); });

  // Errors: a body too large or malformed, a failure of the database: no detail, never the URL. A notice not complete
  // outside the laboratory (P0-13 T5, D7, thrown by the notice provider): the page of an enrollment not open yet.
  router.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    if (isNoticeIncomplete(err)) {
      const tx = textsFor(pickLocale(req.headers['accept-language'], 'fr'));
      if (!res.headersSent) sendPage(res, 503, messagePage(tx, tx.noticeIncompleteTitle, fill(tx.noticeIncompleteBody, { org: locals(res).tenant?.name ?? '' })));
      return;
    }
    const status = Number((err as { status?: unknown })?.status ?? (err as { statusCode?: unknown })?.statusCode);
    if (status === 413 || status === 400) { if (!res.headersSent) res.status(status).end(); return; }
    logger.error({ surface: locals(res).route, tenantId: locals(res).tenant?.tenantId ?? null, code: (err as { code?: unknown })?.code,
      name: (err as Error)?.name ?? null }, 'device surface request failed');
    if (!res.headersSent) res.status(500).end();
  });
  return router;
}

