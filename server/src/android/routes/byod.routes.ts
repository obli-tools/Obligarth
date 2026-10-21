// /api/android (tenant router: requireAuth, requireTenant), BYOD by link (lot AN-F1, sections 10.1, 10.5):
//   POST /byod/invitations              invites an end user: { profileId, endUserId, label?, ttlHours?, locale?, email? } →
//                                       201 { id, code (once), prefix, link, expiresAt, mail }
//   GET  /byod/invitations              the tenant's invitations (never a code)
//   POST /byod/invitations/:id/revoke   revokes an invitation (and its token at Google), audited
//   GET  /byod/notice?locale=fr|en      the notice of a personal device, as the device surface shows it to the user
// Capability: mdm.enrollment.manage (AN41, §22.8). Mounted under /api/android by routes/index.ts (lot AN-A2). The
// code is in the body of the answer only, with Cache-Control no-store; never logged. The link names the notice page of
// the device surface (<base>/a/<MDM key>/byod), which carries no secret.
import { Router, type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import {
  ANDROID_BYOD_INVITATION_STATES, ANDROID_BYOD_INVITATION_TTL_HOURS, type AndroidByodInvitationCreated, type AndroidByodMailOutcome, type AndroidByodNoticeView,
} from '@obligarth/shared';
import { audit } from '../../audit';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { appleTenants } from '../../apple/tenants/registry';
import { ByodError, byodNotice, createInvitation, listInvitations, revokeInvitation, tenantFactsOf } from '../byod/invitations';
import { sendByodMail } from '../byod/mail';
import { TokenError } from '../enrollment/tokens';
import { toRouteError } from './enterprise.routes';

const L = ANDROID_BYOD_INVITATION_TTL_HOURS;
const CreateBody = z.object({
  profileId: z.string().uuid(),
  endUserId: z.number().int().positive(),
  label: z.string().trim().min(1).max(200).optional(),
  ttlHours: z.number().int().min(L.min).max(L.max).optional(),
  locale: z.enum(['fr', 'en']).optional(),
  email: z.string().trim().max(320).optional(),
}).strict();
const ListQuery = z.object({ state: z.enum(ANDROID_BYOD_INVITATION_STATES).optional() }).strict();
const UUID = z.string().uuid();
const NoticeQuery = z.object({ locale: z.enum(['fr', 'en']).optional() }).strict();

let surfaceBase: () => string | null = () => null;
/** The public base of the device surface (https://mdm.<domain>): config.apple.mdmPublicBase of lot C, plugged at the
 *  junction; null until then (503 androidByodSurfaceUnavailable: an invitation without a page to open is useless). */
export function setByodSurfaceBase(fn: () => string | null): void { surfaceBase = fn; }

/** The link of an invitation: the notice page of the device surface of the tenant (no secret in it). */
export const byodLink = (base: string, key: string): string => `${base.replace(/\/+$/, '')}/a/${key}/byod`;

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function routeError(err: unknown): unknown {
  if (err instanceof ByodError || err instanceof TokenError) return new AppError(err.status, err.message, err.code);
  return toRouteError(err);
}

export function createAndroidByodRouter(): Router {
  const router = Router();
  const capability = requireTenantCapability('mdm.enrollment.manage');
  /** 30 invitations a minute and per user (lot C's rule for links and invitations). */
  const createLimiter = rateLimit({
    windowMs: 60_000, limit: 30, standardHeaders: false, legacyHeaders: false,
    keyGenerator: (req) => `byod:${String(req.session?.userId ?? 'anonymous')}`,
    handler: (_req, res) => { res.status(429).json({ success: false, error: 'Too many requests', code: 'rateLimited' }); },
    validate: { xForwardedForHeader: false, trustProxy: false },
  });

  router.post('/byod/invitations', capability, createLimiter, wrap(async (req, res) => {
    const parsed = CreateBody.safeParse(req.body);
    if (!parsed.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    const b = parsed.data;
    const tenantId = Number(req.tenantId);
    const userId = Number(req.session.userId);
    const base = surfaceBase();
    if (!base) throw new AppError(503, 'The device surface is not configured', 'androidByodSurfaceUnavailable');
    const key = await appleTenants.keyOrNull(tenantId);
    if (!key) throw new AppError(409, 'The tenant has no MDM key yet', 'androidMdmKeyMissing');
    try {
      const ctx = await audit.fromRequest(req, tenantId);
      const inv = await createInvitation(tenantId, userId, { profileId: b.profileId, endUserId: b.endUserId, label: b.label, ttlHours: b.ttlHours,
        locale: b.locale }, ctx);
      const link = byodLink(base, key);
      let mail: AndroidByodMailOutcome = 'not_requested';
      if (b.email) {
        const tenant = await db('tenants').where({ id: tenantId }).first('name') as { name: string };
        mail = await sendByodMail(tenantId, { to: b.email, locale: inv.locale, organization: String(tenant.name), expiresAt: inv.expiresAt, code: inv.code, url: link });
      }
      const out: AndroidByodInvitationCreated = { id: inv.id, code: inv.code, prefix: inv.prefix, link, expiresAt: inv.expiresAt.toISOString(), mail };
      res.setHeader('Cache-Control', 'no-store');
      res.status(201).json({ success: true, data: out });
    } catch (err) { throw routeError(err); }
  }));

  router.get('/byod/invitations', capability, wrap(async (req, res) => {
    const q = ListQuery.safeParse(req.query);
    if (!q.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    res.json({ success: true, data: await listInvitations(Number(req.tenantId), Number(req.session.userId), q.data) });
  }));

  // The notice the user acknowledges on the device before the Google link (section 10.5, USR-01): the same provider
  // and the same text as the device surface, for the administrator to know what the user reads.
  router.get('/byod/notice', capability, wrap(async (req, res) => {
    const q = NoticeQuery.safeParse(req.query);
    if (!q.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    const facts = await tenantFactsOf(Number(req.tenantId));
    const notice = facts ? await byodNotice(facts, q.data.locale ?? 'fr') : null;
    if (!notice) throw new AppError(503, 'No notice is available', 'androidByodNoticeUnavailable');
    const out: AndroidByodNoticeView = {
      versionId: notice.versionId, locale: notice.locale, title: notice.title, sections: notice.sections, consentSummary: notice.consentSummary,
      contact: notice.contact,
    };
    res.json({ success: true, data: out });
  }));

  router.post('/byod/invitations/:id/revoke', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const tenantId = Number(req.tenantId);
    try {
      const r = await revokeInvitation(tenantId, Number(req.session.userId), id.data.toLowerCase(), await audit.fromRequest(req, tenantId));
      res.json({ success: true, data: { result: r } });
    } catch (err) { throw routeError(err); }
  }));
  return router;
}
