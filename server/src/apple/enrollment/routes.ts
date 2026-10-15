import { Router, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import type { Knex } from 'knex';
import { z } from 'zod';
import {
  ENROLLMENT_LIMITS, ENROLLMENT_SESSION_STATES, ENROLLMENT_TOKEN_KINDS, ENROLLMENT_TOKEN_STATES,
  type EnrollmentInvitationCreated, type EnrollmentLinkCreated, type EnrollmentMailOutcome,
} from '@obligarth/shared';
import { audit } from '../../audit';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { realtime } from '../realtime';
import { appleTenants } from '../tenants/registry';
import { isMailAddress, sendEnrollmentMail } from './mail';
import {
  archiveProfile, createInvitation, createLink, createProfile, getProfile, linkQrPng, listProfiles, listSessions, listTokens,
  revokeToken, surfaceBase, updateProfile,
} from './service';
import { checkProfile, ProfileBody, ProfileRuleError } from './settings';

// =============================================================================
// Console API of the enrollment (docs: integration-apple-edge §10.9), mounted
// at /api/apple/enrollment behind the session and the tenant; tenant
// capability mdm.enrollment.manage for every route.
//   GET  /profiles, /profiles/:id         profiles not archived (?archived=1: all)
//   POST /profiles, PUT /profiles/:id     version + 1; audit apple.enrollment_profile_saved
//   POST /profiles/:id/archive            refused for the default ADE profile
//   POST /profiles/:id/links              OTA: { label?, maxUses?, ttlHours?, email? } → 201 (token shown once)
//   POST /profiles/:id/invitations        BYOD: { managedAppleAccount, label?, ttlHours?, email?, endUserId? } → 201
//   GET  /tokens                          ?profileId=&kind=&state=: prefix, uses, expiry, state; never the token
//   POST /tokens/:id/revoke               audit apple.enrollment_token_revoked (in the transaction)
//   GET  /sessions                        ?state=&cursor=
// A Managed Apple Account is shown to the tenant's administrators only. A
// link or an invitation is e-mailed when a recipient is given and a channel
// is configured (decision of 15/10): its outcome is in the answer.
// The ADE profiles are defined at Apple by enrollment.ade-profiles-sync (lot
// C2): their version tells it what changed.
// =============================================================================

const manage = requireTenantCapability('mdm.enrollment.manage');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const keyOfUser = (req: Request): string => `u:${req.session?.userId ?? 'anonymous'}`;
/** 30 links or invitations a minute and per user. */
const createLimiter = rateLimit({
  windowMs: 60_000, limit: 30, keyGenerator: keyOfUser, standardHeaders: true, legacyHeaders: false,
  handler: (_q, res) => { res.status(429).json({ success: false, error: 'Too many requests', code: 'rateLimited' }); },
});

const L = ENROLLMENT_LIMITS;
const LABEL = z.string().trim().min(1).max(200).nullable().optional();
const EMAIL = z.string().trim().max(320).refine(isMailAddress, 'invalid e-mail address').optional();
const LinkBody = z.object({
  label: LABEL,
  maxUses: z.number().int().min(L.linkMaxUses.min).max(L.linkMaxUses.max).optional(),
  ttlHours: z.number().int().min(L.linkTtlHours.min).max(L.linkTtlHours.max).optional(),
  email: EMAIL,
}).strict();
const InvitationBody = z.object({
  managedAppleAccount: z.string().trim().toLowerCase().max(320).refine(isMailAddress, 'invalid Managed Apple Account'),
  label: LABEL,
  ttlHours: z.number().int().min(L.invitationTtlHours.min).max(L.invitationTtlHours.max).optional(),
  email: EMAIL,
  endUserId: z.number().int().positive().nullable().optional(),
}).strict();
const TokensQuery = z.object({
  profileId: z.string().regex(UUID_RE).optional(),
  kind: z.enum(ENROLLMENT_TOKEN_KINDS).optional(),
  state: z.enum(ENROLLMENT_TOKEN_STATES).optional(),
}).strict();
const SessionsQuery = z.object({ state: z.enum(ENROLLMENT_SESSION_STATES).optional(), cursor: z.string().max(40).optional() }).strict();

function parse<S extends z.ZodTypeAny>(schema: S, v: unknown): z.infer<S> {
  const r = schema.safeParse(v ?? {});
  if (!r.success) {
    const i = r.error.issues[0];
    throw new AppError(400, `${i?.path.join('.') || 'request'}: ${i?.message ?? 'invalid'}`, 'invalidRequest');
  }
  return r.data;
}

function idParam(req: Request): string {
  const id = String(req.params.id ?? '');
  if (!UUID_RE.test(id)) throw new AppError(404, 'Not found', 'enrollmentProfileNotFound');
  return id.toLowerCase();
}

function checked(body: unknown) {
  try {
    return checkProfile(parse(ProfileBody, body));
  } catch (err) {
    if (err instanceof ProfileRuleError) throw new AppError(400, err.message, err.code);
    throw err;
  }
}

/** Is the caller an administrator of the tenant (platform administrator, or tenant role admin)? */
async function isTenantAdmin(req: Request): Promise<boolean> {
  if (req.session.role === 'admin') return true;
  const ut = await db('user_tenants').where({ user_id: req.session.userId, tenant_id: req.tenantId }).first('role') as { role: string } | undefined;
  return ut?.role === 'admin';
}

/** The public base, the tenant's key and display name, for the URLs of links and invitations (503 when the
 *  integration is off, 409 while the tenant has no key). */
async function urlParts(trx: Knex.Transaction, tenantId: number): Promise<{ base: string; key: string; tenant: { name: string } }> {
  const base = surfaceBase();
  const key = await appleTenants.keyOf(tenantId, trx);
  const tenant = await trx('tenants').where({ id: tenantId }).first('name') as { name: string };
  return { base, key, tenant };
}

type Handler = (req: Request, res: Response) => Promise<void>;
const h = (fn: Handler) => (req: Request, res: Response, next: (err?: unknown) => void): void => { fn(req, res).catch(next); };

export function createEnrollmentRouter(): Router {
  const router = Router();
  router.use(manage);

  router.get('/profiles', h(async (req, res) => {
    res.json({ data: await listProfiles(db, req.tenantId!, req.query.archived === '1') });
  }));

  router.get('/profiles/:id', h(async (req, res) => {
    res.json({ data: await getProfile(db, req.tenantId!, idParam(req)) });
  }));

  router.post('/profiles', h(async (req, res) => {
    const tenantId = req.tenantId!;
    const p = checked(req.body);
    const id = await db.transaction((trx) => createProfile(trx, tenantId, req.session.userId!, p));
    await audit.append({
      tenantId, action: 'apple.enrollment_profile_saved', target: { type: 'enrollment_profile', id },
      details: { created: true, method: p.method, ownership: p.ownership, version: 1 },
    }, await audit.fromRequest(req, tenantId));
    res.status(201).json({ data: await getProfile(db, tenantId, id) });
  }));

  router.put('/profiles/:id', h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = idParam(req);
    const p = checked(req.body);
    const ended: string[] = [];
    const version = await db.transaction((trx) => updateProfile(trx, tenantId, req.session.userId!, id, p, ended));
    realtime.sessionChanged(tenantId, ...ended);
    await audit.append({
      tenantId, action: 'apple.enrollment_profile_saved', target: { type: 'enrollment_profile', id },
      details: { method: p.method, ownership: p.ownership, version },
    }, await audit.fromRequest(req, tenantId));
    res.json({ data: await getProfile(db, tenantId, id) });
  }));

  router.post('/profiles/:id/archive', h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = idParam(req);
    const ended: string[] = [];
    const version = await db.transaction((trx) => archiveProfile(trx, tenantId, req.session.userId!, id, ended));
    realtime.sessionChanged(tenantId, ...ended);
    await audit.append({
      tenantId, action: 'apple.enrollment_profile_saved', target: { type: 'enrollment_profile', id }, details: { archived: true, version, endedSessions: ended.length },
    }, await audit.fromRequest(req, tenantId));
    res.json({ data: await getProfile(db, tenantId, id) });
  }));

  router.post('/profiles/:id/links', createLimiter, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = idParam(req);
    const b = parse(LinkBody, req.body);
    // The profile first (404 for a profile out of reach), then what the URL needs: a failure rolls the link back.
    const { link, base, key, tenant } = await db.transaction(async (trx) => {
      const l = await createLink(trx, tenantId, req.session.userId!, id, b);
      return { link: l, ...(await urlParts(trx, tenantId)) };
    });
    const url = `${base}/t/${key}/enroll/${link.token}`;
    const mail: EnrollmentMailOutcome = b.email
      ? await sendEnrollmentMail(tenantId, { to: b.email, locale: link.locale, organization: String(tenant.name), expiresAt: link.expiresAt, link: { url } })
      : 'not_requested';
    await audit.append({
      tenantId, action: 'apple.enrollment_token_created', target: { type: 'enrollment_token', id: link.id },
      details: { kind: 'link', profileId: id, prefix: link.prefix, maxUses: link.maxUses, ttlHours: link.ttlHours, mail },
    }, await audit.fromRequest(req, tenantId));
    const out: EnrollmentLinkCreated = {
      id: link.id, token: link.token, url, qrPng: await linkQrPng(url), prefix: link.prefix, maxUses: link.maxUses,
      expiresAt: link.expiresAt.toISOString(), mail,
    };
    res.status(201).json({ data: out });
  }));

  router.post('/profiles/:id/invitations', createLimiter, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = idParam(req);
    const b = parse(InvitationBody, req.body);
    const { inv, base, key, tenant } = await db.transaction(async (trx) => {
      const i = await createInvitation(trx, tenantId, req.session.userId!, id, b);
      return { inv: i, ...(await urlParts(trx, tenantId)) };
    });
    const link = `${base}/t/${key}/byod/invite`;
    const mail: EnrollmentMailOutcome = b.email
      ? await sendEnrollmentMail(tenantId, { to: b.email, locale: inv.locale, organization: String(tenant.name), expiresAt: inv.expiresAt,
        invitation: { code: inv.code, account: b.managedAppleAccount, url: link } })
      : 'not_requested';
    await audit.append({
      tenantId, action: 'apple.enrollment_token_created', target: { type: 'enrollment_token', id: inv.id },
      details: { kind: 'invitation', profileId: id, prefix: inv.prefix, ttlHours: inv.ttlHours, mail },
    }, await audit.fromRequest(req, tenantId));
    const out: EnrollmentInvitationCreated = { id: inv.id, code: inv.code, link, prefix: inv.prefix, expiresAt: inv.expiresAt.toISOString(), mail };
    res.status(201).json({ data: out });
  }));

  router.get('/tokens', h(async (req, res) => {
    const q = parse(TokensQuery, req.query);
    res.json({ data: await listTokens(db, req.tenantId!, q, await isTenantAdmin(req)) });
  }));

  router.post('/tokens/:id/revoke', h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = String(req.params.id ?? '');
    if (!UUID_RE.test(id)) throw new AppError(404, 'Not found', 'enrollmentTokenNotFound');
    const auditCtx = await audit.fromRequest(req, tenantId);
    const out = await db.transaction(async (trx) => {
      const r = await revokeToken(trx, tenantId, req.session.userId!, id.toLowerCase());
      if (r && !r.already) {
        await audit.appendInTx(trx, {
          tenantId, action: 'apple.enrollment_token_revoked', target: { type: 'enrollment_token', id: id.toLowerCase() },
          details: { kind: r.kind, prefix: r.prefix, profileId: r.profileId, endedSessions: r.endedSessions.length },
        }, auditCtx);
      }
      return r;
    });
    if (!out) throw new AppError(404, 'Not found', 'enrollmentTokenNotFound');
    realtime.sessionChanged(tenantId, ...out.endedSessions);
    res.json({ data: { id: id.toLowerCase(), revoked: true } });
  }));

  router.get('/sessions', h(async (req, res) => {
    const q = parse(SessionsQuery, req.query);
    const page = await listSessions(db, req.tenantId!, q, await isTenantAdmin(req));
    res.json({ data: page.items, nextCursor: page.nextCursor });
  }));

  return router;
}
