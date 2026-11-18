import type { NextFunction, Request, Response } from 'express';
import { delegationPolicy } from '../../middleware/delegatedAuth';
import { asIdentity } from '../../db/context';
import { delegationVerifyService, type DelegationClaims } from '../../services/delegationVerify.service';
import { tenantService } from '../../services/tenant.service';
import { WindowLimiter } from '../../legacyAgent/limits';
import { logger } from '../../utils/logger';
import { auditRejected } from './audit';
import { OBLIWATCH_ACTOR, OBLIWATCH_APP, OBLIWATCH_RPM } from './config';
import { consumeJti } from './jti';

// =============================================================================
// Authentication of the Obliwatch router (plan §0 F1, F2, F4, F7). Two kinds of token, never interchangeable:
//   app   sub 'app:obliwatch', azp 'obliwatch', scp 'read' (pair obliwatch:obligarth at Obligate): the read API
//         (GET /ping, /access-keys and, lot L2, /devices…). A user token there: 403 user_token_refused.
//   user  sub = the Obligate id of an analyst, azp 'obliwatch' (delegation obliwatch → obligarth): the action requests
//         of lot L5. Resolved to the LOCAL user (never provisioned: 403 subject_unknown), member of the tenant of
//         `ost`; a platform administrator only with OBLIGATE_DELEGATION_ALLOW_ADMIN=true. An app token there:
//         403 app_token_refused.
// Then, for both: the tenant from the SIGNED slug (403 tenant_unknown), the limit of the (app, tenant) pair (429 with
// Retry-After), and the jti burned (401 replayed; 503 when the store cannot be written). The consent is checked by
// the route (consent.ts), after this.
// Header: Authorization: Bearer <JWS> (Obliwatch's client) or X-Obli-Delegation: <JWS> (the suite's delegation
// header); both at once: 401 credentials_ambiguous.
// =============================================================================

export type ObliwatchTokenKind = 'app' | 'user';

export interface ObliwatchCaller {
  kind: ObliwatchTokenKind;
  azp: string;
  jti: string;
  kid: string;
  /** The signed tenant slug and the local tenant it names. */
  ost: string;
  tenantId: number;
  /** Kind 'user' only: the local account the analyst resolves to. */
  user?: { id: number; username: string; role: string };
}

declare global {
  namespace Express {
    interface Request {
      obliwatch?: ObliwatchCaller;
    }
  }
}

/** The status of each refusal. 401: the token itself; 403: a genuine token the policy refuses; 503: our side. */
const STATUS: Record<string, number> = {
  not_configured: 503, jwks_unavailable: 503, internal_error: 503, jti_store_unavailable: 503,
  token_missing: 401, credentials_ambiguous: 401, replayed: 401,
  user_token_refused: 403, app_token_refused: 403, azp_not_allowed: 403, subject_unknown: 403, subject_inactive: 403,
  subject_admin_not_allowed: 403, tenant_unknown: 403, tenant_not_permitted: 403,
  rate_limited: 429,
};

const MESSAGE: Record<number, string> = {
  401: 'Invalid delegation token', 403: 'Access refused', 429: 'Too many requests', 503: 'Temporarily unavailable',
};

/** The JSON body of every refusal of the router (never the detail of a check that would help probing). */
export function sendError(res: Response, status: number, code: string, message?: string): void {
  res.status(status).json({ error: code, message: message ?? MESSAGE[status] ?? 'Refused' });
}

function refuse(
  req: Request, res: Response, code: string,
  opts: { claims?: DelegationClaims | null; tenantId?: number | null; retryAfter?: number } = {},
): void {
  const status = STATUS[code] ?? 401;
  // 429 is not a security event: never journaled (it would flood the journal under the very load it stops).
  if (status !== 429) {
    auditRejected(req, { reason: code, tenantId: opts.tenantId ?? null, jti: opts.claims?.jti, azp: opts.claims?.azp, sub: opts.claims?.sub });
    logger.warn({ reason: code, azp: opts.claims?.azp, jti: opts.claims?.jti, route: `${req.baseUrl}${req.path}` }, '[obliwatch] refused');
  }
  if (opts.retryAfter) res.setHeader('Retry-After', String(opts.retryAfter));
  sendError(res, status, code);
}

/** The token of the request: Bearer or X-Obli-Delegation, never both. */
function tokenOf(req: Request): { token: string } | { error: 'token_missing' | 'credentials_ambiguous' } {
  const auth = typeof req.headers.authorization === 'string' ? req.headers.authorization.trim() : '';
  const bearer = /^Bearer\s+(\S+)$/i.exec(auth)?.[1] ?? '';
  const raw = req.headers['x-obli-delegation'];
  const delegated = typeof raw === 'string' ? raw.trim() : '';
  if (bearer && delegated) return { error: 'credentials_ambiguous' };
  if (auth && !bearer) return { error: 'token_missing' };
  const token = bearer || delegated;
  return token ? { token } : { error: 'token_missing' };
}

const limiter = new WindowLimiter(OBLIWATCH_RPM, 60_000, 10_000);

/** Test hook: empty the limiter. */
export function _resetObliwatchLimiter(): void { limiter.reset(); }

type Verified = { claims: DelegationClaims; kid: string; user?: ObliwatchCaller['user'] };

async function verifyApp(req: Request, res: Response, token: string): Promise<Verified | null> {
  const r = await delegationVerifyService.verifyApp(token);
  if (!r.ok) {
    const code = r.reason === 'subject_invalid' && r.detail === 'user_subject' ? 'user_token_refused' : r.reason;
    refuse(req, res, code, { claims: r.claims });
    return null;
  }
  if (r.app !== OBLIWATCH_APP) { refuse(req, res, 'azp_not_allowed', { claims: r.claims }); return null; }
  return { claims: r.claims, kid: r.kid };
}

async function verifyUser(req: Request, res: Response, token: string): Promise<Verified | null> {
  const r = await delegationVerifyService.verify(token);
  if (!r.ok) {
    // The brief's code (§3): an analyst without an Obligarth account is 'subject_unknown' here (the console's delegated
    // reads keep subject_not_linked).
    const code = r.reason === 'subject_not_linked' ? 'subject_unknown'
      : r.reason === 'subject_invalid' && r.detail === 'app_subject' ? 'app_token_refused' : r.reason;
    refuse(req, res, code, { claims: r.claims });
    return null;
  }
  if (r.claims.azp !== OBLIWATCH_APP) { refuse(req, res, 'azp_not_allowed', { claims: r.claims }); return null; }
  if (r.subject.role === 'admin' && !delegationPolicy().allowPlatformAdmin) {
    refuse(req, res, 'subject_admin_not_allowed', { claims: r.claims });
    return null;
  }
  return { claims: r.claims, kid: r.kid, user: { id: r.subject.localUserId, username: r.subject.username, role: r.subject.role } };
}

/**
 * The authentication of a route of the router, for one kind of token. On success req.obliwatch is set and the jti
 * is burned; the route then checks the consent it needs (requireConsent).
 */
export function obliwatchAuth(kind: ObliwatchTokenKind) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const t = tokenOf(req);
    if ('error' in t) { refuse(req, res, t.error); return; }
    (async () => {
      const v = await asIdentity(OBLIWATCH_ACTOR, () => (kind === 'app' ? verifyApp(req, res, t.token) : verifyUser(req, res, t.token)));
      if (!v) return;
      const { claims, kid } = v;

      // The tenant from the SIGNED slug only, compared byte-exactly (the join key between apps).
      const tenant = await asIdentity(OBLIWATCH_ACTOR, () => tenantService.getBySlug(claims.ost));
      if (!tenant) { refuse(req, res, 'tenant_unknown', { claims }); return; }
      const tenantId = Number(tenant.id);
      if (v.user && v.user.role !== 'admin') {
        const member = await asIdentity(OBLIWATCH_ACTOR, () => tenantService.userHasAccess(v.user!.id, tenantId));
        if (!member) { refuse(req, res, 'tenant_not_permitted', { claims, tenantId }); return; }
      }

      const wait = limiter.hit(`${claims.azp}|${tenantId}`);
      if (wait > 0) { refuse(req, res, 'rate_limited', { claims, tenantId, retryAfter: wait }); return; }

      let outcome: 'fresh' | 'replayed';
      try {
        outcome = await consumeJti(claims.jti, claims.azp, claims.exp);
      } catch (err) {
        logger.error({ err: { message: (err as Error)?.message?.slice(0, 200) } }, '[obliwatch] jti store unavailable');
        refuse(req, res, 'jti_store_unavailable', { claims, tenantId });
        return;
      }
      if (outcome === 'replayed') { refuse(req, res, 'replayed', { claims, tenantId }); return; }

      req.obliwatch = { kind, azp: claims.azp, jti: claims.jti, kid, ost: claims.ost, tenantId, ...(v.user ? { user: v.user } : {}) };
      next();
    })().catch((err) => {
      // Fail closed: an unexpected error is a refusal, never a pass.
      logger.error({ err }, '[obliwatch] authentication error — refusing');
      if (!res.headersSent) sendError(res, 503, 'internal_error');
    });
  };
}
