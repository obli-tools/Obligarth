import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import {
  DbContextDeniedError, asPlatform, asTenant, assertValidContext, enterDbContext, type DbActor, type DbContext,
} from '../db/context';
import { globalViewGrant, integrationGrant, type PlatformGrant } from '../db/platformAccess';
import { hasGlobalView } from '../services/deviceScope.service';
import { AppError } from './errorHandler';
import { logger } from '../utils/logger';

// =============================================================================
// Database context of an HTTP request (rls-tenant §7.4)
// =============================================================================
//
//   dbContextBase       right after the session: 'none', actor = the session's
//                       user (or a:http), request id;
//   requireTenant       (middleware/tenant.ts) 'tenant' of the session, once
//                       its membership is checked;
//   globalViewScope     read routes that accept the master tenant's global
//                       view: 'platform' with the session's grant;
//   memberScope         personal views over every tenant of the user;
//   integrationPlatformScope  transverse reads of an authenticated integration;
//   asTargetTenant      writes from the global view: 'tenant' of the target,
//                       one target per request.

declare global {
  namespace Express {
    interface Request {
      /** The database context the request entered last (for the logs). */
      dbContext?: DbContext;
      /** X-Request-ID relayed, or generated. */
      requestId?: string;
      /** asTargetTenant: the one tenant this request may write to besides
       *  its own. */
      dbTargetTenantId?: number;
    }
  }
}

const REQUEST_ID_RE = /^[A-Za-z0-9._:-]{1,64}$/;

/** The actor of a request: its session's user, or a:http. */
export function actorOfRequest(req: Request): DbActor {
  const userId = Number(req.session?.userId);
  return Number.isSafeInteger(userId) && userId > 0 ? { type: 'user', userId } : { type: 'anonymous', name: 'http' };
}

/** Enters ctx for the rest of the chain; an invalid context (a session's
 *  tenant id out of range, say) goes to the error handler (404). */
function enter(req: Request, ctx: DbContext, next: NextFunction): void {
  try {
    assertValidContext(ctx);
  } catch (err) {
    next(err);
    return;
  }
  req.dbContext = ctx;
  enterDbContext(ctx, next);
}

/** app.ts, right after the session middleware. */
export function dbContextBase(req: Request, res: Response, next: NextFunction): void {
  try {
    const relayed = req.get('X-Request-ID');
    const requestId = relayed && REQUEST_ID_RE.test(relayed) ? relayed : randomUUID();
    req.requestId = requestId;
    if (!res.headersSent) res.setHeader('X-Request-ID', requestId);
    enter(req, { kind: 'none', tenantId: null, actor: actorOfRequest(req), grantId: null, origin: 'request', requestId }, next);
  } catch (err) {
    next(err);
  }
}

/** Re-enters the base context, for a middleware that changed the session's
 *  user (session regenerated for a disabled user, delegated identity). */
export function rebaseDbContext(req: Request, next: NextFunction): void {
  enter(req, {
    kind: 'none', tenantId: null, actor: actorOfRequest(req), grantId: null, origin: 'request', requestId: req.requestId,
  }, next);
}

/** The second-factor step of a sign-in whose password is proven
 *  (session.pendingMfaUserId): the account's own rows, as that user
 *  (context 'none', actor u:<id>), like the end of the password step. */
export function pendingSignInContext(req: Request, _res: Response, next: NextFunction): void {
  const pending = Number((req.session as { pendingMfaUserId?: unknown } | undefined)?.pendingMfaUserId);
  if (!Number.isSafeInteger(pending) || pending <= 0) { next(); return; }
  try {
    enter(req, {
      kind: 'none', tenantId: null, actor: { type: 'user', userId: pending }, grantId: null, origin: 'request', requestId: req.requestId,
    }, next);
  } catch (err) {
    next(err);
  }
}

/** The tenant context of a request on `tenantId` (requireTenant). */
export function tenantContextFor(req: Request, tenantId: number): DbContext {
  return { kind: 'tenant', tenantId, actor: actorOfRequest(req), grantId: null, origin: 'request', requestId: req.requestId };
}

/** Enters the tenant context (requireTenant, attachSessionTenant). */
export function enterTenantContext(req: Request, tenantId: number, next: NextFunction): void {
  enter(req, tenantContextFor(req, tenantId), next);
}

function platformContext(req: Request, grant: PlatformGrant): DbContext {
  return { kind: 'platform', tenantId: null, actor: grant.actor, grantId: grant.id, origin: 'request', requestId: req.requestId };
}

function logPlatformRead(req: Request, grant: PlatformGrant): void {
  logger.info({
    grantId: grant.id,
    route: `${req.method} ${req.baseUrl ?? ''}${req.path ?? ''}`,
    requestId: req.requestId,
    userId: grant.actor.type === 'user' ? grant.actor.userId : undefined,
    actor: grant.actor.type === 'user' ? undefined : `${grant.actor.type}:${grant.actor.name}`,
  }, 'platform read');
}

/**
 * On every read route that accepts the global view: with hasGlobalView(req)
 * (platform administrator on the master tenant), the session's grant, then
 * the context 'platform' (read only); otherwise the tenant context stays. A
 * route that forgot it stays limited to the master tenant by the RLS (safe
 * failure). Never on a route that writes: writes go through asTargetTenant.
 */
export function globalViewScope(reason = 'console.global_view'): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!hasGlobalView(req)) { next(); return; }
      const grant = await globalViewGrant(req, reason);
      logPlatformRead(req, grant);
      enter(req, platformContext(req, grant), next);
    } catch (err) {
      next(err);
    }
  };
}

/** Runs fn in the global view's context when the request has it (a read
 *  inside a route that also writes), in the current context otherwise. */
export async function globalViewRead<T>(req: Request, fn: () => T | PromiseLike<T>): Promise<T> {
  if (!hasGlobalView(req)) return await fn();
  const grant = await globalViewGrant(req);
  logPlatformRead(req, grant);
  return asPlatform(grant, fn);
}

/** Personal views over every tenant of the user (GET /api/live-alerts/all):
 *  the database computes the user's tenants, no grant (not a global view). */
export function memberScope(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    try {
      const actor = actorOfRequest(req);
      if (actor.type !== 'user') { next(new AppError(401, 'Authentication required')); return; }
      enter(req, { kind: 'member', tenantId: null, actor, grantId: null, origin: 'request', requestId: req.requestId }, next);
    } catch (err) {
      next(err);
    }
  };
}

/** Transverse reads of an integration (Obligate's app-info, dashboard-stats),
 *  AFTER its credential is verified: its grant (reused 15 min), then the
 *  context 'platform'. */
export function integrationPlatformScope(name: 'obligate', reason: string): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const grant = await integrationGrant(name, `integration:${name}.${reason}`);
      logPlatformRead(req, grant);
      enter(req, platformContext(req, grant), next);
    } catch (err) {
      next(err);
    }
  };
}

/** Same as integrationPlatformScope, for a handler that verifies the
 *  integration's credential itself before reading. */
export async function asIntegrationPlatform<T>(
  req: Request, name: 'obligate', reason: string, fn: () => T | PromiseLike<T>,
): Promise<T> {
  const grant = await integrationGrant(name, `integration:${name}.${reason}`);
  logPlatformRead(req, grant);
  return asPlatform(grant, fn);
}

/**
 * Writes from the global view (rls-tenant §6.3): fn runs in the context
 * 'tenant' of `tenantId`, the request's actor. Accepted for the session's
 * tenant, or any tenant with hasGlobalView(req); refused otherwise
 * (DbContextDeniedError → 404). A second distinct target in the same
 * request is refused (409 crossTenantBatch): a mass action never crosses
 * several clients (D27).
 */
export async function asTargetTenant<T>(req: Request, tenantId: number, fn: () => T | PromiseLike<T>): Promise<T> {
  const target = Number(tenantId);
  if (!Number.isSafeInteger(target) || target <= 0) throw new DbContextDeniedError('invalid target tenant');
  const own = Number(req.tenantId);
  if (target !== own) {
    if (!hasGlobalView(req)) throw new DbContextDeniedError('target tenant outside the request\'s tenant');
    if (req.dbTargetTenantId !== undefined && req.dbTargetTenantId !== target) {
      throw new AppError(409, 'One request acts on one tenant only', 'crossTenantBatch');
    }
    req.dbTargetTenantId = target;
  }
  return asTenant(target, actorOfRequest(req), fn);
}
