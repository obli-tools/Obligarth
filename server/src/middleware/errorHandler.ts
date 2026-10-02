import type { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import {
  DbContextDeniedError, DbContextMismatchError, DbContextMissingError, countRlsDenied, currentDbContext,
} from '../db/context';
import { VaultError } from '../vault/errors';

export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    /** Optional machine-readable code, sent next to `error` (lets the client translate). */
    public code?: string,
    /** Optional values of the refusal, sent as `details` (specs README §14):
     *  never a secret nor another tenant's data. */
    public details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

// ── Database refusals (rls-tenant §7.8) ─────────────────────────────────────
// A write refused by a row level security policy, or a reference to a row
// of another tenant, answers 404: the existence of the other tenant's row is
// not revealed. Both are counted and logged (a defect or an attack).

type PgError = Error & { code?: unknown; constraint?: unknown; table?: unknown };

const TENANT_REFERENCE_RE = /(_tenant_fk|_scope_tenant|_channel_tenant)$/;

/** The context a log line names: kind, tenant and actor, never a value. */
function contextForLog(req: Request): Record<string, unknown> {
  const ctx = currentDbContext() ?? req.dbContext;
  if (!ctx) return {};
  const actor = ctx.actor.type === 'user' ? `u:${ctx.actor.userId}` : `${ctx.actor.type}:${ctx.actor.name}`;
  return { dbContext: { kind: ctx.kind, tenantId: ctx.tenantId, actor }, requestId: ctx.requestId ?? req.requestId };
}

/** The table a refusal names ("... for table x" / "... on table \"x\""). */
function tableOf(err: PgError): string {
  if (typeof err.table === 'string' && err.table) return err.table;
  const m = /(?:for|on) table "?([a-z_][a-z0-9_]*)"?/.exec(String(err.message));
  return m ? m[1] : 'unknown';
}

/** Is this a row level security refusal (42501 "row-level security")? */
export function isRlsDenial(err: unknown): boolean {
  const e = err as PgError;
  return !!e && e.code === '42501' && /row-level security/i.test(String(e.message));
}

/** Is this a reference to a row of another tenant (composite key, scope
 *  or channel check)? */
export function isCrossTenantReference(err: unknown): boolean {
  const e = err as PgError;
  return !!e && e.code === '23503' && typeof e.constraint === 'string' && TENANT_REFERENCE_RE.test(e.constraint);
}

export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  if (err instanceof AppError) {
    // A critical action refused because its audit entry could not be written
    // (audit-durci §5.4): the client may retry later.
    if (err.code === 'auditUnavailable' && !res.headersSent) res.setHeader('Retry-After', '30');
    if (res.headersSent) { res.end(); return; }
    res.status(err.statusCode).json({
      success: false,
      error: err.message,
      ...(err.code ? { code: err.code } : {}),
      ...(err.details ? { details: err.details } : {}),
    });
    return;
  }

  if (err instanceof DbContextDeniedError) {
    logger.warn({ err, ...contextForLog(req) }, 'database context denied');
    res.status(404).json({ success: false, error: 'Not found' });
    return;
  }

  if (isRlsDenial(err)) {
    const table = tableOf(err as PgError);
    countRlsDenied(table);
    // A global view the database refuses to open (the actor is no longer an
    // active platform administrator): 403, nothing about any tenant's rows.
    if (table === 'platform_access_grants') {
      logger.warn({ err, table, ...contextForLog(req) }, 'platform grant refused by the database');
      res.status(403).json({ success: false, error: 'Access denied' });
      return;
    }
    logger.error({ err, table, ...contextForLog(req) }, 'write refused by a row level security policy');
    res.status(404).json({ success: false, error: 'Not found' });
    return;
  }

  if (isCrossTenantReference(err)) {
    const table = tableOf(err as PgError);
    countRlsDenied(table);
    logger.warn({ err, table, constraint: (err as PgError).constraint, ...contextForLog(req) }, 'reference to another tenant refused');
    res.status(404).json({ success: false, error: 'Not found' });
    return;
  }

  // Errors of the vault (docs: coffre-secrets §5.7): never a value in the
  // answer nor in the log (the vault logged the failure, with its
  // coordinates, and raised the alert when it hints at tampering or at an
  // isolation defect). A tenant being deleted refuses new secrets (409).
  if (err instanceof VaultError) {
    if (err.code === 'tenant_retiring') {
      res.status(409).json({ success: false, error: 'This tenant is being deleted: its secrets can no longer be changed', code: 'tenantRetiring' });
      return;
    }
    logger.error({ vault: { code: err.code }, ...contextForLog(req) }, 'request failed on a vault error');
    res.status(500).json({ success: false, error: 'Internal server error' });
    return;
  }

  if (err instanceof DbContextMissingError || err instanceof DbContextMismatchError) {
    logger.error({ err, ...contextForLog(req) }, err.message);
    res.status(500).json({ success: false, error: 'Internal server error' });
    return;
  }

  logger.error(err, 'Unhandled error');
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
}
