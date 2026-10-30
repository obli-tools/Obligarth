import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { db } from '../db';
import { asIdentity } from '../db/context';
import { BucketLimiter, ConcurrencyLimiter, WindowLimiter } from '../legacyAgent/limits';
import { neverBlockReason } from '../security/neverBlock';
import { clientAddress, type ResolvedClient } from '../utils/clientIp';
import { logger } from '../utils/logger';
import { auditAuthFailure } from './audit';
import { blockAddress, isBlocked } from './blocks';
import { effectiveTenantsOf, type McpCaller } from './caller';
import { currentPolicy, refreshPolicy } from './ipPolicy';
import { compileCidrs } from './ipUtil';
import { hasStepUpFactor, keyInfoOf, lookupForAuth, revokeAllOfUser, revokeKey, touchLastUsed } from './keys/service';
import { bearerOf, parseToken, tokenMatches } from './keys/secret';
import { MCP_ACTOR, mcpSettings } from './settings';

// =============================================================================
// Authentication of /mcp (docs: specs mcp-server §3.2, §3.6), with the IP gate
// in front of it. The key authenticates by its own secret: Obligate is never
// called here (an SSO account's key works while Obligate is down), and the key
// acts for the local users row, re-read on every request (≤ 5 s cache), so a
// deprovisioned account (disabled or removed, the Obligate sync included) kills
// its keys at their next use. Fails closed: any error answers 401 or 503,
// never next() without a caller.
// Failures are of two families: guessing (missing, malformed, invalid secret)
// counts per address towards a block; possession (the secret matched: revoked,
// expired, owner gone or disabled, credentials changed, address not allowed)
// is answered and journaled, never counted.
// =============================================================================

declare module 'express-serve-static-core' {
  interface Request {
    /** The caller of an /mcp request, once authenticated (never a session). */
    mcp?: McpCaller;
  }
}

const REQUEST_ID_RE = /^[A-Za-z0-9._:-]{1,64}$/;

/** The one answer of every authentication failure (no oracle). */
export function sendUnauthorized(res: Response): void {
  res.status(401).setHeader('WWW-Authenticate', 'Bearer realm="obligarth", error="invalid_token"');
  res.json({ jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized' } });
}

export function sendForbidden(res: Response, code?: string, message = 'Forbidden'): void {
  res.status(403).json({ jsonrpc: '2.0', id: null, error: { code: -32003, message, ...(code ? { data: { code } } : {}) } });
}

// ── Failure counting (rate mode) ────────────────────────────────────────────

let failures: { threshold: number; window: number; limiter: WindowLimiter } | null = null;

async function failureLimiter(): Promise<WindowLimiter> {
  const s = await mcpSettings();
  if (!failures || failures.threshold !== s.failureThreshold || failures.window !== s.failureWindowSeconds) {
    // hit() refuses once `max` hits are in the window: the threshold-th failure is the one that blocks.
    failures = { threshold: s.failureThreshold, window: s.failureWindowSeconds, limiter: new WindowLimiter(Math.max(1, s.failureThreshold - 1), s.failureWindowSeconds * 1000) };
  }
  return failures.limiter;
}

/** The address a failure is counted on, and whether it may be blocked (never a relay nor an untrusted forwarder). */
function countingKey(req: Request, client: ResolvedClient): { key: string; blockable: boolean } {
  if (client.relay || client.untrustedForwarder) return { key: `relay:${req.ip ?? ''}`, blockable: false };
  return { key: client.ip, blockable: true };
}

/** A guessing failure: counted per address; beyond the threshold, a local block (and Obliguard when connected). */
async function guessingFailure(req: Request, client: ResolvedClient, kind: string, publicId?: string): Promise<void> {
  auditAuthFailure({ kind, ip: client.ip, publicId, requestId: req.requestId });
  try {
    const limiter = await failureLimiter();
    const { key, blockable } = countingKey(req, client);
    if (limiter.hit(key) === 0 || !blockable) return;
    const s = await mcpSettings();
    const guard = neverBlockReason(client, s.neverBlock);
    if (guard) { logger.warn({ ip: client.ip, guard }, 'mcp: failure threshold reached, address never blocked'); return; }
    await blockAddress({
      ip: client.ip, source: 'mcp_failures', reason: `${s.failureThreshold} failed authentications within ${s.failureWindowSeconds} s`,
      until: new Date(Date.now() + s.blockSeconds * 1000), hits: s.failureThreshold,
    });
  } catch (err) {
    logger.warn({ err }, 'mcp: failure not counted');
  }
}

// ── IP gate (before the authentication; memory only) ────────────────────────

/**
 * 1. an active local block of the address or its /64: 403; 2. strict mode and an address outside the global and the
 * known lists: blocked at once and for good (unless the never-block guard refuses), reported to Obliguard, 403.
 */
export async function ipGate(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const client = clientAddress(req);
    if (client.ip && isBlocked(client.ip)) { sendForbidden(res); return; }
    const policy = currentPolicy();
    if (!policy) { void refreshPolicy().catch(() => undefined); next(); return; }
    if (policy.mode === 'strict' && client.ip && !policy.inGlobal(client.ip) && !policy.inKnown(client.ip)) {
      const s = await mcpSettings();
      const guard = neverBlockReason(client, s.neverBlock);
      auditAuthFailure({ kind: 'ip_outside_strict_list', ip: client.ip, requestId: req.requestId });
      if (!guard) {
        await blockAddress({
          ip: client.ip, source: 'mcp_strict', reason: 'Address outside the allow-list of every MCP access key (strict mode)', until: null,
        });
      } else {
        logger.warn({ ip: client.ip, guard }, 'mcp: address outside the strict list, never blocked');
      }
      sendForbidden(res);
      return;
    }
    next();
  } catch (err) {
    logger.error({ err }, 'mcp: IP gate failed');
    res.status(503).json({ jsonrpc: '2.0', id: null, error: { code: -32603, message: 'Service unavailable' } });
  }
}

// ── Authentication ──────────────────────────────────────────────────────────

let perKey: { rpm: number; limiter: BucketLimiter } | null = null;
const concurrency = new ConcurrencyLimiter(4);

/** The per-key request limiter (key_rpm per minute; each JSON-RPC message counts). */
export async function keyLimiter(): Promise<BucketLimiter> {
  const s = await mcpSettings();
  if (!perKey || perKey.rpm !== s.keyRequestsPerMinute) {
    perKey = { rpm: s.keyRequestsPerMinute, limiter: new BucketLimiter(s.keyRequestsPerMinute, 60_000 / s.keyRequestsPerMinute) };
  }
  return perKey.limiter;
}

const userCache = new Map<number, { at: number; row: Record<string, any> | null }>();
const USER_TTL_MS = 5_000;

async function userOf(id: number): Promise<Record<string, any> | null> {
  const hit = userCache.get(id);
  if (hit && Date.now() - hit.at < USER_TTL_MS) return hit.row;
  const row = await asIdentity(MCP_ACTOR, () => db('users').where({ id })
    .first('id', 'username', 'role', 'is_active', 'totp_enabled', 'totp_secret_enc', 'foreign_source', 'foreign_id', 'credential_version')) as Record<string, any> | undefined;
  if (userCache.size > 10_000) userCache.clear();
  userCache.set(id, { at: Date.now(), row: row ?? null });
  return row ?? null;
}

/** Drops the cached account (a hook of killSessionsForUser). */
export function forgetMcpUser(userId: number): void {
  userCache.delete(Number(userId));
}

export async function mcpAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const client = clientAddress(req);
  const relayed = req.get('X-Request-ID');
  const requestId = relayed && REQUEST_ID_RE.test(relayed) ? relayed : randomUUID();
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  try {
    // 1. Parse: Authorization: Bearer <token>, nothing else.
    const header = req.headers.authorization;
    if (!header) { await guessingFailure(req, client, 'missing'); sendUnauthorized(res); return; }
    const token = bearerOf(header);
    const parsed = token ? parseToken(token) : null;
    if (!token || !parsed) { await guessingFailure(req, client, 'malformed'); sendUnauthorized(res); return; }

    // 2. The key of the public id, its secret compared in constant time.
    const found = await lookupForAuth(parsed.publicId);
    if (!found || !tokenMatches(token, String(found.row.secret_sha256))) {
      await guessingFailure(req, client, 'invalid', parsed.publicId);
      sendUnauthorized(res);
      return;
    }
    const { row, targets } = found;
    const key = keyInfoOf(row);
    const possession = (kind: string): void => {
      auditAuthFailure({ kind, ip: client.ip, publicId: key.publicId, requestId });
      logger.info({ kind, keyId: key.publicId, ip: client.ip, requestId }, 'mcp: key refused');
      sendUnauthorized(res);
    };

    // 3. State of the key.
    if (row.revoked_at) { possession('revoked'); return; }
    if (key.expiresAt.getTime() <= Date.now()) { possession('expired'); return; }

    // 4. Its address allow-list (the secret matched: possession, never counted).
    if (key.ipAllow.length > 0 && !compileCidrs(key.ipAllow)(client.ip)) { possession('ip_not_allowed'); return; }

    // 5. The owner, re-read: gone, disabled or credentials changed revoke the key.
    const user = await userOf(Number(row.user_id));
    if (!user) { await revokeKey(key.rowId, 'owner_removed', null); possession('owner_removed'); return; }
    if (user.is_active !== true) { await revokeAllOfUser(Number(user.id), 'user_disabled'); possession('user_inactive'); return; }
    if (Number(user.credential_version) !== key.credentialVersion) { await revokeKey(key.rowId, 'credentials_changed', null); possession('credentials_changed'); return; }
    // A factor that can approve the key's authorizations (checkSecondFactor's rule; an SSO account's factor is
    // Obligate's). Not a failure: no ban.
    if (!hasStepUpFactor(user)) { sendForbidden(res, 'stepUpFactorMissing', 'Second factor required on the account'); return; }

    const caller: McpCaller = {
      userId: Number(user.id), username: String(user.username), isPlatformAdmin: user.role === 'admin', isSso: user.foreign_source === 'obligate',
      key, targets, ip: client.ip, requestId, memo: {},
    };

    // 6. The effective tenants (computed once for this request): none left = the key is alive, its rights are not.
    const eff = await effectiveTenantsOf(caller);
    if (eff.tenants.length === 0) { sendForbidden(res, 'noTenantInPerimeter', 'No tenant in the perimeter of this key now'); return; }

    // 7. At most 4 requests of a key at once (the per-message rate is counted by the transport).
    const release = concurrency.acquire(`key:${key.rowId}`);
    if (!release) { res.status(429).setHeader('Retry-After', '1'); res.json({ jsonrpc: '2.0', id: null, error: { code: -32029, message: 'Too many requests' } }); return; }
    res.on('finish', release);
    res.on('close', release);

    // 8. Last use (once a minute per key), with the new-network notice.
    touchLastUsed(key, caller.userId, client.ip);

    req.mcp = caller;
    next();
  } catch (err) {
    logger.error({ err, requestId }, 'mcp: authentication failed closed');
    if (!res.headersSent) res.status(503).json({ jsonrpc: '2.0', id: null, error: { code: -32603, message: 'Service unavailable' } });
  }
}
