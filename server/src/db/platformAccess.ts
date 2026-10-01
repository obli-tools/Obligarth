import { createHash, randomUUID } from 'node:crypto';
import type { Request } from 'express';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { db } from './index';
import { actorToken, asNone, type DbActor } from './context';
import { config } from '../config';
import { logger } from '../utils/logger';

// =============================================================================
// Cross-tenant read grants (rls-tenant §6.1, §6.2, §7.4)
// =============================================================================
//
// The global view of the master tenant, and the transverse reads of jobs and
// integrations, run in the context 'platform' (role obligarth_reader, read
// only). Each such context names a grant journaled in
// obligarth.platform_access_grants, which the database checks at every query
// once the RLS is active: platform administrator still active, same actor,
// not expired. A user's grant also leaves an audit event in the master
// tenant ('platform.global_view_opened'). The journal is insert-only (its id
// is generated here: no RETURNING), purged by obligarth.platform_access_grants_purge.

export interface PlatformGrant {
  readonly id: string;                         // uuid generated here: the journal is insert-only
  readonly actor: DbActor;                     // user, job or integration
  readonly expiresAt: number;                  // epoch ms
}

/** A cached grant is reused while more than this is left of it. */
const REUSE_MARGIN_MS = 60_000;
const MAX_CACHED = 10_000;

function ttlMs(): number {
  return config.platformGrantTtlSeconds * 1000;
}

const shortText = (v: string | undefined, max: number): string | null => {
  if (typeof v !== 'string' || !v) return null;
  return v.length > max ? v.slice(0, max) : v;
};

/** The SHA-256 of a session id: what the journal keeps, never the id. */
export function sessionRef(sessionId: string): string {
  return createHash('sha256').update(sessionId).digest('hex');
}

/** Opens a grant: inserted in the context 'none' of its actor (the database
 *  refuses a user who is not an active platform administrator, once the RLS
 *  is active). A user's grant is audited in the master tenant. */
export async function openPlatformGrant(input: {
  actor: DbActor; reason: string; route?: string; requestId?: string;
  sessionRef?: string; tenantFilter?: number[] | null;
}): Promise<PlatformGrant> {
  const { actor } = input;
  if (actor.type !== 'user' && actor.type !== 'job' && actor.type !== 'integration') {
    throw new Error('a platform grant is opened by a user, a job or an integration');
  }
  const token = actorToken(actor);
  const reason = String(input.reason ?? '').slice(0, 200);
  if (reason.length < 3) throw new Error('a platform grant needs a reason');
  const id = randomUUID();
  const now = Date.now();
  const expiresAt = now + ttlMs();
  const filter = Array.isArray(input.tenantFilter)
    ? input.tenantFilter.map(Number).filter((n) => Number.isInteger(n) && n > 0)
    : null;
  await asNone(actor, () => db('platform_access_grants').insert({
    id,
    actor: token,
    actor_type: actor.type,
    user_id: actor.type === 'user' ? actor.userId : null,
    reason,
    route: shortText(input.route, 200),
    request_id: shortText(input.requestId, 64),
    session_ref: input.sessionRef && /^[0-9a-f]{64}$/.test(input.sessionRef) ? input.sessionRef : null,
    tenant_filter: filter && filter.length > 0 ? filter : null,
    created_at: new Date(now),
    expires_at: new Date(expiresAt),
  }));
  if (actor.type === 'user') {
    try {
      const { auditService } = await import('../services/audit.service');
      await asNone(actor, () => auditService.log({
        tenantId: MASTER_TENANT_ID,
        userId: actor.userId,
        action: 'platform.global_view_opened',
        resourceType: 'platform_grant',
        resourcePath: id,
        details: { reason, route: shortText(input.route, 200), expiresAt: new Date(expiresAt).toISOString() },
      }));
    } catch { /* the audit never breaks the read */ }
  }
  logger.info({ grantId: id, actor: token, reason, route: input.route, requestId: input.requestId }, 'platform grant opened');
  return { id, actor, expiresAt };
}

// ── Grants of the sessions (global view of the console) ─────────────────────

const sessionGrants = new Map<string, PlatformGrant>();   // actor|sha256(sid) → grant
/** Grants being opened, by key: concurrent requests of one session (the
 *  dashboard's parallel reads) share one grant and one audit event. */
const opening = new Map<string, Promise<PlatformGrant>>();

function remember(map: Map<string, PlatformGrant>, key: string, grant: PlatformGrant): void {
  if (map.size >= MAX_CACHED) {
    const now = Date.now();
    for (const [k, g] of map) if (g.expiresAt - now <= REUSE_MARGIN_MS) map.delete(k);
    if (map.size >= MAX_CACHED) map.clear();
  }
  map.set(key, grant);
}

/** The cached grant of `key` while more than REUSE_MARGIN_MS is left of it,
 *  else the one being opened, else a new one (`open`). */
function reuseOrOpen(map: Map<string, PlatformGrant>, key: string, open: () => Promise<PlatformGrant>): Promise<PlatformGrant> {
  const cached = map.get(key);
  if (cached && cached.expiresAt - Date.now() > REUSE_MARGIN_MS) return Promise.resolve(cached);
  const inFlight = opening.get(key);
  if (inFlight) return inFlight;
  const p: Promise<PlatformGrant> = open().then((grant) => {
    // Not cached when forgotten meanwhile (sign-out, sessions killed).
    if (opening.get(key) === p) remember(map, key, grant);
    return grant;
  }).finally(() => {
    if (opening.get(key) === p) opening.delete(key);
  });
  opening.set(key, p);
  return p;
}

/** The grant of the session's global view: reused within its window (more
 *  than 60 s left), a new one otherwise. */
export async function globalViewGrant(req: Request, reason = 'console.global_view'): Promise<PlatformGrant> {
  const userId = Number(req.session?.userId);
  if (!Number.isInteger(userId) || userId <= 0) throw new Error('global view without a signed-in user');
  const actor: DbActor = { type: 'user', userId };
  const sid = typeof req.sessionID === 'string' && req.sessionID ? req.sessionID : `request:${randomUUID()}`;
  const ref = sessionRef(sid);
  const key = `${actorToken(actor)}|${ref}`;
  return reuseOrOpen(sessionGrants, key, () => openPlatformGrant({
    actor,
    reason,
    route: `${req.method} ${req.baseUrl ?? ''}${req.route?.path ?? req.path ?? ''}`,
    requestId: req.requestId,
    sessionRef: ref,
  }));
}

/** Drops the cached grant of a session (sign-out): the next global-view
 *  request opens a new one. The grant expires by itself in the database. */
export function forgetGrantsOfSession(sessionId: string): void {
  if (typeof sessionId !== 'string' || !sessionId) return;
  const suffix = `|${sessionRef(sessionId)}`;
  for (const key of sessionGrants.keys()) if (key.endsWith(suffix)) sessionGrants.delete(key);
  for (const key of opening.keys()) if (key.endsWith(suffix)) opening.delete(key);
}

/** Drops every cached grant of a user (killSessionsForUser). */
export function forgetGrantsOfUser(userId: number): void {
  const prefix = `u:${Number(userId)}|`;
  for (const key of sessionGrants.keys()) if (key.startsWith(prefix)) sessionGrants.delete(key);
  for (const key of opening.keys()) if (key.startsWith(prefix)) opening.delete(key);
}

// ── Grants of integrations and jobs ─────────────────────────────────────────

const integrationGrants = new Map<string, PlatformGrant>();

/** An integration's grant, reused within its window (one per name and
 *  reason). */
export async function integrationGrant(name: string, reason: string): Promise<PlatformGrant> {
  const actor: DbActor = { type: 'integration', name };
  const key = `${actorToken(actor)}|${reason}`;
  return reuseOrOpen(integrationGrants, key, () => openPlatformGrant({ actor, reason }));
}

/** One grant per execution of a job (reason 'job:<queue>'). */
export function jobGrant(name: string): Promise<PlatformGrant> {
  return openPlatformGrant({ actor: { type: 'job', name }, reason: `job:${name}` });
}

/** Daily purge of the journal (PLATFORM_GRANT_RETENTION_DAYS, 30 days at
 *  least): rows removed. Runs in the caller's context (a job's). */
export async function purgePlatformGrants(): Promise<number> {
  const days = Math.max(30, config.platformGrantRetentionDays);
  const res = await db.raw('SELECT obligarth.platform_access_grants_purge(make_interval(days => ?)) AS n', [days]) as
    { rows: Array<{ n: number | null }> };
  return Number(res.rows[0]?.n ?? 0);
}
