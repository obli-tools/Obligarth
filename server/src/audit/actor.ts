// Who acts, and on which side (docs: audit-durci §3.1, §5.3, §9.1).
//
// The actor of an entry is the actor of its database context (RLS §4.2):
// u:<id>, j:<queue>, i:<integration>, e:<enrolment>, a:<anonymous>. A user's
// entry freezes their username, their role in the chain's tenant and their
// side: a platform administrator is the MSP's; anyone else takes the
// audience of their role in that tenant (permission_sets.audience); without
// a role there, a member of the master tenant is the MSP's; jobs,
// integrations and anonymous callers are the system's. Looked up in the
// identity context, cached 60 s per user and tenant, dropped by
// killSessionsForUser.
import { createHash } from 'node:crypto';
import type { Request } from 'express';
import { MASTER_TENANT_ID, type AuditActorSide } from '@obligarth/shared';
import { db } from '../db';
import { asIdentity, currentDbContext, type DbActor } from '../db/context';
import { clientIp } from '../utils/clientIp';
import type { AuditActor, AuditOrigin, AuditWriteContext } from './types';

const PREFIX = { user: 'u', job: 'j', integration: 'i', enrollment: 'e', anonymous: 'a' } as const;
const CACHE_TTL_MS = 60_000;
const CACHE_MAX = 10_000;

interface UserFacts {
  at: number;
  label: string | undefined;
  platformAdmin: boolean;
  role: string | undefined;
  side: AuditActorSide;
}

const cache = new Map<string, UserFacts>();

/** Drops the cached facts of a user (killSessionsForUser, role changes). */
export function forgetAuditActor(userId: number): void {
  const prefix = `${Number(userId)}|`;
  for (const k of cache.keys()) if (k.startsWith(prefix)) cache.delete(k);
}

/** The database actor of an audit actor (its RLS token). */
export function dbActorOf(actor: AuditActor): DbActor {
  const ref = String(actor?.ref ?? '');
  const name = ref.slice(2);
  switch (ref[0]) {
    case 'u': return { type: 'user', userId: Number(name) };
    case 'j': return { type: 'job', name };
    case 'i': return { type: 'integration', name };
    case 'e': return { type: 'enrollment', name };
    default: return { type: 'anonymous', name: name || 'unscoped' };
  }
}

export function actorRef(actor: DbActor): string {
  return actor.type === 'user' ? `u:${actor.userId}` : `${PREFIX[actor.type]}:${actor.name}`;
}

/** userFacts, or what is known without the database (the entry is written
 *  anyway; its side then says it is unknown). */
async function factsOrUnknown(userId: number, chainTenantId: number, label?: string): Promise<UserFacts> {
  try {
    return await userFacts(userId, chainTenantId);
  } catch {
    return { at: 0, label, platformAdmin: false, role: undefined, side: 'unknown' };
  }
}

/** The side of a user in a tenant, with their frozen label and role. */
export async function userFacts(userId: number, chainTenantId: number): Promise<UserFacts> {
  const key = `${userId}|${chainTenantId}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit;
  const row = await asIdentity({ type: 'user', userId }, () => db.raw(
    `SELECT u.username, u.role AS platform_role, ut.role AS tenant_role, ps.audience,
            EXISTS (SELECT 1 FROM user_tenants m WHERE m.user_id = u.id AND m.tenant_id = ?) AS master_member
       FROM users u
       LEFT JOIN user_tenants ut ON ut.user_id = u.id AND ut.tenant_id = ?
       LEFT JOIN permission_sets ps ON ps.slug = ut.role
      WHERE u.id = ?`, [MASTER_TENANT_ID, chainTenantId, userId],
  )) as { rows: Array<{ username: string; platform_role: string; tenant_role: string | null; audience: string | null; master_member: boolean }> };
  const r = row.rows[0];
  const platformAdmin = r?.platform_role === 'admin';
  let side: AuditActorSide;
  if (!r) side = 'unknown';
  else if (platformAdmin) side = 'msp';
  else if (r.tenant_role) side = r.audience === 'client' ? 'client' : 'msp';
  else side = r.master_member ? 'msp' : 'client';
  const facts: UserFacts = {
    at: Date.now(),
    label: r?.username ?? undefined,
    platformAdmin,
    role: platformAdmin ? 'platform_admin' : (r?.tenant_role ?? undefined),
    side,
  };
  if (cache.size >= CACHE_MAX) cache.clear();
  cache.set(key, facts);
  return facts;
}

/** sha256 of a session id: what the journal keeps, never the id. */
export function sessionDigest(sessionId: string | undefined | null): string | undefined {
  return typeof sessionId === 'string' && sessionId ? createHash('sha256').update(sessionId).digest('hex') : undefined;
}

/** The origin of a request: client address through the trusted proxies, agent,
 *  request id, method and route pattern (never the raw URL). */
export function originOfRequest(req: Request): AuditOrigin {
  const routePath = (req.route as { path?: unknown } | undefined)?.path;
  const route = `${req.method} ${req.baseUrl ?? ''}${typeof routePath === 'string' ? routePath : ''}`;
  return {
    ip: clientIp(req) || undefined,
    ua: req.get?.('user-agent') || undefined,
    requestId: req.requestId,
    route: route.trim(),
  };
}

/** The context of an entry written by a request, for the chain of
 *  `chainTenantId`. */
export async function fromRequest(req: Request, chainTenantId: number): Promise<AuditWriteContext> {
  const origin = originOfRequest(req);
  const userId = Number(req.session?.userId);
  if (!Number.isSafeInteger(userId) || userId <= 0) {
    return { actor: { type: 'anonymous', ref: 'a:http', side: 'system' }, origin };
  }
  const f = await factsOrUnknown(userId, chainTenantId, req.session?.username || undefined);
  const home = Number(req.session?.currentTenantId);
  return {
    actor: {
      type: 'user',
      ref: `u:${userId}`,
      label: f.label ?? (req.session?.username || undefined),
      side: f.side,
      role: f.role,
      homeTenant: Number.isSafeInteger(home) && home > 0 ? home : undefined,
      auth: typeof req.session?.authMethod === 'string' ? req.session.authMethod : undefined,
      stepUp: req.stepUpVia,
      session: sessionDigest(req.sessionID),
    },
    origin,
  };
}

/** The context of an entry written by a durable job (actor j:<queue>,
 *  request id job-<id>). */
export function fromJob(job: { name: string; requestId: string }): AuditWriteContext {
  return { actor: { type: 'job', ref: `j:${job.name}`, side: 'system' }, origin: { requestId: job.requestId } };
}

/** An integration, an enrolment flow or an anonymous caller. */
export function system(kind: 'integration' | 'enrollment' | 'anonymous', name: string, origin?: AuditOrigin): AuditWriteContext {
  return { actor: { type: kind, ref: `${PREFIX[kind]}:${name}`, side: 'system' }, origin };
}

/** The context of an entry written for `actor` (a user looked up), with the
 *  current database context's request id. */
export async function fromDbActor(actor: DbActor, chainTenantId: number, origin: AuditOrigin = {}): Promise<AuditWriteContext> {
  const requestId = origin.requestId ?? currentDbContext()?.requestId;
  const o: AuditOrigin = { ...origin, requestId };
  if (actor.type !== 'user') return { actor: { type: actor.type, ref: actorRef(actor), side: 'system' }, origin: o };
  const f = await factsOrUnknown(actor.userId, chainTenantId);
  return {
    actor: { type: 'user', ref: `u:${actor.userId}`, label: f.label, side: f.side, role: f.role },
    origin: o,
  };
}
