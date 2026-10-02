// Who requests, reviews or is designated (docs: audit-durci §9.1, §10.4,
// §10.8): the side of an account in a tenant, its designations, its 72-hour
// cooldown, and the losses of client approvers that hold the fallback of
// D24 (AUD-A7-R4). Accounts are read in the identity context (an MSP
// technician who is not a member of the client's tenant is not readable from
// the tenant's context), designations and losses in the tenant's.
import { GUARD_FALLBACK_HOLD_DAYS, MASTER_TENANT_ID, type GuardSide } from '@obligarth/shared';
import { db } from '../db';
import { currentActor, switchToIdentity } from '../db/context';
import type { ReviewerFacts } from './policy';

export interface PersonFacts {
  userId: number;
  exists: boolean;
  active: boolean;
  username: string | null;
  platformAdmin: boolean;
  /** Role slug in the tenant ('admin', 'user', 'approver'…), null: no role there. */
  tenantRole: string | null;
  /** Audience of that role (null: no role there). */
  audience: GuardSide | null;
  /** Side of the account in the tenant (audit-durci §9.1). */
  side: GuardSide;
  /** A second factor: local TOTP, or an Obligate account (MFA at Obligate). */
  hasSecondFactor: boolean;
}

type FactsRow = {
  username: string; role: string; is_active: boolean; totp_enabled: boolean; totp_secret_enc: string | null;
  foreign_source: string | null; foreign_id: number | null; tenant_role: string | null; audience: string | null;
  master_member: boolean;
};

/** The facts of an account in a tenant (identity context of the current actor). */
export async function personFacts(userId: number, tenantId: number): Promise<PersonFacts> {
  const res = await switchToIdentity(() => db.raw(
    `SELECT u.username, u.role, u.is_active, u.totp_enabled, u.totp_secret_enc, u.foreign_source, u.foreign_id,
            ut.role AS tenant_role, ps.audience,
            EXISTS (SELECT 1 FROM user_tenants m WHERE m.user_id = u.id AND m.tenant_id = ?) AS master_member
       FROM users u
       LEFT JOIN user_tenants ut ON ut.user_id = u.id AND ut.tenant_id = ?
       LEFT JOIN permission_sets ps ON ps.slug = (CASE WHEN ut.role = 'member' THEN 'user' ELSE ut.role END)
      WHERE u.id = ?`, [MASTER_TENANT_ID, tenantId, userId],
  )) as { rows: FactsRow[] };
  const r = res.rows[0];
  if (!r) {
    return {
      userId, exists: false, active: false, username: null, platformAdmin: false, tenantRole: null, audience: null,
      side: 'client', hasSecondFactor: false,
    };
  }
  const platformAdmin = r.role === 'admin';
  const tenantRole = r.tenant_role ?? null;
  // A tenant administrator's role ('admin') has no permission set: an MSP
  // role unless the set says otherwise (sets of audience 'client' only).
  const audience: GuardSide | null = tenantRole === null ? null : r.audience === 'client' ? 'client' : 'msp';
  let side: GuardSide;
  if (platformAdmin) side = 'msp';
  else if (audience) side = audience;
  else side = r.master_member ? 'msp' : 'client';
  return {
    userId,
    exists: true,
    active: r.is_active === true,
    username: r.username,
    platformAdmin,
    tenantRole,
    audience,
    side,
    hasSecondFactor: (r.totp_enabled === true && !!r.totp_secret_enc) || (r.foreign_source === 'obligate' && !!r.foreign_id),
  };
}

/** End of the cooldown of `userId` in `tenantId` for these kinds of grant
 *  (obligarth.guard_cooldown_until), or null. */
export async function cooldownUntil(userId: number, tenantId: number,
  kinds: ReadonlyArray<'platform_admin' | 'tenant_admin' | 'approver'>): Promise<Date | null> {
  const res = await db.raw('SELECT obligarth.guard_cooldown_until(?, ?, ?::text[]) AS until', [userId, tenantId, [...kinds]]) as
    { rows: Array<{ until: Date | string | null }> };
  const v = res.rows[0]?.until;
  return v ? new Date(v) : null;
}

/** Active designations of an account in the tenant of the current context. */
export async function designationsOf(userId: number, tenantId: number): Promise<{ client: boolean; msp: boolean }> {
  const rows = await db('tenant_approvers').where({ tenant_id: tenantId, user_id: userId }).whereNull('revoked_at').select('side') as
    Array<{ side: string }>;
  return { client: rows.some((r) => r.side === 'client'), msp: rows.some((r) => r.side === 'msp') };
}

/** Designated client approvers of a tenant whose account is active and whose
 *  role in the tenant is a client one: what decides the fallback (§10.4). A
 *  platform administrator never counts (always on the MSP side, §9.1). */
export async function activeClientApprovers(tenantId: number): Promise<number> {
  const ids = await db('tenant_approvers').where({ tenant_id: tenantId, side: 'client' }).whereNull('revoked_at').pluck('user_id') as number[];
  let n = 0;
  for (const id of ids) {
    const f = await personFacts(Number(id), tenantId);
    if (f.active && f.audience === 'client' && !f.platformAdmin) n++;
  }
  return n;
}

/**
 * The fallback of D24 held (AUD-A7-R4): the last loss of a client approver
 * of the tenant that the approver did not decide (revocation by another
 * account, deactivation, role changed or removed, deletion, promotion to
 * platform administrator — recorded by the database whatever the path,
 * table guard_approver_losses), less than GUARD_FALLBACK_HOLD_DAYS old;
 * null otherwise. Read in the tenant's context.
 */
export async function fallbackHold(tenantId: number): Promise<{ lostAt: Date; until: Date } | null> {
  const res = await db.raw(
    `SELECT max(lost_at) AS lost_at FROM guard_approver_losses
      WHERE tenant_id = ? AND NOT self AND lost_at > now() - make_interval(days => ?)`,
    [tenantId, GUARD_FALLBACK_HOLD_DAYS],
  ) as { rows: Array<{ lost_at: Date | string | null }> };
  const v = res.rows[0]?.lost_at;
  if (!v) return null;
  const lostAt = new Date(v);
  return { lostAt, until: new Date(lostAt.getTime() + GUARD_FALLBACK_HOLD_DAYS * 86_400_000) };
}

/** The facts the examination policy reads (policy.ts reviewerRefusal). */
export async function reviewerFacts(userId: number, tenantId: number): Promise<ReviewerFacts> {
  const f = await personFacts(userId, tenantId);
  const d = await designationsOf(userId, tenantId);
  return {
    userId,
    active: f.exists && f.active,
    platformAdmin: f.platformAdmin && f.active,
    audience: f.audience,
    designatedClient: d.client,
    designatedMsp: d.msp,
    cooldownUntil: await cooldownUntil(userId, tenantId, ['platform_admin', 'tenant_admin', 'approver']),
  };
}

/** Is the current actor a user (the id), else null. */
export function currentUserId(): number | null {
  const a = currentActor();
  return a.type === 'user' ? a.userId : null;
}
