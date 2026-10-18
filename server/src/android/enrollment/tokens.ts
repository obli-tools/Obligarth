// Android enrollment tokens (sections 10.2, 10.3, 22.3; AN17, AN50, RR-9): created in two transactions around the
// call to Google (G-A1), the value sealed in the tenant's vault at once (tenant_secrets, purpose
// android.enrollment_token; value_ref is a declared holder of references, so the garbage collection of the vault never
// destroys the value of an active token), shown again on demand while active, destroyed as soon as the token leaves
// the state active (used, expired, revoked, failed). An interrupted creation (the token exists at Google, the second
// transaction did not commit) is adopted by the recovery of AN50, then the garbage collection of the maintenance
// deletes at Google the tokens of the instance that no row knows, except those whose row is creating for less than
// 15 minutes (RR-9). The value of a token is never logged, audited nor sent in a job payload.
import type { Knex } from 'knex';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { vault } from '../../vault';
import { logger } from '../../utils/logger';
import { androidGateway } from '../gateway';
import { AndroidError } from '../gateway/errors';
import { parseOwnedName } from '../gateway/names';
import type { AndroidEnterpriseRef } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { readEnterprise } from '../enterprises/registry';
import { tokenData, tokenIdOf, tokenPayload, tokenPlan, type AndroidTokenKind, type TokenPayload } from './methods';
import { readAndroidProfile, requiresApproval, snapshotOf } from './profiles';

export const TOKEN_SECRET_PURPOSE = 'android.enrollment_token';
export const TOKENS_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.tokens' }) as DbActor;
/** A creating row younger than this is a creation in progress: never collected (RR-9). */
export const CREATING_GRACE_MS = 15 * 60_000;

export class TokenError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message = code) {
    super(message);
    this.name = 'TokenError';
    this.status = status;
    this.code = code;
  }
}

export interface CreateTokenRequest {
  profileId: string;
  endUserId?: number;
  expiresInSeconds?: number;
}

export interface CreatedToken {
  id: string;
  kind: AndroidTokenKind;
  expiresAt: string;
  requiresApproval: boolean;
  payload: TokenPayload;
}

interface TokenRow {
  id: string;
  tenant_id: number;
  enterprise_id: number;
  profile_id: string;
  kind: AndroidTokenKind;
  token_name: string | null;
  value_ref: string | null;
  one_time: boolean;
  expires_at: Date;
  state: string;
  created_at: Date;
}

const TOKEN_COLUMNS = ['id', 'tenant_id', 'enterprise_id', 'profile_id', 'kind', 'token_name', 'value_ref', 'one_time', 'expires_at',
  'state', 'created_at'];

const tokenIdOfName = (e: AndroidEnterpriseRef, name: string): string => {
  const p = parseOwnedName(e, name);
  if (p.kind !== 'enrollmentToken') throw new TokenError(502, 'androidInvalidRequest', 'unexpected token name');
  return p.tokenId;
};

/**
 * Destroys the sealed value of a token leaving the state active, in the caller's transaction (tenant context): the
 * row of tenant_secrets is deleted, value_ref emptied. Used by the revocation, the expiry and the first use of a
 * single-use token.
 */
export async function endToken(trx: Knex.Transaction, row: { id: string; value_ref: string | null }, state: 'used' | 'expired' | 'revoked' | 'failed',
  extra: Record<string, unknown> = {}): Promise<void> {
  await trx('android_enrollment_tokens').where({ id: row.id }).update({ state, value_ref: null, ended_at: trx.fn.now(), ...extra });
  if (row.value_ref) await trx('tenant_secrets').where({ id: row.value_ref }).delete();
}

/**
 * POST /api/android/enrollment-tokens (section 10.2). Transaction 1: the row 'creating' and its audit entry; outside
 * any transaction: enrollmentTokens.create (policy e-<profile uuid>, additionalData obg1:<id>); transaction 2: the
 * name, the value sealed, 'active'. The enrollment policy of the profile must have been pushed (rule of the 5
 * minutes, section 10.7): 409 androidEnrollmentPolicyMissing otherwise.
 */
export async function createEnrollmentToken(tenantId: number, userId: number | null, req: CreateTokenRequest, auditCtx: AuditWriteContext,
  o: { gateway?: AndroidGateway; actor?: DbActor } = {}): Promise<CreatedToken> {
  const gw = o.gateway ?? androidGateway();
  const actor: DbActor = o.actor ?? (userId ? { type: 'user', userId } : TOKENS_ACTOR);
  return asTenant(tenantId, actor, async () => {
    const t1 = await db.transaction(async (trx) => {
      const e = await readEnterprise(trx);
      if (!e || e.state !== 'linked') throw new TokenError(409, 'androidNotLinked', 'no linked Android enterprise');
      const profile = await readAndroidProfile(trx, String(req.profileId ?? ''), tenantId);
      if (!profile || !profile.enabled) throw new TokenError(404, 'notFound', 'Android enrollment profile not found');
      const snapshot = snapshotOf(profile);
      let plan;
      try { plan = tokenPlan(snapshot, req.expiresInSeconds); } catch (err) { throw new TokenError(422, (err as { code?: string }).code ?? 'invalidInput'); }
      if (plan.kind === 'signin') throw new TokenError(422, 'androidSigninTokenByFlow', 'sign-in tokens are created by the sign-in flow');
      if (plan.kind === 'byod_link' && !req.endUserId) throw new TokenError(422, 'androidEndUserRequired', 'a BYOD link is bound to an end user');
      if (req.endUserId !== undefined) {
        const user = await trx('end_users').where({ id: req.endUserId, status: 'active' }).first('id');
        if (!user) throw new TokenError(404, 'notFound', 'end user not found');
      }
      const pol = await trx('android_enrollment_policies').where({ profile_id: profile.id }).first('state', 'policy_id');
      if (!pol || pol.state !== 'pushed') throw new TokenError(409, 'androidEnrollmentPolicyMissing', 'the enrollment policy of the profile is not pushed yet');
      const approval = requiresApproval(profile, plan.approvalByDefault);
      const [row] = await trx('android_enrollment_tokens').insert({
        tenant_id: tenantId, enterprise_id: e.id, profile_id: profile.id, profile_snapshot: JSON.stringify(snapshot),
        requires_approval: approval, end_user_id: req.endUserId ?? null, kind: plan.kind, one_time: plan.oneTime,
        max_uses: plan.oneTime ? 1 : null, expires_at: new Date(Date.now() + plan.durationSeconds * 1000), state: 'creating',
        created_by: userId,
      }).returning('id');
      const id = String((row as { id: string }).id ?? row);
      await audit.appendInTx(trx, {
        tenantId, action: 'android.enrollment_token_created', target: { type: 'android_enrollment_token', id },
        details: { tokenId: id, profileId: profile.id, kind: plan.kind, oneTime: plan.oneTime, requiresApproval: approval, durationSeconds: plan.durationSeconds },
      }, auditCtx);
      return { id, e, plan, approval, policyId: String(pol.policy_id) };
    });

    let created;
    try {
      created = await gw.createEnrollmentToken(t1.e, {
        policyId: t1.policyId, duration: `${t1.plan.durationSeconds}s`, oneTimeOnly: t1.plan.oneTime,
        allowPersonalUsage: t1.plan.allowPersonalUsage, additionalData: tokenData(t1.id),
      });
    } catch (err) {
      await db.transaction((trx) => trx('android_enrollment_tokens').where({ id: t1.id, state: 'creating' })
        .update({ state: 'failed', ended_at: trx.fn.now() }));
      throw err;
    }
    const value = typeof created.value === 'string' ? created.value : '';
    if (!value) throw new TokenError(502, 'androidInvalidRequest', 'token without a value');
    const expiresAt = created.expirationTimestamp && Number.isFinite(Date.parse(created.expirationTimestamp))
      ? new Date(created.expirationTimestamp) : new Date(Date.now() + t1.plan.durationSeconds * 1000);
    await db.transaction(async (trx) => {
      const ref = await vault.createTenantSecret(tenantId, TOKEN_SECRET_PURPOSE, value, { userId: userId ?? null }, { trx });
      const n = await trx('android_enrollment_tokens').where({ id: t1.id, state: 'creating' })
        .update({ token_name: created.name, value_ref: ref, expires_at: expiresAt, state: 'active' });
      if (n !== 1) throw new TokenError(409, 'conflict', 'the token changed meanwhile');
    });
    return { id: t1.id, kind: t1.plan.kind, expiresAt: expiresAt.toISOString(), requiresApproval: t1.approval,
      payload: tokenPayload(t1.plan.kind, value, created.qrCode) };
  });
}

/** GET /api/android/enrollment-tokens/:id/payload: the value read back from the vault while active, audited. */
export async function revealEnrollmentToken(tenantId: number, userId: number, id: string, auditCtx: AuditWriteContext): Promise<CreatedToken> {
  return asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
    const row = await trx('android_enrollment_tokens').where({ id }).first([...TOKEN_COLUMNS, 'requires_approval']) as
      (TokenRow & { requires_approval: boolean }) | undefined;
    if (!row || row.state !== 'active' || !row.value_ref || new Date(row.expires_at).getTime() <= Date.now()) {
      throw new TokenError(404, 'notFound', 'no active token');
    }
    const value = await vault.readTenantSecret(tenantId, row.value_ref, { trx });
    try {
      await audit.appendInTx(trx, {
        tenantId, action: 'android.enrollment_token_revealed', target: { type: 'android_enrollment_token', id }, details: { tokenId: id, kind: row.kind },
      }, auditCtx);
      // qrCode is not kept: Google builds it from the value; the console renders the typed value and the link.
      return { id, kind: row.kind, expiresAt: new Date(row.expires_at).toISOString(), requiresApproval: row.requires_approval,
        payload: tokenPayload(row.kind, value.toString('utf8'), undefined) };
    } finally {
      value.fill(0);
    }
  }));
}

/** DELETE /api/android/enrollment-tokens/:id: deleted at Google (outside any transaction), then revoked and its value destroyed. */
export async function revokeEnrollmentToken(tenantId: number, userId: number, id: string, auditCtx: AuditWriteContext,
  o: { gateway?: AndroidGateway } = {}): Promise<'revoked' | 'not_active'> {
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    const row = await db('android_enrollment_tokens').where({ id }).first(TOKEN_COLUMNS) as TokenRow | undefined;
    if (!row) throw new TokenError(404, 'notFound', 'token not found');
    if (row.state !== 'active') return 'not_active';
    const e = await readEnterprise();
    if (e && row.token_name) {
      try {
        await gw.deleteEnrollmentToken(e, tokenIdOfName(e, row.token_name));
      } catch (err) {
        if (!(err instanceof AndroidError && err.kind === 'not_found')) throw err;
      }
    }
    await db.transaction(async (trx) => {
      const fresh = await trx('android_enrollment_tokens').where({ id }).forUpdate().first(['id', 'value_ref', 'state']) as
        { id: string; value_ref: string | null; state: string } | undefined;
      if (!fresh || fresh.state !== 'active') return;
      await endToken(trx, fresh, 'revoked', { revoked_at: trx.fn.now(), revoked_by: userId });
      await audit.appendInTx(trx, {
        tenantId, action: 'android.enrollment_token_revoked', target: { type: 'android_enrollment_token', id }, details: { tokenId: id, kind: row.kind },
      }, auditCtx);
    });
    return 'revoked';
  });
}

/** Hourly sweep: active tokens past their end become expired, their value destroyed (Google expires them itself). */
export async function expireEnrollmentTokens(tenantId: number, actor: DbActor = TOKENS_ACTOR): Promise<number> {
  return asTenant(tenantId, actor, () => db.transaction(async (trx) => {
    const rows = await trx('android_enrollment_tokens').where({ state: 'active' }).where('expires_at', '<=', trx.fn.now())
      .forUpdate().skipLocked().select('id', 'value_ref') as Array<{ id: string; value_ref: string | null }>;
    for (const r of rows) await endToken(trx, r, 'expired');
    return rows.length;
  }));
}

export interface RecoveryResult { adopted: number; failed: number; collected: number }

/**
 * Recovery of the interrupted creations (AN50), then garbage collection at Google (section 10.2 step 5, RR-9):
 * enrollmentTokens.list gives a partial view (no additionalData nor policyName, AMAPI-R2): the names no row of the
 * tenant knows are read one by one (get); a token whose additionalData is obg1:<id> of a row 'creating' is adopted
 * (its value sealed from the answer of get); one of the instance (prefix obg1:) without an active row is deleted,
 * except when its row is creating for less than 15 minutes; a row creating for more than 15 minutes that Google
 * does not know becomes failed. A token without the prefix is not the instance's: left alone.
 */
export async function recoverEnrollmentTokens(tenantId: number, o: { gateway?: AndroidGateway; actor?: DbActor; now?: Date } = {}): Promise<RecoveryResult> {
  const gw = o.gateway ?? androidGateway();
  const actor = o.actor ?? TOKENS_ACTOR;
  const out: RecoveryResult = { adopted: 0, failed: 0, collected: 0 };
  return asTenant(tenantId, actor, async () => {
    const e = await readEnterprise();
    if (!e || (e.state !== 'linked' && e.state !== 'unlinking')) return out;
    const rows = await db('android_enrollment_tokens').where({ enterprise_id: e.id }).select(TOKEN_COLUMNS) as TokenRow[];
    const byName = new Map(rows.filter((r) => r.token_name).map((r) => [r.token_name as string, r]));
    const byId = new Map(rows.map((r) => [r.id, r]));
    const seenIds = new Set<string>();
    let pageToken: string | undefined;
    let pages = 0;
    do {
      const page = await gw.listEnrollmentTokens(e, pageToken);
      for (const item of page.items) {
        if (byName.has(item.name)) { seenIds.add(byName.get(item.name)!.id); continue; }
        const full = await gw.getEnrollmentToken(e, tokenIdOfName(e, item.name));
        if (!full) continue;
        const id = tokenIdOf(full.additionalData);
        if (!id) continue;                                   // not a token of the instance
        seenIds.add(id);
        const row = byId.get(id);
        const now = (o.now ?? new Date()).getTime();
        // A creation in progress (creating for less than 15 minutes): neither adopted nor collected (RR-9); the
        // second transaction of the route finishes it.
        if (row && row.state === 'creating' && now - new Date(row.created_at).getTime() < CREATING_GRACE_MS) continue;
        if (row && row.state === 'creating' && typeof full.value === 'string' && full.value) {
          const value = full.value;
          const adopted = await db.transaction(async (trx) => {
            const ref = await vault.createTenantSecret(tenantId, TOKEN_SECRET_PURPOSE, value, { userId: null }, { trx });
            const expiresAt = full.expirationTimestamp && Number.isFinite(Date.parse(full.expirationTimestamp)) ? new Date(full.expirationTimestamp) : row.expires_at;
            const n = await trx('android_enrollment_tokens').where({ id, state: 'creating' })
              .update({ token_name: full.name, value_ref: ref, expires_at: expiresAt, state: 'active' });
            if (n !== 1) await trx('tenant_secrets').where({ id: ref }).delete();
            return n === 1;
          });
          if (adopted) out.adopted += 1;
          continue;
        }
        if (row && row.state === 'active') continue;
        await gw.deleteEnrollmentToken(e, tokenIdOfName(e, full.name));
        out.collected += 1;
      }
      pageToken = page.nextPageToken;
      pages += 1;
    } while (pageToken && pages < 50);
    // A creation older than the grace that Google does not know: it never reached Google.
    const now = (o.now ?? new Date()).getTime();
    for (const r of rows) {
      if (r.state === 'creating' && !seenIds.has(r.id) && now - new Date(r.created_at).getTime() >= CREATING_GRACE_MS) {
        const n = await db('android_enrollment_tokens').where({ id: r.id, state: 'creating' }).update({ state: 'failed', ended_at: db.fn.now() });
        out.failed += n;
      }
    }
    if (out.adopted || out.collected || out.failed) logger.info({ android: { tokens: out, tenantId } }, 'android: enrollment tokens recovered');
    return out;
  });
}
