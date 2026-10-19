import { createHmac, randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import { config } from '../../config';
import { audit } from '../../audit';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { raiseInTx } from '../alerts/service';
import { realtime } from '../realtime';
import { checkFormToken as checkToken, newFormToken as newToken } from './adeRules';
import { challengeTtlFor, composeSigned, endSession, withdrawalOf, type TenantFacts } from './flow';
import type { SurfaceLocale } from './i18n';
import { enrollmentNotice, type EnrollmentNotice } from './notice';
import { invitationHash, newAccessToken, normalizeInvitationCode, sha256Hex } from './tokens';

// =============================================================================
// Account-driven enrollment of a personal device (docs: integration-apple-edge §10.5, ENR-05; decision D10 of
// 15/10: BYOD Apple at the MVP), the database and apple-edge side of the BYOD routes of the device surface
// (surface.ts renders the answers). Apple-hosted discovery (iOS and iPadOS 18.2 and later: apple-edge §7.7):
//   1. GET  /byod/discovery   → the base URL of the enrollment (served while a BYOD profile of the tenant serves);
//   2. POST /byod/enroll      without a bearer → 401, WWW-Authenticate: Bearer method="apple-as-web" url=…/byod/auth;
//   3. GET  /byod/auth        the web view of the device (user-identifier: the Managed Apple Account the
//      employee signed in with [J1, J-5]): the notice of a personal device and the invitation code;
//   4. POST /byod/auth        the code of a live invitation of this account: one use reserved, the session
//      acknowledged (Managed Apple Account, end user of the invitation), the notice's acknowledgement, a
//      single-use bearer (oba_, hashed, 15 minutes); 303 to apple-remotemanagement-user-login://…;
//   5. POST /byod/enroll      with the bearer (consumed): the BYOD profile (AssignedManagedAppleID,
//      EnrollmentMode BYOD, no AccessRights: §10.2), profile_issued; the outbox does the rest (User Enrollment:
//      an EnrollmentID, never a UDID nor a serial number: INV-01).
// A wrong code counts on every live invitation of the account (and on the invitation of the code when another
// account presents it), per (invitation, address) first: five wrong codes from one address shut it out of the
// invitation, thirty counted from addresses under their own cap revoke the invitation (alert
// enrollment.invitation_locked, protective audit entry; decision of the owners of 19/10/2026). The form token of the web view binds the account of the GET to its POST (HMAC of a key derived
// from SESSION_SECRET, 30 minutes): no state before the code. Every statement runs in the tenant's context,
// actor enrollment:byod.
// =============================================================================

export const BYOD_SESSION_TTL_MS = 60 * 60_000;
export const ACCESS_TOKEN_TTL_MS = 15 * 60_000;
export const BYOD_CHALLENGE_TTL_S = 900;
/** Wrong codes from one address that shut this address out of an invitation (decision of the owners of 19/10/2026,
 *  review of lot C2, invitation option A). */
export const MAX_WRONG_CODES_PER_ADDRESS = 5;
/** Wrong codes, counted from addresses still under their own cap, that revoke an invitation (§10.5; the global cap,
 *  higher than one address's since 19/10/2026: one third party alone no longer revokes it). */
export const MAX_WRONG_CODES = 30;

/** The HMAC of an address (never stored in clear), with the tenant's uuid: 32 hex characters. */
export function addressHmac(tenantUuid: string, address: string): string {
  const key = createHmac('sha256', String(config.sessionSecret)).update('obligarth.invitation-address.v1').digest();
  return createHmac('sha256', key).update(`${tenantUuid}
${address}`).digest('hex').slice(0, 32);
}

export { normalizeAccount } from './adeRules';

/** Is there a BYOD profile of the tenant that serves enrollments (method byod_account, enabled, not archived)? */
export async function byodServes(tenantId: number, actor: DbActor): Promise<boolean> {
  const p = await asTenant(tenantId, actor, () => db('enrollment_profiles')
    .where({ tenant_id: tenantId, method: 'byod_account', enabled: true }).whereNull('archived_at').first('id'));
  return !!p;
}

/** The notice of a personal device (the profile is not known before the code: the notice of the method). */
export function byodNotice(t: TenantFacts, locale: SurfaceLocale, actor: DbActor): Promise<EnrollmentNotice | null> {
  return asTenant(t.tenantId, actor, () => enrollmentNotice().noticeFor(db, t.tenantId, 'personal', locale,
    { method: 'byod_account', organization: t.name }));
}

/** The form token of the web view (adeRules.ts), under SESSION_SECRET. */
export const newFormToken = (key: string, account: string | null, now = Date.now()): string => newToken(String(config.sessionSecret), key, account, now);
export const checkFormToken = (token: unknown, key: string, account: string | null, now = Date.now()): boolean =>
  checkToken(String(config.sessionSecret), token, key, account, now);

export type ByodAuthOutcome =
  | { kind: 'ok'; sessionId: string; accessToken: string }
  /** The code is not one of a live invitation of this account (counted). */
  | { kind: 'wrong_code' }
  /** This address gave MAX_WRONG_CODES_PER_ADDRESS wrong codes for the invitations at stake: refused, not counted. */
  | { kind: 'address_locked' }
  /** The notice changed since the page. */
  | { kind: 'notice_changed'; notice: EnrollmentNotice | null };

interface LiveInvitation { id: string; profile_id: string; managed_apple_account: string; end_user_id: number | null; prefix: string }

/** The wrong codes of `address` for each of `ids` (0 when none). */
async function addressFailures(trx: Knex.Transaction, tenantId: number, ids: string[], address: string): Promise<Map<string, number>> {
  if (!ids.length) return new Map();
  const rows = await trx('enrollment_invitation_address_attempts').where({ tenant_id: tenantId, address_hmac: address })
    .whereIn('token_id', ids).select('token_id', 'failed') as Array<{ token_id: string; failed: number }>;
  return new Map(rows.map((r) => [String(r.token_id), Number(r.failed)]));
}

/**
 * Counts a wrong code on `ids` (locked: FOR UPDATE by the caller's read), per (invitation, address) first: an address
 * under MAX_WRONG_CODES_PER_ADDRESS also counts on the invitation itself, an address over it no longer does (it is
 * shut out of the invitation). An invitation that reaches MAX_WRONG_CODES is revoked, its alert raised and the
 * protective entry written (in the transaction). An invitation counted here is live (a use left): it has no open
 * session to end.
 */
async function countWrongCode(trx: Knex.Transaction, tenantId: number, invitations: LiveInvitation[], address: string): Promise<void> {
  const before = await addressFailures(trx, tenantId, invitations.map((x) => x.id), address);
  for (const inv of invitations) {
    const prior = before.get(inv.id) ?? 0;
    await trx.raw(`INSERT INTO enrollment_invitation_address_attempts (tenant_id, token_id, address_hmac, failed, updated_at)
      VALUES (?, ?, ?, 1, now())
      ON CONFLICT (tenant_id, token_id, address_hmac) DO UPDATE
        SET failed = LEAST(enrollment_invitation_address_attempts.failed + 1, 1000), updated_at = now()`, [tenantId, inv.id, address]);
    if (prior >= MAX_WRONG_CODES_PER_ADDRESS) continue;
    const [row] = await trx('enrollment_tokens').where({ tenant_id: tenantId, id: inv.id })
      .update({ failed_attempts: trx.raw('LEAST(failed_attempts + 1, 1000)') }, ['failed_attempts', 'revoked_at']) as
      Array<{ failed_attempts: number; revoked_at: Date | null }>;
    if (!row || row.revoked_at || Number(row.failed_attempts) < MAX_WRONG_CODES) continue;
    await trx('enrollment_tokens').where({ tenant_id: tenantId, id: inv.id }).whereNull('revoked_at').update({ revoked_at: new Date() });
    await raiseInTx(trx, tenantId, 'enrollment.invitation_locked', { discriminant: inv.id, navigateTo: '/device-enrollment' });
    await audit.appendInTx(trx, {
      tenantId, action: 'apple.enrollment_token_revoked', target: { type: 'enrollment_token', id: inv.id },
      details: { kind: 'invitation', prefix: inv.prefix, profileId: inv.profile_id, reason: 'wrong_codes', attempts: MAX_WRONG_CODES },
    }, audit.system('enrollment', 'byod'));
  }
}

const LIVE = (q: Knex.QueryBuilder): Knex.QueryBuilder => q.where('t.kind', 'invitation')
  .whereRaw('t.revoked_at IS NULL AND t.expires_at > now() AND t.uses < t.max_uses');

/**
 * POST /t/:key/byod/auth (§10.5 step 4), in one transaction: the invitation of the code (hashed with the tenant's
 * uuid), live, of a BYOD profile that serves, whose Managed Apple Account is `account` (case ignored); one use
 * reserved; the session acknowledged with a single-use bearer. Otherwise a wrong code, counted.
 */
export async function byodAuthenticate(t: TenantFacts, a: { account: string; code: unknown; noticeVersionId: string; locale: SurfaceLocale; address: string },
  actor: DbActor): Promise<ByodAuthOutcome> {
  const code = normalizeInvitationCode(a.code);
  const address = addressHmac(t.uuid, a.address);
  const out = await asTenant(t.tenantId, actor, () => db.transaction(async (trx): Promise<ByodAuthOutcome> => {
    const notice = await enrollmentNotice().noticeFor(trx, t.tenantId, 'personal', a.locale, { method: 'byod_account', organization: t.name });
    if (!notice || notice.versionId !== a.noticeVersionId) return { kind: 'notice_changed', notice };
    // The live invitations of the account and the invitation of the code, locked in one statement in the order of
    // their ids: two concurrent answers (each with the code of the other's account) never wait on each other.
    const codeHash = code ? invitationHash(t.uuid, code) : null;
    const locked = await LIVE(trx('enrollment_tokens as t').where('t.tenant_id', t.tenantId))
      .where((w) => {
        w.whereRaw('lower(t.managed_apple_account) = ?', [a.account]);
        if (codeHash) w.orWhere('t.token_hash', codeHash);
      })
      .orderBy('t.id').forUpdate()
      .select('t.id', 't.profile_id', 't.managed_apple_account', 't.end_user_id', 't.prefix', 't.token_hash') as Array<LiveInvitation & { token_hash: string }>;
    const strip = ({ token_hash: _h, ...rest }: LiveInvitation & { token_hash: string }): LiveInvitation => rest;
    const ofAccount = locked.filter((x) => String(x.managed_apple_account).toLowerCase() === a.account).map(strip);
    const found = codeHash ? locked.find((x) => x.token_hash === codeHash) : undefined;
    const inv = found ? strip(found) : undefined;
    // The address shut out of the invitation of the code, or of every invitation of the account without a code of its
    // own: refused before anything is checked or counted (a right code from this address no longer serves).
    const failures = await addressFailures(trx, t.tenantId, locked.map((x) => String(x.id)), address);
    const shut = (id: string): boolean => (failures.get(id) ?? 0) >= MAX_WRONG_CODES_PER_ADDRESS;
    if (inv ? shut(inv.id) : ofAccount.length > 0 && ofAccount.every((x) => shut(x.id))) return { kind: 'address_locked' };
    const serves = inv ? !(await withdrawalOf(trx, t.tenantId, inv.profile_id, null))
      && !!(await trx('enrollment_profiles').where({ tenant_id: t.tenantId, id: inv.profile_id, method: 'byod_account' }).first('id')) : false;
    if (!inv || !serves || String(inv.managed_apple_account).toLowerCase() !== a.account) {
      const counted = [...ofAccount];
      // A right code presented with another account: the code leaked, its invitation counts too.
      if (inv && serves && !counted.some((x) => x.id === inv.id)) counted.push(inv);
      await countWrongCode(trx, t.tenantId, counted, address);
      return { kind: 'wrong_code' };
    }
    const reserved = await trx('enrollment_tokens').where({ tenant_id: t.tenantId, id: inv.id })
      .whereRaw('revoked_at IS NULL AND expires_at > now() AND uses < max_uses')
      .update({ uses: trx.raw('uses + 1'), last_used_at: trx.fn.now() }, ['id']) as Array<{ id: string }>;
    if (reserved.length !== 1) return { kind: 'wrong_code' };
    const now = new Date();
    const sessionId = randomUUID();
    const access = newAccessToken();
    await trx('enrollment_sessions').insert({
      id: sessionId, tenant_id: t.tenantId, profile_id: inv.profile_id, token_id: inv.id, method: 'byod_account', ownership: 'personal',
      state: 'acknowledged', state_at: now, managed_apple_account: a.account, end_user_id: inv.end_user_id,
      access_token_hash: access.hash, access_token_expires_at: new Date(now.getTime() + ACCESS_TOKEN_TTL_MS),
      notice_version_id: notice.versionId, acknowledged_at: now, locale: a.locale, expires_at: new Date(now.getTime() + BYOD_SESSION_TTL_MS),
    });
    const ackId = await enrollmentNotice().recordAcknowledgement(trx, t.tenantId, { sessionId, versionId: notice.versionId, locale: a.locale, at: now });
    await trx('enrollment_sessions').where({ tenant_id: t.tenantId, id: sessionId }).update({ notice_ack_id: ackId });
    return { kind: 'ok', sessionId, accessToken: access.value };
  }));
  if (out.kind === 'ok') realtime.sessionChanged(t.tenantId, out.sessionId);
  return out;
}

export type ByodEnrollOutcome =
  | { kind: 'profile'; body: Buffer; signed: boolean; sessionId: string }
  /** No bearer, or one unknown, consumed, expired, of a session ended: the device signs in again. */
  | { kind: 'unauthorized' }
  | { kind: 'not_ready' }
  | { kind: 'signing_unavailable' }
  | { kind: 'retry' };

/**
 * POST /t/:key/byod/enroll with the bearer (§10.5 step 5): consumed in a short transaction, then, outside any
 * transaction, the BYOD profile composed and signed; the session moves to profile_issued. A failure of the service
 * (no push certificate, apple-edge) gives the bearer back while it lives, so that the device may try again; signing
 * required and unavailable ends the session (its invitation's use given back).
 */
export async function byodEnroll(t: TenantFacts, bearer: string, actor: DbActor): Promise<ByodEnrollOutcome> {
  const hash = sha256Hex(bearer);
  let ended: string | null = null;
  const s = await asTenant(t.tenantId, actor, () => db.transaction(async (trx) => {
    const row = await trx('enrollment_sessions')
      .where({ tenant_id: t.tenantId, access_token_hash: hash, method: 'byod_account' }).forUpdate()
      .first('id', 'state', 'profile_id', 'token_id', 'managed_apple_account', 'locale', 'access_token_expires_at', 'expires_at') as Record<string, any> | undefined;
    if (!row) return null;
    await trx('enrollment_sessions').where({ tenant_id: t.tenantId, id: row.id }).update({ access_token_hash: null, updated_at: new Date() });
    const now = Date.now();
    if (row.state !== 'acknowledged' || !row.managed_apple_account) return null;
    if (!row.access_token_expires_at || new Date(row.access_token_expires_at).getTime() <= now || new Date(row.expires_at).getTime() <= now) return null;
    const withdrawn = await withdrawalOf(trx, t.tenantId, String(row.profile_id), row.token_id ? String(row.token_id) : null);
    if (withdrawn) {
      if (await endSession(trx, t.tenantId, String(row.id), 'failed', withdrawn, ['acknowledged'])) ended = String(row.id);
      return null;
    }
    return {
      id: String(row.id), account: String(row.managed_apple_account), locale: (row.locale === 'en' ? 'en' : 'fr') as SurfaceLocale,
      accessExpiresAt: new Date(row.access_token_expires_at), expiresAt: new Date(row.expires_at),
    };
  }));
  if (ended) realtime.sessionChanged(t.tenantId, ended);
  if (!s) return { kind: 'unauthorized' };
  // The challenge lives no longer than the session (INT-C1-R7); less than a minute left: the device signs in again.
  const ttlSeconds = challengeTtlFor(BYOD_CHALLENGE_TTL_S, s.expiresAt);
  if (ttlSeconds === null) return { kind: 'unauthorized' };
  const out = await composeSigned(t, { id: s.id, method: 'byod_account', ownership: 'personal', locale: s.locale }, actor,
    { ttlSeconds, byod: { managedAppleId: s.account } });
  const giveBack = () => asTenant(t.tenantId, actor, () => db('enrollment_sessions')
    .where({ tenant_id: t.tenantId, id: s.id, state: 'acknowledged' }).whereNull('access_token_hash')
    .where('access_token_expires_at', '>', new Date())
    .update({ access_token_hash: hash, updated_at: new Date() })).catch(() => 0);
  switch (out.kind) {
    case 'not_ready':
      await giveBack();
      return { kind: 'not_ready' };
    case 'retry':
      await giveBack();
      return { kind: 'retry' };
    case 'signing_unavailable':
      await asTenant(t.tenantId, actor, () => db.transaction((trx) => endSession(trx, t.tenantId, s.id, 'failed', 'signing_unavailable', ['acknowledged'])));
      realtime.sessionChanged(t.tenantId, s.id);
      return { kind: 'signing_unavailable' };
    default:
      break;
  }
  const moved = await asTenant(t.tenantId, actor, () => db('enrollment_sessions')
    .where({ tenant_id: t.tenantId, id: s.id, state: 'acknowledged' })
    .update({ state: 'profile_issued', state_at: new Date(), challenge_id: out.challengeId, updated_at: new Date() }));
  realtime.sessionChanged(t.tenantId, s.id);
  if (Number(moved) !== 1) return { kind: 'unauthorized' };
  return { kind: 'profile', body: out.body, signed: out.signed, sessionId: s.id };
}
