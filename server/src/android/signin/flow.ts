// The sign-in URL flow of the device surface (lot AN-F2, section 10.5, §22.3; SEC-AN-1, AMAPI-R15 transposed):
//   1. GET /a/:key/signin?provisioningInfo=<id> (the device opens the signinUrl of the enterprise): the provisioningInfo
//      is read by the gateway FOR THE TENANT'S ENTERPRISE (a global resource at Google: the gateway compares its
//      enterprise field with the tenant's and answers 404 otherwise, then keeps six fields only, never the IMEI, the
//      MEID nor the serial number); the instance keeps the mode, the ownership, the API level and the model, chooses the
//      profile by rule, opens a session of 15 minutes (one per provisioning: a provisioning id that already gave a
//      token never gives another one) bound to the browser by a cookie, and sends the browser to Obligate (the e-mail
//      of the provisioningInfo as a login hint only, never stored); a personal device first gets the notice of a
//      personal device (USR-01), acknowledged by a form of the page;
//   2. GET /a/:key/signin/callback?code&state: the state and the cookie of the browser must be the session's (a state
//      replayed, an answer opened in another browser: refused, the session burnt); the code is exchanged once; the
//      identity must be an active end user of the tenant (e-mail); a token of kind signin is created for him (single
//      use, 15 minutes, the profile of the session) and the device is sent to Google's enrollment page; any refusal
//      sends it to Google's invalid page.
// The enrollment handler accepts a device of a signin token only when its session is issued (signin/guard.ts). Every
// statement runs in the tenant's context, actor enrollment:android-signin. Never logged nor audited: the state, the
// code, the nonce, the provisioning id, the e-mail, the token's value, the Google link.
import { ANDROID_SIGNIN_INVALID_URL, ANDROID_SIGNIN_TTL_SECONDS } from '@obligarth/shared';
import type { Knex } from 'knex';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { logger } from '../../utils/logger';
import { androidNotice, type AndroidNotice } from '../byod/notice';
import type { TenantFacts } from '../byod/invitations';
import { ENROLL_URL } from '../enrollment/methods';
import { validateAndroidProfile } from '../enrollment/profiles';
import { createEnrollmentToken, TokenError } from '../enrollment/tokens';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { AndroidError, AndroidNotFoundError } from '../gateway/errors';
import type { AndroidGateway } from '../gateway/types';
import { storedDetailOf } from './config';
import { isEmail, signinIdentity } from './identity';
import {
  chooseSigninProfile, factsOf, isAuthCode, isRandomToken, nonceHash, ownershipOfFacts, provisioningHash, provisioningIdOf, randomToken,
  signinFacts, stateHash, usageAdmits, type ProvisioningFacts, type SigninCandidate,
} from './rules';

export const SIGNIN_ACTOR: DbActor = Object.freeze({ type: 'enrollment', name: 'android-signin' }) as DbActor;
export const signinAuditCtx = (): AuditWriteContext => audit.system('enrollment', 'android-signin');

export type SigninLocale = 'fr' | 'en';

export type StartOutcome =
  /** Company device: the browser goes to Obligate; the cookie carries `nonce`. */
  | { kind: 'authorize'; url: string; nonce: string }
  /** Personal device: the notice first; the form carries `state`, the cookie `nonce`. */
  | { kind: 'notice'; state: string; nonce: string; notice: AndroidNotice }
  /** The device is sent to Google's invalid page; `reason` is for the audit and the tests only. */
  | { kind: 'invalid'; reason: string }
  /** Google or Obligate out of reach, nothing consumed: the page says so. */
  | { kind: 'unavailable' };

export type NoticeOutcome =
  | { kind: 'authorize'; url: string }
  | { kind: 'notice_changed'; notice: AndroidNotice | null; state: string }
  | { kind: 'invalid'; reason: string }
  | { kind: 'unavailable' };

export type CompleteOutcome =
  | { kind: 'redirect'; url: string; sessionId: string }
  | { kind: 'invalid'; reason: string };

interface SessionRow {
  id: string;
  tenant_id: number;
  enterprise_id: number;
  profile_id: string;
  nonce_hash: string;
  management_mode: string;
  ownership: string;
  api_level: number | null;
  model: string | null;
  state: string;
  locale: string;
  end_user_id: number | null;
  token_id: string | null;
  expires_at: Date;
}

const COLUMNS = ['id', 'tenant_id', 'enterprise_id', 'profile_id', 'nonce_hash', 'management_mode', 'ownership', 'api_level', 'model', 'state',
  'locale', 'end_user_id', 'token_id', 'expires_at'];

/** States in which a provisioning already went past the authentication: never a second session for it. */
const SPENT = ['exchanging', 'authenticated', 'issued', 'used'];

const factsOfRow = (r: SessionRow): ProvisioningFacts => ({
  managementMode: r.management_mode as ProvisioningFacts['managementMode'], ownership: r.ownership as ProvisioningFacts['ownership'],
  apiLevel: r.api_level === null ? null : Number(r.api_level), model: r.model,
});

/** The sign-in URL profiles of the tenant, oldest first, read back strictly (an invalid row is skipped). */
async function candidates(trx: Knex.Transaction, tenantId: number): Promise<SigninCandidate[]> {
  const rows = await trx('enrollment_profiles').where({ tenant_id: tenantId, platform: 'android', method: 'android_signin_url' })
    .whereNull('archived_at').orderBy([{ column: 'created_at', order: 'asc' }, { column: 'id', order: 'asc' }])
    .select('id', 'method', 'ownership', 'enabled', 'settings') as Array<Record<string, unknown>>;
  const out: SigninCandidate[] = [];
  rows.forEach((r, rank) => {
    const v = validateAndroidProfile({ method: r.method, ownership: r.ownership, settings: r.settings });
    if (!v.ok) return;
    out.push({ id: String(r.id), method: String(r.method), ownership: r.ownership as SigninCandidate['ownership'], usage: v.settings.deviceUsage,
      enabled: r.enabled === true, minimumApiLevel: v.settings.minimumApiLevel ?? null, rank });
  });
  return out;
}

async function policyPushed(trx: Knex.Transaction, profileId: string): Promise<boolean> {
  const pol = await trx('android_enrollment_policies').where({ profile_id: profileId }).first('state') as { state: string } | undefined;
  return pol?.state === 'pushed';
}

/** Step 1 (see the head of this file). `callback`: the redirect_uri of the tenant (<base>/a/<key>/signin/callback). */
export async function startSignin(t: TenantFacts, a: { provisioningInfo: unknown; locale: SigninLocale; callback: string },
  o: { gateway?: AndroidGateway } = {}): Promise<StartOutcome> {
  const gw = o.gateway ?? androidGateway();
  const id = provisioningIdOf(a.provisioningInfo);
  if (!id) return { kind: 'invalid', reason: 'malformed' };
  const pre = await asTenant(t.tenantId, SIGNIN_ACTOR, async () => {
    const e = await readEnterprise();
    if (!e || e.state !== 'linked') return null;
    const row = await db('android_enterprises').where({ id: e.id }).first('signin') as { signin: unknown } | undefined;
    const detail = row ? storedDetailOf(row.signin) : null;
    return detail ? { e, detail } : null;
  });
  if (!pre) return { kind: 'invalid', reason: 'not_enabled' };
  // SEC-AN-1: read for the tenant's enterprise; another enterprise's provisioning is a 404 of the gateway (alert).
  let info;
  try {
    // Outside any transaction (G-A1), in the tenant's context (the gateway checks the ownership of the reference).
    info = await asTenant(t.tenantId, SIGNIN_ACTOR, () => gw.provisioningInfo(pre.e, id));
  } catch (err) {
    if (err instanceof AndroidNotFoundError) return { kind: 'invalid', reason: 'unknown_provisioning' };
    if (err instanceof AndroidError) return { kind: 'unavailable' };
    throw err;
  }
  const announced = factsOf(info);
  if (!announced) return { kind: 'invalid', reason: 'unsupported_device' };
  if (!usageAdmits(pre.detail.allowPersonalUsage, announced)) return { kind: 'invalid', reason: 'usage_refused' };
  // The mode the token will give the device (a company device under ALLOWED becomes a COPE): kept in the session, the
  // profile chosen for it, checked against the enrolled Device by the enrollment handler.
  const facts = signinFacts(announced, pre.detail.allowPersonalUsage);
  const provider = signinIdentity();
  if (!(await provider.origin())) return { kind: 'unavailable' };
  const state = randomToken();
  const nonce = randomToken();
  const personal = facts.ownership === 'PERSONALLY_OWNED';
  const step = await asTenant(t.tenantId, SIGNIN_ACTOR, () => db.transaction(async (trx): Promise<{ ok: true } | { ok: false; reason: string }> => {
    const profile = chooseSigninProfile(await candidates(trx, t.tenantId), facts);
    if (!profile || !(await policyPushed(trx, profile.id))) return { ok: false, reason: 'no_profile' };
    const ph = provisioningHash(t.uuid, id);
    const prev = await trx('android_signin_sessions').where({ tenant_id: t.tenantId, provisioning_hash: ph }).forUpdate().first('id', 'state') as
      { id: string; state: string } | undefined;
    // A provisioning that already went past the authentication never opens a second session (no second token, no
    // second identity for the same device).
    if (prev && SPENT.includes(prev.state)) return { ok: false, reason: 'provisioning_used' };
    if (prev) await trx('android_signin_sessions').where({ tenant_id: t.tenantId, id: prev.id }).delete();
    const now = new Date();
    await trx('android_signin_sessions').insert({
      tenant_id: t.tenantId, enterprise_id: pre.e.id, profile_id: profile.id, provisioning_hash: ph, state_hash: stateHash(t.uuid, state),
      nonce_hash: nonceHash(nonce), management_mode: facts.managementMode, ownership: facts.ownership, api_level: facts.apiLevel, model: facts.model,
      state: personal ? 'notice' : 'pending', locale: a.locale, created_at: now, updated_at: now,
      expires_at: new Date(now.getTime() + ANDROID_SIGNIN_TTL_SECONDS * 1000),
    });
    return { ok: true };
  // Two first requests of the same provisioning at once: the unique index keeps one, the other is refused.
  })).catch((err: { code?: string }) => {
    if (err?.code === '23505') return { ok: false as const, reason: 'busy' };
    throw err;
  });
  if (!step.ok) return { kind: 'invalid', reason: step.reason };
  if (personal) {
    const notice = await asTenant(t.tenantId, SIGNIN_ACTOR, () => androidNotice().noticeFor(db, t.tenantId, 'personal', a.locale,
      { method: 'android_byod_link', organization: t.name }));
    if (!notice) return { kind: 'unavailable' };
    return { kind: 'notice', state, nonce, notice };
  }
  const url = await provider.authorizeUrl({ state, redirectUri: a.callback, loginHint: isEmail(info.authenticatedUserEmail) ? info.authenticatedUserEmail : undefined });
  if (!url) return { kind: 'unavailable' };
  return { kind: 'authorize', url, nonce };
}

/** The session of a state in the tenant, locked, with its browser checked; null when unknown. */
async function sessionOf(trx: Knex.Transaction, t: TenantFacts, state: unknown): Promise<SessionRow | null> {
  if (!isRandomToken(state)) return null;
  return await trx('android_signin_sessions').where({ tenant_id: t.tenantId, state_hash: stateHash(t.uuid, state) }).forUpdate()
    .first(COLUMNS) as SessionRow | undefined ?? null;
}

const live = (r: SessionRow, now: Date): boolean => new Date(r.expires_at).getTime() > now.getTime();

async function burn(trx: Knex.Transaction, t: TenantFacts, r: SessionRow, failure: string): Promise<void> {
  await trx('android_signin_sessions').where({ tenant_id: t.tenantId, id: r.id }).whereNotIn('state', ['issued', 'used'])
    .update({ state: 'failed', failure, updated_at: trx.fn.now() });
  await audit.appendInTx(trx, {
    tenantId: t.tenantId, action: 'android.signin_refused', target: { type: 'android_signin_session', id: r.id },
    details: { sessionId: r.id, reason: failure },
  }, signinAuditCtx());
}

/**
 * The form of the notice of a personal device (step 1 for a personal device): the state of the page and the cookie of
 * the browser, the acknowledgement of the current notice. The acknowledgement is recorded, the state renewed for the
 * authorization request (the state of a page never reaches Obligate), the browser sent to Obligate.
 */
export async function acknowledgeSigninNotice(t: TenantFacts, a: { state: unknown; nonce: unknown; noticeVersionId: string; locale: SigninLocale;
  callback: string }): Promise<NoticeOutcome> {
  const provider = signinIdentity();
  const next = randomToken();
  const out = await asTenant(t.tenantId, SIGNIN_ACTOR, () => db.transaction(async (trx): Promise<NoticeOutcome | { kind: 'go' }> => {
    const now = new Date();
    const r = await sessionOf(trx, t, a.state);
    if (!r || r.state !== 'notice' || !live(r, now)) return { kind: 'invalid', reason: 'unknown_state' };
    if (!isRandomToken(a.nonce) || nonceHash(a.nonce) !== r.nonce_hash) {
      await burn(trx, t, r, 'browser_mismatch');
      return { kind: 'invalid', reason: 'browser_mismatch' };
    }
    const notice = await androidNotice().noticeFor(trx, t.tenantId, 'personal', a.locale, { method: 'android_byod_link', organization: t.name });
    if (!notice || notice.versionId !== a.noticeVersionId) return { kind: 'notice_changed', notice, state: String(a.state) };
    const ackId = await androidNotice().recordAcknowledgement(trx, t.tenantId, { sessionId: r.id, versionId: notice.versionId, locale: a.locale, at: now });
    await trx('android_signin_sessions').where({ tenant_id: t.tenantId, id: r.id, state: 'notice' }).update({
      state: 'pending', state_hash: stateHash(t.uuid, next), notice_version_id: notice.versionId, notice_ack_id: ackId, acknowledged_at: now,
      locale: a.locale, updated_at: now,
    });
    await audit.appendInTx(trx, {
      tenantId: t.tenantId, action: 'android.signin_notice_acknowledged', target: { type: 'android_signin_session', id: r.id },
      details: { sessionId: r.id, noticeVersionId: notice.versionId, locale: a.locale },
    }, signinAuditCtx());
    return { kind: 'go' };
  }));
  if (out.kind !== 'go') return out;
  const url = await provider.authorizeUrl({ state: next, redirectUri: a.callback });
  return url ? { kind: 'authorize', url } : { kind: 'unavailable' };
}

/** Step 2 (see the head of this file). */
export async function completeSignin(t: TenantFacts, a: { state: unknown; code: unknown; nonce: unknown; callback: string },
  o: { gateway?: AndroidGateway } = {}): Promise<CompleteOutcome> {
  // 2a. The session: pending → exchanging, once (a replayed answer finds exchanging or later: refused).
  const first = await asTenant(t.tenantId, SIGNIN_ACTOR, () => db.transaction(async (trx): Promise<SessionRow | { reason: string }> => {
    const now = new Date();
    const r = await sessionOf(trx, t, a.state);
    if (!r) return { reason: 'unknown_state' };
    if (r.state !== 'pending' || !live(r, now)) {
      if (r.state === 'pending') await burn(trx, t, r, 'expired');
      return { reason: r.state === 'pending' ? 'expired' : 'replayed' };
    }
    // The answer must come back to the browser that asked (login CSRF: an authorization link opened by someone else).
    if (!isRandomToken(a.nonce) || nonceHash(a.nonce) !== r.nonce_hash) {
      await burn(trx, t, r, 'browser_mismatch');
      return { reason: 'browser_mismatch' };
    }
    if (!isAuthCode(a.code)) {
      await burn(trx, t, r, 'malformed');
      return { reason: 'malformed' };
    }
    await trx('android_signin_sessions').where({ tenant_id: t.tenantId, id: r.id }).update({ state: 'exchanging', updated_at: now });
    return r;
  }));
  if ('reason' in first) return { kind: 'invalid', reason: first.reason };
  const session = first;
  const fail = async (reason: string): Promise<CompleteOutcome> => {
    await asTenant(t.tenantId, SIGNIN_ACTOR, () => db.transaction((trx) => burn(trx, t, session, reason)));
    return { kind: 'invalid', reason };
  };

  // 2b. The code, exchanged once with Obligate (outside any transaction).
  let identity;
  try {
    identity = await signinIdentity().exchange(String(a.code), a.callback);
  } catch (err) {
    logger.warn({ android: { signin: 'exchange_failed', tenantId: t.tenantId } }, 'android: sign-in code not exchanged');
    void err;
    identity = null;
  }
  if (!identity || !isEmail(identity.email)) return fail('auth_refused');

  // 2c. An active end user of the tenant, the profile still serving.
  const auth = await asTenant(t.tenantId, SIGNIN_ACTOR, () => db.transaction(async (trx): Promise<{ endUserId: number } | { reason: string }> => {
    const users = await trx('end_users').where({ tenant_id: t.tenantId, status: 'active' }).whereRaw('lower(email) = lower(?)', [identity.email])
      .limit(2).select('id') as Array<{ id: number }>;
    if (users.length !== 1) return { reason: 'unknown_user' };
    const facts = factsOfRow(session);
    const profile = (await candidates(trx, t.tenantId)).find((c) => c.id === String(session.profile_id));
    if (!profile || !chooseSigninProfile([{ ...profile, rank: 0 }], facts)) return { reason: 'no_profile' };
    const n = await trx('android_signin_sessions').where({ tenant_id: t.tenantId, id: session.id, state: 'exchanging' })
      .update({ state: 'authenticated', end_user_id: users[0].id, authenticated_at: trx.fn.now(), updated_at: trx.fn.now() });
    if (Number(n) !== 1) return { reason: 'replayed' };
    return { endUserId: Number(users[0].id) };
  }));
  if ('reason' in auth) return fail(auth.reason);

  // 2d. The token (single use, 15 minutes), outside any transaction.
  let created;
  try {
    created = await createEnrollmentToken(t.tenantId, null, { profileId: String(session.profile_id), endUserId: auth.endUserId },
      signinAuditCtx(), { gateway: o.gateway, actor: SIGNIN_ACTOR, signinSession: session.id });
  } catch (err) {
    if (err instanceof AndroidError || err instanceof TokenError) {
      logger.warn({ android: { signin: 'token_not_created', tenantId: t.tenantId, kind: err instanceof AndroidError ? err.kind : err.code } },
        'android: sign-in token not created');
      return fail(err instanceof AndroidError ? 'google_unavailable' : 'token_refused');
    }
    throw err;
  }
  const url = created.payload.form === 'signin' ? created.payload.url : '';
  if (!url.startsWith(`${ENROLL_URL}?et=`)) return fail('token_refused');
  // The session must still be authenticated: the hourly sweep may have expired it during the call to Google. A token
  // whose session is not issued never reaches the device (its enrollment would be quarantined anyway): the device goes
  // to the invalid page, the token (single use, 15 minutes) stays unused at Google.
  const issued = await asTenant(t.tenantId, SIGNIN_ACTOR, () => db.transaction(async (trx): Promise<boolean> => {
    const n = await trx('android_signin_sessions').where({ tenant_id: t.tenantId, id: session.id, state: 'authenticated' })
      .where('expires_at', '>', trx.fn.now())
      .update({ state: 'issued', token_id: created.id, issued_at: trx.fn.now(), updated_at: trx.fn.now() });
    if (Number(n) !== 1) {
      await burn(trx, t, session, 'expired');
      return false;
    }
    await audit.appendInTx(trx, {
      tenantId: t.tenantId, action: 'android.signin_completed', target: { type: 'android_signin_session', id: session.id },
      details: { sessionId: session.id, profileId: String(session.profile_id), endUserId: auth.endUserId, tokenId: created.id,
        ownership: ownershipOfFacts(factsOfRow(session)) },
    }, signinAuditCtx());
    return true;
  }));
  if (!issued) return { kind: 'invalid', reason: 'expired' };
  return { kind: 'redirect', url, sessionId: session.id };
}

/** Where a refused sign-in sends the device (Google's page). */
export const SIGNIN_INVALID_URL = ANDROID_SIGNIN_INVALID_URL;

/**
 * Hourly sweep (android.maintenance): sessions past their end that never gave a token become expired; the failed and
 * expired ones go after 30 days.
 */
export async function expireSigninSessions(tenantId: number, actor: DbActor = SIGNIN_ACTOR): Promise<number> {
  return asTenant(tenantId, actor, () => db.transaction(async (trx) => {
    const n = await trx('android_signin_sessions').where({ tenant_id: tenantId }).whereIn('state', ['notice', 'pending', 'exchanging', 'authenticated'])
      .where('expires_at', '<=', trx.fn.now()).update({ state: 'expired', updated_at: trx.fn.now() });
    // An issued session stays issued: the ENROLLMENT of its device may arrive late (backlog, instance stopped), after
    // the token itself expired. Failed and expired sessions go after 30 days; issued and used ones stay (the
    // acknowledgement of the notice of a personal device: no purge in v1, as the BYOD invitations).
    await trx('android_signin_sessions').where({ tenant_id: tenantId }).whereIn('state', ['failed', 'expired'])
      .where('created_at', '<', trx.raw("now() - interval '30 days'")).delete();
    return Number(n);
  }));
}
