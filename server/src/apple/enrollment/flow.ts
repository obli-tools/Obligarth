import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import { MASTER_TENANT_ID, type EnrollmentProfileMethod, type Ownership } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { logger } from '../../utils/logger';
import { isNoticeIncomplete } from '../../privacy/notice/errors';
import { edgeActorOf } from '../actors';
import { raiseAlert, resolveAlert } from '../alerts/service';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import { realtime } from '../realtime';
import { appleTenants } from '../tenants/registry';
import { fill, textsFor, type SurfaceLocale } from './i18n';
import { composeEnrollmentProfile, ProfileCompositionError } from './mobileconfig';
import { enrollmentNotice, type EnrollmentNotice } from './notice';
import { newNonce, sha256Hex } from './tokens';

// =============================================================================
// OTA enrollment (docs: integration-apple-edge §10.3, ENR-03), the database
// and apple-edge side of the device surface (surface.ts renders the answers):
//   1. the page reads the link (valid: not revoked, not expired, a use left,
//      profile active) and the notice; it writes nothing (link previews of
//      messaging apps consume nothing);
//   2. the acknowledgement reserves one use, opens the session
//      (acknowledged), records the notice's acknowledgement and a single-use
//      download nonce (obn_, hashed, 10 minutes), in one transaction;
//   3. the download consumes the nonce in a short transaction, then, outside
//      any transaction, gets the SCEP challenge, composes and signs the
//      profile; the session moves to profile_issued. A failure of apple-edge
//      keeps the session acknowledged and hands a new nonce (the previous one
//      is erased at its consumption);
//   4. the outbox does the rest (certificate_issued, authenticated, enrolled);
//   5. a session not enrolled within one hour expires and gives its use back
//      (jobs.ts): a use is consumed for good by an enrollment only.
// Every statement runs in the tenant's context, actor enrollment:enroll. The
// SCEP challenge exists in clear in the issued profile only: never stored nor
// logged (challenge_id is kept).
// =============================================================================

/** Lifetime of an OTA session, of a download nonce, of the SCEP challenge of an OTA profile. */
export const OTA_SESSION_TTL_MS = 60 * 60_000;
export const NONCE_TTL_MS = 10 * 60_000;
export const OTA_CHALLENGE_TTL_S = 900;

export interface TenantFacts {
  tenantId: number;
  key: string;
  name: string;
  uuid: string;
}

export interface LinkFacts {
  tokenId: string;
  profileId: string;
  method: EnrollmentProfileMethod;
  ownership: Ownership;
  locale: string;
  endUserId: number | null;
}

/** The tenant's display name and uuid (its context). */
export async function tenantFacts(tenantId: number, key: string, actor: DbActor): Promise<TenantFacts | null> {
  const row = await asTenant(tenantId, actor, () => db('tenants').where({ id: tenantId }).first('id', 'name', 'uuid')) as
    { id: number; name: string; uuid: string } | undefined;
  return row ? { tenantId, key, name: String(row.name), uuid: String(row.uuid) } : null;
}

/** A usable OTA link of the tenant (its hash), with its profile; null otherwise (unknown, another tenant's,
 *  revoked, expired, used up, profile archived or disabled). Read only. */
export async function findUsableLink(q: Knex | Knex.Transaction, tenantId: number, token: string): Promise<LinkFacts | null> {
  const row = await q('enrollment_tokens as t')
    .join('enrollment_profiles as p', function joinProfile() { this.on('p.id', '=', 't.profile_id').andOn('p.tenant_id', '=', 't.tenant_id'); })
    .where({ 't.tenant_id': tenantId, 't.token_hash': sha256Hex(token), 't.kind': 'link', 'p.method': 'ota' })
    .whereRaw('t.revoked_at IS NULL AND t.expires_at > now() AND t.uses < t.max_uses').whereRaw('p.archived_at IS NULL AND p.enabled')
    .first('t.id as token_id', 't.end_user_id', 'p.id as profile_id', 'p.method', 'p.ownership', 'p.locale') as Record<string, unknown> | undefined;
  if (!row) return null;
  return {
    tokenId: String(row.token_id), profileId: String(row.profile_id), method: row.method as EnrollmentProfileMethod,
    ownership: row.ownership as Ownership, locale: String(row.locale ?? 'fr'),
    endUserId: row.end_user_id === null || row.end_user_id === undefined ? null : Number(row.end_user_id),
  };
}

/** The notice of a link, in `locale`, from the provider (USR-01 or the default one). */
export function noticeOf(q: Knex | Knex.Transaction, t: TenantFacts, link: Pick<LinkFacts, 'method' | 'ownership'>, locale: SurfaceLocale): Promise<EnrollmentNotice | null> {
  return enrollmentNotice().noticeFor(q, t.tenantId, link.ownership, locale, { method: link.method, organization: t.name });
}

export type AckOutcome =
  | { kind: 'acknowledged'; sessionId: string; nonce: string }
  | { kind: 'invalid' }
  | { kind: 'notice_changed'; notice: EnrollmentNotice | null; link: LinkFacts };

/**
 * Step 2: in one transaction, the reservation of a use, the session (acknowledged), the acknowledgement of
 * the notice, a download nonce. `noticeVersionId` must be the version of the notice the page showed.
 */
export async function acknowledgeLink(t: TenantFacts, token: string, locale: SurfaceLocale, noticeVersionId: string,
  actor: DbActor): Promise<AckOutcome> {
  const out = await asTenant(t.tenantId, actor, () => db.transaction(async (trx): Promise<AckOutcome> => {
    const link = await findUsableLink(trx, t.tenantId, token);
    if (!link) return { kind: 'invalid' };
    const notice = await noticeOf(trx, t, link, locale);
    if (!notice || notice.versionId !== noticeVersionId) return { kind: 'notice_changed', notice, link };
    // The reservation: one use, never beyond max_uses (two concurrent acknowledgements of a single-use link: one wins).
    const reserved = await trx('enrollment_tokens')
      .where({ tenant_id: t.tenantId, id: link.tokenId })
      .whereRaw('revoked_at IS NULL AND expires_at > now() AND uses < max_uses')
      .update({ uses: trx.raw('uses + 1'), last_used_at: trx.fn.now() }, ['id']) as Array<{ id: string }>;
    if (reserved.length !== 1) return { kind: 'invalid' };
    const now = new Date();
    const sessionId = randomUUID();
    const nonce = newNonce();
    await trx('enrollment_sessions').insert({
      id: sessionId, tenant_id: t.tenantId, profile_id: link.profileId, token_id: link.tokenId, method: link.method,
      ownership: link.ownership, state: 'acknowledged', state_at: now, end_user_id: link.endUserId,
      nonce_hash: nonce.hash, nonce_expires_at: new Date(now.getTime() + NONCE_TTL_MS),
      notice_version_id: notice.versionId, acknowledged_at: now, locale, expires_at: new Date(now.getTime() + OTA_SESSION_TTL_MS),
    });
    const ackId = await enrollmentNotice().recordAcknowledgement(trx, t.tenantId,
      { sessionId, versionId: notice.versionId, locale, at: now, endUserId: link.endUserId });
    await trx('enrollment_sessions').where({ tenant_id: t.tenantId, id: sessionId }).update({ notice_ack_id: ackId });
    return { kind: 'acknowledged', sessionId, nonce: nonce.value };
  }));
  if (out.kind === 'acknowledged') realtime.sessionChanged(t.tenantId, out.sessionId);
  return out;
}

export interface SessionForDownload {
  id: string;
  profileId: string;
  tokenId: string | null;
  method: EnrollmentProfileMethod;
  ownership: Ownership;
  locale: SurfaceLocale;
  /** The end of the session: the SCEP challenge of its profile never outlives it (INT-C1-R7). */
  expiresAt: Date;
}

/** The shortest lifetime apple-edge accepts for a SCEP challenge (ttl_seconds, 60 to 3 600). */
export const CHALLENGE_MIN_TTL_S = 60;

/**
 * The lifetime of the SCEP challenge of a profile served for a session (decision of the owners of 19/10/2026,
 * INT-C1-R7 option A): `maxSeconds`, bounded by what is left of the session, so that a device never gets an identity
 * after its session expired (its Authenticate would be refused and its enrollment released). Less than a minute
 * left: null, the profile is not served (the session is about to expire).
 */
export function challengeTtlFor(maxSeconds: number, sessionExpiresAt: Date, now = Date.now()): number | null {
  const left = Math.floor((sessionExpiresAt.getTime() - now) / 1000);
  if (!Number.isFinite(left) || left < CHALLENGE_MIN_TTL_S) return null;
  return Math.min(maxSeconds, left);
}

export type ConsumeOutcome = { kind: 'ok'; session: SessionForDownload } | { kind: 'invalid' } | { kind: 'expired'; locale: SurfaceLocale };

/**
 * Why the link or the profile of a session no longer allows it (review of lot C1, INT-C1-R2): 'link_revoked' (its link
 * revoked), 'profile_withdrawn' (its profile archived or disabled); null: still allowed. The expiry and the uses of the
 * link do not count: the use is the session's own, reserved by its acknowledgement.
 */
export async function withdrawalOf(q: Knex | Knex.Transaction, tenantId: number, profileId: string, tokenId: string | null):
  Promise<'link_revoked' | 'profile_withdrawn' | null> {
  if (tokenId) {
    const tok = await q('enrollment_tokens').where({ tenant_id: tenantId, id: tokenId }).first('revoked_at') as { revoked_at: Date | null } | undefined;
    if (tok?.revoked_at) return 'link_revoked';
  }
  const p = await q('enrollment_profiles').where({ tenant_id: tenantId, id: profileId }).first('archived_at', 'enabled') as
    { archived_at: Date | null; enabled: boolean } | undefined;
  if (!p || p.archived_at || !p.enabled) return 'profile_withdrawn';
  return null;
}

/** Step 3, first part: the nonce of the session, consumed (erased) in a short transaction. */
export async function consumeNonce(t: TenantFacts, sessionId: string, nonce: string, actor: DbActor): Promise<ConsumeOutcome> {
  let ended = false;
  const out = await asTenant(t.tenantId, actor, () => db.transaction(async (trx): Promise<ConsumeOutcome> => {
    const row = await trx('enrollment_sessions')
      .where({ tenant_id: t.tenantId, id: sessionId, nonce_hash: sha256Hex(nonce), method: 'ota' })
      .forUpdate()
      .first('id', 'profile_id', 'token_id', 'method', 'ownership', 'locale', 'state', 'nonce_expires_at', 'expires_at') as Record<string, any> | undefined;
    if (!row) return { kind: 'invalid' };
    // The nonce is erased whatever follows: it serves once.
    await trx('enrollment_sessions').where({ tenant_id: t.tenantId, id: sessionId })
      .update({ nonce_hash: null, nonce_expires_at: null, updated_at: new Date() });
    const locale: SurfaceLocale = row.locale === 'en' ? 'en' : 'fr';
    const now = Date.now();
    if (row.state !== 'acknowledged') return { kind: 'invalid' };
    // The link revoked, the profile archived or disabled since the acknowledgement (the console ends the session
    // then; a concurrent withdrawal is caught here): the session ends, the page of an invalid link answers.
    const withdrawn = await withdrawalOf(trx, t.tenantId, String(row.profile_id), row.token_id ? String(row.token_id) : null);
    if (withdrawn) {
      ended = await endSession(trx, t.tenantId, sessionId, 'failed', withdrawn, ['acknowledged']);
      return { kind: 'invalid' };
    }
    if (!row.nonce_expires_at || new Date(row.nonce_expires_at).getTime() <= now || new Date(row.expires_at).getTime() <= now) {
      return { kind: 'expired', locale };
    }
    return {
      kind: 'ok',
      session: {
        id: String(row.id), profileId: String(row.profile_id), tokenId: row.token_id ? String(row.token_id) : null,
        method: row.method, ownership: row.ownership, locale, expiresAt: new Date(row.expires_at),
      },
    };
  }));
  if (ended) realtime.sessionChanged(t.tenantId, sessionId);
  return out;
}

/** A new download nonce for a session still acknowledged and not expired, its link not revoked and its profile active
 *  (the retry page); null otherwise. */
export async function renewNonce(t: TenantFacts, sessionId: string, actor: DbActor): Promise<string | null> {
  const nonce = newNonce();
  const n = await asTenant(t.tenantId, actor, () => db('enrollment_sessions as s')
    .where({ 's.tenant_id': t.tenantId, 's.id': sessionId, 's.state': 'acknowledged' })
    .where('s.expires_at', '>', new Date())
    .whereNotExists(function revoked() {
      this.select(db.raw('1')).from('enrollment_tokens as t')
        .whereRaw('t.tenant_id = s.tenant_id AND t.id = s.token_id AND t.revoked_at IS NOT NULL');
    })
    .whereExists(function active() {
      this.select(db.raw('1')).from('enrollment_profiles as p')
        .whereRaw('p.tenant_id = s.tenant_id AND p.id = s.profile_id AND p.archived_at IS NULL AND p.enabled');
    })
    .update({ nonce_hash: nonce.hash, nonce_expires_at: new Date(Date.now() + NONCE_TTL_MS), updated_at: new Date() }));
  return Number(n) === 1 ? nonce.value : null;
}

/**
 * The withdrawal of a link (revoked) or of a profile (archived, disabled) ends its sessions that have not reached a
 * device yet (review of lot C1, INT-C1-R2): failed, with the code of the withdrawal; their nonce erased. An Authenticate
 * that occurred before the withdrawal still finds such a session (findSessionForAuthenticate); a later one does not.
 * The sessions of a profile: those of a link or an invitation only (an ADE session has no token). The ids ended.
 */
export async function endWithdrawnSessions(trx: Knex.Transaction, tenantId: number,
  of: { tokenId: string } | { profileId: string }): Promise<string[]> {
  const q = trx('enrollment_sessions').where({ tenant_id: tenantId }).whereIn('state', OPEN_SESSION_STATES as unknown as string[]);
  if ('tokenId' in of) q.where({ token_id: of.tokenId });
  else q.where({ profile_id: of.profileId }).whereNotNull('token_id');
  const ids = await q.orderBy('created_at').forUpdate().pluck('id') as string[];
  const code = 'tokenId' in of ? 'link_revoked' : 'profile_withdrawn';
  const ended: string[] = [];
  for (const id of ids) if (await endSession(trx, tenantId, id, 'failed', code, OPEN_SESSION_STATES)) ended.push(id);
  return ended;
}

/** States of a session that has not reached a device (no Authenticate consumed yet). */
export const OPEN_SESSION_STATES = ['started', 'acknowledged', 'profile_issued', 'certificate_issued'] as const;

/**
 * A session ends without an enrollment (failed, expired): its state, and the use of its link given back, once
 * (the update of the state is the guard). `states`: the states it may leave.
 */
export async function endSession(trx: Knex.Transaction, tenantId: number, sessionId: string, state: 'failed' | 'expired',
  failureCode: string | null, states: readonly string[]): Promise<boolean> {
  const ended = await trx('enrollment_sessions').where({ tenant_id: tenantId, id: sessionId }).whereIn('state', states as string[])
    .update({ state, failure_code: failureCode, state_at: new Date(), nonce_hash: null, nonce_expires_at: null, updated_at: new Date() },
      ['token_id']) as Array<{ token_id: string | null }>;
  if (ended.length !== 1) return false;
  const tokenId = ended[0].token_id;
  if (tokenId) {
    await trx('enrollment_tokens').where({ tenant_id: tenantId, id: tokenId }).where('uses', '>', 0)
      .update({ uses: trx.raw('uses - 1') });
  }
  return true;
}

export type IssueOutcome =
  | { kind: 'profile'; body: Buffer; signed: boolean }
  | { kind: 'retry'; nonce: string | null }
  | { kind: 'not_ready'; nonce: string | null }
  | { kind: 'signing_unavailable' }
  | { kind: 'ended' };

/** Whether the platform alert signing.identity_missing is known raised (null: not known since the start). */
let signingAlert: boolean | null = null;

/** Tests: forget what is known of the platform alert. */
export function resetEnrollmentFlowForTests(): void {
  signingAlert = null;
}

async function signingAlertState(open: boolean, actor: DbActor): Promise<void> {
  if (signingAlert === open) return;
  try {
    if (open) await raiseAlert(actor, MASTER_TENANT_ID, 'signing.identity_missing');
    else await resolveAlert(actor, MASTER_TENANT_ID, 'signing.identity_missing');
    signingAlert = open;
  } catch (err) {
    logger.warn({ code: (err as { code?: unknown })?.code }, 'enrollment: the platform alert of the signing identity was not updated');
  }
}

/** What the composition and the signature of a profile gave. */
export type SignOutcome =
  | { kind: 'ok'; body: Buffer; signed: boolean; challengeId: string }
  | { kind: 'not_ready' }
  | { kind: 'signing_unavailable' }
  | { kind: 'retry'; code: string | null };

/** The session a profile is composed for. */
export interface SessionToSign {
  id: string;
  method: EnrollmentProfileMethod;
  ownership: Ownership;
  locale: SurfaceLocale;
}

/** How the profile of a session is composed: the lifetime of its SCEP challenge, the MachineInfo it is bound to
 *  (ADE), the Managed Apple Account of an account-driven enrollment (BYOD). */
export interface SignOptions {
  ttlSeconds: number;
  machineInfoId?: string;
  byod?: { managedAppleId: string };
}

/**
 * Outside any transaction: the enrollment configuration (a cached configuration without topic is read again: a
 * push certificate may have just been imported), the SCEP challenge bound to the session (and to its MachineInfo
 * for ADE), the composition and the signature (unsigned while no identity is imported, unless
 * APPLE_REQUIRE_SIGNED_PROFILES). The caller moves the session; nothing is written here but the alerts and, on
 * reading the notice, the publication of its current version (with its audit). The notice is read before the
 * challenge is created: an incomplete notice outside the laboratory (D7) leaves nothing at apple-edge.
 */
export async function composeSigned(t: TenantFacts, s: SessionToSign, actor: DbActor, o: SignOptions): Promise<SignOutcome> {
  const edgeActor = { actor: edgeActorOf(actor) };
  try {
    let cfg = await appleTenants.enrollmentConfig(t.tenantId, actor);
    if (!cfg.topic) cfg = await appleTenants.enrollmentConfig(t.tenantId, actor, { refresh: true });
    if (!cfg.topic) {
      await raiseAlert(actor, t.tenantId, 'apns.no_certificate').catch(() => undefined);
      return { kind: 'not_ready' };
    }
    // The notice before the challenge (D7: refused outside the laboratory, nothing created at apple-edge).
    const consent: Record<string, string> = {};
    for (const lang of ['en', 'fr'] as const) {
      const n = await asTenant(t.tenantId, actor, () => enrollmentNotice().noticeFor(db, t.tenantId, s.ownership, lang, { method: s.method, organization: t.name }));
      if (n?.consentSummary) consent[lang === 'en' ? 'default' : lang] = n.consentSummary;
    }
    const challenge = await appleEdge.createScepChallenge(t.key, {
      session_ref: s.id, ttl_seconds: o.ttlSeconds, ...(o.machineInfoId ? { machine_info_id: o.machineInfoId } : {}),
    }, edgeActor);
    const tx = textsFor(s.locale);
    const v = { org: t.name };
    const unsigned = composeEnrollmentProfile({
      key: t.key, config: cfg, challenge: challenge.challenge, sessionId: s.id, organization: t.name,
      displayName: fill(tx.profileName, v), description: fill(tx.profileDescription, v), scepName: tx.scepName, mdmName: tx.mdmName,
      consent, ...(o.byod ? { byod: o.byod } : {}),
    });
    let body = unsigned;
    let signed = false;
    try {
      body = await appleEdge.signProfile(t.key, unsigned, edgeActor);
      signed = true;
    } catch (err) {
      if (!isAppleEdgeError(err) || (err.code !== 'signing_identity_missing' && err.code !== 'signing_identity_unusable')) throw err;
      await signingAlertState(true, actor);
      if (config.apple.requireSignedProfiles) return { kind: 'signing_unavailable' };
    }
    if (signed) await signingAlertState(false, actor);
    return { kind: 'ok', body, signed, challengeId: challenge.challenge_id.toLowerCase() };
  } catch (err) {
    // The notice became incomplete outside the laboratory since its page (P0-13 T5, D7): no profile, retried later.
    if (isNoticeIncomplete(err)) return { kind: 'retry', code: 'noticeIncomplete' };
    if (err instanceof ProfileCompositionError || isAppleEdgeError(err)) {
      logger.warn({ tenantId: t.tenantId, code: (err as { code?: unknown }).code }, 'enrollment profile not issued');
      return { kind: 'retry', code: String((err as { code?: unknown }).code ?? '') || null };
    }
    logger.error({ tenantId: t.tenantId, err: { message: (err as Error)?.message } }, 'enrollment profile not issued');
    return { kind: 'retry', code: null };
  }
}

/**
 * Step 3, second part, outside any transaction (OTA): the profile composed and signed (composeSigned), then the
 * session moves to profile_issued. Not ready (no push certificate) or a failure of apple-edge: a new nonce for the
 * retry page; signing required and unavailable: the session fails (signing_unavailable) and gives its use back.
 */
export async function issueOtaProfile(t: TenantFacts, s: SessionForDownload, actor: DbActor): Promise<IssueOutcome> {
  // The challenge lives no longer than the session (INT-C1-R7); less than a minute left: not served, as if ended.
  const ttlSeconds = challengeTtlFor(OTA_CHALLENGE_TTL_S, s.expiresAt);
  if (ttlSeconds === null) return { kind: 'ended' };
  const out = await composeSigned(t, s, actor, { ttlSeconds });
  switch (out.kind) {
    case 'not_ready':
      return { kind: 'not_ready', nonce: await renewNonce(t, s.id, actor) };
    case 'signing_unavailable':
      await asTenant(t.tenantId, actor, () => db.transaction((trx) => endSession(trx, t.tenantId, s.id, 'failed', 'signing_unavailable', ['acknowledged'])));
      realtime.sessionChanged(t.tenantId, s.id);
      return { kind: 'signing_unavailable' };
    case 'retry':
      return { kind: 'retry', nonce: await renewNonce(t, s.id, actor).catch(() => null) };
    default:
      break;
  }
  // The profile is served only if the session is still acknowledged (review of lot C1, INT-C1-R4): ended meanwhile
  // (its link revoked, its profile withdrawn, expired), the profile is not served; its unused SCEP challenge expires.
  const moved = await asTenant(t.tenantId, actor, () => db('enrollment_sessions')
    .where({ tenant_id: t.tenantId, id: s.id, state: 'acknowledged' })
    .update({ state: 'profile_issued', state_at: new Date(), challenge_id: out.challengeId, updated_at: new Date() }));
  realtime.sessionChanged(t.tenantId, s.id);
  if (Number(moved) !== 1) return { kind: 'ended' };
  return { kind: 'profile', body: out.body, signed: out.signed };
}
