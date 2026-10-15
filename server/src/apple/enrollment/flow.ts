import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import { MASTER_TENANT_ID, type EnrollmentProfileMethod, type Ownership } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { logger } from '../../utils/logger';
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
    const ackId = await enrollmentNotice().recordAcknowledgement(trx, t.tenantId, { sessionId, versionId: notice.versionId, locale, at: now });
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
}

export type ConsumeOutcome = { kind: 'ok'; session: SessionForDownload } | { kind: 'invalid' } | { kind: 'expired'; locale: SurfaceLocale };

/** Step 3, first part: the nonce of the session, consumed (erased) in a short transaction. */
export async function consumeNonce(t: TenantFacts, sessionId: string, nonce: string, actor: DbActor): Promise<ConsumeOutcome> {
  return asTenant(t.tenantId, actor, () => db.transaction(async (trx): Promise<ConsumeOutcome> => {
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
    if (!row.nonce_expires_at || new Date(row.nonce_expires_at).getTime() <= now || new Date(row.expires_at).getTime() <= now) {
      return { kind: 'expired', locale };
    }
    return {
      kind: 'ok',
      session: {
        id: String(row.id), profileId: String(row.profile_id), tokenId: row.token_id ? String(row.token_id) : null,
        method: row.method, ownership: row.ownership, locale,
      },
    };
  }));
}

/** A new download nonce for a session still acknowledged and not expired (the retry page); null otherwise. */
export async function renewNonce(t: TenantFacts, sessionId: string, actor: DbActor): Promise<string | null> {
  const nonce = newNonce();
  const n = await asTenant(t.tenantId, actor, () => db('enrollment_sessions')
    .where({ tenant_id: t.tenantId, id: sessionId, state: 'acknowledged' })
    .where('expires_at', '>', new Date())
    .update({ nonce_hash: nonce.hash, nonce_expires_at: new Date(Date.now() + NONCE_TTL_MS), updated_at: new Date() }));
  return Number(n) === 1 ? nonce.value : null;
}

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
  | { kind: 'signing_unavailable' };

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

/**
 * Step 3, second part, outside any transaction: the enrollment configuration (a cached configuration without
 * topic is read again: a push certificate may have just been imported), the SCEP challenge bound to the
 * session, the composition and the signature (unsigned while no identity is imported, unless
 * APPLE_REQUIRE_SIGNED_PROFILES), then the session moves to profile_issued.
 */
export async function issueOtaProfile(t: TenantFacts, s: SessionForDownload, actor: DbActor): Promise<IssueOutcome> {
  const edgeActor = { actor: edgeActorOf(actor) };
  let challengeId: string;
  let body: Buffer;
  let signed = false;
  try {
    let cfg = await appleTenants.enrollmentConfig(t.tenantId, actor);
    if (!cfg.topic) cfg = await appleTenants.enrollmentConfig(t.tenantId, actor, { refresh: true });
    if (!cfg.topic) {
      await raiseAlert(actor, t.tenantId, 'apns.no_certificate').catch(() => undefined);
      return { kind: 'not_ready', nonce: await renewNonce(t, s.id, actor) };
    }
    const challenge = await appleEdge.createScepChallenge(t.key, { session_ref: s.id, ttl_seconds: OTA_CHALLENGE_TTL_S }, edgeActor);
    challengeId = challenge.challenge_id;
    const tx = textsFor(s.locale);
    const v = { org: t.name };
    const consent: Record<string, string> = {};
    for (const lang of ['en', 'fr'] as const) {
      const n = await asTenant(t.tenantId, actor, () => enrollmentNotice().noticeFor(db, t.tenantId, s.ownership, lang, { method: s.method, organization: t.name }));
      if (n?.consentSummary) consent[lang === 'en' ? 'default' : lang] = n.consentSummary;
    }
    const unsigned = composeEnrollmentProfile({
      key: t.key, config: cfg, challenge: challenge.challenge, sessionId: s.id, organization: t.name,
      displayName: fill(tx.profileName, v), description: fill(tx.profileDescription, v), scepName: tx.scepName, mdmName: tx.mdmName,
      consent,
    });
    body = unsigned;
    try {
      body = await appleEdge.signProfile(t.key, unsigned, edgeActor);
      signed = true;
    } catch (err) {
      if (!isAppleEdgeError(err) || (err.code !== 'signing_identity_missing' && err.code !== 'signing_identity_unusable')) throw err;
      await signingAlertState(true, actor);
      if (config.apple.requireSignedProfiles) {
        await asTenant(t.tenantId, actor, () => db.transaction((trx) => endSession(trx, t.tenantId, s.id, 'failed', 'signing_unavailable', ['acknowledged'])));
        realtime.sessionChanged(t.tenantId, s.id);
        return { kind: 'signing_unavailable' };
      }
    }
    if (signed) await signingAlertState(false, actor);
  } catch (err) {
    if (err instanceof ProfileCompositionError || isAppleEdgeError(err)) {
      logger.warn({ tenantId: t.tenantId, code: (err as { code?: unknown }).code }, 'enrollment profile not issued');
    } else {
      logger.error({ tenantId: t.tenantId, err: { message: (err as Error)?.message } }, 'enrollment profile not issued');
    }
    return { kind: 'retry', nonce: await renewNonce(t, s.id, actor).catch(() => null) };
  }
  await asTenant(t.tenantId, actor, () => db('enrollment_sessions')
    .where({ tenant_id: t.tenantId, id: s.id, state: 'acknowledged' })
    .update({ state: 'profile_issued', state_at: new Date(), challenge_id: challengeId.toLowerCase(), updated_at: new Date() }));
  realtime.sessionChanged(t.tenantId, s.id);
  return { kind: 'profile', body, signed };
}
