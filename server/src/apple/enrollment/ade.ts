import { randomUUID } from 'node:crypto';
import type { EnrollmentProfileSettings, Ownership } from '@obligarth/shared';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { logger } from '../../utils/logger';
import { edgeActorOf } from '../actors';
import { raiseAlert } from '../alerts/service';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import type { EdgeMachineInfoCheck } from '../edge/wire';
import { realtime } from '../realtime';
import { compareVersions, platformOfProduct } from './adeRules';
import { composeSigned, endSession, withdrawalOf, type TenantFacts } from './flow';
import type { SurfaceLocale } from './i18n';
import { enrollmentNotice, type EnrollmentNotice } from './notice';
import { newNonce, sha256Hex } from './tokens';

// =============================================================================
// Automated Device Enrollment (docs: integration-apple-edge §10.4, ENR-01; apple-edge §7.5), the database and
// apple-edge side of the ADE routes of the device surface (surface.ts renders the answers). The ADE profile
// defined at Apple (adeProfiles.ts) sends the device of the setup assistant to:
//   - url = /t/<key>/ade/<profile>/enroll (POST, the MachineInfo signed by the device's identity in the body):
//     without a web view (kiosks, devices without a user) the session opens and the profile is served at once;
//     with one (webAuth, the default), the profile is served only to a device whose web session, same serial
//     number, was acknowledged within the last 30 minutes (taken over): the notice is never bypassed by url;
//   - configuration_web_url = …/web (GET with the header x-apple-aspen-deviceinfo): the notice of the profile's
//     ownership, a form token (hashed in nonce_hash); the POST of the form records the acknowledgement and
//     answers the profile itself [J1, J-3].
// Every MachineInfo is checked by apple-edge (signature chained to Apple, serial number of an ADE device of the
// tenant); refused: 403 without body. The minimum system version of the profile (minOsVersion, per platform
// from PRODUCT) answers the 403 JSON com.apple.softwareupdate.required [J1, J-4]. The SCEP challenge is bound to
// the MachineInfo (machine_info_id: apple-edge binds the verified UDID and serial number, and gives the ADE
// proof to the Authenticate that matches them); it lives 1 800 s (the setup assistant may be slow), the session
// one hour after the profile is issued. Every statement runs in the tenant's context, actor enrollment:ade-web.
// =============================================================================

/** Lifetime of the SCEP challenge of an ADE profile (§10.2), of a web session before its acknowledgement, of a
 *  session once its profile is issued (it covers the challenge and the Authenticate: review of lot C1). */
export const ADE_CHALLENGE_TTL_S = 1_800;
export const ADE_WEB_SESSION_TTL_MS = 30 * 60_000;
export const ADE_ISSUED_SESSION_TTL_MS = 60 * 60_000;
/** A web session acknowledged within this delay is taken over by the url of the profile (§10.4 step 3). */
export const ADE_WEB_TAKEOVER_MS = 30 * 60_000;
/** The largest MachineInfo (CMS DER) the surface forwards. */
export const MAX_MACHINE_INFO_BYTES = 64 * 1024;

export interface AdeProfileFacts {
  id: string;
  name: string;
  ownership: Ownership;
  locale: string;
  noticeRequired: boolean;
  settings: EnrollmentProfileSettings;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** An ADE profile of the tenant that serves enrollments (method ade, enabled, not archived); null otherwise. */
export async function findAdeProfile(tenantId: number, profileId: string, actor: DbActor): Promise<AdeProfileFacts | null> {
  if (!UUID_RE.test(profileId)) return null;
  const p = await asTenant(tenantId, actor, () => db('enrollment_profiles')
    .where({ tenant_id: tenantId, id: profileId.toLowerCase(), method: 'ade', enabled: true }).whereNull('archived_at')
    .first('id', 'name', 'ownership', 'locale', 'notice_required', 'settings')) as Record<string, any> | undefined;
  if (!p) return null;
  return {
    id: String(p.id), name: String(p.name), ownership: p.ownership as Ownership, locale: String(p.locale ?? 'fr'),
    noticeRequired: p.notice_required === true, settings: (p.settings ?? {}) as EnrollmentProfileSettings,
  };
}

/** Does the profile show its notice in the web view of the setup assistant (webAuth, on by default)? */
export const usesWebAuth = (p: AdeProfileFacts): boolean => p.settings.webAuth !== false;

export type MachineInfoOutcome =
  | { kind: 'ok'; check: EdgeMachineInfoCheck; serial: string }
  /** Refused by apple-edge (signature, chain, content) or a serial number that is not an ADE device of the tenant. */
  | { kind: 'refused' }
  /** The system of the device is older than the profile's minimum. */
  | { kind: 'os_update'; required: string }
  /** apple-edge did not answer. */
  | { kind: 'unavailable' };

/** The MachineInfo (base64 of the CMS) checked by apple-edge, then the profile's minimum system version. */
export async function checkMachineInfo(t: TenantFacts, profile: AdeProfileFacts, machineInfoB64: string, actor: DbActor): Promise<MachineInfoOutcome> {
  let check: EdgeMachineInfoCheck;
  try {
    check = await appleEdge.verifyMachineInfo(t.key, machineInfoB64, { actor: edgeActorOf(actor) });
  } catch (err) {
    if (isAppleEdgeError(err) && (err.status === 400 || err.status === 422)) return { kind: 'refused' };
    logger.warn({ tenantId: t.tenantId, code: (err as { code?: unknown })?.code ?? null }, 'ADE enrollment: MachineInfo not checked');
    return { kind: 'unavailable' };
  }
  if (!check.serial_in_tenant || !/^[A-Za-z0-9]{1,64}$/.test(check.serial) || !UUID_RE.test(check.machine_info_id)) return { kind: 'refused' };
  const platform = platformOfProduct(check.product);
  const required = platform ? profile.settings.minOsVersion?.[platform] : undefined;
  if (required && compareVersions(check.os_version, required) < 0) return { kind: 'os_update', required };
  return { kind: 'ok', check, serial: check.serial.toUpperCase() };
}

export type AdeIssueOutcome =
  | { kind: 'profile'; body: Buffer; signed: boolean; sessionId: string }
  /** No web session to take over (webAuth), or a profile that asks a notice without a web view. */
  | { kind: 'forbidden' }
  | { kind: 'not_ready' }
  | { kind: 'signing_unavailable' }
  | { kind: 'retry' }
  /** The MachineInfo check of the session expired (15 minutes at apple-edge): the setup starts again. */
  | { kind: 'restart' };

interface AdeSession { id: string; ownership: Ownership; locale: SurfaceLocale; machineInfoId: string }

const localeOf = (v: unknown): SurfaceLocale => (v === 'en' ? 'en' : 'fr');

/**
 * Composes, signs and serves the profile of an ADE session (any state before its device): the challenge bound to
 * its MachineInfo, then the session moves to profile_issued (one hour more to live). Signing required and
 * unavailable: the session fails.
 */
async function issueAde(t: TenantFacts, s: AdeSession, actor: DbActor): Promise<AdeIssueOutcome> {
  const out = await composeSigned(t, { id: s.id, method: 'ade', ownership: s.ownership, locale: s.locale }, actor,
    { ttlSeconds: ADE_CHALLENGE_TTL_S, machineInfoId: s.machineInfoId });
  switch (out.kind) {
    case 'not_ready':
      return { kind: 'not_ready' };
    case 'signing_unavailable':
      await asTenant(t.tenantId, actor, () => db.transaction((trx) => endSession(trx, t.tenantId, s.id, 'failed', 'signing_unavailable',
        ['started', 'acknowledged', 'profile_issued'])));
      realtime.sessionChanged(t.tenantId, s.id);
      return { kind: 'signing_unavailable' };
    case 'retry':
      return out.code === 'machine_info_not_found' ? { kind: 'restart' } : { kind: 'retry' };
    default:
      break;
  }
  const now = new Date();
  const moved = await asTenant(t.tenantId, actor, () => db('enrollment_sessions')
    .where({ tenant_id: t.tenantId, id: s.id }).whereIn('state', ['started', 'acknowledged', 'profile_issued'])
    .update({
      state: 'profile_issued', state_at: now, challenge_id: out.challengeId, updated_at: now,
      expires_at: db.raw('GREATEST(expires_at, ?::timestamptz)', [new Date(now.getTime() + ADE_ISSUED_SESSION_TTL_MS)]),
    }));
  realtime.sessionChanged(t.tenantId, s.id);
  if (Number(moved) !== 1) return { kind: 'forbidden' };
  return { kind: 'profile', body: out.body, signed: out.signed, sessionId: s.id };
}

/**
 * POST /t/:key/ade/:profileId/enroll (§10.4, without web view, or after it): the MachineInfo checked by the
 * caller. With webAuth, the web session of the same serial number acknowledged within 30 minutes is taken over
 * (bound to this newer MachineInfo); none: forbidden (the notice is not bypassed). Without webAuth, a profile that
 * asks a notice is misconfigured (refused at its saving: alert enrollment.profile_misconfigured, forbidden);
 * otherwise a session opens (started) and the profile is issued.
 */
export async function adeEnroll(t: TenantFacts, profile: AdeProfileFacts, mi: { check: EdgeMachineInfoCheck; serial: string },
  locale: SurfaceLocale, actor: DbActor): Promise<AdeIssueOutcome> {
  const now = new Date();
  let session: AdeSession | null = null;
  if (usesWebAuth(profile)) {
    session = await asTenant(t.tenantId, actor, () => db.transaction(async (trx): Promise<AdeSession | null> => {
      const row = await trx('enrollment_sessions')
        .where({ tenant_id: t.tenantId, profile_id: profile.id, method: 'ade', serial_number: mi.serial })
        .whereIn('state', ['acknowledged', 'profile_issued'])
        .where('acknowledged_at', '>', new Date(now.getTime() - ADE_WEB_TAKEOVER_MS))
        .orderBy('acknowledged_at', 'desc').forUpdate().first('id', 'ownership', 'locale') as Record<string, any> | undefined;
      if (!row) return null;
      await trx('enrollment_sessions').where({ tenant_id: t.tenantId, id: row.id })
        .update({ machine_info_id: mi.check.machine_info_id.toLowerCase(), updated_at: now });
      return { id: String(row.id), ownership: row.ownership, locale: localeOf(row.locale), machineInfoId: mi.check.machine_info_id.toLowerCase() };
    }));
    if (!session) return { kind: 'forbidden' };
  } else {
    if (profile.noticeRequired) {
      await raiseAlert(actor, t.tenantId, 'enrollment.profile_misconfigured', { discriminant: profile.id, params: { profileName: profile.name } })
        .catch(() => undefined);
      return { kind: 'forbidden' };
    }
    const id = randomUUID();
    await asTenant(t.tenantId, actor, () => db('enrollment_sessions').insert({
      id, tenant_id: t.tenantId, profile_id: profile.id, method: 'ade', ownership: profile.ownership, state: 'started', state_at: now,
      machine_info_id: mi.check.machine_info_id.toLowerCase(), serial_number: mi.serial, locale,
      expires_at: new Date(now.getTime() + ADE_WEB_SESSION_TTL_MS),
    }));
    realtime.sessionChanged(t.tenantId, id);
    session = { id, ownership: profile.ownership, locale, machineInfoId: mi.check.machine_info_id.toLowerCase() };
  }
  return issueAde(t, session, actor);
}

/** The notice of an ADE profile, in `locale`. */
export function adeNotice(t: TenantFacts, profile: AdeProfileFacts, locale: SurfaceLocale, actor: DbActor): Promise<EnrollmentNotice | null> {
  return asTenant(t.tenantId, actor, () => enrollmentNotice().noticeFor(db, t.tenantId, profile.ownership, locale,
    { method: 'ade', organization: t.name }));
}

/**
 * GET /t/:key/ade/:profileId/web (§10.4 step 1): the session opens (started, 30 minutes, bound to the checked
 * MachineInfo), with a form token stored hashed (nonce_hash). Returns the session and the token for the page.
 */
export async function adeOpenWebSession(t: TenantFacts, profile: AdeProfileFacts, mi: { check: EdgeMachineInfoCheck; serial: string },
  locale: SurfaceLocale, actor: DbActor): Promise<{ sessionId: string; formToken: string }> {
  const now = new Date();
  const id = randomUUID();
  const token = newNonce();
  await asTenant(t.tenantId, actor, () => db('enrollment_sessions').insert({
    id, tenant_id: t.tenantId, profile_id: profile.id, method: 'ade', ownership: profile.ownership, state: 'started', state_at: now,
    machine_info_id: mi.check.machine_info_id.toLowerCase(), serial_number: mi.serial, locale,
    nonce_hash: token.hash, nonce_expires_at: new Date(now.getTime() + ADE_WEB_SESSION_TTL_MS),
    expires_at: new Date(now.getTime() + ADE_WEB_SESSION_TTL_MS),
  }));
  realtime.sessionChanged(t.tenantId, id);
  return { sessionId: id, formToken: token.value };
}

export type AdeAckOutcome =
  | { kind: 'acknowledged'; session: AdeSession }
  | { kind: 'invalid' }
  | { kind: 'expired' }
  /** The notice changed since the page: shown again, with a new form token. */
  | { kind: 'notice_changed'; formToken: string; notice: EnrollmentNotice | null };

/**
 * POST /t/:key/ade/:profileId/web, first part (§10.4 step 3): the form token of the session (erased whatever
 * follows), the profile still serving, the version of the notice shown; the acknowledgement recorded, the session
 * acknowledged. In one transaction.
 */
export async function adeAcknowledgeWeb(t: TenantFacts, profile: AdeProfileFacts, sessionId: string, formToken: string,
  noticeVersionId: string, locale: SurfaceLocale, actor: DbActor): Promise<AdeAckOutcome> {
  const out = await asTenant(t.tenantId, actor, () => db.transaction(async (trx): Promise<AdeAckOutcome> => {
    const row = await trx('enrollment_sessions')
      .where({ tenant_id: t.tenantId, id: sessionId, profile_id: profile.id, method: 'ade', nonce_hash: sha256Hex(formToken) })
      .forUpdate().first('id', 'state', 'ownership', 'machine_info_id', 'nonce_expires_at', 'expires_at') as Record<string, any> | undefined;
    if (!row) return { kind: 'invalid' };
    await trx('enrollment_sessions').where({ tenant_id: t.tenantId, id: sessionId })
      .update({ nonce_hash: null, nonce_expires_at: null, updated_at: new Date() });
    if (row.state !== 'started' || !row.machine_info_id) return { kind: 'invalid' };
    if (await withdrawalOf(trx, t.tenantId, profile.id, null)) {
      await endSession(trx, t.tenantId, sessionId, 'failed', 'profile_withdrawn', ['started']);
      return { kind: 'invalid' };
    }
    const now = new Date();
    if (!row.nonce_expires_at || new Date(row.nonce_expires_at).getTime() <= now.getTime() || new Date(row.expires_at).getTime() <= now.getTime()) {
      return { kind: 'expired' };
    }
    const notice = await enrollmentNotice().noticeFor(trx, t.tenantId, profile.ownership, locale, { method: 'ade', organization: t.name });
    if (!notice || notice.versionId !== noticeVersionId) {
      const again = newNonce();
      await trx('enrollment_sessions').where({ tenant_id: t.tenantId, id: sessionId })
        .update({ nonce_hash: again.hash, nonce_expires_at: row.nonce_expires_at, updated_at: now });
      return { kind: 'notice_changed', formToken: again.value, notice };
    }
    await trx('enrollment_sessions').where({ tenant_id: t.tenantId, id: sessionId }).update({
      state: 'acknowledged', state_at: now, notice_version_id: notice.versionId, acknowledged_at: now, locale, updated_at: now,
    });
    const ackId = await enrollmentNotice().recordAcknowledgement(trx, t.tenantId, { sessionId, versionId: notice.versionId, locale, at: now });
    await trx('enrollment_sessions').where({ tenant_id: t.tenantId, id: sessionId }).update({ notice_ack_id: ackId });
    return { kind: 'acknowledged', session: { id: sessionId, ownership: row.ownership, locale, machineInfoId: String(row.machine_info_id) } };
  }));
  if (out.kind === 'acknowledged') realtime.sessionChanged(t.tenantId, sessionId);
  return out;
}

/** POST /t/:key/ade/:profileId/web, second part, outside any transaction: the profile of the acknowledged session. */
export function adeIssueAfterWeb(t: TenantFacts, s: AdeSession, actor: DbActor): Promise<AdeIssueOutcome> {
  return issueAde(t, s, actor);
}
