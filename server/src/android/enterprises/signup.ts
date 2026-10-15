// Signup of the Android enterprise of a tenant (section 6.2): the customer's administrator accepts the publisher's
// terms, the instance asks Google a signup URL restricted to the customer's domain, Google sends the browser back to
// the public route /api/android/signup/callback?s=<token>&enterpriseToken=<…>, which creates the enterprise and binds
// it to the tenant of the signup. Routing by the SHA-256 of the 256-bit token `s` only (AN33), consumed atomically
// (url_issued → consuming) before any call to Google; no Google call inside a transaction (G-A1); neither `s` nor
// the enterpriseToken is stored or logged; the administrator's e-mail is passed to Google and forgotten.
import type { Knex } from 'knex';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit } from '../../audit';
import type { AuditEntryInput, AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asNone, asTenant, type DbActor } from '../../db/context';
import { logger } from '../../utils/logger';
import { raiseAndroidPlatformAlert, raiseAndroidTenantAlert } from '../alerts';
import { androidConfig, type AndroidConfig } from '../config';
import type { AndroidError } from '../gateway/errors';
import { androidGateway } from '../gateway';
import { callbackTokenHash, newCallbackToken } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { pinProject, readEnterpriseRow } from './registry';

export const CALLBACK_ACTOR: DbActor = Object.freeze({ type: 'anonymous', name: 'android.signup-callback' }) as DbActor;
export const SIGNUP_TTL_MS = 3_600_000;
/** Current version of the publisher's terms accepted in the linking assistant (AN35). */
export const PUBLISHER_TERMS_VERSION = '2026-10';

const PERSONAL_DOMAINS = /^(gmail\.com|googlemail\.com|outlook\.[a-z.]+|hotmail\.[a-z.]+|live\.[a-z.]+|msn\.com|yahoo\.[a-z.]+|ymail\.com|icloud\.com|me\.com|mac\.com|aol\.com|gmx\.[a-z.]+|proton(mail)?\.[a-z.]+|laposte\.net|orange\.fr|free\.fr|sfr\.fr|wanadoo\.fr)$/;
const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{3,253})$/;

export class SignupError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'SignupError';
    this.status = status;
    this.code = code;
  }
}

export interface SignupRequest {
  domain: string;
  adminEmail?: string;
  displayName: string;
  primaryColor?: number;
  termsAccepted: boolean;
  termsVersion: string;
  /** Reason given by the operator's technician acting for the customer (optional). */
  onBehalfReason?: string;
}

export function isPersonalDomain(domain: string): boolean {
  return PERSONAL_DOMAINS.test(domain.toLowerCase());
}

/** The marker appended to the display name at creation (RR-3): ' ~' + 8 hex characters of the signup id. */
export function signupMarker(signupId: string): string {
  return ` ~${signupId.replace(/-/g, '').slice(0, 8)}`;
}

/** The display name given to Google at creation: the tenant's name (88 characters) and the marker. */
export function creationDisplayName(name: string, signupId: string): string {
  return `${name.slice(0, 88)}${signupMarker(signupId)}`;
}

/**
 * Starts a signup (POST /api/android/enterprise/signups): two transactions around the call to Google. Returns the
 * URL of Google (never `s` alone).
 */
export async function startSignup(tenantId: number, userId: number, req: SignupRequest, auditCtx: AuditWriteContext,
  o: { gateway?: AndroidGateway; cfg?: AndroidConfig } = {}): Promise<{ signupId: string; url: string }> {
  const cfg = o.cfg ?? androidConfig();
  const gw = o.gateway ?? androidGateway();
  if (cfg.mode === 'off') throw new SignupError(503, 'androidDisabled', 'the Android integration is off');
  if (!cfg.publicOrigin) throw new SignupError(503, 'androidGoogleUnavailable', 'ANDROID_PUBLIC_ORIGIN is not set');
  const domain = String(req.domain ?? '').trim().toLowerCase();
  if (!DOMAIN_RE.test(domain)) throw new SignupError(422, 'androidInvalidDomain', 'invalid domain');
  let adminEmail: string | undefined;
  if (req.adminEmail !== undefined && req.adminEmail !== '') {
    const m = EMAIL_RE.exec(String(req.adminEmail).trim());
    if (!m || m[1].toLowerCase() !== domain) throw new SignupError(422, 'androidAdminEmailOutsideDomain', 'adminEmail must belong to the domain');
    adminEmail = String(req.adminEmail).trim();
  }
  const displayName = String(req.displayName ?? '').trim();
  if (displayName.length < 1 || displayName.length > 100) throw new SignupError(422, 'invalidInput', 'displayName: 1 to 100 characters');
  if (req.primaryColor !== undefined && !(Number.isInteger(req.primaryColor) && req.primaryColor >= 0 && req.primaryColor <= 0xffffff)) {
    throw new SignupError(422, 'invalidInput', 'primaryColor must be an RGB integer');
  }
  if (req.termsAccepted !== true || req.termsVersion !== PUBLISHER_TERMS_VERSION) {
    throw new SignupError(409, 'androidTermsNotAccepted', 'the publisher terms must be accepted');
  }

  const { token, hash } = newCallbackToken();
  // Transaction 1: the pending enterprise row, the signup (hash of s), the audit entries.
  const t1 = await asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
    const live = await readEnterpriseRow(trx, { forUpdate: true });
    if (live && live.state !== 'pending') throw new SignupError(409, 'androidAlreadyLinked', 'an Android enterprise is already linked');
    const open = await trx('android_signups').whereIn('state', ['requested', 'url_issued', 'consuming']).first('id');
    if (open) throw new SignupError(409, 'androidSignupInProgress', 'a signup is already in progress');
    const claimed = await trx.raw('SELECT obligarth.android_domain_claimed(?) AS c', [domain]) as { rows: Array<{ c: boolean }> };
    if (claimed.rows[0]?.c) throw new SignupError(409, 'androidDomainClaimed', 'this domain is claimed by another customer');
    if (isPersonalDomain(domain) && !(live?.mgpa_exception) && tenantId !== MASTER_TENANT_ID) {
      throw new SignupError(422, 'androidPersonalDomainRefused', 'a personal e-mail domain cannot hold an Android enterprise');
    }
    const acceptance = { version: req.termsVersion, acceptedAt: new Date().toISOString(), userId };
    let enterpriseId: number;
    if (live) {
      enterpriseId = live.id;
      await trx('android_enterprises').where({ id: live.id }).update({
        admin_domain: domain, display_name: displayName, primary_color: req.primaryColor ?? null,
        terms_acceptance: JSON.stringify(acceptance), updated_at: trx.fn.now(),
      });
    } else {
      const [row] = await trx('android_enterprises').insert({
        tenant_id: tenantId, state: 'pending', admin_domain: domain, display_name: displayName,
        primary_color: req.primaryColor ?? null, terms_acceptance: JSON.stringify(acceptance), linked_by: userId,
      }).returning('id');
      enterpriseId = Number((row as { id: number }).id ?? row);
    }
    const [signup] = await trx('android_signups').insert({
      tenant_id: tenantId, enterprise_id: enterpriseId, callback_token_hash: hash, state: 'requested',
      allowed_domain: domain, requested_by: userId, expires_at: new Date(Date.now() + SIGNUP_TTL_MS),
    }).returning('id');
    const signupId = String((signup as { id: string }).id ?? signup);
    await audit.appendManyInTx(trx, [
      { tenantId, action: 'android.enterprise_terms_accepted', details: { version: req.termsVersion, userId },
        ...(req.onBehalfReason ? { reason: String(req.onBehalfReason).slice(0, 500) } : {}) },
      { tenantId, action: 'android.enterprise_signup_started', target: { type: 'android_signup', id: signupId }, details: { signupId, domain } },
    ], auditCtx);
    return { signupId, enterpriseId };
  })).catch((err) => {
    if ((err as { code?: string }).code === '23505') throw new SignupError(409, 'androidSignupInProgress', 'a signup is already in progress');
    throw err;
  });

  const callbackUrl = `${cfg.publicOrigin}/api/android/signup/callback?s=${token}`;
  let url: { name: string; url: string };
  try {
    url = await asTenant(tenantId, { type: 'user', userId }, () => gw.createSignupUrl({ callbackUrl, adminEmail, allowedDomains: [domain] }));
  } catch (err) {
    await asTenant(tenantId, { type: 'user', userId }, () => db('android_signups').where({ id: t1.signupId })
      .update({ state: 'failed', failure_code: 'google_error' }));
    throw err;
  }
  // Transaction 2: url_issued, one hour from now.
  await asTenant(tenantId, { type: 'user', userId }, () => db('android_signups').where({ id: t1.signupId, state: 'requested' })
    .update({ state: 'url_issued', signup_url_name: url.name, expires_at: new Date(Date.now() + SIGNUP_TTL_MS) }));
  return { signupId: t1.signupId, url: url.url };
}

export type CallbackResult = { result: 'ok' | 'error'; reason?: string; tenantId?: number };

let rejectedTimes: number[] = [];

async function rejected(reason: string, tenantId: number | null): Promise<CallbackResult> {
  const now = Date.now();
  rejectedTimes = rejectedTimes.filter((t) => now - t < 3_600_000);
  rejectedTimes.push(now);
  if (rejectedTimes.length > 5) void raiseAndroidPlatformAlert('android.signup_callback_rejected', { lastHour: rejectedTimes.length }, new Date().toISOString().slice(0, 13));
  if (tenantId !== null) {
    try {
      await audit.append({ tenantId, action: 'android.signup_callback_rejected', details: { reason } }, audit.system('anonymous', 'android.signup-callback'));
    } catch { /* standard class: spooled */ }
  }
  return { result: 'error', reason };
}

/**
 * The public signup callback. `query`: the raw query of the request (s, enterpriseToken). Never throws for a
 * malformed or replayed request: answers { result: 'error' } (the route redirects to a fixed page).
 */
export async function handleSignupCallback(query: Record<string, unknown>, o: { gateway?: AndroidGateway; cfg?: AndroidConfig } = {}): Promise<CallbackResult> {
  const cfg = o.cfg ?? androidConfig();
  const gw = o.gateway ?? androidGateway();
  if (cfg.mode === 'off') return { result: 'error', reason: 'disabled' };
  const hash = callbackTokenHash(typeof query.s === 'string' ? query.s : undefined);
  if (!hash) return rejected('unknown_token', null);
  const tenantId = await asNone(CALLBACK_ACTOR, async () => {
    const r = await db.raw('SELECT obligarth.android_signup_lookup(?) AS t', [hash]) as { rows: Array<{ t: number | null }> };
    return r.rows[0]?.t ?? null;
  });
  if (tenantId === null) return rejected('unknown_token', null);
  const ctxAudit = audit.system('anonymous', 'android.signup-callback');

  // Transaction 3: url_issued → consuming; only one concurrent request passes (SEC-AN-13).
  const signup = await asTenant(tenantId, CALLBACK_ACTOR, () => db('android_signups')
    .where({ callback_token_hash: hash, state: 'url_issued' }).where('expires_at', '>', db.fn.now())
    .update({ state: 'consuming', consuming_at: db.fn.now() })
    .returning(['id', 'enterprise_id', 'signup_url_name'])) as Array<{ id: string; enterprise_id: number; signup_url_name: string | null }>;
  if (!signup.length) return rejected('already_consumed', tenantId);
  const s = signup[0];
  const fail = async (code: string, alert: 'android.signup_failed' | null): Promise<CallbackResult> => {
    await asTenant(tenantId, CALLBACK_ACTOR, () => db('android_signups').where({ id: s.id, state: 'consuming' })
      .update({ state: 'failed', failure_code: code }));
    if (alert) void raiseAndroidTenantAlert(tenantId, alert, { code });
    return { result: 'error', reason: code, tenantId };
  };
  const enterpriseToken = typeof query.enterpriseToken === 'string' ? query.enterpriseToken : '';
  if (!enterpriseToken) {
    await audit.append({ tenantId, action: 'android.signup_callback_rejected', details: { reason: 'token_missing' } }, ctxAudit).catch(() => undefined);
    return fail('token_missing', 'android.signup_failed');
  }
  if (!s.signup_url_name) return fail('google_error', 'android.signup_failed');

  const row = await asTenant(tenantId, CALLBACK_ACTOR, () => db('android_enterprises').where({ id: s.enterprise_id })
    .first<{ display_name: string; primary_color: number | null; mgpa_exception: boolean }>('display_name', 'primary_color', 'mgpa_exception'));
  let enterprise;
  try {
    enterprise = await asTenant(tenantId, CALLBACK_ACTOR, () => gw.createEnterprise({
      signupUrlName: s.signup_url_name as string, enterpriseToken,
      enterpriseDisplayName: creationDisplayName(row?.display_name ?? 'Obligarth', s.id),
      ...(row?.primary_color !== null && row?.primary_color !== undefined ? { primaryColor: row.primary_color } : {}),
    }));
  } catch (err) {
    logger.warn({ android: { signup: 'create_failed', tenantId, kind: (err as AndroidError)?.kind ?? 'error' } }, 'android: enterprise creation failed');
    return fail('google_error', 'android.signup_failed');
  }

  // Transaction 4: type check, pin, bind, completed, setup job, audit.
  const type = enterprise.enterpriseType ?? 'ENTERPRISE_TYPE_UNSPECIFIED';
  if (type === 'MANAGED_GOOGLE_PLAY_ACCOUNTS_ENTERPRISE' && !row?.mgpa_exception && tenantId !== MASTER_TENANT_ID) {
    return fail('mgpa_refused', 'android.signup_failed');
  }
  try {
    await asTenant(tenantId, CALLBACK_ACTOR, () => db.transaction(async (trx) => {
      const pinned = await pinProject(trx, String(cfg.projectId));
      await trx.raw('SELECT obligarth.android_enterprise_bind(?, ?, ?, ?, ?, ?)', [
        tenantId, s.enterprise_id, enterprise.name, type, cfg.projectId, enterprise.managedGoogleDomainType ?? null]);
      await trx('android_signups').where({ id: s.id }).update({ state: 'completed', completed_at: trx.fn.now() });
      await setupSender(trx, tenantId);
      const entries: AuditEntryInput[] = [{
        tenantId, action: 'android.enterprise_linked', target: { type: 'android_enterprise', id: String(s.enterprise_id) },
        details: { enterpriseName: enterprise.name, type, projectId: cfg.projectId, signupId: s.id },
      }];
      if (pinned === 'pinned') entries.push({ tenantId, action: 'android.project_pinned', target: { type: 'android_enterprise', id: String(s.enterprise_id) }, details: { projectId: cfg.projectId } });
      await audit.appendManyInTx(trx, entries, ctxAudit);
    }));
  } catch (err) {
    logger.warn({ android: { signup: 'bind_failed', tenantId, code: (err as { code?: string }).code ?? 'error' } }, 'android: enterprise bind failed');
    return fail('bind_refused', 'android.signup_failed');
  }
  return { result: 'ok', tenantId };
}

/** Sends android.enterprise-setup of the tenant in the binding transaction (jobs.ts sets it). */
type SetupSender = (trx: Knex.Transaction, tenantId: number) => Promise<unknown>;
let setupSender: SetupSender = async () => undefined;
export function setSetupSender(fn: SetupSender): void { setupSender = fn; }
