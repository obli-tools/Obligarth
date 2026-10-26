// BYOD Android invitations (lot AN-F1, sections 10.1, 10.5; AN17; criterion 6): the only way to the enrollment
// token of a personal device. An administrator invites an end user (single use, 7 days at most): the code is shown
// once (stored hashed, bound to the tenant), the link names the notice page of the device surface (no secret in it),
// both e-mailed when a channel is configured. On the device, the page shows the notice of a personal device; the code
// and the acknowledgement of the notice, in one form, move the invitation to issuing (the acknowledgement recorded:
// version, time, language), then the enrollment token (kind byod_link, PERSONAL_USAGE_ALLOWED, single use, its life
// bounded by the invitation's) is created at Google outside any transaction, and the device is sent to Google's
// enrollment page. The same code gives the same link again while the token is active (a page closed too early); once a
// device enrolled with the token, the invitation is used and the code serves no more. The enrollment handler accepts
// a device of a byod_link token only when the token belongs to an invitation issued after an acknowledged notice
// (invitationForEnrollment): no BYOD enrollment without the notice, whatever the path.
// Guessing: a code has 50 bits; wrong codes are counted per address and per hour first (beyond
// ANDROID_BYOD_WRONG_CODES_PER_ADDRESS_HOUR every code from this address is refused until the hour ends), then per
// tenant and per hour (beyond ANDROID_BYOD_WRONG_CODES_PER_HOUR, 200, every code of the tenant is refused until the hour
// ends, alert android.byod_code_flood): decision of the owners of 19/10/2026 on F1R-4. The surface also limits each
// address (10 answers a minute). The address is never stored: an HMAC of it.
// Every statement of the surface runs in the tenant's context, actor enrollment:android-byod. Never logged nor audited:
// the code, the token's value, the Google link.
import { createHmac } from 'node:crypto';
import type { Knex } from 'knex';
import {
  ANDROID_BYOD_INVITATION_TTL_HOURS, ANDROID_BYOD_WRONG_CODES_PER_ADDRESS_HOUR, ANDROID_BYOD_WRONG_CODES_PER_HOUR, type AndroidByodInvitationState, type AndroidByodInvitationView,
} from '@obligarth/shared';
import { audit } from '../../audit';
import { config } from '../../config';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { vault } from '../../vault';
import { logger } from '../../utils/logger';
import { raiseAndroidTenantAlert } from '../alerts';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { AndroidError } from '../gateway/errors';
import { parseOwnedName } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { tokenPayload } from '../enrollment/methods';
import { readAndroidProfile } from '../enrollment/profiles';
import { createEnrollmentToken, endToken, revokeEnrollmentToken, TokenError } from '../enrollment/tokens';
import { formatInvitationCode, invitationHash, invitationPrefix, newInvitationCode, normalizeInvitationCode } from './codes';
import { isByodLocale, type ByodLocale } from './i18n';
import { androidNotice, type AndroidNotice } from './notice';

export const BYOD_ACTOR: DbActor = Object.freeze({ type: 'enrollment', name: 'android-byod' }) as DbActor;
export const byodAuditCtx = (): AuditWriteContext => audit.system('enrollment', 'android-byod');
/** An issuing state older than this is an interrupted creation (instance stopped between Google and the record). */
export const ISSUING_STALE_MS = 2 * 60_000;

export class ByodError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message = code) {
    super(message);
    this.name = 'ByodError';
    this.status = status;
    this.code = code;
  }
}

export interface TenantFacts {
  tenantId: number;
  name: string;
  uuid: string;
}

interface InvitationRow {
  id: string;
  tenant_id: number;
  enterprise_id: number;
  profile_id: string;
  end_user_id: number;
  prefix: string;
  label: string | null;
  locale: string;
  state: AndroidByodInvitationState;
  expires_at: Date;
  notice_version_id: string | null;
  acknowledged_at: Date | null;
  ack_locale: string | null;
  issuing_at: Date | null;
  token_id: string | null;
  device_id: number | null;
  used_at: Date | null;
  revoked_at: Date | null;
  created_at: Date;
  /** Joined by the list only. */
  end_user_name?: string | null;
  end_user_email?: string | null;
}

const COLUMNS = ['id', 'tenant_id', 'enterprise_id', 'profile_id', 'end_user_id', 'prefix', 'label', 'locale', 'state', 'expires_at',
  'notice_version_id', 'acknowledged_at', 'ack_locale', 'issuing_at', 'token_id', 'device_id', 'used_at', 'revoked_at', 'created_at'];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const iso = (d: Date | null): string | null => (d ? new Date(d).toISOString() : null);

// ── Creation, list, revocation (console) ─────────────────────────────────────

export interface NewInvitation {
  id: string;
  /** Shown once (xxxxx-xxxxx); never stored nor logged. */
  code: string;
  prefix: string;
  expiresAt: Date;
  locale: ByodLocale;
}

export interface CreateInvitationRequest {
  profileId: string;
  endUserId: number;
  label?: string | null;
  ttlHours?: number;
  locale?: ByodLocale;
}

/**
 * POST /api/android/byod/invitations: an Android BYOD profile of the tenant (method android_byod_link, enabled), its
 * enrollment policy pushed (rule of the 5 minutes, section 10.7: the token would be refused later), a linked
 * enterprise, an active end user of the tenant; 7 days at most. Audited android.byod_invitation_created (the prefix,
 * never the code).
 */
export async function createInvitation(tenantId: number, userId: number, req: CreateInvitationRequest, auditCtx: AuditWriteContext): Promise<NewInvitation> {
  const ttl = req.ttlHours ?? ANDROID_BYOD_INVITATION_TTL_HOURS.dflt;
  if (!Number.isInteger(ttl) || ttl < ANDROID_BYOD_INVITATION_TTL_HOURS.min || ttl > ANDROID_BYOD_INVITATION_TTL_HOURS.max) {
    throw new ByodError(400, 'invalidInput', 'lifetime out of bounds');
  }
  return asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
    const e = await readEnterprise(trx);
    if (!e || e.state !== 'linked') throw new ByodError(409, 'androidNotLinked', 'no linked Android enterprise');
    const profile = await readAndroidProfile(trx, String(req.profileId ?? ''), tenantId);
    if (!profile || !profile.enabled) throw new ByodError(404, 'notFound', 'Android enrollment profile not found');
    if (profile.method !== 'android_byod_link' || profile.ownership !== 'personal') {
      throw new ByodError(409, 'androidByodProfileRequired', 'invitations serve the BYOD link profiles only');
    }
    const user = await trx('end_users').where({ tenant_id: tenantId, id: req.endUserId, status: 'active' }).first('id');
    if (!user) throw new ByodError(404, 'endUserNotFound', 'end user not found');
    const pol = await trx('android_enrollment_policies').where({ profile_id: profile.id }).first('state');
    if (!pol || pol.state !== 'pushed') throw new ByodError(409, 'androidEnrollmentPolicyMissing', 'the enrollment policy of the profile is not pushed yet');
    const t = await trx('tenants').where({ id: tenantId }).first('uuid') as { uuid: string };
    const locale: ByodLocale = isByodLocale(req.locale) ? req.locale : 'fr';
    // A code drawn twice (10 characters of 32: never in practice) is drawn again.
    for (let attempt = 0; attempt < 3; attempt++) {
      const code = newInvitationCode();
      const expiresAt = new Date(Date.now() + ttl * 3_600_000);
      try {
        const [row] = await trx('android_byod_invitations').insert({
          tenant_id: tenantId, enterprise_id: e.id, profile_id: profile.id, end_user_id: req.endUserId, code_hash: invitationHash(String(t.uuid), code),
          prefix: invitationPrefix(code), label: req.label ?? null, locale, expires_at: expiresAt, created_by: userId,
        }, ['id']) as Array<{ id: string }>;
        const id = String(row.id);
        await audit.appendInTx(trx, {
          tenantId, action: 'android.byod_invitation_created', target: { type: 'android_byod_invitation', id },
          details: { invitationId: id, profileId: profile.id, endUserId: req.endUserId, prefix: invitationPrefix(code), ttlHours: ttl },
        }, auditCtx);
        return { id, code: formatInvitationCode(code), prefix: invitationPrefix(code), expiresAt, locale };
      } catch (err) {
        if ((err as { code?: string }).code !== '23505' || attempt === 2) throw err;
      }
    }
    throw new ByodError(500, 'internalError', 'invitation not created');
  }));
}

/** The state shown for a row (an invitation past its end without enrollment is expired). */
function viewState(r: InvitationRow, now: number): AndroidByodInvitationState {
  if ((r.state === 'active' || r.state === 'issuing' || r.state === 'issued') && new Date(r.expires_at).getTime() <= now) return 'expired';
  return r.state;
}

const viewOf = (r: InvitationRow, now: number): AndroidByodInvitationView => ({
  id: String(r.id), profileId: String(r.profile_id), endUserId: r.end_user_id === null ? null : Number(r.end_user_id), prefix: r.prefix,
  label: r.label ?? null, state: viewState(r, now), expiresAt: new Date(r.expires_at).toISOString(), acknowledgedAt: iso(r.acknowledged_at),
  noticeVersionId: r.notice_version_id ?? null, endUserName: r.end_user_name ?? r.end_user_email ?? null, deviceId: r.device_id === null ? null : Number(r.device_id), createdAt: new Date(r.created_at).toISOString(),
  revokedAt: iso(r.revoked_at), usedAt: iso(r.used_at),
});

/** GET /api/android/byod/invitations: the tenant's invitations (RLS), newest first, never a code. */
export async function listInvitations(tenantId: number, userId: number, f: { state?: AndroidByodInvitationState } = {}): Promise<AndroidByodInvitationView[]> {
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    // The state filtered in SQL, before the limit (F1R-9), with the rule of viewState: an open invitation past its end
    // is shown expired.
    const OPEN: AndroidByodInvitationState[] = ['active', 'issuing', 'issued'];
    let q = db('android_byod_invitations as i')
      .leftJoin('end_users as u', function j() { this.on('u.id', '=', 'i.end_user_id').andOn('u.tenant_id', '=', 'i.tenant_id'); })
      .where({ 'i.tenant_id': tenantId });
    if (f.state === 'expired') {
      q = q.where((w) => { w.where('i.state', 'expired').orWhere((o) => { o.whereIn('i.state', OPEN).where('i.expires_at', '<=', db.fn.now()); }); });
    } else if (f.state && OPEN.includes(f.state)) {
      q = q.where('i.state', f.state).where('i.expires_at', '>', db.fn.now());
    } else if (f.state) {
      q = q.where('i.state', f.state);
    }
    const rows = await q.orderBy('i.created_at', 'desc').limit(500)
      .select([...COLUMNS.map((c) => `i.${c}`), 'u.display_name as end_user_name', 'u.email as end_user_email']) as InvitationRow[];
    const now = Date.now();
    return rows.map((r) => viewOf(r, now));
  });
}

/**
 * POST /api/android/byod/invitations/:id/revoke: the invitation revoked (the code serves no more), then its token
 * revoked at Google when one was issued and is still active. A device enrolling later with that token is not accepted
 * (invitationForEnrollment: the invitation is no longer issued), even if Google was out of reach for the revocation.
 */
export async function revokeInvitation(tenantId: number, userId: number, id: string, auditCtx: AuditWriteContext,
  o: { gateway?: AndroidGateway } = {}): Promise<'revoked' | 'not_open'> {
  if (!UUID_RE.test(id)) throw new ByodError(404, 'notFound', 'invitation not found');
  const r = await asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
    const row = await trx('android_byod_invitations').where({ tenant_id: tenantId, id }).forUpdate().first(COLUMNS) as InvitationRow | undefined;
    if (!row) throw new ByodError(404, 'notFound', 'invitation not found');
    if (row.state === 'used' || row.state === 'revoked' || row.state === 'expired') return { result: 'not_open' as const, tokenId: null };
    await trx('android_byod_invitations').where({ tenant_id: tenantId, id }).update({
      state: 'revoked', revoked_at: trx.fn.now(), revoked_by: userId, issuing_at: null, updated_at: trx.fn.now(),
    });
    await audit.appendInTx(trx, {
      tenantId, action: 'android.byod_invitation_revoked', target: { type: 'android_byod_invitation', id },
      details: { invitationId: id, prefix: row.prefix, tokenId: row.token_id },
    }, auditCtx);
    return { result: 'revoked' as const, tokenId: row.token_id };
  }));
  if (r.tokenId) {
    try {
      await revokeEnrollmentToken(tenantId, userId, r.tokenId, auditCtx, o);
    } catch (err) {
      // The invitation is revoked whatever Google answers: its token no longer enrolls a device of the instance.
      logger.warn({ android: { byod: 'token_revoke_failed', tenantId, kind: err instanceof AndroidError ? err.kind : 'error' } },
        'android: token of a revoked BYOD invitation not revoked at Google');
    }
  }
  return r.result;
}

// ── The device surface ──────────────────────────────────────────────────────

/** The notice of a personal device for the tenant (the profile is not known before the code). */
export function byodNotice(t: TenantFacts, locale: ByodLocale): Promise<AndroidNotice | null> {
  return asTenant(t.tenantId, BYOD_ACTOR, () => androidNotice().noticeFor(db, t.tenantId, 'personal', locale,
    { method: 'android_byod_link', organization: t.name }));
}

/** The facts of a tenant for the surface (in its context). */
export async function tenantFactsOf(tenantId: number): Promise<TenantFacts | null> {
  const row = await asTenant(tenantId, BYOD_ACTOR, () => db('tenants').where({ id: tenantId }).first('id', 'name', 'uuid')) as
    { id: number; name: string; uuid: string } | undefined;
  return row ? { tenantId: Number(row.id), name: String(row.name), uuid: String(row.uuid) } : null;
}

export type AcknowledgeOutcome =
  /** The Google enrollment page of the token (never logged). */
  | { kind: 'redirect'; url: string; invitationId: string }
  /** The code is not one of a live invitation of the tenant (counted). */
  | { kind: 'wrong_code' }
  /** Too many wrong codes this hour: every code of the tenant refused until the hour ends. */
  | { kind: 'flood' }
  /** Too many wrong codes from this address this hour: every code from it refused until the hour ends (F1R-4). */
  | { kind: 'address_flood' }
  /** The notice changed since the page. */
  | { kind: 'notice_changed'; notice: AndroidNotice | null }
  /** Another answer is creating the token right now. */
  | { kind: 'busy' }
  /** Google or the enterprise is not available: nothing consumed, try again. */
  | { kind: 'retry' }
  | { kind: 'unavailable' };

const hourStart = (now: Date): Date => new Date(Math.floor(now.getTime() / 3_600_000) * 3_600_000);

/** The HMAC of an address (never stored in clear), with the tenant's uuid: 32 hex characters. */
export function byodAddressHmac(tenantUuid: string, address: string): string {
  const key = createHmac('sha256', String(config.sessionSecret)).update('obligarth.android-byod-address.v1').digest();
  return createHmac('sha256', key).update(`${tenantUuid}
${address}`).digest('hex').slice(0, 32);
}

async function addressFloodReached(trx: Knex.Transaction, tenantId: number, address: string, now: Date): Promise<boolean> {
  const row = await trx('android_byod_address_attempts').where({ tenant_id: tenantId, hour_start: hourStart(now), address_hmac: address })
    .first('wrong_codes') as { wrong_codes: number } | undefined;
  return Number(row?.wrong_codes ?? 0) >= ANDROID_BYOD_WRONG_CODES_PER_ADDRESS_HOUR;
}

async function floodReached(trx: Knex.Transaction, tenantId: number, now: Date): Promise<boolean> {
  const row = await trx('android_byod_attempts').where({ tenant_id: tenantId, hour_start: hourStart(now) }).first('wrong_codes') as
    { wrong_codes: number } | undefined;
  return Number(row?.wrong_codes ?? 0) >= ANDROID_BYOD_WRONG_CODES_PER_HOUR;
}

/** Counts a wrong code of the address and of the tenant (its own short transaction: the answer's transaction may roll
 *  back). The address is checked before the code is read, but answers of one address racing each other all pass that
 *  check: the count of the address only grows while under its cap (the row lock of the upsert serialises them), and a
 *  wrong code beyond it no longer counts for the tenant, so that one address never brings more than
 *  ANDROID_BYOD_WRONG_CODES_PER_ADDRESS_HOUR to the count of the tenant (review of lot D-1910). */
async function countWrongCode(tenantId: number, address: string, now: Date): Promise<void> {
  const alert = await asTenant(tenantId, BYOD_ACTOR, () => db.transaction(async (trx) => {
    const hour = hourStart(now);
    const counted = await trx.raw(
      `INSERT INTO obligarth.android_byod_address_attempts AS a (tenant_id, hour_start, address_hmac, wrong_codes) VALUES (?, ?, ?, 1)
       ON CONFLICT (tenant_id, hour_start, address_hmac) DO UPDATE SET wrong_codes = a.wrong_codes + 1
       WHERE a.wrong_codes < ?
       RETURNING wrong_codes`, [tenantId, hour, address, ANDROID_BYOD_WRONG_CODES_PER_ADDRESS_HOUR])
      .then((r: { rows: unknown[] }) => r.rows.length > 0);
    await trx('android_byod_address_attempts').where({ tenant_id: tenantId }).where('hour_start', '<', new Date(hour.getTime() - 48 * 3_600_000)).delete();
    if (!counted) return false;
    const [row] = await trx.raw(
      `INSERT INTO obligarth.android_byod_attempts AS a (tenant_id, hour_start, wrong_codes) VALUES (?, ?, 1)
       ON CONFLICT (tenant_id, hour_start) DO UPDATE SET wrong_codes = LEAST(a.wrong_codes + 1, 1000000)
       RETURNING wrong_codes, alerted`, [tenantId, hour]).then((r: { rows: Array<{ wrong_codes: number; alerted: boolean }> }) => r.rows);
    // Two days are enough to read the counts of an incident; older rows go.
    await trx('android_byod_attempts').where({ tenant_id: tenantId }).where('hour_start', '<', new Date(hour.getTime() - 48 * 3_600_000)).delete();
    if (Number(row.wrong_codes) >= ANDROID_BYOD_WRONG_CODES_PER_HOUR && !row.alerted) {
      await trx('android_byod_attempts').where({ tenant_id: tenantId, hour_start: hour }).update({ alerted: true });
      return true;
    }
    return false;
  }));
  if (alert) void raiseAndroidTenantAlert(tenantId, 'android.byod_code_flood', { perHour: ANDROID_BYOD_WRONG_CODES_PER_HOUR });
}

type Step =
  | { kind: 'done'; out: AcknowledgeOutcome }
  | { kind: 'reuse'; inv: InvitationRow }
  | { kind: 'issue'; inv: InvitationRow; seconds: number };

/** The Google link of an issued invitation's token, read back from the vault while the token is active. */
async function linkOf(trx: Knex.Transaction, tenantId: number, tokenId: string): Promise<string | null> {
  const tok = await trx('android_enrollment_tokens').where({ tenant_id: tenantId, id: tokenId }).first('state', 'value_ref', 'expires_at', 'kind') as
    { state: string; value_ref: string | null; expires_at: Date; kind: string } | undefined;
  if (!tok || tok.kind !== 'byod_link' || tok.state !== 'active' || !tok.value_ref || new Date(tok.expires_at).getTime() <= Date.now()) return null;
  const value = await vault.readTenantSecret(tenantId, tok.value_ref, { trx });
  try {
    const p = tokenPayload('byod_link', value.toString('utf8'), undefined);
    return p.form === 'link' ? p.url : null;
  } finally {
    value.fill(0);
  }
}

/**
 * POST of the notice page (section 10.5): the code of a live invitation of the tenant and the acknowledgement of the
 * current notice. Returns where to send the device, or why not. The acknowledgement is recorded in the transaction
 * that moves the invitation to issuing; the token is created outside it (G-A1) and recorded in a third one.
 */
export async function acknowledgeInvitation(t: TenantFacts, a: { code: unknown; noticeVersionId: string; locale: ByodLocale; address: string },
  o: { gateway?: AndroidGateway; now?: () => Date } = {}): Promise<AcknowledgeOutcome> {
  const clock = o.now ?? (() => new Date());
  const code = normalizeInvitationCode(a.code);
  const address = byodAddressHmac(t.uuid, a.address);
  let wrong = false;
  const step = await asTenant(t.tenantId, BYOD_ACTOR, () => db.transaction(async (trx): Promise<Step> => {
    const now = clock();
    // The address first (F1R-4): a third party exhausts its own budget, then only the tenant's.
    if (await addressFloodReached(trx, t.tenantId, address, now)) return { kind: 'done', out: { kind: 'address_flood' } };
    if (await floodReached(trx, t.tenantId, now)) return { kind: 'done', out: { kind: 'flood' } };
    const notice = await androidNotice().noticeFor(trx, t.tenantId, 'personal', a.locale, { method: 'android_byod_link', organization: t.name });
    if (!notice || notice.versionId !== a.noticeVersionId) return { kind: 'done', out: { kind: 'notice_changed', notice } };
    if (!code) { wrong = true; return { kind: 'done', out: { kind: 'wrong_code' } }; }
    const inv = await trx('android_byod_invitations').where({ tenant_id: t.tenantId, code_hash: invitationHash(t.uuid, code) })
      .forUpdate().first(COLUMNS) as InvitationRow | undefined;
    const live = inv && (inv.state === 'active' || inv.state === 'issuing' || inv.state === 'issued') && new Date(inv.expires_at).getTime() > now.getTime();
    if (!inv || !live) {
      if (inv && (inv.state === 'active' || inv.state === 'issuing' || inv.state === 'issued')) {
        await trx('android_byod_invitations').where({ tenant_id: t.tenantId, id: inv.id }).update({ state: 'expired', issuing_at: null, updated_at: now });
      }
      wrong = true;
      return { kind: 'done', out: { kind: 'wrong_code' } };
    }
    // The profile must still serve (enabled, not archived, a BYOD link profile) and the enterprise be linked.
    const profile = await readAndroidProfile(trx, inv.profile_id, t.tenantId);
    const e = await readEnterprise(trx);
    if (!profile || !profile.enabled || profile.method !== 'android_byod_link' || !e || e.state !== 'linked' || e.id !== Number(inv.enterprise_id)) {
      return { kind: 'done', out: { kind: 'unavailable' } };
    }
    if (inv.state === 'issuing' && inv.issuing_at && now.getTime() - new Date(inv.issuing_at).getTime() < ISSUING_STALE_MS) {
      return { kind: 'done', out: { kind: 'busy' } };
    }
    const ackId = await androidNotice().recordAcknowledgement(trx, t.tenantId,
      { sessionId: inv.id, versionId: notice.versionId, locale: a.locale, at: now, channel: 'android_byod_invitation', endUserId: inv.end_user_id });
    const ack = { notice_version_id: notice.versionId, notice_ack_id: ackId, acknowledged_at: now, ack_locale: a.locale, updated_at: now };
    // Every passage acknowledges the notice and leaves its own audit entry (F1R-6); the invitation keeps the FIRST
    // acknowledgement that led to its token, never overwritten by a later passage (the proof of the consent).
    const passage = (again: boolean) => audit.appendInTx(trx, {
      tenantId: t.tenantId, action: 'android.byod_notice_acknowledged', target: { type: 'android_byod_invitation', id: inv.id },
      details: { invitationId: inv.id, noticeVersionId: notice.versionId, locale: a.locale, ackId, again },
    }, byodAuditCtx());
    if (inv.state === 'issued' && inv.token_id) {
      await trx('android_byod_invitations').where({ tenant_id: t.tenantId, id: inv.id }).update({ updated_at: now });
      await passage(true);
      return { kind: 'reuse', inv };
    }
    if (inv.state === 'issuing' && inv.issuing_at && inv.token_id) {
      // An interrupted creation (F1R-7): the token was bound to this invitation in the first transaction of its
      // creation (createEnrollmentToken), so it is adopted by its id, never the token of another invitation.
      const tok = await trx('android_enrollment_tokens').where({ tenant_id: t.tenantId, id: inv.token_id }).first('id', 'state') as
        { id: string; state: string } | undefined;
      if (tok?.state === 'creating') return { kind: 'done', out: { kind: 'busy' } };
      if (tok?.state === 'active') {
        await trx('android_byod_invitations').where({ tenant_id: t.tenantId, id: inv.id }).update({ state: 'issued', issuing_at: null, updated_at: now });
        await passage(true);
        return { kind: 'reuse', inv: { ...inv, state: 'issued', token_id: tok.id } };
      }
    }
    const seconds = Math.floor((new Date(inv.expires_at).getTime() - now.getTime()) / 1000);
    if (seconds < 60) {
      await trx('android_byod_invitations').where({ tenant_id: t.tenantId, id: inv.id }).update({ state: 'expired', issuing_at: null, updated_at: now });
      wrong = true;
      return { kind: 'done', out: { kind: 'wrong_code' } };
    }
    await trx('android_byod_invitations').where({ tenant_id: t.tenantId, id: inv.id }).update({ ...ack, state: 'issuing', issuing_at: now, token_id: null });
    await passage(false);
    return { kind: 'issue', inv, seconds };
  }));
  if (wrong) await countWrongCode(t.tenantId, address, clock());
  if (step.kind === 'done') return step.out;
  if (step.kind === 'reuse') {
    const url = await asTenant(t.tenantId, BYOD_ACTOR, () => db.transaction((trx) => linkOf(trx, t.tenantId, String(step.inv.token_id))));
    if (url) return { kind: 'redirect', url, invitationId: step.inv.id };
    // The token is no longer active (expired, revoked at Google, used meanwhile): nothing to hand out.
    return { kind: 'wrong_code' };
  }

  // The token, outside any transaction.
  const inv = step.inv;
  let created;
  try {
    created = await createEnrollmentToken(t.tenantId, null, { profileId: inv.profile_id, endUserId: Number(inv.end_user_id), expiresInSeconds: step.seconds },
      byodAuditCtx(), { gateway: o.gateway, actor: BYOD_ACTOR, byodInvitation: inv.id });
  } catch (err) {
    await asTenant(t.tenantId, BYOD_ACTOR, () => db('android_byod_invitations').where({ tenant_id: t.tenantId, id: inv.id, state: 'issuing' })
      .update({ state: 'active', issuing_at: null, token_id: null, updated_at: new Date() }));
    if (err instanceof AndroidError || err instanceof TokenError) {
      logger.warn({ android: { byod: 'token_not_created', tenantId: t.tenantId, kind: err instanceof AndroidError ? err.kind : err.code } },
        'android: BYOD token not created');
      return err instanceof TokenError && err.status !== 502 ? { kind: 'unavailable' } : { kind: 'retry' };
    }
    throw err;
  }
  const recorded = await asTenant(t.tenantId, BYOD_ACTOR, () => db('android_byod_invitations')
    .where({ tenant_id: t.tenantId, id: inv.id, state: 'issuing' }).update({ state: 'issued', issuing_at: null, token_id: created.id, updated_at: new Date() }));
  if (Number(recorded) !== 1) {
    // Revoked meanwhile: the token never serves (invitationForEnrollment refuses it); deleted at Google, its value destroyed.
    await asTenant(t.tenantId, BYOD_ACTOR, async () => {
      try {
        const e = await readEnterprise();
        const tok = await db('android_enrollment_tokens').where({ id: created.id }).first('token_name') as { token_name: string | null } | undefined;
        if (e && tok?.token_name) {
          const p = parseOwnedName(e, tok.token_name);
          if (p.kind === 'enrollmentToken') await (o.gateway ?? androidGateway()).deleteEnrollmentToken(e, p.tokenId);
        }
      } catch { /* Google out of reach: the token is ended below all the same */ }
      await db.transaction(async (trx) => {
        const fresh = await trx('android_enrollment_tokens').where({ id: created.id }).forUpdate().first('id', 'value_ref', 'state') as
          { id: string; value_ref: string | null; state: string } | undefined;
        if (fresh?.state === 'active') await endToken(trx, fresh, 'revoked', { revoked_at: trx.fn.now() });
      });
    });
    return { kind: 'wrong_code' };
  }
  if (created.payload.form !== 'link') return { kind: 'retry' };
  return { kind: 'redirect', url: created.payload.url, invitationId: inv.id };
}
