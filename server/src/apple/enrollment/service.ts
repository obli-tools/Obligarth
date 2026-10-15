import type { Knex } from 'knex';
import QRCode from 'qrcode';
import type {
  EnrollmentProfileSettings, EnrollmentProfileView, EnrollmentSessionState, EnrollmentSessionView, EnrollmentTokenKind,
  EnrollmentTokenState, EnrollmentTokenView,
} from '@obligarth/shared';
import { ENROLLMENT_LIMITS } from '@obligarth/shared';
import { config } from '../../config';
import { AppError } from '../../middleware/errorHandler';
import type { CheckedProfile } from './settings';
import { invitationTtlOf, linkDefaults } from './settings';
import {
  formatInvitationCode, invitationHash, invitationPrefix, newInvitationCode, newLinkToken,
} from './tokens';

// =============================================================================
// Console side of the enrollment (docs: integration-apple-edge §10.1, §10.9):
// profiles (never deleted: archived; every change bumps version), links (OTA)
// and invitations (account-driven), their revocation, the sessions. Runs in
// the request's tenant context; every function takes the caller's
// transaction or connection. A link's token and an invitation's code are
// returned once, by their creation: the database keeps their hash.
// =============================================================================

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);
const isoReq = (v: unknown): string => iso(v) ?? new Date(0).toISOString();
const num = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));

type Q = Knex | Knex.Transaction;

function profileView(r: Record<string, any>): EnrollmentProfileView {
  return {
    id: String(r.id), name: String(r.name), method: r.method, ownership: r.ownership, usage: r.usage ?? null,
    defaultGroupId: num(r.default_group_id), defaultGroupName: r.group_name ?? null, noticeRequired: r.notice_required === true,
    locale: String(r.locale), settings: (r.settings ?? {}) as EnrollmentProfileSettings, isDefault: r.is_default === true,
    enabled: r.enabled === true, version: Number(r.version), createdAt: isoReq(r.created_at), updatedAt: isoReq(r.updated_at),
    archivedAt: iso(r.archived_at), activeTokens: Number(r.active_tokens ?? 0),
  };
}

function profilesQuery(q: Q, tenantId: number) {
  return q('enrollment_profiles as p')
    .leftJoin('device_groups as g', function joinGroup() { this.on('g.id', '=', 'p.default_group_id').andOn('g.tenant_id', '=', 'p.tenant_id'); })
    .where('p.tenant_id', tenantId)
    .select('p.*', 'g.name as group_name', q.raw(`(SELECT count(*) FROM obligarth.enrollment_tokens t
      WHERE t.tenant_id = p.tenant_id AND t.profile_id = p.id AND t.revoked_at IS NULL AND t.expires_at > now() AND t.uses < t.max_uses)::int AS active_tokens`));
}

export async function listProfiles(q: Q, tenantId: number, archived: boolean): Promise<EnrollmentProfileView[]> {
  let qb = profilesQuery(q, tenantId);
  if (!archived) qb = qb.whereNull('p.archived_at');
  const rows = await qb.orderBy([{ column: 'p.archived_at', order: 'desc', nulls: 'first' }, { column: 'p.name' }]) as Array<Record<string, any>>;
  return rows.map(profileView);
}

export async function getProfile(q: Q, tenantId: number, id: string): Promise<EnrollmentProfileView> {
  const row = await profilesQuery(q, tenantId).where('p.id', id).first() as Record<string, any> | undefined;
  if (!row) throw new AppError(404, 'Enrollment profile not found', 'enrollmentProfileNotFound');
  return profileView(row);
}

async function checkGroup(trx: Knex.Transaction, tenantId: number, groupId: number | null): Promise<void> {
  if (groupId === null) return;
  const g = await trx('device_groups').where({ tenant_id: tenantId, id: groupId }).first('id');
  if (!g) throw new AppError(404, 'Group not found', 'groupNotFound');
}

/** The database's refusals of a profile, as console errors. */
function profileDbError(err: unknown): never {
  const e = err as { code?: string; constraint?: string };
  if (e?.code === '23505' && e.constraint === 'enrollment_profiles_ade_usage') {
    throw new AppError(409, 'Another ADE profile has this usage key', 'enrollmentUsageTaken');
  }
  if (e?.code === '23514') throw new AppError(400, 'This combination of method, ownership and settings is not allowed', 'enrollmentProfileRules');
  throw err;
}

export async function createProfile(trx: Knex.Transaction, tenantId: number, userId: number, p: CheckedProfile): Promise<string> {
  await checkGroup(trx, tenantId, p.defaultGroupId);
  if (p.isDefault) {
    await trx('enrollment_profiles').where({ tenant_id: tenantId, method: 'ade', is_default: true }).whereNull('archived_at')
      .update({ is_default: false, version: trx.raw('version + 1'), updated_at: new Date(), updated_by: userId });
  }
  try {
    const [row] = await trx('enrollment_profiles').insert({
      tenant_id: tenantId, name: p.name, method: p.method, ownership: p.ownership, usage: p.usage, default_group_id: p.defaultGroupId,
      notice_required: p.noticeRequired, locale: p.locale, settings: JSON.stringify(p.settings), is_default: p.isDefault,
      enabled: p.enabled, created_by: userId, updated_by: userId,
    }, ['id']) as Array<{ id: string }>;
    return String(row.id);
  } catch (err) {
    return profileDbError(err);
  }
}

/** A change of a profile (the method never changes); version + 1. Null: not found. */
export async function updateProfile(trx: Knex.Transaction, tenantId: number, userId: number, id: string, p: CheckedProfile): Promise<number> {
  const cur = await trx('enrollment_profiles').where({ tenant_id: tenantId, id }).forUpdate().first('id', 'method', 'archived_at', 'is_default') as
    { id: string; method: string; archived_at: Date | null; is_default: boolean } | undefined;
  if (!cur) throw new AppError(404, 'Enrollment profile not found', 'enrollmentProfileNotFound');
  if (cur.archived_at) throw new AppError(409, 'This enrollment profile is archived', 'enrollmentProfileArchived');
  if (cur.method !== p.method) throw new AppError(400, 'The method of an enrollment profile cannot change', 'enrollmentMethodFixed');
  if (cur.is_default && !p.isDefault) {
    throw new AppError(409, 'Designate another default ADE profile first', 'enrollmentDefaultRequired');
  }
  await checkGroup(trx, tenantId, p.defaultGroupId);
  if (p.isDefault && !cur.is_default) {
    await trx('enrollment_profiles').where({ tenant_id: tenantId, method: 'ade', is_default: true }).whereNull('archived_at').whereNot({ id })
      .update({ is_default: false, version: trx.raw('version + 1'), updated_at: new Date(), updated_by: userId });
  }
  try {
    const [row] = await trx('enrollment_profiles').where({ tenant_id: tenantId, id }).update({
      name: p.name, ownership: p.ownership, usage: p.usage, default_group_id: p.defaultGroupId, notice_required: p.noticeRequired,
      locale: p.locale, settings: JSON.stringify(p.settings), is_default: p.isDefault, enabled: p.enabled,
      version: trx.raw('version + 1'), updated_by: userId, updated_at: new Date(),
    }, ['version']) as Array<{ version: number }>;
    return Number(row.version);
  } catch (err) {
    return profileDbError(err);
  }
}

/** Archives a profile (never deleted); refused for the default ADE profile while another is not designated. */
export async function archiveProfile(trx: Knex.Transaction, tenantId: number, userId: number, id: string): Promise<number> {
  const cur = await trx('enrollment_profiles').where({ tenant_id: tenantId, id }).forUpdate().first('archived_at', 'is_default', 'version') as
    { archived_at: Date | null; is_default: boolean; version: number } | undefined;
  if (!cur) throw new AppError(404, 'Enrollment profile not found', 'enrollmentProfileNotFound');
  if (cur.archived_at) return Number(cur.version);
  if (cur.is_default) throw new AppError(409, 'Designate another default ADE profile first', 'enrollmentDefaultRequired');
  const [row] = await trx('enrollment_profiles').where({ tenant_id: tenantId, id })
    .update({ archived_at: new Date(), version: trx.raw('version + 1'), updated_by: userId, updated_at: new Date() }, ['version']) as Array<{ version: number }>;
  return Number(row.version);
}

interface ActiveProfile { id: string; method: string; ownership: string; locale: string; settings: EnrollmentProfileSettings }

async function activeProfile(trx: Knex.Transaction, tenantId: number, id: string): Promise<ActiveProfile> {
  const p = await trx('enrollment_profiles').where({ tenant_id: tenantId, id }).forShare()
    .first('id', 'method', 'ownership', 'locale', 'settings', 'archived_at', 'enabled') as (ActiveProfile & { archived_at: Date | null; enabled: boolean }) | undefined;
  if (!p) throw new AppError(404, 'Enrollment profile not found', 'enrollmentProfileNotFound');
  if (p.archived_at) throw new AppError(409, 'This enrollment profile is archived', 'enrollmentProfileArchived');
  if (!p.enabled) throw new AppError(409, 'This enrollment profile is disabled', 'enrollmentProfileDisabled');
  return { ...p, settings: (p.settings ?? {}) as EnrollmentProfileSettings };
}

/** The public base of the device surface and the tenant's key, for the URLs of links and invitations. */
export function surfaceBase(): string {
  if (config.apple.mode !== 'on' || !config.apple.mdmPublicBase) {
    throw new AppError(503, 'The Apple integration is turned off', 'appleIntegrationDisabled');
  }
  return config.apple.mdmPublicBase;
}

export interface NewLink {
  id: string;
  token: string;
  prefix: string;
  maxUses: number;
  ttlHours: number;
  expiresAt: Date;
  locale: string;
}

export async function createLink(trx: Knex.Transaction, tenantId: number, userId: number, profileId: string,
  o: { label?: string | null; maxUses?: number; ttlHours?: number }): Promise<NewLink> {
  const p = await activeProfile(trx, tenantId, profileId);
  if (p.method !== 'ota') throw new AppError(409, 'Links serve OTA enrollment profiles only', 'enrollmentLinkNotOta');
  const d = linkDefaults(p.settings);
  const maxUses = o.maxUses ?? d.maxUses;
  const ttlHours = o.ttlHours ?? d.ttlHours;
  const L = ENROLLMENT_LIMITS;
  if (maxUses < L.linkMaxUses.min || maxUses > L.linkMaxUses.max || ttlHours < L.linkTtlHours.min || ttlHours > L.linkTtlHours.max) {
    throw new AppError(400, 'Uses or lifetime out of bounds', 'invalidRequest');
  }
  const tok = newLinkToken();
  const expiresAt = new Date(Date.now() + ttlHours * 3_600_000);
  const [row] = await trx('enrollment_tokens').insert({
    tenant_id: tenantId, profile_id: profileId, kind: 'link', token_hash: tok.hash, prefix: tok.prefix, label: o.label ?? null,
    expires_at: expiresAt, max_uses: maxUses, created_by: userId,
  }, ['id']) as Array<{ id: string }>;
  return { id: String(row.id), token: tok.value, prefix: tok.prefix, maxUses, ttlHours, expiresAt, locale: p.locale };
}

export interface NewInvitation {
  id: string;
  code: string;
  prefix: string;
  ttlHours: number;
  expiresAt: Date;
  locale: string;
}

export async function createInvitation(trx: Knex.Transaction, tenantId: number, userId: number, profileId: string,
  o: { managedAppleAccount: string; label?: string | null; ttlHours?: number; endUserId?: number | null }): Promise<NewInvitation> {
  const p = await activeProfile(trx, tenantId, profileId);
  if (p.method !== 'byod_account') throw new AppError(409, 'Invitations serve account-driven enrollment profiles only', 'enrollmentInvitationNotByod');
  const ttlHours = o.ttlHours ?? invitationTtlOf(p.settings);
  const L = ENROLLMENT_LIMITS.invitationTtlHours;
  if (ttlHours < L.min || ttlHours > L.max) throw new AppError(400, 'Lifetime out of bounds', 'invalidRequest');
  let endUserId = o.endUserId ?? null;
  if (endUserId !== null) {
    const u = await trx('end_users').where({ tenant_id: tenantId, id: endUserId }).first('id');
    if (!u) throw new AppError(404, 'End user not found', 'endUserNotFound');
  } else {
    // The end user of the Managed Apple Account, when the tenant knows one (PLT-28).
    const u = await trx('end_users').where({ tenant_id: tenantId }).whereRaw('lower(managed_apple_account) = lower(?)', [o.managedAppleAccount])
      .first('id') as { id: number } | undefined;
    endUserId = u ? Number(u.id) : null;
  }
  const t = await trx('tenants').where({ id: tenantId }).first('uuid') as { uuid: string };
  // A code drawn twice in the tenant (10 characters of 32: never in practice) is drawn again.
  for (let attempt = 0; attempt < 3; attempt++) {
    const code = newInvitationCode();
    const expiresAt = new Date(Date.now() + ttlHours * 3_600_000);
    try {
      const [row] = await trx('enrollment_tokens').insert({
        tenant_id: tenantId, profile_id: profileId, kind: 'invitation', token_hash: invitationHash(String(t.uuid), code),
        prefix: invitationPrefix(code), managed_apple_account: o.managedAppleAccount, end_user_id: endUserId, label: o.label ?? null,
        expires_at: expiresAt, max_uses: 1, created_by: userId,
      }, ['id']) as Array<{ id: string }>;
      return { id: String(row.id), code: formatInvitationCode(code), prefix: invitationPrefix(code), ttlHours, expiresAt, locale: p.locale };
    } catch (err) {
      if ((err as { code?: string }).code !== '23505' || attempt === 2) throw err;
    }
  }
  throw new AppError(500, 'Invitation not created');
}

/** The QR code of a link (PNG, data URL). */
export const linkQrPng = (url: string): Promise<string> => QRCode.toDataURL(url, { errorCorrectionLevel: 'M', margin: 1, width: 320 });

function tokenState(r: Record<string, any>, now: number): EnrollmentTokenState {
  if (r.revoked_at) return 'revoked';
  if (Number(r.uses) >= Number(r.max_uses)) return 'exhausted';
  if (new Date(r.expires_at).getTime() <= now) return 'expired';
  return 'active';
}

export async function listTokens(q: Q, tenantId: number, f: { profileId?: string; kind?: EnrollmentTokenKind; state?: EnrollmentTokenState },
  showAccounts: boolean): Promise<EnrollmentTokenView[]> {
  let qb = q('enrollment_tokens as t')
    .join('enrollment_profiles as p', function joinProfile() { this.on('p.id', '=', 't.profile_id').andOn('p.tenant_id', '=', 't.tenant_id'); })
    .where('t.tenant_id', tenantId);
  if (f.profileId) qb = qb.where('t.profile_id', f.profileId);
  if (f.kind) qb = qb.where('t.kind', f.kind);
  if (f.state === 'revoked') qb = qb.whereNotNull('t.revoked_at');
  else if (f.state === 'exhausted') qb = qb.whereNull('t.revoked_at').whereRaw('t.uses >= t.max_uses');
  else if (f.state === 'expired') qb = qb.whereNull('t.revoked_at').whereRaw('t.uses < t.max_uses AND t.expires_at <= now()');
  else if (f.state === 'active') qb = qb.whereNull('t.revoked_at').whereRaw('t.uses < t.max_uses AND t.expires_at > now()');
  const rows = await qb.orderBy('t.created_at', 'desc').limit(500)
    .select('t.id', 't.profile_id', 'p.name as profile_name', 't.kind', 't.prefix', 't.label', 't.managed_apple_account', 't.uses',
      't.max_uses', 't.expires_at', 't.revoked_at', 't.created_at', 't.last_used_at') as Array<Record<string, any>>;
  const now = Date.now();
  return rows.map((r) => ({
    id: String(r.id), profileId: String(r.profile_id), profileName: String(r.profile_name), kind: r.kind, prefix: String(r.prefix),
    label: r.label ?? null, managedAppleAccount: showAccounts ? (r.managed_apple_account ?? null) : null, uses: Number(r.uses),
    maxUses: Number(r.max_uses), expiresAt: isoReq(r.expires_at), state: tokenState(r, now), createdAt: isoReq(r.created_at),
    lastUsedAt: iso(r.last_used_at), revokedAt: iso(r.revoked_at),
  }));
}

/** Revokes a link or an invitation (idempotent). The facts of the audit entry; null: not found. */
export async function revokeToken(trx: Knex.Transaction, tenantId: number, userId: number, id: string):
  Promise<{ kind: string; prefix: string; profileId: string; already: boolean } | null> {
  const cur = await trx('enrollment_tokens').where({ tenant_id: tenantId, id }).forUpdate().first('kind', 'prefix', 'profile_id', 'revoked_at') as
    { kind: string; prefix: string; profile_id: string; revoked_at: Date | null } | undefined;
  if (!cur) return null;
  if (!cur.revoked_at) {
    await trx('enrollment_tokens').where({ tenant_id: tenantId, id }).update({ revoked_at: new Date(), revoked_by: userId });
  }
  return { kind: cur.kind, prefix: cur.prefix, profileId: String(cur.profile_id), already: Boolean(cur.revoked_at) };
}

const SESSION_PAGE = 100;

/** The recent sessions, newest first; `cursor`: the id of the last row of the previous page. */
export async function listSessions(q: Q, tenantId: number, f: { state?: EnrollmentSessionState; cursor?: string },
  showAccounts: boolean): Promise<{ items: EnrollmentSessionView[]; nextCursor: string | null }> {
  let qb = q('enrollment_sessions as s')
    .join('enrollment_profiles as p', function joinProfile() { this.on('p.id', '=', 's.profile_id').andOn('p.tenant_id', '=', 's.tenant_id'); })
    .leftJoin('enrollment_tokens as t', function joinToken() { this.on('t.id', '=', 's.token_id').andOn('t.tenant_id', '=', 's.tenant_id'); })
    .where('s.tenant_id', tenantId);
  if (f.state) qb = qb.where('s.state', f.state);
  if (f.cursor) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(f.cursor)) throw new AppError(400, 'Invalid cursor', 'invalidRequest');
    qb = qb.whereRaw('(s.created_at, s.id) < (SELECT c.created_at, c.id FROM obligarth.enrollment_sessions c WHERE c.tenant_id = ? AND c.id = ?::uuid)',
      [tenantId, f.cursor]);
  }
  const rows = await qb.orderBy([{ column: 's.created_at', order: 'desc' }, { column: 's.id', order: 'desc' }]).limit(SESSION_PAGE + 1)
    .select('s.id', 's.profile_id', 'p.name as profile_name', 't.prefix as token_prefix', 's.method', 's.ownership', 's.state', 's.state_at',
      's.failure_code', 's.managed_apple_account', 's.device_id', 's.locale', 's.acknowledged_at', 's.created_at', 's.expires_at') as Array<Record<string, any>>;
  const page = rows.slice(0, SESSION_PAGE);
  const last = page[page.length - 1];
  return {
    items: page.map((r) => ({
      id: String(r.id), profileId: String(r.profile_id), profileName: String(r.profile_name), tokenPrefix: r.token_prefix ?? null,
      method: r.method, ownership: r.ownership, state: r.state, stateAt: isoReq(r.state_at), failureCode: r.failure_code ?? null,
      managedAppleAccount: showAccounts ? (r.managed_apple_account ?? null) : null, deviceId: num(r.device_id), locale: r.locale ?? null,
      acknowledgedAt: iso(r.acknowledged_at), createdAt: isoReq(r.created_at), expiresAt: isoReq(r.expires_at),
    })),
    nextCursor: rows.length > SESSION_PAGE && last ? String(last.id) : null,
  };
}
