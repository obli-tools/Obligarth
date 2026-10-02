import { regenerateSession } from '../utils/session';
import { Router } from 'express';
import type { Request } from 'express';
import crypto from 'crypto';
import { z } from 'zod';
import { db } from '../db';
import { registerJob, safeErr, type JobHandle, type JobResult } from '../jobs';
import { asIdentity, asPlatform, switchToTenant, type DbActor } from '../db/context';
import { globalViewGrant } from '../db/platformAccess';
import { asIntegrationPlatform } from '../middleware/dbContext';
import { obligateService, moduleDashboardStats, type ObligateDashboardStat, type ObligateRoster } from '../services/obligate.service';
import { tenantService, refuseSignInWithoutTenant, forgetTenantMemberships } from '../services/tenant.service';
import { appConfigService } from '../services/appConfig.service';
import { permissionSetService } from '../services/permissionSet.service';
import { auditService } from '../services/audit.service';
import { forgetSessionUser } from '../middleware/sessionUserGuard';
import { clientAddress } from '../utils/clientIp';
import { logger } from '../utils/logger';
import { MASTER_TENANT_ID, isMasterTenant } from '@obligarth/shared';
import { permissionService } from '../services/permission.service';

const router = Router();

// Database contexts (rls-tenant §7.7, §8.2): Obligate's sign-in and its user
// sync write accounts, links and memberships in the identity context of the
// integration (actor i:obligate); the team memberships of each tenant in that
// tenant's context; its transverse reads (app-info, dashboard-stats) in the
// context 'platform' with the integration's grant, once its Bearer secret is
// verified.
const OBLIGATE_ACTOR: DbActor = { type: 'integration', name: 'obligate' };

/**
 * Public origin used to build the OAuth redirect_uri. Host / X-Forwarded-*
 * are client-controlled (and client/nginx.conf relays X-Forwarded-Proto as
 * received), so the origin they name is only accepted when it is one this app
 * is really published under (obligateService.verifyPublicOrigin) — otherwise
 * a forged Host would make us exchange, with our own key, a code that Obligate
 * issued for an attacker's redirect_uri, and sign the attacker in as the
 * victim.
 */
async function resolvePublicOrigin(req: Request): Promise<string | null> {
  const protocol = String(req.headers['x-forwarded-proto'] || req.protocol).split(',')[0].trim();
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  if (!host) return null;
  const origin = await obligateService.verifyPublicOrigin(`${protocol}://${host}`);
  if (!origin) {
    logger.warn({ protocol, host },
      'Obligate SSO: request origin is not a public URL of this app (APP_URL, CLIENT_ORIGIN or its base URL in Obligate)');
  }
  return origin;
}

/**
 * Tenant + team memberships of an SSO identity as Obligate grants them (the
 * verified assertion at sign-in, Obligate's roster on a confirmed sync).
 * Upserts the granted tenant rows and reconciles the team memberships of
 * each granted tenant. With `prune` — og_ accounts, whose access Obligate
 * owns (their tenant access cannot be edited here) — also removes what
 * Obligate no longer grants: tenant rows (including the master-tenant
 * 'admin' row of a platform admin who is one no longer) and the team
 * memberships of those tenants.
 * Returns true when a tenant row was removed: an open session may sit on that
 * tenant (requireTenant refuses it from then on), the caller ends them.
 */
async function applySsoMemberships(
  localUserId: number,
  grant: { tenants: unknown; teams: unknown },
  platformRole: 'admin' | 'user',
  prune: boolean,
): Promise<boolean> {
  const tenants = Array.isArray(grant.tenants) ? grant.tenants as Array<{ slug?: unknown; role?: unknown }> : [];
  const teams = Array.isArray(grant.teams) ? (grant.teams as unknown[]).filter((n): n is string => typeof n === 'string') : [];
  const keep = new Set<number>();

  for (const t of tenants) {
    if (!t || typeof t.slug !== 'string') continue;
    const found = await db.raw('SELECT obligarth.tenant_lookup_by_slug(?) AS id', [t.slug]) as { rows: Array<{ id: number | null }> };
    const tenant = found.rows[0]?.id ? { id: Number(found.rows[0].id) } : undefined;
    if (!tenant) continue;
    keep.add(tenant.id);
    // Store the raw role slug Obligate sent. `permission_sets.slug`
    // is keyed on this string, so 'admin' / 'user' / 'viewer' / any
    // custom slug the operator created in the PermissionSets UI all
    // pass through unchanged. The pre-091 coercion to admin/member
    // was the old enum constraint — that's gone now.
    const roleSlug = typeof t.role === 'string' && t.role.length > 0 ? t.role : 'user';
    await db('user_tenants')
      .insert({ user_id: localUserId, tenant_id: tenant.id, role: roleSlug })
      .onConflict(['user_id', 'tenant_id'])
      .merge({ role: roleSlug });

    // Reconcile team_memberships for THIS tenant against the granted teams:
    // a flat list of team NAMES across the user's tenants (Obligate's
    // role-binding model), matched by name within this tenant_id so the same
    // name in another tenant doesn't cross-contaminate.
    // Teams are rows of the tenant: reconciled in its context.
    await switchToTenant(tenant.id, async () => {
      const wantedTeamIds = teams.length
        ? await db('user_teams').where({ tenant_id: tenant.id }).whereIn('name', teams).pluck('id') as number[]
        : [];
      const currentTeamIds = await db('team_memberships')
        .join('user_teams', 'user_teams.id', 'team_memberships.team_id')
        .where({ 'team_memberships.user_id': localUserId, 'user_teams.tenant_id': tenant.id })
        .pluck('team_memberships.team_id') as number[];
      const toAdd = wantedTeamIds.filter((id) => !currentTeamIds.includes(id));
      const toRemove = currentTeamIds.filter((id) => !wantedTeamIds.includes(id));
      if (toAdd.length > 0) {
        await db('team_memberships')
          .insert(toAdd.map((team_id) => ({ tenant_id: tenant.id, team_id, user_id: localUserId })))
          .onConflict(['team_id', 'user_id'])
          .ignore();
      }
      if (toRemove.length > 0) {
        await db('team_memberships').where({ user_id: localUserId, tenant_id: tenant.id }).whereIn('team_id', toRemove).del();
      }
    });

    // Capabilities from Obligate are intentionally ignored: they live on
    // team_permissions (Obligarth) and are configured per-team via
    // /admin/users. Obligate owns the user-tenant binding (which tenants the
    // user belongs to + which role + which teams), not what a team may do.
  }

  // Global (All-tenants) admin → ensure a master-tenant membership so the
  // user lands on the god-view tenant (id=1) and shows in its user list,
  // exactly like the local bootstrap admin. god view itself is granted by
  // users.role='admin'; this row just makes tenant resolution deterministic.
  if (platformRole === 'admin') {
    keep.add(MASTER_TENANT_ID);
    await db('user_tenants')
      .insert({ user_id: localUserId, tenant_id: MASTER_TENANT_ID, role: 'admin' })
      .onConflict(['user_id', 'tenant_id'])
      .merge({ role: 'admin' });
  }

  if (!prune) return false;
  const keepIds = [...keep];
  const staleTenants = await db('user_tenants')
    .where({ user_id: localUserId })
    .modify((q) => { if (keepIds.length) q.whereNotIn('tenant_id', keepIds); })
    .pluck('tenant_id') as number[];
  // The teams of each tenant no longer granted, in that tenant's context.
  for (const staleTenantId of staleTenants) {
    await switchToTenant(Number(staleTenantId), () => db('team_memberships')
      .where({ user_id: localUserId, tenant_id: Number(staleTenantId) }).del());
  }
  if (staleTenants.length > 0) {
    await db('user_tenants').where({ user_id: localUserId }).whereIn('tenant_id', staleTenants).del();
    logger.info({ localUserId, tenantIds: staleTenants }, 'Obligate SSO: tenant access no longer granted by Obligate — removed');
    return true;
  }
  return false;
}

// ── Lot O: Obligate re-authentication (device-bound 2FA, SSO accounts) ─────
// docs/mobile/device-bound-2fa.md §4.10, §6.10. GET /auth/sso-redirect?reauth=1
// (&return=/path) sends a SIGNED-IN og_ account to Obligate with
// prompt=login&max_age=0 (Obligate then forces password + TOTP even with a
// live Obligate session); /auth/callback accepts the answer only for the same
// Obligate identity, authenticated after the request (authTime) with an OTP
// (amr), and then marks THIS session (ssoReauthAt) without changing its user
// nor its id. The browser goes back to `<return>?reauth=ok`, or
// `<return>?reauth=failed&reason=<code>` — never to /login (the user stays
// signed in).

/** A pending re-authentication older than this is refused. */
const REAUTH_MAX_AGE_MS = 10 * 60 * 1000;
/** Clock tolerance between Obligate and this server for authTime. */
const REAUTH_CLOCK_SKEW_S = 30;

/** Same-origin path to come back to after a re-authentication (default '/'). */
function reauthReturnPath(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length > 200) return '/';
  // A plain absolute path: no scheme, host, '//', backslash, query or fragment.
  if (!/^\/(?![/\\])[A-Za-z0-9\-._~/]*$/.test(raw)) return '/';
  // Never back into the sign-in / SSO machinery.
  if (/^\/(auth|api|login)(\/|$)/.test(raw)) return '/';
  return raw;
}

function reauthResultUrl(returnTo: string, outcome: 'ok' | 'failed', reason?: string): string {
  const q = new URLSearchParams({ reauth: outcome });
  if (reason) q.set('reason', reason);
  return `${returnTo}?${q.toString()}`;
}

async function reauthAudit(req: Request, action: string, details: Record<string, unknown>): Promise<void> {
  try {
    const uid = req.session?.userId;
    await auditService.log({
      tenantId: req.session?.currentTenantId ?? MASTER_TENANT_ID,
      userId: uid,
      action,
      resourceType: 'user',
      resourcePath: uid ? String(uid) : undefined,
      ipAddress: clientAddress(req).ip || undefined,
      details,
    });
  } catch { /* audit never breaks the flow */ }
}

/**
 * /auth/callback with a pending re-authentication: checks the assertion
 * (same Obligate identity as the signed-in og_ account, authTime after the
 * request, amr with 'otp'), reads the MFA epoch uncached (fail closed), then
 * sets ssoReauthAt / ssoReauthEpoch / ssoReauthCv on THIS session. Never
 * provisions, never changes the session's user or id.
 */
async function completeReauth(
  req: Request, res: import('express').Response,
  assertion: import('../services/obligate.service').ObligateUserAssertion,
  pending: { startedAt: number; foreignId: number; returnTo?: string },
): Promise<void> {
  const returnTo = reauthReturnPath(pending.returnTo);
  const finish = (url: string) => {
    req.session.save((err) => {
      if (err) logger.error(err, 'reauth: session save failed');
      res.redirect(url);
    });
  };
  const fail = async (reason: string) => {
    delete req.session.pendingReauth;
    await reauthAudit(req, 'sso.reauth_failed', { reason, obligateUserId: pending.foreignId });
    logger.warn({ reason, userId: req.session.userId, obligateUserId: pending.foreignId }, 'Obligate re-authentication refused');
    finish(reauthResultUrl(returnTo, 'failed', reason));
  };

  const userId = Number(req.session.userId);
  if (!Number.isSafeInteger(userId) || userId <= 0) { await fail('signed_out'); return; }
  if (!(Date.now() - Number(pending.startedAt) <= REAUTH_MAX_AGE_MS)) { await fail('expired'); return; }
  if (assertion.obligateUserId !== pending.foreignId) { await fail('identity'); return; }
  const user = await db('users').where({ id: userId })
    .first('foreign_source', 'foreign_id', 'is_active', 'credential_version') as
    { foreign_source: string | null; foreign_id: number | null; is_active: boolean; credential_version: number } | undefined;
  if (!user || !user.is_active || user.foreign_source !== 'obligate' || Number(user.foreign_id) !== pending.foreignId
    || (await obligateService.getLinkedLocalUserId(pending.foreignId)) !== userId) {
    await fail('identity');
    return;
  }
  const authTime = assertion.authTime;
  const startedS = Math.floor(Number(pending.startedAt) / 1000);
  const nowS = Math.floor(Date.now() / 1000);
  if (typeof authTime !== 'number' || !Number.isFinite(authTime)
    || authTime < startedS - REAUTH_CLOCK_SKEW_S || authTime > nowS + REAUTH_CLOCK_SKEW_S) {
    await fail('stale_auth');
    return;
  }
  if (!Array.isArray(assertion.amr) || !assertion.amr.includes('otp')) { await fail('no_otp'); return; }
  if (!(await obligateService.lotOSupported())) { await fail('unsupported'); return; }
  const epoch = await obligateService.getMfaEpoch(pending.foreignId, { fresh: true });
  if (!epoch || !epoch.active) { await fail('verifier_unavailable'); return; }

  delete req.session.pendingReauth;
  req.session.ssoReauthAt = Date.now();
  req.session.ssoReauthEpoch = epoch.mfaEpoch;
  req.session.ssoReauthCv = Number(user.credential_version);
  // A full Obligate authentication (password + OTP) lifts the step-up code
  // lock, like a full sign-in (§6.8).
  const { clearCodeThrottle } = await import('../services/deviceKey/stepUpProof');
  await clearCodeThrottle(userId);
  await reauthAudit(req, 'sso.reauth', { obligateUserId: pending.foreignId, amr: assertion.amr.filter((m) => typeof m === 'string').slice(0, 8) });
  finish(reauthResultUrl(returnTo, 'ok'));
}

/**
 * Shared: provision or sync a user from an Obligate assertion.
 * Creates session fields on req.session.
 * Returns the local user ID.
 */
async function provisionObligateUser(assertion: import('../services/obligate.service').ObligateUserAssertion, req: any): Promise<number> {
  // Obligate is the source of truth for an SSO user's PLATFORM role.
  //
  // `assertion.role === 'admin'` means the user was granted "All tenants"
  // admin on the Obligarth app in Obligate's Permission Groups (an app-wide
  // mapping). That maps to a global / god-view admin here. Anything else is
  // a plain platform user — their PER-TENANT roles (incl. tenant-admin) are
  // synced into user_tenants further down from assertion.tenants[].
  //
  // This is the correct SSO authZ model: the self-hosted IdP owns identity
  // AND authorization, and the server↔server exchange is already secured
  // (held API key, one-time 60s code, redirect_uri match, single-use claim).
  // SSO accounts are intentionally non-editable locally (see users.controller
  // "manage from Obligate"), so without trusting this there is NO path to an
  // admin once SSO is enabled. The local bootstrap admin (ensureDefaultAdmin)
  // remains as break-glass for when Obligate is unreachable.
  const platformRole = assertion.role === 'admin' ? 'admin' : 'user';
  const obligateUserId = assertion.obligateUserId;
  if (!Number.isSafeInteger(obligateUserId) || obligateUserId <= 0
    || typeof assertion.username !== 'string' || assertion.username.length === 0) {
    throw new Error('SSO sign-in refused: malformed assertion (obligateUserId / username)');
  }

  // Which local account? From OUR records only (sso_foreign_users, written by
  // this server alone, or the og_ account provisioned for this identity).
  //
  // assertion.linkedLocalUserId is Obligate's copy of the id WE reported via
  // report-provision. Anyone holding the app's API key can rewrite it
  // (report-provision is authenticated by that key alone, and the key is
  // public while the client_id is 'raw'), so it is cross-checked, never
  // trusted: a stale or rewritten value (e.g. pointing at a local admin) can
  // never open a session on another account. Linking a LOCAL (non-og_)
  // account to an Obligate identity has no flow in which Obligarth verifies
  // the local credentials: such a link counts only when it is in
  // sso_foreign_users.
  let localUserId = (await obligateService.getLinkedLocalUserId(obligateUserId)) ?? 0;
  const claimedLocalUserId = assertion.linkedLocalUserId ?? null;
  if (claimedLocalUserId && claimedLocalUserId !== localUserId) {
    logger.warn(
      { obligateUserId, claimedLocalUserId, linkedLocalUserId: localUserId || null },
      'Obligate SSO: linkedLocalUserId does not match our link records — ignored',
    );
    void auditService.log({
      tenantId: MASTER_TENANT_ID,
      action: 'sso.link_mismatch_ignored',
      resourceType: 'user',
      resourcePath: localUserId ? String(localUserId) : undefined,
      ipAddress: clientAddress(req).ip || undefined,
      details: { obligateUserId, claimedLocalUserId, linkedLocalUserId: localUserId || null, username: assertion.username },
    });
  }

  // og_ account (Obligate owns its access): memberships pruned to the grant
  let ssoOwned = false;
  // Platform admin → user: the other sessions end (like a local demotion)
  let demoted = false;
  if (localUserId) {
    const existing = await db('users').where({ id: localUserId })
      .first('foreign_source', 'is_active', 'role') as { foreign_source: string | null; is_active: boolean; role: string } | undefined;
    ssoOwned = existing?.foreign_source === 'obligate';
    demoted = existing?.role === 'admin' && platformRole !== 'admin';
    // A LINKED local account (not og_) that is disabled never gets a session
    // through SSO (P6: a disabled account has no session at all), and nothing
    // of it is touched. The login page is told why (?error=account_disabled):
    // an Obligarth platform admin re-enables the account (Admin > Users).
    if (existing && existing.is_active === false && existing.foreign_source !== 'obligate') {
      throw Object.assign(new Error(`SSO sign-in refused: linked local user #${localUserId} is disabled`), { ssoErrorCode: 'account_disabled' });
    }
    const update: Record<string, unknown> = {
      email: assertion.email,
      display_name: assertion.displayName,
      // Obligate owns the platform role — sync it every login (promotion AND
      // demotion). See the rationale at the top of this function.
      role: platformRole,
      updated_at: new Date(),
    };
    // An og_ account's activity is Obligate's: Obligate only issues an
    // assertion for an active user allowed on this app, so a valid assertion
    // re-enables an og_ account left disabled (lost 'reactivate' push, or a
    // 'deactivate' pushed by someone holding the API key). A linked LOCAL
    // account is never re-enabled here (refused above).
    const reactivated = existing?.foreign_source === 'obligate' && existing.is_active === false;
    if (reactivated) update.is_active = true;
    await db('users').where({ id: localUserId }).update(update);
    // The session guard caches role / is_active for a few seconds: without
    // this, a role just changed by the assertion (either way) would be
    // overridden by the cached one on the next requests.
    forgetSessionUser(localUserId);
    if (reactivated) {
      logger.info({ obligateUserId, localUserId }, 'Obligate SSO: og_ account re-enabled by a valid sign-in');
      void auditService.log({
        tenantId: MASTER_TENANT_ID, action: 'sso.account_reactivated', resourceType: 'user',
        resourcePath: String(localUserId), ipAddress: clientAddress(req).ip || undefined,
        details: { obligateUserId },
      });
    }
    // Keep the link row (idempotent; repairs an og_ account found through
    // users.foreign_id) and Obligate's pointer (missing, stale or rewritten).
    await db('sso_foreign_users')
      .insert({ foreign_source: 'obligate', foreign_user_id: obligateUserId, local_user_id: localUserId })
      .onConflict(['foreign_source', 'foreign_user_id'])
      .merge({ local_user_id: localUserId });
    if (claimedLocalUserId !== localUserId) {
      obligateService.reportProvision(obligateUserId, localUserId).catch(() => {});
    }
  } else {
    const [newUser] = await db('users')
      .insert({
        username: `og_${assertion.username}`,
        display_name: assertion.displayName || assertion.username,
        email: assertion.email,
        // Platform role comes from Obligate (All-tenants admin → admin).
        // See the rationale at the top of this function.
        role: platformRole,
        is_active: true,
        foreign_source: 'obligate',
        foreign_id: obligateUserId,
        enrollment_version: 999,
      })
      .returning('id') as Array<{ id: number }>;
    localUserId = newUser.id;
    ssoOwned = true;

    await db('sso_foreign_users')
      .insert({ foreign_source: 'obligate', foreign_user_id: obligateUserId, local_user_id: localUserId })
      .onConflict(['foreign_source', 'foreign_user_id'])
      .merge({ local_user_id: localUserId });

    // Tell Obligate which local id to use (overwrites a stale or rewritten one).
    obligateService.reportProvision(obligateUserId, localUserId).catch(() => {});
  }

  // Sync tenants + team memberships from Obligate (every SSO login, not just
  // first provision). For an og_ account, what Obligate no longer grants is
  // removed too — a platform admin demoted in Obligate loses the
  // master-tenant 'admin' row that would otherwise keep every capability on
  // the god-view tenant.
  const tenantRemoved = await applySsoMemberships(
    localUserId, { tenants: assertion.tenants, teams: assertion.teams }, platformRole, ssoOwned,
  );
  // requireTenant caches memberships a few seconds: start from these rows.
  forgetTenantMemberships(localUserId);
  if (demoted || tenantRemoved) {
    // Open sessions keep their tenant (and an admin's may sit on any tenant):
    // end them, as a local demotion does. This sign-in gets a new session.
    const { killSessionsForUser } = await import('../services/userSessions.service');
    await killSessionsForUser(localUserId, demoted ? 'role_demoted' : 'tenant_access_removed');
  }

  // Sync preferences
  if (assertion.preferences) {
    const prefUpdate: Record<string, unknown> = {};
    if (assertion.preferences.preferredLanguage) prefUpdate.preferred_language = assertion.preferences.preferredLanguage;
    if (assertion.preferences.profilePhotoUrl !== undefined) prefUpdate.avatar = assertion.preferences.profilePhotoUrl;
    if (Object.keys(prefUpdate).length > 0) {
      await db('users').where({ id: localUserId }).update(prefUpdate);
    }
    const uiPrefs: Record<string, unknown> = {};
    if (assertion.preferences.preferredTheme) uiPrefs.preferredTheme = assertion.preferences.preferredTheme;
    if (assertion.preferences.toastEnabled !== undefined) uiPrefs.toastEnabled = assertion.preferences.toastEnabled;
    if (assertion.preferences.toastPosition) uiPrefs.toastPosition = assertion.preferences.toastPosition;
    if (assertion.preferences.anonymousMode !== undefined) uiPrefs.anonymousMode = assertion.preferences.anonymousMode;
    if (Object.keys(uiPrefs).length > 0) {
      const existingRow = await db('users').where({ id: localUserId }).select('preferences').first() as { preferences: unknown } | undefined;
      const existing = (typeof existingRow?.preferences === 'string' ? JSON.parse(existingRow.preferences) : existingRow?.preferences) ?? {};
      await db('users').where({ id: localUserId }).update({
        preferences: JSON.stringify({ ...existing, ...uiPrefs }),
      });
    }
  }

  // The session's tenant when no cross-app hint applies: the first tenant of
  // the account (a platform admin lands on the master tenant). An account
  // left without any tenant gets no session — never the master tenant it is
  // not a member of; the login page says why (?error=no_tenant) and access
  // is granted in Obligate.
  const firstTenantId = await tenantService.sessionTenantFor(localUserId, platformRole);
  if (firstTenantId === null) {
    await refuseSignInWithoutTenant(req, { id: localUserId, username: assertion.username }, 'sso');
    throw Object.assign(new Error(`SSO sign-in refused: local user #${localUserId} belongs to no tenant`), { ssoErrorCode: 'no_tenant' });
  }

  // Set session, under a NEW id (session fixation). Only the cross-app tenant
  // hint survives from the pre-login session.
  await regenerateSession(req, ['requestedTenantSlug']);
  req.session.userId = localUserId;
  // How the session was opened (audit-durci §5.3: actor.auth).
  req.session.authMethod = 'sso';
  req.session.authAt = Date.now();
  // A full Obligate sign-in lifts the step-up code lock (§6.8).
  const { clearCodeThrottle } = await import('../services/deviceKey/stepUpProof');
  await clearCodeThrottle(localUserId);
  const user = await db('users').where({ id: localUserId }).first() as { username: string; role: string } | undefined;
  if (user) {
    req.session.username = user.username;
    // Platform role straight from the verified assertion (written to
    // users.role above), not re-read: a concurrent sso-user-sync call cannot
    // slip another role into this new session.
    req.session.role = platformRole;
  }

  // Cross-app handoff: prefer the tenant slug requested by the source app
  // when the user has access to a tenant with that slug. Otherwise fall
  // back to the first available tenant (existing behaviour).
  //
  // Platform admins (assertion.role === 'admin') have implicit access to all
  // tenants and don't get user_tenants rows materialised, so the JOIN that
  // gates regular users would always miss for them. We resolve by tenant
  // existence only when the user is a platform admin; non-admins still need
  // the access-check JOIN so the slug cannot be forged for a tenant they
  // shouldn't reach.
  let resolvedTenantId: number | null = null;
  const requestedSlug = req.session.requestedTenantSlug;
  if (requestedSlug) {
    const isPlatformAdmin = assertion.role === 'admin';
    const match = isPlatformAdmin
      ? await db('tenants').where({ slug: requestedSlug }).select('id').first() as { id: number } | undefined
      : await db('tenants as t')
          .join('user_tenants as ut', 'ut.tenant_id', 't.id')
          .where({ 't.slug': requestedSlug, 'ut.user_id': localUserId })
          .select('t.id')
          .first() as { id: number } | undefined;
    if (match) {
      resolvedTenantId = match.id;
      logger.info({ userId: localUserId, slug: requestedSlug, isPlatformAdmin }, 'Cross-app handoff: tenant matched');
    } else {
      logger.info({ userId: localUserId, slug: requestedSlug, isPlatformAdmin },
        'Cross-app handoff: requested tenant not accessible, falling back');
    }
    // Always clear so the value does not leak into a subsequent login that did
    // not originate from a cross-app pill click.
    delete req.session.requestedTenantSlug;
  }

  if (resolvedTenantId === null) resolvedTenantId = firstTenantId;
  req.session.currentTenantId = resolvedTenantId;

  return localUserId;
}

/**
 * GET /auth/callback?code=xxx&state=xxx
 * Called by Obligate after successful authentication.
 * Exchanges the code for user info, auto-provisions, creates session, redirects.
 */
router.get('/callback', async (req, res) => {
  // Lot O: this callback answers a re-authentication of a signed-in session.
  const pendingReauth = req.session?.pendingReauth;
  try {
    const { code, state } = req.query as { code?: string; state?: string };
    if (!code) {
      if (pendingReauth) {
        // Cancelled / refused at Obligate: the user stays signed in.
        delete req.session.pendingReauth;
        res.redirect(reauthResultUrl(reauthReturnPath(pendingReauth.returnTo), 'failed', 'cancelled'));
        return;
      }
      res.status(400).json({ success: false, error: 'Missing code' });
      return;
    }

    // Validate OAuth state parameter to prevent Login CSRF (RFC 6749 §10.12)
    const expectedState = (req.session as any)?.oauthState as string | undefined;
    if (!expectedState || !state || state !== expectedState) {
      logger.warn({ state, expectedState: !!expectedState }, 'Obligate callback: state mismatch — possible CSRF');
      if (pendingReauth) {
        delete req.session.pendingReauth;
        res.redirect(reauthResultUrl(reauthReturnPath(pendingReauth.returnTo), 'failed', 'state'));
        return;
      }
      res.redirect('/login?error=sso_failed');
      return;
    }
    // Clear state after validation (single-use)
    delete (req.session as any).oauthState;

    // The redirect_uri of the authorize request: the one /sso-redirect stored
    // with the state (built from a verified origin), else rebuilt from a
    // VERIFIED public origin — never from the raw Host / X-Forwarded-* headers
    // (see resolvePublicOrigin).
    const storedRedirectUri = req.session.oauthRedirectUri;
    delete req.session.oauthRedirectUri;
    let redirectUri: string;
    if (typeof storedRedirectUri === 'string' && storedRedirectUri) {
      redirectUri = storedRedirectUri;
    } else {
      const origin = await resolvePublicOrigin(req);
      if (!origin) {
        res.redirect('/login?error=sso_failed');
        return;
      }
      redirectUri = `${origin}/auth/callback`;
    }

    // Exchange code with Obligate
    logger.info({ redirectUri }, 'Obligate callback: exchanging code');
    const assertion = await obligateService.exchangeCode(code, redirectUri);
    if (!assertion) {
      logger.warn('Obligate callback: exchange returned null — code invalid/expired or redirect_uri mismatch');
      if (pendingReauth) {
        delete req.session.pendingReauth;
        res.redirect(reauthResultUrl(reauthReturnPath(pendingReauth.returnTo), 'failed', 'exchange'));
        return;
      }
      res.redirect('/login?error=sso_failed');
      return;
    }
    logger.info({ obligateUserId: assertion.obligateUserId, username: assertion.username }, 'Obligate callback: exchange OK');

    // Lot O re-authentication: never a sign-in (no provisioning, same user,
    // same session id).
    if (pendingReauth) {
      await completeReauth(req, res, assertion, pendingReauth);
      return;
    }

    // Provision user and create session (identity context of the integration)
    const localUserId = await asIdentity(OBLIGATE_ACTOR, () => provisionObligateUser(assertion, req));
    logger.info(`Obligate SSO: user ${assertion.username} (obligate #${assertion.obligateUserId}) → local #${localUserId}`);

    // Save session, then redirect via HTML meta refresh to ensure Set-Cookie header
    // is fully processed by the browser before navigation occurs.
    req.session.save((err) => {
      if (err) { logger.error(err, 'Session save failed'); res.redirect('/login?error=sso_failed'); return; }
      logger.info({ userId: req.session.userId }, 'Session saved, redirecting to /');
      res.setHeader('Content-Type', 'text/html');
      res.end(`<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=/"><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0d1117;color:#8b949e;font-family:-apple-system,BlinkMacSystemFont,sans-serif}.s{text-align:center}.d{width:28px;height:28px;border:2.5px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:r .6s linear infinite;margin:0 auto 14px}@keyframes r{to{transform:rotate(360deg)}}</style></head><body><div class="s"><div class="d"></div><div>Signing in...</div></div></body></html>`);
    });
  } catch (err) {
    logger.error(err, 'Obligate callback error');
    if (pendingReauth && req.session?.userId) {
      delete req.session.pendingReauth;
      res.redirect(reauthResultUrl(reauthReturnPath(pendingReauth.returnTo), 'failed', 'error'));
      return;
    }
    const ssoErrorCode = (err as { ssoErrorCode?: string } | null)?.ssoErrorCode;
    const code = ssoErrorCode === 'account_disabled' || ssoErrorCode === 'no_tenant' ? ssoErrorCode : 'sso_failed';
    res.redirect(`/login?error=${code}`);
  }
});

/**
 * GET /auth/sso-redirect
 * Server-side redirect to Obligate authorize endpoint (browser redirect).
 *
 * WARNING — the client_id of this public route IS visible to anyone (it is in
 * the Location header, browser history, Referer, access logs): it is the
 * public id sha256(api key), never the key itself (Obligate refuses the raw
 * form). Every Bearer-authenticated route below still grants a key holder
 * nothing beyond what Obligate legitimately does (see /sso-user-sync).
 */
router.get('/sso-redirect', async (req, res) => {
  // Lot O: ?reauth=1 re-authenticates the SIGNED-IN og_ account (see
  // completeReauth). Its failures go back to `return`, never to /login.
  const reauth = req.query.reauth === '1';
  const reauthReturn = reauthReturnPath(req.query.return);
  const failTo = (loginError: string, reauthReason: string) =>
    (reauth ? reauthResultUrl(reauthReturn, 'failed', reauthReason) : `/login?error=${loginError}`);
  try {
    // A plain sign-in drops a re-authentication left pending in this session.
    if (!reauth && req.session?.pendingReauth) delete req.session.pendingReauth;
    let reauthFor: number | null = null;
    if (reauth) {
      const userId = req.session?.userId;
      if (!userId) { res.redirect('/login'); return; }
      const row = await db('users').where({ id: userId }).first('foreign_source', 'foreign_id', 'is_active') as
        { foreign_source: string | null; foreign_id: number | null; is_active: boolean } | undefined;
      const foreignId = Number(row?.foreign_id);
      if (!row || !row.is_active || row.foreign_source !== 'obligate' || !Number.isSafeInteger(foreignId) || foreignId <= 0) {
        res.redirect(reauthResultUrl(reauthReturn, 'failed', 'not_sso'));
        return;
      }
      if ((await obligateService.getLinkedLocalUserId(foreignId)) !== userId) {
        res.redirect(reauthResultUrl(reauthReturn, 'failed', 'not_sso'));
        return;
      }
      // Without the lot-O capabilities Obligate would ignore prompt=login and
      // answer without authTime / amr: refused up front (fail closed).
      if (!(await obligateService.lotOSupported())) {
        res.redirect(reauthResultUrl(reauthReturn, 'failed', 'unsupported'));
        return;
      }
      reauthFor = foreignId;
    }

    // Cross-app tenant handoff: the source Obli* app appends ?tenant=<slug>
    // when the user clicks the topbar switcher pill. Stashed in the session
    // (below, once the origin is known to be ours) so /auth/callback can apply
    // it once the user comes back from Obligate. Validated against the same
    // regex the tenants table enforces — anything else is dropped silently
    // (defence-in-depth, untrusted query input).
    const requestedTenant = req.query.tenant;
    const tenantSlug = !reauth && typeof requestedTenant === 'string' && /^[a-z0-9-]{1,64}$/.test(requestedTenant)
      ? requestedTenant : null;

    const raw = await appConfigService.getObligateRaw();
    const clientId = obligateService.authorizeClientId(raw);
    if (!raw.url || !clientId) {
      res.redirect(reauth ? reauthResultUrl(reauthReturn, 'failed', 'unsupported') : '/login');
      return;
    }
    // Verify Obligate is reachable before redirecting (prevents redirect loop when Gate is down)
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      const healthRes = await fetch(`${raw.url}/health`, { signal: controller.signal });
      clearTimeout(timeout);
      if (!healthRes.ok) { res.redirect(failTo('sso_failed', 'unreachable')); return; }
    } catch {
      res.redirect(failTo('sso_failed', 'unreachable'));
      return;
    }
    const selfUrl = await resolvePublicOrigin(req);
    if (!selfUrl && reauth) {
      // The session lives on this origin only: no restart on another one.
      res.redirect(reauthResultUrl(reauthReturn, 'failed', 'origin'));
      return;
    }
    if (!selfUrl) {
      // Reached through a host this app is not published under (LAN IP,
      // second DNS name…) or a forged one: restart the flow on the canonical
      // public origin, where the session, the state and a trusted
      // redirect_uri all live. Only once (`canon=1`): if even that request is
      // not recognised, the proxy hides the public host — give up.
      const retried = req.query.canon === '1';
      const canonical = retried ? null : await obligateService.getCanonicalOrigin();
      if (canonical) {
        const target = new URL('/auth/sso-redirect', canonical);
        target.searchParams.set('canon', '1');
        if (tenantSlug) target.searchParams.set('tenant', tenantSlug);
        logger.info({ canonical }, 'sso-redirect: untrusted host — restarting SSO on the canonical origin');
        res.redirect(target.toString());
        return;
      }
      if (retried) {
        logger.error('sso-redirect: canonical origin not recognised either — make the reverse proxy forward the public host (X-Forwarded-Host) or set APP_URL');
      }
      res.redirect('/login?error=sso_failed');
      return;
    }
    if (tenantSlug) req.session.requestedTenantSlug = tenantSlug;
    // Safety: never redirect to ourselves (misconfigured obligate_url pointing to this app)
    if (raw.url.replace(/\/$/, '') === selfUrl) {
      logger.error({ obligateUrl: raw.url, selfUrl }, 'sso-redirect: obligate_url points to this app — aborting to prevent loop');
      res.redirect(failTo('sso_misconfigured', 'misconfigured'));
      return;
    }
    const redirectUri = `${selfUrl}/auth/callback`;

    // Generate cryptographic state for CSRF protection (RFC 6749 §10.12),
    // stored with the exact redirect_uri /auth/callback must present.
    const oauthState = crypto.randomBytes(32).toString('hex');
    req.session.oauthState = oauthState;
    req.session.oauthRedirectUri = redirectUri;

    let obligateUrl = `${raw.url}/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(oauthState)}`;
    if (reauthFor !== null) {
      // Lot O (O4): Obligate must authenticate again (password + TOTP), even
      // with a live Obligate session.
      obligateUrl += '&prompt=login&max_age=0';
      req.session.pendingReauth = { startedAt: Date.now(), foreignId: reauthFor, returnTo: reauthReturn };
    }
    logger.info({ obligateUrl: raw.url, redirectUri, reauth: reauthFor !== null }, 'sso-redirect: redirecting to Obligate');

    // Save session before redirecting to ensure state is persisted
    req.session.save((err) => {
      if (err) { logger.error(err, 'sso-redirect: session save failed'); res.redirect(failTo('sso_failed', 'error')); return; }
      res.redirect(obligateUrl);
    });
  } catch {
    res.redirect(reauth ? reauthResultUrl(reauthReturn, 'failed', 'error') : '/login');
  }
});

/**
 * GET /api/auth/app-info
 * Called by Obligate (Bearer auth) to discover teams + tenants for mapping UI.
 *
 * Returns only what Obligate's permission-group mapping UI uses: tenant
 * slug/name, team name + tenant, permission set slug/name. No internal ids,
 * no capability matrix — the Bearer secret may be the (public) API key.
 */
router.get('/app-info', async (req, res) => {
  try {
    // Reverse auth: Obligate calls us with the inbound secret (default: the API key)
    if (!(await obligateService.verifyInboundBearer(req.headers.authorization))) {
      res.status(401).json({ success: false, error: 'Invalid API key' });
      return;
    }

    // Every tenant's teams: a transverse read with the integration's grant.
    const { teams, tenants, permissionSets } = await asIntegrationPlatform(req, 'obligate', 'app-info', async () => {
      // Fetch all teams across all tenants
      const teams = await db('user_teams')
        .join('tenants', 'user_teams.tenant_id', 'tenants.id')
        .select('user_teams.name', 'tenants.slug as tenant_slug', 'tenants.name as tenant_name')
        .orderBy('tenants.name')
        .orderBy('user_teams.name') as Array<{ name: string; tenant_slug: string; tenant_name: string }>;

      // Fetch all tenants
      const tenants = await db('tenants')
        .select('name', 'slug')
        .orderBy('name') as Array<{ name: string; slug: string }>;

      // Permission sets: Obligate offers them as role choices (slug + label)
      const permissionSets = (await permissionSetService.getAll())
        .map((p) => ({ slug: p.slug, name: p.name, isDefault: p.isDefault }));
      return { teams, tenants, permissionSets };
    });

    res.json({
      success: true,
      data: {
        roles: ['admin', 'user'],
        teams: teams.map(t => ({ name: t.name, tenantSlug: t.tenant_slug, tenantName: t.tenant_name })),
        tenants: tenants.map(t => ({ slug: t.slug, name: t.name })),
        permissionSets,
      },
    });
  } catch (err) {
    logger.error(err, 'app-info error');
    res.status(500).json({ success: false, error: 'Failed to fetch app info' });
  }
});

/**
 * GET /api/auth/dashboard-stats
 * Called by Obligate (Bearer auth) to display stats on the Obligate dashboard.
 */
router.get('/dashboard-stats', async (req, res) => {
  try {
    // Fleet-wide counters, nothing else (the Bearer secret may be public):
    // the devices, then the modules' counters (registerDashboardStat).
    if (!(await obligateService.verifyInboundBearer(req.headers.authorization))) { res.status(401).json({ success: false }); return; }

    const counters: ObligateDashboardStat[] = [
      // The devices under management; 'Active': a contact within 24 hours (modele-donnees-mdm §4.4, §11.1).
      { label: 'Devices', color: '#58a6ff', count: async () => Number(((await db('devices').whereNot('enrollment_state', 'unenrolled').count('id as c').first()) as any)?.c ?? 0) },
      { label: 'Active', color: '#2ea043', count: async () => Number(((await db('devices').whereNot('enrollment_state', 'unenrolled').whereRaw("last_checkin_at >= now() - interval '24 hours'").count('id as c').first()) as any)?.c ?? 0) },
      ...moduleDashboardStats(),
    ];
    // Fleet-wide counters: a transverse read with the integration's grant.
    const values = await asIntegrationPlatform(req, 'obligate', 'dashboard-stats', () => Promise.all(counters.map((s) => s.count())));
    res.json({ success: true, data: { stats: counters.map((s, i) => ({ label: s.label, value: values[i], color: s.color })) } });
  } catch { res.json({ success: true, data: null }); }
});

/**
 * GET /api/auth/sso-config
 * Returns Obligate SSO config for the LoginPage (public, no auth required).
 */
router.get('/sso-config', async (_req, res) => {
  try {
    const config = await obligateService.getSsoConfig();
    res.json({ success: true, data: config });
  } catch (err) {
    res.json({ success: true, data: { obligateUrl: null, obligateReachable: false, obligateEnabled: false } });
  }
});

/**
 * GET /api/auth/sso-logout-url
 * Returns Obligate logout URL so the client can redirect after local logout.
 */
router.get('/sso-logout-url', async (req, res) => {
  try {
    const cfg = await appConfigService.getObligateRaw();
    if (!cfg.url) {
      res.json({ success: true, data: null });
      return;
    }
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const redirectUri = `${protocol}://${host}/login`;
    const logoutUrl = `${cfg.url}/logout?redirect_uri=${encodeURIComponent(redirectUri)}`;
    res.json({ success: true, data: logoutUrl });
  } catch {
    res.json({ success: true, data: null });
  }
});

/**
 * GET /api/auth/connected-apps
 * Returns list of connected apps from Obligate (for cross-app nav buttons).
 */
router.get('/connected-apps', async (req, res) => {
  try {
    if (!req.session?.userId) {
      res.status(401).json({ success: false, error: 'Authentication required' });
      return;
    }
    // Scope the app switcher to the caller's Obligate entitlements. A local
    // (non-SSO) user has no Obligate id → we pass null and Obligate returns
    // nothing user-scoped; only SSO-provisioned users get the filtered list.
    const row = await db('users')
      .where({ id: req.session.userId })
      .select('foreign_source', 'foreign_id')
      .first() as { foreign_source: string | null; foreign_id: number | null } | undefined;
    const obligateUserId = row?.foreign_source === 'obligate' && row.foreign_id ? row.foreign_id : null;
    const apps = await obligateService.getConnectedApps(obligateUserId);
    res.json({ success: true, data: apps });
  } catch (err) {
    res.json({ success: true, data: [] });
  }
});

// POST /api/auth/set-password was REMOVED (2026-09). It let the holder of a
// session cookie give an SSO (og_) account a local password, which then
// signed in alone and outlived an Obligate password / MFA change. No client
// used it for an SSO account (the enrollment password step, its only caller,
// is hidden for them and always failed with 409 for accounts that already
// have a password). An SSO account never gets a local password here: it
// signs in through Obligate (see authController.login for the local-TOTP
// exception of accounts that already hold one).

/**
 * GET /api/auth/device-links?uuid=xxx
 * Returns cross-app links for a device UUID via Obligate.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
router.get('/device-links', async (req, res) => {
  try {
    const userId = req.session?.userId;
    if (!userId) { res.status(401).json({ success: false }); return; }
    const uuid = req.query.uuid;
    const tenantId = req.session.currentTenantId;
    if (typeof uuid !== 'string' || !UUID_RE.test(uuid) || !tenantId) { res.json({ success: true, data: [] }); return; }
    // Only for a device the caller may read, in its current tenant (a
    // platform admin on the master tenant: any tenant) — the links name the
    // device in the other apps, and are fetched with our key.
    const isAdmin = req.session.role === 'admin';
    // The global view of a platform administrator on the master tenant reads
    // every tenant (its grant); anyone else reads in its session's tenant.
    const globalView = isAdmin && isMasterTenant(tenantId);
    const lookup = async () => {
      const q = db('devices').where({ uuid });
      if (!globalView) q.where({ tenant_id: tenantId });
      const found = await q.first('id') as { id: number } | undefined;
      if (!found || (!isAdmin && !(await permissionService.canReadDevice(userId, found.id, false)))) return null;
      return found;
    };
    const device = globalView
      ? await asPlatform(await globalViewGrant(req, 'console.device_links'), lookup)
      : await switchToTenant(Number(tenantId), lookup);
    if (!device) {
      res.json({ success: true, data: [] });
      return;
    }
    const links = await obligateService.getDeviceLinks(uuid);
    res.json({ success: true, data: links });
  } catch {
    res.json({ success: true, data: [] });
  }
});

/** A positive safe integer from a JSON body field (number or digit string), else null. */
function positiveInt(v: unknown): number | null {
  const n = typeof v === 'number' ? v : (typeof v === 'string' && /^\d{1,15}$/.test(v) ? Number(v) : NaN);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

const SYNC_ACTIONS = ['deactivate', 'reactivate', 'delete', 'update-role', 'credentials-changed'] as const;
type SyncAction = typeof SYNC_ACTIONS[number];

type SyncAudit = (outcome: string, details?: Record<string, unknown>) => Promise<void>;

/**
 * Audit of one sso-user-sync push. `remoteUserId` is the PUSHED pointer
 * (informational, null when Obligate sent none); `localUserId` is the account
 * OUR records resolved (resourcePath), when there is one.
 */
function syncAuditFor(
  obligateId: number, pushedPointer: number | null, localId: number | null, action: SyncAction,
  ip: string | undefined, extra: Record<string, unknown> = {},
): SyncAudit {
  return (outcome, details = {}) => auditService.log({
    tenantId: MASTER_TENANT_ID,
    action: `sso_sync.${outcome}`,
    resourceType: 'user',
    resourcePath: localId !== null ? String(localId) : (pushedPointer !== null ? String(pushedPointer) : undefined),
    ipAddress: ip,
    details: {
      obligateUserId: obligateId, remoteUserId: pushedPointer, ...(localId !== null ? { localUserId: localId } : {}),
      requestedAction: action, ...extra, ...details,
    },
  });
}

type SyncUser = { id: number; username: string; role: string; is_active: boolean };

/**
 * The og_ account OUR records link to this Obligate identity
 * (getLinkedLocalUserId: sso_foreign_users, else users.foreign_id), provided
 * it really is one (users.foreign_source = 'obligate', foreign_id =
 * obligateId). Null for anything else: nothing linked, a local or
 * linked-local account. Never resolved from a pointer pushed by Obligate.
 * `expectedId` (re-checks): null too when the link now names another
 * account than the one the push was resolved to.
 */
async function linkedSsoAccount(obligateId: number, expectedId?: number): Promise<{ user: SyncUser | null; reason: string; linkedId: number | null }> {
  const linkedId = await obligateService.getLinkedLocalUserId(obligateId);
  if (!linkedId) return { user: null, reason: 'not_linked', linkedId };
  if (expectedId !== undefined && linkedId !== expectedId) return { user: null, reason: 'relinked', linkedId };
  const row = await db('users').where({ id: linkedId })
    .first('id', 'username', 'role', 'is_active', 'foreign_source', 'foreign_id') as
    (SyncUser & { foreign_source: string | null; foreign_id: number | null }) | undefined;
  if (!row || row.foreign_source !== 'obligate' || Number(row.foreign_id) !== obligateId) {
    return { user: null, reason: 'not_an_sso_account', linkedId };
  }
  return { user: row, reason: '', linkedId };
}

/**
 * 'done', or not confirmed (yet): `retry` says why — the route re-checks it
 * (roster actions) or answers 503 (credentials-changed).
 */
type SyncResult = 'done' | {
  retry: 'still_on_roster' | 'identity_still_at_obligate' | 'epoch_unavailable' | 'roster_unavailable' | 'throttled';
};

/**
 * A deactivation Obligate confirmed (read by us): the account disabled, its
 * sessions killed (P6: requireAuth does not re-read is_active), its trusted
 * IPs and phone keys revoked (§6.7: restrictive only).
 */
async function deactivateConfirmed(localId: number, wasActive: boolean): Promise<void> {
  if (wasActive) await db('users').where({ id: localId }).update({ is_active: false, updated_at: new Date() });
  const { killSessionsForUser } = await import('../services/userSessions.service');
  await killSessionsForUser(localId, 'user_disabled');
  const { tfaTrustService } = await import('../services/tfaTrust.service');
  await tfaTrustService.revokeAllForUser(localId);
  try {
    const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
    await deviceKeyService.revokeAllForUser(localId, 'user_disabled');
  } catch { /* the credential-version trigger (is_active) is the safety net */ }
}

/**
 * Apply a sync action ONLY as far as Obligate itself (read by us, from the
 * configured Obligate) confirms it:
 *   - deactivate: only when the user is no longer on the roster (may no
 *     longer sign in here);
 *   - delete: only when the user is off the roster AND Obligate says the
 *     identity is gone (mfa-epoch: its JSON 404). Off the roster but still
 *     known to Obligate (deactivated, disabled on this app, no longer
 *     entitled): only what the roster confirms — a deactivation — is applied,
 *     and the deletion is re-checked (Obligate pushes 'delete' BEFORE removing
 *     the user). Obligate does not list the local ids of off-roster users,
 *     but their Obligate ids can be enumerated by anyone holding the key: the
 *     absence from the roster alone never deletes an account;
 *   - reactivate: never applied — a push never re-enables an account. The
 *     next SSO sign-in does it, since Obligate issues an assertion only for a
 *     user active and allowed here (provisionObligateUser);
 *   - update-role: the role is the roster's, never the body's. A demotion
 *     (not an admin on the roster, or off it) is applied at once, with the
 *     master-tenant admin row and the tenant access Obligate no longer grants;
 *     a PROMOTION never is — the verified assertion of the next SSO sign-in
 *     carries the platform role.
 * A pushed body alone thus changes nothing Obligate itself does not say, even
 * from someone holding the API key. `localId` is the account OUR records
 * resolved for obligateId (never the pushed pointer).
 */
async function applyConfirmedSync(
  obligateId: number, localId: number, action: SyncAction, roster: ObligateRoster, audit: SyncAudit,
): Promise<SyncResult> {
  const { user } = await linkedSsoAccount(obligateId, localId);
  if (!user) return 'done'; // gone (or re-linked) meanwhile
  const current = roster.get(obligateId);

  switch (action) {
    case 'deactivate': {
      if (current) { await audit('unconfirmed', { username: user.username }); return 'done'; }
      await deactivateConfirmed(localId, user.is_active !== false);
      logger.info(`SSO sync: deactivated user #${localId} (not on the Obligate roster)`);
      await audit('deactivated', { username: user.username });
      return 'done';
    }
    case 'reactivate': {
      if (!current) { await audit('unconfirmed', { username: user.username }); return 'done'; }
      if (user.is_active === false) {
        logger.info({ obligateUserId: obligateId, localUserId: localId },
          'SSO sync: reactivation not applied — the next SSO sign-in re-enables the account');
        await audit('reactivation_deferred', { username: user.username });
      }
      return 'done';
    }
    case 'delete': {
      if (current) return { retry: 'still_on_roster' };
      const e = await obligateService.mfaEpochForPush(obligateId);
      if (e.kind === 'throttled') return { retry: 'throttled' };
      if (e.kind === 'unavailable') return { retry: 'epoch_unavailable' };
      if (e.kind === 'ok') {
        // Still known to Obligate: only the deactivation is confirmed.
        if (user.is_active !== false) {
          await deactivateConfirmed(localId, true);
          logger.info(`SSO sync: delete of user #${localId} not confirmed (still known to Obligate) — deactivated, deletion re-checked`);
          await audit('deactivated', { username: user.username, deleteDeferred: true });
        }
        return { retry: 'identity_still_at_obligate' };
      }
      await db('sso_foreign_users').where({ local_user_id: localId }).del();
      await db('users').where({ id: localId }).del();
      // A deleted user's sessions would keep their role (admin bypasses).
      const { killSessionsForUser } = await import('../services/userSessions.service');
      await killSessionsForUser(localId, 'user_deleted');
      logger.info(`SSO sync: deleted user #${localId} (gone from Obligate)`);
      await audit('deleted', { username: user.username });
      return 'done';
    }
    case 'credentials-changed':
      // Confirmed by the MFA epoch (see applyCredentialsChanged).
      return applyCredentialsChanged(obligateId, localId, audit);
    case 'update-role': {
      if (current?.role === 'admin') {
        if (user.role !== 'admin') {
          logger.warn({ obligateUserId: obligateId, localUserId: localId },
            'SSO sync: promotion not applied — the role comes from the next SSO sign-in');
          await audit('promotion_deferred', { username: user.username, currentRole: user.role });
        }
        return 'done';
      }
      // Not an admin per Obligate (or no access at all): the platform role,
      // the master-tenant admin row and the tenant access Obligate no longer
      // grants go now.
      const wasAdmin = user.role === 'admin';
      if (wasAdmin) await db('users').where({ id: localId }).update({ role: 'user', updated_at: new Date() });
      const tenantRemoved = await applySsoMemberships(
        localId, { tenants: current?.tenants ?? [], teams: current?.teams ?? [] }, 'user', true,
      );
      forgetTenantMemberships(localId);
      if (wasAdmin || tenantRemoved) {
        const { killSessionsForUser } = await import('../services/userSessions.service');
        await killSessionsForUser(localId, wasAdmin ? 'role_demoted' : 'tenant_access_removed');
        logger.info(`SSO sync: demoted user #${localId} (per the Obligate roster)`);
        await audit('demoted', {
          username: user.username, before: user.role, after: 'user', rosterRole: current?.role ?? null, tenantAccessRemoved: tenantRemoved,
        });
      }
      return 'done';
    }
  }
  return 'done';
}

/**
 * Lot O (O3) `credentials-changed {obligateUserId, remoteUserId?, mfaEpoch}`:
 * the user's password / TOTP / activation changed at Obligate, or an admin
 * reset their MFA. Obligate queues it for EVERY such change and retries it for
 * 24 h: it is also the reliable carrier of a deactivation whose one-shot
 * 'deactivate' push was lost. The push proves nothing and its mfaEpoch is
 * never used: the epoch is re-read from Obligate by us (mfaEpochForPush:
 * uncached, coalesced, bounded over time), for every linked og_ account —
 * with or without a phone key, so that the answer tells nothing about keys:
 *   - active for this app at Obligate: the phone keys enrolled under another
 *     epoch are revoked ('sso_mfa_changed', which also drops the user's
 *     trusted IPs) and the sessions killed; nothing when every key matches
 *     (a forged push) or there is no key;
 *   - no longer active for this app (active:false: deactivated, disabled on
 *     this app, no longer entitled): the confirmed deactivation, as for
 *     'deactivate' (never a reactivation: the next SSO sign-in does that);
 *   - Obligate's 404 (no such user, or no SSO link any more): the same, once
 *     the roster confirms the user is not listed; a 404 for a listed user
 *     (e.g. the app registered again at Obligate) changes nothing;
 *   - unreadable, or not read (PUSH_READ_BUDGET) → retry: the route answers
 *     503 and Obligate's persisted queue retries (30 s up to 1 h, for 24 h,
 *     then an alert). The epoch cache is dropped first: meanwhile the
 *     use-time check re-reads Obligate or fails closed.
 */
async function applyCredentialsChanged(obligateId: number, localId: number, audit: SyncAudit): Promise<SyncResult> {
  const { user } = await linkedSsoAccount(obligateId, localId);
  if (!user) return 'done';
  obligateService.forgetMfaEpoch(obligateId);
  const e = await obligateService.mfaEpochForPush(obligateId);
  if (e.kind === 'throttled') return { retry: 'throttled' };
  if (e.kind === 'unavailable') return { retry: 'epoch_unavailable' };
  const { applySsoCredentialsChanged } = await import('../services/deviceKey/deviceKey.service');
  if (e.kind === 'ok' && e.value.active) {
    const r = await applySsoCredentialsChanged(localId, e.value);
    // No active phone key: nothing to change, no audit row (a push
    // authenticated by a possibly public secret must not fill the audit log).
    if (r.outcome === 'none') return 'done';
    if (r.outcome === 'unconfirmed') {
      await audit('unconfirmed', { username: user.username, mfaEpoch: e.value.mfaEpoch });
      return 'done';
    }
    logger.info({ localUserId: localId, revoked: r.count }, 'SSO sync: credentials changed at Obligate — phone keys revoked, sessions killed');
    await audit('credentials_changed', { username: user.username, mfaEpoch: e.value.mfaEpoch, keysRevoked: r.count });
    return 'done';
  }
  if (e.kind === 'not_found') {
    const rr = await obligateService.rosterForPush();
    if (rr.kind === 'throttled') return { retry: 'throttled' };
    if (rr.kind === 'unavailable') return { retry: 'roster_unavailable' };
    if (rr.roster.has(obligateId)) {
      await audit('unconfirmed', { username: user.username, reason: 'epoch_not_found_but_listed' });
      return 'done';
    }
  }
  // Obligate no longer lets this user use the app (active:false), or no
  // longer knows them here (404 and off the roster).
  const reason = e.kind === 'ok' ? 'inactive_at_obligate' : 'gone_at_obligate';
  const epoch = e.kind === 'ok' ? { mfaEpoch: e.value.mfaEpoch } : {};
  if (user.is_active !== false) {
    await deactivateConfirmed(localId, true);
    logger.info(`SSO sync: deactivated user #${localId} (credentials-changed: ${reason})`);
    await audit('deactivated', { username: user.username, reason, ...epoch });
    return 'done';
  }
  // Already disabled here: its phone keys go all the same.
  const r = await applySsoCredentialsChanged(localId, e.kind === 'ok' ? e.value : null);
  if (r.outcome === 'revoked') {
    await audit('credentials_changed', { username: user.username, reason, keysRevoked: r.count, ...epoch });
  }
  return 'done';
}

/**
 * Re-check delays (ms) of a roster sync change not confirmed yet (delete
 * pushed before Obligate removes the user) or not readable (roster / epoch
 * unavailable, PUSH_READ_BUDGET): the one-shot roster pushes are never
 * retried by Obligate. Not used for credentials-changed, which Obligate
 * retries itself on a 5xx. Exported for the verification harness only.
 */
export const SYNC_RECHECK_DELAYS_MS: number[] = [15_000, 60_000, 180_000];

/**
 * A re-check, as a durable job (core.sso.sync-recheck): what the audit of
 * the push needs, serialisable — never the closure. The client address is
 * the only personal data of a job payload (kept one day).
 */
const RecheckPayload = z.object({
  obligateId: z.number().int().positive(),
  localId: z.number().int().positive(),
  action: z.enum(SYNC_ACTIONS),
  pushedPointer: z.number().int().positive().nullable(),
  ip: z.string().max(64).nullable(),
  extra: z.object({
    role: z.string().max(64).optional(),
    pointerMismatch: z.boolean().optional(),
    linkedLocalUserId: z.number().int().positive().nullable().optional(),
  }).strict(),
  step: z.number().int().min(0).max(2),
}).strict();
type RecheckPayload = z.infer<typeof RecheckPayload>;

let recheckJob: JobHandle<RecheckPayload> | null = null;

/**
 * The chain of re-checks (+15 s, +75 s, +255 s, then 'recheck_expired'):
 * one job per step, the next one sent by the handler. Policy 'stately' on
 * the key `<account>:<action>`: a push of the same account and action while
 * a re-check is queued is the same chain (the Set in memory it replaces was
 * lost at each restart: now the chain survives one). Registered by index.ts
 * before the start.
 */
export function registerSsoSyncJobs(): void {
  if (recheckJob) return;
  recheckJob = registerJob({
    name: 'core.sso.sync-recheck',
    scope: 'platform',
    description: 'Re-check an Obligate user-sync push against the roster (15 s, 60 s, 180 s)',
    payload: RecheckPayload,
    policy: 'stately',
    // The chain is the retry.
    retry: { limit: 0 },
    timeoutSeconds: 60,
    // The client address in the payload: one day at most.
    keepFinishedSeconds: 86_400,
    keepPendingSeconds: 86_400,
    deadLetter: false,
    handler: async (ctx): Promise<JobResult> => {
      const p = ctx.payload;
      const audit = syncAuditFor(p.obligateId, p.pushedPointer, p.localId, p.action, p.ip ?? undefined,
        { ...p.extra, actor: ctx.actor, jobId: ctx.jobId });
      let outcome: SyncResult = { retry: 'roster_unavailable' };
      try {
        const rr = await obligateService.rosterForPush();
        // Accounts and links: the identity context, as the job.
        if (rr.kind === 'ok') outcome = await asIdentity(ctx.dbActor, () => applyConfirmedSync(p.obligateId, p.localId, p.action, rr.roster, audit));
      } catch (err) {
        ctx.log.error({ err: safeErr(err) }, 'SSO sync: re-check failed');
      }
      if (outcome === 'done') return { output: { outcome: 'done' } };
      const next = p.step + 1;
      if (next < SYNC_RECHECK_DELAYS_MS.length) {
        const id = await recheckJob!.send({ ...p, step: next },
          { singletonKey: `${p.localId}:${p.action}`, startAfter: SYNC_RECHECK_DELAYS_MS[next] / 1000 });
        // null: a newer push of the same account and action is already queued; it carries on.
        return { output: { outcome: id ? 'rescheduled' : 'superseded', step: next } };
      }
      ctx.log.warn({ obligateUserId: p.obligateId, localUserId: p.localId, action: p.action },
        'SSO sync: change not confirmed by Obligate in time — not applied');
      await audit('recheck_expired');
      return { output: { outcome: 'recheck_expired' } };
    },
  });
}

/** Keyed on the account OUR records resolved (`localId`), never on the pushed pointer. */
async function scheduleSyncRecheck(p: Omit<RecheckPayload, 'step'>): Promise<void> {
  if (!recheckJob) throw new Error('SSO sync re-checks not registered (registerSsoSyncJobs)');
  await recheckJob.send({ ...p, step: 0 },
    { singletonKey: `${p.localId}:${p.action}`, startAfter: SYNC_RECHECK_DELAYS_MS[0] / 1000 });
}

/** The re-check payload's copy of the push's audit extras (role cut to 64). */
function recheckExtra(role: string | undefined, pointerMismatch: boolean, linkedId: number | null): RecheckPayload['extra'] {
  return {
    ...(role !== undefined ? { role: role.slice(0, 64) } : {}),
    ...(pointerMismatch ? { pointerMismatch: true, linkedLocalUserId: linkedId } : {}),
  };
}

// Bursts of sync pushes are unusual for a real Obligate (an admin changes one
// user at a time): above this many in a minute, log + audit once per minute.
const SYNC_BURST_WINDOW_MS = 60_000;
const SYNC_BURST_THRESHOLD = 30;
let syncWindow = { start: 0, count: 0, reported: false };
function noteSyncCall(ip: string | undefined): void {
  const now = Date.now();
  if (now - syncWindow.start > SYNC_BURST_WINDOW_MS) syncWindow = { start: now, count: 0, reported: false };
  syncWindow.count++;
  if (syncWindow.count > SYNC_BURST_THRESHOLD && !syncWindow.reported) {
    syncWindow.reported = true;
    logger.warn({ count: syncWindow.count, ip }, 'SSO sync: burst of sso-user-sync calls — check who holds the Obligate API key');
    void auditService.log({
      tenantId: MASTER_TENANT_ID, action: 'sso_sync.burst', ipAddress: ip,
      details: { count: syncWindow.count, windowSeconds: SYNC_BURST_WINDOW_MS / 1000 },
    });
  }
}

// Audit rows a stream of pushes could repeat for one user (the 503 answers
// of credentials-changed): at most one per user and reason every 5 min.
const SPARSE_AUDIT_MS = 5 * 60_000;
const sparseAudits = new Map<string, number>();
function sparseAudit(key: string): boolean {
  const now = Date.now();
  const last = sparseAudits.get(key);
  if (last !== undefined && now - last < SPARSE_AUDIT_MS) return false;
  if (sparseAudits.size >= 10_000) sparseAudits.clear();
  sparseAudits.set(key, now);
  return true;
}

const RETRY_ERRORS: Record<string, string> = {
  epoch_unavailable: 'Obligate MFA epoch unavailable',
  roster_unavailable: 'Obligate roster unavailable',
  throttled: 'Too many sync pushes, retry later',
};

/**
 * POST /api/auth/sso-user-sync
 * Called by Obligate (Bearer auth) when an SSO user is deactivated,
 * reactivated, deleted, or role-changed (one-shot pushes, never retried) —
 * and (lot O / O3) when their credentials changed ('credentials-changed',
 * queued and retried by Obligate; body mfaEpoch, never trusted).
 * Body: { obligateUserId, obligateUsername, remoteUserId: number | null, action, role?, mfaEpoch? }
 *
 * The Bearer secret may be public (the key may have leaked), so:
 *   - the account is resolved from `obligateUserId` by OUR records only
 *     (getLinkedLocalUserId: sso_foreign_users / users.foreign_id), and must
 *     be an og_ account (users.foreign_source = 'obligate', foreign_id =
 *     obligateUserId) — never a local or linked-local account. Nothing
 *     linked, or not an og_ account → left untouched, logged, audited and
 *     answered success (Obligate stops retrying);
 *   - `remoteUserId` (Obligate's copy of our id) is informational only: it
 *     may be absent or null (Obligate lost or never had the pointer), and a
 *     value that differs from our link is never followed: logged, and flagged
 *     (pointerMismatch) on the push's audit row when there is one. A present,
 *     non-null value must still be a positive integer (400 otherwise);
 *   - every action only as far as Obligate itself confirms it, read by us
 *     (applyConfirmedSync, applyCredentialsChanged): the roster, and for
 *     'delete' and credentials-changed the MFA epoch too. A roster action not
 *     confirmed yet or not readable → re-checked here (these one-shot pushes
 *     are never retried); credentials-changed not readable → 503 (Obligate's
 *     persisted queue retries, then alerts its admins);
 *   - the reads a push starts at Obligate are bounded (PUSH_READ_BUDGET:
 *     coalesced, per user and over time): pushes cannot spend Obligarth's
 *     request budget at Obligate.
 * The account being resolved from obligateUserId alone, and Obligate user ids
 * being enumerable, nothing here relies on the pointer being secret.
 * Every applied or refused change is audited (sso_sync.*), except a
 * credentials-changed with nothing to do (no phone key, still active), whose
 * pointer mismatch, if any, is only logged; a 503 is audited at most once per
 * user and reason every 5 min; an unlinked id is audited ('ignored').
 */
router.post('/sso-user-sync', async (req, res) => {
  try {
    if (!(await obligateService.verifyInboundBearer(req.headers.authorization))) { res.status(401).json({ success: false }); return; }
    // Accounts, links and memberships: the identity context of the integration.
    await asIdentity(OBLIGATE_ACTOR, () => ssoUserSync(req, res));
  } catch (err) {
    logger.error(err, 'sso-user-sync error');
    res.status(500).json({ success: false, error: 'Sync failed' });
  }
});

async function ssoUserSync(req: Request, res: import('express').Response): Promise<void> {
  {

    const body = (req.body ?? {}) as Record<string, unknown>;
    const obligateId = positiveInt(body.obligateUserId);
    const action = SYNC_ACTIONS.find((a) => a === body.action) as SyncAction | undefined;
    const role = typeof body.role === 'string' ? body.role : undefined;
    // Informational pointer: absent / null accepted, anything else must be valid.
    const pointerSent = body.remoteUserId !== undefined && body.remoteUserId !== null;
    const pushedPointer = pointerSent ? positiveInt(body.remoteUserId) : null;
    if (!obligateId || !action || (pointerSent && !pushedPointer)) {
      res.status(400).json({ success: false, error: 'Missing fields' });
      return;
    }

    const ip = clientAddress(req).ip || undefined;
    noteSyncCall(ip);
    // The account, from OUR records only.
    const { user, reason, linkedId } = await linkedSsoAccount(obligateId);
    const localId = user ? user.id : null;
    const pointerMismatch = pushedPointer !== null && linkedId !== null && pushedPointer !== linkedId;
    // The pushed epoch is recorded for the audit only (never compared nor stored).
    const pushedEpoch = action === 'credentials-changed' && typeof body.mfaEpoch === 'number' && Number.isSafeInteger(body.mfaEpoch)
      ? body.mfaEpoch : undefined;
    const audit = syncAuditFor(obligateId, pushedPointer, localId, action, ip, {
      ...(role !== undefined ? { role } : {}),
      ...(pushedEpoch !== undefined ? { pushedMfaEpoch: pushedEpoch } : {}),
      ...(pointerMismatch ? { pointerMismatch: true, linkedLocalUserId: linkedId } : {}),
    });
    if (pointerMismatch) {
      // Obligate's pointer is stale, or someone pushes another account's id:
      // never followed. Logged here, flagged on the outcome's audit row.
      logger.warn({ obligateUserId: obligateId, remoteUserId: pushedPointer, linkedLocalUserId: linkedId, action },
        'SSO sync: pushed remoteUserId differs from our link — ignored, the linked account is used');
    }

    if (!user || localId === null) {
      logger.warn({ obligateUserId: obligateId, remoteUserId: pushedPointer, linkedLocalUserId: linkedId, action, reason },
        'SSO sync: no og_ account linked to this Obligate user — ignored');
      await audit('ignored', { reason, linkedLocalUserId: linkedId });
      res.json({ success: true });
      return;
    }

    // Lot O: confirmed with the user's MFA epoch, read from Obligate by us.
    // Not confirmable now → 503 so that Obligate's persisted queue retries (30
    // s up to 1 h, for 24 h, then an alert); no in-memory re-check (lost on
    // restart).
    if (action === 'credentials-changed') {
      const r = await applyCredentialsChanged(obligateId, localId, audit);
      if (r !== 'done') {
        logger.warn({ obligateUserId: obligateId, localUserId: localId, reason: r.retry },
          'SSO sync: credentials-changed not confirmable now — 503, Obligate retries');
        if (sparseAudit(`${localId}:${r.retry}`)) await audit(r.retry, { username: user.username });
        res.status(503).json({ success: false, error: RETRY_ERRORS[r.retry] ?? 'Retry later' });
        return;
      }
      res.json({ success: true });
      return;
    }

    // The push itself proves nothing: confirm it with Obligate's roster.
    // Not confirmed (or not readable) now: a durable re-check (+15 s, +75 s,
    // +255 s) carries the audit's elements, the same as this push's.
    const recheck = () => scheduleSyncRecheck({
      obligateId, localId, action, pushedPointer, ip: ip ?? null, extra: recheckExtra(role, pointerMismatch, linkedId),
    });
    const rr = await obligateService.rosterForPush();
    if (rr.kind !== 'ok') {
      await recheck();
      logger.warn({ obligateUserId: obligateId, localUserId: localId, action, reason: rr.kind },
        'SSO sync: Obligate roster not read — change re-checked later');
      await audit('recheck_scheduled', { reason: rr.kind === 'throttled' ? 'throttled' : 'roster_unavailable', username: user.username });
      res.json({ success: true });
      return;
    }
    const r = await applyConfirmedSync(obligateId, localId, action, rr.roster, audit);
    if (r !== 'done') {
      await recheck();
      await audit('recheck_scheduled', { reason: r.retry, username: user.username });
    }

    res.json({ success: true });
  }
}

export default router;
