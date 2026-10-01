import { regenerateSession } from '../utils/session';
import { clientIp } from '../utils/clientIp';
import type { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { appConfigService } from '../services/appConfig.service';
import { twoFactorService } from '../services/twoFactor.service';
import { hasLocalTotp } from '../services/totpSecret';
import { permissionService } from '../services/permission.service';
import { tenantService, noTenantAccessError, refuseSignInWithoutTenant } from '../services/tenant.service';
import { AppError } from '../middleware/errorHandler';
import { config } from '../config';
import { obligateService } from '../services/obligate.service';
import { db } from '../db';
import { asIdentity, asNone, switchToTenant, userActor } from '../db/context';
import { forgetGrantsOfSession } from '../db/platformAccess';
import type { LoginInput } from '../validators/auth.schema';
import { DEVICE_KEY_HEADER, type DeviceChallenge, type AuthMeDeviceKey } from '@obligarth/shared';

// Database contexts (rls-tenant §8.2): the account is looked up by its name
// in the identity context (anonymous actor a:login); once the password is
// proven, the sign-in reads and writes the account's own rows as that user
// (context 'none', actor u:<id>). The permissions of a session are read in
// the context of its tenant.

/** The user's permissions in the session's tenant, read in that tenant's
 *  context (a session without a valid tenant: none at all). */
function permissionsIn(userId: number, isAdmin: boolean, tenantId: unknown) {
  const tid = Number(tenantId);
  if (!Number.isSafeInteger(tid) || tid <= 0) return permissionService.getUserPermissions(userId, isAdmin, undefined);
  return switchToTenant(tid, () => permissionService.getUserPermissions(userId, isAdmin, tid));
}

type SignedInUser = NonNullable<Awaited<ReturnType<typeof authService.authenticate>>>;

/** The rest of a sign-in whose password is proven, as the user (context
 *  'none', actor u:<id>: the account's own rows). */
async function signIn(req: Request, res: Response, user: SignedInUser): Promise<void> {
  let methods = { totp: user.totpEnabled ?? false, email: user.emailOtpEnabled ?? false };

  // SSO account (Obligate, og_): it signs in through Obligate. A local
  // password alone must never open a session — it would bypass the
  // Obligate password / MFA and survive their change. Accepted only with
  // a LOCAL TOTP, which is then required (e-mail codes are not enough).
  // Evaluated only once the password is proven: a wrong password answers
  // exactly like any other account (no enumeration).
  if (user.foreignSource === 'obligate') {
    const f = await db('users').where({ id: user.id }).first('totp_enabled', 'totp_secret_enc') as
      { totp_enabled: boolean | null; totp_secret_enc: string | null } | undefined;
    if (!hasLocalTotp(f)) {
      try {
        const tenant = await tenantService.getFirstTenantForUser(user.id);
        const { auditService } = await import('../services/audit.service');
        await auditService.log({
          tenantId: tenant?.id ?? 1,
          userId: user.id,
          action: 'auth.login_refused',
          resourceType: 'user',
          resourcePath: String(user.id),
          details: { username: user.username, reason: 'sso_login_required', via: 'password' },
          ipAddress: clientIp(req) || undefined,
        });
      } catch {}
      res.status(403).json({
        success: false,
        error: 'This account signs in through Obligate (SSO).',
        code: 'ssoLoginRequired',
        ssoLoginRequired: true,
      });
      return;
    }
    methods = { totp: true, email: false };
  }

  const hasMfa = methods.totp || methods.email;

  // New session id once the password is proven (session fixation): an id
  // planted before sign-in never reaches the pending-2FA or signed-in state.
  await regenerateSession(req);

  if (hasMfa) {
    // Step 1: store pending MFA, don't create real session yet
    req.session.pendingMfaUserId = user.id;

    // Device-bound 2FA sign-in [D7] (docs/mobile/device-bound-2fa.md
    // §4.9.3): the Android app names its key for this user in the
    // X-Obli-Device-Key header. An eligible key (active, this user's,
    // credential version current, local account with TOTP, device keys
    // and device sign-in on, acceptable attestation) gets a 'login'
    // challenge bound to the NEW session; no e-mail code is sent then.
    // Anything else: the usual answer, nothing revealed.
    let deviceChallenge: DeviceChallenge | null = null;
    if (methods.totp && user.foreignSource !== 'obligate') {
      const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
      const key = await deviceKeyService.loginKeyFor(user.id, req.get(DEVICE_KEY_HEADER));
      if (key) deviceChallenge = await deviceKeyService.issueLoginChallenge(req, key);
    }
    if (deviceChallenge) {
      res.json({
        success: true,
        data: { requires2fa: true, methods: { ...methods, device: true }, deviceChallenge },
      });
      return;
    }

    // If email OTP is enabled, auto-send a code. We store ONLY a
    // SHA-256 hash of the code in the session — a session-store
    // dump can't pre-empt the user typing the OTP from email.
    if (methods.email && user.email) {
      const cfg = await appConfigService.getAll();
      if (cfg.otp_smtp_server_id) {
        const code = twoFactorService.generateEmailOtp();
        const { createHash } = await import('crypto');
        const codeHash = createHash('sha256').update(String(code)).digest('hex');
        req.session.pendingEmailOtp = { codeHash, email: user.email, expires: Date.now() + 10 * 60 * 1000 };
        await twoFactorService.sendEmailOtp(Number(cfg.otp_smtp_server_id), user.email, code);
      }
    }

    res.json({
      success: true,
      data: {
        requires2fa: true,
        methods,
      },
    });
    return;
  }

  // No 2FA — complete session immediately, on the first tenant of the
  // account (the master tenant for a platform admin without membership
  // rows). An account without any tenant gets no session: never the
  // master tenant it is not a member of. (With a second factor, the same
  // check runs once it is proven, twoFactorController.verify: nothing is
  // told before both factors are.)
  const tenantId = await tenantService.sessionTenantFor(user.id, user.role);
  if (tenantId === null) throw await refuseSignInWithoutTenant(req, user, 'password');
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.role = user.role;
  // How the session was opened (audit-durci §5.3: actor.auth of its entries).
  req.session.authMethod = 'password';
  req.session.authAt = Date.now();
  req.session.currentTenantId = tenantId;

  try {
    const { auditService } = await import('../services/audit.service');
    if (req.session.currentTenantId) {
      await auditService.log({
        tenantId: req.session.currentTenantId,
        userId: user.id,
        action: 'auth.login',
        resourceType: 'user',
        resourcePath: String(user.id),
        details: { username: user.username, via: 'password' },
        ipAddress: clientIp(req) || undefined,
      });
    }
  } catch {}

  res.json({ success: true, data: { user } });
}

export const authController = {
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { username, password } = req.body as LoginInput;
      const user = await asIdentity({ type: 'anonymous', name: 'login' }, () => authService.authenticate(username, password));

      if (!user) {
        throw new AppError(401, 'Invalid username or password');
      }

      await asNone(userActor(user.id), () => signIn(req, res, user));
    } catch (err) {
      next(err);
    }
  },

  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.session.userId;
      const tenantId = req.session.currentTenantId;
      // Device-bound 2FA (§4.9.6): the app signs out with its key's header —
      // the key is revoked ('logout'), which also kills the other sessions
      // bound to it; the app deletes the key on its side. Only a key of the
      // session's user (the header of another user's key is ignored).
      if (userId) {
        const header = req.get(DEVICE_KEY_HEADER);
        const keyIds = [...new Set([header, req.session.deviceKeyId].filter((k): k is string => typeof k === 'string'))];
        if (keyIds.length > 0) {
          const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
          await deviceKeyService.revoke(keyIds, 'logout', { ownerId: userId, byUserId: userId, req });
        }
      }
      // The session's cached global-view grant goes with it.
      if (typeof req.sessionID === 'string') forgetGrantsOfSession(req.sessionID);
      req.session.destroy(async (err) => {
        if (err) {
          next(new AppError(500, 'Failed to logout'));
          return;
        }
        res.clearCookie(config.sessionCookieName);
        try {
          if (userId && tenantId) {
            const { auditService } = await import('../services/audit.service');
            await auditService.log({
              tenantId, userId, action: 'auth.logout', resourceType: 'user', resourcePath: String(userId),
              ipAddress: clientIp(req) || undefined,
            });
          }
        } catch {}
        res.json({ success: true, message: 'Logged out' });
      });
    } catch (err) {
      next(err);
    }
  },

  async me(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.session.userId!;

      // Sync preferences from Obligate for SSO users (throttled, non-blocking)
      const fRow = await db('users').where({ id: userId }).select('foreign_source', 'foreign_id').first() as
        { foreign_source: string | null; foreign_id: number | null } | undefined;
      if (fRow?.foreign_source === 'obligate' && fRow.foreign_id) {
        await obligateService.syncUserPreferences(userId, fRow.foreign_id).catch(() => {});
      }

      const user = await authService.getUserById(userId);
      if (!user) {
        throw new AppError(401, 'User not found');
      }

      // Repair a missing session tenant (e.g. sessions from before Phase 13)
      // or one the user no longer belongs to (requireTenant refuses it): the
      // first tenant it still belongs to. None — never the master tenant it
      // is not a member of: the session ends, as the sign-in is refused.
      const current = Number(req.session.currentTenantId);
      const stale = !Number.isInteger(current) || current <= 0
        || (user.role !== 'admin' && !(await tenantService.isMemberCached(user.id, current)));
      if (stale) {
        const tenantId = await tenantService.sessionTenantFor(user.id, user.role);
        if (tenantId === null) {
          await new Promise<void>((resolve) => req.session.destroy(() => resolve()));
          throw noTenantAccessError();
        }
        req.session.currentTenantId = tenantId;
      }

      const isAdmin = user.role === 'admin';
      const permissions = await permissionsIn(user.id, isAdmin, req.session.currentTenantId);

      // Check if force 2FA applies to this user
      let requires2faSetup = false;
      if (!config.disable2faForce) {
        const cfg = await appConfigService.getAll();
        // app_config values are strings: 'false' is truthy — compare explicitly.
        if (cfg.force_2fa === 'true' && !user.totpEnabled && !user.emailOtpEnabled) {
          requires2faSetup = true;
        }
      }

      // Device-bound 2FA (§6.5): is this session bound to a phone key?
      const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
      const binding = await deviceKeyService.sessionBinding(req);
      const deviceKey: AuthMeDeviceKey = binding.kind === 'bound' ? { bound: true, keyId: binding.key.id } : { bound: false };

      res.json({
        success: true,
        data: { user, permissions, requires2faSetup, currentTenantId: req.session.currentTenantId, deviceKey },
      });
    } catch (err) {
      next(err);
    }
  },

  async permissions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const isAdmin = req.session.role === 'admin';
      const permissions = await permissionsIn(req.session.userId!, isAdmin, req.session.currentTenantId);
      res.json({ success: true, data: permissions });
    } catch (err) {
      next(err);
    }
  },
};
