import { regenerateSession } from '../utils/session';
import { clientIp } from '../utils/clientIp';
import type { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { appConfigService } from '../services/appConfig.service';
import { twoFactorService } from '../services/twoFactor.service';
import { permissionService } from '../services/permission.service';
import { tenantService } from '../services/tenant.service';
import { AppError } from '../middleware/errorHandler';
import { config } from '../config';
import { obligateService } from '../services/obligate.service';
import { db } from '../db';
import type { LoginInput } from '../validators/auth.schema';
import { DEVICE_KEY_HEADER, type DeviceChallenge, type AuthMeDeviceKey } from '@obliance/shared';

/** Helper: resolve & store the first accessible tenant in the session. */
async function setSessionTenant(req: Request, userId: number): Promise<void> {
  const tenant = await tenantService.getFirstTenantForUser(userId);
  req.session.currentTenantId = tenant?.id ?? 1;
}

export const authController = {
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { username, password } = req.body as LoginInput;
      const user = await authService.authenticate(username, password);

      if (!user) {
        throw new AppError(401, 'Invalid username or password');
      }

      let methods = { totp: user.totpEnabled ?? false, email: user.emailOtpEnabled ?? false };

      // SSO account (Obligate, og_): it signs in through Obligate. A local
      // password alone must never open a session — it would bypass the
      // Obligate password / MFA and survive their change. Accepted only with
      // a LOCAL TOTP, which is then required (e-mail codes are not enough).
      // Evaluated only once the password is proven: a wrong password answers
      // exactly like any other account (no enumeration).
      if (user.foreignSource === 'obligate') {
        const f = await db('users').where({ id: user.id }).first('totp_enabled', 'totp_secret') as
          { totp_enabled: boolean | null; totp_secret: string | null } | undefined;
        if (!(f?.totp_enabled && f?.totp_secret)) {
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

      // No 2FA — complete session immediately
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;
      await setSessionTenant(req, user.id);

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
      req.session.destroy(async (err) => {
        if (err) {
          next(new AppError(500, 'Failed to logout'));
          return;
        }
        res.clearCookie('connect.sid');
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

      // Repair missing currentTenantId (e.g. sessions from before Phase 13)
      if (!req.session.currentTenantId) {
        await setSessionTenant(req, user.id);
      }

      const isAdmin = user.role === 'admin';
      const permissions = await permissionService.getUserPermissions(user.id, isAdmin, req.session.currentTenantId);

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
      const permissions = await permissionService.getUserPermissions(req.session.userId!, isAdmin, req.session.currentTenantId);
      res.json({ success: true, data: permissions });
    } catch (err) {
      next(err);
    }
  },
};
