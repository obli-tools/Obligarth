import { Router, type Request, type Response, type NextFunction } from 'express';
import { requireAuth } from '../middleware/auth';
import { attachSessionTenant } from '../middleware/tenant';
import { validate } from '../middleware/validate';
import { profileController } from '../controllers/profile.controller';
import { updateProfileSchema, changePasswordSchema } from '../validators/profile.schema';
import { db } from '../db';

const router = Router();

// All routes require authentication (any role)
router.use(requireAuth);
// This router is not under the tenant router: expose the session tenant as
// req.tenantId (restriction envelope, "Trust this IP" duration, audit — P4).
router.use(attachSessionTenant);

const normEmail = (v: unknown): string => (typeof v === 'string' ? v.trim().toLowerCase() : '');

/**
 * Does this profile write change how the account is RECOVERED or signed in
 * to? The password itself, or the e-mail address (password-reset links go
 * there). An unchanged address re-sent by the profile form does not count.
 */
function touchesRecovery(req: Request, currentEmail: string | null | undefined): boolean {
  if (req.method === 'PUT' && req.path === '/password') return true;
  if (req.method === 'PUT' && req.path === '/') {
    const body = (req.body ?? {}) as Record<string, unknown>;
    return Object.prototype.hasOwnProperty.call(body, 'email') && normEmail(body.email) !== normEmail(currentEmail);
  }
  return false;
}

// Gate profile writes — skip the 2FA step for SSO users (their identity
// is managed by the SSO provider and can't be mutated locally anyway).
// Local users changing their own profile / password hit the tenant's
// `tenant.manage_profile` policy.
//
// Device-bound 2FA [D2] (docs/mobile/device-bound-2fa.md §4.7): in a session
// bound to a phone key, changing the password or the e-mail address ALWAYS
// needs the owner's finger (or password + code), whatever the tenant level:
// otherwise the holder of the unlocked phone would move the address, reset
// the password through the e-mail link, and sign in again unbound (code
// alone and trusted IPs back). A 'restricted' level keeps its approval for
// an e-mail change; a password change never becomes an approval (it would
// carry the password): a fresh step-up, without IP trust, is asked instead.
async function gateProfileWrite(req: Request, res: Response, next: NextFunction) {
  try {
    const userId = (req.session as any).userId as number | undefined;
    if (!userId) return next();
    const row = await db('users').where({ id: userId }).first('foreign_source', 'email');
    if (row?.foreign_source === 'obligate') return next(); // SSO user → no local gate
    // The profile is global: its level is the STRICTEST of the user's
    // tenants, not the one of the tenant the session has selected (switching
    // to the laxest tenant must not skip the code).
    const tenantIds = (await db('user_tenants').where({ user_id: userId }).pluck('tenant_id')).map(Number);
    const { applyRestriction, restrictionService } = await import('../services/restriction.service');
    let bound = false;
    if (touchesRecovery(req, row?.email)) {
      const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
      const binding = await deviceKeyService.sessionBinding(req);
      bound = binding.kind !== 'unbound';
      if (bound) {
        const tenantId = (req as any).tenantId as number | undefined;
        const { level } = await restrictionService.getStrictestLevel(
          [...(tenantId ? [tenantId] : []), ...tenantIds], 'tenant.manage_profile',
        );
        if (level !== 'restricted') {
          const { checkSecondFactor, sendStepUpFailure } = await import('../services/deviceKey/stepUpProof');
          const outcome = await checkSecondFactor(req, {
            actionKey: 'tenant.manage_profile', allowTrustedIp: false, allowDevice: true,
          });
          if (!outcome.ok) { sendStepUpFailure(res, outcome); return; }
          return next();
        }
      }
    }
    // An approved profile write is EXECUTED for the requester's own account
    // (approval.service _executeProfileUpdate): the payload carries the
    // (validated) body; an avatar image goes to the sealed part (not shown,
    // wiped once resolved). A password change (current + new password) never
    // becomes a request: at the 'restricted' level restriction.service asks a
    // fresh step-up instead (carriesSecret — never an IP trust).
    const isAvatarUpload = req.method === 'PUT' && req.path === '/avatar';
    const isPasswordChange = req.method === 'PUT' && req.path === '/password';
    let description = `Update own profile (${req.method} ${req.path})`;
    if (isAvatarUpload) description = 'Change own profile picture';
    else if (req.method === 'DELETE' && req.path === '/avatar') description = 'Remove own profile picture';
    else if (req.method === 'PUT' && req.path === '/') {
      const { change } = await import('../services/approvalDescribe');
      const cur = await db('users').where({ id: userId }).first('display_name', 'email', 'preferred_language') as Record<string, unknown> | undefined;
      const b = (req.body ?? {}) as Record<string, unknown>;
      const parts = [
        'displayName' in b ? change('display name', cur?.display_name ?? null, b.displayName) : null,
        'email' in b ? change('e-mail', cur?.email ?? null, b.email) : null,
        'preferredLanguage' in b ? change('language', cur?.preferred_language ?? null, b.preferredLanguage) : null,
        b.preferences !== undefined ? `display preferences (${Object.keys((b.preferences ?? {}) as object).join(', ') || 'reset'})` : null,
      ].filter(Boolean);
      description = `Update own profile — ${parts.join('; ') || 'no change'}`;
    }
    const approved = await applyRestriction(res, {
      req,
      levelTenantIds: tenantIds,
      actionKey: 'tenant.manage_profile',
      carriesSecret: isPasswordChange,
      approvalRequestType: 'batch_command',
      approvalDescription: description,
      approvalPayload: {
        action: 'profile_update', userId, path: req.path, method: req.method,
        ...(isAvatarUpload || req.method === 'DELETE' || isPasswordChange ? {} : { body: req.body ?? {} }),
      },
      approvalSealed: isAvatarUpload ? { avatar: (req.body as { avatar?: unknown } | undefined)?.avatar } : undefined,
    });
    if (!approved) return;
    next();
  } catch (err) { next(err); }
}

router.get('/', profileController.get);
router.put('/', validate(updateProfileSchema), gateProfileWrite, profileController.update);
router.put('/password', validate(changePasswordSchema), gateProfileWrite, profileController.changePassword);
router.put('/avatar', gateProfileWrite, profileController.uploadAvatar);
router.delete('/avatar', gateProfileWrite, profileController.deleteAvatar);

// ── Trusted-IP TOTP sessions ─────────────────────────────────────────────
// The user can see which IPs currently skip the sensitive-action TOTP
// prompt, and revoke them. Listing is unauthenticated beyond the session;
// revocation just deletes — no step-up required because it's restrictive.

router.get('/trusted-ips', async (req, res, next) => {
  try {
    const userId = (req.session as any).userId as number;
    const { tfaTrustService } = await import('../services/tfaTrust.service');
    const items = await tfaTrustService.listForUser(userId);
    res.json({ data: items });
  } catch (err) { next(err); }
});

router.delete('/trusted-ips', async (req, res, next) => {
  try {
    const userId = (req.session as any).userId as number;
    const { tfaTrustService } = await import('../services/tfaTrust.service');
    await tfaTrustService.revokeAllForUser(userId);
    res.status(204).send();
  } catch (err) { next(err); }
});

router.delete('/trusted-ips/:ip', async (req, res, next) => {
  try {
    const userId = (req.session as any).userId as number;
    const { tfaTrustService } = await import('../services/tfaTrust.service');
    await tfaTrustService.revokeForUserIp(userId, req.params.ip);
    res.status(204).send();
  } catch (err) { next(err); }
});

export default router;
