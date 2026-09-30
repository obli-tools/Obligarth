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

// ── SSH bastion public keys ──────────────────────────────────────────────
// A user's registered SSH public keys (identity at the bastion door). Local
// Obliance-owned, settable by SSO users too.

router.get('/ssh-keys', async (req, res, next) => {
  try {
    const userId = (req.session as any).userId as number;
    const { userKeysService } = await import('../services/sshBastion/userKeys.service');
    res.json({ data: await userKeysService.list(userId) });
  } catch (err) { next(err); }
});

// Registering a key grants a root-capable shell path through the bastion, so
// it requires a FRESH 2FA code (no trusted-IP shortcut) and is audited. A
// stolen web session alone must not be enough to plant a persistent key.
router.post('/ssh-keys', async (req, res, next) => {
  try {
    const userId = (req.session as any).userId as number;
    const { requireFreshTotp } = await import('../services/sshBastion/stepUp');
    const step = await requireFreshTotp(req, 'profile.ssh_key_add');
    if (!step.ok) {
      for (const [k, v] of Object.entries(step.headers ?? {})) res.setHeader(k, v);
      return res.status(step.status).json(step.body);
    }

    const { userKeysService } = await import('../services/sshBastion/userKeys.service');
    const key = await userKeysService.add(userId, req.body?.name, req.body?.publicKey);
    const { bastionAudit } = await import('../services/sshBastion/bastionUtil');
    const { clientIp } = await import('../services/tfaTrust.service');
    bastionAudit('key_added', { tenantId: (req as any).tenantId, userId, ip: clientIp(req), details: { keyId: key.id, fingerprint: key.fingerprint, name: key.name } });
    res.status(201).json({ data: key });
  } catch (err: any) {
    if (/Invalid|Unsupported|mismatch|already registered/i.test(err?.message || '')) {
      const { AppError } = await import('../middleware/errorHandler');
      return next(new AppError(400, err.message));
    }
    next(err);
  }
});

// Removal is restrictive (it can only reduce access) -> no step-up, audited.
router.delete('/ssh-keys/:id', async (req, res, next) => {
  try {
    const userId = (req.session as any).userId as number;
    const id = parseInt(req.params.id, 10);
    const { userKeysService } = await import('../services/sshBastion/userKeys.service');
    const ok = await userKeysService.remove(userId, id);
    if (ok) {
      const { bastionAudit } = await import('../services/sshBastion/bastionUtil');
      const { clientIp } = await import('../services/tfaTrust.service');
      bastionAudit('key_removed', { tenantId: (req as any).tenantId, userId, ip: clientIp(req), details: { keyId: id } });
    }
    res.status(ok ? 204 : 404).send();
  } catch (err) { next(err); }
});

// Header "SSH" button: after a fresh 2FA code, authorize the caller's current
// IP to reach the bastion for 24h. Stored in ssh_bastion_ip_grants (NOT in
// tfa_trusted_sessions) so it never silences 2FA for sensitive web actions.
router.post('/ssh-authorize-ip', async (req, res, next) => {
  try {
    const userId = (req.session as any).userId as number;
    // Same duration as the tenant "Trust this IP" setting; 0 disables IP
    // authorization entirely (allow-list only). Checked BEFORE the 2FA prompt.
    const { trustWindowMs } = await import('../services/tfaTrust.service');
    const windowMs = await trustWindowMs((req as any).tenantId);
    if (windowMs <= 0) {
      const { AppError } = await import('../middleware/errorHandler');
      return next(new AppError(403, 'IP authorization is disabled ("Trust this IP" duration is 0). Ask an administrator to add your IP to the SSH bastion allow-list.'));
    }
    const { requireFreshTotp } = await import('../services/sshBastion/stepUp');
    const step = await requireFreshTotp(req, 'profile.ssh_authorize_ip');
    if (!step.ok) {
      for (const [k, v] of Object.entries(step.headers ?? {})) res.setHeader(k, v);
      return res.status(step.status).json(step.body);
    }

    const { clientIp } = await import('../services/tfaTrust.service');
    const ip = clientIp(req);
    if (!ip) {
      const { AppError } = await import('../middleware/errorHandler');
      return next(new AppError(400, 'Could not determine your IP address'));
    }
    const { bastionGate, isInfraIp } = await import('../services/sshBastion/bastionGate.service');
    const { clientAddress } = await import('../utils/clientIp');
    // The web side only sees a relay (reverse proxy / Docker) address: granting
    // it would authorize every user behind that relay. Fail closed.
    if (isInfraIp(ip) || clientAddress(req).relay) {
      const { AppError } = await import('../middleware/errorHandler');
      return next(new AppError(400, `Obliance sees your IP as ${ip}, an internal relay address — your real IP cannot be authorized. Ask an administrator to fix the reverse-proxy X-Forwarded-For configuration.`));
    }
    const expiresAt = await bastionGate.grantIp(userId, ip, windowMs);
    const { bastionAudit } = await import('../services/sshBastion/bastionUtil');
    bastionAudit('ip_authorized', { tenantId: (req as any).tenantId, userId, ip, details: { expiresAt } });
    res.json({ data: { ip, expiresAt } });
  } catch (err) { next(err); }
});

// Revoke the caller's own SSH authorization for their current IP.
router.delete('/ssh-authorize-ip', async (req, res, next) => {
  try {
    const userId = (req.session as any).userId as number;
    const { clientIp } = await import('../services/tfaTrust.service');
    const { db: kdb } = await import('../db');
    const { bastionGate } = await import('../services/sshBastion/bastionGate.service');
    const ip = bastionGate.normalize(clientIp(req));
    await kdb('ssh_bastion_ip_grants').where({ user_id: userId, ip }).delete();
    const { bastionAudit } = await import('../services/sshBastion/bastionUtil');
    bastionAudit('ip_authorization_revoked', { tenantId: (req as any).tenantId, userId, ip });
    res.status(204).send();
  } catch (err) { next(err); }
});

// Everything the user-facing UI needs: is the bastion on, where to connect,
// the host-key fingerprint to verify, and the SSH-button state for THIS IP.
router.get('/ssh-bastion', async (req, res, next) => {
  try {
    const userId = (req.session as any).userId as number;
    const { config } = await import('../config');
    const { clientIp } = await import('../services/tfaTrust.service');
    const { getHostKeyInfo, isBastionRunning } = await import('../services/sshBastion/sshBastion.service');
    const { bastionGate } = await import('../services/sshBastion/bastionGate.service');
    const ip = bastionGate.normalize(clientIp(req));
    const grant = ip
      ? await db('ssh_bastion_ip_grants')
          .where({ user_id: userId, ip })
          .andWhere('expires_at', '>', new Date())
          .first('expires_at')
      : null;
    // Same decision the bastion takes for this (user, IP) — the UI shows the truth.
    const gate = await bastionGate.evaluate(ip || undefined, userId);
    const { trustWindowMs } = await import('../services/tfaTrust.service');
    const grantHours = (await trustWindowMs((req as any).tenantId)) / 3_600_000;
    const user = await db('users').where({ id: userId }).first('totp_enabled', 'totp_secret', 'foreign_source', 'foreign_id');
    const has2fa = !!(user && ((user.totp_enabled && user.totp_secret) || (user.foreign_source === 'obligate' && user.foreign_id)));
    res.json({
      data: {
        enabled: config.sshBastion.enabled,
        running: isBastionRunning(),
        port: config.sshBastion.port,
        enforce: await bastionGate.isEnforce(),
        hostKey: getHostKeyInfo(),
        currentIp: ip || null,
        ipAuthorizedUntil: grant?.expires_at ?? null,
        gateVia: gate.allowed ? gate.via : null,
        ipRelayed: gate.infra,
        grantHours, // SSH-button duration (tenant "Trust this IP"); 0 = button disabled
        has2fa,
      },
    });
  } catch (err) { next(err); }
});

export default router;
