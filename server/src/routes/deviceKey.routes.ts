import { Router, type Request, type Response, type NextFunction } from 'express';
import { attachSessionTenant } from '../middleware/tenant';
import { db } from '../db';
import { deviceKeyService, ENROL_NO_TOTP_ERROR } from '../services/deviceKey/deviceKey.service';
import { isUuid } from '../services/deviceKey/payload';
import {
  checkSecondFactor, sendStepUpFailure, enrolLocked, recordEnrolFailure,
} from '../services/deviceKey/stepUpProof';
import type { DeviceKeyListResponse } from '@obligarth/shared';
import { config } from '../config';

// Device-bound 2FA — profile endpoints (docs/mobile/device-bound-2fa.md §6.5).
// Mounted in routes/index.ts as /api/profile/device-keys, requireAuth, BEFORE
// /profile. The list doubles as the capability probe of the app: an older
// server answers 404.
//
//   GET    /                    policy, allowed origins, bound key, eligibility, active keys
//   POST   /enrol/begin         {installId} + proofs stepUpPassword + twoFactorCode (NEW step);
//                               SSO account (lot O): a fresh Obligate re-authentication instead
//   POST   /enrol/finish        {ticketId, origin, publicKey, attestation[], signature, label, installId, appVersion}
//   DELETE /:id                 revoke one of the caller's keys — no step-up [D8b]
//   DELETE /                    revoke all the caller's keys — no step-up
//   POST   /:id/invalidated     the app reports its key invalidated (new biometric) [D10]
//
// Revoking only reduces access: no second factor (a stolen cookie can at
// worst revoke — a denial of service the owner sees in the list).

const router = Router();

// Not under the tenant router: the session tenant is req.tenantId (audit — P4).
router.use(attachSessionTenant);

const ENROL_ACTION_KEY = 'device_key.enrol';
const INSTALL_ID_RE = /^[\x21-\x7e]{1,64}$/;

type FactorRow = {
  id: number; role: string; foreign_source: string | null; foreign_id: number | null; totp_enabled: boolean; totp_secret_enc: string | null;
};

async function factorRow(userId: number): Promise<FactorRow | undefined> {
  return db('users').where({ id: userId })
    .first('id', 'role', 'foreign_source', 'foreign_id', 'totp_enabled', 'totp_secret_enc') as Promise<FactorRow | undefined>;
}

/** Lot O: a fresh Obligate re-authentication opens an SSO enrolment for 5 min (§4.10). */
const SSO_REAUTH_WINDOW_MS = 5 * 60 * 1000;

/** 401 of an SSO enrolment without a fresh re-authentication: the step-up
 *  shape (§4.8 → StepUpRequired) with `codeRequiresReauth` — the app opens
 *  /auth/sso-redirect?reauth=1, then calls enrol/begin again. */
const SSO_REAUTH_REQUIRED = Object.freeze({
  error: 'twoFactorCode required',
  twoFactorRequired: true,
  action: 'device_key.enrol',
  trustIpAllowed: false,
  codeRequiresReauth: true,
});

async function auditEnrolFailed(req: Request, userId: number, reason: string): Promise<void> {
  try {
    const { auditService } = await import('../services/audit.service');
    const { clientIp } = await import('../utils/clientIp');
    await auditService.log({
      tenantId: req.tenantId ?? req.session.currentTenantId ?? 1,
      userId, action: 'device_key.enrol_failed', resourceType: 'user', resourcePath: String(userId),
      details: { reason }, ipAddress: clientIp(req) || undefined,
    });
  } catch { /* audit never breaks the request */ }
}

/** Ends the caller's own session (its key was just revoked or invalidated):
 *  destroyed so the end of this response cannot save it back. */
function endSession(req: Request): Promise<void> {
  return new Promise((resolve) => req.session.destroy(() => resolve()));
}

// ── GET / ─────────────────────────────────────────────────────────────────

router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.session.userId!;
    const user = await factorRow(userId);
    if (!user) { res.status(401).json({ success: false, error: 'Authentication required' }); return; }
    const [policy, binding] = await Promise.all([deviceKeyService.getPolicy({ sso: true }), deviceKeyService.sessionBinding(req)]);
    const boundKeyId = binding.kind === 'bound' ? binding.key.id : null;
    const eligibility = await deviceKeyService.eligibilityOf(user, () => enrolLocked(userId));
    const data: DeviceKeyListResponse = {
      policy,
      allowedOrigins: deviceKeyService.allowedOrigins(),
      boundKeyId,
      eligibility,
      keys: await deviceKeyService.list(userId, boundKeyId),
    };
    // Lot O status for the Settings page (platform admins only). Same cache
    // as policy.ssoSupported; no I/O while DEVICE_KEYS_SSO_ENABLED is off.
    if (user.role === 'admin') {
      const { obligateService } = await import('../services/obligate.service');
      const { reason } = await obligateService.lotOStatus().catch(() => ({ reason: 'unreachable' as const }));
      data.ssoStatus = { switchOn: config.deviceKeys.ssoEnabled, state: reason };
    }
    res.json({ success: true, data });
  } catch (err) { next(err); }
});

// ── POST /enrol/begin ─────────────────────────────────────────────────────

router.post('/enrol/begin', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.session.userId!;
    const installId = (req.body as { installId?: unknown } | undefined)?.installId;
    // Shape first: a malformed request must not consume a code.
    if (typeof installId !== 'string' || !INSTALL_ID_RE.test(installId)) {
      res.status(400).json({ success: false, error: 'Validation', details: { installId: ['invalid'] } });
      return;
    }
    const user = await factorRow(userId);
    if (!user) { res.status(401).json({ success: false, error: 'Authentication required' }); return; }

    // 1–4. Policy on, origin configured, SSO refused without lot O, local account with TOTP.
    const pre = await deviceKeyService.enrolPreconditions(user);
    if (!pre.ok) { res.status(pre.status).json({ success: false, ...pre.body }); return; }

    // 5. Enrolment locked (3 failures / 24 h).
    if (await enrolLocked(userId)) {
      await auditEnrolFailed(req, userId, 'locked');
      res.status(403).json({ success: false, error: 'enrol_locked' });
      return;
    }

    // 6 (SSO account, lot O §4.10). Instead of password + code: a fresh
    //    Obligate re-authentication of this session (password + OTP forced by
    //    Obligate, amr 'otp', auth time after the request — checked by
    //    /auth/callback), less than 5 min old. Single use: one
    //    re-authentication opens one ticket. The Obligate MFA epoch read then
    //    must still be the current one (read uncached, fail closed); the
    //    ticket records it and the credential version of that moment.
    if (user.foreign_source != null) {
      const s = req.session;
      const at = Number(s.ssoReauthAt ?? 0);
      const epoch = s.ssoReauthEpoch;
      const cv = s.ssoReauthCv;
      const fresh = at > 0 && Date.now() - at <= SSO_REAUTH_WINDOW_MS
        && Number.isSafeInteger(epoch) && Number.isSafeInteger(cv);
      if (!fresh) { res.status(401).json({ ...SSO_REAUTH_REQUIRED }); return; }
      delete s.ssoReauthAt; delete s.ssoReauthEpoch; delete s.ssoReauthCv;
      const { obligateService } = await import('../services/obligate.service');
      const e = await obligateService.getMfaEpoch(Number(user.foreign_id), { fresh: true });
      if (!e) {
        res.status(503).json({ success: false, error: 'Two-factor verification is temporarily unavailable', verifierUnavailable: true });
        return;
      }
      if (!e.active || e.mfaEpoch !== epoch) {
        await auditEnrolFailed(req, userId, 'sso_mfa_changed');
        res.status(401).json({ ...SSO_REAUTH_REQUIRED });
        return;
      }
      const out = await deviceKeyService.beginEnrol(req, { userId, installId, credentialVersion: cv, ssoEpoch: e.mfaEpoch });
      if (!out.ok) { res.status(out.status).json({ success: false, ...out.body }); return; }
      res.json({ success: true, data: out.data });
      return;
    }

    // 6. Password + a STRICTLY new TOTP step (never the sign-in code), no
    //    trusted IP, never a device key — even outside a bound session. A
    //    failure counts for 'enrol' and for 'code' (§6.8).
    let failed = false;
    const step = await checkSecondFactor(req, {
      actionKey: ENROL_ACTION_KEY,
      allowTrustedIp: false,
      allowDevice: false,
      requireNewStep: true,
      requirePassword: true,
      noFactorError: ENROL_NO_TOTP_ERROR,
      onFailure: async () => {
        await recordEnrolFailure(req, userId);
        await auditEnrolFailed(req, userId, 'bad_password_or_code');
      },
    });
    // 401 twoFactorRequired (codeRequiresPassword, codeMustBeNew) when a
    // proof is missing, 401 'Invalid 2FA code' on a wrong one, 429 caps.
    if (!step.ok) { sendStepUpFailure(res, step); return; }

    // 7–9. Key cap, ticket (180 s) bound to this session and to the
    //      credential version the password + code were checked under, audit.
    const out = await deviceKeyService.beginEnrol(req, { userId, installId, credentialVersion: step.credentialVersion });
    if (!out.ok) { res.status(out.status).json({ success: false, ...out.body }); return; }
    res.json({ success: true, data: out.data });
  } catch (err) { next(err); }
});

// ── POST /enrol/finish ────────────────────────────────────────────────────

router.post('/enrol/finish', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const out = await deviceKeyService.finishEnrol(req, req.body);
    if (!out.ok) { res.status(out.status).json({ success: false, ...out.body }); return; }
    res.status(201).json({ success: true, data: out.data });
  } catch (err) { next(err); }
});

// ── DELETE / (all) and DELETE /:id ────────────────────────────────────────

router.delete('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.session.userId!;
    const current = req.session.deviceKeyId;
    const done = await deviceKeyService.revokeAllForUser(userId, 'user', { byUserId: userId, req });
    if (current && done.some((d) => d.id === current)) await endSession(req);
    res.status(204).send();
  } catch (err) { next(err); }
});

router.delete('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.session.userId!;
    const id = req.params.id;
    if (!isUuid(id)) { res.status(404).json({ success: false, error: 'Not found' }); return; }
    const current = req.session.deviceKeyId;
    const done = await deviceKeyService.revoke([id], 'user', { ownerId: userId, byUserId: userId, req });
    if (done.length === 0) { res.status(404).json({ success: false, error: 'Not found' }); return; }
    if (current === id) await endSession(req);
    res.status(204).send();
  } catch (err) { next(err); }
});

// ── POST /:id/invalidated ─────────────────────────────────────────────────
// The phone's key was invalidated (new biometric enrolled, screen lock
// removed): revoked ('invalidated'), every session bound to it killed, AND
// the caller's own session ended [D10] — the app signs in again with
// password + code. Idempotent for an already-revoked key of the caller.

router.post('/:id/invalidated', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.session.userId!;
    const id = req.params.id;
    const owned = isUuid(id)
      ? await db('user_device_keys').where({ id, user_id: userId }).first('id')
      : null;
    if (!owned) { res.status(404).json({ success: false, error: 'Not found' }); return; }
    await deviceKeyService.revoke([id], 'invalidated', { ownerId: userId, byUserId: userId, req });
    await endSession(req);
    res.clearCookie(config.sessionCookieName);
    res.status(204).send();
  } catch (err) { next(err); }
});

export default router;
