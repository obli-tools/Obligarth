import crypto from 'crypto';
import type { Request, Response } from 'express';
import { MASTER_TENANT_ID, DEVICE_KEY_HEADER, type DeviceChallenge } from '@obliance/shared';
import { isUuid } from './payload';
import { db } from '../../db';
import { twoFactorService } from '../twoFactor.service';
import { tfaTrustService } from '../tfaTrust.service';
import { clientAddress } from '../../utils/clientIp';
import { logger } from '../../utils/logger';

// ── checkSecondFactor: THE step-up verifier ────────────────────────────────
//
// docs/mobile/device-bound-2fa.md §6.2 (prerequisites P2/P3, §6.8 caps).
// Every second-factor check of a signed-in user goes through here:
//   - the restriction envelope, "sensitive" level (restriction.service.ts)
//     {allowTrustedIp:true, allowDevice:true}
//   - requireFreshTotp (sshBastion/stepUp.ts)  {allowTrustedIp:false}
//   - TOTP management (twoFactor.controller.ts) {allowTrustedIp:false,
//     requireNewStep:true}
// The sign-in 2FA (twoFactor.controller verify) is not a step-up: it uses
// verifyTotpStep + acceptTotpStep('strict') directly and the existing
// per-account limiter.
//
// Proofs are read from req.stepUpProof only (middleware/captureStepUpProof.ts,
// P5), never from req.body.
//
// Device keys (lot S2, §4.7, §6.2, §6.3): a session BOUND to an active key
// of its user (deviceKeyService.sessionBinding) ignores the trusted-IP
// shortcut and never grants it, refuses the code alone [D2] (password +
// code, `codeRequiresPassword`) while `device_keys_strict_session` is on,
// and accepts the key's assertion where the call site allows it
// (`allowDevice`). A session bound to a key that died is destroyed
// (401 `deviceKeyStatus:'revoked'`). Outside a bound session nothing changes.

export type StepUpVia = 'trusted_ip' | 'totp' | 'obligate_totp' | 'device_key' | 'password';

export type StepUpOpts = {
  /** Action key, echoed as `action` in the 401 (the clients display it). */
  actionKey: string;
  /** Devices the action targets (request binding of a device challenge, §4.5). */
  deviceIds?: number[];
  /** Honour and grant the "trust this IP" shortcut (never in a bound session). */
  allowTrustedIp: boolean;
  /** Accept a device-key assertion (bound session only, §6.6). */
  allowDevice: boolean;
  /** 'strict' TOTP step (never seen before, even in this session) instead of 'stepup'. */
  requireNewStep?: boolean;
  /** 403 text when the account has no second factor (each site keeps its current text). */
  noFactorError?: string;
  /** Local account: the current password is required WITH the code, even
   *  outside a bound session (device-key enrolment, §6.2 / §6.5 step 6). */
  requirePassword?: boolean;
  /** Called once per counted failure (wrong code or wrong password) — the
   *  enrolment counts its own 'enrol' failures (§6.8). Never throws out. */
  onFailure?: () => Promise<void>;
};

export type StepUpOutcome =
  | { ok: true; via: StepUpVia; credentialVersion?: number }
  | { ok: false; status: number; body: Record<string, unknown>; headers?: Record<string, string> };

/** The envelope's historical 403 text — the app recognises "enable TOTP". */
export const NO_FACTOR_ENVELOPE = 'This action is marked sensitive — enable TOTP 2FA on your profile before you can use it.';

/** 'stepup' mode: a step already used IN THE SAME SESSION stays reusable
 *  while it is at most this many steps behind the newest accepted one. */
export const STEPUP_REUSE_STEPS = 4;

/** Code-failure caps (§6.8, [D12]). */
export const CODE_WINDOW_MINUTES = 15;
export const CODE_WINDOW_MAX = 10;   // failures per 15 min → 429 + Retry-After
export const CODE_DAY_MAX = 30;      // failures per 24 h → code locked until a full sign-in
export const CODE_NOTIFY_AT = 5;     // e-mail on the 5th failure in 24 h (once per 24 h)

/** sha256 of the session id — the only form ever stored. A missing id gets
 *  a random value so it can never match another session. */
export function hashSessionId(sessionId: string | undefined | null): string {
  const sid = sessionId ? String(sessionId) : crypto.randomBytes(16).toString('hex');
  return crypto.createHash('sha256').update(sid).digest('hex');
}

// ── TOTP anti-replay (migration 127) ────────────────────────────────────────

/**
 * Atomically accepts TOTP `step` for the user, or refuses it (replay).
 *  - strict (sign-in, TOTP management, enrolment): step > totp_last_step.
 *  - stepup (envelope, requireFreshTotp): step > totp_last_step, OR same
 *    session and step >= totp_last_step - STEPUP_REUSE_STEPS (a code typed
 *    once serves a loop of requests of that session, never another one).
 * totp_last_step never goes backwards.
 */
export async function acceptTotpStep(
  userId: number,
  step: number,
  sessionHash: string,
  mode: 'strict' | 'stepup',
): Promise<boolean> {
  if (!Number.isSafeInteger(step) || step <= 0) return false;
  if (mode === 'strict') {
    const r = await db.raw(
      `UPDATE users SET totp_last_step = ?, totp_last_session = ?
        WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)
        RETURNING id`,
      [step, sessionHash, userId, step],
    ) as { rows: unknown[] };
    return r.rows.length > 0;
  }
  const r = await db.raw(
    `UPDATE users
        SET totp_last_session = CASE WHEN totp_last_step IS NULL OR totp_last_step < ? THEN ? ELSE totp_last_session END,
            totp_last_step    = GREATEST(COALESCE(totp_last_step, ?), ?)
      WHERE id = ?
        AND (totp_last_step IS NULL OR totp_last_step < ?
             OR (totp_last_session = ? AND ? >= totp_last_step - ?))
      RETURNING id`,
    [step, sessionHash, step, step, userId, step, sessionHash, step, STEPUP_REUSE_STEPS],
  ) as { rows: unknown[] };
  return r.rows.length > 0;
}

/** Sign-in: the step was accepted against the pre-login session, then the
 *  session id was regenerated — point the step at the NEW session so the
 *  sign-in code stays reusable for a step-up in it (never for a strict use). */
export async function rebindTotpStepSession(userId: number, step: number, fromHash: string, toHash: string): Promise<void> {
  await db('users')
    .where({ id: userId, totp_last_step: step, totp_last_session: fromHash })
    .update({ totp_last_session: toHash });
}

// ── Code-failure caps (step_up_throttle, kind 'code') ───────────────────────

type Reservation = { ok: true } | { ok: false; locked: boolean; retryAfterSec?: number };

/**
 * Reserves one attempt BEFORE the code is checked (one atomic upsert), so
 * parallel requests cannot exceed the caps; settleCodeAttempt() gives the
 * slot back on success (and on an unavailable verification).
 */
export async function reserveCodeAttempt(userId: number): Promise<Reservation> {
  const r = await db.raw(
    `INSERT INTO step_up_throttle AS t (user_id, kind, window_start, window_failures, day_start, day_failures)
     VALUES (?, 'code', now(), 1, now(), 1)
     ON CONFLICT (user_id, kind) DO UPDATE SET
       window_start    = CASE WHEN t.window_start IS NULL OR t.window_start <= now() - interval '${CODE_WINDOW_MINUTES} minutes'
                              THEN now() ELSE t.window_start END,
       window_failures = CASE WHEN t.window_start IS NULL OR t.window_start <= now() - interval '${CODE_WINDOW_MINUTES} minutes'
                              THEN 1 ELSE t.window_failures + 1 END,
       day_start       = CASE WHEN t.day_start IS NULL OR t.day_start <= now() - interval '24 hours'
                              THEN now() ELSE t.day_start END,
       day_failures    = CASE WHEN t.day_start IS NULL OR t.day_start <= now() - interval '24 hours'
                              THEN 1 ELSE t.day_failures + 1 END
     WHERE NOT t.locked
       AND (t.window_start IS NULL OR t.window_start <= now() - interval '${CODE_WINDOW_MINUTES} minutes' OR t.window_failures < ?)
       AND (t.day_start IS NULL OR t.day_start <= now() - interval '24 hours' OR t.day_failures < ?)
     RETURNING window_failures`,
    [userId, CODE_WINDOW_MAX, CODE_DAY_MAX],
  ) as { rows: unknown[] };
  if (r.rows.length > 0) return { ok: true };

  const peek = await peekCodeThrottle(userId);
  if (peek.locked) return { ok: false, locked: true };
  return { ok: false, locked: false, retryAfterSec: peek.retryAfterSec ?? 60 };
}

/**
 * Current state of the code caps, without counting anything: locked (30 / 24 h,
 * until a full sign-in or an admin MFA reset), or the 15-min window full
 * (retry after N s), or open.
 */
export async function peekCodeThrottle(userId: number): Promise<{ locked: boolean; retryAfterSec?: number }> {
  const s = await db.raw(
    `SELECT locked,
            (day_start > now() - interval '24 hours' AND day_failures >= ?) AS day_full,
            (window_start > now() - interval '${CODE_WINDOW_MINUTES} minutes' AND window_failures >= ?) AS window_full,
            GREATEST(1, CEIL(EXTRACT(EPOCH FROM (window_start + interval '${CODE_WINDOW_MINUTES} minutes' - now()))))::int AS retry_after
       FROM step_up_throttle WHERE user_id = ? AND kind = 'code'`,
    [CODE_DAY_MAX, CODE_WINDOW_MAX, userId],
  ) as { rows: Array<{ locked: boolean; day_full: boolean; window_full: boolean; retry_after: number | null }> };
  const row = s.rows[0];
  if (!row) return { locked: false };
  if (row.locked || row.day_full) return { locked: true };
  if (row.window_full) return { locked: false, retryAfterSec: Math.max(1, Number(row.retry_after) || 60) };
  return { locked: false };
}

/** 429 bodies of the code caps (§6.8). */
export function throttledOutcome(t: { locked: boolean; retryAfterSec?: number }): StepUpOutcome {
  if (t.locked) {
    return { ok: false, status: 429, body: { error: 'Too many verification attempts', codeLocked: true } };
  }
  return {
    ok: false, status: 429,
    body: { error: 'Too many verification attempts' },
    headers: { 'Retry-After': String(t.retryAfterSec ?? 60) },
  };
}

function auditTenantId(req: Request): number {
  const t = Number((req as any).tenantId ?? (req.session as any)?.currentTenantId ?? MASTER_TENANT_ID);
  return Number.isInteger(t) && t > 0 ? t : MASTER_TENANT_ID;
}

async function audit(req: Request, userId: number, action: string, details: Record<string, unknown>): Promise<void> {
  try {
    const { auditService } = await import('../audit.service');
    await auditService.log({
      tenantId: auditTenantId(req),
      userId,
      action,
      resourceType: 'user',
      resourcePath: String(userId),
      details,
      ipAddress: clientAddress(req).ip || undefined,
    });
  } catch { /* audit never breaks the request */ }
}

/**
 * Settles a reserved attempt.
 *  success → the 15-min window is reset (not the 24-h count: the slot is given back)
 *  void    → verification could not run (Obligate down), or a CORRECT code
 *            already used by another session / strictly consumed (replay
 *            guard): slot given back, nothing counted — a valid code tells an
 *            attacker nothing, counting it would only lock legitimate users
 *  failure → counted; audit auth.step_up_failed; lock at CODE_DAY_MAX (audit
 *            auth.step_up_locked); e-mail from the CODE_NOTIFY_AT-th failure,
 *            once per 24 h.
 */
export async function settleCodeAttempt(
  req: Request,
  userId: number,
  outcome: 'success' | 'failure' | 'void',
  ctx: { action: string; via: 'totp' | 'obligate_totp' | 'password'; email?: string | null },
): Promise<void> {
  const q = () => db('step_up_throttle').where({ user_id: userId, kind: 'code' });
  if (outcome === 'success') {
    await q().update({
      window_failures: 0,
      window_start: null,
      day_failures: db.raw('GREATEST(day_failures - 1, 0)'),
    });
    return;
  }
  if (outcome === 'void') {
    await q().update({
      window_failures: db.raw('GREATEST(window_failures - 1, 0)'),
      day_failures: db.raw('GREATEST(day_failures - 1, 0)'),
    });
    return;
  }

  const row = await q().first('window_failures', 'day_failures') as { window_failures: number; day_failures: number } | undefined;
  const windowFailures = Number(row?.window_failures ?? 0);
  const dayFailures = Number(row?.day_failures ?? 0);
  await audit(req, userId, 'auth.step_up_failed', { action: ctx.action, via: ctx.via, windowFailures, dayFailures });

  if (dayFailures >= CODE_DAY_MAX) {
    const locked = await db.raw(
      `UPDATE step_up_throttle SET locked = true
        WHERE user_id = ? AND kind = 'code' AND NOT locked AND day_failures >= ?
        RETURNING user_id`,
      [userId, CODE_DAY_MAX],
    ) as { rows: unknown[] };
    if (locked.rows.length > 0) {
      await audit(req, userId, 'auth.step_up_locked', { kind: 'code', dayFailures });
      logger.warn({ userId }, 'step-up code entry locked (too many wrong codes in 24 h)');
    }
  }

  if (dayFailures >= CODE_NOTIFY_AT && ctx.email) {
    const claim = await db.raw(
      `UPDATE step_up_throttle SET notified_at = now()
        WHERE user_id = ? AND kind = 'code'
          AND (notified_at IS NULL OR notified_at <= now() - interval '24 hours')
        RETURNING user_id`,
      [userId],
    ) as { rows: unknown[] };
    if (claim.rows.length > 0) {
      const to = ctx.email;
      void (async () => {
        try {
          const { appConfigService } = await import('../appConfig.service');
          const cfg = await appConfigService.getAll();
          if (!cfg.otp_smtp_server_id) return;
          await twoFactorService.sendStepUpFailureNotice(Number(cfg.otp_smtp_server_id), to, dayFailures);
        } catch (err) {
          logger.warn({ err, userId }, 'step-up failure notice not sent');
        }
      })();
    }
  }
}

/** Full sign-in (password + 2FA, or Obligate SSO) or admin MFA reset: the
 *  code lock and both windows are cleared. notified_at is kept. */
export async function clearCodeThrottle(userId: number): Promise<void> {
  await db('step_up_throttle').where({ user_id: userId, kind: 'code' }).update({
    locked: false,
    window_failures: 0,
    window_start: null,
    day_failures: 0,
    day_start: null,
  });
}

// ── Enrolment failures (step_up_throttle, kind 'enrol') ─────────────────────

/** §6.8 [D12]: 3 failed enrolments (wrong password or code) in 24 h lock
 *  enrolment for 24 h (403 enrol_locked). Independent of the code caps. */
export const ENROL_DAY_MAX = 3;
export const ENROL_LOCK_HOURS = 24;

/** True while the account's enrolment is locked (§6.5 enrol/begin step 5). */
export async function enrolLocked(userId: number): Promise<boolean> {
  const r = await db.raw(
    `SELECT (locked_until IS NOT NULL AND locked_until > now()) AS locked
       FROM step_up_throttle WHERE user_id = ? AND kind = 'enrol'`,
    [userId],
  ) as { rows: Array<{ locked: boolean }> };
  return r.rows[0]?.locked === true;
}

/** Counts one failed enrolment; the 3rd in 24 h locks enrolment for 24 h
 *  (audit auth.step_up_locked {kind:'enrol'}). */
export async function recordEnrolFailure(req: Request, userId: number): Promise<void> {
  const r = await db.raw(
    `INSERT INTO step_up_throttle AS t (user_id, kind, day_start, day_failures)
     VALUES (?, 'enrol', now(), 1)
     ON CONFLICT (user_id, kind) DO UPDATE SET
       day_start    = CASE WHEN t.day_start IS NULL OR t.day_start <= now() - interval '24 hours'
                           THEN now() ELSE t.day_start END,
       day_failures = CASE WHEN t.day_start IS NULL OR t.day_start <= now() - interval '24 hours'
                           THEN 1 ELSE t.day_failures + 1 END
     RETURNING day_failures`,
    [userId],
  ) as { rows: Array<{ day_failures: number }> };
  const n = Number(r.rows[0]?.day_failures ?? 0);
  if (n < ENROL_DAY_MAX) return;
  const locked = await db.raw(
    `UPDATE step_up_throttle
        SET locked_until = now() + interval '${ENROL_LOCK_HOURS} hours', day_failures = 0, day_start = NULL
      WHERE user_id = ? AND kind = 'enrol' AND (locked_until IS NULL OR locked_until <= now())
      RETURNING user_id`,
    [userId],
  ) as { rows: unknown[] };
  if (locked.rows.length > 0) {
    await audit(req, userId, 'auth.step_up_locked', { kind: 'enrol', dayFailures: n });
    logger.warn({ userId }, 'device-key enrolment locked for 24 h (too many failures)');
  }
}

/**
 * [D11] diagnostic, for a local TOTP code refused at ±1 step: when it
 * matches at ±2 steps (the ±60 s window used before), the phone's or the
 * server's clock is 31–60 s off. Logged and audited (auth.totp_drift) so the
 * owner sees a drift at once instead of "Invalid code". Never accepts.
 */
export async function reportTotpDrift(req: Request, userId: number, secret: string, code: string, context: string): Promise<void> {
  const drift = twoFactorService.totpDriftSteps(secret, code);
  if (drift === null) return;
  logger.warn({ userId, driftSteps: drift, context }, 'TOTP code off by more than 30 s (clock drift?) — refused');
  await audit(req, userId, 'auth.totp_drift', { driftSteps: drift, driftSeconds: drift * 30, context });
}

/**
 * Current-password proof, for managing the second factors of an account
 * that has NO code to give (no local TOTP, not an Obligate account): first
 * TOTP enrolment, e-mail codes. Read from req.stepUpProof.stepUpPassword
 * (P5). Wrong passwords count in the same caps as wrong codes (§6.8).
 *  - no password sent → 401 {passwordRequired:true, action}
 *  - wrong password   → 401 {error:'Invalid password', passwordInvalid:true}
 */
export async function checkPasswordStepUp(req: Request, o: { actionKey: string }): Promise<StepUpOutcome> {
  const userId = (req.session as any)?.userId as number | undefined;
  if (!userId) return { ok: false, status: 401, body: { error: 'Unauthenticated' } };
  const user = await db('users').where({ id: userId }).first('is_active', 'password_hash', 'email') as
    { is_active: boolean; password_hash: string | null; email: string | null } | undefined;
  if (!user || !user.is_active) {
    await destroySession(req);
    return { ok: false, status: 401, body: { error: 'Unauthenticated' } };
  }
  if (!user.password_hash) {
    return { ok: false, status: 403, body: { error: 'No password on this account to confirm the change. Ask an administrator.' } };
  }
  const password = req.stepUpProof?.stepUpPassword;
  if (!password) {
    const throttle = await peekCodeThrottle(userId);
    if (throttle.locked || throttle.retryAfterSec) return throttledOutcome(throttle);
    return { ok: false, status: 401, body: { error: 'Current password required', passwordRequired: true, action: o.actionKey } };
  }
  const slot = await reserveCodeAttempt(userId);
  if (!slot.ok) return throttledOutcome(slot);
  let valid = false;
  try {
    const { comparePassword } = await import('../../utils/crypto');
    valid = await comparePassword(password, user.password_hash);
  } catch (err) {
    await settleCodeAttempt(req, userId, 'void', { action: o.actionKey, via: 'password' }).catch(() => {});
    throw err;
  }
  if (!valid) {
    await settleCodeAttempt(req, userId, 'failure', { action: o.actionKey, via: 'password', email: user.email });
    return { ok: false, status: 401, body: { error: 'Invalid password', passwordInvalid: true } };
  }
  await settleCodeAttempt(req, userId, 'success', { action: o.actionKey, via: 'password' });
  return { ok: true, via: 'password' };
}

function destroySession(req: Request): Promise<void> {
  return new Promise((resolve) => {
    if (!req.session) { resolve(); return; }
    req.session.destroy(() => resolve());
  });
}

// ── Obligate codes (SSO accounts) ───────────────────────────────────────────

function ssoCodeHash(req: Request, userId: number, code: string): string {
  return crypto.createHash('sha256').update(`obli-sso-stepup\n${req.sessionID ?? ''}\n${userId}\n${code}`).digest('hex');
}

/**
 * The code of an SSO account, checked by Obligate. Before lot O: as always
 * (no replay guard at Obligate). With lot O (capabilities announced):
 * `consume:true`, so Obligate refuses a step already used anywhere (its own
 * sign-in included, R3) — a replay answers 'used' (not counted). To keep the
 * local 'stepup' semantics (design §7.7: a code typed once serves the next
 * requests of THIS session, e.g. a per-device loop), a code accepted this way
 * is remembered in the session (hash only) until the end of its ±1-step
 * validity; a strict use (requireNewStep) always goes to Obligate.
 */
async function checkObligateCode(
  req: Request, userId: number, foreignId: number, code: string, strict: boolean,
  deviceKeysEnabled: boolean,
): Promise<'valid' | 'invalid' | 'used' | 'unavailable'> {
  const { obligateService } = await import('../obligate.service');
  // The consuming verify-totp is part of lot O: only with the Obliance
  // opt-in (checked first by lotOSupported, no I/O while off) AND the
  // feature on (DEVICE_KEYS_DISABLED / device_keys_enabled=false restore
  // the historical call too).
  if (!deviceKeysEnabled || !(await obligateService.lotOSupported())) {
    return obligateService.verifyTotpDetailed(foreignId, code);
  }
  const hash = ssoCodeHash(req, userId, code);
  const memo = req.session?.ssoStepUpCode;
  if (!strict && memo && memo.userId === userId && memo.hash === hash && Date.now() < memo.until) return 'valid';
  const r = await obligateService.checkTotp(foreignId, code, { consume: true });
  if (r.result === 'replayed') return 'used';
  if (r.result === 'valid' && r.step !== null && req.session) {
    // End of the code's validity at Obligate (±1 step, D11), never beyond
    // 90 s from now whatever Obligate's clock says.
    req.session.ssoStepUpCode = { hash, userId, until: Math.min((r.step + 2) * 30_000, Date.now() + 90_000) };
  }
  return r.result;
}

// ── The verifier ────────────────────────────────────────────────────────────

/** 401 of a session bound to a key that is no longer usable (J4). The
 *  caller's session was destroyed. */
export const DEVICE_KEY_REVOKED_BODY = Object.freeze({
  success: false, error: 'Authentication required', deviceKeyStatus: 'revoked',
});

/** Fresh Obligate re-authentication window of a bound SSO session (lot O). */
const SSO_REAUTH_WINDOW_MS = 5 * 60 * 1000;

export async function checkSecondFactor(req: Request, o: StepUpOpts): Promise<StepUpOutcome> {
  // 1. User: present and active, else the session dies.
  const userId = (req.session as any)?.userId as number | undefined;
  if (!userId) return { ok: false, status: 401, body: { error: 'Unauthenticated' } };
  const user = await db('users')
    .where({ id: userId })
    .first('id', 'is_active', 'totp_enabled', 'totp_secret', 'foreign_source', 'foreign_id', 'email',
      'password_hash', 'credential_version') as {
      id: number; is_active: boolean; totp_enabled: boolean; totp_secret: string | null;
      foreign_source: string | null; foreign_id: number | null; email: string | null;
      password_hash: string | null; credential_version: number | null;
    } | undefined;
  if (!user || !user.is_active) {
    await destroySession(req);
    return { ok: false, status: 401, body: { error: 'Unauthenticated' } };
  }
  const credentialVersion = user.credential_version == null ? undefined : Number(user.credential_version);

  // 2. A factor must exist: local TOTP, or the Obligate account (SSO).
  const hasLocalTotp = !!(user.totp_enabled && user.totp_secret);
  const isObligateSso = user.foreign_source === 'obligate' && !!user.foreign_id;
  if (!hasLocalTotp && !isObligateSso) {
    return { ok: false, status: 403, body: { error: o.noFactorError ?? NO_FACTOR_ENVELOPE } };
  }

  // 3. Device-bound session (§4.7). A session bound to a key that died
  //    (revoked, credentials changed, other user, unverified under required
  //    attestation) is destroyed: never treated as unbound, which would
  //    reopen the trusted-IP shortcut and the code alone on that phone.
  const dk = await import('./deviceKey.service');
  const policy = await dk.getPolicy();
  const binding = await dk.sessionBinding(req);
  if (binding.kind === 'revoked') {
    await destroySession(req);
    return { ok: false, status: 401, body: { ...DEVICE_KEY_REVOKED_BODY } };
  }
  const bound = binding.kind === 'bound' ? binding.key : null;
  // [D2] strict session: the code alone is refused; its fallback is the
  // password (local account) or a fresh Obligate re-authentication (SSO, lot O).
  const isSsoAccount = user.foreign_source === 'obligate';
  const strict = !!bound && policy.strictSession;
  const needPassword = !isSsoAccount && (strict || o.requirePassword === true);
  // Lot O state, read only for an SSO account in a bound session (no I/O
  // while the Obliance switch is off; cached otherwise). When lot O is
  // EXPLICITLY off (the switch, Obligate SSO off, or Obligate no longer
  // announcing the capabilities), the phone's SSO key cannot be used
  // (verifyAssertion: 'disabled') and no re-authentication can be started
  // (sso-redirect?reauth=1: 'unsupported'): the code alone goes back to the
  // historical Obligate check instead of a dead end — never weaker than an
  // unbound SSO session, and the trusted IP stays ignored (bound). 'unknown'
  // (Obligate unreadable) changes nothing: fail closed.
  let ssoLotOOff = false;
  if (isSsoAccount && bound) {
    const { obligateService } = await import('../obligate.service');
    ssoLotOOff = (await obligateService.lotOState().catch(() => 'unknown' as const)) === 'off';
  }
  // A fresh re-authentication (< 5 min) of THIS session makes the code alone
  // acceptable again (§4.7): `codeRequiresReauth` only while it is missing.
  const reauthAt = Number(req.session?.ssoReauthAt ?? 0);
  const needReauth = isSsoAccount && strict && !ssoLotOOff
    && !(reauthAt > 0 && Date.now() - reauthAt <= SSO_REAUTH_WINDOW_MS);
  // `deviceKeyStatus` is reported only to a bound session, or to a request
  // naming a key while the feature is off (§4.8); an unknown key or another
  // user's key gets no information at all.
  const headerKey = req.get?.(DEVICE_KEY_HEADER);
  const deviceContext = !!bound || (!policy.enabled && (!!req.session?.deviceKeyId || isUuid(headerKey)));

  // 4. Trusted-IP shortcut. A relay address (our proxy, Docker gateway, an
  //    edge proxy missing from TRUSTED_PROXIES) is shared by everyone behind
  //    it: never honoured nor granted. Ignored in a bound session (R2).
  const { ip, relay } = clientAddress(req);
  const trustUsable = o.allowTrustedIp && !bound && !relay;
  if (trustUsable && await tfaTrustService.isTrusted(userId, ip)) {
    return { ok: true, via: 'trusted_ip', credentialVersion };
  }

  const proof = req.stepUpProof ?? {};

  /** The 401 the clients handle (prompt, then the same body again with a
   *  proof). Extra fields are optional (§4.8). */
  const prompt = async (extra: {
    deviceError?: 'invalid_assertion' | 'challenge_expired';
    /** 'issue': a new challenge when allowed; a challenge already issued; null: none. */
    challenge?: 'issue' | DeviceChallenge | null;
    status?: 'active' | 'disabled' | 'throttled';
    codeLocked?: boolean;
  } = {}): Promise<StepUpOutcome> => {
    const body: Record<string, unknown> = {
      error: 'twoFactorCode required',
      twoFactorRequired: true,
      action: o.actionKey,
      currentIp: ip,
      trustIpAllowed: trustUsable,
    };
    // A strict use needs a code never seen before (not the sign-in code):
    // lets the web prompt say "wait for the next code".
    if (o.requireNewStep && hasLocalTotp) body.codeMustBeNew = true;
    if (needPassword) body.codeRequiresPassword = true;
    if (needReauth) body.codeRequiresReauth = true;
    if (deviceContext) {
      // An SSO key while lot O is off: 'disabled' (J5), no challenge — the
      // app goes straight to the code instead of a fingerprint bound to fail.
      let status: 'active' | 'disabled' | 'throttled' = extra.status
        ?? (!bound || ssoLotOOff ? 'disabled' : dk.assertionThrottled(req) ? 'throttled' : 'active');
      let challenge: DeviceChallenge | null = null;
      if (status === 'active' && bound && o.allowDevice) {
        const want = extra.challenge === undefined ? 'issue' : extra.challenge;
        challenge = want === 'issue'
          ? await dk.issueStepUpChallenge(req, { actionKey: o.actionKey, deviceIds: o.deviceIds, key: bound, bulkId: proof.deviceBulkId })
          : want;
        // Issuance capped (§6.8): no challenge this time — password + code.
        if (want === 'issue' && !challenge) status = 'throttled';
      }
      body.deviceKeyStatus = status;
      if (challenge) body.deviceChallenge = challenge;
      if (extra.deviceError) body.deviceError = extra.deviceError;
    }
    if (extra.codeLocked) body.codeLocked = true;
    return { ok: false, status: 401, body };
  };

  // 5. A code was sent: only the code is evaluated (a device assertion sent
  //    alongside is ignored — R7).
  const code = typeof proof.twoFactorCode === 'string' ? proof.twoFactorCode.trim() : '';
  if (code) {
    const slot = await reserveCodeAttempt(userId);
    if (!slot.ok) return throttledOutcome(slot);

    // Bound session, strict [D2]: the code alone is refused (not counted)
    // until the session re-authenticated with Obligate (SSO, lot O).
    if (needReauth) {
      await settleCodeAttempt(req, userId, 'void', { action: o.actionKey, via: 'obligate_totp' });
      return prompt();
    }
    const password = typeof proof.stepUpPassword === 'string' ? proof.stepUpPassword : '';
    if (needPassword) {
      if (!password) {
        await settleCodeAttempt(req, userId, 'void', { action: o.actionKey, via: 'totp' });
        return prompt();
      }
      let passwordOk = false;
      try {
        const { comparePassword } = await import('../../utils/crypto');
        passwordOk = !!user.password_hash && await comparePassword(password, user.password_hash);
      } catch (err) {
        await settleCodeAttempt(req, userId, 'void', { action: o.actionKey, via: 'password' }).catch(() => {});
        throw err;
      }
      if (!passwordOk) {
        // Same answer as a wrong code: nothing tells which one was wrong.
        await settleCodeAttempt(req, userId, 'failure', { action: o.actionKey, via: 'password', email: user.email });
        await o.onFailure?.().catch(() => {});
        return { ok: false, status: 401, body: { error: 'Invalid 2FA code' } };
      }
    }

    const via: 'totp' | 'obligate_totp' = hasLocalTotp ? 'totp' : 'obligate_totp';
    // 'used': the code is right but its step was already consumed (another
    // session's sign-in or step-up, or a strict use) — the replay guard.
    let result: 'valid' | 'invalid' | 'used' | 'unavailable';
    try {
      if (hasLocalTotp) {
        const step = twoFactorService.verifyTotpStep(user.totp_secret!, code);
        if (step === null) {
          result = 'invalid';
          await reportTotpDrift(req, userId, user.totp_secret!, code, o.actionKey);
        } else {
          result = await acceptTotpStep(userId, step, hashSessionId(req.sessionID), o.requireNewStep ? 'strict' : 'stepup')
            ? 'valid' : 'used';
        }
      } else {
        result = await checkObligateCode(req, userId, Number(user.foreign_id), code, !!o.requireNewStep, policy.enabled);
      }
    } catch (err) {
      await settleCodeAttempt(req, userId, 'void', { action: o.actionKey, via }).catch(() => {});
      throw err;
    }

    if (result === 'unavailable') {
      // Obligate unreachable / refusing: not the user's fault, not counted,
      // and not "Invalid code" (which would make them retype a good code).
      await settleCodeAttempt(req, userId, 'void', { action: o.actionKey, via });
      return {
        ok: false, status: 503,
        body: { error: 'Two-factor verification is temporarily unavailable', verifierUnavailable: true },
      };
    }
    if (result === 'used') {
      await settleCodeAttempt(req, userId, 'void', { action: o.actionKey, via });
      // Same error text as a wrong code for older clients; codeUsed tells
      // newer ones to wait for the next code.
      return { ok: false, status: 401, body: { error: 'Invalid 2FA code', codeUsed: true } };
    }
    if (result !== 'valid') {
      await settleCodeAttempt(req, userId, 'failure', { action: o.actionKey, via, email: user.email });
      await o.onFailure?.().catch(() => {});
      return { ok: false, status: 401, body: { error: 'Invalid 2FA code' } };
    }

    await settleCodeAttempt(req, userId, 'success', { action: o.actionKey, via });
    // IP trust is granted ONLY on an explicit opt-in, never to a bound
    // session; the duration comes from the tenant's "Trust this IP" setting
    // (0 disables it).
    if (trustUsable && proof.trustIp === true) {
      const tenantId = (req as any).tenantId ?? (req.session as any)?.currentTenantId;
      await tfaTrustService.grant(userId, ip, tenantId);
    }
    return { ok: true, via, credentialVersion };
  }

  // 6. Device assertion: only where the site accepts it, only in a session
  //    bound to that very key (§6.3). Outside a bound session it is ignored
  //    (the prompt below), except that a request naming a key while the
  //    feature is off learns `disabled` (J5): the code alone is accepted.
  if (o.allowDevice && proof.deviceAssertion !== undefined && proof.deviceAssertion !== null) {
    if (bound) {
      const r = await dk.verifyAssertion(req, {
        purpose: 'stepup', actionKey: o.actionKey, deviceIds: o.deviceIds, key: bound,
      });
      if (r.ok) return { ok: true, via: 'device_key', credentialVersion };
      switch (r.error) {
        case 'malformed':
          return {
            ok: false, status: 400,
            body: { success: false, error: 'Validation', details: { deviceAssertion: ['malformed'] } },
          };
        case 'revoked':
          await destroySession(req);
          return { ok: false, status: 401, body: { ...DEVICE_KEY_REVOKED_BODY } };
        case 'invalid_assertion':
          return prompt({ deviceError: 'invalid_assertion', challenge: null });
        case 'challenge_expired':
          // The renewed challenge (J2); none when issuance is capped → throttled.
          return r.challenge
            ? prompt({ deviceError: 'challenge_expired', challenge: r.challenge })
            : prompt({ deviceError: 'challenge_expired', challenge: null, status: 'throttled' });
        case 'throttled':
          return prompt({ status: 'throttled' });
        case 'disabled':
          return prompt({ status: 'disabled' });
      }
    }
  }

  // 7. No usable proof. Code entry locked (or the 15-min window full): say
  //    so now instead of prompting for a code that would be refused anyway —
  //    unless a bound session can still use its key (code failures never
  //    block the fingerprint, §6.8): then the prompt carries the challenge
  //    and `codeLocked` for the fallback's message.
  const throttle = await peekCodeThrottle(userId);
  if (throttle.locked || throttle.retryAfterSec) {
    if (bound && o.allowDevice && !dk.assertionThrottled(req)) {
      const out = await prompt({ codeLocked: throttle.locked });
      if (!out.ok && out.body.deviceChallenge) return out;
    }
    return throttledOutcome(throttle);
  }
  return prompt();
}

/** Writes a failed StepUpOutcome (status, optional headers, JSON body). */
export function sendStepUpFailure(
  res: Response,
  outcome: { status: number; body: Record<string, unknown>; headers?: Record<string, string> },
): void {
  for (const [k, v] of Object.entries(outcome.headers ?? {})) res.setHeader(k, v);
  res.status(outcome.status).json(outcome.body);
}
