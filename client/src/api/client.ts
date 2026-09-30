import axios from 'axios';
import type { DeviceAssertion, DeviceChallenge, SignDeviceChallengeResult } from '@obliance/shared';
import { awaitTwoFactorCode, isTwoFactorCancelled, TWO_FACTOR_CANCELLED } from '@/utils/twoFactorGate';
import { canUseNative, native } from '@/native/bridge';

// ObliTools (cross-site iframe / WebView2 shell): Chrome blocks all cookies for cross-site
// iframes, so we use X-Auth-Token header instead. The token = req.sessionID, stored in
// sessionStorage after login and sent on every request via the interceptor below.
export const isInObliTools = (() => {
  try { return window !== window.top; } catch { return true; }
})() || !!(window as unknown as { __obliview_is_native_app?: boolean }).__obliview_is_native_app;

export const OBLITOOLS_TOKEN_KEY = 'oblitools_auth_token';

const apiClient = axios.create({
  baseURL: '/api',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: inject X-Auth-Token header when running inside ObliTools.
apiClient.interceptors.request.use((config) => {
  if (isInObliTools) {
    const token = sessionStorage.getItem(OBLITOOLS_TOKEN_KEY);
    if (token) {
      config.headers['X-Auth-Token'] = token;
    }
  }
  return config;
});

// Response interceptor.
//
// Two roles:
//  1. 401 session expired        → redirect to /login (or clear ObliTools token).
//  2. 401 { twoFactorRequired }  → a restriction marked this action "sensitive".
//     Pop the TwoFactorGate modal, await the user's code, retry the original
//     request once with `twoFactorCode` injected into the JSON body. If the
//     retry fails (bad code), the error bubbles to the caller normally.
//
// The retry is guarded by `config._tfaRetried` so a bad code response
// doesn't loop back into the gate — the user sees a plain "Invalid 2FA
// code" error and can re-trigger the action from the UI.

/** Replays a request once with extra JSON body fields (the step-up proof). */
function retryWithProof(config: any, proof: Record<string, unknown>) {
  let payload: Record<string, unknown> = {};
  if (typeof config.data === 'string') {
    try { payload = JSON.parse(config.data) as Record<string, unknown>; } catch { payload = {}; }
  } else if (config.data && typeof config.data === 'object') {
    payload = { ...(config.data as object) };
  }
  Object.assign(payload, proof);
  config._tfaRetried = true;
  config.data = JSON.stringify(payload);
  if (!config.headers) config.headers = {};
  config.headers['Content-Type'] = 'application/json';
  return apiClient(config);
}

/** Proof fields of a previous attempt, removed before each resend (R7: a
 *  code never travels with a stale assertion and vice versa). The bulk id
 *  (deviceBulkId) is kept. */
const PROOF_FIELDS = ['twoFactorCode', 'trustIp', 'stepUpPassword', 'deviceAssertion'] as const;

function bodyWithoutProofs(config: any): Record<string, unknown> {
  let payload: Record<string, unknown> = {};
  if (typeof config.data === 'string') {
    try { payload = JSON.parse(config.data) as Record<string, unknown>; } catch { payload = {}; }
  } else if (config.data && typeof config.data === 'object') {
    payload = { ...(config.data as object) } as Record<string, unknown>;
  }
  for (const k of PROOF_FIELDS) delete payload[k];
  return payload;
}

/**
 * The step-up of a 401 `twoFactorRequired` (docs/mobile/device-bound-2fa.md
 * §4.8, §8). The SAME body is sent again with one proof:
 *  - in the Android app's web view (S90), when the server sends a device
 *    challenge and the shell offers `signDeviceChallenge` (bridgeVersion 2):
 *    the fingerprint (at most 2 signatures per action — a second one only
 *    after `challenge_expired`); "Use a code", a bridge error or a refused
 *    assertion fall back to the code prompt; a cancelled prompt cancels;
 *  - otherwise the code prompt: password + code when the session is bound
 *    to a phone key (`codeRequiresPassword`), the "trust this IP" box only
 *    when the server allows it (`trustIpAllowed`).
 */
async function stepUp(config: any, first: any) {
  const base = bodyWithoutProofs(config);
  let body = first;
  let signs = 0;
  let preferCode = false;
  for (;;) {
    const challenge = body?.deviceChallenge as DeviceChallenge | undefined;
    if (!preferCode && signs < 2 && body?.deviceKeyStatus === 'active' && challenge?.purpose === 'stepup'
      && canUseNative('signDeviceChallenge')) {
      signs++;
      let res: SignDeviceChallengeResult;
      try { res = normaliseSignResult(await native.signDeviceChallenge(challenge)); } catch (err) { res = { error: String((err as Error)?.message ?? err) }; }
      if ('deviceAssertion' in res && res.deviceAssertion) {
        try {
          return await sendWithProof(config, base, { deviceAssertion: res.deviceAssertion });
        } catch (err: any) {
          const b = err?.response?.data;
          if (err?.response?.status === 401 && b?.twoFactorRequired) {
            body = b;
            // Only an expired challenge is signed again; anything else → code.
            if (!(b.deviceError === 'challenge_expired' && b.deviceChallenge)) preferCode = true;
            continue;
          }
          throw err;
        }
      }
      if ('cancelled' in res && res.cancelled) throw new Error(TWO_FACTOR_CANCELLED);
      preferCode = true; // "Use a code", locked-out biometric, bridge error
      continue;
    }
    const actionLabel = body?.action || 'Sensitive action';
    const currentIp = typeof body?.currentIp === 'string' ? body.currentIp : undefined;
    // Optional hints (absent on older servers → previous behaviour).
    const trustIpAllowed = body?.trustIpAllowed !== false;
    const { code, trustIp, password } = await awaitTwoFactorCode(actionLabel, currentIp, {
      trustIpAllowed,
      codeMustBeNew: body?.codeMustBeNew === true,
      passwordRequired: body?.codeRequiresPassword === true,
      reauthRequired: body?.codeRequiresReauth === true,
      codeLocked: body?.codeLocked === true,
    });
    const proof: Record<string, unknown> = { twoFactorCode: code };
    if (password) proof.stepUpPassword = password;
    if (trustIp && trustIpAllowed && !password) proof.trustIp = true;
    return sendWithProof(config, base, proof);
  }
}

/** The shell's answer as an object (a JSON string is parsed; anything else is an error). */
function normaliseSignResult(raw: unknown): SignDeviceChallengeResult {
  let v: unknown = raw;
  if (typeof v === 'string') {
    try { v = JSON.parse(v); } catch { return { error: 'unreadable bridge answer' }; }
  }
  if (!v || typeof v !== 'object') return { error: 'unreadable bridge answer' };
  const o = v as Record<string, unknown>;
  const a = o.deviceAssertion as Record<string, unknown> | undefined;
  if (a && typeof a === 'object' && a.v === 1 && typeof a.keyId === 'string'
    && Array.isArray(a.challengeIds) && typeof a.signature === 'string') {
    return { deviceAssertion: a as unknown as DeviceAssertion };
  }
  if (o.cancelled === true) return { cancelled: true };
  if (o.useCode === true) return { useCode: true };
  return { error: typeof o.error === 'string' ? o.error : 'unreadable bridge answer' };
}

/** Sends the original request once more with `proof` (errors bubble to the caller). */
function sendWithProof(config: any, base: Record<string, unknown>, proof: Record<string, unknown>) {
  // `_tfaWithPassword`: the proof carried the password WITH the code (bound
  // session), so a refusal means "wrong password or code", not "wrong code".
  const next = {
    ...config, _tfaRetried: true, _tfaWithPassword: typeof proof.stepUpPassword === 'string',
    data: JSON.stringify({ ...base, ...proof }),
  };
  next.headers = { ...(config.headers ?? {}), 'Content-Type': 'application/json' };
  return apiClient(next);
}

/** Step-up failures the server marks explicitly → translated message.
 *  `withPassword`: the refused proof was password + code (the server answers
 *  the same 'Invalid 2FA code' for either, on purpose). */
function stepUpErrorMessage(status: number | undefined, body: any, withPassword = false): [key: string, fallback: string] | null {
  if (!body || typeof body !== 'object') return null;
  if (status === 403 && body.code === 'ssoEmailManaged') {
    return ['profile.ssoEmailManaged', 'The e-mail address of an SSO account is managed in Obligate.'];
  }
  if (status === 503 && body.verifierUnavailable === true) {
    return ['twoFactorPrompt.verifierUnavailable', 'Two-factor verification is temporarily unavailable. Try again in a moment.'];
  }
  if (status !== 401) return null;
  if (body.codeUsed === true) return ['twoFactorPrompt.codeUsed', 'This code was already used. Wait for the next code, then try again.'];
  if (body.passwordInvalid === true) return ['twoFactorPrompt.passwordInvalid', 'Wrong password.'];
  if (body.error === 'Invalid 2FA code') {
    return withPassword
      ? ['twoFactorPrompt.passwordOrCodeInvalid', 'Wrong password or code.']
      : ['twoFactorPrompt.invalidCode', 'Invalid code.'];
  }
  return null;
}

function isStepUpThrottleBody(status: number | undefined, body: any): boolean {
  return status === 429 && !!body && typeof body === 'object'
    && (body.codeLocked === true || body.error === 'Too many verification attempts');
}

/**
 * True when the failure was already reported to the user by this client
 * (cancelled 2FA / password prompt, step-up throttle or verifier outage, or a
 * 401/403/423 message surfaced below): callers skip their own error toast.
 */
export function isStepUpHandled(err: unknown): boolean {
  if (isTwoFactorCancelled(err)) return true;
  const e = err as { response?: { status?: number; data?: any }; config?: { method?: string } } | null;
  const status = e?.response?.status;
  const body = e?.response?.data;
  if (isStepUpThrottleBody(status, body)) return true;
  if (status === 503 && body?.verifierUnavailable === true) return true;
  const method = (e?.config?.method || 'get').toLowerCase();
  return (status === 401 || status === 403 || status === 423) && typeof body?.error === 'string' && method !== 'get';
}

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const status = error?.response?.status;
    const body = error?.response?.data;
    const config = error?.config ?? {};

    // ── Sensitive-action 2FA gate ──────────────────────────────────────────
    if (status === 401 && body?.twoFactorRequired && !(config as any)._tfaRetried) {
      console.debug('[tfa-gate] server requested 2FA for', body?.action || '(unknown action)');
      try {
        return await stepUp(config, body);
      } catch (cancelled) {
        console.warn('[tfa-gate] 2FA prompt rejected:', (cancelled as any)?.message);
        return Promise.reject(cancelled);
      }
    }

    // ── Device-bound session revoked (J4) ─────────────────────────────────
    // The session was bound to a phone key that was revoked (from the web
    // profile, by an administrator, a password / TOTP change…): the server
    // destroyed it. Only the Android app's web view ever sees this.
    if (status === 401 && body?.deviceKeyStatus === 'revoked') {
      if (isInObliTools) {
        sessionStorage.removeItem(OBLITOOLS_TOKEN_KEY);
      } else if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
      return Promise.reject(error);
    }

    // ── Current-password step-up ───────────────────────────────────────────
    // Adding / removing a second factor on an account that has no code to
    // give (first authenticator app, e-mail codes): the server asks the
    // current password (401 passwordRequired). Same prompt, password mode;
    // sent once as `stepUpPassword` (moved out of the body server-side).
    if (status === 401 && body?.passwordRequired && !(config as any)._tfaRetried) {
      try {
        const actionLabel = body?.action || 'Sensitive action';
        const { code: password } = await awaitTwoFactorCode(actionLabel, undefined, { mode: 'password', trustIpAllowed: false });
        return retryWithProof(config, { stepUpPassword: password });
      } catch (cancelled) {
        return Promise.reject(cancelled);
      }
    }

    // ── Plain 401 (session lost) ──────────────────────────────────────────
    // Only redirect to /login when the 401 is *not* an action-specific error
    // (bad 2FA code, missing TOTP config, invalid approval state, etc). Those
    // carry an `error` string in the body but no session-loss signal; if we
    // redirected here, a bad 2FA code would boot the user out of the app.
    const isActionError = status === 401 && body && typeof body === 'object' && typeof body.error === 'string';
    if (status === 401 && !isActionError && !(config as any)._tfaRetried) {
      if (isInObliTools) {
        sessionStorage.removeItem(OBLITOOLS_TOKEN_KEY);
      } else if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }

    // ── Step-up code caps (429) ───────────────────────────────────────────
    // Too many wrong codes: 10 in 15 min → 429 + Retry-After; 30 in 24 h →
    // `codeLocked`, code entry blocked until the next full sign-in. The
    // server text is English: show a translated message instead.
    if (isStepUpThrottleBody(status, body)) {
      const retryAfter = Number(error?.response?.headers?.['retry-after']);
      const minutes = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.max(1, Math.ceil(retryAfter / 60)) : 15;
      Promise.all([import('react-hot-toast'), import('i18next')]).then(([{ default: toast }, { default: i18n }]) => {
        const msg = body.codeLocked === true
          ? i18n.t('twoFactorPrompt.codeLocked', 'Too many wrong codes. Sign out and sign in again to unlock code entry.')
          : i18n.t('twoFactorPrompt.tooManyAttempts', { minutes, defaultValue: 'Too many wrong codes. Try again in {{minutes}} min.' });
        toast.error(msg, { duration: 8000 });
      }).catch(() => {});
    }

    // ── Surface actionable restriction errors ─────────────────────────────
    // When a sensitive/restricted action is refused (no TOTP on the account,
    // bad 2FA code, unauthorised user, etc.) the server ships a useful
    // `error` string. Most UI call sites show a generic "Failed to …" toast
    // that hides this, so we pop the server message here as a fallback.
    //
    // Skip this for:
    //   - 2FA prompts (status 401 + twoFactorRequired — handled above)
    //   - 2FA retries (bad code → the caller still shows its toast anyway,
    //     we don't want to double-toast but we DO want visibility; keep it)
    //   - GET requests (usually background polling — noise)
    const method = (config.method || 'get').toLowerCase();
    // Step-up failures the server flags (code already used, wrong password,
    // Obligate unreachable, wrong code) get a translated text.
    const stepUpMsg = stepUpErrorMessage(status, body, (config as any)._tfaWithPassword === true);
    const shouldSurface =
      ((status === 401 || status === 403 || status === 423) || (stepUpMsg !== null))
      && body?.error
      && !body?.twoFactorRequired
      && !body?.passwordRequired
      // SSO account signing in locally: the login page explains it inline.
      && body?.code !== 'ssoLoginRequired'
      && method !== 'get';
    if (shouldSurface) {
      // Lazy-load to avoid a circular import (client.ts is imported very early).
      Promise.all([import('react-hot-toast'), import('i18next')]).then(([{ default: toast }, { default: i18n }]) => {
        toast.error(stepUpMsg ? i18n.t(stepUpMsg[0], stepUpMsg[1]) : body.error, { duration: 6000 });
      }).catch(() => {});
    }

    return Promise.reject(error);
  },
);

export default apiClient;
