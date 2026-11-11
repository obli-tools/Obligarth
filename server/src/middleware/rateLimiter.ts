import type { Request } from 'express';
import rateLimit from 'express-rate-limit';
import { clientAddress } from '../utils/clientIp';
import { limiterKeyOf, loginUsernameOf, resetRequestEmail, type ResolvedForKey } from './rateLimitKeys';

// Key of the anonymous limiters: the client's real address.
//
// req.ip ('trust proxy' 1, app.ts) is the address the client container's nginx
// saw: behind an edge proxy (Nginx Proxy Manager…) it is the proxy's, shared by
// every visitor, so a few anonymous requests used to exhaust one bucket for
// everyone (the second factor and the SSO return of all users answered 429).
// clientAddress walks X-Forwarded-For through TRUSTED_PROXIES and at most
// TRUSTED_PROXY_HOPS hops (utils/clientIp.ts): behind a correctly configured
// edge proxy, a client cannot choose the address it gets, the entries it
// writes itself are left of the ones our proxies add. A client inside a
// trusted range (or reaching the client container directly with
// TRUSTED_PROXY_HOPS=2) can steer it, but only to spread itself over more
// buckets, never to fill someone else's: an address key alone is therefore
// never a brute-force bound — the login and the second factor also have a
// per-account limiter (authAccountLimiter, mfaAccountLimiter). When the address is a relay (an edge proxy missing from
// TRUSTED_PROXIES), everyone behind it shares req.ip's bucket, as before.
export function limiterClientKey(req: Pick<Request, 'ip' | 'socket' | 'headers'>): string {
  let resolved: ResolvedForKey | null = null;
  try { resolved = clientAddress(req as never); } catch { /* fall back on the nginx-seen address */ }
  return limiterKeyOf(resolved, req.ip);
}

export { resetRequestEmail };

// Path prefixes of machine-to-machine endpoints, never counted by apiLimiter:
// declared by the module that serves them (exemptFromApiLimiter; none
// today). Only for endpoints authenticated otherwise (API key, token), polled
// at their own cadence: counting them would eat the shared budget of the
// login page, limiting them adds nothing to their auth.
const exemptPrefixes: string[] = [];

export function exemptFromApiLimiter(prefix: string): void {
  if (!prefix.startsWith('/api/') || !prefix.endsWith('/')) throw new Error(`Invalid limiter exemption: ${prefix}`);
  if (!exemptPrefixes.includes(prefix)) exemptPrefixes.push(prefix);
}

// Global API limiter — protects unauthenticated / public endpoints only.
//
// IMPORTANT: This limiter runs AFTER session middleware (see app.ts) so that
// req.session.userId is populated and we can skip authenticated users.
//
// Why skip authenticated sessions?
//   - Behind a reverse proxy (e.g. Nginx Proxy Manager) ALL users share the
//     same apparent IP.  A limit of N req/window would be shared by every user
//     simultaneously, causing false positives on normal dashboard usage.
//   - Authenticated requests are already protected by the session cookie; the
//     rate limiter adds no meaningful security benefit for them.
//   - Unauthenticated requests (login page, public health endpoint, etc.) still
//     get rate-limited to defend against enumeration / DDoS.
export const apiLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes (shorter window = faster recovery)
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: limiterClientKey,
  skip: (req) =>
    // ── Authenticated dashboard users ──────────────────────────────────────
    // Session is populated by the time this limiter runs (middleware order in app.ts).
    !!req.session?.userId ||
    // ── Public informational endpoints ─────────────────────────────────────
    // Health check is polled by the login page to show the server version;
    // rate-limiting it would block the login page's UI, not improve security.
    req.path === '/health' ||
    // Auth state probe — returns 401 for unauthenticated callers, no info leak.
    req.path === '/api/auth/me' ||
    // ── Machine-to-machine endpoints (declared by their modules) ──────────
    exemptPrefixes.some((p) => req.path.startsWith(p)) ||
    // Android app update check + APK download (public, docs/obli-mobile.md §6).
    // Shells poll without a session, often from shared carrier-NAT IPs; counting
    // them would eat the shared 500/5 min budget of the login page. Read-only,
    // served from disk, no user input.
    req.path.startsWith('/api/mobile/android/') ||
    // Login is already protected by the dedicated authLimiter (IP+username keyed,
    // brute-force focused). Skipping it here avoids false positives when many
    // unauthenticated requests arrive from the same apparent IP (shared proxy).
    req.path === '/api/auth/login' ||
    req.path === '/api/auth/logout',
  message: {
    success: false,
    error: 'Too many requests, please try again later',
  },
});

// MFA verify limiter — applied to /profile/2fa/verify, /device-challenge and /resend-email.
// Keyed by the client's address (no username in the body at that point).
// More generous than the login limiter: the attacker must first have a valid
// username+password AND a live pendingMfaUserId session to even reach this endpoint.
// 50 attempts / 15 minutes is enough to survive testing while still blocking automation.
// A request without a pending sign-in is not counted (the controller answers
// 400, nothing to guess): anonymous noise must never fill the bucket of the
// users who share an address.
export const mfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  max: 50,                   // 50 failed attempts per 15 minutes per client address
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => !req.session?.pendingMfaUserId,
  keyGenerator: (req) => `mfa-${limiterClientKey(req)}`,
  message: {
    success: false,
    error: 'Too many verification attempts, please try again later',
  },
});

// MFA verify limiter keyed on the ACCOUNT (the pending 2FA user), not the IP.
// An IP-keyed limit alone does not bound a TOTP / email-code brute force: the
// attacker already knows the password and can open a new pending session at
// will, from as many addresses as they have. 10 wrong codes per 15 minutes
// per account keeps a 6-digit code out of reach; the worst an attacker can do
// with it is delay that one account's sign-in (and they hold its password).
// Applied to /profile/2fa/verify only, after mfaLimiter.
export const mfaAccountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  // No pending 2FA user: the controller answers 400, nothing to guess.
  skip: (req) => !req.session?.pendingMfaUserId,
  keyGenerator: (req) => `mfa-user:${req.session?.pendingMfaUserId}`,
  message: {
    success: false,
    error: 'Too many verification attempts, please try again later',
  },
});

// Login-specific limiter — stricter window to slow down brute-force attempts.
//
// Key = IP + username so that:
//   a) A shared proxy IP does NOT cause all users to share one rate-limit bucket.
//      User A hitting the limit doesn't lock out User B.
//   b) An attacker cannot brute-force a single account faster than the limit allows.
//   c) req.body is available here because authLimiter is applied per-route in
//      auth.routes.ts, after express.json() has already run globally.
//
// skipSuccessfulRequests: successful logins (HTTP 200) do not count toward the
// limit, so a legitimate user who eventually gets their password right is not
// penalised for earlier typos.  Only failed attempts (4xx) accumulate.
export const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes — resets quickly after an accidental lock-out
  max: 20,                  // 20 failed attempts per 5-minute window per IP+username
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip       = limiterClientKey(req);
    // Combine both so shared-IP users each get their own bucket per account
    // (bounded per account alone by authAccountLimiter).
    return `${ip}:${loginUsernameOf(req.body)}`;
  },
  message: {
    success: false,
    error: 'Too many login attempts, please try again in 5 minutes',
  },
});

// Login limiter keyed on the ACCOUNT alone (the username named), whatever the
// address. authLimiter keys on the client's address, which a client inside a
// trusted range can steer (TRUSTED_PROXY_HOPS=2 with the client container
// reachable without the edge proxy, see utils/clientIp.ts): changing its
// X-Forwarded-For at each try would give it a fresh authLimiter bucket every
// time. This bound holds anyway: 50 failed passwords per 15 minutes per
// account (on the model of mfaAccountLimiter). The worst an attacker can do
// with it is delay that one account's local sign-in for 15 minutes; SSO
// sign-ins (Obligate) never go through this route.
export const authAccountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  // No username: validate() answers 400, nothing to guess.
  skip: (req) => loginUsernameOf(req.body) === '',
  keyGenerator: (req) => `login-user:${loginUsernameOf(req.body)}`,
  message: {
    success: false,
    error: 'Too many login attempts, please try again later',
  },
});

// Enrollment (POST /api/auth/enrollment), keyed on the signed-in account: an
// account without an address may give itself one there, and the answer says
// when the address is already another account's. 10 refused attempts per hour
// per account keep that answer from being used to enumerate addresses.
export const enrollmentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  // requireAuth runs first: no session user, nothing to count.
  skip: (req) => !req.session?.userId,
  keyGenerator: (req) => `enroll-user:${req.session?.userId}`,
  message: {
    success: false,
    error: 'Too many attempts, please try again later',
  },
});

// Password-reset requests (POST /api/auth/forgot-password). The route answers
// 200 whatever the address (no enumeration), so EVERY request is counted
// (authLimiter counts failures only, and keys on a `username` this body does
// not carry: nothing was ever counted). Two buckets:
//   - per client address: 10 requests per hour;
//   - per e-mail address named: 3 requests per hour, whoever asks — a mail
//     bomb at one account, or a stream of new links that each invalidate the
//     previous one, stops there. An attacker can delay the owner's own
//     request by at most an hour; the owner's administrator can still reset.
export const passwordResetIpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `reset-${limiterClientKey(req)}`,
  message: {
    success: false,
    error: 'Too many password reset requests, please try again later',
  },
});

export const passwordResetAccountLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  // A body without an address is refused 400 by the controller.
  skip: (req) => resetRequestEmail(req.body) === '',
  keyGenerator: (req) => `reset-email:${resetRequestEmail(req.body)}`,
  // Same answer as an accepted request: the bucket of an address must not
  // tell whether it names an account (it never does: every address is
  // counted), nor that someone else asked for it.
  handler: (_req, res) => {
    res.json({ success: true, message: 'If an account with that email exists, a reset link has been sent.' });
  },
});

// The reset itself (POST /reset-password, /reset-password/validate): a 256-bit
// token, so no brute force to fear; a bound on the requests per client keeps
// the password hashing (scrypt/bcrypt) from being used as a load amplifier.
export const passwordResetTokenLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `reset-token-${limiterClientKey(req)}`,
  message: {
    success: false,
    error: 'Too many attempts, please try again later',
  },
});
