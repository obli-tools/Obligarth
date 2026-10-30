import type { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';
import type { StepUpVia } from '../services/deviceKey/stepUpProof';

declare global {
  namespace Express {
    interface Request {
      /** The fresh proof a step-up of this request accepted (restriction
       *  envelope), for its audit entry (audit-durci §5.3, actor.stepUp). */
      stepUpVia?: StepUpVia;
      /** Request-scoped memo of a fresh second factor (the approval of an MCP authorization): checkSecondFactor
       *  accepts these action keys without asking again. Set by that handler only, never persisted. */
      stepUpVerified?: { via: StepUpVia; actionKeys: ReadonlySet<string> };
    }
  }
}

// Extend express-session types
declare module 'express-session' {
  interface SessionData {
    userId: number;
    username: string;
    role: string;
    currentTenantId: number;
    oauthState: string;
    // Exact redirect_uri of the pending Obligate authorize request, stored by
    // /auth/sso-redirect (built from a verified public origin) and presented
    // by /auth/callback at the code exchange.
    oauthRedirectUri?: string;
    pendingMfaLinkToken?: string;
    pendingEmailOtp?: { codeHash: string; email: string; expires: number };
    // Cross-app tenant handoff: captured by /auth/sso-redirect when the source
    // Obli* app appends ?tenant=<slug> to the redirect URL, applied by
    // /auth/callback after the user comes back from Obligate, then cleared.
    requestedTenantSlug?: string;
    // Device-bound 2FA (docs/mobile/device-bound-2fa.md §5.3).
    /** Bound device key (user_device_keys.id): set at enrolment, at a sign-in
     *  carrying the key's X-Obli-Device-Key header, or at the first
     *  authenticated request carrying it. Never re-bound to another key. */
    deviceKeyId?: string;
    /** Lot O: time (ms) of the last fresh Obligate re-authentication
     *  (GET /auth/sso-redirect?reauth=1 → /auth/callback). Valid 5 min: the
     *  code fallback of a bound SSO session; consumed by an enrolment. */
    ssoReauthAt?: number;
    /** Lot O: Obligate MFA epoch read (uncached) at that re-authentication. */
    ssoReauthEpoch?: number;
    /** Lot O: users.credential_version at that re-authentication. */
    ssoReauthCv?: number;
    /** Lot O: an Obligate re-authentication in progress (`returnTo`: the
     *  same-origin path the callback sends the browser back to). */
    pendingReauth?: { startedAt: number; foreignId: number; returnTo?: string };
    /** Lot O: the Obligate code accepted (consumed) by a step-up of THIS
     *  session — reusable by the next step-ups of this session until
     *  `until` (ms), like a local code (stepup mode, design §7.7). Only a
     *  hash is kept. */
    ssoStepUpCode?: { hash: string; userId: number; until: number };
    /** How the session was opened (audit-durci §5.3, actor.auth): 'password',
     *  'password+totp', 'password+email', 'password+device_key', 'sso'. */
    authMethod?: string;
    /** When the session was opened (ms). */
    authAt?: number;
    /** Tenants whose journal this session viewed, and the UTC day: one
     *  audit.viewed entry per session, tenant and day (audit-durci §9.5). */
    auditViewedOn?: Record<string, string>;
  }
}

export function requireAuth(req: Request, _res: Response, next: NextFunction): void {
  if (!req.session?.userId) {
    next(new AppError(401, 'Authentication required'));
    return;
  }
  next();
}
