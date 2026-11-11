import type { Request, Response, NextFunction } from 'express';
import { performance } from 'node:perf_hooks';
import { db } from '../db';
import { config } from '../config';
import { appConfigService } from '../services/appConfig.service';
import { exemptFromForce2fa } from './force2faExempt';

// "Force 2FA" (platform setting force_2fa), enforced by the server.
//
// GET /api/auth/me announces requires2faSetup to the console, which sends the
// account to its profile; that alone protects nothing: a session opened with
// the password only used the whole API. While force_2fa is 'true' (and
// DISABLE_2FA_FORCE is not set), a LOCAL account without a second factor (no
// authenticator app, no e-mail codes) reaches only what it needs to set one
// up and to leave; anything else answers 403 code 'twoFactorSetupRequired'.
// Never an account of Obligate (SSO): its second factor is Obligate's.
//
// Mounted in app.ts on /api, after the session's user is re-read. The setting
// is cached a few seconds; an account found compliant (SSO, or with a factor)
// too, a non-compliant one is read again on every request (it must get
// through the moment its factor is enabled).

const SETTING_TTL_MS = 5_000;
const COMPLIANT_TTL_MS = 30_000;
const MAX_ENTRIES = 10_000;

export { exemptFromForce2fa };

let setting: { at: number; on: boolean } | null = null;
const compliant = new Map<number, number>();

/** Drops the caches (tests; a change of the setting is seen within a few seconds anyway). */
export function forgetForce2faState(): void {
  setting = null;
  compliant.clear();
}

async function forceOn(): Promise<boolean> {
  if (config.disable2faForce) return false;
  const now = performance.now();
  if (setting && now - setting.at < SETTING_TTL_MS) return setting.on;
  const on = (await appConfigService.get('force_2fa')) === 'true';
  setting = { at: now, on };
  return on;
}

/** The account may use the API under force_2fa (SSO, or a local second factor). */
async function isCompliant(userId: number): Promise<boolean> {
  const now = performance.now();
  const at = compliant.get(userId);
  if (at !== undefined && now - at < COMPLIANT_TTL_MS) return true;
  const row = await db('users').where({ id: userId })
    .first('foreign_source', 'totp_enabled', 'email_otp_enabled') as
    { foreign_source: string | null; totp_enabled: boolean | null; email_otp_enabled: boolean | null } | undefined;
  // No such user: sessionUserGuard already ended the session; requireAuth answers.
  const ok = !row || row.foreign_source === 'obligate' || row.totp_enabled === true || row.email_otp_enabled === true;
  if (ok) {
    if (compliant.size >= MAX_ENTRIES) compliant.clear();
    compliant.set(userId, now);
  }
  return ok;
}

/** force_2fa is on and this account has no second factor yet (the Socket.io
 *  handshake applies it too: a socket would otherwise stream the tenant's
 *  live events to a session the API refuses). */
export async function force2faBlocks(userId: number): Promise<boolean> {
  return (await forceOn()) && !(await isCompliant(userId));
}

export async function force2faGate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const userId = Number(req.session?.userId);
  if (!Number.isInteger(userId) || userId <= 0) { next(); return; }
  if (exemptFromForce2fa(req.method, req.path)) { next(); return; }
  try {
    if (!(await forceOn()) || await isCompliant(userId)) { next(); return; }
    res.status(403).json({
      success: false,
      error: 'Two-factor authentication is required: set it up on your profile first.',
      code: 'twoFactorSetupRequired',
      requires2faSetup: true,
    });
  } catch (err) {
    next(err);
  }
}
