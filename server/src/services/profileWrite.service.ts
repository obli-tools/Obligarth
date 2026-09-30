import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import type { UpdateProfileInput } from '../validators/profile.schema';

// ── Own-profile writes (PUT /api/profile, avatar) ──────────────────────────
//
// ONE implementation for the routes (profile.controller.ts) and for an
// approved `profile_update` request (approval.service.ts, executed for the
// requester's own account when the tenant.manage_profile level is
// 'restricted'). A password change never goes through an approval (it asks a
// step-up instead): nothing here writes a password.

export const normEmail = (v: unknown): string => (typeof v === 'string' ? v.trim().toLowerCase() : '');

export const PROFILE_COLUMNS = ['id', 'username', 'display_name', 'role', 'is_active', 'created_at', 'updated_at', 'preferences', 'email', 'preferred_language', 'enrollment_version'] as const;

/**
 * The e-mail address of an SSO account (Obligate, og_) is Obligate's: it is
 * resynced at each SSO sign-in and must not be changed locally. Sending the
 * current address back (a profile form re-saved) is accepted: the field is
 * then dropped from `data`. Returns true when the change must be refused.
 */
export async function ssoEmailChangeRefused(userId: number, data: { email?: string | null }): Promise<boolean> {
  if (!('email' in data)) return false;
  const row = await db('users').where({ id: userId }).first('email', 'foreign_source') as
    { email: string | null; foreign_source: string | null } | undefined;
  if (row?.foreign_source !== 'obligate') return false;
  if (normEmail(data.email) === normEmail(row.email)) {
    delete (data as { email?: string | null }).email;
    return false;
  }
  return true;
}

/** Security notice to the PREVIOUS address of an account whose e-mail was
 *  changed (best effort, only if the OTP SMTP server is set). */
function notifyEmailChanged(oldEmail: string): void {
  void (async () => {
    try {
      const { appConfigService } = await import('./appConfig.service');
      const cfg = await appConfigService.getAll();
      if (!cfg.otp_smtp_server_id) return;
      const { twoFactorService } = await import('./twoFactor.service');
      await twoFactorService.sendSecurityNotice(Number(cfg.otp_smtp_server_id), oldEmail, 'The e-mail address of your account was changed', [
        'The e-mail address of your account was just changed. Password-reset links and security notices now go to the new address.',
        'If this was not you, contact an administrator now and change your password.',
      ]);
    } catch { /* a notice never breaks the change */ }
  })();
}

/**
 * Applies a validated profile update (updateProfileSchema) to `userId` —
 * the SSO e-mail rule is the caller's (ssoEmailChangeRefused). Returns the
 * updated row (PROFILE_COLUMNS).
 */
export async function applyProfileUpdate(userId: number, data: UpdateProfileInput): Promise<Record<string, unknown>> {
  const updatePayload: Record<string, unknown> = { updated_at: new Date() };

  if ('displayName' in data) updatePayload.display_name = data.displayName;
  if ('preferences' in data) {
    if (data.preferences === null || data.preferences === undefined) {
      updatePayload.preferences = null;
    } else {
      // Merge with existing preferences so partial updates don't
      // wipe other fields. Strip prototype-mutating keys before
      // the spread to defuse any
      // `{__proto__: {admin: true}}` payload — the merge target
      // is a plain object, so a normal spread would otherwise
      // attach to Object.prototype (Node treats `__proto__` as
      // setter on plain objects).
      const sanitise = (obj: any): Record<string, unknown> => {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return {};
        const out: Record<string, unknown> = Object.create(null);
        for (const [k, v] of Object.entries(obj)) {
          if (k === '__proto__' || k === 'prototype' || k === 'constructor') continue;
          out[k] = v;
        }
        return out;
      };
      const currentRow = await db('users').select('preferences').where({ id: userId }).first();
      const existing = currentRow?.preferences
        ? (typeof currentRow.preferences === 'string' ? JSON.parse(currentRow.preferences) : currentRow.preferences)
        : {};
      const merged = { ...sanitise(existing), ...sanitise(data.preferences) };
      // Cap size: 100 KB is more than enough for user prefs and
      // protects the row from being weaponised as DB bloat.
      const json = JSON.stringify(merged);
      if (json.length > 100_000) {
        throw new AppError(400, 'Preferences payload exceeds 100 KB limit');
      }
      updatePayload.preferences = json;
    }
  }
  if ('email' in data) updatePayload.email = data.email || null;
  if ('preferredLanguage' in data) updatePayload.preferred_language = data.preferredLanguage;

  // If email changes and email OTP is enabled, disable it for security
  if ('email' in data && data.email) {
    const current = await db('users').select('email', 'email_otp_enabled').where({ id: userId }).first();
    if (current?.email_otp_enabled && current.email !== data.email) {
      updatePayload.email_otp_enabled = false;
    }
  }

  const previous = 'email' in data
    ? await db('users').where({ id: userId }).first('email') as { email: string | null } | undefined
    : undefined;

  const [row] = await db('users')
    .where({ id: userId })
    .update(updatePayload)
    .returning([...PROFILE_COLUMNS]);

  if (!row) throw new AppError(404, 'User not found');

  // The address password-reset links go to moved: tell the OLD address.
  if (previous?.email && normEmail(previous.email) !== normEmail(row.email)) {
    notifyEmailChanged(previous.email);
  }
  return row;
}

/** PUT /avatar: a base64 image data URI (≈375 KB max). */
export async function setAvatar(userId: number, avatar: unknown): Promise<string> {
  if (typeof avatar !== 'string' || !avatar.startsWith('data:image/')) {
    throw new AppError(400, 'Invalid image data — must be a base64 data URI');
  }
  // Limit to ~500KB base64 (~375KB image)
  if (avatar.length > 500_000) {
    throw new AppError(400, 'Image too large — max 375KB');
  }
  const n = await db('users').where({ id: userId }).update({ avatar, updated_at: new Date() });
  if (!n) throw new AppError(404, 'User not found');
  return avatar;
}

/** DELETE /avatar */
export async function clearAvatar(userId: number): Promise<void> {
  await db('users').where({ id: userId }).update({ avatar: null, updated_at: new Date() });
}
