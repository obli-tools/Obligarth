import type { Request, Response, NextFunction } from 'express';
import { db } from '../db';
import { comparePassword, hashPassword } from '../utils/crypto';
import { AppError } from '../middleware/errorHandler';
import type { UpdateProfileInput, ChangePasswordInput } from '../validators/profile.schema';
import { ssoEmailChangeRefused, applyProfileUpdate, setAvatar, clearAvatar } from '../services/profileWrite.service';

/**
 * The e-mail address of an SSO account (Obligate, og_) is Obligate's: it is
 * resynced at each SSO sign-in and must not be changed locally (a stolen
 * cookie would move the address the account's notices go to). Sending the
 * current address back (a profile form re-saved) is accepted and left as is.
 * Returns true when the request was answered (403).
 */
export async function refuseSsoEmailChange(userId: number, data: { email?: string | null }, res: Response): Promise<boolean> {
  if (!(await ssoEmailChangeRefused(userId, data))) return false;
  res.status(403).json({
    success: false,
    error: 'The e-mail address of an SSO account is managed in Obligate.',
    code: 'ssoEmailManaged',
    ssoEmailManaged: true,
  });
  return true;
}

function buildUserResponse(row: Record<string, unknown>) {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    role: row.role,
    isActive: row.is_active,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    preferences: row.preferences ?? null,
    email: row.email ?? null,
    preferredLanguage: row.preferred_language ?? 'en',
    enrollmentVersion: row.enrollment_version ?? 0,
    hasPassword: !!row.password_hash,
    avatar: row.avatar ?? null,
  };
}

export const profileController = {
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await db('users')
        .select('id', 'username', 'display_name', 'role', 'is_active', 'created_at', 'updated_at', 'preferences', 'email', 'preferred_language', 'enrollment_version', 'password_hash', 'avatar')
        .where({ id: req.session.userId })
        .first();

      if (!row) throw new AppError(404, 'User not found');

      res.json({ success: true, data: buildUserResponse(row) });
    } catch (err) {
      next(err);
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = req.body as UpdateProfileInput;
      if (await refuseSsoEmailChange(req.session.userId!, data, res)) return;

      // Shared with an approved profile_update (services/profileWrite.service.ts).
      const row = await applyProfileUpdate(req.session.userId!, data);

      res.json({ success: true, data: buildUserResponse(row) });
    } catch (err) {
      next(err);
    }
  },

  async changePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { currentPassword, newPassword } = req.body as ChangePasswordInput;
      const userId = req.session.userId!;

      const user = await db('users').select('password_hash', 'email').where({ id: userId }).first();
      if (!user) throw new AppError(404, 'User not found');

      // The current-password check is an oracle: it shares the step-up caps
      // (§6.8, 10 / 15 min then 30 / 24 h, e-mail, audit) with the codes and
      // the step-up password, for every session — a stolen cookie, or the
      // unlocked phone of a bound session, gets no free guessing.
      const { reserveCodeAttempt, settleCodeAttempt, throttledOutcome, sendStepUpFailure } =
        await import('../services/deviceKey/stepUpProof');
      const slot = await reserveCodeAttempt(userId);
      if (!slot.ok) {
        const out = throttledOutcome(slot);
        if (!out.ok) sendStepUpFailure(res, out);
        return;
      }
      let valid = false;
      try {
        valid = !!user.password_hash && await comparePassword(currentPassword, user.password_hash);
      } catch (err) {
        await settleCodeAttempt(req, userId, 'void', { action: 'profile.password', via: 'password' }).catch(() => {});
        throw err;
      }
      if (!valid) {
        await settleCodeAttempt(req, userId, 'failure', { action: 'profile.password', via: 'password', email: user.email ?? null });
        throw new AppError(400, 'Current password is incorrect');
      }
      await settleCodeAttempt(req, userId, 'success', { action: 'profile.password', via: 'password' });

      const newHash = await hashPassword(newPassword);
      await db('users').where({ id: req.session.userId }).update({ password_hash: newHash, updated_at: new Date() });

      // [D8] changing one's own password revokes the account's phone keys
      // (their sessions die; the fingerprint must be enabled again). The
      // credential-version trigger is the safety net if this hook fails.
      try {
        const { deviceKeyService } = await import('../services/deviceKey/deviceKey.service');
        await deviceKeyService.revokeAllForUser(req.session.userId!, 'password_change', { byUserId: req.session.userId!, req });
      } catch { /* trigger */ }

      res.json({ success: true, message: 'Password changed successfully' });
    } catch (err) {
      next(err);
    }
  },

  async uploadAvatar(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const avatar = await setAvatar(req.session.userId!, (req.body as { avatar?: unknown })?.avatar);

      res.json({ success: true, avatar });
    } catch (err) {
      next(err);
    }
  },

  async deleteAvatar(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      await clearAvatar(req.session.userId!);
      res.json({ success: true });
    } catch (err) {
      next(err);
    }
  },
};
