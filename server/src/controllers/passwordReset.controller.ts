import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { passwordResetService } from '../services/passwordReset.service';
import { AppError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';

const forgotSchema = z.object({ email: z.string().email() });
const validateSchema = z.object({ token: z.string().min(1) });
const resetSchema = z.object({
  token: z.string().min(1),
  newPassword: z.string().min(6).max(128),
});

export const passwordResetController = {
  async forgot(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = forgotSchema.safeParse(req.body);
      if (!parsed.success) throw new AppError(400, 'Invalid email address');

      // Always the same 200, at once — no email enumeration: the lookup and the
      // SMTP delivery run after the answer, so neither the response time nor
      // an SMTP failure (logged, never answered) tells a known address.
      res.json({ success: true, message: 'If an account with that email exists, a reset link has been sent.' });
      void passwordResetService.requestReset(parsed.data.email).catch((err: unknown) => {
        logger.warn({ err: { name: (err as Error | null)?.name, message: (err as Error | null)?.message } }, 'password reset request failed');
      });
    } catch (err) {
      next(err);
    }
  },

  async validate(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = validateSchema.safeParse(req.body);
      if (!parsed.success) throw new AppError(400, 'Invalid token');

      const userId = await passwordResetService.validateToken(parsed.data.token);
      res.json({ success: true, data: { valid: userId !== null } });
    } catch (err) {
      next(err);
    }
  },

  async reset(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = resetSchema.safeParse(req.body);
      if (!parsed.success) throw new AppError(400, parsed.error.errors[0]?.message ?? 'Invalid input');

      const ok = await passwordResetService.resetPassword(parsed.data.token, parsed.data.newPassword);
      if (!ok) throw new AppError(400, 'Invalid or expired reset token');

      res.json({ success: true, message: 'Password reset successfully' });
    } catch (err) {
      next(err);
    }
  },
};
