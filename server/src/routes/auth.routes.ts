import { Router } from 'express';
import { authController } from '../controllers/auth.controller';
import { enrollmentController } from '../controllers/enrollment.controller';
import { passwordResetController } from '../controllers/passwordReset.controller';
import { requireAuth } from '../middleware/auth';
import { validate } from '../middleware/validate';
import { authLimiter, authAccountLimiter, enrollmentLimiter, passwordResetIpLimiter, passwordResetAccountLimiter, passwordResetTokenLimiter } from '../middleware/rateLimiter';
import { loginSchema } from '../validators/auth.schema';

const router = Router();

router.post('/login', authLimiter, authAccountLimiter, validate(loginSchema), authController.login);
router.post('/logout', requireAuth, authController.logout);
router.get('/me', requireAuth, authController.me);
router.get('/permissions', requireAuth, authController.permissions);

// Enrollment (requires auth — user must be logged in)
router.post('/enrollment', requireAuth, enrollmentLimiter, enrollmentController.complete);

// Password reset (public): every request counted, per client and per address
// named (middleware/rateLimiter.ts).
router.post('/forgot-password', passwordResetIpLimiter, passwordResetAccountLimiter, passwordResetController.forgot);
router.post('/reset-password/validate', passwordResetTokenLimiter, passwordResetController.validate);
router.post('/reset-password', passwordResetTokenLimiter, passwordResetController.reset);

export default router;
