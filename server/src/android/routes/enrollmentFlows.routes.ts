// /api/android (tenant router: requireAuth, requireTenant), the company enrollments without a QR code and the sign-in
// URL (lot AN-F2, sections 6.4, 10.5, 12.1):
//   GET  /enterprise/signin              the sign-in URL of the enterprise (never Google's token nor its QR code)
//   PUT  /enterprise/signin              { enabled, allowPersonalUsage? } → signinDetails of the enterprise; step-up
//   POST /zero-touch/iframe-token        { tokenId } → the zero-touch iframe URL (web token + extras of a long token); step-up
//   GET  /enrollment-tokens/:id/kme      the Knox Mobile Enrollment configuration of a KME token; step-up
// Capabilities: mdm.integrations.manage (sign-in URL, zero-touch) and mdm.enrollment.manage (KME) once they exist
// (AN41, §22.8); devices.manage until then. Mounted at lot AN-A2. The iframe URL and the KME JSON carry the value of a
// long token: in the body of the answer only, Cache-Control no-store, never logged.
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { ANDROID_SIGNIN_PERSONAL_USAGE } from '@obligarth/shared/dist/android/enrollment.js';
import { audit } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { checkSecondFactor, sendStepUpFailure } from '../../services/deviceKey/stepUpProof';
import { createZeroTouchIframe, kmeConfiguration } from '../enrollment/longTokens';
import { TokenError } from '../enrollment/tokens';
import { configureSignin, readSigninConfig, SigninConfigError } from '../signin/config';
import { toRouteError } from './enterprise.routes';

const SigninBody = z.object({
  enabled: z.boolean(),
  allowPersonalUsage: z.enum(ANDROID_SIGNIN_PERSONAL_USAGE).optional(),
}).strict();
const ZeroTouchBody = z.object({ tokenId: z.string().uuid() }).strict();
const UUID = z.string().uuid();

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function routeError(err: unknown): unknown {
  if (err instanceof TokenError || err instanceof SigninConfigError) return new AppError(err.status, err.message, err.code);
  return toRouteError(err);
}

export function createAndroidEnrollmentFlowsRouter(): Router {
  const router = Router();
  const capability = requireTenantCapability('devices.manage');

  router.get('/enterprise/signin', capability, wrap(async (req, res) => {
    res.json({ success: true, data: await readSigninConfig(Number(req.tenantId), Number(req.session.userId)) });
  }));

  router.put('/enterprise/signin', capability, wrap(async (req, res) => {
    const parsed = SigninBody.safeParse(req.body);
    if (!parsed.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    const step = await checkSecondFactor(req, { actionKey: 'android.signin_configure', allowTrustedIp: false, allowDevice: true });
    if (!step.ok) { sendStepUpFailure(res, step); return; }
    const tenantId = Number(req.tenantId);
    try {
      const r = await configureSignin(tenantId, Number(req.session.userId), parsed.data, await audit.fromRequest(req, tenantId));
      res.json({ success: true, data: r });
    } catch (err) { throw routeError(err); }
  }));

  router.post('/zero-touch/iframe-token', capability, wrap(async (req, res) => {
    const parsed = ZeroTouchBody.safeParse(req.body);
    if (!parsed.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    const step = await checkSecondFactor(req, { actionKey: 'android.zero_touch_iframe', allowTrustedIp: false, allowDevice: true });
    if (!step.ok) { sendStepUpFailure(res, step); return; }
    const tenantId = Number(req.tenantId);
    try {
      const r = await createZeroTouchIframe(tenantId, Number(req.session.userId), { tokenId: parsed.data.tokenId.toLowerCase() },
        await audit.fromRequest(req, tenantId));
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, data: r });
    } catch (err) { throw routeError(err); }
  }));

  router.get('/enrollment-tokens/:id/kme', capability, wrap(async (req, res) => {
    const id = UUID.safeParse(req.params.id);
    if (!id.success) throw new AppError(404, 'Not found', 'notFound');
    const step = await checkSecondFactor(req, { actionKey: 'android.enrollment_token_reveal', allowTrustedIp: false, allowDevice: true });
    if (!step.ok) { sendStepUpFailure(res, step); return; }
    const tenantId = Number(req.tenantId);
    try {
      const r = await kmeConfiguration(tenantId, Number(req.session.userId), id.data.toLowerCase(), await audit.fromRequest(req, tenantId));
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, data: r });
    } catch (err) { throw routeError(err); }
  }));
  return router;
}
