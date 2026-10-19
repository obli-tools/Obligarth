// /api/android (tenant router: requireAuth, requireTenant):
//   GET  /enterprise           the tenant's Android enterprise card (state, type, domain; never a Google token)
//   POST /enterprise/signups   starts a signup: publisher terms accepted, step-up; answers the URL of Google
// Capability: mdm.integrations.manage (AN41). Mounted under /api/android by routes/index.ts (lot AN-A2).
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { audit } from '../../audit';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { checkSecondFactor, sendStepUpFailure } from '../../services/deviceKey/stepUpProof';
import { raiseAndroidPlatformAlert } from '../alerts';
import { readEnterpriseRow } from '../enterprises/registry';
import { SignupError, startSignup } from '../enterprises/signup';
import { isAndroidError, routeStatusOf } from '../gateway/errors';

const SignupBody = z.object({
  domain: z.string().min(3).max(253),
  adminEmail: z.string().max(320).optional(),
  displayName: z.string().min(1).max(100),
  primaryColor: z.number().int().min(0).max(0xffffff).optional(),
  termsAccepted: z.boolean(),
  termsVersion: z.string().max(32),
  onBehalfReason: z.string().max(500).optional(),
}).passthrough();

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

/** An Android or signup error as an AppError of the route. */
export function toRouteError(err: unknown): unknown {
  if (err instanceof SignupError) return new AppError(err.status, err.message, err.code);
  if (isAndroidError(err)) {
    const { status, code } = routeStatusOf(err);
    return new AppError(status, err.kind === 'ownership' ? 'Not found' : err.message, code);
  }
  return err;
}

export function createAndroidTenantRouter(): Router {
  const router = Router();
  const capability = requireTenantCapability('mdm.integrations.manage');

  router.get('/enterprise', capability, wrap(async (_req, res) => {
    const row = await readEnterpriseRow(db);
    res.json({
      success: true,
      data: row ? {
        id: row.id, state: row.state, enterpriseName: row.enterprise_name, enterpriseType: row.enterprise_type,
        domainType: row.domain_type, adminDomain: row.admin_domain, displayName: row.display_name,
        topicSet: row.topic_set_at !== null, testMessageAt: row.test_message_at, linkedAt: row.linked_at,
      } : null,
    });
  }));

  router.post('/enterprise/signups', capability, wrap(async (req, res) => {
    const parsed = SignupBody.safeParse(req.body);
    if (!parsed.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    const step = await checkSecondFactor(req, { actionKey: 'android.enterprise_signup', allowTrustedIp: false, allowDevice: true });
    if (!step.ok) { sendStepUpFailure(res, step); return; }
    const tenantId = Number(req.tenantId);
    const userId = Number(req.session.userId);
    try {
      const auditCtx = await audit.fromRequest(req, tenantId);
      const r = await startSignup(tenantId, userId, parsed.data, auditCtx);
      res.status(201).json({ success: true, data: { signupId: r.signupId, url: r.url } });
    } catch (err) {
      if (err instanceof SignupError && err.code === 'androidDomainClaimed') {
        void raiseAndroidPlatformAlert('android.domain_claimed', { tenantId });
      }
      throw toRouteError(err);
    }
  }));
  return router;
}
