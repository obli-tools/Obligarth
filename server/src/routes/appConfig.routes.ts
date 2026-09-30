import { Router, type Request, type Response, type NextFunction } from 'express';
import { appConfigController } from '../controllers/appConfig.controller';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { DEVICE_KEY_SETTING_KEYS } from '@obliance/shared';
import { AppError } from '../middleware/errorHandler';

const router = Router();

// Middleware used on every WRITE to tenant settings. Consults the action
// restriction policy and either lets the request through, requires a
// fresh TOTP code, or routes it to a pending approval.
//
// The approval carries the validated write (settingsWrite.service
// prepareSettingsApproval): only the fields the write reads, never a secret,
// and a description of what will change — an approved request is REPLAYED
// (approval.service settings_update). Setting the Obligate API key or inbound
// secret is the only write that carries a secret (decided from those fields,
// never from the caller's field names): at the 'restricted' level it asks a
// fresh code instead of a second administrator, and only for the secret
// itself — the SSO gateway address, switch and client-id form (the trust
// root) still need the second administrator.
async function gateSettingsWrite(req: Request, res: Response, next: NextFunction) {
  try {
    const { applyRestriction, restrictionService } = await import('../services/restriction.service');
    const { prepareSettingsApproval } = await import('../services/settingsWrite.service');
    const prepared = await prepareSettingsApproval(req.method, req.path, req.body);
    if (prepared.carriesSecret && prepared.otherChanges) {
      const level = await restrictionService.getLevelFor({ tenantId: req.tenantId!, actionKey: 'tenant.manage_settings' });
      if (level === 'restricted') {
        throw new AppError(409, 'Settings changes need a second administrator here, and a secret is never kept in an approval: save the SSO gateway address / switch first (without the API key or inbound secret) — a second administrator approves it — then set the API key or inbound secret alone (a fresh code is asked).');
      }
    }
    // Device-bound 2FA switches (PUT /:key, value 'true' | 'false'): key and
    // value at the top level too (the in-app kill switch among them).
    const m = /^\/([a-z_]+)$/.exec(req.path);
    const dkKey = req.method === 'PUT' && m && (DEVICE_KEY_SETTING_KEYS as readonly string[]).includes(m[1]) ? m[1] : null;
    const approvalPayload: Record<string, unknown> = { action: 'settings_update', path: req.path, method: req.method, body: prepared.body };
    if (dkKey) Object.assign(approvalPayload, { key: dkKey, value: prepared.body.value });
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'tenant.manage_settings',
      approvalRequestType: 'batch_command',
      approvalDescription: prepared.description,
      approvalPayload,
      carriesSecret: prepared.carriesSecret,
    });
    if (!approved) return; // response already written by applyRestriction
    next();
  } catch (err) { next(err); }
}

// GET is available to all authenticated users (needed for profile page to check allow_2fa)
router.get('/', requireAuth, appConfigController.getAll);

// Specific named routes MUST come before /:key (otherwise /:key captures them first)

// Agent global defaults — admin only
router.get('/agent-global', requireAuth, requireRole('admin'), appConfigController.getAgentGlobal);
router.patch('/agent-global', requireAuth, requireRole('admin'), gateSettingsWrite, appConfigController.patchAgentGlobal);

// Obligate SSO gateway config — admin only
router.get('/obligate', requireAuth, requireRole('admin'), appConfigController.getObligateConfig);
router.put('/obligate', requireAuth, requireRole('admin'), gateSettingsWrite, appConfigController.setObligateConfig);

// File explorer editable extensions — read by all auth'd users (needed
// by the file explorer UI), write admin only. Cross-tenant global setting.
router.get('/editable-extensions', requireAuth, appConfigController.getEditableExtensions);
router.put('/editable-extensions', requireAuth, requireRole('admin'), gateSettingsWrite, appConfigController.setEditableExtensions);

// Global metric-threshold default (cascade layer 2). Cross-tenant —
// only the platform admin sitting on the master tenant can edit. Read
// is admin-only because the response shape is for the editor; the
// resolver inside threshold.service.ts reads it directly without
// going through this endpoint.
router.get('/global-thresholds', requireAuth, requireRole('admin'), appConfigController.getGlobalThresholds);
router.put('/global-thresholds', requireAuth, requireRole('admin'), gateSettingsWrite, appConfigController.setGlobalThresholds);

// Generic key setter — must be LAST among PUT routes
router.put('/:key', requireAuth, requireRole('admin'), gateSettingsWrite, appConfigController.set);

export default router;
