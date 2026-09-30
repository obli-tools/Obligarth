import type { Request, Response, NextFunction } from 'express';
import { appConfigService } from '../services/appConfig.service';
import {
  writeConfigKey, agentGlobalPatch, obligatePatch,
} from '../services/settingsWrite.service';

// The writes live in services/settingsWrite.service.ts, shared with the
// approval executor (an approved `settings_update` replays the same write).

export const appConfigController = {
  async getAll(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const cfg = await appConfigService.getAll();
      res.json({ success: true, data: cfg });
    } catch (err) { next(err); }
  },

  async set(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // Device-key switches: same path as an approved `settings_update`
      // (approval.service): write, policy cache dropped, unverified keys
      // revoked when attestation becomes required ('policy', §6.7), audited.
      await writeConfigKey(req.params.key, (req.body ?? {}).value, { byUserId: req.session.userId, req });
      res.json({ success: true });
    } catch (err) { next(err); }
  },

  /** GET /admin/config/agent-global */
  async getAgentGlobal(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const cfg = await appConfigService.getAgentGlobal();
      res.json({ success: true, data: cfg });
    } catch (err) { next(err); }
  },

  /** PATCH /admin/config/agent-global */
  async patchAgentGlobal(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const updated = await appConfigService.setAgentGlobal(agentGlobalPatch(req.body ?? {}));
      res.json({ success: true, data: updated });
    } catch (err) { next(err); }
  },

  // ── Obligate SSO gateway ───────────────────────────────────────────────────

  async getObligateConfig(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const cfg = await appConfigService.getObligateConfig();
      res.json({ success: true, data: cfg });
    } catch (err) { next(err); }
  },

  async setObligateConfig(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const updated = await appConfigService.patchObligateConfig(obligatePatch(req.body ?? {}));
      res.json({ success: true, data: updated });
    } catch (err) { next(err); }
  },
};
