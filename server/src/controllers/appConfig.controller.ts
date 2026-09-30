import type { Request, Response, NextFunction } from 'express';
import { appConfigService } from '../services/appConfig.service';
import {
  writeConfigKey, agentGlobalPatch, obligatePatch, writeEditableExtensions, writeGlobalThresholds,
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

  // ── File explorer editable extensions (cross-tenant global setting) ────

  async getEditableExtensions(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const extensions = await appConfigService.getEditableExtensions();
      const defaults = appConfigService.getDefaultEditableExtensions();
      res.json({ success: true, data: { extensions, defaults } });
    } catch (err) { next(err); }
  },

  async setEditableExtensions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const saved = await writeEditableExtensions((req.body as { extensions?: unknown })?.extensions);
      res.json({ success: true, data: { extensions: saved } });
    } catch (err) { next(err); }
  },

  // ── Global metric-threshold default (cascade layer 2) ─────────────
  // Stored as a JSON-encoded string under app_config['metric_thresholds_global'].
  // The endpoint validates the shape with the same Zod schema the
  // group + tenant editors use so all three surfaces accept the same
  // input — no surprise where one layer rejects a payload another
  // would accept.

  async getGlobalThresholds(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const raw = await appConfigService.get('metric_thresholds_global');
      let value: unknown = null;
      if (raw) {
        try { value = JSON.parse(raw); } catch { value = null; }
      }
      res.json({ success: true, data: { thresholds: value } });
    } catch (err) { next(err); }
  },

  async setGlobalThresholds(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const thresholds = await writeGlobalThresholds((req.body as { thresholds?: unknown })?.thresholds);
      res.json({ success: true, data: { thresholds } });
    } catch (err) { next(err); }
  },
};
