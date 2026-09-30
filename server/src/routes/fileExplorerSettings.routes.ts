import { Router, type Request, type Response, type NextFunction } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { gateSettingsWrite } from './appConfig.routes';
import { fileExplorerSettings, writeEditableExtensions } from '../services/fileExplorerSettings.service';

// File explorer editable extensions, under /api/admin/config (mounted in
// routes/index.ts before the core settings router, whose PUT /:key would
// otherwise take the path). Cross-tenant global setting.

const router = Router();

// ── File explorer editable extensions (cross-tenant global setting) ────
// Read by all auth'd users (needed by the file explorer UI), write admin only.

router.get('/editable-extensions', requireAuth, async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const extensions = await fileExplorerSettings.getEditableExtensions();
    const defaults = fileExplorerSettings.getDefaultEditableExtensions();
    res.json({ success: true, data: { extensions, defaults } });
  } catch (err) { next(err); }
});

router.put('/editable-extensions', requireAuth, requireRole('admin'), gateSettingsWrite, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const saved = await writeEditableExtensions((req.body as { extensions?: unknown })?.extensions);
    res.json({ success: true, data: { extensions: saved } });
  } catch (err) { next(err); }
});

export default router;
