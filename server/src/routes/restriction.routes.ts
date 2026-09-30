import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { restrictionService, restrictableActions, sanitizeMap, diffMaps } from '../services/restriction.service';
import { auditService } from '../services/audit.service';

const router = Router();

router.use(requireAuth, requireRole('admin'));

// GET /api/restrictions — tenant's current action map + the canonical
// actions catalog so the UI can render unknown keys last.
router.get('/', async (req, res, next) => {
  try {
    const map = await restrictionService.getMap(req.tenantId!);
    res.json({ data: { map, actions: restrictableActions() } });
  } catch (err) { next(err); }
});

// PUT /api/restrictions — replace the whole map (simpler than PATCH per key
// and matches how the UI edits a whole matrix form at once).
router.put('/', async (req, res, next) => {
  try {
    // Only action keys with a real level are kept (what setMap stores): a
    // junk key never reaches the matrix nor an approval. An absent map is a
    // 400 (it used to clear the whole matrix).
    const incoming = sanitizeMap(req.body?.map);
    const current = await restrictionService.getMap(req.tenantId!);
    const changes = diffMaps(current, incoming);
    if (changes.length) {
      // Gate via the "manage restrictions" action itself — bootstrap-friendly
      // because the default is None, but tenants that opt in get TOTP-
      // protected edits to their own security policy. At the 'restricted'
      // level the approval carries the CHANGES (before → after, shown to the
      // reviewer) and the executor applies exactly those onto the matrix of
      // that moment (approval.service _executeRestrictionsUpdate).
      const { applyRestriction } = await import('../services/restriction.service');
      const { describeRestrictionChanges } = await import('../services/approvalDescribe');
      const approved = await applyRestriction(res, {
        req,
        actionKey: 'tenant.manage_restrictions',
        approvalRequestType: 'batch_command',
        approvalDescription: describeRestrictionChanges(changes),
        approvalPayload: { action: 'restrictions_update', changes },
      });
      if (!approved) return;
    }

    await restrictionService.setMap(req.tenantId!, incoming);
    await auditService.logReq(req, 'restrictions.updated', {
      resourceType: 'restrictions',
      resourcePath: 'tenant',
      details: { keys: Object.keys(incoming), changed: changes.map((c) => c.key) },
    });
    const map = await restrictionService.getMap(req.tenantId!);
    res.json({ data: { map, actions: restrictableActions() } });
  } catch (err) { next(err); }
});

export default router;
