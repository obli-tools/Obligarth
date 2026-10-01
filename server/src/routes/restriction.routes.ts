import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { restrictionService, restrictableActions, restrictionFloors, sanitizeMap, diffMaps } from '../services/restriction.service';
import { db } from '../db';
import { audit } from '../audit';

const router = Router();

router.use(requireAuth, requireRole('admin'));

// GET /api/restrictions — tenant's current action map + the canonical
// actions catalog so the UI can render unknown keys last.
router.get('/', async (req, res, next) => {
  try {
    const map = await restrictionService.getMap(req.tenantId!);
    // Floors: the levels an action never goes below (audit-durci §12.2).
    res.json({ data: { map, actions: restrictableActions(), floors: restrictionFloors() } });
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

    // P1 (critical): the matrix and its entry in one transaction, the entry
    // last; a matrix whose entry cannot be written is not changed (503).
    const ctx = await audit.fromRequest(req, req.tenantId!);
    await db.transaction(async (trx) => {
      await restrictionService.setMap(req.tenantId!, incoming, trx);
      await audit.appendInTx(trx, {
        tenantId: req.tenantId!, action: 'restrictions.updated', target: { type: 'restrictions', id: 'tenant' },
        details: { keys: Object.keys(incoming), changed: changes.map((c) => c.key) },
      }, ctx);
    });
    const map = await restrictionService.getMap(req.tenantId!);
    res.json({ data: { map, actions: restrictableActions(), floors: restrictionFloors() } });
  } catch (err) { next(err); }
});

export default router;
