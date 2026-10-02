import { Router } from 'express';
import { deviceService } from '../services/device.service';
import { requireDeviceRead } from '../middleware/rbac';
import { permissionService } from '../services/permission.service';
import { hasGlobalView } from '../services/deviceScope.service';
import { globalViewScope } from '../middleware/dbContext';

const router = Router();

// /api/devices keeps only the timeline of the change events of a device
// (the Blame Ribbon source, Oblidesk's contract: formatVersion unchanged).
// Every other route of the device registry moved to /api/mdm/devices… with
// the MDM data model (modele-donnees-mdm §10.6, §11.1): the approval,
// refusal, suspension and transfer of agents are gone with the agent, the
// group statistics are the facets of the registry.
//
// Tenant rule: the devices of the session's tenant; the master tenant's
// global view (every tenant) is a platform administrator's only
// (hasGlobalView), in the context 'platform' (globalViewScope). A device out
// of reach answers like an unknown one (404).

/** The caller reads the journal in the request's tenant (audit.read,
 *  audit-durci §9.7): the device timeline then shows its configuration
 *  changes. Platform administrators always do. */
async function readsAudit(req: import('express').Request): Promise<boolean> {
  if (req.session.role === 'admin') return true;
  const userId = Number(req.session.userId);
  const tenantId = Number(req.tenantId);
  if (!Number.isSafeInteger(userId) || !Number.isSafeInteger(tenantId)) return false;
  return permissionService.userHasTenantCapability(userId, tenantId, 'audit.read');
}

// ── Change events (Blame Ribbon source) ─────────────────────────────────────
// Read-through union over the tables Obligarth already writes: what changed on
// this device in a window. Guarded like the device itself (requireDeviceRead) —
// a weaker guard would be a permission bypass, since this exposes per-device
// history. The service also filters per CALLER (a non-admin does not see
// another user's audit rows), so the session identity is passed through.
router.get('/:id/change-events', requireDeviceRead(), globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    // Same tenant rule as the record; the service applies it to the rows too
    // (global view passed explicitly, never inferred from the tenant id).
    if (!(await deviceService.deviceExists(deviceId, req.tenantId!, { globalView: hasGlobalView(req) }))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { changeEventService, changeEventsQuerySchema } = await import('../services/changeEvent.service');
    const parsed = changeEventsQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.issues[0]?.message ?? 'Invalid query' });
    }
    res.json({
      data: await changeEventService.getTimeline(deviceId, req.tenantId!, {
        ...parsed.data,
        callerUserId: req.session.userId!,
        callerIsAdmin: req.session.role === 'admin',
        callerReadsAudit: await readsAudit(req),
        globalView: hasGlobalView(req),
      }),
    });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/change-events/summary?from=&to= — counts per kind
router.get('/:id/change-events/summary', requireDeviceRead(), globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    if (!(await deviceService.deviceExists(deviceId, req.tenantId!, { globalView: hasGlobalView(req) }))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { changeEventService, changeEventsSummaryQuerySchema } = await import('../services/changeEvent.service');
    const parsed = changeEventsSummaryQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.issues[0]?.message ?? 'Invalid query' });
    }
    res.json({
      data: await changeEventService.getSummary(deviceId, req.tenantId!, {
        ...parsed.data,
        callerUserId: req.session.userId!,
        callerIsAdmin: req.session.role === 'admin',
        callerReadsAudit: await readsAudit(req),
        globalView: hasGlobalView(req),
      }),
    });
  } catch (err) { next(err); }
});

export default router;
