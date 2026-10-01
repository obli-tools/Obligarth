// DORMANT: this router is not mounted (routes/index.ts) while software
// licenses sleep (design §6.1). Before mounting it again, guard every route,
// reads included, with a tenant capability: any member of the tenant, a
// viewer included, could read and change license keys through it.
import { Router } from 'express';
import { licenseService } from '../services/license.service';
import { requireDeviceRead, requireDeviceWriteParam } from '../middleware/rbac';
import { parseRequestDeviceId } from '../services/deviceScope.service';
import { db } from '../db';

const router = Router();

// GET /licenses — tenant-wide listing
router.get('/', async (req, res, next) => {
  try {
    const items = await licenseService.listAll(req.tenantId!);
    res.json({ data: items });
  } catch (err) { next(err); }
});

// GET /licenses/device/:deviceId — per device
router.get('/device/:deviceId', requireDeviceRead('deviceId'), async (req, res, next) => {
  try {
    const items = await licenseService.listForDevice(parseInt(req.params.deviceId), req.tenantId!);
    res.json({ data: items });
  } catch (err) { next(err); }
});

// POST /licenses/device/:deviceId — create, for a device of the session's
// tenant only (the license is written there): another tenant's device
// answers like an unknown one (404).
router.post('/device/:deviceId', requireDeviceWriteParam('deviceId'), async (req, res, next) => {
  try {
    const deviceId = parseRequestDeviceId(req.params.deviceId);
    const device = deviceId === null ? undefined : await db('devices').where({ id: deviceId, tenant_id: req.tenantId! }).first('id');
    if (!device) return res.status(404).json({ error: 'Device not found' });
    const license = await licenseService.create(deviceId!, req.tenantId!, req.body);
    res.status(201).json({ data: license });
  } catch (err) { next(err); }
});

// PATCH /licenses/:id — update (check tenant ownership inside)
router.patch('/:id', async (req, res, next) => {
  try {
    const license = await licenseService.update(parseInt(req.params.id), req.tenantId!, req.body);
    if (!license) return res.status(404).json({ error: 'License not found' });
    res.json({ data: license });
  } catch (err) { next(err); }
});

// DELETE /licenses/:id — delete (check tenant ownership inside)
router.delete('/:id', async (req, res, next) => {
  try {
    const deleted = await licenseService.delete(parseInt(req.params.id), req.tenantId!);
    if (!deleted) return res.status(404).json({ error: 'License not found' });
    res.status(204).send();
  } catch (err) { next(err); }
});

export default router;
