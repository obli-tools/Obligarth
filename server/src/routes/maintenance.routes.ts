import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { maintenanceController } from '../controllers/maintenance.controller';
import { globalViewScope } from '../middleware/dbContext';

const router = Router();

router.use(requireAuth);
router.use(requireRole('admin'));

// Collection routes. The reads accept the master tenant's global view
// (context 'platform'); the writes read their window there too, then write
// in the window's tenant (maintenance.controller, asTargetTenant).
router.get('/', globalViewScope('console.maintenance'), maintenanceController.list);
router.post('/', maintenanceController.create);

// Specific named routes before generic /:id to avoid param conflicts
router.get('/effective/:type/:id', globalViewScope('console.maintenance'), maintenanceController.getEffective);
router.post('/:id/disable', maintenanceController.disable);
router.delete('/:id/disable', maintenanceController.enable);

// Generic /:id routes last
router.get('/:id', globalViewScope('console.maintenance'), maintenanceController.getById);
router.put('/:id', maintenanceController.update);
router.delete('/:id', maintenanceController.delete);

export default router;
