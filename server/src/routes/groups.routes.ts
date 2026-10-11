import { Router } from 'express';
import { groupsController } from '../controllers/groups.controller';
import { requireAuth } from '../middleware/auth';
import { requireTenantCapability, requireGroupWrite, requireCanCreate } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import { globalViewScope } from '../middleware/dbContext';
import {
  createGroupSchema,
  updateGroupSchema,
  moveGroupSchema,
} from '../validators/group.schema';

const router = Router();

// All routes require authentication
router.use(requireAuth);

// Read routes (visibility filtering in controller). The master tenant's
// global view reads every tenant (context 'platform'); the writes below read
// their group there too, then write in its tenant (groups.controller).
router.get('/', globalViewScope('console.groups'), groupsController.list);
router.get('/tree', globalViewScope('console.groups'), groupsController.tree);
router.get('/stats', groupsController.stats);
router.get('/:id', globalViewScope('console.groups'), groupsController.getById);

// Write routes (permission-based: admin OR team RW)
router.post('/', requireCanCreate(), validate(createGroupSchema), groupsController.create);
router.put('/:id', requireGroupWrite(), validate(updateGroupSchema), groupsController.update);
router.post('/reorder', requireTenantCapability('groups.manage'), groupsController.reorder);
// A group moved in the tree or deleted changes what its subtree inherits (policies): previewed (?dryRun=true),
// then a second factor or a second approver (202) when it changes the configuration of devices
// (mdm/policies/groupTree.ts; modele-donnees-mdm S12).
router.post('/:id/move', requireGroupWrite(), validate(moveGroupSchema), groupsController.move);
router.delete('/:id', requireGroupWrite(), groupsController.delete);

export default router;
