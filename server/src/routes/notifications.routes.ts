import { Router } from 'express';
import { notificationsController } from '../controllers/notifications.controller';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import { globalViewScope } from '../middleware/dbContext';
import {
  createChannelSchema,
  updateChannelSchema,
  addBindingSchema,
  removeBindingSchema,
} from '../validators/notification.schema';

const router = Router();

router.use(requireAuth);
router.use(requireRole('admin'));

// Plugin info
router.get('/plugins', notificationsController.plugins);

// Channels CRUD. The reads (and the test, which only reads and sends)
// accept the master tenant's global view (context 'platform'); the writes
// stay on the channels the session's tenant owns.
router.get('/channels', globalViewScope('console.notifications'), notificationsController.listChannels);
router.get('/channels/:id', globalViewScope('console.notifications'), notificationsController.getChannel);
router.post('/channels', validate(createChannelSchema), notificationsController.createChannel);
router.put('/channels/:id', validate(updateChannelSchema), notificationsController.updateChannel);
router.delete('/channels/:id', notificationsController.deleteChannel);
router.post('/channels/:id/test', globalViewScope('console.notifications'), notificationsController.testChannel);
router.get('/channels/:id/tenants', globalViewScope('console.notifications'), notificationsController.getChannelTenants);
router.put('/channels/:id/tenants', notificationsController.setChannelTenants);

// Bindings
router.get('/bindings/resolved', globalViewScope('console.notifications'), notificationsController.resolvedBindings);
router.get('/bindings', globalViewScope('console.notifications'), notificationsController.listBindings);
router.post('/bindings', validate(addBindingSchema), notificationsController.addBinding);
router.delete('/bindings', validate(removeBindingSchema), notificationsController.removeBinding);

export default router;
