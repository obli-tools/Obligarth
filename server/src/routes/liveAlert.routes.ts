import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireTenant } from '../middleware/tenant';
import { memberScope } from '../middleware/dbContext';
import * as ctrl from '../controllers/liveAlert.controller';

export const liveAlertRouter = Router();

// All tenants accessible by this user (no requireTenant — cross-tenant):
// database context 'member', the user's tenants computed by the database.
liveAlertRouter.get('/all', requireAuth, memberScope(), ctrl.getAllTenantAlerts);

// Current-tenant endpoints
liveAlertRouter.get('/', requireAuth, requireTenant, ctrl.getAlerts);
liveAlertRouter.post('/read-all', requireAuth, requireTenant, ctrl.markAllRead);
liveAlertRouter.delete('/', requireAuth, requireTenant, ctrl.clearAll);

// Cross-tenant by alert id (ownership verified inside controller: read in
// the context 'member', written in the context of the alert's tenant)
liveAlertRouter.patch('/:id/read', requireAuth, ctrl.markRead);
liveAlertRouter.delete('/:id', requireAuth, ctrl.deleteAlert);
