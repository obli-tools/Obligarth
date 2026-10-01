import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireTenant } from '../middleware/tenant';
import { delegatedAuth } from '../middleware/delegatedAuth';

// Route imports
import authRoutes from './auth.routes';
import twoFactorRoutes from './twoFactor.routes';
import deviceKeyRoutes from './deviceKey.routes';
import obligateCallbackRoutes from './obligateCallback.routes';
import profileRoutes from './profile.routes';
import tenantRoutes from './tenant.routes';
import usersRoutes from './users.routes';
import teamsRoutes from './teams.routes';
import groupsRoutes from './groups.routes';
import settingsRoutes from './settings.routes';
import notificationsRoutes from './notifications.routes';
import maintenanceRoutes from './maintenance.routes';
import { liveAlertRouter as liveAlertsRoutes } from './liveAlert.routes';
import adminRoutes from './appConfig.routes';
import smtpRoutes from './smtpServer.routes';

// Devices and the other tenant-scoped modules
import deviceRoutes from './device.routes';
import inventoryRoutes from './inventory.routes';
import softwareRepoRoutes from './softwareRepo.routes';
import repoPublicRoutes from './repoPublic.routes';
import reportRoutes from './report.routes';
import agentAdminRoutes from './agentAdmin.routes';
import systemRoutes from './system.routes';
import permissionSetsRoutes from './permissionSets.routes';
import approvalRoutes from './approval.routes';
import auditRoutes from './audit.routes';
import restrictionRoutes from './restriction.routes';
import mobileAppRoutes from './mobileApp.routes';

const router = Router();

// ── Public / auth ────────────────────────────────────────────────────────────
router.use('/auth', authRoutes);
router.use('/auth', obligateCallbackRoutes);  // sso-config, connected-apps, app-info (under /api/auth)
router.use('/mobile', mobileAppRoutes);    // Public: Android app version + APK download (/api/mobile/android/*)
router.use('/repo', repoPublicRoutes);   // script-facing software repo (per-tenant access key auth)
router.use('/system', systemRoutes);       // system info / about (admin only, no tenant required)

// ── Authenticated, no tenant required ───────────────────────────────────────
// Device-bound 2FA (the account's phones) — before /profile. A 404 here tells
// the Android app that this server has no device keys.
router.use('/profile/device-keys', requireAuth, deviceKeyRoutes);
router.use('/profile/2fa', twoFactorRoutes); // must be before /profile (auth handled inside twoFactorRoutes)
router.use('/profile', requireAuth, profileRoutes);
router.use('/tenants', requireAuth, tenantRoutes);
router.use('/tenant', requireAuth, tenantRoutes);
router.use('/live-alerts', requireAuth, liveAlertsRoutes);

// ── Authenticated + tenant scoped ────────────────────────────────────────────
const tenantRouter = Router();

// Cross-app delegated reads. A short-lived Obligate-signed token naming a USER
// stands in for the session on a small allowlist of device read routes, and
// resolves to the local Obligarth user, so requireAuth / requireTenant and every
// RBAC guard below run against that user unchanged. Registered before
// requireAuth because it is an alternative credential, not an extra check;
// requests without the header fall straight through to the session path.
// See middleware/delegatedAuth.ts.
tenantRouter.use('/devices', delegatedAuth);

tenantRouter.use(requireAuth, requireTenant);

tenantRouter.use('/devices',     deviceRoutes);
tenantRouter.use('/inventory',   inventoryRoutes);
tenantRouter.use('/software-repo', softwareRepoRoutes);
tenantRouter.use('/reports',     reportRoutes);
tenantRouter.use('/groups',      groupsRoutes);
tenantRouter.use('/settings',    settingsRoutes);
tenantRouter.use('/notifications', notificationsRoutes);
tenantRouter.use('/users',       usersRoutes);
tenantRouter.use('/teams',       teamsRoutes);
tenantRouter.use('/maintenance', maintenanceRoutes);
tenantRouter.use('/approvals',   approvalRoutes);
tenantRouter.use('/audit-log',   auditRoutes);
tenantRouter.use('/restrictions', restrictionRoutes);
// A module's named platform settings are mounted before the core settings
// router (its PUT /:key would take their paths).
tenantRouter.use('/admin/config', adminRoutes);
tenantRouter.use('/admin/smtp-servers', smtpRoutes);
tenantRouter.use('/agent',       agentAdminRoutes);  // admin: API key management
tenantRouter.use('/permission-sets', permissionSetsRoutes);
// Software licenses are dormant (design §6.1): license.routes.ts stays in the
// tree but is not mounted. No capability guards it (any member, viewer
// included, read and changed license keys); give it one before mounting it
// again.

router.use('/', tenantRouter);

export { router as routes };
