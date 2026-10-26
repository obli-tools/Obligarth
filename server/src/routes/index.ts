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
import softwareRepoRoutes from './softwareRepo.routes';
import repoPublicRoutes from './repoPublic.routes';
import reportRoutes from './report.routes';
import systemRoutes from './system.routes';
import permissionSetsRoutes from './permissionSets.routes';
import approvalRoutes from './approval.routes';
import auditRoutes from './audit.routes';
import restrictionRoutes from './restriction.routes';
import mobileAppRoutes from './mobileApp.routes';
import { createAppleCommandsRouter } from '../apple/commands';
import { defaultRuntime } from '../jobs';
import { createJobsAdmin } from '../jobs/admin';
import { createJobsAdminRouter } from '../jobs/admin.routes';
import { createOutboxAdminRouter } from '../jobs/outbox/admin.routes';
import { createVaultAdminRouter } from '../vault/admin.routes';
import { createOpsAdminRouter } from '../ops/routes';
import { createPrivacyRouter } from '../privacy';
import { createAuditAdminRouter } from '../audit/admin.routes';
import { createGuardRouter } from '../guard/routes';
import { createAppleEdgeAdminRouter } from '../apple/admin.routes';
import { createAppleDdmRouter } from '../apple/ddm/routes';
import { createAppleOperationsRouter } from '../apple/reconcile/routes';
import { createEnrollmentRouter } from '../apple/enrollment';
import { createAppleAdminIntegrationsRouter, createAppleIntegrationsRouter } from '../apple/integrations';
import { createMdmRouter } from '../mdm';
import { createAndroidAdminRouter } from '../android/routes/admin.routes';
import { createAndroidAppsRouter } from '../android/routes/apps.routes';
import { createAndroidByodRouter } from '../android/routes/byod.routes';
import { createAndroidCommandsRouter } from '../android/routes/commands.routes';
import { createAndroidConsoleRouter } from '../android/routes/console.routes';
import { createAndroidEnrollmentRouter } from '../android/routes/enrollment.routes';
import { createAndroidEnrollmentFlowsRouter } from '../android/routes/enrollmentFlows.routes';
import { createAndroidTenantRouter } from '../android/routes/enterprise.routes';
import { createAndroidInboxAdminRouter } from '../android/routes/inbox.routes';
import { createAndroidKioskRouter } from '../android/routes/kiosk.routes';
import { createAndroidOperationsAdminRouter, createAndroidOperationsRouter } from '../android/routes/operations.routes';
import { createAndroidSignupCallbackRouter } from '../android/routes/signupCallback.routes';
import { createLegacyAgentRouter } from '../legacyAgent/routes';
import { createLegacyAgentAdminRouter } from '../legacyAgent/admin.routes';

const router = Router();

// ── Public / auth ────────────────────────────────────────────────────────────
router.use('/auth', authRoutes);
router.use('/auth', obligateCallbackRoutes);  // sso-config, connected-apps, app-info (under /api/auth)
router.use('/mobile', mobileAppRoutes);    // Public: Android app version + APK download (/api/mobile/android/*)
router.use('/repo', repoPublicRoutes);   // script-facing software repo (per-tenant access key auth)
router.use('/system', systemRoutes);       // system info / about (admin only, no tenant required)
// Return of Google after the signup of an Android enterprise (android-amapi §6.2, AN48): public and mute, no session
// (the customer's administrator may have no account here), its own limiter, never logged (client/nginx.conf).
router.use('/android/signup', createAndroidSignupCallbackRouter());

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

// The device registry of the MDM (modele-donnees-mdm §10.6): devices, inventory, end users, fleet;
// /devices keeps the two timeline routes of the change events (Oblidesk's contract).
tenantRouter.use('/mdm',         createMdmRouter());
tenantRouter.use('/devices',     deviceRoutes);
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
// Guards against mass erasure (audit-durci §10.11): guarded actions, freeze,
// settings, designated approvers.
tenantRouter.use('/guard',       createGuardRouter());
// Enrollment profiles, links, invitations and sessions (integration-apple-edge §10.9; apple/enrollment/routes.ts),
// before the other /apple routers.
tenantRouter.use('/apple/enrollment', createEnrollmentRouter());
// The Apple integrations of the console: push certificate, ADE servers, deadlines, readiness (integration-apple-edge
// §11.6, lot C3; apple/integrations/routes.ts): its own paths only, each with its capability.
tenantRouter.use('/apple', createAppleIntegrationsRouter());
// The MDM command queue of the console (integration-apple-edge §8.12): actions and queue of a device, commands,
// cancellation, relaunch, timeline (apple/commands/routes.ts).
tenantRouter.use('/apple',       createAppleCommandsRouter());
// Operations (integration-apple-edge §13, lot C5): enrollments unknown to the brain (attach, release), the
// verified retirement of a device, the revocation of a stolen device's identity (apple/reconcile/routes.ts).
tenantRouter.use('/apple', createAppleOperationsRouter());
// Android (android-amapi §3.3, lot AN-A2): the enterprise of the tenant and its operation (mdm.integrations.manage),
// enrollment tokens, approvals, BYOD invitations, sign-in URL, zero-touch and KME (mdm.enrollment.manage and
// mdm.integrations.manage), apps of the catalog and iframes (mdm.apps.manage), commands and kiosks of a device
// (devices.manage); each router names its own capability. A tenant without a linked enterprise, or an instance with
// ANDROID_MODE off, is answered by the routes themselves (404, 409 or 503 androidDisabled).
tenantRouter.use('/android', createAndroidTenantRouter());
tenantRouter.use('/android', createAndroidOperationsRouter());
tenantRouter.use('/android', createAndroidEnrollmentRouter());
tenantRouter.use('/android', createAndroidEnrollmentFlowsRouter());
tenantRouter.use('/android', createAndroidByodRouter());
tenantRouter.use('/android', createAndroidAppsRouter());
tenantRouter.use('/android', createAndroidCommandsRouter());
tenantRouter.use('/android', createAndroidKioskRouter());
// The reads of the Android console (lot AN-C2): onboarding, policy catalog, tokens, approvals, device facet and menu.
tenantRouter.use('/android', createAndroidConsoleRouter());
// The platform side of Android (master tenant, platform administrators): identity, health, quota, orphan
// enterprises, deadline of the service account key.
tenantRouter.use('/admin/android', createAndroidAdminRouter());
tenantRouter.use('/admin/android', createAndroidOperationsAdminRouter());
// The dead letters of the Android inbox (lot AN-C2, section 7.2): list, audited detail, redrive, discard.
tenantRouter.use('/admin/android/inbox', createAndroidInboxAdminRouter());
// Background jobs administration (master tenant, platform administrators;
// jobs/admin.routes.ts), before /admin/config.
tenantRouter.use('/admin/jobs', createJobsAdminRouter(createJobsAdmin(defaultRuntime)));
// The apple-edge outbox consumer: state, dead letters (master tenant,
// platform administrators; jobs/outbox/admin.routes.ts).
tenantRouter.use('/admin/outbox', createOutboxAdminRouter());
// apple-edge: its state and the tenant registry (master tenant, platform
// administrators; apple/admin.routes.ts).
tenantRouter.use('/admin/apple-edge', createAppleEdgeAdminRouter());
// The deadlines of every tenant and of the instance (master tenant, platform administrators; lot C3).
tenantRouter.use('/admin/apple', createAppleAdminIntegrationsRouter());
// The DDM engine seen from the console: declaration set, status items, forced synchronisation of a device
// (apple/ddm/routes.ts).
tenantRouter.use('/apple', createAppleDdmRouter());
// The vault of secrets: state, escrow events, key rotations (master tenant,
// platform administrators; vault/admin.routes.ts).
tenantRouter.use('/admin/vault', createVaultAdminRouter());
// The observability of the instance: readiness in detail, metrics listener, backlog of the commands (master tenant,
// platform administrators; ops/routes.ts, P0-13 T8).
tenantRouter.use('/admin/ops', createOpsAdminRouter());
// The privacy profiles of the tenant (P0-13 T3, CNF-02): read with settings, audit.read or mdm.privacy.manage; a change
// is always an approval request (privacy/routes.ts).
tenantRouter.use('/privacy', createPrivacyRouter());
// The Android bridge agent (agent-pont-android §7): the console of the tenant, the platform's (versions of the agent,
// instance key, settings; master tenant, platform administrators).
tenantRouter.use('/legacy-agent', createLegacyAgentRouter());
tenantRouter.use('/admin/legacy-agent', createLegacyAgentAdminRouter());
// The hardened audit journal: retention, legal holds, SIEM destinations,
// seal keys (master tenant, platform administrators; audit/admin.routes.ts).
tenantRouter.use('/admin/audit', createAuditAdminRouter());
// A module's named platform settings are mounted before the core settings
// router (its PUT /:key would take their paths).
tenantRouter.use('/admin/config', adminRoutes);
tenantRouter.use('/admin/smtp-servers', smtpRoutes);
tenantRouter.use('/permission-sets', permissionSetsRoutes);
// Software licenses are dormant (design §6.1): license.routes.ts stays in the
// tree but is not mounted. No capability guards it (any member, viewer
// included, read and changed license keys); give it one before mounting it
// again.

router.use('/', tenantRouter);

export { router as routes };
