import { useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { useNativeTopOffset } from '@/hooks/useNativeTopOffset';
import { useAuthStore } from '@/store/authStore';
import { ProtectedRoute } from '@/components/layout/ProtectedRoute';
import { AppLayout } from '@/components/layout/AppLayout';
import { LoginPage } from '@/pages/LoginPage';
import { EnrollmentPage } from '@/pages/EnrollmentPage';
import { ForgotPasswordPage } from '@/pages/ForgotPasswordPage';
import { ResetPasswordPage } from '@/pages/ResetPasswordPage';
import { DashboardPage } from '@/pages/DashboardPage';
import { DeviceListPage } from '@/pages/DeviceListPage';
import { DeviceSummaryPage } from '@/pages/DeviceSummaryPage';
import { PoliciesPage } from '@/pages/PoliciesPage';
import { AppsPage } from '@/pages/AppsPage';
import { PolicyEditorPage } from '@/pages/PolicyEditorPage';
import { EndUsersPage } from '@/pages/EndUsersPage';
import { DeviceEnrollmentPage } from '@/pages/DeviceEnrollmentPage';
import { IntegrationsPage } from '@/pages/IntegrationsPage';
import { SupervisionPage } from '@/pages/SupervisionPage';
import { GroupDetailPage } from '@/pages/GroupDetailPage';
import { GroupEditPage } from '@/pages/GroupEditPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { AdminUsersPage } from '@/pages/AdminUsersPage';
import { ProfilePage } from '@/pages/ProfilePage';
import { AdminTenantsPage } from '@/pages/AdminTenantsPage';
import { AndroidPlatformPage } from '@/pages/admin/AndroidPlatformPage';
import { AndroidZeroTouchPage } from '@/pages/AndroidZeroTouchPage';
import { AndroidAppsPage } from '@/pages/AndroidAppsPage';
import { AndroidManagedConfigPage } from '@/pages/AndroidManagedConfigPage';
import { ApprovalsPage } from '@/pages/ApprovalsPage';
import { AuditLogPage } from '@/pages/AuditLogPage';
import { SecurityPage } from '@/pages/SecurityPage';
import { NotFoundPage } from '@/pages/NotFoundPage';
import { DownloadPage } from '@/pages/DownloadPage';
import { LegacyAgentPage } from '@/pages/LegacyAgentPage';
import { TwoFactorGate } from '@/components/common/TwoFactorGate';
import { ConfirmProvider } from '@/components/common/ConfirmDialog';
import '@/i18n';

export default function App() {
 const { checkSession } = useAuthStore();
 const nativeTop = useNativeTopOffset();

 useEffect(() => {
 checkSession();
 }, [checkSession]);

 return (
 <BrowserRouter>
 <Routes>
 {/* Public */}
 <Route path="/login" element={<LoginPage />} />
 <Route path="/forgot-password" element={<ForgotPasswordPage />} />
 <Route path="/reset-password" element={<ResetPasswordPage />} />
 {/* Protected */}
 <Route element={<ProtectedRoute />}>
 <Route path="/enroll" element={<EnrollmentPage />} />
 <Route element={<AppLayout />}>
 {/* Main */}
 <Route path="/" element={<DashboardPage />} />
 <Route path="/devices" element={<DeviceListPage />} />
 {/* The record of a device: overview, configuration, inventory, commands, history, actions. */}
 <Route path="/devices/:id" element={<DeviceSummaryPage />} />
 {/* Policies: any member reads them; writing needs mdm.policies.manage (checked by the pages and the server). */}
 <Route path="/policies" element={<PoliciesPage />} />
 <Route path="/policies/:id" element={<PolicyEditorPage />} />
 {/* Apps (lot C4): any member reads the catalog; writing needs mdm.apps.manage (checked by the page and the server). */}
 <Route path="/apps" element={<AppsPage />} />
 {/* The Android bridge agent (agent-pont-android §7): any member reads; the API checks each capability. */}
 <Route path="/legacy-agent" element={<LegacyAgentPage />} />
 {/* Groups */}
 <Route path="/group/:id" element={<GroupDetailPage />} />
 <Route path="/group/:id/edit" element={<GroupEditPage />} />
 {/* User */}
 <Route path="/profile" element={<ProfilePage />} />
 <Route path="/download" element={<DownloadPage />} />

 {/* Admin-only — Settings / Users / Tenants / Audit / Security
     remain locked to platform admins. */}
 <Route element={<ProtectedRoute requiredRole="admin" />}>
 <Route path="/settings" element={<SettingsPage />} />
 <Route path="/admin/users" element={<AdminUsersPage />} />
 <Route path="/admin/tenants" element={<AdminTenantsPage />} />
 {/* Renamed: /workspace replaces /admin/tenants in the new sidebar
     ("Workspace" reads more like "the platform partition" than
     "tenants admin"). Old URL kept as alias above so external
     bookmarks / saved deep-links keep resolving. */}
 <Route path="/workspace" element={<AdminTenantsPage />} />
 {/* Platform > Android (android-amapi §12.1, lot AN-A2): identity and health of the link to Google (the server
     answers the platform administrators of the master tenant only). */}
 <Route path="/admin/android" element={<AndroidPlatformPage />} />
 </Route>

 {/* Security — the journal for the holders of audit.read (tenant
     administrators, the client sets approver and auditor), the
     approvals; platform administrators always. */}
 <Route element={<ProtectedRoute requiredCapabilities={['audit.read', 'approvals.review', 'devices.manage']} />}>
 <Route path="/admin/audit-log" element={<AuditLogPage />} />
 <Route path="/admin/security" element={<SecurityPage />} />
 </Route>

 {/* Supervision — admin OR users with `supervision:read`. */}
 <Route element={<ProtectedRoute requiredCapabilities={['supervision:read']} />}>
 <Route path="/admin/supervision" element={<SupervisionPage />} />
 </Route>

 {/* End users — the reader gate of /api/mdm/end-users (users.manage or devices.manage). */}
 <Route element={<ProtectedRoute requiredCapabilities={['users.manage', 'devices.manage']} />}>
 <Route path="/end-users" element={<EndUsersPage />} />
 </Route>

 {/* Apple integrations: push certificate, ADE servers, deadlines, readiness (settings or mdm.integrations.manage). */}
 <Route element={<ProtectedRoute requiredCapabilities={['settings', 'mdm.integrations.manage']} />}>
  <Route path="/integrations" element={<IntegrationsPage />} />
  {/* The zero-touch portal of Google, embedded (android-amapi §10.5, lot AN-C2): its path is the parentFrameUrl. */}
  <Route path="/enrollment/android/zero-touch" element={<AndroidZeroTouchPage />} />
 </Route>
 {/* Device enrollment: profiles, links, invitations, sessions (mdm.enrollment.manage). */}
 {/* Android apps (lot AN-E): managed Google Play iframes, catalog and managed configuration (mdm.apps.manage). */}
 <Route element={<ProtectedRoute requiredCapabilities={['mdm.apps.manage']} />}>
  <Route path="/apps/android" element={<AndroidAppsPage />} />
  <Route path="/apps/android/:uuid/managed-config" element={<AndroidManagedConfigPage />} />
 </Route>
 <Route element={<ProtectedRoute requiredCapabilities={['mdm.enrollment.manage']} />}>
  <Route path="/device-enrollment" element={<DeviceEnrollmentPage />} />
 </Route>
 {/* The approval queue on its own (the Security page embeds it): its reviewers, and the members who
     may request a restricted action. */}
 <Route element={<ProtectedRoute requiredCapabilities={['approvals.review', 'devices.manage', 'mdm.policies.manage']} />}>
 <Route path="/admin/approvals" element={<ApprovalsPage />} />
 </Route>
 </Route>
 </Route>

 <Route path="*" element={<NotFoundPage />} />
 </Routes>

 <Toaster
 position="top-right"
 // Safe-area offsets (status bar / notch / gesture bar in the Android
 // shell, landscape cut-outs). The insets are 0 on desktop, so these
 // resolve to react-hot-toast's own 16 px defaults (or the ObliTools
 // tab-bar offset) — same position as before.
 containerStyle={{
 top: `calc(${nativeTop ? nativeTop + 8 : 16}px + var(--safe-top))`,
 right: 'calc(16px + var(--safe-right))',
 bottom: 'calc(16px + var(--safe-bottom))',
 left: 'calc(16px + var(--safe-left))',
 }}
 toastOptions={{
 className: '!bg-bg-secondary !text-text-primary !border !border-transparent',
 duration: 4000,
 }}
 />

 {/* Singleton modal that pops whenever the server replies
 401 twoFactorRequired — no need to wire anything at call sites. */}
 <TwoFactorGate />
 {/* Host for useConfirm() / usePrompt() / confirmDialog() / promptDialog()
 (docs/obli-mobile.md §8) — replaces window.confirm / window.prompt. */}
 <ConfirmProvider />
 </BrowserRouter>
 );
}
