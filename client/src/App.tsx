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
import { SupervisionPage } from '@/pages/SupervisionPage';
import { GroupDetailPage } from '@/pages/GroupDetailPage';
import { GroupEditPage } from '@/pages/GroupEditPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { AdminUsersPage } from '@/pages/AdminUsersPage';
import { AdminDevicesPage } from '@/pages/AdminDevicesPage';
import { ProfilePage } from '@/pages/ProfilePage';
import { AdminTenantsPage } from '@/pages/AdminTenantsPage';
import { ApprovalsPage } from '@/pages/ApprovalsPage';
import { AuditLogPage } from '@/pages/AuditLogPage';
import { SecurityPage } from '@/pages/SecurityPage';
import { NotFoundPage } from '@/pages/NotFoundPage';
import { DownloadPage } from '@/pages/DownloadPage';
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
 {/* Minimal device record (registry fields) until the MDM device page. */}
 <Route path="/devices/:id" element={<DeviceSummaryPage />} />
 <Route path="/policies" element={<PoliciesPage />} />
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

 {/* Agent config — admin OR users with the agent_config:keys or
     agent_config:approval capability (the same pair the server
     accepts for the enrolment keys). */}
 <Route element={<ProtectedRoute requiredCapabilities={[
 'agent_config:keys',
 'agent_config:approval',
 ]} />}>
 <Route path="/admin/devices" element={<AdminDevicesPage />} />
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
