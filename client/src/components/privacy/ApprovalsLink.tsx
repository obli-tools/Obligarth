import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/store/authStore';

// The link of a request waiting for its approval (P0-13 T7) to the approvals of the Security page, shown only to whom
// that tab is shown (the rule of SecurityPage: a platform administrator, approvals.review or devices.manage); the others
// read the number of the request alone, beside it.
export function ApprovalsLink() {
  const { t } = useTranslation();
  const isPlatformAdmin = useAuthStore((s) => s.user?.role === 'admin');
  const caps = useAuthStore((s) => s.permissions?.tenantCapabilities ?? []);
  if (!isPlatformAdmin && !caps.includes('approvals.review') && !caps.includes('devices.manage')) return null;
  return <Link to="/admin/security?tab=approvals" className="text-xs text-accent hover:underline">{t('privacy.seeApprovals') || 'See the approvals'}</Link>;
}
