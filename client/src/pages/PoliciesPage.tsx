import { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Bell } from 'lucide-react';
import { NotificationsPage } from './NotificationsPage';
import { useAuthStore } from '@/store/authStore';
import { SegmentedTabs, type SegmentedTab } from '@/components/common/SegmentedTabs';
import { PageContainer } from '@/components/common/PageContainer';

type Tab = 'notifications';

// ─── Policies Page ───────────────────────────────────────────────────────────

export function PoliciesPage() {
 const { t } = useTranslation();
 const { isAdmin } = useAuthStore();
 const admin = isAdmin();
 const [tab, setTab] = useState<Tab>('notifications');

 // "Notifications" is admin-only (channels + bindings, an operational
 // concern that used to live under /admin/users). It is the only tab left
 // for now: without it the container is empty and its menu entry hidden.
 const tabs: SegmentedTab<Tab>[] = admin
 ? [{ id: 'notifications', label: t('policies.tabNotifications', 'Notifications'), icon: <Bell size={16} /> }]
 : [];

 if (tabs.length === 0) return <Navigate to="/" replace />;

 return (
 <PageContainer className="space-y-6">
 <h1 className="text-2xl font-bold text-text-primary">{t('policies.title')}</h1>
 <SegmentedTabs tabs={tabs} value={tab} onChange={setTab} ariaLabel={t('policies.title')} />
 {tab === 'notifications' && <NotificationsPage embedded />}
 </PageContainer>
 );
}
