import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Clock, FileText, ShieldCheck } from 'lucide-react';
import { PageContainer } from '@/components/common/PageContainer';
import { SegmentedTabs } from '@/components/common/SegmentedTabs';
import { ProfilesTab } from '@/components/privacy/ProfilesTab';
import { RetentionTab } from '@/components/privacy/RetentionTab';
import { NoticeTab } from '@/components/privacy/NoticeTab';

// The privacy console of a tenant (P0-13 T7; CNF-02, CNF-04, USR-01), as three tabs: the privacy profiles per
// ownership, the retention of the data, the notice of the employees. Read by the holders of settings, audit.read (the
// DPO, the auditor) or mdm.privacy.manage (the route's gate, as the server's); changed with mdm.privacy.manage only (the
// profiles and the retention through a second person's approval, the notice directly). The tab is kept in the URL
// (?tab=profiles|retention|notice) so that a link (the readiness of the Integrations page) opens it.

type Tab = 'profiles' | 'retention' | 'notice';
const TABS: readonly Tab[] = ['profiles', 'retention', 'notice'];
const isTab = (v: string | null): v is Tab => v !== null && (TABS as readonly string[]).includes(v);

export function PrivacyPage() {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const asked = searchParams.get('tab');
  const [tab, setTab] = useState<Tab>(isTab(asked) ? asked : 'profiles');

  // A link to another tab of the page while it is open (the URL changes, the component stays).
  useEffect(() => { if (isTab(asked) && asked !== tab) setTab(asked); }, [asked]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (searchParams.get('tab') === tab) return;
    const next = new URLSearchParams(searchParams);
    next.set('tab', tab);
    setSearchParams(next, { replace: true });
  }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <PageContainer className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">{t('privacy.title') || 'Privacy'}</h1>
        <p className="mt-1 text-sm text-text-muted">
          {t('privacy.subtitle') || 'What the organisation collects from its devices, how long it keeps it, and what the employees are told before enrolling.'}
        </p>
      </div>
      <SegmentedTabs<Tab>
        tabs={[
          { id: 'profiles', label: t('privacy.tabs.profiles') || 'Profiles', icon: <ShieldCheck size={16} /> },
          { id: 'retention', label: t('privacy.tabs.retention') || 'Retention', icon: <Clock size={16} /> },
          { id: 'notice', label: t('privacy.tabs.notice') || 'Notice', icon: <FileText size={16} /> },
        ]}
        value={tab}
        onChange={setTab}
        ariaLabel={t('privacy.title') || 'Privacy'}
        tabClassName="max-sm:px-3"
      />
      <div role="tabpanel">
        {tab === 'profiles' && <ProfilesTab />}
        {tab === 'retention' && <RetentionTab />}
        {tab === 'notice' && <NoticeTab />}
      </div>
    </PageContainer>
  );
}
