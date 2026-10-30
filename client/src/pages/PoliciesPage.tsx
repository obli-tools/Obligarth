import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import toast from 'react-hot-toast';
import { Bell, Plus, RefreshCw, ScrollText, Search } from 'lucide-react';
import type { Policy, PolicyState, PolicyVersionState } from '@obligarth/shared';
import { POLICY_CATEGORIES, POLICY_CATEGORY_RE, SocketEvents } from '@obligarth/shared';
import { NotificationsPage } from './NotificationsPage';
import { mdmApi } from '@/api/mdm.api';
import { isStepUpHandled } from '@/api/client';
import { useAuthStore } from '@/store/authStore';
import { registerSocketListener } from '@/socket/socketListeners';
import { SegmentedTabs, type SegmentedTab } from '@/components/common/SegmentedTabs';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// Policies (modele-donnees-mdm §11.3): the list of the policies of the tenant with their state, their published
// version and their assignments; the notifications (channels and bindings, administrators) keep their tab. The
// catalog of applications comes with its lot (C4).

type Tab = 'policies' | 'notifications';

const POLICY_TONE: Record<PolicyState, 'green' | 'gray' | 'blue'> = { draft: 'blue', published: 'green', archived: 'gray' };
const POLICY_FALLBACK: Record<PolicyState, string> = { draft: 'Draft', published: 'Published', archived: 'Archived' };
export const policyStateLabel = (t: TFunction, s: PolicyState): string => t(`policies.state.${s}`) || POLICY_FALLBACK[s] || s;

const VERSION_FALLBACK: Record<PolicyVersionState, string> = {
  draft: 'Draft', pending_approval: 'Awaiting approval', published: 'Published', superseded: 'Superseded', rejected: 'Rejected',
};
export const versionStateLabel = (t: TFunction, s: PolicyVersionState): string => t(`policies.versionState.${s}`) || VERSION_FALLBACK[s] || s;
export const VERSION_TONE: Record<PolicyVersionState, 'green' | 'gray' | 'blue' | 'amber' | 'red'> = {
  draft: 'blue', pending_approval: 'amber', published: 'green', superseded: 'gray', rejected: 'red',
};
export const categoryLabel = (c: string): string => trCode(`policies.category.${c}`, c);

export function PoliciesPage() {
  const { t } = useTranslation();
  const { isAdmin } = useAuthStore();
  const admin = isAdmin();
  const [searchParams, setSearchParams] = useSearchParams();
  const asked = searchParams.get('tab');
  const [tab, setTabState] = useState<Tab>(asked === 'notifications' && admin ? 'notifications' : 'policies');
  const setTab = (next: Tab) => {
    setTabState(next);
    setSearchParams((prev) => { const p = new URLSearchParams(prev); p.set('tab', next); return p; }, { replace: true });
  };

  // Reading the policies needs no capability; "Notifications" (channels and bindings) is for administrators.
  const tabs: SegmentedTab<Tab>[] = [
    { id: 'policies', label: t('policies.tabPolicies') || 'Policies', icon: <ScrollText size={16} /> },
    { id: 'notifications', label: t('policies.tabNotifications', 'Notifications'), icon: <Bell size={16} />, hidden: !admin },
  ];

  return (
    <PageContainer className="space-y-6">
      <h1 className="text-2xl font-bold text-text-primary">{t('policies.title')}</h1>
      <SegmentedTabs tabs={tabs} value={tab} onChange={setTab} ariaLabel={t('policies.title')} />
      {tab === 'policies' && <PolicyList />}
      {tab === 'notifications' && admin && <NotificationsPage embedded />}
    </PageContainer>
  );
}

function PolicyList() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { isAdmin, permissions } = useAuthStore();
  const canManage = isAdmin() || (permissions?.tenantCapabilities ?? []).includes('mdm.policies.manage');
  const [policies, setPolicies] = useState<Policy[] | null>(null);
  const [state, setState] = useState<PolicyState | ''>('');
  const [q, setQ] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    mdmApi.listPolicies({ state: state || undefined, q: q.trim() || undefined })
      .then((list) => { setPolicies(list); setError(null); })
      .catch((err) => { setPolicies([]); setError(apiErrorMessage(err)); });
  }, [state, q]);
  useEffect(() => {
    const timer = setTimeout(load, 200);
    return () => clearTimeout(timer);
  }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.POLICY_CHANGED, () => load()), [load]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('policies.search') || 'Search a policy…'}
            className="w-full pl-9 pr-3 py-2 text-sm bg-bg-tertiary rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
        </div>
        {(['', 'published', 'draft', 'archived'] as const).map((s) => (
          <button key={s || 'all'} type="button" onClick={() => setState(s)}
            className={`px-2.5 py-1.5 text-xs font-medium rounded-full coarse:min-h-10 ${state === s ? 'bg-accent/15 text-accent' : 'text-text-muted hover:bg-bg-tertiary hover:text-text-primary'}`}>
            {s === '' ? (t('common.all') || 'All') : policyStateLabel(t, s)}
          </button>
        ))}
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
        {canManage && (
          <Button size="sm" className="ml-auto" onClick={() => setCreating(true)}>
            <Plus className="w-4 h-4 mr-1" />{t('policies.new') || 'New policy'}
          </Button>
        )}
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}

      {policies === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : policies.length === 0 ? (
          <div className="p-10 text-center bg-bg-secondary rounded-xl text-text-muted">
            <p className="font-medium text-text-primary mb-1">{t('policies.empty') || 'No policy yet'}</p>
            <p className="text-sm">{t('policies.emptyHint') || 'A policy groups settings, publishes them as immutable versions and applies them to the tenant, to groups or to devices.'}</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl bg-bg-secondary">
            <table className="w-full text-sm">
              <thead className="text-xs text-text-muted">
                <tr className="text-left">
                  <th className="font-medium px-4 py-2">{t('policies.name') || 'Name'}</th>
                  <th className="font-medium px-3 py-2">{t('policies.categoryLabel') || 'Category'}</th>
                  <th className="font-medium px-3 py-2">{t('common.status') || 'Status'}</th>
                  <th className="font-medium px-3 py-2">{t('policies.version') || 'Version'}</th>
                  <th className="font-medium px-3 py-2 text-right">{t('policies.assignments') || 'Assignments'}</th>
                  <th className="font-medium px-4 py-2">{t('policies.updated') || 'Updated'}</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={`${p.tenantId}-${p.id}`} className="border-t border-border/50 hover:bg-bg-tertiary cursor-pointer" onClick={() => navigate(`/policies/${p.id}`)}>
                    <td className="px-4 py-2.5">
                      <Link to={`/policies/${p.id}`} onClick={(e) => e.stopPropagation()} className="font-medium text-text-primary hover:text-accent">{p.name}</Link>
                      {p.shared && <span className="ml-2 text-[10px] uppercase px-1.5 py-0.5 rounded bg-violet-400/10 text-violet-400">{t('policies.shared') || 'library'}</span>}
                      {/* The section of the bridge agent (lot PONT-POL). */}
                      {p.sections.includes('legacy_agent') && <span className="ml-2 text-[10px] uppercase px-1.5 py-0.5 rounded bg-accent/10 text-accent">{t('legacyAgentPolicy.sectionChip') || 'Agent'}</span>}
                      {p.description && <span className="block text-xs text-text-muted truncate max-w-md">{p.description}</span>}
                    </td>
                    <td className="px-3 py-2.5 text-text-secondary">{categoryLabel(p.category)}</td>
                    <td className="px-3 py-2.5"><StateBadge tone={POLICY_TONE[p.state] ?? 'gray'} label={policyStateLabel(t, p.state)} /></td>
                    <td className="px-3 py-2.5 text-text-secondary">
                      {p.currentVersion ? `v${p.currentVersion}` : '—'}
                      {p.openVersion && (
                        <span className="ml-2 text-xs text-text-muted">
                          {versionStateLabel(t, p.openVersion.state)} v{p.openVersion.version}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-right tabular-nums text-text-secondary">{p.assignmentCount}</td>
                    <td className="px-4 py-2.5 text-xs text-text-muted">{formatDateTime(p.updatedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

      <CreatePolicyDialog open={creating} onClose={() => setCreating(false)} policies={policies ?? []} onCreated={(p) => navigate(`/policies/${p.id}`)} />
    </div>
  );
}

function CreatePolicyDialog({ open, onClose, policies, onCreated }: { open: boolean; onClose: () => void; policies: Policy[]; onCreated: (p: Policy) => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState<string>(POLICY_CATEGORIES[0]);
  const [copyFrom, setCopyFrom] = useState<number | ''>('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) { setName(''); setDescription(''); setCategory(POLICY_CATEGORIES[0]); setCopyFrom(''); } }, [open]);
  const ok = name.trim().length > 0 && POLICY_CATEGORY_RE.test(category);
  const create = async () => {
    setBusy(true);
    try {
      const out = await mdmApi.createPolicy({ name: name.trim(), description: description.trim() || null, category, copyFrom: copyFrom || null });
      toast.success(t('policies.created') || 'Policy created');
      onClose();
      onCreated(out.policy);
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  const field = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';
  return (
    <Modal
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      size="md"
      title={t('policies.new') || 'New policy'}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={create} loading={busy} disabled={!ok}>{t('common.create') || 'Create'}</Button>
        </>
      )}
    >
      <div className="space-y-3 text-sm">
        <label className="block">
          <span className="text-xs text-text-muted">{t('policies.name') || 'Name'}</span>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={200} className={field} autoFocus />
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('common.description') || 'Description'}</span>
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} maxLength={10000} className={field} />
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('policies.categoryLabel') || 'Category'}</span>
          <select value={category} onChange={(e) => setCategory(e.target.value)} className={field}>
            {POLICY_CATEGORIES.map((c) => <option key={c} value={c}>{categoryLabel(c)}</option>)}
          </select>
        </label>
        {policies.length > 0 && (
          <label className="block">
            <span className="text-xs text-text-muted">{t('policies.copyFrom') || 'Start from a copy of (optional)'}</span>
            <select value={copyFrom} onChange={(e) => setCopyFrom(e.target.value ? Number(e.target.value) : '')} className={field}>
              <option value="">{t('policies.copyFromNone') || 'An empty policy'}</option>
              {policies.map((p) => <option key={`${p.tenantId}-${p.id}`} value={p.id}>{p.name}</option>)}
            </select>
          </label>
        )}
      </div>
    </Modal>
  );
}
