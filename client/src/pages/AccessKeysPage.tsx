import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Bot, KeyRound, Plus } from 'lucide-react';
import type { AccessKeyView } from '@obligarth/shared';
import { accessKeysApi } from '@/api/accessKeys.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { PageContainer } from '@/components/common/PageContainer';
import { SegmentedTabs } from '@/components/common/SegmentedTabs';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { AuthorizationList } from '@/components/accessKeys/AuthorizationList';
import { CreateKeyModal } from '@/components/accessKeys/CreateKeyModal';
import { KeyList } from '@/components/accessKeys/KeyList';
import { TenantKeysList } from '@/components/accessKeys/TenantKeysList';
import { useAuthStore } from '@/store/authStore';
import { useMcpAuthorizationsStore, livePending } from '@/store/mcpAuthorizationsStore';
import { apiErrorMessage } from '@/utils/apiError';

// Access keys of the MCP server (docs: specs mcp-server §6.5, owner decision 4): the personal keys an AI agent uses
// to act as the user (holders of mcp.access_keys; a platform administrator passes), the authorizations their
// sensitive actions wait for, and, for the managers of the tenant (users.manage), the keys that reach it.

type Tab = 'keys' | 'authorizations' | 'tenant';
const TABS: Tab[] = ['keys', 'authorizations', 'tenant'];

export function AccessKeysPage() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [params, setParams] = useSearchParams();
  const { isAdmin, permissions } = useAuthStore();
  const caps = permissions?.tenantCapabilities ?? [];
  // The page is open to the holders of mcp.access_keys (their keys) and to the managers of the tenant (its keys).
  const canKeys = isAdmin() || caps.includes('mcp.access_keys');
  const canOversee = isAdmin() || caps.includes('users.manage');
  const requested = params.get('tab') as Tab | null;
  const allowed = (x: Tab) => (x === 'tenant' ? canOversee : x === 'keys' ? canKeys : true);
  const tab: Tab = requested && TABS.includes(requested) && allowed(requested) ? requested
    : canKeys ? 'keys' : canOversee ? 'tenant' : 'authorizations';
  const setTab = (next: Tab) => setParams(next === 'keys' ? {} : { tab: next }, { replace: true });
  const pendingCount = useMcpAuthorizationsStore((s) => livePending(s.pending).length);

  const [keys, setKeys] = useState<AccessKeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    accessKeysApi.list().then((r) => { setKeys(r); setError(null); })
      .catch((err) => { setKeys((p) => p ?? []); setError(apiErrorMessage(err)); });
  }, []);
  useEffect(() => { if (canKeys) load(); }, [load, canKeys]);

  const revoke = async (k: AccessKeyView) => {
    const ok = await confirm({
      title: t('accessKeys.revokeTitle') || 'Revoke the key',
      message: t('accessKeys.revokeConfirm', { name: k.name }) || `The key « ${k.name} » stops working at once, and the actions it asked that still wait are cancelled. This cannot be undone.`,
      confirmLabel: t('accessKeys.list.revoke') || 'Revoke',
      danger: true,
    });
    if (!ok) return;
    try {
      await accessKeysApi.revoke(k.id);
      toast.success(t('accessKeys.revoked') || 'Key revoked.');
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err));
    }
  };

  const active = (keys ?? []).filter((k) => k.state === 'active');
  const inactive = (keys ?? []).filter((k) => k.state !== 'active');
  const shown = showRevoked ? [...active, ...inactive] : active;

  return (
    <PageContainer className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <KeyRound size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-text-primary">{t('accessKeys.title') || 'Access keys for AI agents'}</h1>
        {tab === 'keys' && canKeys && (
          <Button size="sm" className="ml-auto" onClick={() => setCreating(true)}>
            <Plus size={14} className="mr-1" />{t('accessKeys.new') || 'New key'}
          </Button>
        )}
      </div>
      <p className="text-sm text-text-muted">
        {t('accessKeys.intro') || 'An AI agent such as Claude Code connects to Obligarth\'s MCP server with one of your keys and acts as you, for diagnosis and remediation: never more than your current rights, limited to the key\'s rights and perimeter. Sensitive actions always wait for your approval with a second factor.'}
      </p>
      <SegmentedTabs<Tab>
        value={tab}
        onChange={setTab}
        tabs={[
          { id: 'keys', label: t('accessKeys.tabs.keys') || 'My keys', icon: <KeyRound size={14} />, hidden: !canKeys },
          {
            id: 'authorizations',
            label: t('accessKeys.tabs.authorizations') || 'Authorizations',
            icon: <Bot size={14} />,
            badge: pendingCount > 0 ? <span className="rounded-full bg-red-500 px-1.5 text-[10px] font-bold text-white">{pendingCount}</span> : undefined,
          },
          { id: 'tenant', label: t('accessKeys.tabs.tenant') || 'Keys of this tenant', hidden: !canOversee },
        ]}
      />

      {tab === 'keys' && canKeys && (
        <div className="space-y-3">
          {error && <p className="text-sm text-red-400">{error}</p>}
          {keys === null ? <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>
            : shown.length === 0 ? (
              <div className="rounded-xl bg-bg-secondary p-6 text-center text-sm text-text-muted">
                {t('accessKeys.empty') || 'No active key. Create one to connect an AI agent.'}
              </div>
            ) : <KeyList keys={shown} onRevoke={revoke} />}
          {inactive.length > 0 && (
            <Button variant="ghost" size="sm" onClick={() => setShowRevoked((v) => !v)}>
              {showRevoked
                ? (t('accessKeys.hideInactive') || 'Hide revoked and expired keys')
                : (t('accessKeys.showInactive', { count: inactive.length }) || `Show revoked and expired keys (${inactive.length})`)}
            </Button>
          )}
        </div>
      )}
      {tab === 'authorizations' && <AuthorizationList />}
      {tab === 'tenant' && canOversee && <TenantKeysList />}

      <CreateKeyModal open={creating} onClose={() => setCreating(false)} onCreated={load} />
    </PageContainer>
  );
}
