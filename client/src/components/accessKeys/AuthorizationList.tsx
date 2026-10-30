import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Bot, ChevronRight, RefreshCw } from 'lucide-react';
import { SocketEvents, type McpAuthorizationView } from '@obligarth/shared';
import { accessKeysApi } from '@/api/accessKeys.api';
import { IconButton } from '@/components/common/IconButton';
import { SegmentedTabs } from '@/components/common/SegmentedTabs';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { registerSocketListener } from '@/socket/socketListeners';
import { useTenantStore } from '@/store/tenantStore';
import { apiErrorMessage } from '@/utils/apiError';
import { AUTH_STATE_TONE, authStateLabel } from './accessKeyLabels';
import { RelativeDate } from './KeyList';

// The authorizations of the user's keys (docs: specs mcp-server §6.2, §6.5): the actions his AI agents asked and that
// wait for him (or were decided), every tenant. A row opens its page; one of another tenant switches tenant first
// (a hard navigation, as the live alerts do).

type Filter = 'pending' | 'all';

/** Opens the page of an authorization, switching to its tenant first when needed. */
export async function openAuthorization(navigate: (to: string) => void, a: { id: string; tenantId: number }): Promise<void> {
  const to = `/access-keys/authorizations/${a.id}`;
  const { currentTenantId, setCurrentTenant } = useTenantStore.getState();
  if (a.tenantId !== currentTenantId) {
    await setCurrentTenant(a.tenantId);
    window.location.href = to;
    return;
  }
  navigate(to);
}

export function AuthorizationList() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const tenants = useTenantStore((s) => s.tenants);
  const [filter, setFilter] = useState<Filter>('pending');
  const [rows, setRows] = useState<McpAuthorizationView[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    accessKeysApi.authorizations.list(filter).then((r) => { setRows(r); setError(null); })
      .catch((err) => { setRows((p) => p ?? []); setError(apiErrorMessage(err)); });
  }, [filter]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.MCP_AUTHORIZATION_CHANGED, () => load()), [load]);

  const tenantName = (id: number) => tenants.find((x) => x.id === id)?.name ?? `#${id}`;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <SegmentedTabs<Filter>
          size="sm"
          fill={false}
          value={filter}
          onChange={setFilter}
          tabs={[
            { id: 'pending', label: t('mcpAuthorizations.filter.pending') || 'Waiting for me' },
            { id: 'all', label: t('mcpAuthorizations.filter.all') || 'All' },
          ]}
        />
        <IconButton className="ml-auto" label={t('common.refresh') || 'Refresh'} icon={<RefreshCw className="h-4 w-4" />} onClick={load} />
      </div>
      <p className="text-xs text-text-muted">
        {t('mcpAuthorizations.intro') || 'A sensitive action asked by one of your AI agents never runs on its own: open it, check it, then approve it with your second factor (a code or your phone), or deny it.'}
      </p>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {rows === null ? <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? (
          <p className="text-sm text-text-muted">
            {filter === 'pending' ? (t('mcpAuthorizations.emptyPending') || 'No action waits for you.') : (t('mcpAuthorizations.empty') || 'No authorization yet.')}
          </p>
        ) : (
          <div className="overflow-hidden rounded-xl bg-bg-secondary">
            <ul>
              {rows.map((a) => (
                <li key={a.id}>
                  <button type="button" onClick={() => openAuthorization(navigate, a)}
                    className="flex w-full items-start gap-3 px-4 py-3 text-left text-sm transition-colors hover:bg-bg-tertiary">
                    <Bot size={16} className="mt-0.5 shrink-0 text-accent" />
                    <span className="min-w-0 flex-1 space-y-1">
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-text-primary">{a.summary}</span>
                        <StateBadge tone={AUTH_STATE_TONE[a.state]} label={authStateLabel(a.state)} pulse={a.state === 'pending'} />
                      </span>
                      <span className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-text-muted">
                        <span>{tenantName(a.tenantId)}</span>
                        <span>{t('mcpAuthorizations.key') || 'Key'}: {a.key.name}</span>
                        {a.agentIp && <span className="font-mono">{a.agentIp}</span>}
                        <span><RelativeDate iso={a.createdAt} /></span>
                        {a.state === 'pending' && (
                          <span className="text-amber-400">{t('mcpAuthorizations.expires') || 'Expires'} <RelativeDate iso={a.expiresAt} /></span>
                        )}
                      </span>
                    </span>
                    <ChevronRight size={16} className="mt-0.5 shrink-0 text-text-muted" />
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
    </div>
  );
}
