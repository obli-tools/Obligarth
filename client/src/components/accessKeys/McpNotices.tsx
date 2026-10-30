import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Bot, Globe, X } from 'lucide-react';
import { IconButton } from '@/components/common/IconButton';
import { useMcpAuthorizationsStore, livePending } from '@/store/mcpAuthorizationsStore';
import { useTenantStore } from '@/store/tenantStore';
import { openAuthorization } from './AuthorizationList';
import { RelativeDate } from './KeyList';

// The user's own section of the notification centre (docs: specs mcp-server §6.3): the actions his AI agents wait
// for him to approve (a click opens the page of the authorization, switching tenant when needed), and the notices of
// a key used from a new network. Nothing renders when there is nothing to show.

export function McpNotices({ onNavigate }: { onNavigate: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const pending = livePending(useMcpAuthorizationsStore((s) => s.pending));
  const notices = useMcpAuthorizationsStore((s) => s.notices);
  const dismissNotice = useMcpAuthorizationsStore((s) => s.dismissNotice);
  const tenants = useTenantStore((s) => s.tenants);
  if (pending.length === 0 && notices.length === 0) return null;
  const tenantName = (id: number) => tenants.find((x) => x.id === id)?.name ?? `#${id}`;

  return (
    <div className="divide-y divide-border/50 bg-accent/5">
      {pending.map((p) => (
        <button key={p.id} type="button"
          onClick={() => { onNavigate(); void openAuthorization(navigate, p); }}
          className="flex w-full items-start gap-2 px-4 py-2.5 text-left transition-colors hover:bg-bg-hover coarse:min-h-11">
          <Bot size={14} className="mt-0.5 shrink-0 text-accent" />
          <span className="min-w-0 flex-1">
            <span className="block text-xs font-medium text-text-primary">{t('mcpAuthorizations.notice') || 'An AI agent waits for your approval'}</span>
            <span className="block truncate text-xs text-text-secondary">{p.summary}</span>
            <span className="block text-[10px] text-text-muted">
              {tenants.length > 1 && <>{tenantName(p.tenantId)} · </>}
              {t('mcpAuthorizations.expires') || 'Expires'} <RelativeDate iso={p.expiresAt} />
            </span>
          </span>
        </button>
      ))}
      {notices.map((n) => (
        <div key={n.id} className="flex items-start gap-2 px-4 py-2.5">
          <Globe size={14} className="mt-0.5 shrink-0 text-amber-400" />
          <span className="min-w-0 flex-1">
            <span className="block text-xs font-medium text-text-primary">
              {t('accessKeys.newNetwork.title', { name: n.name }) || `Your key « ${n.name} » was used from a new network`}
            </span>
            <span className="block text-[11px] text-text-muted">
              <span className="font-mono">{n.ip}</span> · <RelativeDate iso={n.at} />
            </span>
            <span className="block text-[10px] text-text-muted">
              {t('accessKeys.newNetwork.hint') || 'If it was not you or your agent, revoke the key.'}
            </span>
          </span>
          <IconButton size="sm" label={t('common.close') || 'Close'} icon={<X size={12} />} onClick={() => dismissNotice(n.id)} />
        </div>
      ))}
    </div>
  );
}
