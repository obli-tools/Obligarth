import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { KeyRound, LogOut } from 'lucide-react';
import type { TenantOversightKeyView } from '@obligarth/shared';
import { accessKeysApi } from '@/api/accessKeys.api';
import { isStepUpHandled } from '@/api/client';
import { IconButton } from '@/components/common/IconButton';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { apiErrorMessage } from '@/utils/apiError';
import { maskedToken } from './accessKeyLabels';
import { RelativeDate, ScopePills } from './KeyList';

// The keys that reach the current tenant, for its managers (users.manage; docs: specs mcp-server §6.1, decision D6):
// owner, name, rights, expiry, last use. No address is shown. A manager can take his tenant out of a key (the key
// keeps working in its other tenants).

export function TenantKeysList() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [rows, setRows] = useState<TenantOversightKeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    accessKeysApi.tenantOversight.list().then((r) => { setRows(r); setError(null); })
      .catch((err) => { setRows((p) => p ?? []); setError(apiErrorMessage(err)); });
  }, []);
  useEffect(() => { load(); }, [load]);

  const exclude = async (k: TenantOversightKeyView) => {
    const ok = await confirm({
      title: t('accessKeys.tenant.excludeTitle') || 'Exclude this tenant from the key',
      message: t('accessKeys.tenant.excludeConfirm', { name: k.name, owner: k.owner.username ?? `#${k.owner.userId}` })
        || `The key « ${k.name} » of ${k.owner.username ?? `#${k.owner.userId}`} will no longer reach this tenant. Its actions waiting here are cancelled. This cannot be undone.`,
      confirmLabel: t('accessKeys.tenant.exclude') || 'Exclude from this tenant',
      danger: true,
    });
    if (!ok) return;
    try {
      await accessKeysApi.tenantOversight.exclude(k.id);
      toast.success(t('accessKeys.tenant.excluded') || 'This tenant is excluded from the key.');
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err));
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-xs text-text-muted">
        {t('accessKeys.tenant.intro') || 'The access keys of the users that can reach this tenant now. Each key acts as its owner, within his rights here.'}
      </p>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {rows === null ? <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? <p className="text-sm text-text-muted">{t('accessKeys.tenant.empty') || 'No access key reaches this tenant.'}</p> : (
          <div className="overflow-hidden rounded-xl bg-bg-secondary">
            <div className="hidden grid-cols-[minmax(0,2fr)_minmax(0,3fr)_minmax(0,2fr)_auto] gap-3 bg-bg-tertiary/50 px-4 py-2 text-[10px] uppercase tracking-wider text-text-muted md:grid">
              <span>{t('accessKeys.tenant.owner') || 'Owner and key'}</span>
              <span>{t('accessKeys.list.scopes') || 'Rights'}</span>
              <span>{t('accessKeys.list.usage') || 'Expiry and use'}</span>
              <span className="w-8" />
            </div>
            <ul>
              {rows.map((k) => (
                <li key={k.id} className="grid gap-3 px-4 py-3 text-sm transition-colors hover:bg-bg-tertiary md:grid-cols-[minmax(0,2fr)_minmax(0,3fr)_minmax(0,2fr)_auto]">
                  <div className="min-w-0 space-y-0.5">
                    <p className="truncate font-medium text-text-primary">{k.owner.username ?? `#${k.owner.userId}`}</p>
                    <p className="flex items-center gap-1.5 truncate text-[11px] text-text-secondary">
                      <KeyRound size={11} className="shrink-0 text-text-muted" />{k.name}
                    </p>
                    <p className="truncate font-mono text-[10px] text-text-muted">{maskedToken(k.id)}</p>
                  </div>
                  <ScopePills scopes={k.scopes} />
                  <div className="space-y-0.5 text-[11px] text-text-secondary">
                    <p><span className="text-text-muted">{t('accessKeys.list.expires') || 'Expires'} </span><RelativeDate iso={k.expiresAt} /></p>
                    <p><span className="text-text-muted">{t('accessKeys.list.lastUsed') || 'Last used'} </span><RelativeDate iso={k.lastUsedAt} empty={t('common.never') || 'Never'} /></p>
                  </div>
                  <div className="flex items-start justify-end">
                    <IconButton label={t('accessKeys.tenant.exclude') || 'Exclude from this tenant'} variant="danger" icon={<LogOut className="h-4 w-4" />} onClick={() => exclude(k)} />
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
    </div>
  );
}
