import { useTranslation } from 'react-i18next';
import { Snowflake } from 'lucide-react';
import type { GuardSettingsDto } from '@obligarth/shared';

// The emergency freeze of the tenant (audit-durci §10.7): while it lasts, no
// guarded action is requested nor approved, and apple-edge delivers none of
// the tenant's commands. Unfreezing needs a second person.

export function FreezeBanner({ settings, onUnfreeze }: { settings: GuardSettingsDto | null; onUnfreeze?: () => void }) {
  const { t } = useTranslation();
  if (!settings?.frozen) return null;
  const since = settings.frozenAt ? new Date(settings.frozenAt).toLocaleString() : '';
  return (
    <div className="mb-3 rounded border border-sky-400/40 bg-sky-400/10 px-3 py-2 text-sm text-sky-200 flex items-start gap-2">
      <Snowflake className="w-4 h-4 mt-0.5 shrink-0 text-sky-300" />
      <div className="flex-1 min-w-0">
        <p className="font-medium">
          {settings.frozenSource === 'anomaly'
            ? (t('guard.freeze.bannerAnomaly', { since }) || `Tenant frozen automatically (anomaly) since ${since}`)
            : (t('guard.freeze.banner', { since }) || `Tenant frozen since ${since}`)}
        </p>
        {settings.frozenReason && <p className="text-xs opacity-80 break-words">{settings.frozenReason}</p>}
        <p className="text-xs opacity-80">{t('guard.freeze.effects') || 'No guarded action is possible and no MDM command is delivered until the tenant is unfrozen (second approver).'}</p>
      </div>
      {onUnfreeze && (
        <button
          type="button"
          onClick={onUnfreeze}
          className="shrink-0 text-xs px-2.5 py-1 rounded border border-sky-300/40 hover:bg-sky-300/10 coarse:min-h-10"
        >
          {t('guard.freeze.unfreeze') || 'Request unfreeze'}
        </button>
      )}
    </div>
  );
}
