import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Package } from 'lucide-react';
import type { LegacyAgentRequiredAppState, LegacyAgentRequiredAppsView } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { unavailableLabel } from '@/components/mdm/DeviceConfigurationTab';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The required apps of a bridge device (agent:requiredApp[<package>]): for each app its effective policy requires, the
// server's state (installed, queued, waiting for the inventory, next run, retry later, failed, set aside and why), the
// failed attempts of the job, its next attempt and the source policy. Read only, computed by the server on read with the
// same decision as the job legacy-agent.required-apps. Nothing is shown when no policy of the device requires an app.

const STATE_TONE: Record<LegacyAgentRequiredAppState, 'green' | 'gray' | 'blue' | 'amber' | 'red' | 'violet'> = {
  installed: 'green', queued: 'blue', awaiting_inventory: 'blue', due: 'violet', backoff: 'amber', failed: 'red', skipped: 'gray',
};

export function LegacyRequiredAppsBlock({ deviceId, refreshKey }: { deviceId: number; refreshKey: number }) {
  const { t } = useTranslation();
  const [view, setView] = useState<LegacyAgentRequiredAppsView | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    legacyAgentApi.deviceRequiredApps(deviceId)
      .then((v) => { if (live) { setView(v); setError(null); } })
      .catch((err) => { if (live) setError(apiErrorMessage(err)); });
    return () => { live = false; };
  }, [deviceId, refreshKey]);

  const errorBanner = error ? <p role="alert" className="text-sm text-red-400">{error}</p> : null;
  if (!view || view.items.length === 0) return errorBanner;
  const modeLabel = (m: string) => (m === 'minVersion'
    ? (t('legacyAgentPolicy.requiredApps.modes.minVersion') || 'Install or update to this version')
    : (t('legacyAgentPolicy.requiredApps.modes.install') || 'Install if missing'));

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold text-text-primary">{t('legacyAgentPolicy.requiredApps.device.title') || 'Required apps'}</h3>
      {errorBanner}
      <ul className="divide-y divide-border/50 rounded-xl bg-bg-secondary">
        {view.items.map((i) => (
          <li key={`${i.packageName}-${i.packageId}`} className="space-y-1 px-3 py-2 text-sm hover:bg-bg-tertiary">
            <div className="flex flex-wrap items-center gap-2">
              <Package className="h-4 w-4 text-text-muted" />
              <span className="text-text-primary">{i.package?.label ?? i.packageName}</span>
              <span className="font-mono text-[11px] text-text-muted">{i.packageName}</span>
              <span className="text-[11px] text-text-muted">{modeLabel(i.mode)}</span>
              <span className="ml-auto">
                <StateBadge tone={STATE_TONE[i.state] ?? 'gray'} label={trCode(`legacyAgentPolicy.requiredApps.states.${i.state}`, i.state)} pulse={i.state === 'queued'} />
              </span>
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-text-secondary">
              <span>{t('legacyAgentPolicy.requiredApps.device.target') || 'Target'}: {i.package ? `v${i.package.versionName ?? i.package.versionCode}` : '—'}</span>
              <span>{t('legacyAgentPolicy.requiredApps.device.installed') || 'Installed'}: {i.installed ? `v${i.installed.versionName ?? i.installed.versionCode ?? '?'}` : '—'}</span>
              {i.reason && (
                <span className="text-amber-400">
                  {trCode(`legacyAgentPolicy.requiredApps.reasons.${i.reason}`, i.reason)}
                  {i.reason === 'not_applicable' && i.detail ? ` (${unavailableLabel(t, i.detail)})` : ''}
                </span>
              )}
              {i.attempts > 0 && (
                <span className="text-red-400">{t('legacyAgentPolicy.requiredApps.device.attempts', { count: i.attempts, max: i.maxAttempts }) || `Failed ${i.attempts}/${i.maxAttempts}`}</span>
              )}
              {i.state === 'failed' && (
                <span className="text-text-muted">{t('legacyAgentPolicy.requiredApps.device.rearm') || 'To try again now: install it by hand from the device page, or choose another package in the policy.'}</span>
              )}
              {i.nextAttemptAt && <span>{`${t('legacyAgentPolicy.requiredApps.device.nextAttempt') || 'Next attempt'} ${formatDateTime(i.nextAttemptAt)}`}</span>}
              {i.lastAttempt && (
                <span title={i.lastAttempt.commandId}>
                  {t('legacyAgentPolicy.requiredApps.device.lastAttempt') || 'Last attempt'}: {t(`legacyAgent.state.${i.lastAttempt.state}`) || i.lastAttempt.state}
                  {i.lastAttempt.resultCode ? <span className="ml-1 font-mono text-[11px] text-text-muted">{i.lastAttempt.resultCode}</span> : null}
                  {' · '}{formatDateTime(i.lastAttempt.at)}
                </span>
              )}
            </div>
            {i.policy && (
              <p className="text-[11px] text-text-muted">{t('legacyAgentPolicy.requiredApps.device.policy') || 'Policy'}: {`${i.policy.name} · v${i.policy.version}`}</p>
            )}
          </li>
        ))}
      </ul>
      <p className="text-[11px] text-text-muted">
        {t('legacyAgentPolicy.requiredApps.device.limitHint', { limit: view.perRunLimit }) || `At most ${view.perRunLimit} installations per tenant every 10 minutes and ${view.perRunLimit} in progress at once; « Waiting for its turn » items are taken by a later pass.`}
      </p>
    </div>
  );
}
