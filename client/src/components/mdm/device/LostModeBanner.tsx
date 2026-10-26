import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import { MapPin, Siren } from 'lucide-react';
import type { DeviceDetail } from '@obligarth/shared';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { QuickActionButton } from './DeviceHero';
import { CHANNEL_REASONS, type DeviceActions, type UnifiedAction } from './useDeviceActions';

// While the lost mode is on (or changing), a red banner over every tab of the record: since when, and the actions that
// matter then (locate, sound, disable) with a link to the location card. What the channel cannot do is left out here
// (the lost device panel says why).

export function LostModeBanner({ device, actions, onShowLocation }: {
  device: DeviceDetail;
  actions: DeviceActions;
  /** Opens the overview on the location card. */
  onShowLocation?: () => void;
}) {
  const { t } = useTranslation();
  const state = device.lostModeState;
  if (state === 'off') return null;
  const changing = state === 'enabling' || state === 'disabling';
  const a = actions.actions;
  const shown = (x: UnifiedAction) => !x.hidden && !(x.reason && CHANNEL_REASONS.has(x.reason));
  const buttons = [
    { ...a.locate, label: t('deviceSummary.lostBanner.locate') || 'Locate' },
    { ...a.sound, label: t('deviceSummary.lostBanner.sound') || 'Play a sound' },
    { ...a.lostOff, label: t('deviceSummary.lostBanner.disable') || 'Disable' },
  ].filter(shown);
  const heading = state === 'on' ? (t('deviceSummary.lostBanner.on') || 'Lost mode is on')
    : state === 'enabling' ? (t('deviceSummary.lostBanner.enabling') || 'Lost mode is being enabled')
      : (t('deviceSummary.lostBanner.disabling') || 'Lost mode is being disabled');
  return (
    <div role="status" className="flex flex-wrap items-center gap-3 rounded-xl border border-red-400/40 bg-red-400/10 p-3 sm:p-4">
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-red-400/15 text-red-400">
        <Siren className={clsx('w-5 h-5', changing && 'animate-pulse')} aria-hidden />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-red-400">{heading}</p>
        {device.lostModeChangedAt && (
          <p className="text-xs text-text-secondary">
            {t('deviceSummary.lostBanner.since', { date: formatDateTime(device.lostModeChangedAt) }) || `Since ${formatDateTime(device.lostModeChangedAt)}`}
          </p>
        )}
      </div>
      <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
        {buttons.map((x) => <QuickActionButton key={x.key} action={x} className="max-sm:flex-1" />)}
        {onShowLocation && actions.channel !== 'legacy_agent' && device.ownership !== 'personal' && (
          <button type="button" onClick={onShowLocation}
            className="inline-flex items-center gap-1 text-sm text-red-400 hover:underline coarse:min-h-10">
            <MapPin className="w-4 h-4" aria-hidden />{t('deviceSummary.lostBanner.seeLocation') || 'See the location'}
          </button>
        )}
      </div>
    </div>
  );
}
