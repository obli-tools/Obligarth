import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import { ShieldAlert } from 'lucide-react';
import type { DeviceDetail } from '@obligarth/shared';
import { InfoCard } from '@/components/mdm/ui/InfoCard';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { ACTION_ICON, type DeviceActions, type UnifiedAction, type UnifiedActionKey } from './useDeviceActions';

// "Lost or stolen?": the actions that matter then, as large tiles with what each does, whether one waits in the queue,
// and — for one that cannot run — why, in plain sight (not only in a tip). Running a tile goes through the runner of
// the channel: the same parameters, reasons, guard dialogs, second factors and approvals as the Actions tab.

const HINT: Partial<Record<UnifiedActionKey, { key: string; fallback: string }>> = {
  lock: { key: 'lockHint', fallback: 'Locks the screen now, with a message if you wish.' },
  lostOn: { key: 'lostOnHint', fallback: 'Locks the device with your message and allows locating it.' },
  lostOff: { key: 'lostOffHint', fallback: 'Ends the lost mode: the device is usable again.' },
  sound: { key: 'soundHint', fallback: 'Plays a sound on the device, even silent.' },
  locate: { key: 'locateHint', fallback: 'Asks the device for its position.' },
  erase: { key: 'eraseHint', fallback: 'Erases every data of the device. Cannot be undone.' },
  message: { key: 'messageHint', fallback: 'Shows a message on the device.' },
};

function LostTile({ action }: { action: UnifiedAction }) {
  const { t } = useTranslation();
  const Icon = ACTION_ICON[action.key];
  const hint = HINT[action.key];
  return (
    <button
      type="button"
      disabled={!action.available}
      onClick={action.run}
      className={clsx(
        'flex min-h-24 min-w-0 flex-col items-start gap-1.5 rounded-lg border p-3 text-left transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60',
        'disabled:cursor-not-allowed',
        action.danger
          ? 'border-red-400/40 enabled:hover:bg-red-400/10'
          : 'border-border enabled:hover:border-accent/50 enabled:hover:bg-bg-hover',
        !action.available && 'bg-bg-tertiary/40',
      )}
    >
      <span className="flex w-full min-w-0 items-start gap-2">
        <Icon className={clsx('w-5 h-5 shrink-0', !action.available ? 'text-text-muted' : action.danger ? 'text-red-400' : 'text-accent')} aria-hidden />
        <span className={clsx('min-w-0 break-words text-sm font-medium leading-tight', !action.available ? 'text-text-muted' : action.danger ? 'text-red-400' : 'text-text-primary')}>
          {action.label}
        </span>
      </span>
      {hint && <span className="text-[11px] leading-snug text-text-muted">{t(`deviceSummary.lost.${hint.key}`) || hint.fallback}</span>}
      {action.pending && <StateBadge tone="blue" label={t('deviceSummary.lost.pending') || 'Waiting for the device'} pulse />}
      {!action.available && action.reasonLabel && (
        <span className="text-[11px] leading-snug text-amber-400">{action.reasonLabel}</span>
      )}
    </button>
  );
}

export function LostDevicePanel({ device, actions, className }: { device: DeviceDetail; actions: DeviceActions; className?: string }) {
  const { t } = useTranslation();
  const a = actions.actions;
  const tiles = [a.lock, device.lostModeState === 'off' ? a.lostOn : a.lostOff, a.sound, a.locate, a.erase, a.message].filter((x) => !x.hidden);
  return (
    <InfoCard
      icon={ShieldAlert}
      title={t('deviceSummary.lost.title') || 'Lost or stolen device?'}
      tone={device.lostModeState !== 'off' ? 'danger' : 'default'}
      className={className}
    >
      <p className="-mt-1 mb-3 text-xs text-text-muted">
        {t('deviceSummary.lost.subtitle') || 'Act from here: each action reaches the device at its next contact. The guarded ones ask for a reason and a confirmation.'}
      </p>
      {actions.channel === 'apple_mdm' && !device.supervised && device.ownership !== 'personal' && (
        <p className="mb-3 text-xs text-amber-400">{t('deviceSummary.lost.supervisionRequired') || 'Lost mode: a supervised device is required.'}</p>
      )}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {tiles.map((x) => <LostTile key={x.key} action={x} />)}
      </div>
    </InfoCard>
  );
}
