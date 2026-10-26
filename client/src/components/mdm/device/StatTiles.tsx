import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import { BatteryCharging, Clock, HardDrive, HeartPulse, type LucideIcon } from 'lucide-react';
import type { DeviceDetail } from '@obligarth/shared';
import { BatteryIndicator } from '@/components/mdm/BatteryIndicator';
import { LastSeenPill } from '@/components/mdm/LastSeenPill';
import { formatBytes, formatDateTime } from '@/components/mdm/PlatformIcon';
import { MeterBar, RingGauge, percentTone, scoreTone, toneText } from '@/components/mdm/ui/Meter';
import { storageUsedPercent, type DeviceHealth } from '@/utils/deviceHealth';

// Four figures at the top of the overview: the health score (derived by the console), the battery, the storage and
// the last contact. A figure without a source says "unknown" rather than inventing one (no battery from Android
// Enterprise).

function Tile({ icon: Icon, label, children, foot }: { icon: LucideIcon; label: string; children: ReactNode; foot?: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-2 rounded-xl border border-border bg-bg-secondary p-3 sm:p-4">
      <div className="flex items-center gap-1.5 text-xs font-medium text-text-muted">
        <Icon className="w-3.5 h-3.5 shrink-0" aria-hidden />
        <span className="truncate">{label}</span>
      </div>
      <div className="min-w-0">{children}</div>
      {foot && <div className="mt-auto min-w-0 text-[11px] text-text-muted">{foot}</div>}
    </div>
  );
}

export function StatTiles({ device, health, agentStorageFree }: {
  device: DeviceDetail;
  health: DeviceHealth;
  /** The bridge agent's agent.storage.free (bytes), when the record has no capacity. */
  agentStorageFree?: number | null;
}) {
  const { t } = useTranslation();
  const unknown = t('deviceSummary.stats.unknown') || 'Unknown';
  const used = storageUsedPercent(device);
  const battery = device.battery;
  const big = 'text-xl font-semibold tabular-nums sm:text-2xl';
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Tile icon={HeartPulse} label={t('deviceSummary.stats.health') || 'Health'}>
        <div className="flex items-center gap-3">
          <RingGauge value={health.score} size={52} label={health.score === null ? unknown : `${health.score} / 100`} />
          <span className={clsx('text-sm font-medium', toneText(scoreTone(health.score)))}>
            {health.score === null ? unknown : `${health.score} / 100`}
          </span>
        </div>
      </Tile>

      <Tile
        icon={BatteryCharging}
        label={t('deviceSummary.stats.battery') || 'Battery'}
        foot={battery?.observedAt ? formatDateTime(battery.observedAt) : undefined}
      >
        {battery ? (
          <div className="space-y-2">
            <div className="flex items-baseline gap-2">
              <span className={clsx(big, toneText(percentTone(battery.level, { invert: true })))}>{battery.level}&nbsp;%</span>
              {battery.charging && <span className="text-xs text-green-400">{t('mdm.ui.charging') || 'Charging'}</span>}
            </div>
            <MeterBar percent={battery.level} tone={percentTone(battery.level, { invert: true })} label={t('deviceSummary.stats.battery') || 'Battery'} />
          </div>
        ) : (
          <div className="space-y-2">
            <span className={clsx(big, 'text-text-muted')}>—</span>
            <BatteryIndicator level={null} className="block text-xs" />
          </div>
        )}
      </Tile>

      <Tile
        icon={HardDrive}
        label={t('deviceSummary.stats.storage') || 'Storage'}
        foot={used !== null
          ? (t('deviceSummary.stats.storageFree', { free: formatBytes(device.storageAvailableBytes), total: formatBytes(device.storageCapacityBytes) })
            || `${formatBytes(device.storageAvailableBytes)} free of ${formatBytes(device.storageCapacityBytes)}`)
          : undefined}
      >
        {used !== null ? (
          <div className="space-y-2">
            <span className={clsx(big, toneText(percentTone(used)))}>{Math.round(used)}&nbsp;%</span>
            <MeterBar percent={used} label={t('deviceSummary.stats.storage') || 'Storage'} />
          </div>
        ) : typeof agentStorageFree === 'number' ? (
          <span className={clsx(big, 'text-text-primary')}>{formatBytes(agentStorageFree)}</span>
        ) : (
          <span className={clsx(big, 'text-text-muted')}>—</span>
        )}
      </Tile>

      <Tile
        icon={Clock}
        label={t('deviceSummary.stats.lastContact') || 'Last contact'}
        foot={device.lastCheckinAt ? formatDateTime(device.lastCheckinAt) : undefined}
      >
        {/* The full date in its tip (tap on a touch screen) and under it. */}
        <LastSeenPill lastCheckinAt={device.lastCheckinAt} contactState={device.contactState} compact className={big} />
      </Tile>
    </div>
  );
}
