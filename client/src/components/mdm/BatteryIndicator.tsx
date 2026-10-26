import { clsx } from 'clsx';
import { useTranslation } from 'react-i18next';
import { BatteryCharging, BatteryFull, BatteryLow, BatteryMedium, BatteryWarning, type LucideIcon } from 'lucide-react';
import { Tip } from '@/components/common/Tip';
import { percentTone, toneText } from '@/components/mdm/ui/Meter';

// The battery of a device: an icon by level (or charging), the percentage coloured like the gauges (red under 15 %,
// amber under 30 %). Nothing is invented for a device without a source (AMAPI): the caller shows it only with a level.

function iconOf(level: number, charging: boolean | null | undefined): LucideIcon {
  if (charging) return BatteryCharging;
  if (level < 15) return BatteryWarning;
  if (level < 40) return BatteryLow;
  if (level < 80) return BatteryMedium;
  return BatteryFull;
}

export function BatteryIndicator({ level, charging, compact = false, tip = true, className }: {
  /** Integer percent 0-100; null: unknown. */
  level: number | null | undefined;
  charging?: boolean | null;
  /** Icon and percentage only, small (a list row). */
  compact?: boolean;
  /** false: no tooltip (a tap must reach the clickable row around it on a touch screen). */
  tip?: boolean;
  className?: string;
}) {
  const { t } = useTranslation();
  if (level === null || level === undefined || !Number.isFinite(level)) {
    if (compact) return null;
    return <span className={clsx('text-sm text-text-muted', className)}>{t('mdm.ui.batteryUnknown') || 'Battery unknown'}</span>;
  }
  const pct = Math.min(100, Math.max(0, Math.round(level)));
  const Icon = iconOf(pct, charging);
  const tone = toneText(percentTone(pct, { invert: true }));
  const title = `${t('mdm.ui.battery') || 'Battery'} ${pct} %${charging ? ` · ${t('mdm.ui.charging') || 'Charging'}` : ''}`;
  const body = (
    <span className={clsx('inline-flex items-center gap-1 whitespace-nowrap tabular-nums', compact ? 'text-xs' : 'text-sm', tone, className)}
      title={tip ? undefined : title}>
      <Icon className={compact ? 'w-3.5 h-3.5' : 'w-4 h-4'} aria-hidden />
      <span>{pct}&nbsp;%</span>
    </span>
  );
  return tip ? <Tip content={title}>{body}</Tip> : body;
}
