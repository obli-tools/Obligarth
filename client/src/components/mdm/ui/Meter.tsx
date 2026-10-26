import { clsx } from 'clsx';

// Gauges of a device record (health score, battery, storage): pure SVG and CSS, no chart library. The tones are the
// state colours of the badges (DeviceStateBadges), so a red gauge reads like a red badge on every theme.

export type MeterTone = 'green' | 'amber' | 'red' | 'gray' | 'accent';

const TEXT: Record<MeterTone, string> = {
  green: 'text-green-400', amber: 'text-amber-400', red: 'text-red-400', gray: 'text-text-muted', accent: 'text-accent',
};
const BAR: Record<MeterTone, string> = {
  green: 'bg-green-400', amber: 'bg-amber-400', red: 'bg-red-400', gray: 'bg-text-muted', accent: 'bg-accent',
};

/** Text colour of a tone (a value next to its gauge). */
export const toneText = (tone: MeterTone): string => TEXT[tone];

/**
 * The tone of a filling percentage: red beyond 90 %, amber beyond 70 % (storage). `invert` for a level that is bad when
 * low (battery): red under 15 %, amber under 30 %. Null or unknown: gray.
 */
export function percentTone(p: number | null | undefined, opts: { invert?: boolean } = {}): MeterTone {
  if (p === null || p === undefined || !Number.isFinite(p)) return 'gray';
  if (opts.invert) return p < 15 ? 'red' : p < 30 ? 'amber' : 'green';
  return p > 90 ? 'red' : p > 70 ? 'amber' : 'green';
}

/** The tone of a health score (0-100): green from 80, amber from 50, red below. */
export const scoreTone = (score: number | null | undefined): MeterTone =>
  (score === null || score === undefined || !Number.isFinite(score) ? 'gray' : score >= 80 ? 'green' : score >= 50 ? 'amber' : 'red');

/** A ring gauge with its value in the centre (the health score of a device). `value` from 0 to 100; null: an empty ring. */
export function RingGauge({ value, size = 64, tone, label, className }: {
  value: number | null; size?: number; tone?: MeterTone;
  /** Accessible name (the gauge reads as an image): '82 / 100', 'Health 82'. */
  label: string;
  className?: string;
}) {
  const stroke = Math.max(3, Math.round(size / 13));
  const r = size / 2 - stroke;
  const c = 2 * Math.PI * r;
  const v = value === null || !Number.isFinite(value) ? null : Math.min(100, Math.max(0, value));
  const t = tone ?? scoreTone(v);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label} className={clsx('shrink-0', className)}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={stroke} className="text-border" />
      {v !== null && v > 0 && (
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={`${(c * v) / 100} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`}
          className={clsx(TEXT[t], 'transition-[stroke-dasharray] duration-500')} />
      )}
      <text x="50%" y="50%" dominantBaseline="central" textAnchor="middle" fill="currentColor" className="text-text-primary"
        fontSize={size * 0.3} fontWeight={700}>{v === null ? '—' : Math.round(v)}</text>
    </svg>
  );
}

/** A horizontal bar gauge (storage used, battery level). */
export function MeterBar({ percent, tone, className, label }: {
  percent: number | null; tone?: MeterTone; className?: string;
  /** Accessible name of the bar. */
  label?: string;
}) {
  const p = percent === null || !Number.isFinite(percent) ? null : Math.min(100, Math.max(0, percent));
  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={p === null ? undefined : Math.round(p)}
      className={clsx('h-1.5 w-full overflow-hidden rounded-full bg-bg-tertiary', className)}
    >
      {p !== null && (
        <div className={clsx('h-full rounded-full transition-[width] duration-500', BAR[tone ?? percentTone(p)])} style={{ width: `${p}%` }} />
      )}
    </div>
  );
}
