import { useSyncExternalStore } from 'react';
import { clsx } from 'clsx';
import { useTranslation } from 'react-i18next';
import type { ContactState } from '@obligarth/shared';
import { Tip } from '@/components/common/Tip';
import { CONTACT_TONE, toneDot } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime, shortAge } from '@/components/mdm/PlatformIcon';

// The last contact of a device as a short relative age ('5 min', '3 h', '12 d') tinted by its contact state, refreshed
// every 30 seconds; the full date on hover (or tap on a touch screen).

const TEXT: Record<ContactState, string> = {
  recent: 'text-green-400', quiet: 'text-text-muted', stale: 'text-amber-400', never: 'text-text-muted',
};

// One clock for every pill on screen (an inventory renders up to a thousand rows): a single 30-second interval,
// running while at least one pill is mounted.
const TICK_MS = 30_000;
let clockNow = Date.now();
let clockTimer: number | undefined;
const clockListeners = new Set<() => void>();

function subscribeClock(listener: () => void): () => void {
  clockListeners.add(listener);
  if (clockTimer === undefined) {
    clockTimer = window.setInterval(() => {
      clockNow = Date.now();
      clockListeners.forEach((l) => l());
    }, TICK_MS);
  }
  return () => {
    clockListeners.delete(listener);
    if (clockListeners.size === 0 && clockTimer !== undefined) {
      window.clearInterval(clockTimer);
      clockTimer = undefined;
    }
  };
}

/** Re-renders on every tick of the shared clock while mounted (relative ages). */
function useNow(): number {
  return useSyncExternalStore(subscribeClock, readClock);
}

/** The clock's time; refreshed when it is idle (no pill was on screen), stable within a render (1 s steps). */
function readClock(): number {
  if (clockTimer === undefined && Date.now() - clockNow > 1000) clockNow = Date.now();
  return clockNow;
}

export function LastSeenPill({ lastCheckinAt, contactState, compact = false, tip = true, className }: {
  lastCheckinAt: string | null; contactState: ContactState;
  /** Text only, no border (a list row). */
  compact?: boolean;
  /** false: no tooltip (a tap must reach the clickable row around it on a touch screen). */
  tip?: boolean;
  className?: string;
}) {
  const { t } = useTranslation();
  const now = useNow();
  const label = lastCheckinAt ? shortAge(lastCheckinAt, now) : (t('mdm.ui.lastSeenNever') || 'Never seen');
  const full = lastCheckinAt
    ? (t('mdm.ui.lastSeenAt', { date: formatDateTime(lastCheckinAt) }) || `Last contact: ${formatDateTime(lastCheckinAt)}`)
    : (t('mdm.ui.lastSeenNever') || 'Never seen');
  const body = (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 whitespace-nowrap tabular-nums',
        compact ? 'text-xs' : 'rounded-full border border-border px-2 py-0.5 text-[11px] font-medium',
        TEXT[contactState] ?? 'text-text-muted',
        className,
      )}
      title={tip ? undefined : full}
    >
      {!compact && <span className={clsx('h-1.5 w-1.5 rounded-full', toneDot(CONTACT_TONE[contactState] ?? 'gray'))} />}
      <time dateTime={lastCheckinAt ?? undefined}>{label}</time>
    </span>
  );
  return tip ? <Tip content={full}>{body}</Tip> : body;
}
