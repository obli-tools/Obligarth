import type { ReactNode } from 'react';
import { clsx } from 'clsx';
import { useTranslation } from 'react-i18next';
import { Apple, Layers, ShieldAlert, Siren, Smartphone, WifiOff } from 'lucide-react';
import type { DeviceFacets } from '@obligarth/shared';
import { InfoTip } from '@/components/common/Tip';

// The counters of the fleet above the inventory (GET /api/mdm/devices/facets, already narrowed to the devices the
// user's teams may see): total, non compliant, without contact, lost mode, Apple, Android. They count the devices
// under management (facets.managed: an unenrolled record keeps its lost mode and never checks in again), not the
// filtered view; a tile toggles the matching filter of the list (the same state as the chips of the toolbar), on the
// "under management" tab, and is highlighted while that filter is on. Phone: one row scrolled sideways.

export type KpiFilter = 'nonCompliant' | 'stale' | 'lostMode' | 'apple' | 'android';

/** The platform values counted as Apple (every platform but Android). */
export const isApplePlatform = (p: string): boolean => p !== 'android';

interface DevicesKpiStripProps {
  facets: DeviceFacets | null;
  /** The KPI filters on in the list. */
  active: ReadonlySet<KpiFilter>;
  /** No KPI filter on: the "Total" tile is the highlighted one. */
  showingAll: boolean;
  onToggle: (filter: KpiFilter) => void;
  /** "Total": drops the KPI filters. */
  onShowAll: () => void;
}

type Tone = 'neutral' | 'red' | 'amber';

const VALUE_TONE: Record<Tone, string> = {
  neutral: 'text-text-primary', red: 'text-red-400', amber: 'text-amber-400',
};

export function DevicesKpiStrip({ facets, active, showingAll, onToggle, onShowAll }: DevicesKpiStripProps) {
  const { t } = useTranslation();
  const countOf = (list: Array<{ value: string; count: number }> | undefined, pick: (v: string) => boolean): number =>
    (list ?? []).filter((x) => pick(x.value)).reduce((n, x) => n + x.count, 0);

  const managed = facets?.managed;
  const total = managed?.total ?? 0;
  const nonCompliant = managed?.nonCompliant ?? 0;
  const stale = managed?.contact.stale ?? 0;
  const lostMode = managed?.lostMode ?? 0;
  const apple = countOf(managed?.platform, isApplePlatform);
  const android = countOf(managed?.platform, (v) => v === 'android');

  const tiles: Array<{ key: KpiFilter | 'total'; icon: ReactNode; label: string; value: number; tone: Tone; alert?: boolean }> = [
    { key: 'total', icon: <Layers className="w-4 h-4" />, label: t('devices.kpi.total') || 'Managed devices', value: total, tone: 'neutral' },
    { key: 'nonCompliant', icon: <ShieldAlert className="w-4 h-4" />, label: t('devices.kpi.nonCompliant') || 'Non compliant', value: nonCompliant, tone: nonCompliant > 0 ? 'red' : 'neutral' },
    { key: 'stale', icon: <WifiOff className="w-4 h-4" />, label: t('devices.kpi.stale') || 'No contact', value: stale, tone: stale > 0 ? 'amber' : 'neutral' },
    { key: 'lostMode', icon: <Siren className="w-4 h-4" />, label: t('devices.kpi.lostMode') || 'Lost mode', value: lostMode, tone: lostMode > 0 ? 'red' : 'neutral', alert: lostMode > 0 },
    { key: 'apple', icon: <Apple className="w-4 h-4" />, label: t('devices.kpi.apple') || 'Apple', value: apple, tone: 'neutral' },
    { key: 'android', icon: <Smartphone className="w-4 h-4" />, label: t('devices.kpi.android') || 'Android', value: android, tone: 'neutral' },
  ];

  return (
    <section aria-label={t('devices.kpi.title') || 'Fleet'} className="min-w-0">
      <div className="mb-1.5 flex items-center gap-1.5">
        <span className="text-[10px] font-medium uppercase tracking-wider text-text-muted">{t('devices.kpi.title') || 'Fleet'}</span>
        <InfoTip content={t('devices.kpi.hint') || 'Counts of the devices under management, not of the filtered view. A tile toggles its filter.'} />
      </div>
      <div className="-mx-3 flex snap-x snap-mandatory gap-2 overflow-x-auto overscroll-x-contain px-3 pb-1 scrollbar-none sm:mx-0 sm:grid sm:grid-cols-3 sm:overflow-visible sm:px-0 sm:pb-0 lg:grid-cols-6">
        {tiles.map((tile) => {
          const on = tile.key === 'total' ? showingAll : active.has(tile.key);
          return (
            <button
              key={tile.key}
              type="button"
              aria-pressed={on}
              onClick={() => (tile.key === 'total' ? onShowAll() : onToggle(tile.key))}
              className={clsx(
                'group flex min-w-[8.5rem] shrink-0 snap-start items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition-colors sm:min-w-0',
                on
                  ? 'border-accent/60 bg-accent/10 ring-1 ring-accent/30'
                  : tile.alert
                    ? 'border-red-500/40 bg-red-500/5 hover:bg-red-500/10'
                    : 'border-border bg-bg-secondary hover:bg-bg-tertiary',
              )}
            >
              <span
                className={clsx(
                  'flex h-8 w-8 shrink-0 items-center justify-center rounded-lg',
                  on ? 'bg-accent/15 text-accent' : tile.alert ? 'bg-red-500/15 text-red-400' : 'bg-bg-tertiary text-text-muted group-hover:text-text-primary',
                )}
              >
                {tile.icon}
              </span>
              <span className="min-w-0">
                <span className={clsx('block text-lg font-semibold leading-tight tabular-nums', VALUE_TONE[tile.tone])}>
                  {facets ? tile.value : '—'}
                  {tile.alert && <span className="ml-1.5 inline-block h-2 w-2 rounded-full bg-red-400 align-middle animate-pulse" aria-hidden />}
                </span>
                <span className="block truncate text-[11px] text-text-muted">{tile.label}</span>
              </span>
            </button>
          );
        })}
      </div>
    </section>
  );
}
