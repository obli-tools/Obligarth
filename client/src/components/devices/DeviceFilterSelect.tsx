import { useMemo, useState } from 'react';
import { ChevronDown, Monitor, Search } from 'lucide-react';
import { clsx } from 'clsx';
import { useTranslation } from 'react-i18next';
import type { Device } from '@obliance/shared';
import { Modal } from '@/components/common/Modal';
import { useIsCoarsePointer } from '@/hooks/useMediaQuery';
import { deviceMatchesSearch } from '@/utils/deviceSearch';

/**
 * "Filter by device" control (report editor).
 * Fine pointer: a native <select>. Touch: a native <select> over the whole
 * fleet (2000+ devices) is an unsearchable wall on Android, so the control
 * opens a searchable list instead.
 */
const DEVICE_FILTER_LIMIT = 200;
export function DeviceFilterSelect({
  devices, value, onChange, allLabel, touchTriggerClassName,
}: {
  devices: Device[];
  value: number | '';
  onChange: (value: number | '') => void;
  allLabel: string;
  /** Classes for the touch trigger button (default: the filter-bar look). */
  touchTriggerClassName?: string;
}) {
  const { t } = useTranslation();
  const coarse = useIsCoarsePointer();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const name = (d: Device) => d.displayName || d.hostname;
  const selected = value === '' ? null : devices.find(d => d.id === value) ?? null;
  const filtered = useMemo(
    () => (open ? devices.filter(d => deviceMatchesSearch(d, query)) : []),
    [devices, query, open],
  );

  if (!coarse) {
    return (
      <div className="flex items-center gap-1.5 px-3 py-1.5 bg-bg-secondary rounded-lg min-w-0 max-w-full">
        <Monitor className="w-3.5 h-3.5 text-text-muted shrink-0" />
        <select
          value={value}
          onChange={(e) => onChange(e.target.value === '' ? '' : parseInt(e.target.value))}
          className="text-sm bg-transparent text-text-primary focus:outline-none min-w-[120px] max-w-full"
        >
          <option value="">{allLabel}</option>
          {devices.map(d => (
            <option key={d.id} value={d.id}>
              {name(d)}
            </option>
          ))}
        </select>
      </div>
    );
  }

  const pick = (v: number | '') => { onChange(v); setOpen(false); };
  const rowCls = (active: boolean) => clsx(
    'w-full min-h-11 px-4 py-2 flex items-center gap-2 text-left text-sm transition-colors',
    active ? 'bg-accent/10 text-accent font-medium' : 'text-text-primary hover:bg-bg-tertiary',
  );
  return (
    <>
      <button
        type="button"
        onClick={() => { setQuery(''); setOpen(true); }}
        aria-haspopup="dialog"
        className={touchTriggerClassName ?? 'flex items-center gap-1.5 px-3 py-1.5 min-h-10 bg-bg-secondary rounded-lg min-w-0 max-w-full text-sm text-text-primary'}
      >
        <Monitor className="w-3.5 h-3.5 text-text-muted shrink-0" />
        <span className="truncate">{selected ? name(selected) : allLabel}</span>
        <ChevronDown className="w-3.5 h-3.5 shrink-0 text-text-muted" />
      </button>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title={t('compliance.filterByDevice', 'Filter by device')}
        icon={<Monitor className="w-4 h-4 text-accent" />}
        bodyClassName="p-0"
      >
        <div className="sticky top-0 z-10 bg-bg-secondary px-4 pb-2 pt-1">
          <div className="flex items-center gap-2 px-3 py-2 bg-bg-tertiary rounded-lg">
            <Search className="w-3.5 h-3.5 text-text-muted shrink-0" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('deviceMultiSelect.searchPlaceholder', 'Hostname, IP, user, UUID, OS, tag…')}
              autoCapitalize="off" autoCorrect="off" spellCheck={false}
              className="flex-1 min-w-0 bg-transparent text-sm text-text-primary placeholder:text-text-muted/60 focus:outline-none"
            />
          </div>
        </div>
        <div className="pb-2">
          <button type="button" onClick={() => pick('')} className={rowCls(value === '')}>{allLabel}</button>
          {filtered.slice(0, DEVICE_FILTER_LIMIT).map(d => (
            <button key={d.id} type="button" onClick={() => pick(d.id)} className={rowCls(value === d.id)}>
              <span className="flex-1 min-w-0 truncate">{name(d)}</span>
              {d.ipLocal && <span className="shrink-0 text-xs font-mono text-text-muted">{d.ipLocal}</span>}
            </button>
          ))}
          {filtered.length === 0 && (
            <p className="px-4 py-3 text-sm text-text-muted">{t('common.noResults')}</p>
          )}
          {filtered.length > DEVICE_FILTER_LIMIT && (
            <p className="px-4 py-3 text-xs text-text-muted">
              {t('compliance.refineSearch', { count: filtered.length - DEVICE_FILTER_LIMIT, defaultValue: '{{count}} more — refine the search' })}
            </p>
          )}
        </div>
      </Modal>
    </>
  );
}
