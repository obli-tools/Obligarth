import { memo, type MouseEvent, type ReactNode } from 'react';
import { Eye, FolderOpen, User, Building2, Briefcase, Hash, Clock, ShieldCheck } from 'lucide-react';
import type { DeviceSummary } from '@obligarth/shared';
import { clsx } from 'clsx';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/store/authStore';
import { anonymize } from '@/utils/anonymize';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import { DeviceStateBadges, complianceLabel } from '@/components/mdm/DeviceStateBadges';
import { PlatformIcon, dayIsPast, formatDay, osLabel, ownershipLabel, shortAge } from '@/components/mdm/PlatformIcon';

interface DeviceRowProps {
  device: DeviceSummary;
  isSelected: boolean;
  onSelect: (id: number) => void;
  onNavigate: (id: number) => void;
  onGroupClick?: (groupId: number) => void;
  /** When true, the entire row becomes a selection target (no navigation) and
   *  a checkbox is always visible on the left. Enabled by the "Select"
   *  toggle in DeviceTable. */
  selectionMode?: boolean;
  /** The optional line-2 fields to render (utils/deviceLine2Fields); the catalog's defaults when undefined. */
  visibleFields?: Set<string>;
}

const DEFAULT_FIELDS = ['platform', 'model', 'ownership', 'group', 'endUser'];

/** Colour of the last contact: recent, quiet, without contact (modele-donnees-mdm §4.4). */
const CONTACT_COLOR: Record<DeviceSummary['contactState'], string> = {
  recent: 'text-green-400', quiet: 'text-text-muted', stale: 'text-amber-400', never: 'text-text-muted',
};

// Stacked row = line 1 wraps into a "name" line and a "status" line. The
// single line is kept only where there is room for it: desktop with a
// mouse. Tablet widths (< 1024) and touch screens below xl (landscape
// tablets: pinned 280px sidebar, no hover) get the stacked row; phones
// (< 768) add the max-md: tweaks below.
// One shared MediaQueryList for every row (hooks/useMediaQuery).
const STACKED_ROW_QUERY = '(max-width: 1023.98px), (pointer: coarse) and (max-width: 1279.98px)';

export const DeviceRow = memo(function DeviceRow({
  device,
  isSelected,
  onSelect,
  onNavigate,
  onGroupClick,
  selectionMode = false,
  visibleFields,
}: DeviceRowProps) {
  const { t } = useTranslation();
  const { isAdmin } = useAuthStore();
  const stacked = useMediaQuery(STACKED_ROW_QUERY);
  const fieldOn = (key: string): boolean => (visibleFields ? visibleFields.has(key) : DEFAULT_FIELDS.includes(key));

  const tags = device.tags ?? [];
  const visibleTags = tags.slice(0, 2);
  const overflowCount = tags.length - 2;
  const os = osLabel(device.platform, device.osVersion);
  const model = device.modelName || device.model;
  const endUser = device.endUser?.displayName || device.endUser?.email || null;

  // The checkbox column: explicit selection mode (any role), or an administrator (always, for the batch actions).
  const showCheckbox = selectionMode || isAdmin();
  const line2Offset = showCheckbox ? 'pl-[68px]' : 'pl-[40px]';

  const handleCheckbox = (e: MouseEvent) => {
    e.stopPropagation();
    onSelect(device.id);
  };
  const handleEye = (e: MouseEvent) => {
    e.stopPropagation();
    onNavigate(device.id);
  };
  const handleGroupClick = (e: MouseEvent) => {
    e.stopPropagation();
    if (device.groupId && onGroupClick) onGroupClick(device.groupId);
  };

  // Middle-click opens the device in a new tab. preventDefault on mousedown
  // too, or Windows starts its auto-scroll cursor before auxclick runs.
  const handleMouseDown = (e: MouseEvent) => {
    if (e.button === 1) e.preventDefault();
  };
  const handleAuxClick = (e: MouseEvent) => {
    if (e.button !== 1 || selectionMode) return;
    e.preventDefault();
    window.open(`/devices/${device.id}`, '_blank', 'noopener,noreferrer');
  };

  return (
    <div
      className={clsx(
        // Desktop with a mouse: a fixed 72px two-line row. Stacked (tablet /
        // touch < xl / phone): the row grows with its content.
        'min-h-[72px] px-4 py-2 hover:bg-bg-tertiary cursor-pointer transition-colors flex flex-col justify-center max-md:px-3',
        !stacked && 'md:h-[72px]',
        isSelected && 'bg-accent/10',
        selectionMode && isSelected && 'bg-accent/15',
        device.enrollmentState === 'unenrolled' && 'opacity-70',
      )}
      onClick={() => (selectionMode ? onSelect(device.id) : onNavigate(device.id))}
      onMouseDown={handleMouseDown}
      onAuxClick={handleAuxClick}
    >
      {/* Line 1 */}
      <div className={clsx('flex items-center gap-3 max-md:gap-x-2 max-md:gap-y-0.5', stacked && 'flex-wrap gap-y-1')}>
        {showCheckbox && (
          <button
            onClick={handleCheckbox}
            aria-label={t('devices.row.select', 'Select')}
            aria-pressed={isSelected}
            className={clsx(
              'w-4 h-4 rounded border flex-shrink-0 flex items-center justify-center transition-colors',
              // Touch: invisible 40×40 hit area around the 16px box + a visible unchecked border.
              "relative coarse:after:absolute coarse:after:-inset-3 coarse:after:content-['']",
              selectionMode
                ? (isSelected
                    ? 'bg-accent border-accent text-white'
                    : 'bg-bg-primary/80 border-text-muted/40 hover:border-accent/50')
                : (isSelected
                    ? 'bg-accent border-accent text-white'
                    : 'border-transparent hover:border-accent/50 coarse:border-text-muted/40'),
            )}
          >
            {isSelected && (
              <svg className="w-3 h-3" viewBox="0 0 12 12" fill="none">
                <path d="M2.5 6L5 8.5L9.5 3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
          </button>
        )}

        <PlatformIcon platform={device.platform} className="w-4 h-4 text-text-muted flex-shrink-0" />

        <span className={clsx('text-sm font-semibold text-text-primary truncate', stacked ? 'flex-1 min-w-0' : 'max-w-[240px]')} title={anonymize(device.label)}>
          {anonymize(device.label)}
        </span>

        {visibleTags.map((tag) => (
          <span key={tag} className="text-[10px] px-1.5 rounded-full bg-accent/10 text-accent flex-shrink-0 max-md:hidden">
            {tag}
          </span>
        ))}
        {overflowCount > 0 && (
          <span className="text-[10px] px-1.5 rounded-full bg-accent/10 text-accent flex-shrink-0 max-md:hidden">
            +{overflowCount}
          </span>
        )}

        {/* Spacer on the single-line row; a line break on the stacked row. */}
        <div className={stacked ? 'order-2 flex-none w-full h-0' : 'flex-1'} />

        {/* The separate states: enrollment always, the others when they say something. */}
        <span className={clsx('flex', stacked && 'order-3', stacked && (showCheckbox ? 'md:ml-[68px]' : 'md:ml-[40px]'))}>
          <DeviceStateBadges device={device} />
        </span>

        <span
          className={clsx('text-xs flex-shrink-0 tabular-nums w-12 text-right max-md:w-auto', stacked && 'order-1', CONTACT_COLOR[device.contactState])}
          title={device.lastCheckinAt ? new Date(device.lastCheckinAt).toLocaleString() : (t('mdm.contactState.never') || 'Never seen')}
        >
          {shortAge(device.lastCheckinAt)}
        </span>

        {/* Eye: redundant with the row tap, dropped on phone. */}
        <button
          onClick={handleEye}
          aria-label={t('devices.viewDevice')}
          className={clsx(
            "p-1 rounded hover:bg-bg-tertiary text-text-muted hover:text-text-primary transition-colors flex-shrink-0 max-md:hidden relative coarse:after:absolute coarse:after:-inset-2 coarse:after:content-['']",
            stacked && 'order-1',
          )}
          title={t('devices.viewDevice')}
        >
          <Eye className="w-4 h-4" />
        </button>
      </div>

      {/* Line 2: the fields the user toggled on; an absent value (not collected, unknown) leaves no separator. */}
      <Line2Fields
        className={clsx('flex items-center gap-1.5 text-xs text-text-muted mt-0.5', line2Offset, stacked && 'flex-wrap gap-y-0.5', 'max-md:pl-0 max-md:mt-1')}
        nodes={[
          // Meaningful from the master tenant's global view only (tenantName is absent otherwise).
          fieldOn('tenant') && device.tenantName && (
            <span key="tenant" className="inline-flex items-center gap-1 text-accent" title={device.tenantName}>
              <Building2 className="w-3 h-3" />
              <span className="truncate max-w-[100px]">{device.tenantName}</span>
            </span>
          ),
          fieldOn('platform') && (
            <span key="platform" className="truncate max-w-[140px]">{os}</span>
          ),
          fieldOn('model') && model && (
            <span key="model" className="truncate max-w-[160px]" title={device.model ?? undefined}>{model}</span>
          ),
          fieldOn('ownership') && (
            <span key="ownership" className="inline-flex items-center gap-1">
              <Briefcase className="w-3 h-3" />
              <span>{ownershipLabel(t, device.ownership)}</span>
            </span>
          ),
          fieldOn('group') && (
            <span key="group" className="inline-flex items-center gap-1">
              <FolderOpen className="w-3 h-3" />
              {device.groupId && device.groupName ? (
                <button onClick={handleGroupClick} className="hover:text-accent transition-colors coarse:pointer-events-none">
                  {anonymize(device.groupName)}
                </button>
              ) : (
                <span>{'—'}</span>
              )}
            </span>
          ),
          fieldOn('endUser') && endUser && (
            <span key="endUser" className="inline-flex items-center gap-1">
              <User className="w-3 h-3" />
              <span className="truncate max-w-[140px]">{anonymize(endUser)}</span>
            </span>
          ),
          fieldOn('contact') && (
            <span key="contact" className="inline-flex items-center gap-1">
              <Clock className="w-3 h-3" />
              <span>{device.lastCheckinAt ? new Date(device.lastCheckinAt).toLocaleString() : (t('mdm.contactState.never') || 'Never seen')}</span>
            </span>
          ),
          fieldOn('compliance') && device.enrollmentState !== 'unenrolled' && (
            <span key="compliance" className={clsx(device.complianceState === 'non_compliant' && 'text-red-400')}>
              {complianceLabel(t, device.complianceState)}
            </span>
          ),
          // Absent when the privacy rules of the device's ownership do not collect it.
          fieldOn('serial') && device.serialNumber && (
            <span key="serial" className="inline-flex items-center gap-1 font-mono">
              <Hash className="w-3 h-3" />
              <span>{anonymize(device.serialNumber)}</span>
            </span>
          ),
          fieldOn('tags') && tags.length > 0 && (
            <span key="tags" className="inline-flex items-center gap-1 flex-wrap" title={tags.join(', ')}>
              {tags.slice(0, 5).map((tag) => (
                <span key={tag} className="px-1.5 py-0 rounded-full bg-bg-tertiary text-text-muted text-[10px]">{tag}</span>
              ))}
              {tags.length > 5 && <span className="text-[10px] text-text-muted/60">+{tags.length - 5}</span>}
            </span>
          ),
          // Asset data entered by an administrator: absent when none was entered.
          fieldOn('warranty') && device.warrantyExpiry && (
            <span key="warranty" className={clsx('inline-flex items-center gap-1', dayIsPast(device.warrantyExpiry) && 'text-amber-400')}
              title={dayIsPast(device.warrantyExpiry) ? (t('devices.row.warrantyExpired') || 'Warranty expired') : undefined}>
              <ShieldCheck className="w-3 h-3" />
              <span>{t('devices.row.warrantyUntil', { date: formatDay(device.warrantyExpiry) }) || `Warranty until ${formatDay(device.warrantyExpiry)}`}</span>
            </span>
          ),
        ]}
      />
    </div>
  );
});

/** A list of nodes joined by middots, skipping the falsy entries so that a toggled-off field leaves no stray "·". */
function Line2Fields({ nodes, className }: { nodes: Array<ReactNode | false | null | undefined | ''>; className?: string }) {
  const visible = nodes.filter(Boolean) as ReactNode[];
  return (
    <div className={className}>
      {visible.map((node, i) => (
        <span key={i} className="inline-flex items-center gap-1.5 max-md:min-w-0 max-md:max-w-full">
          {i > 0 && <span className="text-text-muted/50">&middot;</span>}
          {node}
        </span>
      ))}
    </div>
  );
}
