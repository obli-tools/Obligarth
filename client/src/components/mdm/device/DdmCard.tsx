import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Layers } from 'lucide-react';
import type { DeviceDeclarationsView, DeviceStatusItemView } from '@obligarth/shared';
import { appleApi } from '@/api/apple.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { InfoCard, InfoRow, InfoRows } from '@/components/mdm/ui/InfoCard';
import { apiErrorMessage, trCode } from '@/utils/apiError';
import { Flag } from './Flag';

// Declarative management: the set the engine serves and whether the device fetched it, the declarations and their
// state, the status items the device reports — the known ones translated (passcode, software update), the others
// folded with their raw value.

type KnownKey = 'passcodePresent' | 'passcodeCompliant' | 'pendingVersion' | 'installState';
const KNOWN: Array<{ item: string; key: KnownKey; fallback: string }> = [
  { item: 'passcode.is-present', key: 'passcodePresent', fallback: 'Passcode set' },
  { item: 'passcode.is-compliant', key: 'passcodeCompliant', fallback: 'Passcode compliant' },
  { item: 'softwareupdate.pending-version', key: 'pendingVersion', fallback: 'System update waiting' },
  { item: 'softwareupdate.install-state', key: 'installState', fallback: 'System update state' },
];
const KNOWN_ITEMS = new Set(KNOWN.map((k) => k.item));

/** The version a pending-version status names (a dictionary with os-version, or a plain text). */
function versionOf(v: unknown): string | null {
  if (typeof v === 'string') return v || null;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const version = typeof o['os-version'] === 'string' ? o['os-version'] : null;
    const build = typeof o['build-version'] === 'string' ? o['build-version'] : null;
    return version ? `${version}${build ? ` (${build})` : ''}` : build;
  }
  return null;
}

function rawValue(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'object') return JSON.stringify(v, null, 1);
  return String(v);
}

export function DdmCard({ deviceId, enabled, canSync, className }: { deviceId: number; enabled: boolean; canSync: boolean; className?: string }) {
  const { t } = useTranslation();
  const [view, setView] = useState<DeviceDeclarationsView | null>(null);
  const [items, setItems] = useState<DeviceStatusItemView[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => {
    // 503 when the integration is off: the card then shows the satellite's flag alone.
    appleApi.declarations(deviceId).then(setView).catch(() => setView(null));
    appleApi.statusItems(deviceId).then(setItems).catch(() => setItems([]));
  }, [deviceId]);
  useEffect(() => { load(); }, [load]);
  const sync = async () => {
    setBusy(true);
    try {
      const r = await appleApi.ddmSync(deviceId);
      toast.success(r.requested
        ? (t('deviceSummary.ddm.syncRequested') || 'Synchronisation requested')
        : (t('deviceSummary.ddm.syncAlready') || 'A synchronisation was already requested within the minute'));
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  const inSync = view ? !!view.declarationsToken && view.declarationsToken === view.fetchedToken : null;
  const invalid = view?.declarations.filter((d) => d.status?.valid === 'invalid').length ?? 0;
  const byItem = new Map(items.map((i) => [i.item, i]));
  const others = items.filter((i) => !KNOWN_ITEMS.has(i.item));

  const knownValue = (key: KnownKey, v: unknown) => {
    if (key === 'passcodePresent' || key === 'passcodeCompliant') return <Flag value={typeof v === 'boolean' ? v : null} />;
    if (key === 'pendingVersion') return versionOf(v) ? <span className="text-amber-400">{versionOf(v)}</span> : null;
    // installState: the known values translated, an unknown one as reported.
    return typeof v === 'string' && v ? trCode(`deviceSummary.ddm.installStateValue.${v}`, v) : rawValue(v);
  };

  return (
    <InfoCard
      icon={Layers}
      title={t('deviceSummary.cards.ddm') || 'Declarative management'}
      className={className}
      action={canSync && enabled ? <Button size="sm" variant="secondary" loading={busy} onClick={sync}>{t('deviceSummary.ddm.sync') || 'Synchronise'}</Button> : undefined}
    >
      <InfoRows>
        <InfoRow
          label={t('common.status') || 'Status'}
          value={(
            <span className="inline-flex flex-wrap items-center gap-2">
              <StateBadge tone={enabled ? 'green' : 'gray'} label={enabled ? (t('deviceSummary.ddm.enabled') || 'Enabled') : (t('deviceSummary.ddm.disabled') || 'Not enabled')} />
              {view && inSync !== null && (
                <StateBadge
                  tone={inSync ? 'green' : view.syncOpen ? 'blue' : 'amber'}
                  label={inSync ? (t('deviceSummary.ddm.inSync') || 'In sync') : view.syncOpen ? (t('deviceSummary.ddm.syncing') || 'Synchronising') : (t('deviceSummary.ddm.outOfSync') || 'Not fetched yet')}
                />
              )}
            </span>
          )}
        />
        {view && (
          <InfoRow
            label={t('deviceSummary.ddm.declarations') || 'Declarations'}
            value={(
              <span className="block">
                {view.declarations.length}
                {invalid > 0 && <span className="ml-2 text-red-400">{t('deviceSummary.ddm.invalid', { count: invalid }) || `${invalid} invalid`}</span>}
                {view.fetchedAt && <span className="ml-2 text-[11px] text-text-muted">{t('deviceSummary.ddm.fetchedAt', { at: formatDateTime(view.fetchedAt) }) || `fetched ${formatDateTime(view.fetchedAt)}`}</span>}
              </span>
            )}
          />
        )}
        {KNOWN.filter((k) => byItem.has(k.item)).map((k) => {
          const i = byItem.get(k.item) as DeviceStatusItemView;
          return <InfoRow key={k.item} label={t(`deviceSummary.ddm.item.${k.key}`) || k.fallback} value={knownValue(k.key, i.value)} />;
        })}
      </InfoRows>

      {view && view.declarations.length > 0 && (
        <ul className="mt-2 space-y-0.5 text-[11px]">
          {view.declarations.slice(0, open ? 200 : 5).map((d) => (
            <li key={d.identifier} className="flex flex-wrap items-center gap-1.5">
              <span className="font-mono break-all text-text-secondary">{d.identifier}</span>
              <span className={d.status === null ? 'text-text-muted' : d.status.valid === 'invalid' ? 'text-red-400' : d.status.active ? 'text-green-400' : 'text-text-muted'}>
                {d.status === null ? (t('deviceSummary.ddm.notReported') || 'not reported yet')
                  : d.status.valid === 'invalid' ? (t('deviceSummary.ddm.invalidOne') || 'invalid')
                    : d.status.active ? (t('deviceSummary.ddm.active') || 'active') : (t('deviceSummary.ddm.inactive') || 'inactive')}
              </span>
            </li>
          ))}
        </ul>
      )}
      {(view?.declarations.length ?? 0) > 5 && (
        <button type="button" onClick={() => setOpen(!open)} className="mt-1 text-xs text-accent hover:underline coarse:min-h-9">
          {open ? (t('approvals.showLess') || 'Show less') : (t('approvals.showMore') || 'Show more')}
        </button>
      )}

      {others.length > 0 && (
        <details className="mt-3 rounded-lg border border-border/60 px-3 py-2">
          <summary className="cursor-pointer select-none text-xs font-medium text-text-secondary hover:text-text-primary coarse:py-1.5">
            {t('deviceSummary.ddm.item.other') || 'Other status items'} ({others.length})
          </summary>
          <ul className="mt-2 space-y-1.5 text-[11px]">
            {others.map((i) => (
              <li key={i.item} className="min-w-0">
                <span className="text-text-secondary">{trCode(i.i18nKey, i.item)}</span>
                <pre className="mt-0.5 max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-text-primary">{rawValue(i.value)}</pre>
              </li>
            ))}
          </ul>
        </details>
      )}
    </InfoCard>
  );
}
