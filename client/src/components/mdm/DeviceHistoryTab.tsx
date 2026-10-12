import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, Smartphone, TerminalSquare } from 'lucide-react';
import type { EnrollmentEpisode } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { appleApi, type TimelineEntry } from '@/api/apple.api';
import { Button } from '@/components/common/Button';
import { enrollmentMethodLabel, formatDateTime, managementModeLabel, ownershipLabel } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The history of a device (modele-donnees-mdm §4.7; integration-apple-edge §12.4): its enrollment episodes (one
// per enrollment cycle: a restored device enrolled again keeps its record and opens a new episode), then the
// unified timeline of the integration (events of the device, commands, status items).

const SOURCE_ICON = { device_event: Smartphone, command: TerminalSquare, status: Activity } as const;

/** The text of a timeline entry: its translation, the type of its command, the name of its status item. */
function entryText(e: TimelineEntry): string {
  const params = e.params ?? {};
  const base = trCode(e.i18nKey, e.kind, params);
  const requestType = typeof params.requestType === 'string' ? params.requestType : null;
  if (requestType) return `${base} — ${trCode(`apple.commands.types.${requestType}`, requestType)}`;
  // A status item: its new value, when it is a plain one.
  const value = (params as { value?: unknown }).value;
  if (e.source === 'status' && (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean')) {
    return `${base}: ${String(value).slice(0, 80)}`;
  }
  return base;
}

export function DeviceHistoryTab({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const [episodes, setEpisodes] = useState<EnrollmentEpisode[] | null>(null);
  const [entries, setEntries] = useState<TimelineEntry[] | null>(null);
  const [more, setMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const PAGE = 50;

  useEffect(() => {
    let cancelled = false;
    setEpisodes(null);
    mdmApi.enrollments(deviceId).then((e) => { if (!cancelled) setEpisodes(e); }).catch(() => { if (!cancelled) setEpisodes([]); });
    return () => { cancelled = true; };
  }, [deviceId]);

  const loadTimeline = useCallback((before: string | null) => {
    appleApi.timeline(deviceId, { before, limit: PAGE })
      .then((page) => {
        setEntries((prev) => (before && prev ? [...prev, ...page] : page));
        setMore(page.length === PAGE);
        setError(null);
      })
      .catch((err) => { setEntries((prev) => prev ?? []); setError(apiErrorMessage(err)); });
  }, [deviceId]);
  useEffect(() => { setEntries(null); loadTimeline(null); }, [loadTimeline]);

  return (
    <div className="space-y-6">
      <section>
        <h3 className="text-sm font-semibold text-text-primary mb-2">{t('mdm.history.episodes') || 'Enrollment episodes'}</h3>
        {episodes === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
          : episodes.length === 0 ? <p className="text-sm text-text-muted">{t('mdm.history.noEpisode') || 'No enrollment recorded.'}</p> : (
            <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
              {episodes.map((e) => (
                <li key={e.id} className="px-3 py-2 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-text-primary">{enrollmentMethodLabel(t, e.enrollmentMethod)}</span>
                    <span className="text-xs text-text-muted">{managementModeLabel(t, e.managementMode)} · {ownershipLabel(t, e.ownership)}</span>
                    {!e.endedAt && <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-green-400/10 text-green-400">{t('mdm.history.current') || 'current'}</span>}
                  </div>
                  <div className="mt-0.5 flex flex-wrap gap-x-4 text-[11px] text-text-muted">
                    <span>{t('mdm.history.started') || 'Started'}: {formatDateTime(e.startedAt)}</span>
                    {e.enrolledAt && <span>{t('mdm.history.enrolled') || 'Enrolled'}: {formatDateTime(e.enrolledAt)}</span>}
                    {e.endedAt && (
                      <span>
                        {t('mdm.history.ended') || 'Ended'}: {formatDateTime(e.endedAt)}
                        {e.endReason ? ` (${trCode(`mdm.unenrollReason.${e.endReason}`, e.endReason)})` : ''}
                      </span>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
      </section>

      <section>
        <h3 className="text-sm font-semibold text-text-primary mb-2">{t('mdm.history.timeline') || 'Timeline'}</h3>
        {error && <p className="text-sm text-red-400">{error}</p>}
        {entries === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
          : entries.length === 0 ? <p className="text-sm text-text-muted">{t('mdm.history.noEvent') || 'Nothing happened yet.'}</p> : (
            <ol className="relative ml-2 border-l border-border/60">
              {entries.map((e) => {
                const Icon = SOURCE_ICON[e.source] ?? Activity;
                return (
                  <li key={`${e.source}-${e.ref}-${e.kind}-${e.at}`} className="relative pl-5 py-1.5">
                    <span className="absolute -left-[9px] top-2 flex h-[18px] w-[18px] items-center justify-center rounded-full bg-bg-tertiary text-text-muted">
                      <Icon className="w-3 h-3" />
                    </span>
                    <span className="text-sm text-text-primary">{entryText(e)}</span>
                    <span className="ml-2 text-[11px] text-text-muted">{formatDateTime(e.at)}</span>
                  </li>
                );
              })}
            </ol>
          )}
        {more && entries && entries.length > 0 && (
          <Button size="sm" variant="secondary" className="mt-2" onClick={() => loadTimeline(entries[entries.length - 1].at)}>
            {t('devices.pagination.loadMore') || 'Load more'}
          </Button>
        )}
      </section>
    </div>
  );
}
