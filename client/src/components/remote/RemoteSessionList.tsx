import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react';
import { SocketEvents, type RemoteSessionDto } from '@obligarth/shared';
import { remoteApi, type RemoteSessionFilters, type RemoteSessionPage } from '@/api/remote.api';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { registerSocketListener } from '@/socket/socketListeners';
import { apiErrorMessage } from '@/utils/apiError';
import {
  STATE_TONE, formatDuration, remoteEndReasonLabel, remoteModeLabel, remoteSideLabel, remoteStateLabel,
} from './remoteLabels';

// The journal of the remote assistance sessions (P0-15 §4.2, §7): who, when, the device, the mode, the duration, the
// end and its reason, the reason and the ticket given. The server reads the scope of the caller (every session of the
// tenant with audit.read, else those of the devices it may assist). One row a session, a link to its page.

export function RemoteSessionList({ filters, showDevice }: { filters: Omit<RemoteSessionFilters, 'page'>; showDevice: boolean }) {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [data, setData] = useState<RemoteSessionPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const key = JSON.stringify(filters);
  useEffect(() => { setPage(1); }, [key]);
  const load = useCallback(() => {
    // The filters by their JSON (a new object each render of the caller).
    const f = JSON.parse(key) as Omit<RemoteSessionFilters, 'page'>;
    remoteApi.list({ ...f, page }).then((d) => { setData(d); setError(null); }).catch((err) => { setData((p) => p ?? { items: [], page: 1, pageSize: 50, total: 0 }); setError(apiErrorMessage(err)); });
  }, [key, page]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.REMOTE_SESSION_CHANGED, () => load()), [load]);

  const pages = data ? Math.max(1, Math.ceil(data.total / data.pageSize)) : 1;
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        {data && <span className="text-xs text-text-muted">{t('remote.journal.count', { n: data.total }) || `${data.total} session(s)`}</span>}
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="ml-auto rounded-lg p-2 text-text-muted hover:bg-bg-tertiary hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {data === null ? <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>
        : data.items.length === 0 ? <p className="text-sm text-text-muted">{t('remote.journal.empty') || 'No remote assistance session.'}</p> : (
          <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
            {data.items.map((s) => <Row key={s.id} s={s} showDevice={showDevice} />)}
          </ul>
        )}
      {data && pages > 1 && (
        <div className="flex items-center justify-end gap-2 text-xs text-text-muted">
          <button type="button" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} aria-label={t('remote.journal.previous') || 'Previous page'}
            className="rounded p-1.5 hover:bg-bg-tertiary disabled:opacity-40 coarse:min-h-10 coarse:min-w-10"><ChevronLeft size={16} /></button>
          <span>{page} / {pages}</span>
          <button type="button" disabled={page >= pages} onClick={() => setPage((p) => p + 1)} aria-label={t('remote.journal.next') || 'Next page'}
            className="rounded p-1.5 hover:bg-bg-tertiary disabled:opacity-40 coarse:min-h-10 coarse:min-w-10"><ChevronRight size={16} /></button>
        </div>
      )}
    </div>
  );
}

function Row({ s, showDevice }: { s: RemoteSessionDto; showDevice: boolean }) {
  const { t } = useTranslation();
  return (
    <li className="px-3 py-2.5 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Link to={`/devices/${s.deviceId}/remote/${s.id}`} className="font-medium text-text-primary hover:text-accent">
          {remoteModeLabel(t, s.mode)}
        </Link>
        <StateBadge tone={STATE_TONE[s.state] ?? 'gray'} label={remoteStateLabel(s.state)} pulse={s.state === 'live'} />
        {showDevice && (
          <Link to={`/devices/${s.deviceId}`} className="text-xs text-accent hover:underline">{t('remote.session.device') || 'Device'} #{s.deviceId}</Link>
        )}
        <span className="ml-auto text-[11px] text-text-muted" title={s.id}>{formatDateTime(s.createdAt)}</span>
      </div>
      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] text-text-muted">
        <span>{s.requestedByName} · {s.operatorOrg} ({remoteSideLabel(t, s.requesterSide)})</span>
        <span>{t('remote.session.duration') || 'Duration'}: {formatDuration(s.durationSeconds)}</span>
        {s.endReason && <span>{remoteEndReasonLabel(s.endReason)}</span>}
        {s.reason && <span className="break-words">{t('remote.session.reason') || 'Reason'}: {s.reason}</span>}
        {s.ticket && <span>{t('remote.session.ticket') || 'Ticket'}: {s.ticket}</span>}
      </div>
    </li>
  );
}
