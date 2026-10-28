import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { MonitorSmartphone } from 'lucide-react';
import { REMOTE_REQUESTER_SIDES, REMOTE_SESSION_STATES, type RemoteRequesterSide, type RemoteSessionState } from '@obligarth/shared';
import { PageContainer } from '@/components/common/PageContainer';
import { RemoteSessionList } from '@/components/remote/RemoteSessionList';
import { remoteSideLabel, remoteStateLabel } from '@/components/remote/remoteLabels';

// =============================================================================
// The journal of the remote assistance sessions of the tenant (P0-15 §4.2, §7; Administration, beside Privacy): every
// session with audit.read (the administrators, the client approver, the auditor or DPO), else those of the devices the
// caller may assist (the server reads the scope). Filters: device, state, side, period.
// =============================================================================

const fieldCls = 'rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary coarse:min-h-10';

/** A day of a date field → the ISO time of its local start (to: the start of the next day). */
function dayIso(day: string, next = false): string | undefined {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return undefined;
  const [y, m, d] = day.split('-').map(Number);
  const at = new Date(y, m - 1, d + (next ? 1 : 0));
  return Number.isNaN(at.getTime()) ? undefined : at.toISOString();
}

export function RemoteSessionsPage() {
  const { t } = useTranslation();
  const [device, setDevice] = useState('');
  const [state, setState] = useState<RemoteSessionState | ''>('');
  const [side, setSide] = useState<RemoteRequesterSide | ''>('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const filters = useMemo(() => ({
    deviceId: /^[1-9][0-9]{0,9}$/.test(device.trim()) ? Number(device.trim()) : undefined,
    state: state || undefined,
    side: side || undefined,
    from: dayIso(from),
    to: dayIso(to, true),
  }), [device, state, side, from, to]);

  return (
    <PageContainer className="space-y-4">
      <div className="flex items-center gap-2">
        <MonitorSmartphone size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-text-primary">{t('remote.journal.title') || 'Remote assistance sessions'}</h1>
      </div>
      <p className="text-sm text-text-muted">
        {t('remote.journal.intro') || 'Every remote assistance session of this tenant: who opened it, when, on which device, in which mode, how long, and why it ended. The picture is never recorded.'}
      </p>
      <div className="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap">
        <label className="col-span-2 flex flex-col text-xs text-text-muted sm:col-span-1">
          {t('remote.journal.device') || 'Device number'}
          <input className={fieldCls} inputMode="numeric" value={device} onChange={(e) => setDevice(e.target.value)} />
        </label>
        <label className="flex flex-col text-xs text-text-muted">
          {t('remote.journal.state') || 'State'}
          <select className={fieldCls} value={state} onChange={(e) => setState(e.target.value as RemoteSessionState | '')}>
            <option value="">{t('remote.journal.all') || 'All'}</option>
            {REMOTE_SESSION_STATES.map((s) => <option key={s} value={s}>{remoteStateLabel(s)}</option>)}
          </select>
        </label>
        <label className="flex flex-col text-xs text-text-muted">
          {t('remote.journal.side') || 'Side'}
          <select className={fieldCls} value={side} onChange={(e) => setSide(e.target.value as RemoteRequesterSide | '')}>
            <option value="">{t('remote.journal.all') || 'All'}</option>
            {REMOTE_REQUESTER_SIDES.map((s) => <option key={s} value={s}>{remoteSideLabel(t, s)}</option>)}
          </select>
        </label>
        <label className="flex flex-col text-xs text-text-muted">
          {t('remote.journal.from') || 'From'}
          <input type="date" className={fieldCls} value={from} onChange={(e) => setFrom(e.target.value)} />
        </label>
        <label className="flex flex-col text-xs text-text-muted">
          {t('remote.journal.to') || 'To'}
          <input type="date" className={fieldCls} value={to} onChange={(e) => setTo(e.target.value)} />
        </label>
      </div>
      <RemoteSessionList filters={filters} showDevice />
    </PageContainer>
  );
}
