import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { ArrowLeft, Bell, Clock, Hand, Info, Loader2, MonitorSmartphone, PhoneCall, Power, RefreshCw, ShieldAlert, Eye } from 'lucide-react';
import {
  SocketEvents, isRemoteFinalState,
  type RemoteEndReason, type RemoteMode, type RemoteSessionChanged, type RemoteSessionDto,
} from '@obligarth/shared';
import { remoteApi } from '@/api/remote.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { PageContainer } from '@/components/common/PageContainer';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { RemoteViewer } from '@/components/remote/RemoteViewer';
import {
  STATE_TONE, formatDuration, remoteEndReasonLabel, remoteEndedByLabel, remoteModeLabel, remoteStateLabel, secondsUntil,
} from '@/components/remote/remoteLabels';
import { dropViewerToken, keepViewerToken, viewerTokenOf } from '@/components/remote/viewerTokens';
import { registerSocketListener } from '@/socket/socketListeners';
import { useAuthStore } from '@/store/authStore';
import { apiErrorCode, apiErrorMessage, apiErrorStatus } from '@/utils/apiError';

// =============================================================================
// A remote assistance session (P0-15 §7, §0.1; route /devices/:id/remote/:sessionId): its states — waiting for its
// approval, waiting for the device (a countdown and the reminder of « Ask for help »), the device starting its screen
// capture (its system dialog, 60 s), connecting, in progress (the viewer), ended with its reason (projection_denied
// explained: the system authorisation of the capture is to be validated once on the device, « Don't show again »
// ticked). A permanent banner says the user is told by a notification. End, take control (the server grants it after
// the technician's strict second factor: nothing is asked of the device) and back to the view. The state follows
// REMOTE_SESSION_CHANGED and a light polling; the viewer's token stays in this tab (sessionStorage) until the end.
// =============================================================================

const BEFORE_LIVE = new Set(['queued', 'awaiting_consent', 'connecting']);

export function RemoteSessionPage() {
  const { id, sessionId = '' } = useParams<{ id: string; sessionId: string }>();
  const deviceId = Number.parseInt(id ?? '', 10);
  const { t } = useTranslation();
  const confirm = useConfirm();
  const me = useAuthStore((s) => s.user?.id);
  const isAdmin = useAuthStore((s) => s.isAdmin);
  const [s, setS] = useState<RemoteSessionDto | null>(null);
  const [missing, setMissing] = useState(false);
  const [token, setToken] = useState<string | null>(() => viewerTokenOf(sessionId));
  const [busy, setBusy] = useState<string | null>(null);
  const [gone, setGone] = useState<'replaced' | 'refused' | null>(null);
  const [viewerKey, setViewerKey] = useState(0);
  const [now, setNow] = useState(Date.now());
  const loading = useRef(false);

  const load = useCallback(async () => {
    if (loading.current) return;
    loading.current = true;
    try {
      const dto = await remoteApi.get(sessionId);
      setS(dto);
      setMissing(false);
      if (isRemoteFinalState(dto.state)) { dropViewerToken(sessionId); setToken(null); }
    } catch (err) {
      if (apiErrorStatus(err) === 404) setMissing(true);
    } finally {
      loading.current = false;
    }
  }, [sessionId]);

  useEffect(() => { setToken(viewerTokenOf(sessionId)); setS(null); void load(); }, [sessionId, load]);

  // Live: the server's event, and a light polling (every 3 s before the stream, 10 s awaiting an approval, 15 s during
  // the stream).
  useEffect(() => registerSocketListener(SocketEvents.REMOTE_SESSION_CHANGED, (p: RemoteSessionChanged) => {
    if (p?.sessionId === sessionId) void load();
  }), [sessionId, load]);
  const final = s ? isRemoteFinalState(s.state) : false;
  useEffect(() => {
    if (!s || final) return undefined;
    const id2 = setInterval(() => { void load(); }, s.state === 'live' ? 15_000 : s.state === 'awaiting_approval' ? 10_000 : 3_000);
    return () => clearInterval(id2);
  }, [s, final, load]);
  // The countdowns.
  useEffect(() => {
    if (!s || final) return undefined;
    const id3 = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(id3);
  }, [s, final]);

  const requester = !!s && me !== undefined && Number(s.requestedBy) === Number(me);

  const act = async (name: string, fn: () => Promise<RemoteSessionDto>, done?: string) => {
    setBusy(name);
    try {
      const dto = await fn();
      setS(dto);
      if (done) toast.success(done);
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
      void load();
    } finally {
      setBusy(null);
    }
  };
  const end = async () => {
    if (!(await confirm({ message: t('remote.session.confirmEnd') || 'End this remote assistance session?' }))) return;
    await act('end', () => remoteApi.end(sessionId), t('remote.session.ended') || 'Session ended');
  };
  const escalate = () => act('escalate', () => remoteApi.escalate(sessionId), t('remote.session.controlGranted') || 'You have the control');
  const release = () => act('release', () => remoteApi.release(sessionId), t('remote.session.controlReleased') || 'Back to the view');
  const fetchToken = async () => {
    setBusy('token');
    try {
      const r = await remoteApi.viewerToken(sessionId);
      keepViewerToken(sessionId, r.viewerToken);
      setToken(r.viewerToken);
      setS(r.session);
      setGone(null);
    } catch (err) {
      if (apiErrorCode(err) === 'viewerTokenIssued') setGone('replaced');
      else if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(null);
    }
  };

  const onEffective = useCallback((m: RemoteMode) => { setS((prev) => (prev ? { ...prev, effectiveMode: m } : prev)); }, []);
  const onEnded = useCallback((_r: RemoteEndReason) => { void load(); }, [load]);
  const onGone = useCallback((why: 'replaced' | 'refused') => { setGone(why); void load(); }, [load]);

  const back = (
    <Link to={Number.isFinite(deviceId) ? `/devices/${deviceId}?tab=remote` : '/devices'} className="inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary coarse:min-h-10">
      <ArrowLeft size={14} className="shrink-0" />
      {t('remote.session.backToDevice') || 'Back to the device'}
    </Link>
  );

  if (missing) {
    return (
      <PageContainer className="space-y-4 text-center">
        <p className="text-text-muted">{t('remote.session.notFound') || 'Session not found'}</p>
        {back}
      </PageContainer>
    );
  }
  if (!s) {
    return (
      <PageContainer className="flex items-center justify-center gap-2 py-10 text-sm text-text-muted">
        <Loader2 size={16} className="animate-spin" />{t('common.loading') || 'Loading…'}
      </PageContainer>
    );
  }

  const left = secondsUntil(s.expiresAt, now);
  const showViewer = requester && !!token && (s.state === 'connecting' || s.state === 'live') && gone === null;
  const canEnd = !final && (requester || isAdmin());
  const control = s.effectiveMode === 'control';

  return (
    <PageContainer className="space-y-4">
      {back}

      <div className="flex flex-wrap items-center gap-2">
        <MonitorSmartphone size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-text-primary">{t('remote.session.title') || 'Remote assistance'}</h1>
        <StateBadge tone={STATE_TONE[s.state] ?? 'gray'} label={remoteStateLabel(s.state)} pulse={!final} />
        <span className="rounded-full bg-bg-tertiary px-2 py-0.5 text-xs text-text-secondary">
          {remoteModeLabel(t, s.effectiveMode)}{s.mode !== s.effectiveMode ? ` (${t('remote.session.asked') || 'asked'}: ${remoteModeLabel(t, s.mode)})` : ''}
        </span>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted">
        <span>{t('remote.session.device') || 'Device'} #{s.deviceId}</span>
        <span>{t('remote.session.by') || 'By'} {s.requestedByName} ({s.operatorOrg})</span>
        <span>{formatDateTime(s.createdAt)}</span>
        {s.reason && <span className="break-words">{t('remote.session.reason') || 'Reason'}: {s.reason}</span>}
        {s.ticket && <span>{t('remote.session.ticket') || 'Ticket'}: {s.ticket}</span>}
        {s.durationSeconds !== null && <span>{t('remote.session.duration') || 'Duration'}: {formatDuration(s.durationSeconds)}</span>}
      </div>

      {!final && (
        <div role="status" className="flex items-start gap-2 rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-sm text-text-primary">
          <Bell size={16} className="mt-0.5 shrink-0 text-accent" />
          <span>{t('remote.session.informedBanner') || 'The user is informed by a notification: at the opening, during the whole session, and at its end.'}</span>
        </div>
      )}

      {!final && (
        <div className="flex flex-wrap gap-2">
          {requester && s.state === 'live' && !control && (
            <Button size="sm" onClick={() => void escalate()} loading={busy === 'escalate'} disabled={busy !== null}>
              <Hand size={14} className="mr-1" />{t('remote.session.takeControl') || 'Take control'}
            </Button>
          )}
          {requester && s.state === 'live' && control && (
            <Button size="sm" variant="secondary" onClick={() => void release()} loading={busy === 'release'} disabled={busy !== null}>
              <Eye size={14} className="mr-1" />{t('remote.session.backToView') || 'Back to the view'}
            </Button>
          )}
          {canEnd && (
            <Button size="sm" variant="danger" onClick={() => void end()} loading={busy === 'end'} disabled={busy !== null}>
              <Power size={14} className="mr-1" />{t('remote.session.end') || 'End'}
            </Button>
          )}
        </div>
      )}

      {s.state === 'awaiting_approval' && (
        <StateCard icon={<Clock size={18} />}>
          <p>{t('remote.session.awaitingApproval') || 'The session waits for its approval by another person.'}</p>
          {s.approvalId !== null && (
            <p className="text-xs text-text-muted">
              {t('remote.session.approvalRequest', { id: s.approvalId }) || `Request #${s.approvalId}`} · {t('remote.session.timeLeft', { time: formatDuration(left) }) || `${formatDuration(left)} left`}
              {' · '}<Link to="/admin/approvals" className="text-accent hover:underline">{t('remote.session.openApprovals') || 'Approvals'}</Link>
            </p>
          )}
        </StateCard>
      )}

      {s.state === 'queued' && (
        <StateCard icon={<Clock size={18} />}>
          <p>{t('remote.session.queued') || 'Waiting for the device: it takes the request at its next contact with the server.'}</p>
          <p className="text-xs text-text-muted">{t('remote.session.timeLeft', { time: formatDuration(left) }) || `${formatDuration(left)} left`}</p>
          <p className="flex items-start gap-2 text-xs text-text-secondary">
            <PhoneCall size={14} className="mt-0.5 shrink-0" />
            <span>{t('remote.session.askForHelp') || 'To go faster, ask the user to press « Ask for help » in the Obligarth agent: the device contacts the server at once.'}</span>
          </p>
        </StateCard>
      )}

      {s.state === 'awaiting_consent' && (
        <StateCard icon={<Loader2 size={18} className="animate-spin" />}>
          <p>{t('remote.session.startingCapture') || 'The device starts the capture of its screen.'}</p>
          <p className="text-xs text-text-muted">{t('remote.session.timeLeft', { time: formatDuration(left) }) || `${formatDuration(left)} left`}</p>
          <p className="text-xs text-text-secondary">
            {t('remote.session.projectionHint') || "If the system authorisation of the capture was never validated with « Don't show again » ticked, someone must press « Start now » on the device within 60 s; otherwise the session fails."}
          </p>
        </StateCard>
      )}

      {requester && !token && BEFORE_LIVE.has(s.state) && gone === null && (
        <StateCard icon={<ShieldAlert size={18} />}>
          <p>{t('remote.session.needToken') || 'Open the viewer of this session (your second factor is asked).'}</p>
          <div><Button size="sm" onClick={() => void fetchToken()} loading={busy === 'token'}>{t('remote.session.openViewer') || 'Open the viewer'}</Button></div>
        </StateCard>
      )}

      {!requester && !final && (
        <StateCard icon={<Info size={18} />}>
          <p>{t('remote.session.notRequester') || 'Only the technician who opened this session sees its screen.'}</p>
        </StateCard>
      )}

      {gone === 'replaced' && !final && (
        <StateCard icon={<Info size={18} />}>
          <p>{t('remote.session.replaced') || 'The viewer of this session is open in another tab or browser. End the session there, or end it here and open a new one.'}</p>
        </StateCard>
      )}
      {gone === 'refused' && !final && requester && (
        <StateCard icon={<RefreshCw size={18} />}>
          <p>{t('remote.session.disconnected') || 'The viewer lost its connection to the session.'}</p>
          <div>
            <Button size="sm" variant="secondary" onClick={() => { setGone(null); setViewerKey((k) => k + 1); }}>
              {t('remote.session.reconnect') || 'Connect again'}
            </Button>
          </div>
        </StateCard>
      )}

      {showViewer && token && (
        <RemoteViewer key={viewerKey} sessionId={sessionId} token={token} effective={s.effectiveMode} onEffective={onEffective} onEnded={onEnded} onGone={onGone} />
      )}

      {final && <EndedCard s={s} />}
    </PageContainer>
  );
}

function StateCard({ icon, children }: { icon: JSX.Element; children: ReactNode }) {
  return (
    <div className="flex items-start gap-3 rounded-lg bg-bg-secondary p-4 text-sm text-text-primary">
      <span className="mt-0.5 shrink-0 text-accent">{icon}</span>
      <div className="min-w-0 flex-1 space-y-2">{children}</div>
    </div>
  );
}

function EndedCard({ s }: { s: RemoteSessionDto }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-3 rounded-lg bg-bg-secondary p-4 text-sm">
      <p className="font-medium text-text-primary">
        {s.endReason ? remoteEndReasonLabel(s.endReason) : remoteStateLabel(s.state)}
        {s.endedBy && <span className="ml-2 text-xs font-normal text-text-muted">({t('remote.session.endedByLabel') || 'ended by'} {remoteEndedByLabel(s.endedBy)})</span>}
      </p>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted">
        {s.startedAt && <span>{t('remote.session.startedAt') || 'Started'}: {formatDateTime(s.startedAt)}</span>}
        {s.endedAt && <span>{t('remote.session.endedAt') || 'Ended'}: {formatDateTime(s.endedAt)}</span>}
        <span>{t('remote.session.duration') || 'Duration'}: {formatDuration(s.durationSeconds)}</span>
        <span>{t('remote.session.inputs') || 'Inputs'}: {s.inputEvents}</span>
      </div>
      {s.endReason === 'projection_denied' && (
        <div className="rounded border border-amber-400/30 bg-amber-400/10 p-3 text-xs text-amber-200">
          <p className="font-medium">{t('remote.session.projectionDeniedTitle') || 'The screen capture was not authorised on the device'}</p>
          <p className="mt-1">
            {t('remote.session.projectionDeniedHelp') || "Android asks once for the authorisation to capture the screen. Nobody accepted it within 60 s, or it was refused. Have it validated once on site: start a session, then on the device tick « Don't show again » and press « Start now ». The next sessions then start with nobody before the device."}
          </p>
        </div>
      )}
    </div>
  );
}
