import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Bell, ShieldCheck } from 'lucide-react';
import { REMOTE_LIMITS, type RemoteMode } from '@obligarth/shared';
import { remoteApi } from '@/api/remote.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { apiErrorMessage } from '@/utils/apiError';
import { keepViewerToken } from './viewerTokens';

// =============================================================================
// « See the screen » / « Take control » of a device (P0-15 §7, §0.1): a reason and a ticket, both optional, then the
// request of the session. The server asks the technician's strict second factor at every opening (the step-up prompt of
// the API client, never the trusted-IP shortcut) and may hold the session for an approval; the viewer opens on its page.
// The user of the device accepts nothing: they are told by notifications.
// =============================================================================

const fieldCls = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';

export function RemoteOpenDialog({ deviceId, mode, onClose }: { deviceId: number; mode: RemoteMode | null; onClose: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [reason, setReason] = useState('');
  const [ticket, setTicket] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (mode) { setReason(''); setTicket(''); } }, [mode]);

  const open = async () => {
    if (!mode) return;
    setBusy(true);
    try {
      const r = await remoteApi.request({ deviceId, mode, reason: reason.trim() || undefined, ticket: ticket.trim() || undefined });
      if (r.viewerToken) keepViewerToken(r.session.id, r.viewerToken);
      if (r.approvalId) toast(t('remote.open.heldForApproval') || 'The session waits for its approval.', { duration: 6000 });
      onClose();
      navigate(`/devices/${deviceId}/remote/${r.session.id}`);
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };

  const title = mode === 'control' ? (t('legacyAgent.actions.remoteControl') || 'Take control') : (t('legacyAgent.actions.remoteView') || 'See the screen');
  return (
    <Modal
      open={mode !== null}
      onClose={() => { if (!busy) onClose(); }}
      size="md"
      title={title}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={() => void open()} loading={busy}>{t('remote.open.start') || 'Open the session'}</Button>
        </>
      )}
    >
      <div className="space-y-3 text-sm">
        <p className="flex items-start gap-2 text-text-secondary">
          <Bell size={15} className="mt-0.5 shrink-0 text-accent" />
          <span>{t('remote.open.informed') || 'The user of the device accepts nothing: a notification tells them a remote assistance session opens, another stays during the whole session, a last one tells its end.'}</span>
        </p>
        <p className="flex items-start gap-2 text-text-secondary">
          <ShieldCheck size={15} className="mt-0.5 shrink-0 text-accent" />
          <span>{t('remote.open.stepUp') || 'Your second factor is asked at each opening and each move to the control. The session is journaled (who, when, device, mode, duration); the picture is never recorded.'}</span>
        </p>
        {mode === 'control' && (
          <p className="text-xs text-text-muted">{t('remote.open.controlNote') || 'In control, your touches, the navigation keys and the text you type reach the device, including on its locked screen.'}</p>
        )}
        <p className="text-xs text-text-muted">{t('remote.open.projectionNote') || "The first session on a device asks the system authorisation of the screen capture: someone must accept it once on the device, ticking « Don't show again ». Without it, a session on a device with nobody in front fails after 60 s."}</p>
        <label className="block">
          <span className="text-xs text-text-muted">{t('remote.open.reason') || 'Reason (optional)'}</span>
          <textarea className={fieldCls} rows={2} maxLength={REMOTE_LIMITS.reasonMax} value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('remote.open.ticket') || 'Ticket number (optional)'}</span>
          <input className={fieldCls} maxLength={REMOTE_LIMITS.ticketMax} value={ticket} onChange={(e) => setTicket(e.target.value)} autoCapitalize="off" spellCheck={false} />
        </label>
      </div>
    </Modal>
  );
}
