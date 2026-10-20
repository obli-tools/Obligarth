import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { ShieldAlert, Clock, Users, Gauge } from 'lucide-react';
import toast from 'react-hot-toast';
import type { GuardOutcome, GuardSelection } from '@obligarth/shared';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { guardApi, type GuardPreview } from '@/api/guard.api';
import { isStepUpHandled } from '@/api/client';

// The request of a guarded action (audit-durci §10.11, D23): the reason, an
// optional ticket, the typed confirmation (the device's name for one device,
// the number of devices otherwise), with the level, the delay and the quota
// announced before sending. The server decides (floors, matrix, freeze,
// cooldown, hourly cap); a step-up is asked by the client's interceptor.

/** A translated message for a refusal code of the guard (server: AppError code). */
export function guardErrorMessage(t: TFunction, code: string | undefined, fallback: string, details?: Record<string, unknown>): string {
  switch (code) {
    case 'noTargets': return t('guard.errors.noTargets') || 'The selection designates no device.';
    case 'targetsOutsideScope': return t('guard.errors.targetsOutsideScope') || 'Some devices are outside your scope.';
    case 'tenantFrozen': return t('guard.errors.tenantFrozen') || 'The tenant is frozen: no guarded action until it is unfrozen.';
    case 'privilegeCooldown': return t('guard.errors.privilegeCooldown', { until: details?.until ? new Date(String(details.until)).toLocaleString() : '' })
      || 'Your administrator rights are too recent (72 hours) for a destructive action.';
    case 'personalDeviceForbidden': return t('guard.errors.personalDeviceForbidden') || 'This action is refused on personal devices.';
    case 'wholeFleetForbidden': return t('guard.errors.wholeFleetForbidden') || 'This action is refused on the whole fleet.';
    case 'channelMismatch': return t('guard.errors.channelMismatch') || 'This action does not apply to some of the selected devices (another management channel).';
    case 'hourlyCapExceeded': return t('guard.errors.hourlyCapExceeded', { remaining: details?.remaining ?? 0, cap: details?.cap ?? 0 })
      || 'The hourly cap of destructive actions would be exceeded.';
    case 'confirmationMismatch': return t('guard.errors.confirmationMismatch') || 'The confirmation does not match.';
    case 'reasonRequired': return t('guard.errors.reasonRequired') || 'A reason of 5 to 500 characters is required.';
    case 'crossTenantBatch': return t('guard.errors.crossTenantBatch') || 'One request acts on one tenant only.';
    case 'approverSideRequired': return t('guard.errors.approverSideRequired') || 'This request needs an approver of the other side.';
    case 'selfApproval': return t('guard.errors.selfApproval') || 'The requester cannot review this request.';
    case 'approverFallbackHeld': return t('guard.errors.approverFallbackHeld', { until: details?.until ? new Date(String(details.until)).toLocaleString() : '' })
      || 'No client approver: one was removed recently, and the fallback on an MSP approver stays closed for now.';
    case 'auditUnavailable': return t('audit.errors.unavailable') || 'The action was not carried out: the audit log is unavailable.';
    default: return fallback;
  }
}

export function delayText(t: TFunction, seconds: number): string {
  if (seconds <= 0) return t('guard.delay.none') || 'no delay';
  if (seconds < 60) return t('guard.delay.seconds', { count: seconds }) || `${seconds} s`;
  return t('guard.delay.minutes', { count: Math.round(seconds / 60) }) || `${Math.round(seconds / 60)} min`;
}

export interface GuardedActionDialogProps {
  open: boolean;
  onClose: () => void;
  actionKey: string;
  selection: GuardSelection;
  /** Title of the dialog (default: the action's name). */
  title?: string;
  params?: Record<string, unknown>;
  /** The parameters shown to the preview when they differ from the request's (a secret is never previewed: lot AN-C2). */
  previewParams?: Record<string, unknown>;
  onDone?: (outcome: GuardOutcome) => void;
}

export function GuardedActionDialog({ open, onClose, actionKey, selection, title, params, previewParams, onDone }: GuardedActionDialogProps) {
  const { t } = useTranslation();
  const [preview, setPreview] = useState<GuardPreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [ticket, setTicket] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setPreview(null);
    setPreviewError(null);
    setReason('');
    setTicket('');
    setConfirm('');
    let cancelled = false;
    guardApi.preview({ actionKey, selection, params: previewParams ?? params }).then((p) => { if (!cancelled) setPreview(p); }).catch((err) => {
      if (cancelled) return;
      const body = err?.response?.data;
      setPreviewError(guardErrorMessage(t, body?.code, body?.error || (t('common.error') || 'Error'), body?.details));
    });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, actionKey, JSON.stringify(selection)]);

  const reasonOk = reason.trim().length >= 5 && reason.trim().length <= 500;
  const confirmOk = !preview || preview.confirmation === 'none' || confirm.trim() === (preview.expectedConfirmation ?? '').trim();

  const submit = async () => {
    if (!preview || !reasonOk || !confirmOk) return;
    setBusy(true);
    try {
      const outcome = await guardApi.request({
        actionKey, selection, params, reason: reason.trim(), ticket: ticket.trim() || undefined,
        confirm: preview.confirmation === 'none' ? undefined : confirm.trim(),
      });
      if (outcome.state === 'scheduled') {
        toast.success(outcome.delaySeconds > 0
          ? (t('guard.toast.scheduled', { at: new Date(outcome.executeAfter).toLocaleTimeString() }) || `Scheduled: runs at ${new Date(outcome.executeAfter).toLocaleTimeString()} unless cancelled`)
          : (t('guard.toast.running') || 'Accepted: the action runs now'));
      } else {
        toast(outcome.approverFallback
          ? (t('guard.toast.awaitingFallback') || 'Waiting for a second MSP administrator (no client approver designated)')
          : outcome.approverSide === 'client'
            ? (t('guard.toast.awaitingClient') || 'Waiting for the approval of a client approver')
            : (t('guard.toast.awaiting') || 'Waiting for a second approver'), { duration: 6000 });
      }
      onDone?.(outcome);
      onClose();
    } catch (err: any) {
      if (!isStepUpHandled(err)) {
        const body = err?.response?.data;
        toast.error(guardErrorMessage(t, body?.code, body?.error || (t('common.error') || 'Error'), body?.details), { duration: 8000 });
      }
    } finally {
      setBusy(false);
    }
  };

  const levelText = preview?.level === 'restricted'
    ? (t('guard.level.restricted') || 'Second approver required')
    : (t('guard.level.sensitive') || 'Your second factor is required');

  return (
    <Modal
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      title={title || t(`guard.actions.${actionKey}`, actionKey)}
      icon={<ShieldAlert className="w-4 h-4 text-red-400" />}
      size="md"
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button variant="danger" onClick={submit} loading={busy} disabled={!preview || !reasonOk || !confirmOk || busy}>
            {preview?.level === 'restricted' ? (t('guard.dialog.request') || 'Request') : (t('guard.dialog.confirm') || 'Confirm')}
          </Button>
        </>
      )}
    >
      {previewError ? (
        <p className="text-sm text-red-400">{previewError}</p>
      ) : !preview ? (
        <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
      ) : (
        <div className="space-y-3 text-sm">
          <div className="rounded border border-red-400/30 bg-red-400/5 p-3 space-y-1.5">
            <p className="font-medium text-text-primary">
              {t('guard.dialog.targets', { count: preview.targetCount }) || `${preview.targetCount} device(s)`}
              {preview.bulk && <span className="ml-2 text-[11px] uppercase text-orange-400">{t('guard.dialog.bulk') || 'batch'}</span>}
              {preview.requalified && <span className="ml-2 text-[11px] text-orange-400">{t('guard.dialog.requalified') || '(third request in 15 min: treated as a batch)'}</span>}
            </p>
            <p className="flex items-center gap-1.5 text-text-secondary"><Users className="w-3.5 h-3.5" />{levelText}</p>
            <p className="flex items-center gap-1.5 text-text-secondary"><Clock className="w-3.5 h-3.5" />
              {t('guard.dialog.delay', { delay: delayText(t, preview.delaySeconds) }) || `Delay before execution: ${delayText(t, preview.delaySeconds)} (cancellable)`}
            </p>
            {preview.quota && (
              <p className="flex items-center gap-1.5 text-text-secondary"><Gauge className="w-3.5 h-3.5" />
                {t('guard.dialog.quota', { remaining: preview.quota.remaining, cap: preview.quota.cap }) || `Hourly budget: ${preview.quota.remaining} of ${preview.quota.cap} devices left`}
              </p>
            )}
          </div>
          <label className="block">
            <span className="text-xs text-text-muted">{t('guard.dialog.reason') || 'Reason (required)'}</span>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={500}
              rows={2}
              className="mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary"
            />
          </label>
          <label className="block">
            <span className="text-xs text-text-muted">{t('guard.dialog.ticket') || 'Ticket number (optional)'}</span>
            <input
              value={ticket}
              onChange={(e) => setTicket(e.target.value)}
              maxLength={64}
              className="mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary"
              autoCapitalize="off"
              spellCheck={false}
            />
          </label>
          {preview.confirmation !== 'none' && (
            <label className="block">
              <span className="text-xs text-text-muted">
                {preview.confirmation === 'name'
                  ? (t('guard.dialog.typeName', { name: preview.expectedConfirmation }) || `Type the device name to confirm: ${preview.expectedConfirmation}`)
                  : (t('guard.dialog.typeCount', { count: preview.targetCount }) || `Type the number of devices to confirm: ${preview.targetCount}`)}
              </span>
              <input
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm font-mono text-text-primary"
                autoCapitalize="off"
                autoComplete="off"
                spellCheck={false}
              />
            </label>
          )}
        </div>
      )}
    </Modal>
  );
}
