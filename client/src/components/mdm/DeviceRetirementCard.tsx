import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { CheckCircle2, Circle, ShieldOff, XCircle } from 'lucide-react';
import { SocketEvents, type RetirementManualItem, type RetirementView } from '@obligarth/shared';
import { appleApi } from '@/api/apple.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { usePrompt } from '@/components/common/ConfirmDialog';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { InfoCard } from '@/components/mdm/ui/InfoCard';
import { registerSocketListener } from '@/socket/socketListeners';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// Verified retirement of a device (integration-apple-edge §13.3, ENR-17; lot C5): the checklist of the last
// retirement (removal of management, licences, release at the device service, record) and its manual points
// (Apple Business, activation lock), ticked by the operator; the revocation of a stolen device's identity
// (capability mdm:remove, a reason).

const STEP_FALLBACK: Record<RetirementView['steps'][number]['step'], string> = {
  management_removed: 'Management profile removed', licenses_released: 'Licences released', released: 'Released at the device service', retired: 'Record retired',
};
const MANUAL_FALLBACK: Record<RetirementManualItem, string> = {
  apple_business: 'Released in Apple Business', activation_lock: 'Activation lock handled',
};

export function DeviceRetirementCard({ deviceId, canAct, isApple, className }: { deviceId: number; canAct: boolean; isApple: boolean; className?: string }) {
  const { t } = useTranslation();
  const prompt = usePrompt();
  const [view, setView] = useState<RetirementView | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => { appleApi.retirement(deviceId).then(setView).catch(() => setView(null)); }, [deviceId]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.APPLE_DEVICE_CHANGED, (p: { deviceIds?: number[] }) => {
    if (p?.deviceIds?.includes(deviceId)) load();
  }), [deviceId, load]);

  const tick = async (item: RetirementManualItem) => {
    setBusy(true);
    try {
      setView(await appleApi.tickRetirement(deviceId, item));
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  const revoke = async () => {
    const reason = await prompt({
      title: t('deviceRetirement.revokeTitle') || 'Revoke the identity of this device?',
      message: t('deviceRetirement.revokeMessage') || 'For a stolen or lost device: its certificate is revoked and its enrollment released; it can no longer reach the service. Give the reason.',
      confirmLabel: t('deviceRetirement.revoke') || 'Revoke the identity', multiline: true, required: true,
    });
    if (!reason || reason.trim().length < 3) return;
    setBusy(true);
    try {
      const r = await appleApi.revokeIdentity(deviceId, { reason: reason.trim() });
      if ('approvalId' in r) toast.success(t('deviceRetirement.pendingApproval') || 'Request sent for approval');
      else toast.success(t('deviceRetirement.revoked') || 'Identity revoked');
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };

  if (!isApple) return null;
  const started = !!view?.startedAt;
  if (!started && !canAct) return null;
  return (
    <InfoCard
      icon={ShieldOff}
      title={t('deviceRetirement.title') || 'Retirement'}
      className={className}
      action={canAct ? (
        <Button size="sm" variant="danger" onClick={() => { void revoke(); }} disabled={busy}>
          <ShieldOff className="w-4 h-4 mr-1" />{t('deviceRetirement.revoke') || 'Revoke the identity'}
        </Button>
      ) : undefined}
    >
      <div className="space-y-3">
        {started && view ? (
          <>
            <p className="text-xs text-text-muted">{t('deviceRetirement.startedAt', { date: formatDateTime(view.startedAt) }) || `Started ${formatDateTime(view.startedAt)}`}</p>
            <ul className="space-y-1.5 text-sm">
              {view.steps.map((s) => (
                <li key={s.step} className="flex items-start gap-2">
                  {s.outcome === 'cancelled' ? <XCircle className="w-4 h-4 mt-0.5 text-amber-400" />
                    : s.at ? <CheckCircle2 className="w-4 h-4 mt-0.5 text-green-400" /> : <Circle className="w-4 h-4 mt-0.5 text-text-muted" />}
                  <span className={s.at ? 'text-text-primary' : 'text-text-muted'}>
                    {trCode(`deviceRetirement.step.${s.step}`, STEP_FALLBACK[s.step])}
                    {s.outcome && <span className="ml-2 text-[11px] text-text-muted">{trCode(`deviceRetirement.outcome.${s.outcome}`, s.outcome)}</span>}
                  </span>
                </li>
              ))}
              {!view.cancelled && view.manual.map((m) => (
                <li key={m.item} className="flex items-start gap-2">
                  {m.at ? <CheckCircle2 className="w-4 h-4 mt-0.5 text-green-400" /> : <Circle className="w-4 h-4 mt-0.5 text-amber-400" />}
                  <span className={m.at ? 'text-text-primary' : 'text-text-secondary'}>{trCode(`deviceRetirement.manual.${m.item}`, MANUAL_FALLBACK[m.item])}</span>
                  {!m.at && canAct && (
                    <button type="button" disabled={busy} onClick={() => { void tick(m.item); }}
                      className="ml-auto text-xs text-accent hover:underline disabled:opacity-50">
                      {t('deviceRetirement.markDone') || 'Mark as done'}
                    </button>
                  )}
                </li>
              ))}
            </ul>
            {view.cancelled && (
              <p className="text-xs text-amber-400">{t('deviceRetirement.cancelled') || 'Retirement cancelled: the remaining steps were not run and the device was not released.'}</p>
            )}
          </>
        ) : (
          <p className="text-xs text-text-muted">{t('deviceRetirement.none') || 'No retirement started: « Remove from management » starts it.'}</p>
        )}
      </div>
    </InfoCard>
  );
}
