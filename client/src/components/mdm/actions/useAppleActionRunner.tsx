import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import type { MdmDeviceAction } from '@obligarth/shared';
import { appleApi, isAwaitingApproval, newIdempotencyKey } from '@/api/apple.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { GuardedActionDialog } from '@/components/guard/GuardedActionDialog';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// How an Apple action of a device is launched (integration-apple-edge §8.12), shared by the Actions tab and the quick
// actions of the record: a simple command goes to the queue, one that requires a reason asks for it first (10
// characters at least), a guarded one (lock, lost mode, erase) asks for its parameters then opens the dialog of the
// guard engine (reason, typed confirmation, second factor or approver, cancellable delay). No guard logic here.

export const appleCommandLabel = (type: string): string => trCode(`apple.commands.types.${type}`, type);

/** The actions the console can launch without a form of its own: no parameter. */
export const APPLE_SIMPLE = new Set(['DeviceInformation', 'SecurityInfo', 'InstalledApplicationList', 'ManagedApplicationList', 'ProfileList',
  'CertificateList', 'ActivationLockBypassCode', 'RestartDevice', 'ShutDownDevice', 'ClearPasscode', 'DisableLostMode', 'DeviceLocation',
  'PlayLostModeSound']);
/** The guarded actions and their parameters (apple/commands/guarded.ts). */
export const APPLE_GUARDED: Record<string, { actionKey: string; fields: Array<'message' | 'phoneNumber' | 'footnote'>; needsOne?: boolean; toggles?: Array<'preserveDataPlan' | 'disallowProximitySetup'> }> = {
  DeviceLock: { actionKey: 'mdm.device_lock', fields: ['message', 'phoneNumber'] },
  EnableLostMode: { actionKey: 'mdm.lost_mode_enable', fields: ['message', 'phoneNumber', 'footnote'], needsOne: true },
  EraseDevice: { actionKey: 'mdm.erase_device', fields: [], toggles: ['preserveDataPlan', 'disallowProximitySetup'] },
};
export const appleLaunchable = (a: MdmDeviceAction): boolean => APPLE_SIMPLE.has(a.requestType) || a.requestType in APPLE_GUARDED;

export interface AppleActionRunner {
  /** Launch an action of the menu (GET /api/apple/devices/:id/actions). */
  run: (action: MdmDeviceAction) => void;
  /** Open the guard dialog of a guarded action without a command of the menu (the removal from management). */
  guard: (type: string, actionKey: string) => void;
  /** The request type being sent. */
  busy: string | null;
  /** The dialogs of the runner, to render once. */
  dialogs: ReactNode;
}

export function useAppleActionRunner({ deviceId, onQueued }: { deviceId: number; onQueued?: () => void }): AppleActionRunner {
  const { t } = useTranslation();
  const [reasonFor, setReasonFor] = useState<MdmDeviceAction | null>(null);
  const [guardFor, setGuardFor] = useState<{ type: string; actionKey: string } | null>(null);
  const [guardParams, setGuardParams] = useState<Record<string, unknown>>({});
  const [paramsFor, setParamsFor] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // The latest callback (the caller's reload changes with its state).
  const queued = useRef(onQueued);
  useEffect(() => { queued.current = onQueued; }, [onQueued]);

  const send = async (action: MdmDeviceAction, reason?: string) => {
    setBusy(action.requestType);
    try {
      const r = action.requestType === 'DeviceInformation'
        ? await appleApi.refreshInventory(deviceId).then(() => null)
        : await appleApi.enqueue(deviceId, { requestType: action.requestType, reason }, newIdempotencyKey());
      if (r && isAwaitingApproval(r)) toast(t('mdm.outcome.awaitingApproval') || 'Waiting for a second approver: nothing has changed yet.', { duration: 7000 });
      else toast.success(t('apple.commands.queuedOne') || 'Command queued: it reaches the device at its next contact.');
      queued.current?.();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(null);
    }
  };
  const run = (action: MdmDeviceAction) => {
    const guarded = APPLE_GUARDED[action.requestType];
    if (guarded) {
      setGuardParams(guarded.toggles ? { preserveDataPlan: true, disallowProximitySetup: false } : {});
      if (guarded.fields.length || guarded.toggles) setParamsFor(action.requestType);
      else setGuardFor({ type: action.requestType, actionKey: guarded.actionKey });
      return;
    }
    if (action.reasonRequired) { setReasonFor(action); return; }
    void send(action);
  };

  const paramsSpec = paramsFor ? APPLE_GUARDED[paramsFor] : null;
  const paramsOk = !paramsSpec?.needsOne || paramsSpec.fields.some((f) => String(guardParams[f] ?? '').trim().length > 0);

  const dialogs = (
    <>
      {/* A reason the command requires (10 characters at least) */}
      <ReasonDialog
        action={reasonFor}
        onClose={() => setReasonFor(null)}
        onConfirm={(reason) => { const a = reasonFor; setReasonFor(null); if (a) void send(a, reason); }}
      />

      {/* Parameters of a guarded action, before its dialog */}
      <Modal
        open={paramsFor !== null}
        onClose={() => setParamsFor(null)}
        size="sm"
        title={paramsFor ? appleCommandLabel(paramsFor) : ''}
        footer={(
          <>
            <Button variant="secondary" onClick={() => setParamsFor(null)}>{t('common.cancel') || 'Cancel'}</Button>
            <Button
              disabled={!paramsOk}
              onClick={() => {
                const spec = paramsFor ? APPLE_GUARDED[paramsFor] : null;
                if (!spec || !paramsFor) return;
                // Empty texts are left out: the server refuses an empty message.
                setGuardParams((p) => Object.fromEntries(Object.entries(p).filter(([, v]) => typeof v === 'boolean' || String(v).trim() !== '').map(([k, v]) => [k, typeof v === 'string' ? v.trim() : v])));
                setGuardFor({ type: paramsFor, actionKey: spec.actionKey });
                setParamsFor(null);
              }}
            >
              {t('common.next') || 'Next'}
            </Button>
          </>
        )}
      >
        <div className="space-y-3 text-sm">
          {paramsSpec?.fields.map((f) => (
            <label key={f} className="block">
              <span className="text-xs text-text-muted">{t(`apple.actions.param.${f}`) || f}</span>
              <input
                value={String(guardParams[f] ?? '')}
                onChange={(e) => setGuardParams((p) => ({ ...p, [f]: e.target.value }))}
                maxLength={f === 'phoneNumber' ? 30 : 200}
                className="mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary"
              />
            </label>
          ))}
          {paramsSpec?.toggles?.map((f) => (
            <label key={f} className="flex items-center gap-2">
              <input type="checkbox" checked={guardParams[f] === true} onChange={(e) => setGuardParams((p) => ({ ...p, [f]: e.target.checked }))} className="accent-accent" />
              <span>{t(`apple.actions.param.${f}`) || f}</span>
            </label>
          ))}
          {paramsSpec?.needsOne && <p className="text-[11px] text-text-muted">{t('apple.actions.messageOrPhone') || 'A message or a phone number is required: it is shown on the locked screen.'}</p>}
        </div>
      </Modal>

      <GuardedActionDialog
        open={guardFor !== null}
        onClose={() => setGuardFor(null)}
        actionKey={guardFor?.actionKey ?? 'mdm.device_lock'}
        selection={{ deviceIds: [deviceId] }}
        params={guardFor && guardFor.type in APPLE_GUARDED ? guardParams : undefined}
        onDone={() => { queued.current?.(); }}
      />
    </>
  );

  return { run, guard: (type, actionKey) => setGuardFor({ type, actionKey }), busy, dialogs };
}

function ReasonDialog({ action, onClose, onConfirm }: { action: MdmDeviceAction | null; onClose: () => void; onConfirm: (reason: string) => void }) {
  const { t } = useTranslation();
  const [reason, setReason] = useState('');
  const last = useRef<string | null>(null);
  useEffect(() => {
    if (action && last.current !== action.requestType) setReason('');
    last.current = action?.requestType ?? null;
  }, [action]);
  return (
    <Modal
      open={action !== null}
      onClose={onClose}
      size="sm"
      title={action ? appleCommandLabel(action.requestType) : ''}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button disabled={reason.trim().length < 10} onClick={() => onConfirm(reason.trim())}>{t('apple.commands.send') || 'Send'}</Button>
        </>
      )}
    >
      <label className="block text-sm">
        <span className="text-xs text-text-muted">{t('apple.commands.reasonRequired') || 'Reason (10 characters at least): it is written to the audit log'}</span>
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} rows={3}
          className="mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary" />
      </label>
    </Modal>
  );
}
