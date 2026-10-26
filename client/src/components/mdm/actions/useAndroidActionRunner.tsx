import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import type { AndroidDeviceAction } from '@obligarth/shared';
import { androidApi } from '@/api/android.api';
import { newIdempotencyKey } from '@/api/apple.api';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { GuardedActionDialog } from '@/components/guard/GuardedActionDialog';
import { Labeled, errorToast, fieldClass } from '@/components/android/ui';
import { trCode } from '@/utils/apiError';

// How an Android command of a device is launched (android-amapi §11.2; lot AN-C2), shared by the Android Actions tab
// and the quick actions of the record: its parameters first when it has some, then the queue (a command that is not
// guarded, behind the restriction of the tenant) or the dialog of the guard engine. A new password typed for
// RESET_PASSWORD leaves the state of the form once the request is built and is never shown in the preview.

export const androidActionLabel = (type: string): string => trCode(`android.commands.types.${type}`, type);

type ParamField = 'message' | 'phoneNumber' | 'email' | 'streetAddress' | 'organization' | 'wipeReason' | 'newPassword' | 'packageNames';
const PARAMS: Record<string, { fields: ParamField[]; flags?: { key: 'flags' | 'wipeDataFlags'; values: string[] }; needsOne?: ParamField[] }> = {
  START_LOST_MODE: { fields: ['message', 'phoneNumber', 'email', 'streetAddress', 'organization'], needsOne: ['message', 'phoneNumber', 'email', 'streetAddress'] },
  WIPE: { fields: ['wipeReason'], flags: { key: 'wipeDataFlags', values: ['PRESERVE_RESET_PROTECTION_DATA', 'WIPE_EXTERNAL_STORAGE', 'WIPE_ESIMS'] } },
  RESET_PASSWORD: { fields: ['newPassword'], flags: { key: 'flags', values: ['REQUIRE_ENTRY', 'DO_NOT_ASK_CREDENTIALS_ON_BOOT', 'LOCK_NOW'] } },
  CLEAR_APP_DATA: { fields: ['packageNames'], needsOne: ['packageNames'] },
  DISABLE: { fields: ['message'] },
};

export interface AndroidActionRunner {
  run: (action: AndroidDeviceAction) => void;
  /** The type being sent. */
  busy: string | null;
  /** The dialogs of the runner, to render once. */
  dialogs: ReactNode;
}

export function useAndroidActionRunner({ deviceId, ownership, onQueued }: { deviceId: number; ownership: string; onQueued?: () => void }): AndroidActionRunner {
  const { t } = useTranslation();
  const [paramsFor, setParamsFor] = useState<AndroidDeviceAction | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [flags, setFlags] = useState<string[]>([]);
  const [factoryReset, setFactoryReset] = useState(false);
  const [guard, setGuard] = useState<{ actionKey: string; params: Record<string, unknown> } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // The latest callback (the caller's reload changes with its state).
  const queued = useRef(onQueued);
  useEffect(() => { queued.current = onQueued; }, [onQueued]);

  /** The parameters of an action as the server reads them (empty texts left out). */
  const paramsOf = (a: AndroidDeviceAction): Record<string, unknown> => {
    const spec = PARAMS[a.type];
    const out: Record<string, unknown> = {};
    for (const f of spec?.fields ?? []) {
      const v = (values[f] ?? '').trim();
      if (!v) continue;
      out[f] = f === 'packageNames' ? v.split(/[\s,;]+/).filter(Boolean) : v;
    }
    if (spec?.flags && flags.length) out[spec.flags.key] = flags;
    if (a.type === 'DISABLE') out.enable = false;
    if (a.type === 'ENABLE') out.enable = true;
    if (a.type === 'REMOVE_MANAGEMENT' && ownership === 'corporate_personal' && factoryReset) out.mode = 'wipe';
    return out;
  };

  const send = async (a: AndroidDeviceAction, params: Record<string, unknown>) => {
    setBusy(a.type);
    try {
      const r = await androidApi.enqueue(deviceId, { type: a.type, params }, newIdempotencyKey());
      if (r && 'approvalId' in r && r.approvalId) toast(t('mdm.outcome.awaitingApproval') || 'Waiting for a second approver: nothing has changed yet.', { duration: 7000 });
      else toast.success(t('android.commands.queued') || 'Command queued: Google delivers it to the device.');
      queued.current?.();
    } catch (err) { errorToast(err); } finally { setBusy(null); }
  };

  const run = (a: AndroidDeviceAction) => {
    setValues({}); setFlags([]); setFactoryReset(false);
    if (PARAMS[a.type] || (a.type === 'REMOVE_MANAGEMENT' && ownership === 'corporate_personal')) { setParamsFor(a); return; }
    if (a.guarded) setGuard({ actionKey: a.actionKey, params: paramsOf(a) });
    else void send(a, {});
  };
  const next = () => {
    const a = paramsFor;
    if (!a) return;
    setParamsFor(null);
    const params = paramsOf(a);
    // The typed values (a new password among them) do not stay in the state of the menu once the request is built.
    setValues({});
    if (a.guarded) setGuard({ actionKey: a.actionKey, params });
    else void send(a, params);
  };

  const spec = paramsFor ? PARAMS[paramsFor.type] : null;
  const paramsOk = !spec?.needsOne || spec.needsOne.some((f) => (values[f] ?? '').trim().length > 0);

  const dialogs = (
    <>
      <Modal open={paramsFor !== null} onClose={() => { setParamsFor(null); setValues({}); }} size="sm" title={paramsFor ? androidActionLabel(paramsFor.type) : ''}
        footer={(
          <>
            <Button variant="secondary" onClick={() => { setParamsFor(null); setValues({}); }}>{t('common.cancel') || 'Cancel'}</Button>
            <Button disabled={!paramsOk} onClick={next}>{t('common.next') || 'Next'}</Button>
          </>
        )}>
        <div className="space-y-3">
          {spec?.fields.map((f) => (
            <Labeled key={f} label={t(`android.commands.param.${f}`) || f}
              hint={f === 'newPassword' ? (t('android.commands.passwordHint') || 'Sealed in the vault at once, never shown again. Empty: the password is removed.') : f === 'packageNames' ? (t('android.commands.packagesHint') || 'Packages separated by spaces or commas.') : undefined}>
              {f === 'packageNames' || f === 'streetAddress'
                ? <textarea rows={2} value={values[f] ?? ''} onChange={(e) => setValues((v) => ({ ...v, [f]: e.target.value }))} className={fieldClass} spellCheck={false} />
                : <input type={f === 'newPassword' ? 'password' : f === 'email' ? 'email' : 'text'} autoComplete="off" value={values[f] ?? ''}
                  onChange={(e) => setValues((v) => ({ ...v, [f]: e.target.value }))} maxLength={f === 'phoneNumber' ? 30 : f === 'newPassword' ? 64 : 200} className={fieldClass} />}
            </Labeled>
          ))}
          {spec?.flags?.values.map((flag) => (
            <label key={flag} className="flex items-center gap-2 text-sm text-text-secondary">
              <input type="checkbox" checked={flags.includes(flag)} className="accent-accent"
                onChange={(e) => setFlags((prev) => (e.target.checked ? [...prev, flag] : prev.filter((x) => x !== flag)))} />
              {trCode(`android.commands.flags.${flag}`, flag)}
            </label>
          ))}
          {paramsFor?.type === 'REMOVE_MANAGEMENT' && ownership === 'corporate_personal' && (
            <label className="flex items-center gap-2 text-sm text-text-secondary">
              <input type="checkbox" checked={factoryReset} onChange={(e) => setFactoryReset(e.target.checked)} className="accent-accent" />
              {t('android.commands.factoryReset') || 'Factory reset the device (otherwise only the work profile is removed and the device is handed to its user)'}
            </label>
          )}
          {spec?.needsOne && paramsFor?.type === 'START_LOST_MODE' && (
            <p className="text-[11px] text-text-muted">{t('android.commands.lostModeContact') || 'A message, a phone number, an e-mail or an address is required: it is shown on the locked device.'}</p>
          )}
        </div>
      </Modal>

      <GuardedActionDialog open={guard !== null} onClose={() => setGuard(null)} actionKey={guard?.actionKey ?? 'mdm.device_lock'}
        selection={{ deviceIds: [deviceId] }} params={guard?.params}
        previewParams={guard?.params && 'newPassword' in guard.params ? Object.fromEntries(Object.entries(guard.params).filter(([k]) => k !== 'newPassword')) : undefined}
        onDone={() => { queued.current?.(); }} />
    </>
  );

  return { run, busy, dialogs };
}
