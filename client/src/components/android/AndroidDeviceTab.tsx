import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Play, RefreshCw } from 'lucide-react';
import type { AndroidDeviceAction, AndroidDeviceView, AndroidKioskState } from '@obligarth/shared';
import { androidApi } from '@/api/android.api';
import { newIdempotencyKey } from '@/api/apple.api';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { GuardedActionDialog } from '@/components/guard/GuardedActionDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { trCode } from '@/utils/apiError';
import { Fact, Labeled, dateOf, errorToast, fieldClass } from './ui';

// The Android side of a device record (android-amapi §8, §11, §12.1; lot AN-C2): mode, ownership, API level, security
// patch, posture, its own policy (name, versions pushed and applied, state), the non-compliances, the approval and the
// kiosk; and the menu of the Android commands (GET /api/android/devices/:id/actions): the commands that are not
// guarded go to the queue (restriction of the tenant), the others through the guard engine (reason, confirmation,
// second factor or approver).

type Tone = 'green' | 'gray' | 'blue' | 'amber' | 'red';
const POLICY_TONE: Record<AndroidDeviceView['policy']['state'], Tone> = { applied: 'green', delivering: 'blue', pending: 'blue', error: 'red' };
const APPROVAL_TONE: Record<AndroidDeviceView['approvalState'], Tone> = { none: 'gray', pending: 'amber', approved: 'green', rejected: 'red' };

export function AndroidDeviceTab({ deviceId, canAct }: { deviceId: number; canAct: boolean }) {
  const { t } = useTranslation();
  const [d, setD] = useState<AndroidDeviceView | null>(null);
  const [kiosk, setKiosk] = useState<AndroidKioskState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    androidApi.device(deviceId).then((v) => { setD(v); setError(null); }).catch((err) => { setError(trCode(`errors.${(err as { response?: { data?: { code?: string } } })?.response?.data?.code ?? ''}`, t('android.device.unavailable') || 'The Android data of this device cannot be read.')); });
    androidApi.kiosk(deviceId).then(setKiosk).catch(() => setKiosk(null));
  }, [deviceId, t]);
  useEffect(() => { load(); }, [load]);

  if (error) return <p className="text-sm text-text-muted">{error}</p>;
  if (!d) return <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>;
  return (
    <div className="space-y-5">
      <section className="rounded-lg bg-bg-secondary p-4 space-y-3">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-text-primary">{t('android.device.title') || 'Android Enterprise'}</h3>
          <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'} className="ml-auto p-1.5 rounded text-text-muted hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
        <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-3">
          <Fact label={t('android.device.mode') || 'Mode'}>{d.mode ? trCode(`android.modes.${d.mode}`, d.mode) : '—'}</Fact>
          <Fact label={t('android.device.ownership') || 'Ownership at Google'}>{trCode(`android.device.amapiOwnership.${d.ownership}`, d.ownership)}</Fact>
          <Fact label={t('android.device.apiLevel') || 'API level'}>{d.apiLevel ?? '—'}{d.software?.androidVersion ? ` (${t('android.device.androidVersion', { version: d.software.androidVersion }) || d.software.androidVersion})` : ''}</Fact>
          <Fact label={t('android.device.patch') || 'Security patch'}>{d.securityPatchLevel ?? '—'}</Fact>
          <Fact label={t('android.device.state') || 'State at Google'}>{d.state ? trCode(`android.device.states.${d.state}`, d.state) : '—'}</Fact>
          <Fact label={t('android.device.approval') || 'Approval'}><StateBadge tone={APPROVAL_TONE[d.approvalState]} label={trCode(`android.device.approvalStates.${d.approvalState}`, d.approvalState)} /></Fact>
          <Fact label={t('android.device.lastReport') || 'Last status report'}>{dateOf(d.lastStatusReportAt)}</Fact>
          <Fact label={t('android.device.enrolledAt') || 'Enrolled'}>{dateOf(d.enrolledAt)}</Fact>
          <Fact label={t('android.device.posture') || 'Security posture'}>
            {d.posture?.devicePosture ? trCode(`android.enums.devicePosture.${d.posture.devicePosture}`, d.posture.devicePosture) : '—'}
            {d.posture && d.posture.risks.length > 0 && <span className="block text-xs text-amber-400">{d.posture.risks.map((r) => trCode(`android.enums.securityRisk.${r}`, r)).join(', ')}</span>}
          </Fact>
          {d.releasedAt && (
            <Fact label={t('android.device.released') || 'Left the management'}>{dateOf(d.releasedAt)}{d.releaseReason ? ` · ${trCode(`android.device.releaseReasons.${d.releaseReason}`, d.releaseReason)}` : ''}</Fact>
          )}
        </dl>
      </section>

      <section className="rounded-lg bg-bg-secondary p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-sm font-semibold text-text-primary">{t('android.device.policy') || 'Policy of the device'}</h3>
          <StateBadge tone={POLICY_TONE[d.policy.state]} label={trCode(`android.device.policyStates.${d.policy.state}`, d.policy.state)} />
          {d.policy.compliant === false && <StateBadge tone="red" label={t('android.device.nonCompliant') || 'non-compliant'} />}
          {d.policy.compliant === true && <StateBadge tone="green" label={t('android.device.compliant') || 'compliant'} />}
        </div>
        <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-3">
          <Fact label={t('android.device.policyName') || 'Name at Google'}><span className="font-mono text-xs">{d.policy.name ?? '—'}</span></Fact>
          <Fact label={t('android.device.pushedVersion') || 'Version pushed'}>{d.policy.pushedVersion ?? '—'}</Fact>
          <Fact label={t('android.device.appliedVersion') || 'Version applied'}>{d.policy.appliedVersion ?? '—'}</Fact>
          <Fact label={t('android.device.pushedAt') || 'Pushed'}>{dateOf(d.policy.pushedAt)}</Fact>
          <Fact label={t('android.device.lastSync') || 'Last policy sync'}>{dateOf(d.policy.lastSyncAt)}</Fact>
        </dl>
        {d.policy.reasons.length > 0 && (
          <ul className="text-xs text-red-400">{d.policy.reasons.map((r) => <li key={r}>{trCode(`android.device.policyReasons.${r}`, r)}</li>)}</ul>
        )}
        {d.nonCompliance.length > 0 && (
          <div>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-text-muted">{t('android.device.nonCompliance') || 'Non-compliances reported by the device'}</h4>
            <ul className="space-y-0.5 text-sm">
              {d.nonCompliance.map((n, i) => (
                <li key={i} className="flex flex-wrap gap-2">
                  <span className="font-mono text-xs text-text-primary">{n.packageName ?? n.settingName ?? '—'}</span>
                  {n.nonComplianceReason && <span className="text-xs text-amber-400">{trCode(`android.enums.nonComplianceReason.${n.nonComplianceReason}`, n.nonComplianceReason)}</span>}
                  {n.specificNonComplianceReason && <span className="text-xs text-text-muted">{trCode(`android.enums.specificNonComplianceReason.${n.specificNonComplianceReason}`, n.specificNonComplianceReason)}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      {kiosk?.dedicated && <KioskPanel deviceId={deviceId} state={kiosk} canAct={canAct} onChanged={load} />}
    </div>
  );
}

function KioskPanel({ deviceId, state, canAct, onChanged }: { deviceId: number; state: AndroidKioskState; canAct: boolean; onChanged: () => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const exit = state.exit;
  const end = async () => {
    setBusy(true);
    try { await androidApi.endKioskExit(deviceId); toast.success(t('android.kiosk.ended') || 'Kiosk lock requested again'); onChanged(); } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  return (
    <section className="rounded-lg bg-bg-secondary p-4 space-y-2 text-sm">
      <h3 className="text-sm font-semibold text-text-primary">{t('android.kiosk.title') || 'Kiosk'}</h3>
      {exit && !exit.endedAt ? (
        <div className="flex flex-wrap items-center gap-2">
          <StateBadge tone="amber" label={t('android.kiosk.exitRunning') || 'temporary exit running'} />
          <span className="text-xs text-text-muted">{t('android.kiosk.until', { at: dateOf(exit.expiresAt) }) || `until ${dateOf(exit.expiresAt)}`}</span>
          {/* Ending the exit takes write access and mdm:lock on the device (server): offered to whoever may act only. */}
          {canAct && <Button size="sm" variant="secondary" disabled={busy} onClick={() => void end()}>{t('android.kiosk.endNow') || 'End now'}</Button>}
        </div>
      ) : <p className="text-text-secondary">{t('android.kiosk.locked') || 'The device is held in its kiosk.'}</p>}
      {state.lockPending && <p className="text-xs text-amber-400">{t('android.kiosk.lockPending') || 'The policy that locks the kiosk again is not applied yet.'}</p>}
      {state.wipeSettingsWithheld && <p className="text-xs text-amber-400">{t('android.kiosk.wipeWithheld') || 'The wipe settings of the policy are withheld until the tenant is unfrozen.'}</p>}
    </section>
  );
}

// ── Menu of the Android commands ────────────────────────────────────────────────

type ParamField = 'message' | 'phoneNumber' | 'email' | 'streetAddress' | 'organization' | 'wipeReason' | 'newPassword' | 'packageNames';
const PARAMS: Record<string, { fields: ParamField[]; flags?: { key: 'flags' | 'wipeDataFlags'; values: string[] }; needsOne?: ParamField[] }> = {
  START_LOST_MODE: { fields: ['message', 'phoneNumber', 'email', 'streetAddress', 'organization'], needsOne: ['message', 'phoneNumber', 'email', 'streetAddress'] },
  WIPE: { fields: ['wipeReason'], flags: { key: 'wipeDataFlags', values: ['PRESERVE_RESET_PROTECTION_DATA', 'WIPE_EXTERNAL_STORAGE', 'WIPE_ESIMS'] } },
  RESET_PASSWORD: { fields: ['newPassword'], flags: { key: 'flags', values: ['REQUIRE_ENTRY', 'DO_NOT_ASK_CREDENTIALS_ON_BOOT', 'LOCK_NOW'] } },
  CLEAR_APP_DATA: { fields: ['packageNames'], needsOne: ['packageNames'] },
  DISABLE: { fields: ['message'] },
};
const GROUPS: Array<{ key: string; types: string[] }> = [
  { key: 'power', types: ['REBOOT', 'CLEAR_APP_DATA'] },
  { key: 'security', types: ['LOCK', 'RESET_PASSWORD', 'START_LOST_MODE', 'STOP_LOST_MODE', 'DISABLE', 'ENABLE'] },
  { key: 'destructive', types: ['WIPE', 'RELINQUISH_OWNERSHIP', 'REMOVE_MANAGEMENT'] },
];
const GROUP_FALLBACK: Record<string, string> = { power: 'Device', security: 'Security', destructive: 'Destructive actions' };
const actionLabel = (type: string): string => trCode(`android.commands.types.${type}`, type);

export function AndroidDeviceActions({ deviceId, ownership, canAct, onQueued }: { deviceId: number; ownership: string; canAct: boolean; onQueued?: () => void }) {
  const { t } = useTranslation();
  const [actions, setActions] = useState<AndroidDeviceAction[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [paramsFor, setParamsFor] = useState<AndroidDeviceAction | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [flags, setFlags] = useState<string[]>([]);
  const [factoryReset, setFactoryReset] = useState(false);
  const [guard, setGuard] = useState<{ actionKey: string; params: Record<string, unknown> } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    androidApi.actions(deviceId).then((a) => { setActions(a); setError(null); }).catch((err) => { setActions([]); setError(trCode(`errors.${(err as { response?: { data?: { code?: string } } })?.response?.data?.code ?? ''}`, t('common.error') || 'Error')); });
  }, [deviceId, t]);
  useEffect(() => { load(); }, [load]);

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
      onQueued?.();
      load();
    } catch (err) { errorToast(err); } finally { setBusy(null); }
  };

  const start = (a: AndroidDeviceAction) => {
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
  const byType = new Map((actions ?? []).map((a) => [a.type, a]));
  return (
    <div className="space-y-5">
      {error && <p className="text-sm text-red-400">{error}</p>}
      {actions === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p> : GROUPS.map((g) => {
        const list = g.types.map((x) => byType.get(x)).filter((a): a is AndroidDeviceAction => !!a);
        if (!list.length) return null;
        return (
          <section key={g.key}>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">{t(`android.commands.group.${g.key}`) || GROUP_FALLBACK[g.key]}</h3>
            <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
              {list.map((a) => (
                <li key={a.type} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                  <span className="min-w-0 flex-1">
                    <span className={a.available ? 'text-text-primary' : 'text-text-muted'}>{actionLabel(a.type)}</span>
                    {a.guarded && <span className="ml-2 text-[10px] uppercase text-red-400">{t('apple.actions.guarded') || 'guarded'}</span>}
                    {!a.available && a.unavailable && (
                      <span className="block text-[11px] text-text-muted">{trCode(`android.commands.unavailable.${a.unavailable}`, a.unavailable)}</span>
                    )}
                  </span>
                  <Button size="sm" variant={g.key === 'destructive' ? 'danger' : 'secondary'} disabled={!canAct || !a.available || busy === a.type} onClick={() => start(a)}>
                    <Play className="w-3.5 h-3.5 mr-1" />{t('apple.actions.run') || 'Request'}
                  </Button>
                </li>
              ))}
            </ul>
          </section>
        );
      })}
      {!canAct && <p className="text-xs text-text-muted">{t('apple.actions.readOnly') || 'You can read this device but not act on it.'}</p>}

      <Modal open={paramsFor !== null} onClose={() => { setParamsFor(null); setValues({}); }} size="sm" title={paramsFor ? actionLabel(paramsFor.type) : ''}
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
        previewParams={guard?.params && 'newPassword' in guard.params ? Object.fromEntries(Object.entries(guard.params).filter(([k]) => k !== 'newPassword')) : undefined} onDone={() => { onQueued?.(); load(); }} />
    </div>
  );
}
