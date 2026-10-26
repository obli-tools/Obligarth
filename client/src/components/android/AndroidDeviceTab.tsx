import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Play, RefreshCw } from 'lucide-react';
import type { AndroidDeviceAction, AndroidDeviceView, AndroidKioskState } from '@obligarth/shared';
import { androidApi } from '@/api/android.api';
import { Button } from '@/components/common/Button';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { androidActionLabel, useAndroidActionRunner } from '@/components/mdm/actions/useAndroidActionRunner';
import { trCode } from '@/utils/apiError';
import { Fact, dateOf, errorToast } from './ui';

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

const GROUPS: Array<{ key: string; types: string[] }> = [
  { key: 'power', types: ['REBOOT', 'CLEAR_APP_DATA'] },
  { key: 'security', types: ['LOCK', 'RESET_PASSWORD', 'START_LOST_MODE', 'STOP_LOST_MODE', 'DISABLE', 'ENABLE'] },
  { key: 'destructive', types: ['WIPE', 'RELINQUISH_OWNERSHIP', 'REMOVE_MANAGEMENT'] },
];
const GROUP_FALLBACK: Record<string, string> = { power: 'Device', security: 'Security', destructive: 'Destructive actions' };

export function AndroidDeviceActions({ deviceId, ownership, canAct, onQueued }: { deviceId: number; ownership: string; canAct: boolean; onQueued?: () => void }) {
  const { t } = useTranslation();
  const [actions, setActions] = useState<AndroidDeviceAction[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    androidApi.actions(deviceId).then((a) => { setActions(a); setError(null); }).catch((err) => { setActions([]); setError(trCode(`errors.${(err as { response?: { data?: { code?: string } } })?.response?.data?.code ?? ''}`, t('common.error') || 'Error')); });
  }, [deviceId, t]);
  useEffect(() => { load(); }, [load]);
  // The parameters and the guard dialog of a command (shared with the quick actions of the record).
  const runner = useAndroidActionRunner({ deviceId, ownership, onQueued: () => { onQueued?.(); load(); } });

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
                    <span className={a.available ? 'text-text-primary' : 'text-text-muted'}>{androidActionLabel(a.type)}</span>
                    {a.guarded && <span className="ml-2 text-[10px] uppercase text-red-400">{t('apple.actions.guarded') || 'guarded'}</span>}
                    {!a.available && a.unavailable && (
                      <span className="block text-[11px] text-text-muted">{trCode(`android.commands.unavailable.${a.unavailable}`, a.unavailable)}</span>
                    )}
                  </span>
                  <Button size="sm" variant={g.key === 'destructive' ? 'danger' : 'secondary'} disabled={!canAct || !a.available || runner.busy === a.type} onClick={() => runner.run(a)}>
                    <Play className="w-3.5 h-3.5 mr-1" />{t('apple.actions.run') || 'Request'}
                  </Button>
                </li>
              ))}
            </ul>
          </section>
        );
      })}
      {!canAct && <p className="text-xs text-text-muted">{t('apple.actions.readOnly') || 'You can read this device but not act on it.'}</p>}

      {runner.dialogs}
    </div>
  );
}
