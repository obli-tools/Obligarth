import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Ban, BellRing, Play, RefreshCw, ShieldAlert } from 'lucide-react';
import type { MdmDeviceAction, MdmTargetState, MdmTargetView } from '@obligarth/shared';
import { MDM_OPEN_TARGET_STATES, SocketEvents } from '@obligarth/shared';
import { appleApi } from '@/api/apple.api';
import { isStepUpHandled } from '@/api/client';
import { registerSocketListener } from '@/socket/socketListeners';
import { Button } from '@/components/common/Button';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { appleCommandLabel, appleLaunchable, useAppleActionRunner } from '@/components/mdm/actions/useAppleActionRunner';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorBody, apiErrorCode, apiErrorMessage, apiErrorStatus, trCode } from '@/utils/apiError';

// The command queue and the menu of actions of a device (integration-apple-edge §8.12): the queue shows what was
// asked of the device and where each command stands; the menu lists what may be asked now, with what makes an
// action unavailable. The destructive actions (erase, lock, lost mode, removal from management) go through the
// guard engine: reason, typed confirmation, second factor or second approver, cancellable delay.

const STATE_TONE: Record<MdmTargetState, 'green' | 'gray' | 'blue' | 'amber' | 'red'> = {
  pending: 'blue', queued: 'blue', sent: 'blue', notnow: 'amber', expired: 'gray', cancelled: 'gray', rejected: 'red',
  acknowledged: 'green', error: 'red',
};
/** The label of a command type: Apple's, or the Android one for a command of the platform android (field platform, lot AN-D). */
const commandTypeLabel = (type: string, platform?: string): string => (platform === 'android'
  ? trCode(`android.commands.types.${type}`, type) : appleCommandLabel(type));
const stateLabel = (s: string): string => trCode(`apple.commands.state.${s}`, s);

/** The page of the guarded action a command belongs to (its withdrawal is asked there). */
const guardActionLink = (uuid: string): string => `/admin/security?tab=guard&action=${encodeURIComponent(uuid)}`;

// ── Queue ───────────────────────────────────────────────────────────────────

export function DeviceCommandsTab({ deviceId, canAct }: { deviceId: number; canAct: boolean }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [filter, setFilter] = useState<'all' | 'open' | 'final'>('all');
  const [rows, setRows] = useState<MdmTargetView[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback((more = false, from: string | null = null) => {
    appleApi.deviceQueue(deviceId, { state: filter, cursor: more ? from : null })
      .then((r) => {
        setRows((prev) => (more && prev ? [...prev, ...r.items] : r.items));
        setCursor(r.nextCursor);
        setError(null);
      })
      .catch((err) => { setRows((prev) => prev ?? []); setError(apiErrorMessage(err)); });
  }, [deviceId, filter]);
  useEffect(() => { setRows(null); load(); }, [load]);
  // Live: a command of this device changed state.
  useEffect(() => registerSocketListener(SocketEvents.MDM_COMMAND_CHANGED, (p: { deviceIds?: number[] }) => {
    if (!Array.isArray(p?.deviceIds) || p.deviceIds.map(Number).includes(deviceId)) load();
  }), [deviceId, load]);

  const cancel = async (row: MdmTargetView) => {
    setBusy(row.commandId);
    try {
      const o = await appleApi.cancel(row.commandId, [deviceId]);
      if (o.cancelled > 0) toast.success(t('apple.commands.cancelled') || 'Command cancelled');
      else if (o.requested > 0) toast(t('apple.commands.cancelRequested') || 'Cancellation requested: the device may already have received the command.');
      else toast.error(t('apple.commands.notCancellable') || 'This command can no longer be cancelled.');
      load();
    } catch (err) {
      // A command of a guarded action is withdrawn through its action, in the Guards tab (it shows closed actions).
      const uuid = (apiErrorBody(err)?.details as { actionUuid?: unknown } | undefined)?.actionUuid;
      if (apiErrorStatus(err) === 409 && apiErrorCode(err) === 'guardedActionRequired' && typeof uuid === 'string') {
        toast(t('apple.commands.cancelThroughGuard') || 'This command belongs to a guarded action: withdraw it from the action.', { duration: 7000 });
        navigate(guardActionLink(uuid));
      } else if (!isStepUpHandled(err)) {
        toast.error(apiErrorMessage(err), { duration: 7000 });
      }
    } finally {
      setBusy(null);
    }
  };
  const relaunch = async (row: MdmTargetView) => {
    setBusy(row.commandId);
    try {
      // An Android command in error is retried as a new command of its type (lot AN-D): no push to send.
      if (row.platform === 'android') {
        await appleApi.relaunch(row.commandId, [deviceId]);
        toast.success(t('android.commands.retried') || 'A new command was queued');
        load();
        return;
      }
      const o = await appleApi.relaunch(row.commandId, [deviceId]);
      if (o.pushed > 0) toast.success(t('apple.commands.pushed') || 'Push sent');
      else toast(trCode(`apple.commands.pushSkipped.${o.skipped[0]?.code}`, t('apple.commands.pushSkippedGeneric') || 'No push was sent for this device.'));
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        {(['all', 'open', 'final'] as const).map((f) => (
          <button key={f} type="button" onClick={() => setFilter(f)}
            className={`px-2.5 py-1 text-xs font-medium rounded-full coarse:py-2 ${filter === f ? 'bg-accent/15 text-accent' : 'text-text-muted hover:bg-bg-tertiary hover:text-text-primary'}`}>
            {f === 'all' ? (t('common.all') || 'All') : f === 'open' ? (t('apple.commands.filterOpen') || 'Waiting') : (t('apple.commands.filterFinal') || 'Ended')}
          </button>
        ))}
        <button type="button" onClick={() => load()} aria-label={t('common.refresh') || 'Refresh'}
          className="ml-auto p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {rows === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? <p className="text-sm text-text-muted">{t('apple.commands.empty') || 'No command'}</p> : (
          <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
            {rows.map((r) => {
              const open = MDM_OPEN_TARGET_STATES.includes(r.state);
              return (
                <li key={r.commandId} className="px-3 py-2.5 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-text-primary">{commandTypeLabel(r.requestType, r.platform)}</span>
                    {r.platform === 'android' && <StateBadge tone="violet" label={t('android.commands.platform') || 'Android'} />}
                    <StateBadge tone={STATE_TONE[r.state] ?? 'gray'} label={stateLabel(r.state)} pulse={open} />
                    <span className="text-[11px] text-text-muted">{trCode(`apple.commands.origin.${r.origin}`, r.origin)}</span>
                    {r.origin === 'guard' && <ShieldAlert className="w-3.5 h-3.5 text-red-400" aria-hidden />}
                    <span className="ml-auto text-[11px] text-text-muted" title={r.commandId}>{formatDateTime(r.createdAt)}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] text-text-muted">
                    {r.requestedBy && <span>{t('apple.commands.requestedBy') || 'Requested by'}: {r.requestedBy.name}</span>}
                    {r.reason && <span className="break-words">{t('apple.commands.reason') || 'Reason'}: {r.reason}</span>}
                    {open && <span>{t('apple.commands.expiresAt') || 'Expires'}: {formatDateTime(r.expiresAt)}</span>}
                    {r.deliveredAt && <span>{t('apple.commands.deliveredAt') || 'Delivered'}: {formatDateTime(r.deliveredAt)}</span>}
                    {r.completedAt && <span>{t('apple.commands.completedAt') || 'Ended'}: {formatDateTime(r.completedAt)}</span>}
                    {r.pushCount > 0 && (
                      <span>{t('apple.commands.pushes') || 'Pushes'}: {r.pushCount}{r.pushOutcome ? ` (${trCode(`apple.commands.push.${r.pushOutcome}`, r.pushOutcome)})` : ''}</span>
                    )}
                    {r.holdReason && <span className="text-amber-400">{t('apple.commands.held', { reason: trCode(`apple.commands.holdReason.${r.holdReason}`, r.holdReason) }) || `Waiting: ${r.holdReason}`}</span>}
                    {r.rejectCode && <span className="text-red-400">{trCode(`apple.commands.rejectCode.${r.rejectCode}`, r.rejectCode)}</span>}
                  </div>
                  {r.errorChain && r.errorChain.length > 0 && (
                    <ul className="mt-1 text-[11px] text-red-400">
                      {r.errorChain.slice(0, 3).map((e, i) => <li key={i} className="break-words">{e.domain} {e.code}{e.description ? `: ${e.description}` : ''}</li>)}
                    </ul>
                  )}
                  {canAct && open && (
                    <div className="mt-2 flex gap-2">
                      {r.platform !== 'android' && (r.state === 'queued' || r.state === 'sent' || r.state === 'notnow') && (
                        <Button size="sm" variant="secondary" disabled={busy === r.commandId} onClick={() => relaunch(r)}>
                          <BellRing className="w-3.5 h-3.5 mr-1" />{t('apple.commands.relaunch') || 'Push again'}
                        </Button>
                      )}
                      <Button size="sm" variant="secondary" disabled={busy === r.commandId} onClick={() => cancel(r)}>
                        <Ban className="w-3.5 h-3.5 mr-1" />{r.origin === 'guard' ? (t('apple.commands.withdraw') || 'Withdraw…') : (t('apple.commands.cancel') || 'Cancel')}
                      </Button>
                    </div>
                  )}
                  {canAct && r.platform === 'android' && r.state === 'error' && r.origin !== 'guard' && (
                    <div className="mt-2 flex gap-2">
                      <Button size="sm" variant="secondary" disabled={busy === r.commandId} onClick={() => relaunch(r)}>
                        <RefreshCw className="w-3.5 h-3.5 mr-1" />{t('android.commands.retry') || 'Retry'}
                      </Button>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      {cursor && (
        <Button size="sm" variant="secondary" onClick={() => load(true, cursor)}>{t('devices.pagination.loadMore') || 'Load more'}</Button>
      )}
    </div>
  );
}

// ── Actions ─────────────────────────────────────────────────────────────────

const GROUPS: Array<{ key: string; types: string[] }> = [
  { key: 'inventory', types: ['DeviceInformation', 'SecurityInfo', 'InstalledApplicationList', 'ManagedApplicationList', 'ProfileList', 'CertificateList', 'ActivationLockBypassCode'] },
  { key: 'power', types: ['RestartDevice', 'ShutDownDevice'] },
  { key: 'security', types: ['DeviceLock', 'ClearPasscode', 'EnableLostMode', 'DisableLostMode', 'DeviceLocation', 'PlayLostModeSound'] },
  { key: 'destructive', types: ['EraseDevice'] },
];
const GROUP_FALLBACK: Record<string, string> = { inventory: 'Inventory', power: 'Power', security: 'Security', destructive: 'Destructive actions' };

export function DeviceActionsTab({ deviceId, managed, canAct, onQueued }: {
  deviceId: number;
  /** The device is under management (the removal from management is offered). */
  managed: boolean;
  canAct: boolean;
  onQueued?: () => void;
}) {
  const { t } = useTranslation();
  const [actions, setActions] = useState<MdmDeviceAction[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    appleApi.actions(deviceId).then((a) => { setActions(a); setError(null); }).catch((err) => { setActions([]); setError(apiErrorMessage(err)); });
  }, [deviceId]);
  useEffect(() => { load(); }, [load]);
  // The parameters, the reason and the guard dialogs of an action (shared with the quick actions of the record).
  const runner = useAppleActionRunner({ deviceId, onQueued: () => { onQueued?.(); load(); } });

  // AE-C0-R2bis (decision of 19/10/2026): a re-enrollment without proof of this device is refused by the device service
  // unless allowed here (24 hours, one enrollment).
  const reenroll = async (allow: boolean) => {
    setBusy(allow ? 'reenroll' : 'reenroll-withdraw');
    try {
      if (allow) {
        const r = await appleApi.allowReenroll(deviceId);
        toast.success((t('apple.actions.reenrollAllowed', { at: formatDateTime(r.expiresAt) }) as string)
          || `Re-enrollment allowed until ${formatDateTime(r.expiresAt)}.`, { duration: 7000 });
      } else {
        const r = await appleApi.withdrawReenroll(deviceId);
        toast.success(r.withdrawn ? (t('apple.actions.reenrollWithdrawn') || 'Re-enrollment allowance withdrawn.')
          : (t('apple.actions.reenrollNone') || 'No re-enrollment allowance was pending.'));
      }
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(null);
    }
  };

  const byType = new Map((actions ?? []).map((a) => [a.requestType, a]));

  return (
    <div className="space-y-5">
      {error && <p className="text-sm text-red-400">{error}</p>}
      {actions === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p> : (
        <>
          {GROUPS.map((g) => {
            const list = g.types.map((x) => byType.get(x)).filter((a): a is MdmDeviceAction => !!a && appleLaunchable(a));
            if (list.length === 0) return null;
            return (
              <section key={g.key}>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">{t(`apple.actions.group.${g.key}`) || GROUP_FALLBACK[g.key]}</h3>
                <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
                  {list.map((a) => (
                    <li key={a.requestType} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                      <span className="min-w-0 flex-1">
                        <span className={a.available ? 'text-text-primary' : 'text-text-muted'}>{commandTypeLabel(a.requestType)}</span>
                        {a.guarded && <span className="ml-2 text-[10px] uppercase text-red-400">{t('apple.actions.guarded') || 'guarded'}</span>}
                        {!a.available && a.unavailable && (
                          <span className="block text-[11px] text-text-muted">{trCode(`apple.commands.unavailable.${a.unavailable}`, a.unavailable)}</span>
                        )}
                      </span>
                      <Button size="sm" variant={g.key === 'destructive' ? 'danger' : 'secondary'} disabled={!canAct || !a.available || runner.busy === a.requestType} onClick={() => runner.run(a)}>
                        <Play className="w-3.5 h-3.5 mr-1" />{t('apple.actions.run') || 'Request'}
                      </Button>
                    </li>
                  ))}
                </ul>
              </section>
            );
          })}
          {managed && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">{t('apple.actions.group.management') || 'Management'}</h3>
              <div className="flex flex-wrap items-center gap-2 rounded-lg bg-bg-secondary px-3 py-2 text-sm">
                <span className="min-w-0 flex-1">
                  <span className="text-text-primary">{t('guard.actions.mdm.remove_management') || 'Remove management'}</span>
                  <span className="ml-2 text-[10px] uppercase text-red-400">{t('apple.actions.guarded') || 'guarded'}</span>
                  <span className="block text-[11px] text-text-muted">{t('apple.actions.removeManagementHint') || 'Removes the enrollment profile: the device leaves management and loses everything management installed.'}</span>
                </span>
                <Button size="sm" variant="danger" disabled={!canAct} onClick={() => runner.guard('RemoveManagement', 'mdm.remove_management')}>
                  <Play className="w-3.5 h-3.5 mr-1" />{t('apple.actions.run') || 'Request'}
                </Button>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-2 rounded-lg bg-bg-secondary px-3 py-2 text-sm">
                <span className="min-w-0 flex-1">
                  <span className="text-text-primary">{t('apple.actions.reenroll') || 'Allow the re-enrollment without proof'}</span>
                  <span className="block text-[11px] text-text-muted">{t('apple.actions.reenrollHint') || 'Only if you checked that it is this same device (erased or restored without leaving management): its next enrollment, within 24 hours, replaces the current one. Any other is refused.'}</span>
                </span>
                <Button size="sm" variant="secondary" disabled={!canAct || busy === 'reenroll'} onClick={() => void reenroll(true)}>
                  {t('apple.actions.reenrollAllow') || 'Allow for 24 h'}
                </Button>
                <Button size="sm" variant="secondary" disabled={!canAct || busy === 'reenroll-withdraw'} onClick={() => void reenroll(false)}>
                  {t('apple.actions.reenrollWithdraw') || 'Withdraw'}
                </Button>
              </div>
            </section>
          )}
          {!canAct && <p className="text-xs text-text-muted">{t('apple.actions.readOnly') || 'You can read this device but not act on it.'}</p>}
        </>
      )}

      {runner.dialogs}
    </div>
  );
}
