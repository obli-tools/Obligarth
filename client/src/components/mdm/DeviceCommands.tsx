import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Ban, BellRing, Play, RefreshCw, ShieldAlert } from 'lucide-react';
import type { MdmDeviceAction, MdmTargetState, MdmTargetView } from '@obligarth/shared';
import { MDM_OPEN_TARGET_STATES, SocketEvents } from '@obligarth/shared';
import { appleApi, isAwaitingApproval, newIdempotencyKey } from '@/api/apple.api';
import { isStepUpHandled } from '@/api/client';
import { registerSocketListener } from '@/socket/socketListeners';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { GuardedActionDialog } from '@/components/guard/GuardedActionDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
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
const commandTypeLabel = (type: string): string => trCode(`apple.commands.types.${type}`, type);
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
                    <span className="font-medium text-text-primary">{commandTypeLabel(r.requestType)}</span>
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
                      {(r.state === 'queued' || r.state === 'sent' || r.state === 'notnow') && (
                        <Button size="sm" variant="secondary" disabled={busy === r.commandId} onClick={() => relaunch(r)}>
                          <BellRing className="w-3.5 h-3.5 mr-1" />{t('apple.commands.relaunch') || 'Push again'}
                        </Button>
                      )}
                      <Button size="sm" variant="secondary" disabled={busy === r.commandId} onClick={() => cancel(r)}>
                        <Ban className="w-3.5 h-3.5 mr-1" />{r.origin === 'guard' ? (t('apple.commands.withdraw') || 'Withdraw…') : (t('apple.commands.cancel') || 'Cancel')}
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

/** The actions the console can launch without a form of its own: no parameter. */
const SIMPLE = new Set(['DeviceInformation', 'SecurityInfo', 'InstalledApplicationList', 'ManagedApplicationList', 'ProfileList',
  'CertificateList', 'ActivationLockBypassCode', 'RestartDevice', 'ShutDownDevice', 'ClearPasscode', 'DisableLostMode', 'DeviceLocation',
  'PlayLostModeSound']);
/** The guarded actions and their parameters (apple/commands/guarded.ts). */
const GUARDED: Record<string, { actionKey: string; fields: Array<'message' | 'phoneNumber' | 'footnote'>; needsOne?: boolean; toggles?: Array<'preserveDataPlan' | 'disallowProximitySetup'> }> = {
  DeviceLock: { actionKey: 'mdm.device_lock', fields: ['message', 'phoneNumber'] },
  EnableLostMode: { actionKey: 'mdm.lost_mode_enable', fields: ['message', 'phoneNumber', 'footnote'], needsOne: true },
  EraseDevice: { actionKey: 'mdm.erase_device', fields: [], toggles: ['preserveDataPlan', 'disallowProximitySetup'] },
};
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
  const [reasonFor, setReasonFor] = useState<MdmDeviceAction | null>(null);
  const [guardFor, setGuardFor] = useState<{ type: string; actionKey: string } | null>(null);
  const [guardParams, setGuardParams] = useState<Record<string, unknown>>({});
  const [paramsFor, setParamsFor] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    appleApi.actions(deviceId).then((a) => { setActions(a); setError(null); }).catch((err) => { setActions([]); setError(apiErrorMessage(err)); });
  }, [deviceId]);
  useEffect(() => { load(); }, [load]);

  const send = async (action: MdmDeviceAction, reason?: string) => {
    setBusy(action.requestType);
    try {
      const r = action.requestType === 'DeviceInformation'
        ? await appleApi.refreshInventory(deviceId).then(() => null)
        : await appleApi.enqueue(deviceId, { requestType: action.requestType, reason }, newIdempotencyKey());
      if (r && isAwaitingApproval(r)) toast(t('mdm.outcome.awaitingApproval') || 'Waiting for a second approver: nothing has changed yet.', { duration: 7000 });
      else toast.success(t('apple.commands.queuedOne') || 'Command queued: it reaches the device at its next contact.');
      onQueued?.();
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(null);
    }
  };
  const start = (action: MdmDeviceAction) => {
    const guarded = GUARDED[action.requestType];
    if (guarded) {
      setGuardParams(guarded.toggles ? { preserveDataPlan: true, disallowProximitySetup: false } : {});
      if (guarded.fields.length || guarded.toggles) setParamsFor(action.requestType);
      else setGuardFor({ type: action.requestType, actionKey: guarded.actionKey });
      return;
    }
    if (action.reasonRequired) { setReasonFor(action); return; }
    void send(action);
  };

  const byType = new Map((actions ?? []).map((a) => [a.requestType, a]));
  const launchable = (a: MdmDeviceAction): boolean => SIMPLE.has(a.requestType) || a.requestType in GUARDED;
  const paramsSpec = paramsFor ? GUARDED[paramsFor] : null;
  const paramsOk = !paramsSpec?.needsOne || paramsSpec.fields.some((f) => String(guardParams[f] ?? '').trim().length > 0);

  return (
    <div className="space-y-5">
      {error && <p className="text-sm text-red-400">{error}</p>}
      {actions === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p> : (
        <>
          {GROUPS.map((g) => {
            const list = g.types.map((x) => byType.get(x)).filter((a): a is MdmDeviceAction => !!a && launchable(a));
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
                      <Button size="sm" variant={g.key === 'destructive' ? 'danger' : 'secondary'} disabled={!canAct || !a.available || busy === a.requestType} onClick={() => start(a)}>
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
                <Button size="sm" variant="danger" disabled={!canAct} onClick={() => setGuardFor({ type: 'RemoveManagement', actionKey: 'mdm.remove_management' })}>
                  <Play className="w-3.5 h-3.5 mr-1" />{t('apple.actions.run') || 'Request'}
                </Button>
              </div>
            </section>
          )}
          {!canAct && <p className="text-xs text-text-muted">{t('apple.actions.readOnly') || 'You can read this device but not act on it.'}</p>}
        </>
      )}

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
        title={paramsFor ? commandTypeLabel(paramsFor) : ''}
        footer={(
          <>
            <Button variant="secondary" onClick={() => setParamsFor(null)}>{t('common.cancel') || 'Cancel'}</Button>
            <Button
              disabled={!paramsOk}
              onClick={() => {
                const spec = paramsFor ? GUARDED[paramsFor] : null;
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
        params={guardFor && guardFor.type in GUARDED ? guardParams : undefined}
        onDone={() => { onQueued?.(); load(); }}
      />
    </div>
  );
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
      title={action ? commandTypeLabel(action.requestType) : ''}
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
