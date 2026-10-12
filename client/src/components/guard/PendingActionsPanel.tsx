import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Clock, RefreshCw, Snowflake, UserCheck, X, Play, Gauge } from 'lucide-react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import type { GuardApproverDto, GuardQuota, GuardSettingsDto, PendingActionDto, User } from '@obligarth/shared';
import { guardApi } from '@/api/guard.api';
import { usersApi } from '@/api/users.api';
import { isStepUpHandled } from '@/api/client';
import { getSocket } from '@/socket/socketClient';
import { useAuthStore } from '@/store/authStore';
import { usePrompt, useConfirm } from '@/components/common/ConfirmDialog';
import { IconButton } from '@/components/common/IconButton';
import { FreezeBanner } from './FreezeBanner';
import { guardErrorMessage } from './GuardedActionDialog';

// The Guards tab of the Security page (audit-durci §10.11): the guarded
// actions awaiting approval, scheduled (with their countdown), paused,
// running, and the recent ones; cancellation and resumption; the emergency
// freeze; the hourly budget; the designated approvers; the settings. The
// server decides who may do what (requester, administrators, approvers):
// a refusal is shown as is.

const OPEN = new Set(['awaiting_approval', 'scheduled', 'paused', 'executing']);

function stateClass(s: string): string {
  if (s === 'scheduled' || s === 'awaiting_approval') return 'text-yellow-400 border-yellow-400/30 bg-yellow-400/10';
  if (s === 'executing') return 'text-sky-400 border-sky-400/30 bg-sky-400/10';
  if (s === 'paused') return 'text-orange-400 border-orange-400/30 bg-orange-400/10';
  if (s === 'done') return 'text-green-400 border-green-400/30 bg-green-400/10';
  if (s === 'partial') return 'text-orange-400 border-orange-400/30 bg-orange-400/10';
  if (s === 'failed' || s === 'refused') return 'text-red-400 border-red-400/30 bg-red-400/10';
  return 'text-gray-400 border-gray-400/30 bg-gray-400/10';
}

function countdown(at: string, t: TFunction): string {
  const ms = new Date(at).getTime() - Date.now();
  if (ms <= 0) return t('guard.list.due') || 'due';
  const m = Math.floor(ms / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return `${m}m ${String(s).padStart(2, '0')}s`;
}

function errorToast(t: TFunction, err: any): void {
  if (isStepUpHandled(err)) return;
  const body = err?.response?.data;
  toast.error(guardErrorMessage(t, body?.code, body?.error || (t('common.error') || 'Error'), body?.details), { duration: 8000 });
}

export function PendingActionsPanel() {
  const { t } = useTranslation();
  const prompt = usePrompt();
  const confirm = useConfirm();
  const [searchParams] = useSearchParams();
  const highlight = searchParams.get('action');
  const isPlatformAdmin = useAuthStore((s) => s.user?.role === 'admin');
  const caps = useAuthStore((s) => s.permissions?.tenantCapabilities ?? []);
  const canManageUsers = isPlatformAdmin || caps.includes('users.manage');
  const [items, setItems] = useState<PendingActionDto[]>([]);
  const [settings, setSettings] = useState<GuardSettingsDto | null>(null);
  const [quota, setQuota] = useState<GuardQuota | null>(null);
  const [approvers, setApprovers] = useState<GuardApproverDto[]>([]);
  const [members, setMembers] = useState<User[]>([]);
  // A link to one action (the alert of its execution) shows it even once executed: its late cancellation is there.
  const [showClosed, setShowClosed] = useState(!!highlight);
  const [, tick] = useState(0);

  const load = useCallback(async () => {
    try {
      const [list, s] = await Promise.all([guardApi.list(showClosed ? undefined : 'open'), guardApi.settings()]);
      setItems(list);
      setSettings(s);
    } catch (err) {
      errorToast(t, err);
    }
    guardApi.quota().then(setQuota).catch(() => setQuota(null));
    guardApi.approvers().then(setApprovers).catch(() => setApprovers([]));
  }, [showClosed, t]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!canManageUsers) return;
    usersApi.list().then(setMembers).catch(() => setMembers([]));
  }, [canManageUsers]);
  useEffect(() => {
    const h = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(h);
  }, []);
  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;
    const handler = () => load();
    socket.on('GUARD_ACTION_UPDATED', handler);
    socket.on('GUARD_STATE_CHANGED', handler);
    socket.on('APPROVAL_UPDATED', handler);
    return () => {
      socket.off('GUARD_ACTION_UPDATED', handler);
      socket.off('GUARD_STATE_CHANGED', handler);
      socket.off('APPROVAL_UPDATED', handler);
    };
  }, [load]);

  const cancel = async (a: PendingActionDto) => {
    // An action already executed: what it sent and no device received yet is withdrawn (late cancellation).
    const late = !OPEN.has(a.state);
    const reason = await prompt({
      title: late ? (t('guard.list.withdrawTitle') || 'Withdraw what this action sent?') : (t('guard.list.cancelTitle') || 'Cancel this action?'),
      message: t(`guard.actions.${a.actionKey}`, a.actionKey) + ` — ${a.targetCount}`
        + (late ? ` — ${t('guard.list.withdrawHelp') || 'Devices that already received it are not affected.'}` : ''),
      placeholder: t('guard.list.cancelReason') || 'Reason (optional)',
      confirmLabel: late ? (t('guard.list.withdraw') || 'Withdraw') : (t('guard.list.cancel') || 'Cancel the action'),
      multiline: false,
    });
    if (reason === null) return;
    try {
      const r = await guardApi.cancel(a.uuid, reason.trim() || undefined);
      if (r.cancellation) {
        const done = r.cancellation.filter((c) => c.outcome === 'cancelled').length;
        toast(t('guard.list.lateCancel', { done, total: r.cancellation.length }) || `Withdrawn on ${done} of ${r.cancellation.length} devices (the others had received it)`, { duration: 8000 });
      } else {
        toast.success(t('guard.list.cancelled') || 'Action cancelled');
      }
      await load();
    } catch (err) { errorToast(t, err); }
  };

  const resume = async (a: PendingActionDto) => {
    if (!(await confirm({ message: t('guard.list.resumeConfirm') || 'Request the resumption? A second person approves it; the full delay starts again.' }))) return;
    try {
      await guardApi.resume(a.uuid);
      toast.success(t('guard.list.resumeRequested') || 'Resumption requested: waiting for an approver');
      await load();
    } catch (err) { errorToast(t, err); }
  };

  const freeze = async () => {
    const reason = await prompt({
      title: t('guard.freeze.title') || 'Freeze the tenant now?',
      message: t('guard.freeze.effects') || 'No guarded action is possible and no MDM command is delivered until the tenant is unfrozen (second approver).',
      placeholder: t('guard.freeze.reason') || 'Reason (required)',
      confirmLabel: t('guard.freeze.freeze') || 'Freeze',
      required: true,
      multiline: false,
    });
    if (reason === null) return;
    try {
      await guardApi.freeze(reason.trim());
      toast.success(t('guard.freeze.done') || 'Tenant frozen');
      await load();
    } catch (err) { errorToast(t, err); }
  };

  const unfreeze = async () => {
    const reason = await prompt({
      title: t('guard.freeze.unfreezeTitle') || 'Request the end of the freeze?',
      placeholder: t('guard.freeze.reason') || 'Reason (required)',
      confirmLabel: t('guard.freeze.unfreeze') || 'Request unfreeze',
      required: true,
      multiline: false,
    });
    if (reason === null) return;
    try {
      await guardApi.unfreeze(reason.trim());
      toast.success(t('guard.freeze.unfreezeRequested') || 'Unfreeze requested: waiting for an approver');
    } catch (err) { errorToast(t, err); }
  };

  const designate = async (userId: number, side: 'client' | 'msp') => {
    try {
      await guardApi.designate(userId, side);
      toast.success(t('guard.approvers.requested') || 'Designation requested: waiting for an approver');
    } catch (err) { errorToast(t, err); }
  };

  const revoke = async (a: GuardApproverDto) => {
    if (!(await confirm({ message: t('guard.approvers.revokeConfirm', { name: a.username ?? `#${a.userId}` }) || `Revoke ${a.username ?? `#${a.userId}`}?`, danger: true }))) return;
    try {
      await guardApi.revoke(a.id);
      toast.success(t('guard.approvers.revoked') || 'Approver revoked');
      await load();
    } catch (err) { errorToast(t, err); }
  };

  const shown = showClosed ? items : items.filter((a) => OPEN.has(a.state));

  return (
    <div className="space-y-4">
      <FreezeBanner settings={settings} onUnfreeze={settings?.frozen ? unfreeze : undefined} />

      <div className="flex flex-wrap items-center gap-2">
        {quota && (
          <span className="inline-flex items-center gap-1.5 text-xs text-text-secondary rounded bg-bg-secondary px-2 py-1">
            <Gauge className="w-3.5 h-3.5" />
            {t('guard.quota', { remaining: quota.remaining, cap: quota.cap }) || `Hourly budget: ${quota.remaining} of ${quota.cap} devices left`}
          </span>
        )}
        <label className="flex items-center gap-2 text-xs text-text-muted cursor-pointer coarse:min-h-10 ml-auto">
          <input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} className="accent-accent" />
          {t('guard.list.showClosed') || 'Show closed'}
        </label>
        <IconButton label={t('common.refresh') || 'Refresh'} icon={<RefreshCw className="w-4 h-4" />} variant="plain" onClick={() => load()} />
        {!settings?.frozen && (
          <button
            type="button"
            onClick={freeze}
            className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded border border-sky-400/40 text-sky-300 hover:bg-sky-400/10 coarse:min-h-10"
          >
            <Snowflake className="w-3.5 h-3.5" /> {t('guard.freeze.freeze') || 'Freeze'}
          </button>
        )}
      </div>

      {shown.length === 0 ? (
        <div className="rounded-lg bg-bg-secondary p-6 text-center text-sm text-text-muted">
          {t('guard.list.empty') || 'No guarded action in progress.'}
        </div>
      ) : (
        <div className="space-y-2">
          {shown.map((a) => (
            <div key={a.uuid} className={clsx('rounded bg-bg-secondary p-3', highlight === a.uuid && 'ring-1 ring-accent')}>
              <div className="flex items-start justify-between gap-3 max-sm:flex-col max-sm:items-stretch">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className={clsx('px-2 py-0.5 rounded-full border text-[10px] font-medium', stateClass(a.state))}>
                      {t(`guard.state.${a.state}`, a.state)}
                    </span>
                    <span className="text-sm font-medium text-text-primary">{t(`guard.actions.${a.actionKey}`, a.actionKey)}</span>
                    <span className="text-xs text-text-muted">{t('guard.dialog.targets', { count: a.targetCount }) || `${a.targetCount} device(s)`}</span>
                    {a.approverFallback && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded border border-orange-400/40 text-orange-400">
                        {t('guard.list.fallback') || 'MSP approval (no client approver)'}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-text-secondary break-words">{a.reason}{a.ticket ? ` · ${a.ticket}` : ''}</p>
                  <div className="flex items-center gap-3 mt-1 text-[11px] text-text-muted flex-wrap">
                    <span>{t('approvals.by') || 'By'} <strong className="text-text-secondary">{a.requestedBy.label ?? `#${a.requestedBy.id}`}</strong> ({t(`guard.side.${a.requestedBy.side}`, a.requestedBy.side)})</span>
                    {a.approvedBy && <span>{t('approvals.approvedBy') || 'approved by'} <strong>{a.approvedBy.label ?? `#${a.approvedBy.id}`}</strong></span>}
                    {a.state === 'scheduled' && a.executeAfter && (
                      <span className="inline-flex items-center gap-1"><Clock className="w-3 h-3" />{countdown(a.executeAfter, t)}</span>
                    )}
                    {a.result && <span>{t('guard.list.result', { done: a.result.done, failed: a.result.failed, skipped: a.result.skipped }) || `done ${a.result.done}, failed ${a.result.failed}, skipped ${a.result.skipped}`}</span>}
                    {a.lateCancelledAt && <span className="text-orange-400">{t('guard.list.withdrawnAt', { at: new Date(a.lateCancelledAt).toLocaleString() }) || `withdrawn on ${new Date(a.lateCancelledAt).toLocaleString()}`}</span>}
                    <span>{new Date(a.createdAt).toLocaleString()}</span>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 shrink-0 max-sm:justify-end">
                  {a.state === 'paused' && (
                    <button type="button" onClick={() => resume(a)} className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded border border-yellow-400/30 text-yellow-400 hover:bg-yellow-400/10 coarse:min-h-10">
                      <Play className="w-3.5 h-3.5" /> {t('guard.list.resume') || 'Resume'}
                    </button>
                  )}
                  {(OPEN.has(a.state) || a.lateCancellable) && (
                    <button type="button" onClick={() => cancel(a)} className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded border border-red-400/30 text-red-400 hover:bg-red-400/10 coarse:min-h-10">
                      <X className="w-3.5 h-3.5" /> {OPEN.has(a.state) ? (t('guard.list.cancel') || 'Cancel the action') : (t('guard.list.withdraw') || 'Withdraw')}
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <section className="rounded bg-bg-secondary p-3 space-y-2">
        <h3 className="flex items-center gap-2 text-sm font-medium text-text-primary"><UserCheck className="w-4 h-4" />{t('guard.approvers.title') || 'Designated approvers'}</h3>
        <p className="text-xs text-text-muted">{t('guard.approvers.help') || 'A batch requested by the MSP is approved by a client approver; without one, by a second MSP administrator (marked as a fallback).'}</p>
        {settings?.fallbackHeldUntil && new Date(settings.fallbackHeldUntil).getTime() > Date.now() && (
          <p className="text-xs text-orange-400">
            {t('guard.approvers.fallbackHeld', {
              lostAt: settings.clientApproverLostAt ? new Date(settings.clientApproverLostAt).toLocaleString() : '',
              until: new Date(settings.fallbackHeldUntil).toLocaleString(),
            }) || `A client approver was removed recently: while no client approver is designated, requests that need one do not fall back on an MSP approver until ${new Date(settings.fallbackHeldUntil).toLocaleString()}.`}
          </p>
        )}
        {approvers.length === 0 ? (
          <p className="text-xs text-text-muted italic">{t('guard.approvers.none') || 'No approver designated.'}</p>
        ) : (
          <ul className="space-y-1">
            {approvers.map((a) => (
              <li key={a.id} className="flex items-center gap-2 text-xs">
                <span className="text-text-primary">{a.displayName || a.username || `#${a.userId}`}</span>
                <span className="text-text-muted">{t(`guard.side.${a.side}`, a.side)}</span>
                {a.cooldownUntil && <span className="text-orange-400">{t('guard.approvers.cooldown', { until: new Date(a.cooldownUntil).toLocaleString() }) || `cooldown until ${new Date(a.cooldownUntil).toLocaleString()}`}</span>}
                <button type="button" onClick={() => revoke(a)} className="ml-auto text-red-400 hover:underline">{t('guard.approvers.revoke') || 'Revoke'}</button>
              </li>
            ))}
          </ul>
        )}
        {canManageUsers && members.length > 0 && (
          <DesignateForm members={members} onDesignate={designate} />
        )}
      </section>

      {isPlatformAdmin && settings && <SettingsForm settings={settings} onSaved={load} />}
    </div>
  );
}

function DesignateForm({ members, onDesignate }: { members: User[]; onDesignate: (userId: number, side: 'client' | 'msp') => void }) {
  const { t } = useTranslation();
  const [userId, setUserId] = useState<number | ''>('');
  const [side, setSide] = useState<'client' | 'msp'>('client');
  return (
    <div className="flex flex-wrap items-center gap-2 pt-1">
      <select value={userId} onChange={(e) => setUserId(e.target.value ? Number(e.target.value) : '')} className="rounded border border-border bg-bg-tertiary px-2 py-1 text-xs">
        <option value="">{t('guard.approvers.pick') || 'Choose an account'}</option>
        {members.map((m) => <option key={m.id} value={m.id}>{m.displayName || m.username}</option>)}
      </select>
      <select value={side} onChange={(e) => setSide(e.target.value === 'msp' ? 'msp' : 'client')} className="rounded border border-border bg-bg-tertiary px-2 py-1 text-xs">
        <option value="client">{t('guard.side.client') || 'client'}</option>
        <option value="msp">{t('guard.side.msp') || 'MSP'}</option>
      </select>
      <button type="button" disabled={!userId} onClick={() => userId && onDesignate(userId, side)} className="text-xs px-2.5 py-1 rounded bg-accent text-white disabled:opacity-50 coarse:min-h-10">
        {t('guard.approvers.designate') || 'Designate'}
      </button>
    </div>
  );
}

function SettingsForm({ settings, onSaved }: { settings: GuardSettingsDto; onSaved: () => void }) {
  const { t } = useTranslation();
  const [percent, setPercent] = useState(settings.hourlyCapPercent);
  const [min, setMin] = useState(settings.hourlyCapMin);
  const [side, setSide] = useState(settings.massApproverSide);
  useEffect(() => { setPercent(settings.hourlyCapPercent); setMin(settings.hourlyCapMin); setSide(settings.massApproverSide); }, [settings]);
  const save = async () => {
    try {
      const r = await guardApi.updateSettings({ hourlyCapPercent: percent, hourlyCapMin: min, massApproverSide: side });
      toast.success('approvalId' in r ? (t('guard.settings.requested') || 'Change requested: waiting for an approver') : (t('guard.settings.unchanged') || 'Nothing changed'));
      onSaved();
    } catch (err) { errorToast(t, err); }
  };
  return (
    <section className="rounded bg-bg-secondary p-3 space-y-2">
      <h3 className="text-sm font-medium text-text-primary">{t('guard.settings.title') || 'Guard settings'}</h3>
      <div className="flex flex-wrap items-end gap-3 text-xs">
        <label className="flex flex-col gap-1">{t('guard.settings.percent') || 'Hourly cap (% of the fleet)'}
          <input type="number" min={5} max={50} value={percent} onChange={(e) => setPercent(Number(e.target.value))} className="w-24 rounded border border-border bg-bg-tertiary px-2 py-1" />
        </label>
        <label className="flex flex-col gap-1">{t('guard.settings.min') || 'Minimum (devices)'}
          <input type="number" min={3} max={50} value={min} onChange={(e) => setMin(Number(e.target.value))} className="w-24 rounded border border-border bg-bg-tertiary px-2 py-1" />
        </label>
        <label className="flex flex-col gap-1">{t('guard.settings.side') || 'Approver of the mass actions of the MSP'}
          <select value={side} onChange={(e) => setSide(e.target.value === 'msp' ? 'msp' : 'client')} className="rounded border border-border bg-bg-tertiary px-2 py-1">
            <option value="client">{t('guard.side.client') || 'client'}</option>
            <option value="msp">{t('guard.side.msp') || 'MSP'}</option>
          </select>
        </label>
        <button type="button" onClick={save} className="text-xs px-2.5 py-1 rounded bg-accent text-white coarse:min-h-10">{t('guard.settings.save') || 'Request the change'}</button>
      </div>
      <p className="text-[11px] text-text-muted">{t('guard.settings.help') || 'A change is approved by a second person (a client approver by default).'}</p>
    </section>
  );
}
