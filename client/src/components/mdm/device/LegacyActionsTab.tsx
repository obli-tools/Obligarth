import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Ban, MonitorSmartphone, Play, RefreshCw, ShieldAlert } from 'lucide-react';
import type { LegacyAgentCommandState, LegacyAgentCommandView, LegacyAgentDeviceAction } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { legacyActionLabel, useLegacyActionRunner } from '@/components/mdm/actions/useLegacyActionRunner';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The Actions and Commands tabs of a device of the Android bridge agent (agent-pont-android §5, §7): its own menu
// (lock and erase through their guarded action, message, restart, inventory) instead of the greyed Apple menu, and its
// own queue (legacy_agent_commands). The agent page keeps the bulk actions, the apps and the tokens.

const STATE_TONE: Record<LegacyAgentCommandState, 'green' | 'gray' | 'blue' | 'red'> = {
  pending: 'blue', sent: 'blue', acknowledged: 'green', error: 'red', rejected: 'red', expired: 'gray', cancelled: 'gray',
};
const TYPE_LABEL: Record<string, { key: string; fallback: string }> = {
  'app.install': { key: 'legacyAgent.actions.install', fallback: 'Install an app' },
  'app.uninstall': { key: 'legacyAgent.actions.uninstall', fallback: 'Uninstall an app' },
  'agent.update': { key: 'legacyAgent.actions.update', fallback: 'Update the agent' },
};
const MENU: Array<LegacyAgentDeviceAction['type']> = [
  'remote.view', 'remote.control', 'device.lock', 'device.message', 'device.reboot', 'inventory.refresh', 'device.wipe',
];
/** The remote assistance (P0-15): opened by its dialog and its viewer, never a command of the queue. */
const REMOTE_TYPES = new Set<LegacyAgentDeviceAction['type']>(['remote.view', 'remote.control']);

export function LegacyActionsTab({ deviceId, canAct, onQueued }: { deviceId: number; canAct: boolean; onQueued?: () => void }) {
  const { t } = useTranslation();
  const [actions, setActions] = useState<LegacyAgentDeviceAction[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    legacyAgentApi.actions(deviceId).then((a) => { setActions(a); setError(null); }).catch((err) => { setActions([]); setError(apiErrorMessage(err)); });
  }, [deviceId]);
  useEffect(() => { load(); }, [load]);
  const runner = useLegacyActionRunner({ deviceId, onQueued: () => { onQueued?.(); load(); } });
  const byType = new Map((actions ?? []).map((a) => [a.type, a]));
  const list = MENU.map((type) => byType.get(type)).filter((a): a is LegacyAgentDeviceAction => !!a);
  return (
    <div className="space-y-4">
      {error && <p className="text-sm text-red-400">{error}</p>}
      {actions === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p> : (
        <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
          {list.map((a) => (
            <li key={a.type} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
              <span className="min-w-0 flex-1">
                <span className={a.available ? 'text-text-primary' : 'text-text-muted'}>{legacyActionLabel(t, a.type)}</span>
                {a.guarded && <span className="ml-2 text-[10px] uppercase text-red-400">{t('apple.actions.guarded') || 'guarded'}</span>}
                {!a.available && a.unavailable && (
                  <span className="block text-[11px] text-text-muted">{trCode(`legacyAgent.unavailable.${a.unavailable}`, a.unavailable)}</span>
                )}
              </span>
              <Button size="sm" variant={a.type === 'device.wipe' ? 'danger' : 'secondary'} disabled={!canAct || !a.available || runner.busy === a.type} onClick={() => runner.run(a)}>
                {REMOTE_TYPES.has(a.type)
                  ? <><MonitorSmartphone className="w-3.5 h-3.5 mr-1" />{t('remote.open.button') || 'Open'}</>
                  : <><Play className="w-3.5 h-3.5 mr-1" />{t('apple.actions.run') || 'Request'}</>}
              </Button>
            </li>
          ))}
        </ul>
      )}
      <p className="text-xs text-text-muted">
        <Link to={`/legacy-agent?device=${deviceId}`} className="text-accent hover:underline">{t('legacyAgent.openPanel') || 'Android agent panel'}</Link>
      </p>
      {!canAct && <p className="text-xs text-text-muted">{t('apple.actions.readOnly') || 'You can read this device but not act on it.'}</p>}
      {runner.dialogs}
    </div>
  );
}

export function LegacyCommandsTab({ deviceId, canAct, onChanged }: { deviceId: number; canAct: boolean; onChanged?: () => void }) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<LegacyAgentCommandView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const load = useCallback(() => {
    legacyAgentApi.deviceCommands(deviceId).then((r) => { setRows(r); setError(null); }).catch((err) => { setRows((prev) => prev ?? []); setError(apiErrorMessage(err)); });
  }, [deviceId]);
  useEffect(() => { load(); }, [load]);
  const cancel = async (c: LegacyAgentCommandView) => {
    setBusy(c.id);
    try {
      await legacyAgentApi.cancel(c.id);
      toast.success(t('apple.commands.cancelled') || 'Command cancelled');
      load();
      onChanged?.();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(null);
    }
  };
  const label = (type: string): string => {
    const l = TYPE_LABEL[type];
    if (l) return t(l.key) || l.fallback;
    return MENU.includes(type as LegacyAgentDeviceAction['type']) ? legacyActionLabel(t, type as LegacyAgentDeviceAction['type']) : type;
  };
  return (
    <div className="space-y-3">
      <div className="flex items-center">
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="ml-auto p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {rows === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? <p className="text-sm text-text-muted">{t('apple.commands.empty') || 'No command'}</p> : (
          <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
            {rows.map((c) => {
              const open = c.state === 'pending' || c.state === 'sent';
              return (
                <li key={c.id} className="px-3 py-2.5 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-text-primary">{label(c.type)}</span>
                    <StateBadge tone={STATE_TONE[c.state] ?? 'gray'} label={t(`legacyAgent.state.${c.state}`) || c.state} pulse={open} />
                    {c.guardActionUuid && <ShieldAlert className="w-3.5 h-3.5 text-red-400" aria-hidden />}
                    {c.resultCode && <span className="font-mono text-[11px] text-text-muted">{c.resultCode}</span>}
                    <span className="ml-auto text-[11px] text-text-muted" title={c.id}>{formatDateTime(c.createdAt)}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] text-text-muted">
                    {c.reason && <span className="break-words">{t('apple.commands.reason') || 'Reason'}: {c.reason}</span>}
                    {c.holdReason && <span className="text-amber-400">{c.holdReason}</span>}
                    {open && <span>{t('apple.commands.expiresAt') || 'Expires'}: {formatDateTime(c.expiresAt)}</span>}
                    {c.deliveredAt && <span>{t('apple.commands.deliveredAt') || 'Delivered'}: {formatDateTime(c.deliveredAt)}</span>}
                    {c.completedAt && <span>{t('apple.commands.completedAt') || 'Ended'}: {formatDateTime(c.completedAt)}</span>}
                  </div>
                  {/* A command of a guarded action is withdrawn from its action (Guards tab), as on the agent page. */}
                  {canAct && c.state === 'pending' && !c.guardActionUuid && (
                    <div className="mt-2">
                      <Button size="sm" variant="secondary" disabled={busy === c.id} onClick={() => void cancel(c)}>
                        <Ban className="w-3.5 h-3.5 mr-1" />{t('apple.commands.cancel') || 'Cancel'}
                      </Button>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
    </div>
  );
}
