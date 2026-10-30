import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import type { LegacyAgentConsoleType, LegacyAgentDeviceAction, RemoteMode } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { GuardedActionDialog } from '@/components/guard/GuardedActionDialog';
import { RemoteOpenDialog } from '@/components/remote/RemoteOpenDialog';
import { apiErrorMessage } from '@/utils/apiError';

// How an action of the Android bridge agent is launched on one device (agent-pont-android §5, §7), shared by the
// Actions tab and the quick actions of the record. Lock and erase go through their guarded action
// (legacy_agent.device_lock, legacy_agent.erase_device) exactly as on the agent page; the message, the restart and
// the inventory go to the command route, behind the restriction of the tenant. See the screen and take control open
// the dialog of a remote assistance session (P0-15), then its viewer.

type LegacyType = LegacyAgentDeviceAction['type'];

const LABEL: Record<LegacyType, { key: string; fallback: string }> = {
  'device.lock': { key: 'legacyAgent.actions.lock', fallback: 'Lock' },
  'device.wipe': { key: 'legacyAgent.actions.wipe', fallback: 'Erase' },
  'device.message': { key: 'legacyAgent.actions.message', fallback: 'Message' },
  'device.reboot': { key: 'legacyAgent.actions.reboot', fallback: 'Restart' },
  'inventory.refresh': { key: 'legacyAgent.actions.inventory', fallback: 'Inventory' },
  'remote.view': { key: 'legacyAgent.actions.remoteView', fallback: 'See the screen' },
  'remote.control': { key: 'legacyAgent.actions.remoteControl', fallback: 'Take control' },
  'kiosk.suspend': { key: 'legacyAgentPolicy.actions.suspendKiosk', fallback: 'Suspend the kiosk' },
  'policy.reapply': { key: 'legacyAgentPolicy.actions.reapply', fallback: 'Re-apply the policy' },
};
/** The guarded action of lock and erase when the menu does not name it. */
const GUARD_KEY: Partial<Record<LegacyType, string>> = { 'device.lock': 'legacy_agent.device_lock', 'device.wipe': 'legacy_agent.erase_device' };

const fieldCls = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';

export interface LegacyActionRunner {
  run: (action: LegacyAgentDeviceAction) => void;
  /** The type being sent. */
  busy: string | null;
  /** The dialogs of the runner, to render once. */
  dialogs: ReactNode;
}

export function useLegacyActionRunner({ deviceId, onQueued }: { deviceId: number; onQueued?: () => void }): LegacyActionRunner {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [guarded, setGuarded] = useState<{ type: LegacyType; actionKey: string } | null>(null);
  const [messageOpen, setMessageOpen] = useState(false);
  const [title, setTitle] = useState('');
  const [text, setText] = useState('');
  const [mode, setMode] = useState<'notification' | 'fullscreen'>('notification');
  const [busy, setBusy] = useState<string | null>(null);
  const [remoteMode, setRemoteMode] = useState<RemoteMode | null>(null);
  const [suspendOpen, setSuspendOpen] = useState(false);
  const [minutes, setMinutes] = useState('15');
  // The latest callback (the caller's reload changes with its state).
  const queued = useRef(onQueued);
  useEffect(() => { queued.current = onQueued; }, [onQueued]);

  const send = async (type: LegacyAgentConsoleType, params: Record<string, unknown>) => {
    setBusy(type);
    try {
      const r = await legacyAgentApi.send(deviceId, type, params);
      if ('approvalId' in r) toast.success(t('legacyAgent.awaitingApproval') || 'Request sent for approval');
      else toast.success(t('legacyAgent.queued', { count: r.targets }) || `Queued for ${r.targets} device(s)`);
      queued.current?.();
      return true;
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
      return false;
    } finally {
      setBusy(null);
    }
  };

  const run = (a: LegacyAgentDeviceAction) => {
    // A remote assistance session is opened through /api/remote-sessions (its viewer), never as a command.
    if (a.type === 'remote.view' || a.type === 'remote.control') {
      setRemoteMode(a.type === 'remote.control' ? 'control' : 'view');
      return;
    }
    if (a.type === 'device.lock' || a.type === 'device.wipe') {
      setGuarded({ type: a.type, actionKey: a.guarded && a.actionKey ? a.actionKey : (GUARD_KEY[a.type] as string) });
      return;
    }
    if (a.type === 'device.message') {
      setTitle(''); setText(''); setMode('notification');
      setMessageOpen(true);
      return;
    }
    // The agent policy (agent 1.3.0, lot PONT-POL): the kiosk left for some minutes; the policy applied again in full.
    if (a.type === 'kiosk.suspend') {
      setMinutes('15');
      setSuspendOpen(true);
      return;
    }
    if (a.type === 'policy.reapply') {
      void (async () => {
        if (await confirm({ message: t('legacyAgentPolicy.actions.reapplyConfirm') || 'Apply the whole policy again on this device at its next poll?' })) void send('policy.reapply', {});
      })();
      return;
    }
    if (a.type === 'device.reboot') {
      void (async () => {
        if (await confirm({ message: t('deviceSummary.confirmRestartAgent') || 'Restart this device? A licensed Knox is required.' })) void send('device.reboot', {});
      })();
      return;
    }
    void send('inventory.refresh', {});
  };

  const dialogs = (
    <>
      <Modal
        open={messageOpen}
        onClose={() => setMessageOpen(false)}
        size="sm"
        title={t('legacyAgent.actions.message') || 'Message'}
        footer={(
          <>
            <Button variant="secondary" onClick={() => setMessageOpen(false)}>{t('common.cancel') || 'Cancel'}</Button>
            <Button
              disabled={!title.trim() || !text.trim()}
              loading={busy === 'device.message'}
              onClick={async () => { if (await send('device.message', { title: title.trim(), text: text.trim(), mode })) setMessageOpen(false); }}
            >
              {t('legacyAgent.send') || 'Send'}
            </Button>
          </>
        )}
      >
        <div className="space-y-3 text-sm">
          <label className="block">
            <span className="text-xs text-text-muted">{t('legacyAgent.message.title') || 'Title'}</span>
            <input className={fieldCls} maxLength={80} value={title} onChange={(e) => setTitle(e.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-text-muted">{t('legacyAgent.message.text') || 'Text'}</span>
            <textarea className={fieldCls} maxLength={500} rows={4} value={text} onChange={(e) => setText(e.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-text-muted">{t('legacyAgent.message.mode') || 'Display'}</span>
            <select className={fieldCls} value={mode} onChange={(e) => setMode(e.target.value as 'notification' | 'fullscreen')}>
              <option value="notification">{t('legacyAgent.message.notification') || 'Notification'}</option>
              <option value="fullscreen">{t('legacyAgent.message.fullscreen') || 'Full screen'}</option>
            </select>
          </label>
        </div>
      </Modal>

      {guarded && (
        <GuardedActionDialog
          open
          onClose={() => setGuarded(null)}
          actionKey={guarded.actionKey}
          selection={{ deviceIds: [deviceId] }}
          params={guarded.type === 'device.wipe' ? { wipeExternal: false } : {}}
          title={legacyActionLabel(t, guarded.type)}
          onDone={() => { setGuarded(null); queued.current?.(); }}
        />
      )}

      <Modal
        open={suspendOpen}
        onClose={() => setSuspendOpen(false)}
        size="sm"
        title={t('legacyAgentPolicy.actions.suspendKiosk') || 'Suspend the kiosk'}
        footer={(
          <>
            <Button variant="secondary" onClick={() => setSuspendOpen(false)}>{t('common.cancel') || 'Cancel'}</Button>
            <Button
              disabled={!/^[0-9]{1,3}$/.test(minutes) || Number(minutes) < 1 || Number(minutes) > 240}
              loading={busy === 'kiosk.suspend'}
              onClick={async () => { if (await send('kiosk.suspend', { minutes: Number(minutes) })) setSuspendOpen(false); }}
            >
              {t('legacyAgent.send') || 'Send'}
            </Button>
          </>
        )}
      >
        <div className="space-y-2 text-sm">
          <p className="text-text-muted">{t('legacyAgentPolicy.actions.suspendHelp') || 'The device leaves its kiosk for this time, then returns to it.'}</p>
          <label className="block">
            <span className="text-xs text-text-muted">{t('legacyAgentPolicy.actions.minutes') || 'Minutes (1 to 240)'}</span>
            <input className={fieldCls} inputMode="numeric" maxLength={3} value={minutes} onChange={(e) => setMinutes(e.target.value.replace(/[^0-9]/g, ''))} />
          </label>
        </div>
      </Modal>

      <RemoteOpenDialog deviceId={deviceId} mode={remoteMode} onClose={() => setRemoteMode(null)} />
    </>
  );

  return { run, busy, dialogs };
}

export function legacyActionLabel(t: (k: string) => string, type: LegacyType): string {
  const l = LABEL[type];
  return l ? (t(l.key) || l.fallback) : type;
}
