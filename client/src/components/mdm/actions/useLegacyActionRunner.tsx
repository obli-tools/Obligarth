import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import type { LegacyAgentConsoleType, LegacyAgentDeviceAction } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { GuardedActionDialog } from '@/components/guard/GuardedActionDialog';
import { apiErrorMessage } from '@/utils/apiError';

// How an action of the Android bridge agent is launched on one device (agent-pont-android §5, §7), shared by the
// Actions tab and the quick actions of the record. Lock and erase go through their guarded action
// (legacy_agent.device_lock, legacy_agent.erase_device) exactly as on the agent page; the message, the restart and
// the inventory go to the command route, behind the restriction of the tenant.

type LegacyType = LegacyAgentDeviceAction['type'];

const LABEL: Record<LegacyType, { key: string; fallback: string }> = {
  'device.lock': { key: 'legacyAgent.actions.lock', fallback: 'Lock' },
  'device.wipe': { key: 'legacyAgent.actions.wipe', fallback: 'Erase' },
  'device.message': { key: 'legacyAgent.actions.message', fallback: 'Message' },
  'device.reboot': { key: 'legacyAgent.actions.reboot', fallback: 'Restart' },
  'inventory.refresh': { key: 'legacyAgent.actions.inventory', fallback: 'Inventory' },
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
    if (a.type === 'device.lock' || a.type === 'device.wipe') {
      setGuarded({ type: a.type, actionKey: a.guarded && a.actionKey ? a.actionKey : (GUARD_KEY[a.type] as string) });
      return;
    }
    if (a.type === 'device.message') {
      setTitle(''); setText(''); setMode('notification');
      setMessageOpen(true);
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
    </>
  );

  return { run, busy, dialogs };
}

export function legacyActionLabel(t: (k: string) => string, type: LegacyType): string {
  const l = LABEL[type];
  return l ? (t(l.key) || l.fallback) : type;
}
