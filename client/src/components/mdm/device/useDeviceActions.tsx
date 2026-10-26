import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type {
  AndroidDeviceAction, DeviceDetail, LegacyAgentDeviceAction, ManagementChannel, MdmDeviceAction,
} from '@obligarth/shared';
import { SocketEvents } from '@obligarth/shared';
import {
  Eraser, Lock, LocateFixed, MessageSquare, RefreshCw, RotateCw, ShieldCheck, Siren, Volume2, type LucideIcon,
} from 'lucide-react';
import { appleApi } from '@/api/apple.api';
import { androidApi } from '@/api/android.api';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { registerSocketListener } from '@/socket/socketListeners';
import { useAppleActionRunner } from '@/components/mdm/actions/useAppleActionRunner';
import { useAndroidActionRunner } from '@/components/mdm/actions/useAndroidActionRunner';
import { useLegacyActionRunner } from '@/components/mdm/actions/useLegacyActionRunner';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The actions of a lost or stolen device in one shape, whatever its channel (Apple MDM, Android Enterprise, the
// Android bridge agent): the quick actions of the header, the lost device panel, the lost mode banner and the location
// card read them. Each action says whether it can run now and why not; running it goes through the runner of its
// channel (the same parameters, reasons, guard dialogs, second factors and approvals as the Actions tab). The pending
// commands come from the queue of the channel.

export type UnifiedActionKey = 'lock' | 'lostOn' | 'lostOff' | 'sound' | 'locate' | 'erase' | 'message' | 'restart' | 'inventory';
export const UNIFIED_KEYS: UnifiedActionKey[] = ['lock', 'lostOn', 'lostOff', 'sound', 'locate', 'erase', 'message', 'restart', 'inventory'];
export const ACTION_ICON: Record<UnifiedActionKey, LucideIcon> = {
  lock: Lock, lostOn: Siren, lostOff: ShieldCheck, sound: Volume2, locate: LocateFixed, erase: Eraser, message: MessageSquare,
  restart: RotateCw, inventory: RefreshCw,
};

export interface UnifiedAction {
  key: UnifiedActionKey;
  label: string;
  available: boolean;
  /** Why it is not: a code of the channel (apple.commands.unavailable.*, android.commands.unavailable.*,
   *  legacyAgent.unavailable.*) or of the record (personal, platformUnsupported, androidAuto, agentUnsupported,
   *  readOnly, loading). */
  reason: string | null;
  /** The translated reason. */
  reasonLabel: string | null;
  danger: boolean;
  /** Not an action of this channel at all (Apple has no message, Android Enterprise no inventory request). */
  hidden: boolean;
  /** Goes through the guard engine. */
  guarded: boolean;
  /** A command of this action waits in the queue of the device. */
  pending: boolean;
  run: () => void;
}

export interface DeviceActions {
  channel: ManagementChannel;
  actions: Record<UnifiedActionKey, UnifiedAction>;
  loading: boolean;
  /** Commands waiting in the queue of the device (first page); null until read. */
  pendingCount: number | null;
  /** The queue has more waiting commands than its first page. */
  pendingMore: boolean;
  /** The dialogs of the runners, to render once. */
  dialogs: ReactNode;
  reload: () => void;
}

const APPLE_TYPES: Partial<Record<UnifiedActionKey, string>> = {
  lock: 'DeviceLock', lostOn: 'EnableLostMode', lostOff: 'DisableLostMode', sound: 'PlayLostModeSound', locate: 'DeviceLocation',
  erase: 'EraseDevice', restart: 'RestartDevice', inventory: 'DeviceInformation',
};
const ANDROID_TYPES: Partial<Record<UnifiedActionKey, string>> = {
  lock: 'LOCK', lostOn: 'START_LOST_MODE', lostOff: 'STOP_LOST_MODE', erase: 'WIPE', restart: 'REBOOT',
};
const LEGACY_TYPES: Partial<Record<UnifiedActionKey, LegacyAgentDeviceAction['type']>> = {
  lock: 'device.lock', erase: 'device.wipe', message: 'device.message', restart: 'device.reboot', inventory: 'inventory.refresh',
};
/** What a channel cannot do: hidden (not a notion of the channel) or greyed with its reason. */
const UNSUPPORTED: Record<ManagementChannel, Partial<Record<UnifiedActionKey, 'hidden' | string>>> = {
  apple_mdm: { message: 'hidden' },
  amapi: { sound: 'platformUnsupported', locate: 'androidAuto', message: 'hidden', inventory: 'hidden' },
  legacy_agent: { lostOn: 'agentUnsupported', lostOff: 'agentUnsupported', sound: 'agentUnsupported', locate: 'agentUnsupported' },
};
/** Never for a personal device: the lost mode and the location (modele-donnees-mdm §4.3). */
const LOST_KEYS = new Set<UnifiedActionKey>(['lostOn', 'lostOff', 'sound', 'locate']);
const RECORD_REASONS = new Set(['personal', 'platformUnsupported', 'androidAuto', 'agentUnsupported']);
/** The reasons that say the channel cannot do it at all (the quick actions leave such an action out; the panel explains). */
export const CHANNEL_REASONS = new Set(['platformUnsupported', 'androidAuto', 'agentUnsupported']);

const LABEL_FALLBACK: Record<UnifiedActionKey, string> = {
  lock: 'Lock', lostOn: 'Lost mode', lostOff: 'Disable lost mode', sound: 'Play a sound', locate: 'Locate', erase: 'Erase',
  message: 'Message', restart: 'Restart', inventory: 'Refresh inventory',
};
const REASON_FALLBACK: Record<string, string> = {
  personal: 'Never on a personal device', platformUnsupported: 'Not supported on Android',
  androidAuto: 'Sent automatically by the device while in lost mode', agentUnsupported: 'Not available with the Android agent',
};

/** The channel of a record (the field, or what the platform and the mode say for an older server). */
export function channelOf(d: Pick<DeviceDetail, 'platform' | 'managementMode'> & { managementChannel?: ManagementChannel }): ManagementChannel {
  if (d.managementChannel) return d.managementChannel;
  if (d.platform !== 'android') return 'apple_mdm';
  return d.managementMode === 'device_admin' ? 'legacy_agent' : 'amapi';
}

export function useDeviceActions(device: DeviceDetail | null, { canAct, onQueued }: { canAct: boolean; onQueued?: () => void }): DeviceActions {
  const { t } = useTranslation();
  const deviceId = device?.id ?? 0;
  const channel: ManagementChannel = device ? channelOf(device) : 'apple_mdm';
  const [apple, setApple] = useState<MdmDeviceAction[] | null>(null);
  const [android, setAndroid] = useState<AndroidDeviceAction[] | null>(null);
  const [legacy, setLegacy] = useState<LegacyAgentDeviceAction[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [queue, setQueue] = useState<{ types: string[]; more: boolean } | null>(null);

  const load = useCallback(() => {
    if (!deviceId) return;
    const fail = (err: unknown) => setError(apiErrorMessage(err));
    if (channel === 'apple_mdm') appleApi.actions(deviceId).then((a) => { setApple(a); setError(null); }).catch((err) => { setApple([]); fail(err); });
    else if (channel === 'amapi') androidApi.actions(deviceId).then((a) => { setAndroid(a); setError(null); }).catch((err) => { setAndroid([]); fail(err); });
    else legacyAgentApi.actions(deviceId).then((a) => { setLegacy(a); setError(null); }).catch((err) => { setLegacy([]); fail(err); });
    // The Apple queue carries the Android Enterprise commands too (lot AN-D); the agent has its own.
    if (channel === 'legacy_agent') {
      legacyAgentApi.deviceCommands(deviceId)
        .then((rows) => setQueue({ types: rows.filter((c) => c.state === 'pending' || c.state === 'sent').map((c) => c.type), more: false }))
        .catch(() => setQueue(null));
    } else {
      appleApi.deviceQueue(deviceId, { state: 'open' })
        .then((r) => setQueue({ types: r.items.map((i) => i.requestType), more: r.nextCursor !== null }))
        .catch(() => setQueue(null));
    }
  }, [deviceId, channel]);

  // Again when what the menus depend on changes (the recorded lost mode, the enrollment, the ownership, the supervision).
  const lostModeState = device?.lostModeState;
  const enrollmentState = device?.enrollmentState;
  const ownership = device?.ownership;
  const supervised = device?.supervised;
  useEffect(() => {
    setApple(null); setAndroid(null); setLegacy(null); setError(null); setQueue(null);
  }, [deviceId, channel]);
  useEffect(() => { load(); }, [load, lostModeState, enrollmentState, ownership, supervised]);
  // Live: a command of this device changed state (Apple and Android Enterprise).
  useEffect(() => registerSocketListener(SocketEvents.MDM_COMMAND_CHANGED, (p: { deviceIds?: number[] }) => {
    if (!Array.isArray(p?.deviceIds) || p.deviceIds.map(Number).includes(deviceId)) load();
  }), [deviceId, load]);

  const afterQueued = useCallback(() => { onQueued?.(); load(); }, [onQueued, load]);
  const appleRunner = useAppleActionRunner({ deviceId, onQueued: afterQueued });
  const androidRunner = useAndroidActionRunner({ deviceId, ownership: ownership ?? 'corporate', onQueued: afterQueued });
  const legacyRunner = useLegacyActionRunner({ deviceId, onQueued: afterQueued });
  const confirm = useConfirm();

  // The quick actions sit one tap away (header, banner, tiles): ending the lost mode and restarting, which no guard
  // dialog stops on Apple and Android Enterprise, ask first (the agent's runner already confirms its restart).
  const confirmFirst = (key: UnifiedActionKey, run: () => void): (() => void) => {
    if (channel === 'legacy_agent' || (key !== 'lostOff' && key !== 'restart')) return run;
    const message = key === 'lostOff'
      ? (t('deviceSummary.confirmLostOff') || 'Disable the lost mode? The device will be unlocked and usable again.')
      : (t('deviceSummary.confirmRestart') || 'Restart this device?');
    return () => {
      void (async () => {
        if (await confirm({ message, confirmLabel: t(`deviceSummary.quick.${key}`) || LABEL_FALLBACK[key] })) run();
      })();
    };
  };

  // Rebuilt on each render: the runners' callbacks are fresh each time, and the list is nine entries.
  const actions = (() => {
    const out = {} as Record<UnifiedActionKey, UnifiedAction>;
    const unsupported = UNSUPPORTED[channel];
    const loaded = channel === 'apple_mdm' ? apple !== null : channel === 'amapi' ? android !== null : legacy !== null;
    const queued = new Set(queue?.types ?? []);
    const reasonLabel = (code: string): string => {
      if (RECORD_REASONS.has(code)) return trCode(`deviceSummary.lost.reason.${code}`, REASON_FALLBACK[code] ?? code);
      if (code === 'readOnly') return t('apple.actions.readOnly') || 'You can read this device but not act on it.';
      if (code === 'loading') return t('common.loading') || 'Loading…';
      if (code === 'unavailable') return error ?? (t('common.error') || 'Error');
      if (channel === 'amapi') return trCode(`android.commands.unavailable.${code}`, code);
      if (channel === 'legacy_agent') return trCode(`legacyAgent.unavailable.${code}`, code);
      return trCode(`apple.commands.unavailable.${code}`, code);
    };
    for (const key of UNIFIED_KEYS) {
      const label = t(`deviceSummary.quick.${key}`) || LABEL_FALLBACK[key];
      const base = { key, label, danger: key === 'erase' };
      const block = unsupported[key];
      const make = (rest: Omit<UnifiedAction, 'key' | 'label' | 'danger'>): UnifiedAction => ({ ...base, ...rest });
      if (block === 'hidden') {
        out[key] = make({ available: false, reason: null, reasonLabel: null, hidden: true, guarded: false, pending: false, run: () => {} });
        continue;
      }
      // The channel's own entry.
      let available = false;
      let code: string | null = null;
      let guarded = false;
      let pending = false;
      let run = () => {};
      if (channel === 'apple_mdm' && APPLE_TYPES[key]) {
        const a = apple?.find((x) => x.requestType === APPLE_TYPES[key]);
        if (a) { available = a.available; code = a.unavailable; guarded = a.guarded; run = () => appleRunner.run(a); }
        pending = queued.has(APPLE_TYPES[key] as string);
      } else if (channel === 'amapi' && ANDROID_TYPES[key]) {
        const a = android?.find((x) => x.type === ANDROID_TYPES[key]);
        if (a) { available = a.available; code = a.unavailable; guarded = a.guarded; run = () => androidRunner.run(a); }
        pending = queued.has(ANDROID_TYPES[key] as string);
      } else if (channel === 'legacy_agent' && LEGACY_TYPES[key]) {
        const a = legacy?.find((x) => x.type === LEGACY_TYPES[key]);
        if (a) { available = a.available; code = a.unavailable; guarded = a.guarded; run = () => legacyRunner.run(a); }
        pending = queued.has(LEGACY_TYPES[key] as string);
      }
      // Android never requests a position (the device sends it in lost mode), but the server tells whether the privacy
      // profile refuses it (LOCATE, P0-13): that refusal replaces the reason of the channel, known before any read.
      const privacyRefused = channel === 'amapi' && key === 'locate'
        && android?.find((x) => x.type === 'LOCATE')?.unavailable === 'locationDisabledByPrivacy';
      // What the record says first (personal, not a capability of the channel), then the write access, then the server.
      const reason = device?.ownership === 'personal' && LOST_KEYS.has(key) ? 'personal'
        : privacyRefused ? 'locationDisabledByPrivacy'
        : block ? block
          : !canAct ? 'readOnly'
            : !loaded ? 'loading'
              : available ? null
                : code ?? 'unavailable';
      out[key] = make({
        available: reason === null, reason, reasonLabel: reason ? reasonLabel(reason) : null, hidden: false, guarded,
        pending, run: reason === null ? confirmFirst(key, run) : () => {},
      });
    }
    return out;
  })();

  return {
    channel,
    actions,
    loading: channel === 'apple_mdm' ? apple === null : channel === 'amapi' ? android === null : legacy === null,
    pendingCount: queue ? queue.types.length : null,
    pendingMore: queue?.more ?? false,
    dialogs: (
      <>
        {channel === 'apple_mdm' && appleRunner.dialogs}
        {channel === 'amapi' && androidRunner.dialogs}
        {channel === 'legacy_agent' && legacyRunner.dialogs}
      </>
    ),
    reload: load,
  };
}
