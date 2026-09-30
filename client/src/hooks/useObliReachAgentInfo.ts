import { useCallback, useEffect, useRef, useState } from 'react';
import type { ObliReachAutoStatus, ObliReachWebView2Mode, ObliReachWebView2Status } from '@obliance/shared';
import { remoteApi, type ObliReachSelfUpdate } from '@/api/remote.api';
import { getSocket } from '@/socket/socketClient';

/**
 * Server event (server/src/services/oblireachHub.service.ts): an ObliReach
 * agent connected, reported another version / self-update state or
 * disconnected. Payload: { deviceUuid, version?, online }.
 */
export const OBLIREACH_AGENT_UPDATED = 'OBLIREACH_AGENT_UPDATED';

/** Re-read while an update is due (belt and braces next to the socket event). */
const POLL_WHILE_OUTDATED_MS = 30_000;
/**
 * After a disconnect event: the server still counts the agent online until
 * its last heartbeat is 2 min old (oblireach-agent.routes OR_ONLINE_THRESHOLD_MS)
 * — read again just after that.
 */
const REREAD_AFTER_DISCONNECT_MS = 2 * 60_000 + 5_000;

/** Obliance agent version whose install_oblireach understands {mode:'upgrade'} (update, not repair). */
export const OR_UPGRADE_MODE_MIN_AGENT = '4.5.82';

function parseVersion(v: string | null | undefined): number[] | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(v ?? '').trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** `current` strictly older than `latest` (x.y.z; false when either is not a version). */
export function isOlderObliReachVersion(current: string | null | undefined, latest: string | null | undefined): boolean {
  const c = parseVersion(current);
  const l = parseVersion(latest);
  if (!c || !l) return false;
  for (let i = 0; i < 3; i++) if (c[i] !== l[i]) return c[i] < l[i];
  return false;
}

/** `version` is x.y.z and at least `min` (false when it is not a version). */
export function isVersionAtLeast(version: string | null | undefined, min: string): boolean {
  return parseVersion(version) !== null && !isOlderObliReachVersion(version, min);
}

export interface ObliReachAgentInfo {
  /** null = loading, false = not installed / offline, true = installed and online. */
  installed: boolean | null;
  /** Version the ObliReach agent reports. */
  version: string | null;
  /** Version this server ships. */
  latest: string | null;
  /** Online and older than the server's build. */
  updateAvailable: boolean;
  /** Its own self-update as it reports it (null: offline / not reported by this build). */
  selfUpdate: ObliReachSelfUpdate | null;
  /** WebView2 runtime of the chat window as it reports it (null: offline / not Windows / older build). */
  webview2: ObliReachWebView2Status | null;
  /** Platform setting 'WebView2 install' (null: unknown yet). */
  webview2Mode: ObliReachWebView2Mode | null;
  refresh: () => Promise<void>;
}

/**
 * ObliReach agent of a device (online, version, own self-update) and the
 * server's build, kept LIVE: re-read when the ObliReach agent connects /
 * changes version or self-update state / disconnects (socket), when the
 * browser socket reconnects (an event may have been missed meanwhile), when
 * the Obliance agent's ObliReach report changes (device.oblireachStatus,
 * itself live) and every 30 s while an update is due or running — the version
 * shown after an update no longer needs a page reload.
 *
 * A failed read (network, server restart…) keeps what was known: only a 404
 * means "not installed".
 */
export function useObliReachAgentInfo(
  deviceUuid: string | null | undefined,
  status?: ObliReachAutoStatus | null,
): ObliReachAgentInfo {
  const [installed, setInstalled] = useState<boolean | null>(null);
  const [version, setVersion] = useState<string | null>(null);
  const [latest, setLatest] = useState<string | null>(null);
  const [selfUpdate, setSelfUpdate] = useState<ObliReachSelfUpdate | null>(null);
  const [webview2, setWebview2] = useState<ObliReachWebView2Status | null>(null);
  const [webview2Mode, setWebview2Mode] = useState<ObliReachWebView2Mode | null>(null);
  const seq = useRef(0);

  const refresh = useCallback(async () => {
    const mine = ++seq.current;
    if (!deviceUuid) {
      setInstalled(false);
      setVersion(null);
      setSelfUpdate(null);
      setWebview2(null);
      return;
    }
    const [dev, lat] = await Promise.all([
      remoteApi.getObliReachDevice(deviceUuid),
      remoteApi.getObliReachLatestVersion(),
    ]);
    if (mine !== seq.current) return; // a newer read won
    if (dev !== undefined) {
      setInstalled(!!dev?.is_online);
      setVersion(dev?.version ?? null);
      setSelfUpdate(dev?.self_update ?? null);
      setWebview2(dev?.webview2 ?? null);
      if (dev?.webview2_mode) setWebview2Mode(dev.webview2_mode);
    }
    if (lat !== undefined) setLatest(lat);
  }, [deviceUuid]);

  // Device changed: back to "loading", then read.
  useEffect(() => {
    setInstalled(null);
    setVersion(null);
    setSelfUpdate(null);
    setWebview2(null);
    void refresh();
  }, [refresh]);

  // ObliReach agent connected / new version or self-update state /
  // disconnected; browser socket reconnected.
  useEffect(() => {
    const socket = getSocket();
    if (!socket || !deviceUuid) return;
    let timer: number | undefined;
    const onUpdated = (data: { deviceUuid?: string; online?: boolean } | null) => {
      if (data?.deviceUuid !== deviceUuid) return;
      void refresh();
      window.clearTimeout(timer);
      timer = undefined;
      if (data.online === false) {
        timer = window.setTimeout(() => { timer = undefined; void refresh(); }, REREAD_AFTER_DISCONNECT_MS);
      }
    };
    const onConnect = () => { void refresh(); };
    socket.on(OBLIREACH_AGENT_UPDATED, onUpdated);
    socket.on('connect', onConnect);
    return () => {
      window.clearTimeout(timer);
      socket.off(OBLIREACH_AGENT_UPDATED, onUpdated);
      socket.off('connect', onConnect);
    };
  }, [deviceUuid, refresh]);

  // The Obliance agent reported another ObliReach state / version.
  const statusKey = status ? `${status.state}|${status.installedVersion ?? ''}|${status.running ?? ''}` : '';
  const lastStatusKey = useRef(statusKey);
  useEffect(() => {
    if (lastStatusKey.current === statusKey) return;
    lastStatusKey.current = statusKey;
    void refresh();
  }, [statusKey, refresh]);

  const updateAvailable = installed === true && isOlderObliReachVersion(version, latest);
  const selfUpdating = selfUpdate?.inProgress === true;
  // (also while the WebView2 runtime installs: its end is shown without a reload)
  const webview2Installing = webview2?.state === 'installing';

  useEffect(() => {
    if (!updateAvailable && !selfUpdating && !webview2Installing) return;
    const id = window.setInterval(() => { void refresh(); }, POLL_WHILE_OUTDATED_MS);
    return () => window.clearInterval(id);
  }, [updateAvailable, selfUpdating, webview2Installing, refresh]);

  return { installed, version, latest, updateAvailable, selfUpdate, webview2, webview2Mode, refresh };
}
