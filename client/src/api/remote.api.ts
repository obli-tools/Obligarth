import apiClient from './client';
import type { RemoteSession, RemoteProtocol, ObliReachWebView2Status, ObliReachWebView2Mode } from '@obliance/shared';

interface ApiResponse<T> { data?: T; error?: string; }

export const remoteApi = {
  async listSessions(params?: { deviceId?: number; status?: string; page?: number }): Promise<{ items: RemoteSession[]; total: number }> {
    const res = await apiClient.get<ApiResponse<{ items: RemoteSession[]; total: number }>>('/remote/sessions', { params });
    return res.data.data ?? { items: [], total: 0 };
  },
  async startSession(deviceId: number, protocol: RemoteProtocol, notes?: string, sessionId?: number, vmId?: string): Promise<RemoteSession> {
    const res = await apiClient.post<ApiResponse<RemoteSession>>('/remote/sessions', {
      deviceId, protocol, notes,
      ...(sessionId !== undefined ? { sessionId } : {}),
      ...(vmId !== undefined ? { vmId } : {}),
    });
    return res.data.data!;
  },
  async endSession(sessionId: string): Promise<void> {
    await apiClient.post(`/remote/sessions/${sessionId}/end`);
  },
  /** Build the browser-side WebSocket URL for a remote tunnel session. */
  getTunnelWsUrl(sessionToken: string): string {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/api/remote/tunnel/${sessionToken}`;
  },
  /** Return the set of device UUIDs where the Oblireach agent is currently online. */
  async listObliReachDeviceUuids(): Promise<Set<string>> {
    try {
      const res = await apiClient.get<ApiResponse<{ items: Array<{ device_uuid: string; is_online: boolean }> }>>('/oblireach/devices');
      const items = res.data.data?.items ?? [];
      // Only count devices that have pushed recently (is_online = true).
      return new Set(items.filter((d) => d.is_online).map((d) => d.device_uuid));
    } catch {
      return new Set();
    }
  },

  /** Return the last-known WTS session list for an Oblireach device. */
  async getObliReachSessions(deviceUuid: string): Promise<ObliReachSession[]> {
    try {
      const res = await apiClient.get<ApiResponse<{ sessions: ObliReachSession[] }>>(
        `/oblireach/devices/${deviceUuid}/sessions`,
      );
      return res.data.data?.sessions ?? [];
    } catch {
      return [];
    }
  },

  /**
   * Return the device record for a specific Oblireach device (includes
   * version, os, arch). null: no such ObliReach agent (404); undefined: the
   * request failed (network, server restart…) — the caller keeps what it
   * knew instead of concluding "not installed".
   */
  async getObliReachDevice(deviceUuid: string): Promise<ObliReachDevice | null | undefined> {
    try {
      const res = await apiClient.get<ApiResponse<{ device: ObliReachDevice }>>(
        `/oblireach/devices/${deviceUuid}`,
      );
      return res.data.data?.device ?? null;
    } catch (err) {
      return (err as { response?: { status?: number } })?.response?.status === 404 ? null : undefined;
    }
  },

  /** Return the latest available Oblireach agent version from the server build artefact (undefined: the request failed). */
  async getObliReachLatestVersion(): Promise<string | null | undefined> {
    try {
      const res = await apiClient.get<ApiResponse<{ version: string | null }>>(
        '/oblireach/devices/latest-version',
      );
      return res.data.data?.version ?? null;
    } catch {
      return undefined;
    }
  },

  /**
   * Ask an Oblireach agent to update itself: sent at once over its live
   * channel, queued (delivered at its next connection) only when offline;
   * nothing when already up to date or while an update / install runs.
   */
  async queueObliReachUpdate(deviceUuid: string): Promise<ObliReachUpdateResult> {
    const res = await apiClient.post<{ status?: string; delivered?: ObliReachUpdateResult['delivered']; reason?: string }>(
      `/oblireach/devices/${deviceUuid}/command`, { type: 'update' },
    );
    return { delivered: res.data?.delivered ?? 'queued', reason: res.data?.reason };
  },

  /**
   * Ask the device's ObliReach to install the Microsoft Edge WebView2 runtime
   * (chat window) now. Errors (axios): 403 {code:'forbidden', error} (rights),
   * 409 {error:'disabled'|'not_reporting'|'no_installer'|'unsupported'}.
   */
  async installObliReachWebView2(deviceUuid: string): Promise<{ delivered: 'sent' | 'already_installed' | 'in_progress' }> {
    const res = await apiClient.post<{ status?: string; delivered?: 'sent' | 'already_installed' | 'in_progress' }>(
      `/oblireach/devices/${deviceUuid}/webview2/install`, {},
    );
    return { delivered: res.data?.delivered ?? 'sent' };
  },
};

export interface ObliReachUpdateResult {
  /** 'sent': delivered now; 'queued': agent offline; 'up_to_date' / 'in_progress': nothing sent. */
  delivered: 'sent' | 'queued' | 'up_to_date' | 'in_progress';
  reason?: string;
}

export interface ObliReachSession {
  id: number;
  username: string;
  state: string;
  stationName?: string;
  isConsole: boolean;
}

export interface ObliReachDevice {
  id: number;
  device_uuid: string;
  hostname: string;
  os: string;
  arch: string;
  version?: string;
  is_online: boolean;
  last_seen_at?: string;
  sessions: ObliReachSession[];
  /** Its own self-update as its last heartbeat reported it (null: offline / not reported by this build). */
  self_update?: ObliReachSelfUpdate | null;
  /** Microsoft Edge WebView2 runtime of the chat window (Windows builds that report it; null otherwise). */
  webview2?: ObliReachWebView2Status | null;
  /** Platform setting 'WebView2 install' (GET of one device only). */
  webview2_mode?: ObliReachWebView2Mode;
}

/** Self-update state an ObliReach agent reports (server: oblireachUpdateGate.ObliReachSelfUpdate). */
export interface ObliReachSelfUpdate {
  inProgress: boolean;
  target: string | null;
  since: string | null;
  /** installed | failed | busy | not_restarted | unsupported */
  lastOutcome: string | null;
  lastResult: string | null;
  lastResultAt: string | null;
  lastError: string | null;
  failures: number;
  /** Automatic attempts not before (a manual request only waits 2 min after the last start). */
  nextAttemptAt: string | null;
}
