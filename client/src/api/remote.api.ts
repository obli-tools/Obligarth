import apiClient from './client';
import type {
  RemoteMode, RemoteRequesterSide, RemoteSessionCreated, RemoteSessionDto, RemoteSessionState, RemoteSettings, RemoteSettingsDto,
} from '@obligarth/shared';

// =============================================================================
// Console API of the remote assistance (/api/remote-sessions; P0-15 §4.2, §0.1). The viewer's token comes back once: at
// the request of a session (201), or by viewerToken() for a session approved later. It is never put in a URL: the
// tunnel (T5/T6) takes it as a WebSocket subprotocol. The request, the move to the control and the viewer's token ask
// the technician's strict second factor (the 401 of the step-up, handled by the client's interceptor); the reason and
// the ticket are optional.
// =============================================================================

interface ApiResponse<T> { success?: boolean; data?: T }

export interface RemoteSessionFilters {
  deviceId?: number;
  state?: RemoteSessionState;
  requestedBy?: number;
  side?: RemoteRequesterSide;
  from?: string;
  to?: string;
  page?: number;
}

export interface RemoteSessionPage { items: RemoteSessionDto[]; page: number; pageSize: number; total: number }

export const remoteApi = {
  async request(body: { deviceId: number; mode: RemoteMode; reason?: string; ticket?: string }): Promise<RemoteSessionCreated> {
    const res = await apiClient.post<ApiResponse<RemoteSessionCreated>>('/remote-sessions', body);
    return res.data.data!;
  },
  async list(f: RemoteSessionFilters = {}): Promise<RemoteSessionPage> {
    const params = Object.fromEntries(Object.entries(f).filter(([, v]) => v !== undefined && v !== '').map(([k, v]) => [k, String(v)]));
    const res = await apiClient.get<ApiResponse<RemoteSessionPage>>('/remote-sessions', { params });
    return res.data.data!;
  },
  async get(id: string): Promise<RemoteSessionDto> {
    const res = await apiClient.get<ApiResponse<RemoteSessionDto>>(`/remote-sessions/${encodeURIComponent(id)}`);
    return res.data.data!;
  },
  async end(id: string): Promise<RemoteSessionDto> {
    const res = await apiClient.post<ApiResponse<RemoteSessionDto>>(`/remote-sessions/${encodeURIComponent(id)}/end`, {});
    return res.data.data!;
  },
  /** View → control, granted by the server (nothing asked of the device). */
  async escalate(id: string): Promise<RemoteSessionDto> {
    const res = await apiClient.post<ApiResponse<RemoteSessionDto>>(`/remote-sessions/${encodeURIComponent(id)}/escalate`, {});
    return res.data.data!;
  },
  /** Control → view. */
  async release(id: string): Promise<RemoteSessionDto> {
    const res = await apiClient.post<ApiResponse<RemoteSessionDto>>(`/remote-sessions/${encodeURIComponent(id)}/release`, {});
    return res.data.data!;
  },
  async viewerToken(id: string): Promise<{ session: RemoteSessionDto; viewerToken: string }> {
    const res = await apiClient.post<ApiResponse<{ session: RemoteSessionDto; viewerToken: string }>>(`/remote-sessions/${encodeURIComponent(id)}/viewer-token`, {});
    return res.data.data!;
  },
  async settings(): Promise<RemoteSettingsDto> {
    const res = await apiClient.get<ApiResponse<RemoteSettingsDto>>('/remote-sessions/settings');
    return res.data.data!;
  },
  /** Always an approval request (202). */
  async requestSettings(change: Partial<RemoteSettings>): Promise<{ approvalId: number; requiredSide: string }> {
    const res = await apiClient.put<ApiResponse<{ approvalId: number; requiredSide: string }>>('/remote-sessions/settings', change);
    return res.data.data!;
  },
};
