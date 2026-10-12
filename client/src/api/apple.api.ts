import apiClient from './client';
import type {
  DdmSyncRequestOutcome, DeviceDeclarationsView, DeviceStatusItemView, GuardOutcome, MdmCancelOutcome, MdmCommandView,
  MdmDeviceAction, MdmEnqueueResult, MdmRelaunchOutcome, MdmTargetView,
} from '@obligarth/shared';

// =============================================================================
// Console API of the integration (/api/apple, integration-apple-edge §8.12,
// §9.9, §12.4): the menu of actions and the command queue of a device, the
// commands of the tenant, the unified timeline, the DDM state.
// =============================================================================

interface ApiResponse<T> { data?: T; nextCursor?: string | null; error?: string; code?: string }

/** One entry of the unified timeline of a device (events, commands, status items). */
export interface TimelineEntry {
  at: string;
  source: 'device_event' | 'command' | 'status';
  kind: string;
  i18nKey: string;
  params: Record<string, unknown>;
  ref: string;
}

/** `null`: the command waits for a second approver (202 with an approval), nothing was queued. */
export type EnqueueAnswer = MdmEnqueueResult | { approvalId: number; status: 'pending_approval' };

export const isAwaitingApproval = (a: EnqueueAnswer): a is { approvalId: number; status: 'pending_approval' } =>
  (a as { status?: string }).status === 'pending_approval';

/** A fresh idempotency key for one click of the console (a retry of the same request replays it). */
export function newIdempotencyKey(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export const appleApi = {
  async actions(deviceId: number): Promise<MdmDeviceAction[]> {
    const res = await apiClient.get<ApiResponse<MdmDeviceAction[]>>(`/apple/devices/${deviceId}/actions`);
    return res.data.data ?? [];
  },
  async enqueue(deviceId: number, body: { requestType: string; params?: Record<string, unknown>; reason?: string; ticket?: string }, key: string): Promise<EnqueueAnswer> {
    const res = await apiClient.post<ApiResponse<EnqueueAnswer>>(`/apple/devices/${deviceId}/commands`, body, { headers: { 'Idempotency-Key': key } });
    return res.data.data!;
  },
  async enqueueBulk(body: { deviceIds: number[]; requestType: string; params?: Record<string, unknown>; reason?: string; ticket?: string }, key: string): Promise<EnqueueAnswer> {
    const res = await apiClient.post<ApiResponse<EnqueueAnswer>>('/apple/commands/bulk', body, { headers: { 'Idempotency-Key': key } });
    return res.data.data!;
  },
  async refreshInventory(deviceId: number): Promise<{ commandIds: string[] }> {
    const res = await apiClient.post<ApiResponse<{ commandIds: string[] }>>(`/apple/devices/${deviceId}/inventory-refresh`);
    return res.data.data ?? { commandIds: [] };
  },
  async removeManagement(deviceId: number, body: { reason: string; ticket?: string; confirm: string }): Promise<GuardOutcome> {
    const res = await apiClient.post<ApiResponse<GuardOutcome>>(`/apple/devices/${deviceId}/remove-management`, body);
    return res.data.data!;
  },
  async deviceQueue(deviceId: number, opts: { state?: 'open' | 'final' | 'all'; cursor?: string | null } = {}): Promise<{ items: MdmTargetView[]; nextCursor: string | null }> {
    const res = await apiClient.get<ApiResponse<MdmTargetView[]>>(`/apple/devices/${deviceId}/commands`, {
      params: { state: opts.state ?? 'all', ...(opts.cursor ? { cursor: opts.cursor } : {}) },
    });
    return { items: res.data.data ?? [], nextCursor: res.data.nextCursor ?? null };
  },
  async command(commandId: string): Promise<{ command: MdmCommandView; targets: MdmTargetView[]; nextCursor: number | null }> {
    const res = await apiClient.get<ApiResponse<{ command: MdmCommandView; targets: MdmTargetView[]; nextCursor: number | null }>>(`/apple/commands/${commandId}`);
    return res.data.data!;
  },
  async cancel(commandId: string, deviceIds?: number[]): Promise<MdmCancelOutcome> {
    const res = await apiClient.post<ApiResponse<MdmCancelOutcome>>(`/apple/commands/${commandId}/cancel`, deviceIds ? { deviceIds } : {});
    return res.data.data ?? { cancelled: 0, requested: 0, notCancellable: 0 };
  },
  async relaunch(commandId: string, deviceIds?: number[]): Promise<MdmRelaunchOutcome> {
    const res = await apiClient.post<ApiResponse<MdmRelaunchOutcome>>(`/apple/commands/${commandId}/relaunch`, deviceIds ? { deviceIds } : {});
    return res.data.data ?? { pushed: 0, skipped: [] };
  },
  async timeline(deviceId: number, opts: { before?: string | null; limit?: number } = {}): Promise<TimelineEntry[]> {
    const res = await apiClient.get<ApiResponse<TimelineEntry[]>>(`/apple/devices/${deviceId}/timeline`, {
      params: { limit: opts.limit ?? 50, ...(opts.before ? { before: opts.before } : {}) },
    });
    return res.data.data ?? [];
  },
  async declarations(deviceId: number): Promise<DeviceDeclarationsView> {
    const res = await apiClient.get<ApiResponse<DeviceDeclarationsView>>(`/apple/devices/${deviceId}/declarations`);
    return res.data.data!;
  },
  async statusItems(deviceId: number): Promise<DeviceStatusItemView[]> {
    const res = await apiClient.get<ApiResponse<DeviceStatusItemView[] | { items: DeviceStatusItemView[] }>>(`/apple/devices/${deviceId}/status-items`);
    const d = res.data.data;
    return Array.isArray(d) ? d : (d?.items ?? []);
  },
  async ddmSync(deviceId: number): Promise<DdmSyncRequestOutcome> {
    const res = await apiClient.post<ApiResponse<DdmSyncRequestOutcome>>(`/apple/devices/${deviceId}/ddm-sync`);
    return res.data.data ?? { requested: false };
  },
};
