import type {
  GuardApproverDto, GuardOutcome, GuardQuota, GuardRequestInput, GuardSettingsDto, GuardSettingsInput, GuardedActionInfo,
  PendingActionDto,
} from '@obligarth/shared';
import apiClient from './client';

// Guards against mass erasure (server: /api/guard, audit-durci §10.11): the
// requests of guarded actions, their list, cancellation and resumption, the
// emergency freeze, the settings and the designated approvers. A step-up
// (401 twoFactorRequired) is handled by the client's interceptor, which sends
// the same body again with the code.

interface ApiResponse<T> { data?: T; error?: string }

/** What a request would be, before it is sent (no effect on the server). */
export interface GuardPreview {
  tenantId: number;
  actionKey: string;
  targetCount: number;
  bulk: boolean;
  requalified: boolean;
  level: 'sensitive' | 'restricted';
  delaySeconds: number;
  confirmation: 'name' | 'count' | 'none';
  expectedConfirmation: string | null;
  quota: GuardQuota | null;
}

/** A request filed for a second person (unfreeze, settings, approver, resume). */
export interface GuardFiled {
  approvalId: number;
  status: 'pending_approval';
  expiresAt: string;
}

export interface GuardFreezeResult {
  frozen: boolean;
  frozenAt: string | null;
  changed: boolean;
  paused: number;
}

export const guardApi = {
  async catalog(): Promise<GuardedActionInfo[]> {
    const res = await apiClient.get<ApiResponse<GuardedActionInfo[]>>('/guard/catalog');
    return res.data.data ?? [];
  },
  async preview(input: Omit<GuardRequestInput, 'reason'>): Promise<GuardPreview> {
    const res = await apiClient.post<ApiResponse<GuardPreview>>('/guard/actions/preview', input);
    return res.data.data!;
  },
  async request(input: GuardRequestInput): Promise<GuardOutcome> {
    const res = await apiClient.post<ApiResponse<GuardOutcome>>('/guard/actions', input);
    return res.data.data!;
  },
  async list(state?: string, tenantId?: number): Promise<PendingActionDto[]> {
    const res = await apiClient.get<ApiResponse<PendingActionDto[]>>('/guard/actions', {
      params: { ...(state ? { state } : {}), ...(tenantId ? { tenantId } : {}) },
    });
    return res.data.data ?? [];
  },
  async cancel(uuid: string, reason?: string): Promise<{ action: PendingActionDto; cancellation?: Array<{ id: number; outcome: string }> }> {
    const res = await apiClient.post<ApiResponse<{ action: PendingActionDto; cancellation?: Array<{ id: number; outcome: string }> }>>(
      `/guard/actions/${uuid}/cancel`, { reason });
    return res.data.data!;
  },
  async resume(uuid: string): Promise<GuardFiled> {
    const res = await apiClient.post<ApiResponse<GuardFiled>>(`/guard/actions/${uuid}/resume`, {});
    return res.data.data!;
  },
  async quota(): Promise<GuardQuota> {
    const res = await apiClient.get<ApiResponse<GuardQuota>>('/guard/quota');
    return res.data.data!;
  },
  async freeze(reason: string): Promise<GuardFreezeResult> {
    const res = await apiClient.post<ApiResponse<GuardFreezeResult>>('/guard/freeze', { reason });
    return res.data.data!;
  },
  async unfreeze(reason: string): Promise<GuardFiled> {
    const res = await apiClient.post<ApiResponse<GuardFiled>>('/guard/unfreeze', { reason });
    return res.data.data!;
  },
  async settings(): Promise<GuardSettingsDto> {
    const res = await apiClient.get<ApiResponse<GuardSettingsDto>>('/guard/settings');
    return res.data.data!;
  },
  /** 202 with the request filed, or 200 with the settings when nothing changes. */
  async updateSettings(input: GuardSettingsInput): Promise<GuardFiled | GuardSettingsDto> {
    const res = await apiClient.put<ApiResponse<GuardFiled | GuardSettingsDto>>('/guard/settings', input);
    return res.data.data!;
  },
  async approvers(): Promise<GuardApproverDto[]> {
    const res = await apiClient.get<ApiResponse<GuardApproverDto[]>>('/guard/approvers');
    return res.data.data ?? [];
  },
  async designate(userId: number, side: 'client' | 'msp'): Promise<GuardFiled> {
    const res = await apiClient.post<ApiResponse<GuardFiled>>('/guard/approvers', { userId, side });
    return res.data.data!;
  },
  async revoke(id: number): Promise<void> {
    await apiClient.delete(`/guard/approvers/${id}`);
  },
};
