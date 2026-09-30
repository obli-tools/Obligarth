import apiClient from './client';
import type { AppConfigData, ObligateConfig } from '@obliance/shared';

interface ApiResponse<T> { data?: T; error?: string; }

export const appConfigApi = {
  async getConfig(): Promise<AppConfigData> {
    const res = await apiClient.get<ApiResponse<AppConfigData>>('/admin/config');
    return res.data.data!;
  },

  /** `pendingApproval`: 202 — the change went to a second administrator
   *  (tenant.manage_settings at the 'restricted' level); nothing changed yet. */
  async setConfig(key: keyof AppConfigData, value: boolean | number | string | null): Promise<{ pendingApproval: boolean }> {
    const res = await apiClient.put(`/admin/config/${key}`, { value: String(value ?? '') });
    return { pendingApproval: res.status === 202 };
  },

  // ── Obligate SSO gateway ────────────────────────────────────────────────

  async getObligateConfig(): Promise<ObligateConfig> {
    const res = await apiClient.get<ApiResponse<ObligateConfig>>('/admin/config/obligate');
    return res.data.data!;
  },

  async patchObligateConfig(patch: {
    url?: string | null; apiKey?: string | null; enabled?: boolean;
    /** Distinct secret expected from Obligate; null clears it. */
    inboundSecret?: string | null;
  }): Promise<ObligateConfig> {
    const res = await apiClient.put<ApiResponse<ObligateConfig>>('/admin/config/obligate', patch);
    return res.data.data!;
  },
};
