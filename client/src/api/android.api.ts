import apiClient from './client';
import type { AndroidQuotaView } from '@obligarth/shared';

// The platform side of Android (android-amapi §5.6, §12.1, lot AN-A2): identity and health of the link to Google,
// quota of the project. Platform administrators, master tenant (/api/admin/android). Never a key nor a token: the
// fingerprint of the service account key and the name of its account only.

interface ApiResponse<T> { success?: boolean; data?: T; error?: string; code?: string }

export interface AndroidPlatformHealth {
  mode: 'off' | 'google' | 'fake';
  auth?: 'vault_key' | 'adc';
  projectId?: string | null;
  pinnedProjectId?: string | null;
  identity?: null | {
    configured: boolean;
    fingerprint: string | null;
    account: string | null;
    lastTokenAt: string | null;
    lastError: string | null;
    setAt: string | null;
  };
  subscriptionPermission?: boolean | null;
  breaker?: null | { state: 'closed' | 'open' | 'half_open'; failures: number; openedAt: number | null; backoffUntil: number | null };
  loop: string;
  lastPullAt?: string | null;
  lastAppliedPublishAt?: string | null;
  lagSeconds?: number | null;
  lastTestMessageAt?: string | null;
  limiter?: { tokens: number; capacity: number };
}

export const androidPlatformApi = {
  async health(): Promise<AndroidPlatformHealth> {
    const res = await apiClient.get<ApiResponse<AndroidPlatformHealth>>('/admin/android/health');
    return res.data.data!;
  },

  async quota(): Promise<AndroidQuotaView> {
    const res = await apiClient.get<ApiResponse<AndroidQuotaView>>('/admin/android/quota');
    return res.data.data!;
  },
};
