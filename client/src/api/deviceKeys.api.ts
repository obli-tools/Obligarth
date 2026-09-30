import apiClient from './client';
import type { DeviceKeyInfo, DeviceKeyListResponse } from '@obligarth/shared';

// Device-bound 2FA ("validation par empreinte") — docs/mobile/device-bound-2fa.md §6.5.
// The web never enrols nor signs: it lists the account's phones and revokes
// them (profile, no step-up [D8b]; administration, P1 scope + the
// tenant.manage_users envelope, which may answer 202 pending approval).

export const deviceKeysApi = {
  /** The caller's phones + policy. null when the server has no device keys (404). */
  async mine(): Promise<DeviceKeyListResponse | null> {
    try {
      const res = await apiClient.get<{ data: DeviceKeyListResponse }>('/profile/device-keys');
      return res.data.data;
    } catch (err) {
      if ((err as { response?: { status?: number } })?.response?.status === 404) return null;
      throw err;
    }
  },

  async revokeMine(id: string): Promise<void> {
    await apiClient.delete(`/profile/device-keys/${encodeURIComponent(id)}`);
  },

  async revokeAllMine(): Promise<void> {
    await apiClient.delete('/profile/device-keys');
  },

  // ── Administration (users.manage) ────────────────────────────────────────

  async listForUser(userId: number): Promise<DeviceKeyInfo[]> {
    const res = await apiClient.get<{ data: DeviceKeyInfo[] }>(`/users/${userId}/device-keys`);
    return res.data.data ?? [];
  },

  /** true when the revocation waits for a second administrator (202). */
  async revokeForUser(userId: number, keyId: string): Promise<boolean> {
    const res = await apiClient.delete(`/users/${userId}/device-keys/${encodeURIComponent(keyId)}`);
    return res.status === 202;
  },

  /** true when the revocation waits for a second administrator (202). */
  async revokeAllForUser(userId: number): Promise<boolean> {
    const res = await apiClient.delete(`/users/${userId}/device-keys`);
    return res.status === 202;
  },
};
