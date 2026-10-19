import apiClient from './client';
import type {
  LegacyAgentCommandView, LegacyAgentConsoleType, LegacyAgentDeviceDetail, LegacyAgentDeviceView, LegacyAgentInstanceSettings,
  LegacyAgentPackageView, LegacyAgentReleaseView, LegacyAgentServerKeyView, LegacyAgentTokenCreated, LegacyAgentTokenView,
} from '@obligarth/shared';

// =============================================================================
// Console API of the Android bridge agent (/api/legacy-agent and, for the
// platform, /api/admin/legacy-agent; agent-pont-android §7). A token's value,
// its encoded configuration and the MobiControl script come back once, at its
// creation. The APKs are sent as raw bodies (application/vnd.android.package-
// archive); the server computes their SHA-256 and size.
// =============================================================================

interface ApiResponse<T> { success?: boolean; data?: T }

export interface LegacyAgentEnqueueResult {
  batchId: string;
  commandIds: string[];
  targets: number;
  refused: Array<{ deviceId: number; code: string }>;
  held: boolean;
  replayed: boolean;
}

export interface DeviceFilters { q?: string; conflict?: boolean; adminInactive?: boolean; silent?: boolean; revoked?: boolean }

const flag = (b: boolean | undefined) => (b ? '1' : undefined);

async function uploadApk<T>(url: string, file: File | Blob, params: Record<string, string | undefined>): Promise<T> {
  const clean = Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined && v !== ''));
  const res = await apiClient.post<ApiResponse<T>>(url, file, {
    params: clean, headers: { 'Content-Type': 'application/vnd.android.package-archive' }, timeout: 15 * 60_000,
  });
  return res.data.data!;
}

export const legacyAgentApi = {
  async devices(f: DeviceFilters = {}): Promise<LegacyAgentDeviceView[]> {
    const res = await apiClient.get<ApiResponse<LegacyAgentDeviceView[]>>('/legacy-agent/devices', {
      params: { q: f.q || undefined, conflict: flag(f.conflict), adminInactive: flag(f.adminInactive), silent: flag(f.silent), revoked: flag(f.revoked) },
    });
    return res.data.data ?? [];
  },
  async device(id: number): Promise<LegacyAgentDeviceDetail> {
    const res = await apiClient.get<ApiResponse<LegacyAgentDeviceDetail>>(`/legacy-agent/devices/${id}`);
    return res.data.data!;
  },
  async deviceCommands(id: number): Promise<LegacyAgentCommandView[]> {
    const res = await apiClient.get<ApiResponse<LegacyAgentCommandView[]>>(`/legacy-agent/devices/${id}/commands`);
    return res.data.data ?? [];
  },
  async send(deviceId: number, type: LegacyAgentConsoleType, params: Record<string, unknown>, reason?: string): Promise<LegacyAgentEnqueueResult | { approvalId: number; status: string }> {
    const res = await apiClient.post<ApiResponse<LegacyAgentEnqueueResult>>(`/legacy-agent/devices/${deviceId}/commands`, { type, params, ...(reason ? { reason } : {}) });
    return res.data.data!;
  },
  async bulk(deviceIds: number[], type: LegacyAgentConsoleType, params: Record<string, unknown>, reason?: string): Promise<LegacyAgentEnqueueResult | { approvalId: number; status: string }> {
    const res = await apiClient.post<ApiResponse<LegacyAgentEnqueueResult>>('/legacy-agent/commands/bulk', { type, params, deviceIds, ...(reason ? { reason } : {}) });
    return res.data.data!;
  },
  async cancel(commandId: string): Promise<void> {
    await apiClient.post(`/legacy-agent/commands/${commandId}/cancel`, {});
  },
  async revoke(deviceId: number, reason: string): Promise<{ revoked: boolean }> {
    const res = await apiClient.post<ApiResponse<{ revoked: boolean }>>(`/legacy-agent/devices/${deviceId}/revoke`, { reason });
    return res.data.data!;
  },
  async tokens(): Promise<LegacyAgentTokenView[]> {
    const res = await apiClient.get<ApiResponse<LegacyAgentTokenView[]>>('/legacy-agent/tokens');
    return res.data.data ?? [];
  },
  async createToken(body: { label: string; groupId?: number | null; days?: number; maxUses?: number }): Promise<LegacyAgentTokenCreated> {
    const res = await apiClient.post<ApiResponse<LegacyAgentTokenCreated>>('/legacy-agent/tokens', body);
    return res.data.data!;
  },
  async revokeToken(id: string): Promise<void> {
    await apiClient.post(`/legacy-agent/tokens/${id}/revoke`, {});
  },
  async packages(): Promise<LegacyAgentPackageView[]> {
    const res = await apiClient.get<ApiResponse<LegacyAgentPackageView[]>>('/legacy-agent/packages');
    return res.data.data ?? [];
  },
  uploadPackage(file: File, meta: { packageName: string; versionCode: string; versionName?: string; signerSha256?: string; label?: string }): Promise<LegacyAgentPackageView> {
    return uploadApk('/legacy-agent/packages', file, meta);
  },
  async releases(): Promise<LegacyAgentReleaseView[]> {
    const res = await apiClient.get<ApiResponse<LegacyAgentReleaseView[]>>('/legacy-agent/releases');
    return res.data.data ?? [];
  },
  async settings(): Promise<{ knoxLicenseSet: boolean }> {
    const res = await apiClient.get<ApiResponse<{ knoxLicenseSet: boolean }>>('/legacy-agent/settings');
    return res.data.data!;
  },
  async setKnoxLicense(licenseKey: string | null): Promise<{ knoxLicenseSet: boolean }> {
    const res = await apiClient.put<ApiResponse<{ knoxLicenseSet: boolean }>>('/legacy-agent/settings/knox', { licenseKey });
    return res.data.data!;
  },

  // ── Platform (master tenant, platform administrators) ──
  admin: {
    async releases(): Promise<LegacyAgentReleaseView[]> {
      const res = await apiClient.get<ApiResponse<LegacyAgentReleaseView[]>>('/admin/legacy-agent/releases');
      return res.data.data ?? [];
    },
    uploadRelease(file: File): Promise<{ sha256: string; size: number }> {
      return uploadApk('/admin/legacy-agent/releases/upload', file, {});
    },
    async createRelease(body: { sha256: string; versionCode: number; versionName: string; signerSha256: string; notes?: string }): Promise<LegacyAgentReleaseView> {
      const res = await apiClient.post<ApiResponse<LegacyAgentReleaseView>>('/admin/legacy-agent/releases', body);
      return res.data.data!;
    },
    async withdraw(id: string): Promise<void> {
      await apiClient.post(`/admin/legacy-agent/releases/${id}/withdraw`, {});
    },
    async settings(): Promise<LegacyAgentInstanceSettings> {
      const res = await apiClient.get<ApiResponse<LegacyAgentInstanceSettings>>('/admin/legacy-agent/settings');
      return res.data.data!;
    },
    async saveSettings(body: { pollSeconds?: number; minVersionCode?: number; inventorySeconds?: number }): Promise<LegacyAgentInstanceSettings> {
      const res = await apiClient.put<ApiResponse<LegacyAgentInstanceSettings>>('/admin/legacy-agent/settings', body);
      return res.data.data!;
    },
    async serverKey(): Promise<LegacyAgentServerKeyView> {
      const res = await apiClient.get<ApiResponse<LegacyAgentServerKeyView>>('/admin/legacy-agent/server-key');
      return res.data.data!;
    },
    async exportServerKey(): Promise<{ pkcs8: string; spkiSha256: string; exportedAt: string }> {
      const res = await apiClient.post<ApiResponse<{ pkcs8: string; spkiSha256: string; exportedAt: string }>>('/admin/legacy-agent/server-key/export', {});
      return res.data.data!;
    },
  },
};
