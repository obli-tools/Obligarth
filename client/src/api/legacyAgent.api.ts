import apiClient from './client';
import type {
  LegacyAgentCommandView, LegacyAgentConsoleType, LegacyAgentDeviceAction, LegacyAgentDeviceDetail, LegacyAgentDeviceView,
  LegacyAgentInstanceSettings, LegacyAgentNameImportFormat, LegacyAgentNameImportResult,
  LegacyAgentPackageView, LegacyAgentReleaseView, LegacyAgentServerKeyView, LegacyAgentTokenCreated, LegacyAgentTokenView,
  LegacyAgentDeviceValuesImportResult, LegacyAgentDeviceValuesImportRow, LegacyAgentFileView, LegacyAgentPolicyStatusView,
} from '@obligarth/shared';

/** The matching of an import of per-device values (lot PONT-POL §12.1). */
export interface DeviceValuesMatch { byName: boolean; byCode?: { nameRegex: string; field: string; pad: number } }
/** An import beyond the thresholds, or held by the matrix: a request for approval. */
export interface DeviceValuesPending { approvalId: number; status: string; code?: string; policyImpact?: number }

/** The media type a store file travels with: images and certificates by their type, anything else as bytes (the API's
 *  JSON parser would read a JSON body first). */
function storeMediaType(file: File): string {
  const t = (file.type || '').toLowerCase();
  if (['image/png', 'image/jpeg', 'image/gif', 'image/x-icon', 'image/vnd.microsoft.icon'].includes(t)) return t;
  if (/\.(png)$/i.test(file.name)) return 'image/png';
  if (/\.(jpe?g)$/i.test(file.name)) return 'image/jpeg';
  if (/\.(gif)$/i.test(file.name)) return 'image/gif';
  if (/\.(ico)$/i.test(file.name)) return 'image/x-icon';
  if (/\.(crt|pem|cer|der)$/i.test(file.name) || t === 'application/x-x509-ca-cert') return 'application/x-x509-ca-cert';
  return 'application/octet-stream';
}

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
  /** The menu of a device's record, with what greys an entry (lock and erase go through POST /actions). */
  async actions(id: number): Promise<LegacyAgentDeviceAction[]> {
    const res = await apiClient.get<ApiResponse<LegacyAgentDeviceAction[]>>(`/legacy-agent/devices/${id}/actions`);
    return res.data.data ?? [];
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
  /** confirmOwnerDeclared (lot BANC, D3): the owner of the device declared for an agent older than 1.4.0 stays set; the
   *  server answers 409 ownerDeclaredConfirm until it is confirmed. */
  async revoke(deviceId: number, reason: string, confirmOwnerDeclared = false): Promise<{ revoked: boolean }> {
    const res = await apiClient.post<ApiResponse<{ revoked: boolean }>>(`/legacy-agent/devices/${deviceId}/revoke`,
      { reason, ...(confirmOwnerDeclared ? { confirmOwnerDeclared: true } : {}) });
    return res.data.data!;
  },
  /** Display names by IMEI or serial number (MobiControl, Omnissa Workspace ONE, any CSV): a preview, or with `apply` the renaming. */
  async importNames(rows: Array<{ name: string; imei?: string; serial?: string }>, apply: boolean, format: LegacyAgentNameImportFormat): Promise<LegacyAgentNameImportResult> {
    const res = await apiClient.post<ApiResponse<LegacyAgentNameImportResult>>('/legacy-agent/devices/names', { rows, apply, format });
    return res.data.data!;
  },
  /** The view of the console (ids in their order) as CSV or XLSX, headers in the language of the console. */
  async exportDevices(deviceIds: number[], format: 'csv' | 'xlsx', lang: string, timeZone: string): Promise<{ blob: Blob; filename: string }> {
    const res = await apiClient.post('/legacy-agent/devices/export', { deviceIds, format, lang, timeZone }, { responseType: 'blob' });
    const match = /filename="([^"]+)"/.exec(String(res.headers['content-disposition'] ?? ''));
    return { blob: res.data as Blob, filename: match ? match[1] : `obligarth-android-agents.${format}` };
  },
  /** origin (lot BANC): the console's tokens by default; bench, the single-use tokens of the bench stations; all. */
  async tokens(origin: 'console' | 'bench' | 'all' = 'console'): Promise<LegacyAgentTokenView[]> {
    const res = await apiClient.get<ApiResponse<LegacyAgentTokenView[]>>('/legacy-agent/tokens', { params: { origin } });
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

  // ── Agent policies (lot PONT-POL §9.2) ──
  files: {
    async list(): Promise<LegacyAgentFileView[]> {
      const res = await apiClient.get<ApiResponse<LegacyAgentFileView[]>>('/legacy-agent/files');
      return res.data.data ?? [];
    },
    /** A raw upload; the server computes the SHA-256, the size and the kind (image, certificate, file). */
    async upload(file: File, name?: string, note?: string): Promise<LegacyAgentFileView> {
      const res = await apiClient.post<ApiResponse<LegacyAgentFileView>>('/legacy-agent/files', file, {
        params: { name: (name ?? file.name).slice(0, 200), ...(note ? { note } : {}) },
        headers: { 'Content-Type': storeMediaType(file) }, timeout: 15 * 60_000,
      });
      return res.data.data!;
    },
    async patch(id: string, body: { name?: string; note?: string | null }): Promise<LegacyAgentFileView> {
      const res = await apiClient.patch<ApiResponse<LegacyAgentFileView>>(`/legacy-agent/files/${id}`, body);
      return res.data.data!;
    },
    async remove(id: string): Promise<void> {
      await apiClient.delete(`/legacy-agent/files/${id}`);
    },
    /** The content of a stored file (images, and files of 64 KiB at most), as a blob: never put in the DOM as HTML. */
    async content(id: string): Promise<Blob> {
      const res = await apiClient.get(`/legacy-agent/files/${id}/content`, { responseType: 'blob' });
      return res.data as Blob;
    },
  },
  async renderPreview(template: string, encoding: 'text' | 'json', deviceId: number): Promise<{ text: string; missing: string[]; jsonValid: boolean | null }> {
    const res = await apiClient.post<ApiResponse<{ text: string; missing: string[]; jsonValid: boolean | null }>>('/legacy-agent/policy/render-preview', { template, encoding, deviceId });
    return res.data.data!;
  },
  async customKeys(): Promise<string[]> {
    const res = await apiClient.get<ApiResponse<string[]>>('/legacy-agent/policy/custom-keys');
    return res.data.data ?? [];
  },
  async devicePolicy(deviceId: number): Promise<LegacyAgentPolicyStatusView> {
    const res = await apiClient.get<ApiResponse<LegacyAgentPolicyStatusView>>(`/legacy-agent/devices/${deviceId}/policy`);
    return res.data.data!;
  },
  /** Per-device values: a preview, or with `apply` the import (a request for approval beyond the thresholds). */
  async importDeviceValues(rows: LegacyAgentDeviceValuesImportRow[], match: DeviceValuesMatch, apply: boolean): Promise<LegacyAgentDeviceValuesImportResult | DeviceValuesPending> {
    const res = await apiClient.post<ApiResponse<LegacyAgentDeviceValuesImportResult | DeviceValuesPending>>('/legacy-agent/device-values', { rows, match, apply });
    return (res.data.data ?? (res.data as unknown as DeviceValuesPending))!;
  },
  async importImages(names: Array<{ name: string; sha256: string }>): Promise<{ marked: number }> {
    const res = await apiClient.post<ApiResponse<{ marked: number }>>('/legacy-agent/policy/import-images', { names });
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
    async saveSettings(body: { pollSeconds?: number; minVersionCode?: number; inventorySeconds?: number; autoUpdate?: boolean; autoUpdatePerHour?: number }): Promise<LegacyAgentInstanceSettings> {
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
