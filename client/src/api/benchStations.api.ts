import apiClient from './client';
import type {
  BenchOwnedStationView, BenchProvisioningView, BenchRolePolicy, BenchSessionView, BenchStationDetail, BenchStationInstallerInfo, BenchStationView,
  BenchTenantStationView, LegacyAgentReleaseView,
} from '@obligarth/shared';

// =============================================================================
// Console API of the bench stations (lot BANC §3.12): the platform's (/api/admin/bench-stations: master tenant,
// platform administrators), the bench sessions a technician opens (/api/bench-sessions, mdm.bench.operate) and the
// tenant's view (/api/bench-provisionings, mdm.bench.manage). A second factor, when the server asks for it, is
// handled by the dialog of the client (TwoFactorGate).
// =============================================================================

interface ApiResponse<T> { success?: boolean; data?: T }
const data = <T,>(r: { data: ApiResponse<T> }): T => r.data.data as T;

export interface BenchServedInfo {
  served: { releaseId: string; versionCode: number; versionName: string; sha256: string; deviceOwnerCapable: boolean; signerAdmitted: boolean } | null;
  releases: LegacyAgentReleaseView[];
}

export interface BenchTargetInput {
  tenantId: number;
  groupId: number;
  rolePolicy?: BenchRolePolicy;
  namePrefix?: string | null;
  /** Lot BANC-T §10: the template of the suggested name ({site.code}, {site.code:N}, {n}, {n:N}); null clears it. */
  nameTemplate?: string | null;
  disableDevOptions?: boolean;
}

export interface BenchTargetPatch {
  rolePolicy?: BenchRolePolicy;
  namePrefix?: string | null;
  nameTemplate?: string | null;
  disableDevOptions?: boolean;
  allowLegacyOwner?: boolean;
  suspended?: boolean;
}

export const benchStationsApi = {
  // ── Platform ──
  async list(): Promise<BenchStationView[]> { return data(await apiClient.get<ApiResponse<BenchStationView[]>>('/admin/bench-stations')); },
  async get(id: string): Promise<BenchStationDetail> { return data(await apiClient.get<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}`)); },
  async rename(id: string, name: string): Promise<BenchStationDetail> {
    return data(await apiClient.patch<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}`, { name }));
  },
  async approve(id: string, verificationCode: string): Promise<BenchStationDetail> {
    return data(await apiClient.post<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}/approve`, { verificationCode }));
  },
  async suspend(id: string): Promise<BenchStationDetail> { return data(await apiClient.post<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}/suspend`, {})); },
  async resume(id: string): Promise<BenchStationDetail> { return data(await apiClient.post<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}/resume`, {})); },
  async revoke(id: string): Promise<BenchStationDetail> { return data(await apiClient.post<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}/revoke`, {})); },
  async addTarget(id: string, t: BenchTargetInput): Promise<BenchStationDetail> {
    return data(await apiClient.post<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}/targets`, t));
  },
  async patchTarget(id: string, tenantId: number, groupId: number, p: BenchTargetPatch): Promise<BenchStationDetail> {
    return data(await apiClient.patch<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}/targets/${tenantId}/${groupId}`, p));
  },
  async removeTarget(id: string, tenantId: number, groupId: number): Promise<BenchStationDetail> {
    return data(await apiClient.delete<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}/targets/${tenantId}/${groupId}`));
  },
  async openSession(id: string, minutes: number): Promise<BenchStationDetail> {
    return data(await apiClient.post<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}/sessions`, { minutes }));
  },
  async closeSession(id: string): Promise<BenchStationDetail> {
    return data(await apiClient.post<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}/sessions/close`, {}));
  },
  async release(): Promise<BenchServedInfo> { return data(await apiClient.get<ApiResponse<BenchServedInfo>>('/admin/bench-stations/release')); },
  async setRelease(releaseId: string | null): Promise<void> { await apiClient.put('/admin/bench-stations/release', { releaseId }); },
  async tenants(): Promise<Array<{ id: number; name: string }>> {
    return data(await apiClient.get<ApiResponse<Array<{ id: number; name: string }>>>('/admin/bench-stations/tenants'));
  },
  async tenantGroups(tenantId: number): Promise<Array<{ id: number; path: string }>> {
    return data(await apiClient.get<ApiResponse<Array<{ id: number; path: string }>>>(`/admin/bench-stations/tenants/${tenantId}/groups`));
  },
  /** Lot BANC-T, Q2: a platform station given to a client (strict second factor; never the other way). */
  async assignOwner(id: string, tenantId: number): Promise<BenchStationDetail> {
    return data(await apiClient.post<ApiResponse<BenchStationDetail>>(`/admin/bench-stations/${id}/owner`, { tenantId }));
  },
  async installer(): Promise<BenchStationInstallerInfo> {
    return data(await apiClient.get<ApiResponse<BenchStationInstallerInfo>>('/admin/bench-stations/installer'));
  },

  // ── Tenant ──
  async history(f: { stationId?: string; state?: string; deviceId?: number; siteId?: string } = {}): Promise<BenchProvisioningView[]> {
    return data(await apiClient.get<ApiResponse<BenchProvisioningView[]>>('/bench-provisionings', { params: f }));
  },
  async tenantStations(): Promise<BenchTenantStationView[]> {
    return data(await apiClient.get<ApiResponse<BenchTenantStationView[]>>('/bench-provisionings/stations'));
  },
  async suspendTarget(stationId: string, groupId: number): Promise<BenchTenantStationView[]> {
    return data(await apiClient.post<ApiResponse<BenchTenantStationView[]>>(`/bench-provisionings/targets/${stationId}/${groupId}/suspend`, {}));
  },
  async removeTenantTarget(stationId: string, groupId: number): Promise<BenchTenantStationView[]> {
    return data(await apiClient.delete<ApiResponse<BenchTenantStationView[]>>(`/bench-provisionings/targets/${stationId}/${groupId}`));
  },
  async openTenantSession(stationId: string, minutes: number): Promise<BenchSessionView> {
    return data(await apiClient.post<ApiResponse<BenchSessionView>>('/bench-sessions', { stationId, minutes }));
  },
  async closeTenantSession(sessionId: string): Promise<void> { await apiClient.post(`/bench-sessions/${sessionId}/close`, {}); },

  // ── The stations the tenant owns (lot BANC-T, /api/bench-stations: mdm.bench.manage, 404 in the master tenant) ──
  /** The claim of a pending station by its name and the code its screen shows (strict second factor, asked by the
   *  client's dialog): 422 claim_mismatch for every refusal, 409 claim_conflict, 429 rate_limited. */
  async claim(name: string, verificationCode: string): Promise<BenchOwnedStationView> {
    return data(await apiClient.post<ApiResponse<BenchOwnedStationView>>('/bench-stations/claim', { name, verificationCode }));
  },
  async owned(): Promise<BenchOwnedStationView[]> { return data(await apiClient.get<ApiResponse<BenchOwnedStationView[]>>('/bench-stations')); },
  async ownedRename(id: string, name: string): Promise<BenchOwnedStationView> {
    return data(await apiClient.patch<ApiResponse<BenchOwnedStationView>>(`/bench-stations/${id}`, { name }));
  },
  async ownedSuspend(id: string): Promise<BenchOwnedStationView> {
    return data(await apiClient.post<ApiResponse<BenchOwnedStationView>>(`/bench-stations/${id}/suspend`, {}));
  },
  async ownedResume(id: string): Promise<BenchOwnedStationView> {
    return data(await apiClient.post<ApiResponse<BenchOwnedStationView>>(`/bench-stations/${id}/resume`, {}));
  },
  async ownedRevoke(id: string): Promise<BenchOwnedStationView> {
    return data(await apiClient.post<ApiResponse<BenchOwnedStationView>>(`/bench-stations/${id}/revoke`, {}));
  },
  async ownedAddTarget(id: string, t: Omit<BenchTargetInput, 'tenantId'>): Promise<BenchOwnedStationView> {
    return data(await apiClient.post<ApiResponse<BenchOwnedStationView>>(`/bench-stations/${id}/targets`, t));
  },
  async ownedPatchTarget(id: string, groupId: number, p: BenchTargetPatch): Promise<BenchOwnedStationView> {
    return data(await apiClient.patch<ApiResponse<BenchOwnedStationView>>(`/bench-stations/${id}/targets/${groupId}`, p));
  },
  async ownedRemoveTarget(id: string, groupId: number): Promise<BenchOwnedStationView> {
    return data(await apiClient.delete<ApiResponse<BenchOwnedStationView>>(`/bench-stations/${id}/targets/${groupId}`));
  },
  async ownedCloseSession(id: string): Promise<BenchOwnedStationView> {
    return data(await apiClient.post<ApiResponse<BenchOwnedStationView>>(`/bench-stations/${id}/sessions/close`, {}));
  },
};
