import apiClient from './client';
import type {
  AuditActorSide, AuditChainStatus, AuditCriticality, AuditDestinationDto, AuditEntryDetailDto, AuditEntryDto, AuditOutcome,
  AuditRetentionRow, AuditSealDto, AuditSealKeyDto, AuditSealingStatus, AuditSpoolStatus, AuditVerificationDto,
} from '@obligarth/shared';

interface ApiResponse<T> { data?: T; error?: string; }

/** An entry of the hardened journal (the legacy fields userId, username and
 *  createdAt are kept for the existing screens). */
export type AuditLogRow = AuditEntryDto;

export interface AuditLogFilters {
  action?: string;        // exact match, or prefix if ends with "."
  userId?: number;
  deviceId?: number;
  resourceType?: string;
  actorSide?: AuditActorSide;
  outcome?: AuditOutcome;
  criticality?: AuditCriticality;
  search?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
  beforeSeq?: number;
  /** Global view only (platform administrators on the master tenant):
   *  one tenant. Ignored by the server elsewhere. */
  filterTenantId?: number;
}

function params(filters: object): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(filters)) if (v !== undefined && v !== null && v !== '') out[k] = v as string | number;
  return out;
}

export const auditApi = {
  async list(filters: AuditLogFilters = {}): Promise<{ items: AuditLogRow[]; total: number; nextBeforeSeq: number | null }> {
    const res = await apiClient.get<ApiResponse<{ items: AuditLogRow[]; total: number; nextBeforeSeq: number | null }>>('/audit-log', { params: params(filters) });
    return res.data.data ?? { items: [], total: 0, nextBeforeSeq: null };
  },
  async distinctActions(filterTenantId?: number): Promise<string[]> {
    const res = await apiClient.get<ApiResponse<string[]>>('/audit-log/distinct-actions', { params: params({ filterTenantId }) });
    return res.data.data ?? [];
  },
  async entry(uuid: string, filterTenantId?: number): Promise<AuditEntryDetailDto> {
    const res = await apiClient.get<ApiResponse<AuditEntryDetailDto>>(`/audit-log/entries/${uuid}`, { params: params({ filterTenantId }) });
    return res.data.data as AuditEntryDetailDto;
  },
  async status(filterTenantId?: number): Promise<AuditChainStatus> {
    const res = await apiClient.get<ApiResponse<AuditChainStatus>>('/audit-log/status', { params: params({ filterTenantId }) });
    return res.data.data as AuditChainStatus;
  },
  async seals(filterTenantId?: number, fromSeq?: number, toSeq?: number): Promise<AuditSealDto[]> {
    const res = await apiClient.get<ApiResponse<AuditSealDto[]>>('/audit-log/seals', { params: params({ filterTenantId, fromSeq, toSeq }) });
    return res.data.data ?? [];
  },
  async sealKeys(): Promise<AuditSealKeyDto[]> {
    const res = await apiClient.get<ApiResponse<AuditSealKeyDto[]>>('/audit-log/seal-keys');
    return res.data.data ?? [];
  },
  async verify(filterTenantId?: number): Promise<{ verificationId: number }> {
    const res = await apiClient.post<ApiResponse<{ verificationId: number }>>('/audit-log/verify', params({ filterTenantId }));
    return res.data.data as { verificationId: number };
  },
  async verifications(filterTenantId?: number, limit = 20): Promise<AuditVerificationDto[]> {
    const res = await apiClient.get<ApiResponse<AuditVerificationDto[]>>('/audit-log/verifications', { params: params({ filterTenantId, limit }) });
    return res.data.data ?? [];
  },
  /** The export file (JSONL verifiable, or CSV), downloaded as a blob. A
   *  step-up may be asked (401 with the usual envelope). */
  async export(format: 'jsonl' | 'csv', filterTenantId?: number): Promise<{ blob: Blob; filename: string }> {
    // POST: the step-up proof (sensitive floor, no trusted IP) travels in the body.
    const res = await apiClient.post<Blob>('/audit-log/export', params({ format, filterTenantId }), { responseType: 'blob' });
    const disposition = String(res.headers['content-disposition'] ?? '');
    const m = /filename="([^"]+)"/.exec(disposition);
    return { blob: res.data, filename: m ? m[1] : `audit-log.${format}` };
  },
};

/** Administration of the journal (platform administrators, master tenant). */
export const auditAdminApi = {
  async retention(): Promise<AuditRetentionRow[]> {
    const res = await apiClient.get<ApiResponse<AuditRetentionRow[]>>('/admin/audit/retention');
    return res.data.data ?? [];
  },
  /** Always an approval request (202 { approvalId }). */
  async setRetention(tenantId: number, months: number, justification: string | null): Promise<{ approvalId?: number; status?: string }> {
    const res = await apiClient.put<ApiResponse<{ approvalId?: number; status?: string }>>(`/admin/audit/retention/${tenantId}`, { months, justification });
    return res.data.data ?? {};
  },
  async setLegalHold(tenantId: number, until: string | null, reason: string | null): Promise<{ approvalId?: number; status?: string }> {
    const res = await apiClient.put<ApiResponse<{ approvalId?: number; status?: string }>>(`/admin/audit/legal-hold/${tenantId}`, { until, reason });
    return res.data.data ?? {};
  },
  async destinations(): Promise<AuditDestinationDto[]> {
    const res = await apiClient.get<ApiResponse<AuditDestinationDto[]>>('/admin/audit/destinations');
    return res.data.data ?? [];
  },
  async createDestination(body: Record<string, unknown>): Promise<{ destination: AuditDestinationDto; hmacSecret?: string }> {
    const res = await apiClient.post<{ data: AuditDestinationDto; secret?: { hmacSecret: string } }>('/admin/audit/destinations', body);
    return { destination: res.data.data, hmacSecret: res.data.secret?.hmacSecret };
  },
  async updateDestination(id: number, body: Record<string, unknown>): Promise<AuditDestinationDto | { approvalId: number }> {
    const res = await apiClient.patch<ApiResponse<AuditDestinationDto | { approvalId: number }>>(`/admin/audit/destinations/${id}`, body);
    return res.data.data as AuditDestinationDto | { approvalId: number };
  },
  async deleteDestination(id: number): Promise<{ approvalId?: number }> {
    const res = await apiClient.delete<ApiResponse<{ approvalId?: number }>>(`/admin/audit/destinations/${id}`);
    return res.data.data ?? {};
  },
  async testDestination(id: number): Promise<{ delivered: boolean; code?: string }> {
    const res = await apiClient.post<ApiResponse<{ delivered: boolean; code?: string }>>(`/admin/audit/destinations/${id}/test`, {});
    return res.data.data ?? { delivered: false };
  },
  async rotateDestinationSecret(id: number): Promise<{ hmacSecret: string }> {
    const res = await apiClient.post<ApiResponse<{ hmacSecret: string }>>(`/admin/audit/destinations/${id}/rotate-secret`, {});
    return res.data.data as { hmacSecret: string };
  },
  async sealKeys(): Promise<AuditSealKeyDto[]> {
    const res = await apiClient.get<ApiResponse<AuditSealKeyDto[]>>('/admin/audit/seal-keys');
    return res.data.data ?? [];
  },
  async rotateSealKey(): Promise<{ approvalId?: number }> {
    const res = await apiClient.post<ApiResponse<{ approvalId?: number }>>('/admin/audit/seal-keys/rotate', {});
    return res.data.data ?? {};
  },
  async sealNow(): Promise<{ queued: boolean; seq?: number }> {
    const res = await apiClient.post<ApiResponse<{ queued: boolean; seq?: number }>>('/admin/audit/seal-now', {});
    return res.data.data ?? { queued: false };
  },
  async sealing(): Promise<AuditSealingStatus> {
    const res = await apiClient.get<ApiResponse<AuditSealingStatus>>('/admin/audit/sealing');
    return res.data.data as AuditSealingStatus;
  },
  async spool(): Promise<AuditSpoolStatus> {
    const res = await apiClient.get<ApiResponse<AuditSpoolStatus>>('/admin/audit/spool');
    return res.data.data as AuditSpoolStatus;
  },
};
