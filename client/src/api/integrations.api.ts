import apiClient from './client';
import type {
  AdeServerView, DeadlineView, IntegrationsSummary, ManualDeadlineKind, PushOverview, PushRequestView, ReadinessItem, VppAssetView,
  VppOperationListItem, VppTokenView,
} from '@obligarth/shared';

// =============================================================================
// Console API of the Apple integrations (/api/apple, integration-apple-edge
// §11.6, lot C3): the five cards, the readiness of the tenant, the push
// certificate and its exchange files, the ADE servers, the deadlines; the
// cross-tenant deadlines of the platform administrators (/api/admin/apple).
// A file is sent as its raw bytes; a downloaded file comes back as a Blob.
// =============================================================================

interface ApiResponse<T> { data?: T }
export interface Download { blob: Blob; filename: string }
export type PendingApproval = { approvalId: number; status: 'pending_approval' };

const RAW = { headers: { 'Content-Type': 'application/octet-stream' } };

function filenameOf(disposition: unknown, fallback: string): string {
  const m = /filename="([^"]+)"/.exec(String(disposition ?? ''));
  return m ? m[1] : fallback;
}

async function download(path: string, fallback: string): Promise<Download> {
  const res = await apiClient.get(path, { responseType: 'blob' });
  return { blob: res.data as Blob, filename: filenameOf(res.headers?.['content-disposition'], fallback) };
}

export const isPendingApproval = (v: unknown): v is PendingApproval =>
  !!v && typeof v === 'object' && (v as { status?: unknown }).status === 'pending_approval';

export const integrationsApi = {
  async summary(): Promise<IntegrationsSummary> {
    const res = await apiClient.get<ApiResponse<IntegrationsSummary>>('/apple/integrations');
    return res.data.data!;
  },
  async readiness(): Promise<ReadinessItem[]> {
    const res = await apiClient.get<ApiResponse<ReadinessItem[]>>('/apple/readiness');
    return res.data.data ?? [];
  },
  async deadlines(retired = false): Promise<DeadlineView[]> {
    const res = await apiClient.get<ApiResponse<DeadlineView[]>>('/apple/deadlines', { params: retired ? { retired: 1 } : {} });
    return res.data.data ?? [];
  },
  // ── Push certificate ─────────────────────────────────────────────────────────
  async push(): Promise<PushOverview> {
    const res = await apiClient.get<ApiResponse<PushOverview>>('/apple/push');
    return res.data.data!;
  },
  async createPushRequest(body: { purpose: 'initial' | 'renewal' | 'topic_change'; appleAccountHint?: string | null }): Promise<PushRequestView> {
    const res = await apiClient.post<ApiResponse<PushRequestView>>('/apple/push/requests', body);
    return res.data.data!;
  },
  vendorFile: (id: string): Promise<Download> => download(`/apple/push/requests/${id}/vendor-file`, `obligarth-push-request-${id}.json`),
  async importVendorSigned(id: string, file: ArrayBuffer): Promise<PushRequestView> {
    const res = await apiClient.post<ApiResponse<PushRequestView>>(`/apple/push/requests/${id}/vendor-signed`, file, RAW);
    return res.data.data!;
  },
  appleFile: (id: string): Promise<Download> => download(`/apple/push/requests/${id}/apple-file`, 'PushCertificateRequest.plist'),
  async importCertificate(id: string, file: ArrayBuffer): Promise<PushRequestView | PendingApproval> {
    const res = await apiClient.post<ApiResponse<PushRequestView | PendingApproval>>(`/apple/push/requests/${id}/certificate`, file, RAW);
    return res.data.data!;
  },
  async abandonPushRequest(id: string): Promise<PushRequestView> {
    const res = await apiClient.post<ApiResponse<PushRequestView>>(`/apple/push/requests/${id}/abandon`);
    return res.data.data!;
  },
  async importPushWithKey(certPem: string, keyPem: string): Promise<PushRequestView | null> {
    const res = await apiClient.post<ApiResponse<PushRequestView | null>>('/apple/push/import', { certPem, keyPem });
    return res.data.data ?? null;
  },
  // ── ADE servers ─────────────────────────────────────────────────────────────
  async adeServers(): Promise<AdeServerView[]> {
    const res = await apiClient.get<ApiResponse<AdeServerView[]>>('/apple/ade-tokens');
    return res.data.data ?? [];
  },
  async createAdeServer(body: { label: string; appleAccountHint?: string | null }): Promise<AdeServerView> {
    const res = await apiClient.post<ApiResponse<AdeServerView>>('/apple/ade-tokens', body);
    return res.data.data!;
  },
  adePublicKey: (id: string): Promise<Download> => download(`/apple/ade-tokens/${id}/public-key`, 'obligarth-ade.pem'),
  async uploadAdeToken(id: string, file: ArrayBuffer): Promise<AdeServerView> {
    const res = await apiClient.put<ApiResponse<AdeServerView>>(`/apple/ade-tokens/${id}/token`, file, RAW);
    return res.data.data!;
  },
  async syncAdeServer(id: string): Promise<void> {
    await apiClient.post(`/apple/ade-tokens/${id}/sync`);
  },
  async declareByod(id: string): Promise<AdeServerView> {
    const res = await apiClient.put<ApiResponse<AdeServerView>>(`/apple/ade-tokens/${id}/account-driven-enrollment`);
    return res.data.data!;
  },
  async deleteAdeServer(id: string): Promise<PendingApproval | null> {
    const res = await apiClient.delete<ApiResponse<PendingApproval>>(`/apple/ade-tokens/${id}`);
    return res.data.data ?? null;
  },
  // ── Apps and Books (lot C4) ─────────────────────────────────────────────────
  async vppTokens(): Promise<VppTokenView[]> {
    const res = await apiClient.get<ApiResponse<VppTokenView[]>>('/apple/vpp-tokens');
    return res.data.data ?? [];
  },
  async importVppToken(label: string, file: ArrayBuffer, appleAccountHint?: string | null): Promise<{ view: VppTokenView; outcome: string }> {
    const res = await apiClient.post<ApiResponse<VppTokenView> & { outcome?: string }>('/apple/vpp-tokens', file,
      { ...RAW, params: { label, ...(appleAccountHint ? { appleAccountHint } : {}) } });
    return { view: res.data.data!, outcome: res.data.outcome ?? 'active' };
  },
  async replaceVppToken(id: string, file: ArrayBuffer): Promise<VppTokenView> {
    const res = await apiClient.put<ApiResponse<VppTokenView>>(`/apple/vpp-tokens/${id}/token`, file, RAW);
    return res.data.data!;
  },
  async syncVppToken(id: string): Promise<void> {
    await apiClient.post(`/apple/vpp-tokens/${id}/sync`);
  },
  async takeOverVppToken(id: string): Promise<VppTokenView | PendingApproval> {
    const res = await apiClient.post<ApiResponse<VppTokenView | PendingApproval>>(`/apple/vpp-tokens/${id}/takeover`, { acknowledgeWarning: true });
    return res.data.data!;
  },
  async removeVppToken(id: string): Promise<void> {
    await apiClient.delete(`/apple/vpp-tokens/${id}`);
  },
  async vppAssets(tokenId?: string): Promise<VppAssetView[]> {
    const res = await apiClient.get<ApiResponse<VppAssetView[]>>(tokenId ? `/apple/vpp-tokens/${tokenId}/assets` : '/apple/vpp-assets');
    return res.data.data ?? [];
  },
  async vppOperations(state?: string): Promise<VppOperationListItem[]> {
    const res = await apiClient.get<ApiResponse<VppOperationListItem[]>>('/apple/vpp-operations', { params: state ? { state } : {} });
    return res.data.data ?? [];
  },
  // ── Platform administrators ──────────────────────────────────────────────────
  async allDeadlines(retired = false): Promise<DeadlineView[]> {
    const res = await apiClient.get<ApiResponse<DeadlineView[]>>('/admin/apple/deadlines', { params: retired ? { retired: 1 } : {} });
    return res.data.data ?? [];
  },
  async setManualDeadline(kind: ManualDeadlineKind, body: { notAfter: string | null; label?: string }): Promise<void> {
    await apiClient.put(`/admin/apple/deadlines/${kind}`, body);
  },
};
