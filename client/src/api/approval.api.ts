import apiClient from './client';

interface ApiResponse<T> { data?: T; error?: string; }

export interface PendingApproval {
  id: number;
  tenantId: number;
  requestedBy: number;
  requestedByName: string | null;
  requestType: 'batch_command' | 'device_uninstall' | 'setting_change' | 'vault_kek_rotation'
    | 'guarded_action' | 'guard_resume' | 'guard_unfreeze' | 'guard_settings_change' | 'guard_approver_designate'
    // A restricted MDM command (integration-apple-edge §8.11); a publication, a batch of assignments, a group moved
    // or deleted (modele-donnees-mdm §7.12).
    | 'apple_action' | 'mdm_policy_publish'
    // A change of a privacy profile or of the retention of the tenant (P0-13 T3, T4).
    | 'privacy_profile_change' | 'privacy_retention_change';
  description: string;
  payload: Record<string, any>;
  status: 'pending' | 'approved' | 'denied' | 'executed' | 'expired' | 'cancelled';
  reviewedBy: number | null;
  reviewedByName: string | null;
  reviewedAt: string | null;
  reviewReason: string | null;
  createdAt: string;
  expiresAt: string;
  executedAt: string | null;
  /** Approved but not executed (status 'approved'), or executed only in
   *  part (status 'executed'): why (server text). Absent on older servers. */
  executionError?: string | null;
}

export const approvalApi = {
  async list(includeResolved = false): Promise<PendingApproval[]> {
    const res = await apiClient.get<ApiResponse<PendingApproval[]>>('/approvals', {
      params: { includeResolved },
    });
    return res.data.data ?? [];
  },
  async approve(id: number, reason?: string): Promise<PendingApproval> {
    const res = await apiClient.post<ApiResponse<PendingApproval>>(`/approvals/${id}/approve`, { reason });
    return res.data.data!;
  },
  async deny(id: number, reason?: string): Promise<PendingApproval> {
    const res = await apiClient.post<ApiResponse<PendingApproval>>(`/approvals/${id}/deny`, { reason });
    return res.data.data!;
  },
  async cancel(id: number): Promise<PendingApproval> {
    const res = await apiClient.post<ApiResponse<PendingApproval>>(`/approvals/${id}/cancel`);
    return res.data.data!;
  },
};
