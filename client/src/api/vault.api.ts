import apiClient from './client';
import type { VaultOperation, VaultOperationKind, VaultStatus } from '@obligarth/shared';

// The server's vault of secrets (platform administrators, master tenant):
// state, operations, escrow events, key rotations. Never a key nor a secret:
// fingerprints (kek_id), ids and counts.

interface ApiResponse<T> { success?: boolean; data?: T; error?: string; code?: string }

export type EscrowEventKind = 'confirmation' | 'test' | 'old_shares_destroyed';

export const vaultApi = {
  async status(): Promise<VaultStatus> {
    const res = await apiClient.get<ApiResponse<VaultStatus>>('/admin/vault/status');
    return res.data.data!;
  },

  async operations(kind?: VaultOperationKind, limit = 50): Promise<VaultOperation[]> {
    const res = await apiClient.get<ApiResponse<VaultOperation[]>>('/admin/vault/operations', { params: { kind, limit } });
    return res.data.data ?? [];
  },

  /** Strict step-up (a current code). */
  async recordEscrowEvent(body: { kind: EscrowEventKind; kekIds: { server: string; edge?: string | null }; note?: string }): Promise<VaultOperation> {
    const res = await apiClient.post<ApiResponse<VaultOperation>>('/admin/vault/escrow/events', body);
    return res.data.data!;
  },

  /** Files the double validation; the CLI runs the rotation once approved. */
  async requestKekRotation(reason: string): Promise<{ approvalId: number; operationId: string }> {
    const res = await apiClient.post<ApiResponse<{ approvalId: number; operationId: string }>>('/admin/vault/kek-rotations', { reason });
    return res.data.data!;
  },

  /** Strict step-up; tenantId null: the instance key. */
  async requestDekRotation(tenantId: number | null, reason: string): Promise<VaultOperation> {
    const res = await apiClient.post<ApiResponse<VaultOperation>>('/admin/vault/dek-rotations', { tenantId, reason });
    return res.data.data!;
  },
};
