import apiClient from './client';
import type {
  AccessKeyCreateBody, AccessKeyCreated, AccessKeyOptions, AccessKeyView, McpAuthorizationDetail, McpAuthorizationView,
  McpBlockView, McpSettingsView, McpTenantIpPolicy, TenantOversightKeyView,
} from '@obligarth/shared';

// Personal access keys of the MCP server (AI agents acting as the user) and the authorizations their sensitive
// actions wait for (docs: specs mcp-server §6). The step-up (second factor) is asked by the client's interceptor:
// callers skip their own error toast when isStepUpHandled(err).

interface ApiResponse<T> { data?: T; error?: string; }

/** A key of any user, as a platform administrator sees it (GET /admin/mcp/keys). */
export type AdminAccessKeyView = AccessKeyView & { owner: { userId: number; username: string } };

/** The approval of an authorization: a move of devices echoes the preview the human saw. */
export interface ApproveBody { devicesToken?: string | null; impactDigest?: string }

export const accessKeysApi = {
  /** The session user's own keys, every tenant (never a secret nor a hash). */
  async list(): Promise<AccessKeyView[]> {
    const res = await apiClient.get<ApiResponse<AccessKeyView[]>>('/access-keys');
    return res.data.data ?? [];
  },

  /** What the user may put in a key: his tenants holding mcp.access_keys, the scopes offerable in each, IP rules. */
  async options(): Promise<AccessKeyOptions> {
    const res = await apiClient.get<ApiResponse<AccessKeyOptions>>('/access-keys/options');
    return res.data.data!;
  },

  /** A new key; the token comes back ONCE (the creation asks a fresh second factor). */
  async create(body: AccessKeyCreateBody): Promise<AccessKeyCreated> {
    const res = await apiClient.post<ApiResponse<AccessKeyCreated>>('/access-keys', body);
    return res.data.data!;
  },

  /** Revokes one of the user's keys (it is kept, never deleted). */
  async revoke(publicId: string): Promise<boolean> {
    const res = await apiClient.delete<ApiResponse<{ revoked: boolean }>>(`/access-keys/${encodeURIComponent(publicId)}`);
    return !!res.data.data?.revoked;
  },

  // ── Oversight of the keys reaching the current tenant (users.manage) ──────

  tenantOversight: {
    async list(): Promise<TenantOversightKeyView[]> {
      const res = await apiClient.get<ApiResponse<TenantOversightKeyView[]>>('/access-keys/tenant-oversight');
      return res.data.data ?? [];
    },
    /** The current tenant is taken out of that key; the key keeps working in its other tenants. */
    async exclude(publicId: string): Promise<void> {
      await apiClient.post(`/access-keys/tenant-oversight/${encodeURIComponent(publicId)}/exclude`);
    },
  },

  // ── Authorizations of the user's keys ─────────────────────────────────────

  authorizations: {
    /** The user's own authorizations, every tenant. */
    async list(state: 'pending' | 'filed' | 'all' = 'pending'): Promise<McpAuthorizationView[]> {
      const res = await apiClient.get<ApiResponse<McpAuthorizationView[]>>('/mcp-authorizations', { params: { state } });
      return res.data.data ?? [];
    },
    /** One of them, in the session's tenant (with the preview of a move). */
    async get(id: string): Promise<McpAuthorizationDetail> {
      const res = await apiClient.get<ApiResponse<McpAuthorizationDetail>>(`/mcp-authorizations/${encodeURIComponent(id)}`);
      return res.data.data!;
    },
    /** Approves with a fresh second factor (asked by the interceptor): the action runs once, as the user. */
    async approve(id: string, body: ApproveBody = {}): Promise<McpAuthorizationView> {
      const res = await apiClient.post<ApiResponse<McpAuthorizationView>>(`/mcp-authorizations/${encodeURIComponent(id)}/approve`, body);
      return res.data.data!;
    },
    async deny(id: string): Promise<McpAuthorizationView> {
      const res = await apiClient.post<ApiResponse<McpAuthorizationView>>(`/mcp-authorizations/${encodeURIComponent(id)}/deny`);
      return res.data.data!;
    },
  },

  // ── Platform administration (master tenant) ───────────────────────────────

  admin: {
    async settings(): Promise<McpSettingsView> {
      const res = await apiClient.get<ApiResponse<McpSettingsView>>('/admin/mcp/settings');
      return res.data.data!;
    },
    async saveSettings(body: Omit<McpSettingsView, 'mode' | 'activeKeys' | 'openKeys'>): Promise<McpSettingsView | null> {
      const res = await apiClient.put<ApiResponse<McpSettingsView>>('/admin/mcp/settings', body);
      return res.status === 202 ? null : res.data.data!;
    },
    async tenantPolicy(tenantId: number): Promise<McpTenantIpPolicy> {
      const res = await apiClient.get<ApiResponse<{ tenantId: number; forceIpAllowList: McpTenantIpPolicy }>>(`/admin/mcp/tenant-policies/${tenantId}`);
      return res.data.data?.forceIpAllowList ?? 'inherit';
    },
    async setTenantPolicy(tenantId: number, forceIpAllowList: McpTenantIpPolicy): Promise<boolean> {
      const res = await apiClient.put(`/admin/mcp/tenant-policies/${tenantId}`, { forceIpAllowList });
      return res.status !== 202;
    },
    async blocks(activeOnly = true): Promise<McpBlockView[]> {
      const res = await apiClient.get<ApiResponse<McpBlockView[]>>('/admin/mcp/blocks', { params: { active: activeOnly ? '1' : '0' } });
      return res.data.data ?? [];
    },
    async unblock(id: number): Promise<boolean> {
      const res = await apiClient.post(`/admin/mcp/blocks/${id}/unblock`);
      return res.status !== 202;
    },
    async keys(userId?: number): Promise<AdminAccessKeyView[]> {
      const res = await apiClient.get<ApiResponse<AdminAccessKeyView[]>>('/admin/mcp/keys', { params: userId ? { userId } : {} });
      return res.data.data ?? [];
    },
    async revokeKey(publicId: string): Promise<boolean> {
      const res = await apiClient.delete<ApiResponse<{ revoked: boolean }>>(`/admin/mcp/keys/${encodeURIComponent(publicId)}`);
      return !!res.data.data?.revoked;
    },
    /** Reaches Obliguard with a fresh delegation token: { ok } or { ok: false, error }. */
    async obliguardTest(): Promise<{ ok: boolean; error?: string }> {
      const res = await apiClient.post<ApiResponse<{ ok: boolean; error?: string }>>('/admin/mcp/obliguard/test');
      return res.data.data ?? { ok: false };
    },
  },
};
