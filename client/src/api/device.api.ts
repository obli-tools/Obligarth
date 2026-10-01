import apiClient from './client';
import type { Device, FleetSummary, AgentApiKey } from '@obligarth/shared';

interface ApiResponse<T> { data?: T; error?: string; }

export interface GroupStats {
  groupId: number | null;
  groupName: string | null;
  /** Parent group id — null for root groups and the "ungrouped" pseudo-row. */
  parentId: number | null;
  /** Admin-defined order within siblings. Drives the dashboard hierarchy. */
  sortOrder: number;
  /** Owning tenant. Populated when the caller is on the master tenant
   *  (god view) so the dashboard can bucket groups under their tenant
   *  in the "Vue par groupe" panel — without this, master sees a flat
   *  mix of "Serveurs" / "Postes" / etc. from every tenant which is
   *  unreadable. Null on child tenants (implicit). */
  tenantId: number | null;
  tenantName: string | null;
  online: number;
  offline: number;
  warning: number;
  critical: number;
  total: number;
}

export interface FleetTimeseriesPoint {
  day: string;
  total: number;
  online: number;
  offline: number;
  stale72: number;
}

export interface FleetHourlyPoint {
  /** ISO timestamp of the hour boundary (rounded down to :00). */
  hour: string;
  total: number;
  online: number;
  offline: number;
  stale72: number;
}

export const deviceApi = {
  // Fleet
  async list(params?: { groupId?: number; status?: string; search?: string; approvalStatus?: string }): Promise<Device[]> {
    const res = await apiClient.get<ApiResponse<{ items: Device[]; total: number }>>('/devices', { params });
    const data = res.data.data;
    // Support both paginated response { items, total } and legacy array
    return Array.isArray(data) ? data : (data?.items ?? []);
  },
  async listPaginated(params?: {
    groupId?: number; includeSubgroups?: boolean; status?: string; search?: string;
    approvalStatus?: string; osType?: string; page?: number; pageSize?: number;
    sortBy?: string; sortOrder?: 'asc' | 'desc';
    /** Set true to return only devices whose group_id is NULL. Used by the
     *  "Ungrouped" pseudo-entry in the group sidebar so admins can quickly
     *  bulk-assign a group to stray devices. */
    ungrouped?: boolean;
    /** Filter rows whose last_seen_at is older than this threshold (in hours).
     *  Used by the dashboard "Injoignables 72h" hero card click-through. */
    staleHours?: number;
    /** Lot C 3-tier OS filter: marketing name. Single string OR array
     *  for multi-select (axios serialises arrays as repeated query params,
     *  which the server collapses with whereIn). */
    osName?: string | string[];
    /** Lot C 3-tier OS filter: build / version string. Same single /
     *  array semantics as osName. */
    osVersion?: string | string[];
    /** Restrict to devices carrying ANY of these tags (OR semantics). */
    tags?: string[];
    /** Master-only: narrow the god view to a tenant subset. The DeviceTable
     *  tenant chips wire this so the master admin can focus on one
     *  customer without leaving the cross-tenant view. Server drops
     *  the param when the caller isn't master. */
    tenantIds?: number[];
  }): Promise<{ items: Device[]; total: number; page: number; pageSize: number }> {
    const res = await apiClient.get<ApiResponse<{ items: Device[]; total: number; page: number; pageSize: number }>>('/devices', { params });
    return res.data.data ?? { items: [], total: 0, page: 1, pageSize: 100 };
  },
  /** Distinct tags currently applied to any device in the tenant — drives the
   *  tag-filter chip popover so admins pick from existing tags rather than
   *  having to remember spelling. Counts attached for UI sorting. */
  async listTags(): Promise<Array<{ tag: string; count: number }>> {
    const res = await apiClient.get<ApiResponse<Array<{ tag: string; count: number }>>>('/devices/tags');
    return res.data.data ?? [];
  },
  async export(format: 'csv' | 'xlsx' | 'pdf', params?: {
    groupId?: number; includeSubgroups?: boolean; status?: string; search?: string;
    approvalStatus?: string; osType?: string; sortBy?: string; sortOrder?: 'asc' | 'desc';
    ungrouped?: boolean;
  }): Promise<{ blob: Blob; filename: string }> {
    const res = await apiClient.get('/devices/export', {
      params: { ...params, format },
      responseType: 'blob',
    });
    const cd = res.headers['content-disposition'] || res.headers['Content-Disposition'] || '';
    const match = /filename="([^"]+)"/.exec(cd);
    const filename = match ? match[1] : `obligarth-devices.${format}`;
    return { blob: res.data as Blob, filename };
  },
  async getSummary(): Promise<FleetSummary> {
    const res = await apiClient.get<ApiResponse<FleetSummary>>('/devices/summary');
    return res.data.data!;
  },
  async getGroupStats(): Promise<GroupStats[]> {
    const res = await apiClient.get<ApiResponse<GroupStats[]>>('/devices/group-stats');
    return res.data.data ?? [];
  },
  async getFleetTimeseries(days = 14): Promise<FleetTimeseriesPoint[]> {
    const res = await apiClient.get<ApiResponse<FleetTimeseriesPoint[]>>('/devices/fleet-timeseries', { params: { days } });
    return res.data.data ?? [];
  },
  async getFleetHourly(hours = 24): Promise<FleetHourlyPoint[]> {
    const res = await apiClient.get<ApiResponse<FleetHourlyPoint[]>>('/devices/fleet-hourly', { params: { hours } });
    return res.data.data ?? [];
  },
  async getOsFacets(): Promise<Array<{ osType: string; osName: string | null; osVersion: string | null; count: number }>> {
    const res = await apiClient.get<ApiResponse<Array<{ osType: string; osName: string | null; osVersion: string | null; count: number }>>>('/devices/os-facets');
    return res.data.data ?? [];
  },
  async getById(id: number): Promise<Device> {
    const res = await apiClient.get<ApiResponse<Device>>(`/devices/${id}`);
    return res.data.data!;
  },
  /** Resolve which tenant a device lives in. Used when the user follows a
   *  shared deep-link to a device on another tenant — we offer to switch
   *  rather than just showing "Device not found". Returns null if the
   *  device doesn't exist or the user has no access to it. */
  async locate(deviceId: number): Promise<{
    deviceId: number;
    hostname: string;
    displayName: string | null;
    tenantId: number;
    tenantName: string;
    tenantSlug: string;
    currentTenantId: number | null;
  } | null> {
    try {
      const res = await apiClient.get<ApiResponse<any>>(`/tenants/locate-device/${deviceId}`);
      return res.data.data ?? null;
    } catch {
      return null;
    }
  },
  async update(id: number, data: Partial<Pick<Device, 'displayName' | 'description' | 'groupId' | 'tags' | 'customFields' | 'overrideGroupSettings' | 'notificationTypes' | 'purchaseDate' | 'warrantyExpiry' | 'warrantyVendor' | 'warrantyStatus' | 'expectedLifetimeYears' | 'lifecycleStatus'>>): Promise<Device> {
    const res = await apiClient.patch<ApiResponse<Device>>(`/devices/${id}`, data);
    return res.data.data!;
  },
  async approve(id: number): Promise<Device> {
    const res = await apiClient.post<ApiResponse<Device>>(`/devices/${id}/approve`);
    return res.data.data!;
  },
  async refuse(id: number): Promise<Device> {
    const res = await apiClient.post<ApiResponse<Device>>(`/devices/${id}/refuse`);
    return res.data.data!;
  },
  async delete(id: number): Promise<void> {
    await apiClient.delete(`/devices/${id}`);
  },
  async bulkApprove(deviceIds: number[]): Promise<void> {
    await apiClient.post('/devices/bulk/approve', { deviceIds });
  },
  async bulkDelete(deviceIds: number[]): Promise<void> {
    await apiClient.delete('/devices/bulk/delete', { data: { deviceIds } });
  },
  async suspend(id: number): Promise<Device> {
    const res = await apiClient.post<ApiResponse<Device>>(`/devices/${id}/suspend`);
    return res.data.data!;
  },
  async unsuspend(id: number): Promise<Device> {
    const res = await apiClient.post<ApiResponse<Device>>(`/devices/${id}/unsuspend`);
    return res.data.data!;
  },
  async batchChangeGroup(deviceIds: number[], groupId: number | null): Promise<{ updated: number; changed: number }> {
    const res = await apiClient.post<ApiResponse<{ updated: number; changed: number }>>('/devices/batch/change-group', { deviceIds, groupId });
    return res.data.data ?? { updated: 0, changed: 0 };
  },
  // API Keys
  async listKeys(): Promise<AgentApiKey[]> {
    const res = await apiClient.get<ApiResponse<AgentApiKey[]>>('/agent/keys');
    return res.data.data ?? [];
  },
  async createKey(name: string, defaultGroupId?: number | null): Promise<AgentApiKey> {
    const res = await apiClient.post<ApiResponse<AgentApiKey>>('/agent/keys', { name, defaultGroupId });
    return res.data.data!;
  },
  async updateKey(id: number, data: { name?: string; defaultGroupId?: number | null }): Promise<void> {
    await apiClient.put(`/agent/keys/${id}`, data);
  },
  async deleteKey(id: number): Promise<void> {
    await apiClient.delete(`/agent/keys/${id}`);
  },
};
