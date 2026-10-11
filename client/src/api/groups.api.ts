import apiClient from './client';
import type { DeviceGroup, DeviceGroupTreeNode } from '@obligarth/shared';

interface ApiResponse<T> { data?: T; error?: string; }

interface CreateGroupRequest {
  name: string;
  parentId?: number | null;
  description?: string | null;
  sortOrder?: number;
}

interface UpdateGroupRequest {
  name?: string;
  parentId?: number | null;
  description?: string | null;
  sortOrder?: number;
  groupNotifications?: boolean;
  alwaysOn?: boolean;
  groupConfig?: DeviceGroup['groupConfig'];
}

export const groupsApi = {
  async list(): Promise<DeviceGroup[]> {
    const res = await apiClient.get<ApiResponse<DeviceGroup[]>>('/groups');
    return res.data.data!;
  },

  async tree(): Promise<DeviceGroupTreeNode[]> {
    const res = await apiClient.get<ApiResponse<DeviceGroupTreeNode[]>>('/groups/tree');
    return res.data.data!;
  },

  async getById(id: number): Promise<DeviceGroup> {
    const res = await apiClient.get<ApiResponse<DeviceGroup>>(`/groups/${id}`);
    return res.data.data!;
  },

  async create(data: CreateGroupRequest): Promise<DeviceGroup> {
    const res = await apiClient.post<ApiResponse<DeviceGroup>>('/groups', data);
    return res.data.data!;
  },

  async update(id: number, data: UpdateGroupRequest): Promise<DeviceGroup> {
    const res = await apiClient.put<ApiResponse<DeviceGroup>>(`/groups/${id}`, data);
    return res.data.data!;
  },

  /**
   * Moves a group in the tree. A move that changes what the devices of the group inherit (policies) may need a
   * second factor (asked by the client's interceptor) or a second approver: `null` then (202), the move waits for
   * its approval and nothing has changed yet.
   */
  async move(id: number, newParentId: number | null): Promise<DeviceGroup | null> {
    const res = await apiClient.post<ApiResponse<DeviceGroup>>(`/groups/${id}/move`, { newParentId });
    return res.status === 202 ? null : res.data.data!;
  },

  /** Deletes a group; `false` when the deletion waits for a second approver (202): nothing is deleted yet. */
  async delete(id: number): Promise<boolean> {
    const res = await apiClient.delete(`/groups/${id}`);
    return res.status !== 202;
  },

  async reorder(items: { id: number; sortOrder: number }[]): Promise<void> {
    await apiClient.post('/groups/reorder', { items });
  },
};
