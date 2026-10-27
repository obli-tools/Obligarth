import apiClient from './client';
import type { DeviceView, DeviceViewCreate, DeviceViewPatch } from '@obligarth/shared';

// =============================================================================
// Saved views of the device list (/api/mdm/device-views, P0-5 §4.1, D6): the caller's views and the shared ones of the
// tenant, the default view of the caller. A view the caller does not see answers 404; a shared view they may not
// change, 403 deviceViewReadOnly.
// =============================================================================

interface ApiResponse<T> { data?: T; error?: string; code?: string }

export const deviceViewsApi = {
  async list(): Promise<DeviceView[]> {
    const res = await apiClient.get<ApiResponse<DeviceView[]>>('/mdm/device-views');
    return res.data.data ?? [];
  },
  /** One view, by id or uuid. */
  async get(ref: number | string): Promise<DeviceView> {
    const res = await apiClient.get<ApiResponse<DeviceView>>(`/mdm/device-views/${encodeURIComponent(String(ref))}`);
    return res.data.data!;
  },
  async create(body: DeviceViewCreate): Promise<DeviceView> {
    const res = await apiClient.post<ApiResponse<DeviceView>>('/mdm/device-views', body);
    return res.data.data!;
  },
  async update(id: number, patch: DeviceViewPatch): Promise<DeviceView> {
    const res = await apiClient.patch<ApiResponse<DeviceView>>(`/mdm/device-views/${id}`, patch);
    return res.data.data!;
  },
  async remove(id: number): Promise<void> {
    await apiClient.delete(`/mdm/device-views/${id}`);
  },
  /** The caller's default view (null: none). */
  async setDefault(viewId: number | null): Promise<{ viewId: number | null; viewUuid: string | null }> {
    const res = await apiClient.put<ApiResponse<{ viewId: number | null; viewUuid: string | null }>>('/mdm/device-views/default', { viewId });
    return res.data.data ?? { viewId: null, viewUuid: null };
  },
};
