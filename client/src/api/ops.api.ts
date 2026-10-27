import apiClient from './client';
import type { OpsStatusDto } from '@obligarth/shared';

// The operations of the instance (platform administrators, master tenant): readiness in detail, stage and
// prerequisites of a pilot, backups, restore drill, profile signing identity. Read only: codes, dates and counts,
// never a tenant nor a secret.

interface ApiResponse<T> { success?: boolean; data?: T; error?: string; code?: string }

export const opsApi = {
  async status(): Promise<OpsStatusDto> {
    const res = await apiClient.get<ApiResponse<OpsStatusDto>>('/admin/ops/status');
    return res.data.data!;
  },
};
