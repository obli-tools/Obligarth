import apiClient from './client';
import type { ObliwatchConsentBody, ObliwatchConsentView, ObliwatchPushRetryResponse } from '@obligarth/shared';

// =============================================================================
// Console API of the Obliwatch consent of the current tenant (/api/integrations/obliwatch/consent): read with the
// capability 'settings'; a change asks a fresh second factor (restriction obliwatch.settings_change, handled by the
// client's interceptor). Both answer 404 while the integration is off on the instance (OBLIWATCH_INTEGRATION).
// =============================================================================

interface ApiResponse<T> { data?: T }

export const obliwatchApi = {
  async consent(): Promise<ObliwatchConsentView> {
    const r = await apiClient.get<ApiResponse<ObliwatchConsentView>>('/integrations/obliwatch/consent');
    return r.data.data as ObliwatchConsentView;
  },
  async setConsent(body: ObliwatchConsentBody): Promise<ObliwatchConsentView> {
    const r = await apiClient.put<ApiResponse<ObliwatchConsentView>>('/integrations/obliwatch/consent', body);
    return r.data.data as ObliwatchConsentView;
  },
  /** The dead letters of the push sent again (lot L3). */
  async retryDead(): Promise<ObliwatchPushRetryResponse> {
    const r = await apiClient.post<ApiResponse<ObliwatchPushRetryResponse>>('/integrations/obliwatch/push/retry-dead', {});
    return r.data.data as ObliwatchPushRetryResponse;
  },
};
