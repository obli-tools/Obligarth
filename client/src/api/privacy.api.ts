import apiClient from './client';
import type {
  NoticeAcknowledgementCountDto, NoticeLocale, NoticePlatform, NoticePreviewDto, NoticeSettingsDto, NoticeSettingsUpdate, NoticesDto,
  Ownership, PrivacyImpactDto, PrivacyProfileRules, PrivacyProfilesDto, RetentionCategory, RetentionPolicyDto,
} from '@obligarth/shared';

// =============================================================================
// Console API of the privacy of a tenant (/api/privacy, P0-13 T3 to T6; page /privacy, T7):
//   - the privacy profiles per ownership (CNF-02): read, the impact of proposed rules, a change filed as an approval
//     request (always: D3);
//   - the retention of the tenant (CNF-04): read, a change filed as an approval request (a decrease waiting for its
//     date is cancelled by such a request asking the value in force: there is no other way, D4);
//   - the notice of the employees (USR-01): its settings (changed with the capability alone, D3), its versions, a
//     preview, the acknowledgements of a version.
// Reading: settings, audit.read or mdm.privacy.manage; writing: mdm.privacy.manage (the server checks both).
// =============================================================================

interface ApiResponse<T> { data?: T }

/** The answer of a change filed for approval (202). */
export interface PrivacyRequestFiled {
  approvalId: number;
  status: 'pending_approval';
  /** Who examines it: a client approver of the tenant, or another platform administrator. */
  reviewerSide: 'client' | 'platform';
}

export const privacyApi = {
  // ── Profiles ─────────────────────────────────────────────────────────────────
  async profiles(): Promise<PrivacyProfilesDto> {
    const res = await apiClient.get<ApiResponse<PrivacyProfilesDto>>('/privacy/profiles');
    return res.data.data!;
  },
  /** The impact of `rules` on `ownership` (every key given: the server takes the query keys as the proposed rules). */
  async impact(ownership: Ownership, rules: PrivacyProfileRules): Promise<PrivacyImpactDto> {
    const params = Object.fromEntries(Object.entries(rules).map(([k, v]) => [k, String(v)]));
    const res = await apiClient.get<ApiResponse<PrivacyImpactDto>>(`/privacy/profiles/${ownership}/impact`, { params });
    return res.data.data!;
  },
  async requestProfile(ownership: Ownership, rules: PrivacyProfileRules, justification: string): Promise<PrivacyRequestFiled> {
    const res = await apiClient.post<ApiResponse<PrivacyRequestFiled>>(`/privacy/profiles/${ownership}`, { rules, justification });
    return res.data.data!;
  },

  // ── Retention ────────────────────────────────────────────────────────────────
  async retention(): Promise<RetentionPolicyDto> {
    const res = await apiClient.get<ApiResponse<RetentionPolicyDto>>('/privacy/retention');
    return res.data.data!;
  },
  /** The categories that change (a value equal to the one in force cancels the decrease waiting for that category). */
  async requestRetention(values: Partial<Record<RetentionCategory, number>>, justification: string): Promise<PrivacyRequestFiled> {
    const res = await apiClient.put<ApiResponse<PrivacyRequestFiled>>('/privacy/retention', { values, justification });
    return res.data.data!;
  },

  // ── Notice ───────────────────────────────────────────────────────────────────
  async noticeSettings(): Promise<NoticeSettingsDto> {
    const res = await apiClient.get<ApiResponse<NoticeSettingsDto>>('/privacy/notice-settings');
    return res.data.data!;
  },
  async updateNoticeSettings(body: NoticeSettingsUpdate): Promise<NoticeSettingsDto> {
    const res = await apiClient.put<ApiResponse<NoticeSettingsDto>>('/privacy/notice-settings', body);
    return res.data.data!;
  },
  async notices(filter: { platform?: NoticePlatform; ownership?: Ownership; locale?: NoticeLocale } = {}): Promise<NoticesDto> {
    const res = await apiClient.get<ApiResponse<NoticesDto>>('/privacy/notices', { params: filter });
    return res.data.data!;
  },
  async noticePreview(platform: NoticePlatform, ownership: Ownership, locale: NoticeLocale): Promise<NoticePreviewDto> {
    const res = await apiClient.get<ApiResponse<NoticePreviewDto>>('/privacy/notices/preview', { params: { platform, ownership, locale } });
    return res.data.data!;
  },
  async acknowledgements(versionId: string): Promise<NoticeAcknowledgementCountDto> {
    const res = await apiClient.get<ApiResponse<NoticeAcknowledgementCountDto>>(`/privacy/notices/${versionId}/acknowledgements/count`);
    return res.data.data!;
  },
};
