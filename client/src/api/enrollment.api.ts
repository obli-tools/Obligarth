import apiClient from './client';
import type {
  EnrollmentInvitationCreated, EnrollmentLinkCreated, EnrollmentProfileInput, EnrollmentProfileView, EnrollmentSessionState,
  EnrollmentSessionView, EnrollmentTokenKind, EnrollmentTokenState, EnrollmentTokenView,
} from '@obligarth/shared';

// =============================================================================
// Console API of the enrollment (/api/apple/enrollment, integration-apple-edge
// §10.9): profiles, links (OTA), invitations (account-driven), sessions. A
// link's token and an invitation's code come back once, at their creation.
// =============================================================================

interface ApiResponse<T> { data?: T; nextCursor?: string | null }

export const enrollmentApi = {
  async profiles(archived = false): Promise<EnrollmentProfileView[]> {
    const res = await apiClient.get<ApiResponse<EnrollmentProfileView[]>>(`/apple/enrollment/profiles`, { params: archived ? { archived: 1 } : {} });
    return res.data.data ?? [];
  },
  async createProfile(body: EnrollmentProfileInput): Promise<EnrollmentProfileView> {
    const res = await apiClient.post<ApiResponse<EnrollmentProfileView>>(`/apple/enrollment/profiles`, body);
    return res.data.data!;
  },
  async updateProfile(id: string, body: EnrollmentProfileInput): Promise<EnrollmentProfileView> {
    const res = await apiClient.put<ApiResponse<EnrollmentProfileView>>(`/apple/enrollment/profiles/${id}`, body);
    return res.data.data!;
  },
  async archiveProfile(id: string): Promise<EnrollmentProfileView> {
    const res = await apiClient.post<ApiResponse<EnrollmentProfileView>>(`/apple/enrollment/profiles/${id}/archive`);
    return res.data.data!;
  },
  async createLink(profileId: string, body: { label?: string | null; maxUses?: number; ttlHours?: number; email?: string }): Promise<EnrollmentLinkCreated> {
    const res = await apiClient.post<ApiResponse<EnrollmentLinkCreated>>(`/apple/enrollment/profiles/${profileId}/links`, body);
    return res.data.data!;
  },
  async createInvitation(profileId: string, body: { managedAppleAccount: string; label?: string | null; ttlHours?: number; email?: string }):
    Promise<EnrollmentInvitationCreated> {
    const res = await apiClient.post<ApiResponse<EnrollmentInvitationCreated>>(`/apple/enrollment/profiles/${profileId}/invitations`, body);
    return res.data.data!;
  },
  async tokens(f: { profileId?: string; kind?: EnrollmentTokenKind; state?: EnrollmentTokenState } = {}): Promise<EnrollmentTokenView[]> {
    const res = await apiClient.get<ApiResponse<EnrollmentTokenView[]>>(`/apple/enrollment/tokens`, { params: f });
    return res.data.data ?? [];
  },
  async revokeToken(id: string): Promise<void> {
    await apiClient.post(`/apple/enrollment/tokens/${id}/revoke`);
  },
  async sessions(f: { state?: EnrollmentSessionState; cursor?: string | null } = {}): Promise<{ items: EnrollmentSessionView[]; nextCursor: string | null }> {
    const res = await apiClient.get<ApiResponse<EnrollmentSessionView[]>>(`/apple/enrollment/sessions`, {
      params: { ...(f.state ? { state: f.state } : {}), ...(f.cursor ? { cursor: f.cursor } : {}) },
    });
    return { items: res.data.data ?? [], nextCursor: res.data.nextCursor ?? null };
  },
};
