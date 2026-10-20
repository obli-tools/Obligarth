import apiClient from './client';
import type {
  AndroidByodInvitationCreated, AndroidByodInvitationRequest, AndroidByodInvitationView, AndroidCreatedTokenView, AndroidDeadLetterDetail,
  AndroidDeadLetterView, AndroidDeadline, AndroidDeviceAction, AndroidDeviceView, AndroidEnrollmentProfileRequest, AndroidEnrollmentProfileView,
  AndroidEnrollmentTokenView, AndroidFormCatalogView, AndroidKioskState, AndroidKmeConfiguration, AndroidOffboardingView, AndroidOnboardingView,
  AndroidPendingDeviceView, AndroidPresumedGoneView, AndroidQuotaView, AndroidSigninConfig, AndroidSigninConfigRequest, AndroidZeroTouchIframe,
} from '@obligarth/shared';

// The Android console (android-amapi §12; lots AN-A2 and AN-C2). Tenant side (/api/android): the enterprise card and
// its signup, unlink and offboarding, the enrollment profiles and tokens, the approvals, BYOD invitations, sign-in
// URL, the Android facet and the menu of a device, the catalog of the policy editor. Platform side
// (/api/admin/android, master tenant): identity, health, quota, deposit of the key, orphan enterprises, dead letters of
// the inbox. Never a Google credential: the fingerprint of the key and the name of its account only; a token value is
// in the answer of its creation or of its audited reveal only, never kept by the console.

interface ApiResponse<T> { success?: boolean; data?: T; error?: string; code?: string }

export interface AndroidPlatformHealth {
  mode: 'off' | 'google' | 'fake';
  auth?: 'vault_key' | 'adc';
  projectId?: string | null;
  pinnedProjectId?: string | null;
  identity?: null | {
    configured: boolean;
    fingerprint: string | null;
    account: string | null;
    lastTokenAt: string | null;
    lastError: string | null;
    setAt: string | null;
  };
  subscriptionPermission?: boolean | null;
  breaker?: null | { state: 'closed' | 'open' | 'half_open'; failures: number; openedAt: number | null; backoffUntil: number | null };
  loop: string;
  lastPullAt?: string | null;
  lastAppliedPublishAt?: string | null;
  lagSeconds?: number | null;
  lastTestMessageAt?: string | null;
  limiter?: { tokens: number; capacity: number };
}

/** GET /api/android/enterprise */
export interface AndroidEnterpriseCard {
  id: number;
  state: string;
  enterpriseName: string | null;
  enterpriseType: string | null;
  domainType: string | null;
  adminDomain: string | null;
  displayName: string | null;
  topicSet: boolean;
  testMessageAt: string | null;
  linkedAt: string | null;
}

export interface AndroidSignupRequest {
  domain: string;
  adminEmail?: string;
  displayName: string;
  primaryColor?: number;
  termsAccepted: boolean;
  termsVersion: string;
  onBehalfReason?: string;
}

/** A restricted request filed (unlink, forced end, adoption): a second approver decides. */
export interface AndroidApprovalFiled { approvalId: number; status: string }

const data = <T>(r: { data: ApiResponse<T> }): T => r.data.data as T;

export const androidApi = {
  // ── Enterprise (mdm.integrations.manage) ──
  async enterprise(): Promise<AndroidEnterpriseCard | null> {
    return data(await apiClient.get<ApiResponse<AndroidEnterpriseCard | null>>('/android/enterprise'));
  },
  async startSignup(body: AndroidSignupRequest): Promise<{ signupId: string; url: string }> {
    return data(await apiClient.post<ApiResponse<{ signupId: string; url: string }>>('/android/enterprise/signups', body));
  },
  async onboarding(): Promise<AndroidOnboardingView> {
    return data(await apiClient.get<ApiResponse<AndroidOnboardingView>>('/android/onboarding'));
  },
  async deadlines(): Promise<AndroidDeadline[]> {
    return data(await apiClient.get<ApiResponse<AndroidDeadline[]>>('/android/deadlines'));
  },
  async offboarding(): Promise<AndroidOffboardingView | null> {
    return data(await apiClient.get<ApiResponse<AndroidOffboardingView | null>>('/android/enterprise/offboarding'));
  },
  async unlink(reason: string): Promise<AndroidApprovalFiled> {
    return data(await apiClient.post<ApiResponse<AndroidApprovalFiled>>('/android/enterprise/unlink', { reason }));
  },
  async forceUnlink(reason: string): Promise<AndroidApprovalFiled> {
    return data(await apiClient.post<ApiResponse<AndroidApprovalFiled>>('/android/enterprise/unlink/force', { reason }));
  },
  async confirmExternalUnlink(): Promise<{ result: string }> {
    return data(await apiClient.post<ApiResponse<{ result: string }>>('/android/enterprise/unlink/confirm-external', {}));
  },
  async recheck(): Promise<{ result: string }> {
    return data(await apiClient.post<ApiResponse<{ result: string }>>('/android/enterprise/recheck', {}));
  },
  async reconcile(): Promise<void> {
    await apiClient.post('/android/reconcile', {});
  },
  async presumedGone(): Promise<AndroidPresumedGoneView[]> {
    return data(await apiClient.get<ApiResponse<AndroidPresumedGoneView[]>>('/android/devices/presumed-gone'));
  },
  async signin(): Promise<AndroidSigninConfig> {
    return data(await apiClient.get<ApiResponse<AndroidSigninConfig>>('/android/enterprise/signin'));
  },
  async configureSignin(body: AndroidSigninConfigRequest): Promise<AndroidSigninConfig> {
    return data(await apiClient.put<ApiResponse<AndroidSigninConfig>>('/android/enterprise/signin', body));
  },
  async zeroTouchIframe(tokenId: string): Promise<AndroidZeroTouchIframe> {
    return data(await apiClient.post<ApiResponse<AndroidZeroTouchIframe>>('/android/zero-touch/iframe-token', { tokenId }));
  },

  // ── Enrollment (mdm.enrollment.manage) ──
  async profiles(archived = false): Promise<AndroidEnrollmentProfileView[]> {
    return data(await apiClient.get<ApiResponse<AndroidEnrollmentProfileView[]>>('/android/enrollment-profiles', { params: archived ? { archived: 1 } : {} }));
  },
  async createProfile(body: AndroidEnrollmentProfileRequest): Promise<AndroidEnrollmentProfileView> {
    return data(await apiClient.post<ApiResponse<AndroidEnrollmentProfileView>>('/android/enrollment-profiles', body));
  },
  async updateProfile(id: string, body: AndroidEnrollmentProfileRequest): Promise<AndroidEnrollmentProfileView> {
    return data(await apiClient.put<ApiResponse<AndroidEnrollmentProfileView>>(`/android/enrollment-profiles/${id}`, body));
  },
  async archiveProfile(id: string): Promise<AndroidEnrollmentProfileView & { tokensRevoked: number }> {
    return data(await apiClient.post<ApiResponse<AndroidEnrollmentProfileView & { tokensRevoked: number }>>(`/android/enrollment-profiles/${id}/archive`, {}));
  },
  async tokens(profileId?: string): Promise<AndroidEnrollmentTokenView[]> {
    return data(await apiClient.get<ApiResponse<AndroidEnrollmentTokenView[]>>('/android/enrollment-tokens', { params: profileId ? { profileId } : {} }));
  },
  async createToken(body: { profileId: string; endUserId?: number; expiresInSeconds?: number }): Promise<AndroidCreatedTokenView> {
    return data(await apiClient.post<ApiResponse<AndroidCreatedTokenView>>('/android/enrollment-tokens', body));
  },
  async revealToken(id: string): Promise<AndroidCreatedTokenView> {
    return data(await apiClient.get<ApiResponse<AndroidCreatedTokenView>>(`/android/enrollment-tokens/${id}/payload`));
  },
  async revokeToken(id: string): Promise<{ result: string }> {
    return data(await apiClient.delete<ApiResponse<{ result: string }>>(`/android/enrollment-tokens/${id}`));
  },
  async kme(id: string): Promise<AndroidKmeConfiguration> {
    return data(await apiClient.get<ApiResponse<AndroidKmeConfiguration>>(`/android/enrollment-tokens/${id}/kme`));
  },
  async pendingApprovals(): Promise<AndroidPendingDeviceView[]> {
    return data(await apiClient.get<ApiResponse<AndroidPendingDeviceView[]>>('/android/devices/pending-approval'));
  },
  async approveDevice(deviceId: number): Promise<{ result: string }> {
    return data(await apiClient.post<ApiResponse<{ result: string }>>(`/android/devices/${deviceId}/approve`, {}));
  },
  async refuseDevice(deviceId: number): Promise<{ result: string }> {
    return data(await apiClient.post<ApiResponse<{ result: string }>>(`/android/devices/${deviceId}/refuse`, {}));
  },
  async byodInvitations(): Promise<AndroidByodInvitationView[]> {
    return data(await apiClient.get<ApiResponse<AndroidByodInvitationView[]>>('/android/byod/invitations'));
  },
  async createByodInvitation(body: AndroidByodInvitationRequest): Promise<AndroidByodInvitationCreated> {
    return data(await apiClient.post<ApiResponse<AndroidByodInvitationCreated>>('/android/byod/invitations', body));
  },
  async revokeByodInvitation(id: string): Promise<void> {
    await apiClient.post(`/android/byod/invitations/${id}/revoke`, {});
  },

  // ── Devices (team scopes) ──
  async device(deviceId: number): Promise<AndroidDeviceView> {
    return data(await apiClient.get<ApiResponse<AndroidDeviceView>>(`/android/devices/${deviceId}`));
  },
  async actions(deviceId: number): Promise<AndroidDeviceAction[]> {
    return data(await apiClient.get<ApiResponse<AndroidDeviceAction[]>>(`/android/devices/${deviceId}/actions`));
  },
  async enqueue(deviceId: number, body: { type: string; params?: Record<string, unknown>; reason?: string }, key: string): Promise<{ commandId?: string; approvalId?: number }> {
    return data(await apiClient.post<ApiResponse<{ commandId?: string; approvalId?: number }>>(`/android/devices/${deviceId}/commands`, body,
      { headers: { 'Idempotency-Key': key } }));
  },
  async kiosk(deviceId: number): Promise<AndroidKioskState> {
    return data(await apiClient.get<ApiResponse<AndroidKioskState>>(`/android/devices/${deviceId}/kiosk`));
  },
  async endKioskExit(deviceId: number): Promise<void> {
    await apiClient.delete(`/android/devices/${deviceId}/kiosk-exit`);
  },

  // ── Policies ──
  async policyCatalog(): Promise<AndroidFormCatalogView> {
    return data(await apiClient.get<ApiResponse<AndroidFormCatalogView>>('/android/policy-catalog'));
  },
};

export const androidPlatformApi = {
  async health(): Promise<AndroidPlatformHealth> {
    const res = await apiClient.get<ApiResponse<AndroidPlatformHealth>>('/admin/android/health');
    return res.data.data!;
  },

  async quota(): Promise<AndroidQuotaView> {
    const res = await apiClient.get<ApiResponse<AndroidQuotaView>>('/admin/android/quota');
    return res.data.data!;
  },

  async keyDeadline(): Promise<AndroidDeadline | null> {
    return data(await apiClient.get<ApiResponse<AndroidDeadline | null>>('/admin/android/deadlines'));
  },

  /** Deposit of the JSON key of the service account (vault_key mode): strict step-up; answers its fingerprint only. */
  async depositKey(key: string): Promise<{ fingerprint: string; account: string }> {
    return data(await apiClient.post<ApiResponse<{ fingerprint: string; account: string }>>('/admin/android/google-credentials', { key }));
  },

  async orphans(tenantId: number): Promise<Array<{ enterpriseName: string; signupId: string }>> {
    return data(await apiClient.get<ApiResponse<Array<{ enterpriseName: string; signupId: string }>>>('/admin/android/orphans', { params: { tenantId } }));
  },

  async adopt(body: { tenantId: number; enterpriseName: string; signupId: string; reason: string }): Promise<AndroidApprovalFiled> {
    return data(await apiClient.post<ApiResponse<AndroidApprovalFiled>>('/admin/android/orphans/adopt', body));
  },

  async deadLetters(tenantId?: number): Promise<AndroidDeadLetterView[]> {
    return data(await apiClient.get<ApiResponse<AndroidDeadLetterView[]>>('/admin/android/inbox/dead', { params: tenantId ? { tenantId } : {} }));
  },

  async deadLetter(id: string): Promise<AndroidDeadLetterDetail> {
    return data(await apiClient.get<ApiResponse<AndroidDeadLetterDetail>>(`/admin/android/inbox/dead/${id}`));
  },

  async redrive(id: string): Promise<{ redriven?: boolean; approvalId?: number }> {
    return data(await apiClient.post<ApiResponse<{ redriven?: boolean; approvalId?: number }>>(`/admin/android/inbox/dead/${id}/redrive`, {}));
  },

  async discard(id: string): Promise<{ deleted?: boolean; approvalId?: number }> {
    return data(await apiClient.delete<ApiResponse<{ deleted?: boolean; approvalId?: number }>>(`/admin/android/inbox/dead/${id}`));
  },
};
