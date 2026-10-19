import apiClient from './client';
import type {
  Assignment, AssignmentChange, DeviceAppView, DeviceCertificateView, DeviceConfigurationView, DeviceDetail,
  DeviceFacets, DeviceProfileView, DeviceSummary, EndUser, EndUserImportReport, EnrollmentEpisode, GuardOutcome,
  ImpactDevicesPage, MdmFleetPoint, MdmFleetSummary, Policy, PolicyConflict, PolicyContentV1, PolicyImpact,
  PolicyValidationIssue, PolicyVersion, SchemaEntry, SubmitOutcome, AppCatalogEntry, AppDetail,
} from '@obligarth/shared';

// =============================================================================
// Console API of the MDM data model (/api/mdm, modele-donnees-mdm §10.6):
// device registry and inventory, fleet counters, policies, assignments, end
// users. The commands, the queue and the timeline of a device are the
// integration's (/api/apple, apple.api.ts).
// =============================================================================

interface ApiResponse<T> { data?: T; error?: string; code?: string }

export type ContactFilter = 'never' | 'recent' | 'quiet' | 'stale';
export type DeviceSortField = 'name' | 'platform' | 'os' | 'lastCheckin' | 'enrolledAt' | 'group' | 'state'
  | 'compliance' | 'ownership' | 'model' | 'warranty';

/** The filters of GET /api/mdm/devices (lists are sent comma-separated). */
export interface DeviceListParams {
  platform?: string[];
  ownership?: string[];
  enrollmentState?: string[];
  contact?: ContactFilter[];
  compliance?: string[];
  config?: string[];
  osBelow?: string;
  supervised?: boolean;
  groupId?: number;
  includeSubgroups?: boolean;
  ungrouped?: boolean;
  tags?: string[];
  endUserId?: number;
  q?: string;
  /** Master tenant only (global view): a subset of the tenants. */
  tenantIds?: number[];
  sortBy?: DeviceSortField;
  sortOrder?: 'asc' | 'desc';
  page?: number;
  pageSize?: number;
}

export interface DevicePage { items: DeviceSummary[]; total: number; page: number; pageSize: number }

/** Lists as comma-separated values; empty lists and undefined left out. */
function query(params: object | undefined): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) { if (v.length) out[k] = v.join(','); } else out[k] = v as string | number | boolean;
  }
  return out;
}

/** What the operator may change on a device record (PATCH /api/mdm/devices/:id). */
export interface DevicePatch {
  displayName?: string | null;
  description?: string | null;
  tags?: string[];
  customFields?: Record<string, string>;
  purchaseDate?: string | null;
  warrantyExpiry?: string | null;
  warrantyVendor?: string | null;
  warrantyStatus?: 'active' | 'expired' | 'unknown' | null;
  expectedLifetimeYears?: number | null;
  lifecycleStatus?: 'active' | 'aging' | 'end_of_life' | 'retired' | 'unknown' | null;
}

export interface PolicyValidation { valid: boolean; issues: PolicyValidationIssue[]; conflicts: PolicyConflict[] }

/** A raw profile imported into the draft (POST /api/mdm/policies/:id/raw-profiles). */
export interface RawProfileImport {
  version: PolicyVersion;
  itemId: string;
  /** The file came inside a signed envelope whose signature verifies (removed at import: MDM-B5c-R8). */
  signed: boolean;
  /** The check of that signature; null when the file was not signed. 'unsupported': an algorithm not verified here. */
  signature?: { status: 'valid' | 'invalid' | 'unsupported'; trusted?: boolean;
    signer?: { subject: string; issuer: string; notAfter: string; sha256: string } } | null;
  /** Names of the keys whose values were moved to the vault. */
  movedSecrets: string[];
  /** Keys that look like secrets and stay in clear in the policy (no rule moved them: MDM-B5c-R9). Names only. */
  suspectKeys?: string[];
  payloadTypes: string[];
}

export interface SchemaCatalogView {
  release: { ref: string; commit: string; importedAt: string };
  types: Array<SchemaEntry & {
    descriptor: unknown; secretKeys: Record<string, unknown>; forbiddenOwnerships: string[]; enabled: boolean;
  }>;
}

/** The answer of a guarded write of the configuration: done (200), or waiting for a second approver (202). */
export type GuardedWrite = SubmitOutcome;

export const mdmApi = {
  // ── Devices ────────────────────────────────────────────────────────────────
  async listDevices(params?: DeviceListParams): Promise<DevicePage> {
    const res = await apiClient.get<ApiResponse<DevicePage>>('/mdm/devices', { params: query(params) });
    return res.data.data ?? { items: [], total: 0, page: 1, pageSize: 100 };
  },
  async facets(): Promise<DeviceFacets> {
    const res = await apiClient.get<ApiResponse<DeviceFacets>>('/mdm/devices/facets');
    return res.data.data ?? { platform: [], ownership: [], enrollmentState: [], complianceState: [], configState: [], osVersion: [], model: [], tag: [] };
  },
  async exportDevices(format: 'csv' | 'xlsx' | 'pdf', params?: DeviceListParams): Promise<{ blob: Blob; filename: string }> {
    const res = await apiClient.get('/mdm/devices/export', { params: { ...query(params), format }, responseType: 'blob' });
    const cd = String(res.headers['content-disposition'] ?? '');
    const match = /filename="([^"]+)"/.exec(cd);
    return { blob: res.data as Blob, filename: match ? match[1] : `obligarth-devices.${format}` };
  },
  async getDevice(id: number): Promise<DeviceDetail> {
    const res = await apiClient.get<ApiResponse<DeviceDetail>>(`/mdm/devices/${id}`);
    return res.data.data!;
  },
  async updateDevice(id: number, patch: DevicePatch): Promise<DeviceDetail> {
    const res = await apiClient.patch<ApiResponse<DeviceDetail>>(`/mdm/devices/${id}`, patch);
    return res.data.data!;
  },
  /** `null`: the move waits for a second approver (202), nothing has moved yet (modele-donnees-mdm S12). */
  async setGroup(id: number, groupId: number | null): Promise<{ changed: boolean } | null> {
    const res = await apiClient.post<ApiResponse<{ changed: boolean }>>(`/mdm/devices/${id}/group`, { groupId });
    return res.status === 202 ? null : (res.data.data ?? { changed: false });
  },
  /** What moving devices into a group would change for them (the policies they inherit): nothing is written. */
  async previewSetGroup(deviceIds: number[], groupId: number | null): Promise<PolicyImpact> {
    const res = await apiClient.post<ApiResponse<{ outcome: string; impact: PolicyImpact }>>('/mdm/devices/batch/group', { deviceIds, groupId },
      { params: { dryRun: true } });
    return res.data.data!.impact;
  },
  /** The same preview for one device (from the global view too: the device's tenant). */
  async previewSetGroupOne(id: number, groupId: number | null): Promise<PolicyImpact> {
    const res = await apiClient.post<ApiResponse<{ outcome: string; impact: PolicyImpact }>>(`/mdm/devices/${id}/group`, { groupId },
      { params: { dryRun: true } });
    return res.data.data!.impact;
  },
  /** `null`: the move waits for a second approver (202), nothing has moved yet. */
  async batchSetGroup(deviceIds: number[], groupId: number | null): Promise<{ updated: number; changed: number } | null> {
    const res = await apiClient.post<ApiResponse<{ updated: number; changed: number }>>('/mdm/devices/batch/group', { deviceIds, groupId });
    return res.status === 202 ? null : (res.data.data ?? { updated: 0, changed: 0 });
  },
  async setEndUser(id: number, endUserId: number | null): Promise<void> {
    await apiClient.post(`/mdm/devices/${id}/end-user`, { endUserId });
  },
  /** `null`: the change waits for a second approver (202). */
  async changeOwnership(id: number, body: { to: 'corporate' | 'corporate_personal'; reason: string; ticket?: string | null }): Promise<unknown | null> {
    const res = await apiClient.post<ApiResponse<unknown>>(`/mdm/devices/${id}/ownership`, body);
    return res.status === 202 ? null : (res.data.data ?? {});
  },
  async deleteDevices(deviceIds: number[], body: { reason: string; ticket?: string; confirm: string }): Promise<GuardOutcome> {
    const res = await apiClient.delete<ApiResponse<GuardOutcome>>('/mdm/devices/batch', { data: { deviceIds, ...body } });
    return res.data.data!;
  },
  async enrollments(id: number): Promise<EnrollmentEpisode[]> {
    const res = await apiClient.get<ApiResponse<EnrollmentEpisode[]>>(`/mdm/devices/${id}/enrollments`);
    return res.data.data ?? [];
  },
  async apps(id: number): Promise<DeviceAppView[]> {
    const res = await apiClient.get<ApiResponse<DeviceAppView[]>>(`/mdm/devices/${id}/apps`);
    return res.data.data ?? [];
  },
  async profiles(id: number): Promise<DeviceProfileView[]> {
    const res = await apiClient.get<ApiResponse<DeviceProfileView[]>>(`/mdm/devices/${id}/profiles`);
    return res.data.data ?? [];
  },
  async certificates(id: number): Promise<DeviceCertificateView[]> {
    const res = await apiClient.get<ApiResponse<DeviceCertificateView[]>>(`/mdm/devices/${id}/certificates`);
    return res.data.data ?? [];
  },
  async configuration(id: number): Promise<DeviceConfigurationView> {
    const res = await apiClient.get<ApiResponse<DeviceConfigurationView>>(`/mdm/devices/${id}/configuration`);
    return res.data.data!;
  },
  /** Which tenant a device lives in, when the caller has access to it (deep links); null otherwise. */
  async locate(deviceId: number): Promise<{ deviceId: number; label: string; tenantId: number; tenantName: string; currentTenantId: number | null } | null> {
    try {
      const res = await apiClient.get<ApiResponse<{ deviceId: number; label: string; tenantId: number; tenantName: string; currentTenantId: number | null }>>(`/tenants/locate-device/${deviceId}`);
      return res.data.data ?? null;
    } catch {
      return null;
    }
  },

  // ── Fleet (dashboard) ──────────────────────────────────────────────────────
  async fleetSummary(): Promise<MdmFleetSummary> {
    const res = await apiClient.get<ApiResponse<MdmFleetSummary>>('/mdm/fleet/summary');
    return res.data.data!;
  },
  async fleetTimeseries(days = 14): Promise<MdmFleetPoint[]> {
    const res = await apiClient.get<ApiResponse<MdmFleetPoint[]>>('/mdm/fleet/timeseries', { params: { days } });
    return res.data.data ?? [];
  },
  async fleetHourly(hours = 24): Promise<MdmFleetPoint[]> {
    const res = await apiClient.get<ApiResponse<MdmFleetPoint[]>>('/mdm/fleet/hourly', { params: { hours } });
    return res.data.data ?? [];
  },

  // ── Policies ───────────────────────────────────────────────────────────────
  async listPolicies(params?: { state?: string; category?: string; q?: string }): Promise<Policy[]> {
    const res = await apiClient.get<ApiResponse<Policy[]>>('/mdm/policies', { params: query(params) });
    return res.data.data ?? [];
  },
  async createPolicy(body: { name: string; description?: string | null; category?: string; copyFrom?: number | null }): Promise<{ policy: Policy; version: PolicyVersion }> {
    const res = await apiClient.post<ApiResponse<{ policy: Policy; version: PolicyVersion }>>('/mdm/policies', body);
    return res.data.data!;
  },
  async getPolicy(id: number): Promise<Policy> {
    const res = await apiClient.get<ApiResponse<Policy>>(`/mdm/policies/${id}`);
    return res.data.data!;
  },
  async updatePolicy(id: number, body: { name?: string; description?: string | null; category?: string }): Promise<Policy> {
    const res = await apiClient.patch<ApiResponse<Policy>>(`/mdm/policies/${id}`, body);
    return res.data.data!;
  },
  async archivePolicy(id: number): Promise<Policy> {
    const res = await apiClient.post<ApiResponse<Policy>>(`/mdm/policies/${id}/archive`);
    return res.data.data!;
  },
  /** The versions of a policy, without their content. */
  async listVersions(id: number): Promise<Array<Omit<PolicyVersion, 'content'>>> {
    const res = await apiClient.get<ApiResponse<Array<Omit<PolicyVersion, 'content'>>>>(`/mdm/policies/${id}/versions`);
    return res.data.data ?? [];
  },
  async getVersion(id: number, version: number): Promise<PolicyVersion> {
    const res = await apiClient.get<ApiResponse<PolicyVersion>>(`/mdm/policies/${id}/versions/${version}`);
    return res.data.data!;
  },
  async newVersion(id: number, from?: number): Promise<PolicyVersion> {
    const res = await apiClient.post<ApiResponse<PolicyVersion>>(`/mdm/policies/${id}/versions`, from ? { from } : {});
    return res.data.data!;
  },
  async saveDraft(id: number, version: number, content: PolicyContentV1, changeNote?: string | null): Promise<PolicyVersion> {
    const res = await apiClient.put<ApiResponse<PolicyVersion>>(`/mdm/policies/${id}/versions/${version}`, { content, changeNote: changeNote ?? null });
    return res.data.data!;
  },
  async discardVersion(id: number, version: number): Promise<void> {
    await apiClient.delete(`/mdm/policies/${id}/versions/${version}`);
  },
  async validateVersion(id: number, version: number): Promise<PolicyValidation> {
    const res = await apiClient.post<ApiResponse<PolicyValidation>>(`/mdm/policies/${id}/versions/${version}/validate`);
    return res.data.data ?? { valid: false, issues: [], conflicts: [] };
  },
  async versionImpact(id: number, version: number): Promise<PolicyImpact> {
    const res = await apiClient.post<ApiResponse<PolicyImpact>>(`/mdm/policies/${id}/versions/${version}/impact`);
    return res.data.data!;
  },
  /** Publication: done (a second factor may have been asked by the interceptor), or waiting for a second approver. */
  async submitVersion(id: number, version: number): Promise<SubmitOutcome> {
    const res = await apiClient.post<ApiResponse<SubmitOutcome>>(`/mdm/policies/${id}/versions/${version}/submit`);
    return res.data.data!;
  },
  async importRawProfile(id: number, file: File): Promise<RawProfileImport> {
    const form = new FormData();
    form.append('file', file);
    const res = await apiClient.post<ApiResponse<RawProfileImport>>(`/mdm/policies/${id}/raw-profiles`, form);
    return res.data.data!;
  },

  // ── Assignments ────────────────────────────────────────────────────────────
  async listAssignments(params: { resourceType?: 'policy' | 'app'; resourceId?: number; targetScope?: 'tenant' | 'group' | 'device'; targetId?: number }): Promise<Assignment[]> {
    const res = await apiClient.get<ApiResponse<Assignment[]>>('/mdm/assignments', { params: query(params) });
    return res.data.data ?? [];
  },
  /** The preview of a batch of changes (nothing written). */
  async previewAssignments(changes: AssignmentChange[]): Promise<PolicyImpact> {
    const res = await apiClient.post<ApiResponse<SubmitOutcome>>('/mdm/assignments/changes', { changes }, { params: { dryRun: true } });
    return res.data.data!.impact;
  },
  async changeAssignments(changes: AssignmentChange[]): Promise<SubmitOutcome> {
    const res = await apiClient.post<ApiResponse<SubmitOutcome>>('/mdm/assignments/changes', { changes });
    return res.data.data!;
  },

  // ── Catalog of apps (lot C4) ───────────────────────────────────────────────
  async listApps(params?: { archived?: boolean; q?: string }): Promise<AppCatalogEntry[]> {
    const res = await apiClient.get<ApiResponse<AppCatalogEntry[]>>('/mdm/apps', { params: query({ archived: params?.archived ? 1 : undefined, q: params?.q }) });
    return res.data.data ?? [];
  },
  async getApp(id: number): Promise<AppDetail> {
    const res = await apiClient.get<ApiResponse<AppDetail>>(`/mdm/apps/${id}`);
    return res.data.data!;
  },
  async createApp(body: { kind: 'app_store' | 'custom'; storeId: string; identifier: string; name: string; publisher?: string | null; iconUrl?: string | null }): Promise<AppCatalogEntry> {
    const res = await apiClient.post<ApiResponse<AppCatalogEntry>>('/mdm/apps', body);
    return res.data.data!;
  },
  async updateApp(id: number, body: { name?: string; publisher?: string | null; iconUrl?: string | null; minimumOsVersion?: string | null }): Promise<AppCatalogEntry> {
    const res = await apiClient.patch<ApiResponse<AppCatalogEntry>>(`/mdm/apps/${id}`, body);
    return res.data.data!;
  },
  async archiveApp(id: number): Promise<AppCatalogEntry> {
    const res = await apiClient.post<ApiResponse<AppCatalogEntry>>(`/mdm/apps/${id}/archive`);
    return res.data.data!;
  },

  // ── Schema and previews ────────────────────────────────────────────────────
  async schema(type?: string): Promise<SchemaCatalogView> {
    const res = await apiClient.get<ApiResponse<SchemaCatalogView>>('/mdm/schema/apple', { params: query({ type }) });
    return res.data.data!;
  },
  async impactDevices(token: string, page = 1, pageSize = 100): Promise<ImpactDevicesPage> {
    const res = await apiClient.get<ApiResponse<ImpactDevicesPage>>(`/mdm/impact/${encodeURIComponent(token)}/devices`, { params: { page, pageSize } });
    return res.data.data ?? { total: 0, page, pageSize, devices: [] };
  },

  // ── End users ──────────────────────────────────────────────────────────────
  async listEndUsers(params?: { status?: 'active' | 'departed'; q?: string; page?: number; pageSize?: number }): Promise<{ items: EndUser[]; total: number; page: number; pageSize: number }> {
    const res = await apiClient.get<ApiResponse<{ items: EndUser[]; total: number; page: number; pageSize: number }>>('/mdm/end-users', { params: query(params) });
    return res.data.data ?? { items: [], total: 0, page: 1, pageSize: 100 };
  },
  async createEndUser(body: EndUserFields): Promise<EndUser> {
    const res = await apiClient.post<ApiResponse<EndUser>>('/mdm/end-users', body);
    return res.data.data!;
  },
  async updateEndUser(id: number, body: EndUserFields): Promise<EndUser> {
    const res = await apiClient.patch<ApiResponse<EndUser>>(`/mdm/end-users/${id}`, body);
    return res.data.data!;
  },
  async departEndUser(id: number): Promise<EndUser> {
    const res = await apiClient.post<ApiResponse<EndUser>>(`/mdm/end-users/${id}/depart`);
    return res.data.data!;
  },
  async importEndUsers(csv: string): Promise<EndUserImportReport> {
    const res = await apiClient.post<ApiResponse<EndUserImportReport>>('/mdm/end-users/import', { csv });
    return res.data.data!;
  },
};

export interface EndUserFields {
  email?: string | null;
  displayName?: string | null;
  managedAppleAccount?: string | null;
  externalId?: string | null;
}

/** The enrollment states of a device under management (every state but 'unenrolled'). */
export const MANAGED_STATES = ['enrolling', 'awaiting_configuration', 'enrolled', 'unenrolling'] as const;

/**
 * Every device under management the caller sees, by pages of 1 000 (pickers: maintenance scopes, reports,
 * team scopes). Bounded by `max`: a picker is not the place to browse a larger fleet (its search narrows it).
 */
export async function listManagedDevices(max = 5000): Promise<DeviceSummary[]> {
  const out: DeviceSummary[] = [];
  for (let page = 1; out.length < max; page += 1) {
    const r = await mdmApi.listDevices({ enrollmentState: [...MANAGED_STATES], sortBy: 'name', page, pageSize: 1000 });
    out.push(...r.items);
    if (r.items.length === 0 || out.length >= r.total) break;
  }
  return out.slice(0, max);
}
