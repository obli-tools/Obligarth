import apiClient from './client';
import type { SiteDetail, SiteEnrollmentSheet, SiteImportResult, SitesFromDevicesResult, SiteView, SiteWriteBody, SiteWritePending } from '@obligarth/shared';

// =============================================================================
// Console API of the sites (lot P1-SITE §2.3): /api/sites (list, record, writes, import, the sites from the custom
// fields) and the site of one device (/api/mdm/devices/:id/site). A change of site never moves a device: the answer
// names the group of the site and the devices outside it, the console asks then for the guarded move. A write that
// changes what the files of a site's phones read (its values, code, name, city; an applied import; the sites from the
// custom fields) may ask a second factor (the client's interceptor) or be held for a second person (202: a
// SiteWritePending); an apply sends back the digest of the dry run shown (409 planChanged when the sites changed).
// =============================================================================

interface ApiResponse<T> { success?: boolean; data?: T }
const data = <T,>(r: { data: ApiResponse<T> }): T => r.data.data as T;
/** The answer of a write, or the request held for a second person (202, with or without the envelope). */
const written = <T,>(r: { data: ApiResponse<T | SiteWritePending> }): T | SiteWritePending =>
  (r.data.data ?? (r.data as unknown as SiteWritePending)) as T | SiteWritePending;

/** What a change of site did (PUT /mdm/devices/:id/site, POST /sites/:id/devices). */
export interface SiteAttachOutcome {
  changed: number[];
  unchanged: number[];
  siteGroupId: number | null;
  outsideGroup: number[];
}

export interface FromDevicesKeysInput {
  codeKey?: string;
  nameKey?: string;
  valuesKeys?: string[];
}

export const sitesApi = {
  async list(params: { q?: string; archived?: boolean } = {}): Promise<SiteView[]> {
    return data(await apiClient.get<ApiResponse<SiteView[]>>('/sites', {
      params: { ...(params.q ? { q: params.q } : {}), ...(params.archived ? { archived: true } : {}) },
    })) ?? [];
  },
  async get(id: string): Promise<SiteDetail> {
    return data(await apiClient.get<ApiResponse<SiteDetail>>(`/sites/${encodeURIComponent(id)}`));
  },
  async valueKeys(): Promise<string[]> {
    return data(await apiClient.get<ApiResponse<string[]>>('/sites/value-keys')) ?? [];
  },
  async create(body: SiteWriteBody): Promise<SiteDetail> {
    return data(await apiClient.post<ApiResponse<SiteDetail>>('/sites', body));
  },
  async update(id: string, body: SiteWriteBody): Promise<SiteDetail | SiteWritePending> {
    return written(await apiClient.patch<ApiResponse<SiteDetail | SiteWritePending>>(`/sites/${encodeURIComponent(id)}`, body));
  },
  async archive(id: string, archived = true): Promise<SiteDetail> {
    return data(await apiClient.post<ApiResponse<SiteDetail>>(`/sites/${encodeURIComponent(id)}/${archived ? 'archive' : 'restore'}`));
  },
  async attach(id: string, deviceIds: number[]): Promise<SiteAttachOutcome> {
    return data(await apiClient.post<ApiResponse<SiteAttachOutcome>>(`/sites/${encodeURIComponent(id)}/devices`, { deviceIds }));
  },
  /** The printable enrollment sheet of the site (lot P1-QR §3.2): a token of the site, its QR code; the previous sheet
   *  of the site revoked. Shown once. */
  async enrollmentSheet(id: string, body: { label?: string; days?: number; maxUses?: number }): Promise<SiteEnrollmentSheet> {
    return data(await apiClient.post<ApiResponse<SiteEnrollmentSheet>>(`/sites/${encodeURIComponent(id)}/enrollment-sheet`, body));
  },
  async setDeviceSite(deviceId: number, siteId: string | null): Promise<SiteAttachOutcome> {
    return data(await apiClient.put<ApiResponse<SiteAttachOutcome>>(`/mdm/devices/${deviceId}/site`, { siteId }));
  },
  /** A CSV file: the plan (dryRun), or applied with the digest of the plan shown. Sent as a Blob: a second factor asked
   *  is sent again with the same bytes, the proof in a header (the interceptor's raw-body path). */
  async importCsv(csv: string, dryRun: boolean, digest?: string): Promise<SiteImportResult | SiteWritePending> {
    return written(await apiClient.post<ApiResponse<SiteImportResult | SiteWritePending>>('/sites/import', new Blob([csv], { type: 'text/csv' }), {
      params: { dryRun: dryRun ? 'true' : 'false', ...(digest ? { digest } : {}) }, headers: { 'Content-Type': 'text/csv' },
    }));
  },
  async fromDevices(keys: FromDevicesKeysInput, dryRun: boolean, digest?: string): Promise<SitesFromDevicesResult | SiteWritePending> {
    return written(await apiClient.post<ApiResponse<SitesFromDevicesResult | SiteWritePending>>('/sites/from-devices', { ...keys, dryRun, ...(digest ? { digest } : {}) }));
  },
};
