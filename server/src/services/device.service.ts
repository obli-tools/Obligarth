import type { Knex } from 'knex';
import { Server as SocketIOServer } from 'socket.io';
import { db } from '../db';
import { logger } from '../utils/logger';
import { AppError } from '../middleware/errorHandler';
import { JobError, safeErr } from '../jobs/errors';
import {
  MDM_STALE_AFTER_DAYS_DEFAULT, SocketEvents, contactState, isMasterTenant, versionNum,
  type AppleDeviceDetail, type ComplianceReason, type ContactState, type DeviceDetail, type DeviceFacets,
  type DeviceSummary, type MdmFleetPoint, type MdmFleetSummary, type NanoEnrollType, type Ownership,
} from '@obligarth/shared';
import { collectedFields, privacyRulesFor, type PrivacyRules } from '../apple/devices/privacy';
import { staleAfterDaysOf } from '../mdm/settings';
import type { TenantView } from './deviceScope.service';

// =============================================================================
// The device registry of the MDM (docs: modele-donnees-mdm §4, §10.2, §11.1):
// list, record, facets, export, fleet summary and series, snapshots, the
// operator's edits, the deletion of records out of management. Reads and
// writes only the MDM columns of devices (version N: the columns of the removed
// agent are neither read nor written; they leave with the contract step).
// The contact of a device is derived from last_checkin_at, never stored; a
// value the privacy rules do not collect is absent from the views (EX-19).
// The master tenant's global view (TenantView) reaches every tenant: an
// explicit flag of the route, never inferred from the tenant id.
// =============================================================================

/** The master tenant's global view, as the caller passed it (TenantView). */
function isGlobalView(tenantId: number, view?: TenantView): boolean {
  return !!view?.globalView && isMasterTenant(tenantId);
}

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);
const nanoTypeOfMode = (mode: string): NanoEnrollType => (mode === 'user_enrollment' ? 'User Enrollment (Device)' : 'Device');
const asArray = <T = unknown>(v: unknown): T[] => {
  if (Array.isArray(v)) return v as T[];
  if (typeof v === 'string') { try { const p = JSON.parse(v); return Array.isArray(p) ? p as T[] : []; } catch { return []; } }
  return [];
};
const asObject = (v: unknown): Record<string, unknown> => {
  if (v && typeof v === 'object' && !Array.isArray(v)) return v as Record<string, unknown>;
  if (typeof v === 'string') { try { const p = JSON.parse(v); return p && typeof p === 'object' && !Array.isArray(p) ? p : {}; } catch { return {}; } }
  return {};
};

/** Filters of GET /api/mdm/devices (§10.6). */
export interface DeviceListFilters {
  platform?: string[];
  ownership?: string[];
  enrollmentState?: string[];
  contact?: ContactState[];
  compliance?: string[];
  config?: string[];
  /** Devices whose OS version is below this one ('17.5'). */
  osBelow?: string;
  supervised?: boolean;
  groupId?: number;
  includeSubgroups?: boolean;
  ungrouped?: boolean;
  tags?: string[];
  endUserId?: number;
  /** Free text: label, names, serial number, model, end user. */
  q?: string;
  /** Global view only: a subset of tenants. */
  tenantIds?: number[];
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  page?: number;
  pageSize?: number;
  /** Non-administrators: the devices their teams see (permissionService.getVisibleDeviceIds). */
  visibleIds?: number[] | 'all';
}

/** Columns of a summary row (devices, its group, tenant and end user, the satellite's type). */
const SUMMARY_COLUMNS = [
  'devices.id', 'devices.uuid', 'devices.tenant_id', 'devices.group_id', 'devices.display_name', 'devices.label',
  'devices.platform', 'devices.ownership', 'devices.enrollment_type', 'devices.management_mode', 'devices.supervised',
  'devices.usage', 'devices.enrollment_state', 'devices.last_checkin_at', 'devices.compliance_state',
  'devices.compliance_reasons', 'devices.config_state', 'devices.lost_mode_state', 'devices.os_version',
  'devices.model', 'devices.model_name', 'devices.serial_number', 'devices.end_user_id', 'devices.tags',
  'devices.enrolled_at', 'device_groups.name as group_name', 'tenants.name as tenant_name',
  'end_users.display_name as end_user_display_name', 'end_users.email as end_user_email',
];

/** Columns of the record of one device, on top of the summary's. */
const DETAIL_COLUMNS = [
  'devices.description', 'devices.custom_fields', 'devices.os_build', 'devices.device_name',
  'devices.storage_capacity_bytes', 'devices.storage_available_bytes', 'devices.unenrolled_at',
  'devices.unenroll_reason', 'devices.purchase_date', 'devices.warranty_expiry', 'devices.warranty_vendor',
  'devices.warranty_status', 'devices.expected_lifetime_years', 'devices.lifecycle_status',
  'devices.enrollment_profile_id', 'devices.created_at', 'devices.updated_at',
];

/** Sortable columns: a whitelist, never the caller's text. */
const SORT_COLUMNS: Record<string, string> = {
  name: 'devices.label',
  platform: 'devices.platform',
  os: 'devices.os_version_num',
  lastCheckin: 'devices.last_checkin_at',
  enrolledAt: 'devices.enrolled_at',
  group: 'device_groups.name',
  state: 'devices.enrollment_state',
  compliance: 'devices.compliance_state',
  ownership: 'devices.ownership',
  model: 'devices.model_name',
};

/** A cache of the privacy rules of a request: one resolution per (tenant, ownership, type). */
class RulesCache {
  private readonly cache = new Map<string, Promise<PrivacyRules>>();
  get(tenantId: number, ownership: Ownership, mode: string): Promise<PrivacyRules> {
    const type = nanoTypeOfMode(mode);
    const key = `${tenantId}:${ownership}:${type}`;
    let p = this.cache.get(key);
    if (!p) {
      p = privacyRulesFor(db, tenantId, ownership, type);
      this.cache.set(key, p);
    }
    return p;
  }
}

class DeviceService {
  private io: SocketIOServer | null = null;

  setIO(io: SocketIOServer) { this.io = io; }

  // ─── Views ────────────────────────────────────────────────────────────────

  private async toSummary(row: any, rules: RulesCache, staleDays: Map<number, number>, now: Date): Promise<DeviceSummary> {
    const tenantId = Number(row.tenant_id);
    const r = await rules.get(tenantId, row.ownership, row.management_mode);
    const summary: DeviceSummary = {
      id: Number(row.id), uuid: row.uuid, tenantId,
      label: row.label, displayName: row.display_name ?? null,
      groupId: row.group_id === null || row.group_id === undefined ? null : Number(row.group_id),
      groupName: row.group_name ?? null,
      platform: row.platform, ownership: row.ownership, enrollmentMethod: row.enrollment_type,
      managementMode: row.management_mode, supervised: !!row.supervised, usage: row.usage,
      enrollmentState: row.enrollment_state,
      contactState: contactState(row.last_checkin_at, now, staleDays.get(tenantId) ?? MDM_STALE_AFTER_DAYS_DEFAULT),
      lastCheckinAt: iso(row.last_checkin_at),
      complianceState: row.compliance_state, complianceReasons: asArray<ComplianceReason>(row.compliance_reasons),
      configState: row.config_state, lostModeState: row.lost_mode_state,
      osVersion: row.os_version ?? null, model: row.model ?? null, modelName: row.model_name ?? null,
      endUser: row.end_user_id ? {
        id: Number(row.end_user_id), displayName: row.end_user_display_name ?? null, email: row.end_user_email ?? null,
      } : null,
      tags: asArray<string>(row.tags).map(String),
      enrolledAt: iso(row.enrolled_at),
    };
    if (row.tenant_name) summary.tenantName = row.tenant_name;
    // Absent, never null, when the rules of the device's ownership do not collect it (EX-19).
    if (r.storeSerialNumber) summary.serialNumber = row.serial_number ?? null;
    return summary;
  }

  /** The base query of the registry, joined with the group, the tenant and the end user. */
  private baseQuery(): Knex.QueryBuilder {
    return db('devices')
      .leftJoin('device_groups', function joinGroup() {
        this.on('device_groups.id', '=', 'devices.group_id').andOn('device_groups.tenant_id', '=', 'devices.tenant_id');
      })
      .leftJoin('tenants', 'tenants.id', 'devices.tenant_id')
      .leftJoin('end_users', function joinEndUser() {
        this.on('end_users.id', '=', 'devices.end_user_id').andOn('end_users.tenant_id', '=', 'devices.tenant_id');
      });
  }

  /** The tenants a list reaches: the request's, or every tenant (or the chosen ones) in the global view. */
  private async listTenantIds(tenantId: number, view?: TenantView, tenantIds?: number[]): Promise<number[] | 'all'> {
    if (!isGlobalView(tenantId, view)) return [tenantId];
    const chosen = (tenantIds ?? []).map(Number).filter((n) => Number.isSafeInteger(n) && n > 0);
    return chosen.length > 0 ? chosen : 'all';
  }

  /** The thresholds of mdmStaleAfterDays of the tenants a query reaches (every tenant: read them all). */
  private async thresholds(scope: number[] | 'all'): Promise<Map<number, number>> {
    if (scope !== 'all') return staleAfterDaysOf(scope);
    const ids = (await db('tenants').pluck('id') as number[]).map(Number);
    return staleAfterDaysOf(ids);
  }

  /** SQL of a tenant's stale threshold in days (a CASE over the tenants of the query). */
  private staleDaysSql(thresholds: Map<number, number>): { sql: string; bindings: number[] } {
    const pairs = [...thresholds.entries()].filter(([, d]) => d !== MDM_STALE_AFTER_DAYS_DEFAULT);
    if (pairs.length === 0) return { sql: '?::int', bindings: [MDM_STALE_AFTER_DAYS_DEFAULT] };
    return {
      sql: `(CASE devices.tenant_id ${pairs.map(() => 'WHEN ?::int THEN ?::int').join(' ')} ELSE ?::int END)`,
      bindings: [...pairs.flat(), MDM_STALE_AFTER_DAYS_DEFAULT],
    };
  }

  private async applyFilters(q: Knex.QueryBuilder, tenantId: number, f: DeviceListFilters, view: TenantView | undefined,
    thresholds: Map<number, number>): Promise<void> {
    const scope = await this.listTenantIds(tenantId, view, f.tenantIds);
    if (scope !== 'all') q.whereIn('devices.tenant_id', scope);
    if (f.visibleIds !== undefined && f.visibleIds !== 'all') {
      if (f.visibleIds.length === 0) q.whereRaw('false');
      else q.whereIn('devices.id', f.visibleIds);
    }
    const inList = (col: string, values: string[] | undefined) => {
      if (Array.isArray(values) && values.length > 0) q.whereIn(col, values);
    };
    inList('devices.platform', f.platform);
    inList('devices.ownership', f.ownership);
    inList('devices.enrollment_state', f.enrollmentState);
    inList('devices.compliance_state', f.compliance);
    inList('devices.config_state', f.config);
    if (typeof f.supervised === 'boolean') q.where('devices.supervised', f.supervised);
    if (f.osBelow) {
      const below = versionNum(f.osBelow);
      if (below === null) throw new AppError(400, 'Invalid OS version', 'invalidRequest');
      q.where('devices.os_version_num', '<', below);
    }
    if (f.ungrouped) {
      q.whereNull('devices.group_id');
    } else if (f.groupId) {
      if (f.includeSubgroups) {
        q.whereIn('devices.group_id', db('device_group_closure').where('ancestor_id', f.groupId).select('descendant_id'));
      } else {
        q.where('devices.group_id', f.groupId);
      }
    }
    if (Array.isArray(f.tags) && f.tags.length > 0) {
      // jsonb ?| text[]: the operator's '?' escaped for Knex.
      q.whereRaw('devices.tags \\?| ?::text[]', [f.tags]);
    }
    if (f.endUserId) q.where('devices.end_user_id', f.endUserId);
    if (Array.isArray(f.contact) && f.contact.length > 0) {
      const days = this.staleDaysSql(thresholds);
      q.where(function contact() {
        for (const c of f.contact!) {
          if (c === 'never') this.orWhereNull('devices.last_checkin_at');
          else if (c === 'recent') this.orWhereRaw("devices.last_checkin_at >= now() - interval '24 hours'");
          else if (c === 'quiet') {
            this.orWhereRaw(`devices.last_checkin_at < now() - interval '24 hours'
              AND devices.last_checkin_at >= now() - make_interval(days => ${days.sql})`, days.bindings);
          } else if (c === 'stale') {
            this.orWhereRaw(`devices.last_checkin_at < now() - make_interval(days => ${days.sql})`, days.bindings);
          }
        }
      });
    }
    if (f.q && f.q.trim()) {
      const pat = `%${f.q.trim().replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      q.where(function search() {
        this.whereILike('devices.label', pat)
          .orWhereILike('devices.display_name', pat)
          .orWhereILike('devices.device_name', pat)
          .orWhereILike('devices.serial_number', pat)
          .orWhereILike('devices.model', pat)
          .orWhereILike('devices.model_name', pat)
          .orWhereILike('end_users.display_name', pat)
          .orWhereILike('end_users.email', pat)
          .orWhereILike('end_users.external_id', pat)
          .orWhereRaw('devices.uuid::text ILIKE ?', [pat])
          .orWhereRaw('devices.tags::text ILIKE ?', [pat]);
      });
    }
  }

  /** The inventory list (GET /api/mdm/devices), paginated. */
  async listDevices(tenantId: number, filters: DeviceListFilters = {}, view?: TenantView):
    Promise<{ items: DeviceSummary[]; total: number; page: number; pageSize: number }> {
    const page = Math.max(1, Math.floor(filters.page ?? 1));
    const pageSize = Math.min(1000, Math.max(1, Math.floor(filters.pageSize ?? 100)));
    const scope = await this.listTenantIds(tenantId, view, filters.tenantIds);
    const thresholds = await this.thresholds(scope);
    const q = this.baseQuery();
    await this.applyFilters(q, tenantId, filters, view, thresholds);
    const total = Number((await q.clone().clearSelect().count<{ n: string }[]>('devices.id as n').first())?.n ?? 0);
    const sortCol = filters.sortBy ? SORT_COLUMNS[filters.sortBy] : undefined;
    const dir = filters.sortOrder === 'desc' ? 'desc' : 'asc';
    if (sortCol) q.orderByRaw(`${sortCol} ${dir} NULLS LAST, devices.id asc`);
    else q.orderBy('devices.id', 'asc');
    const rows = await q.select(SUMMARY_COLUMNS).limit(pageSize).offset((page - 1) * pageSize);
    const rules = new RulesCache();
    const now = new Date();
    const items = await Promise.all(rows.map((row: any) => this.toSummary(row, rules, thresholds, now)));
    return { items, total, page, pageSize };
  }

  /** The whole filtered list, for the export (50 000 rows at most). */
  async exportDevices(tenantId: number, filters: DeviceListFilters = {}, view?: TenantView): Promise<DeviceSummary[]> {
    const scope = await this.listTenantIds(tenantId, view, filters.tenantIds);
    const thresholds = await this.thresholds(scope);
    const q = this.baseQuery();
    await this.applyFilters(q, tenantId, filters, view, thresholds);
    const sortCol = filters.sortBy ? SORT_COLUMNS[filters.sortBy] : undefined;
    if (sortCol) q.orderByRaw(`${sortCol} ${filters.sortOrder === 'desc' ? 'desc' : 'asc'} NULLS LAST, devices.id asc`);
    else q.orderBy('devices.id', 'asc');
    const rows = await q.select(SUMMARY_COLUMNS).limit(50_000);
    const rules = new RulesCache();
    const now = new Date();
    return Promise.all(rows.map((row: any) => this.toSummary(row, rules, thresholds, now)));
  }

  /** Counters of the facets (GET /api/mdm/devices/facets): platform, ownership, states, OS version, model, tag. */
  async getFacets(tenantId: number, view?: TenantView, visibleIds?: number[] | 'all'): Promise<DeviceFacets> {
    const base = () => {
      const q = db('devices');
      if (!isGlobalView(tenantId, view)) q.where('devices.tenant_id', tenantId);
      if (visibleIds !== undefined && visibleIds !== 'all') {
        if (visibleIds.length === 0) q.whereRaw('false');
        else q.whereIn('devices.id', visibleIds);
      }
      return q;
    };
    const count = async (col: string) => (await base().groupBy(col).select(`${col} as value`)
      .count<{ value: string; n: string }[]>('devices.id as n').orderBy('n', 'desc').orderBy('value', 'asc'))
      .filter((r) => r.value !== null && r.value !== undefined)
      .map((r) => ({ value: String(r.value), count: Number(r.n) }));
    const os = await base().whereNotNull('devices.os_version').groupBy('devices.platform', 'devices.os_version')
      .select('devices.platform', 'devices.os_version').count<{ platform: string; os_version: string; n: string }[]>('devices.id as n')
      .orderBy('devices.platform').orderBy('devices.os_version');
    const tagRows = await base()
      .joinRaw("CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(devices.tags, '[]'::jsonb)) AS t(tag)")
      .groupByRaw('t.tag').select(db.raw('t.tag AS value')).count<{ value: string; n: string }[]>('devices.id as n')
      .orderBy('n', 'desc').orderBy('value', 'asc');
    return {
      platform: await count('devices.platform'),
      ownership: await count('devices.ownership'),
      enrollmentState: await count('devices.enrollment_state'),
      complianceState: await count('devices.compliance_state'),
      configState: await count('devices.config_state'),
      osVersion: os.map((r) => ({ platform: r.platform, value: r.os_version, count: Number(r.n) })),
      model: await count('devices.model_name'),
      tag: tagRows.map((r) => ({ value: String(r.value), count: Number(r.n) })),
    };
  }

  /** Is the device reachable (the request's tenant, or any tenant in the global view)? */
  async deviceExists(id: number, tenantId: number, view?: TenantView): Promise<boolean> {
    if (!Number.isSafeInteger(id) || id <= 0) return false;
    const q = db('devices').where({ id });
    if (!isGlobalView(tenantId, view)) q.where({ tenant_id: tenantId });
    return !!(await q.first('id'));
  }

  /** The record of one device (GET /api/mdm/devices/:id), or null when it is out of reach. */
  async getDeviceById(id: number, tenantId: number, view?: TenantView): Promise<DeviceDetail | null> {
    if (!Number.isSafeInteger(id) || id <= 0) return null;
    const q = this.baseQuery().where('devices.id', id);
    if (!isGlobalView(tenantId, view)) q.where('devices.tenant_id', tenantId);
    const row = await q.first([...SUMMARY_COLUMNS, ...DETAIL_COLUMNS]);
    if (!row) return null;
    const deviceTenant = Number(row.tenant_id);
    const rules = new RulesCache();
    const thresholds = await staleAfterDaysOf([deviceTenant]);
    const summary = await this.toSummary(row, rules, thresholds, new Date());
    const r = await rules.get(deviceTenant, row.ownership, row.management_mode);
    const detail: DeviceDetail = {
      ...summary,
      description: row.description ?? null,
      customFields: asObject(row.custom_fields),
      osBuild: row.os_build ?? null,
      storageCapacityBytes: row.storage_capacity_bytes === null || row.storage_capacity_bytes === undefined ? null : Number(row.storage_capacity_bytes),
      storageAvailableBytes: row.storage_available_bytes === null || row.storage_available_bytes === undefined ? null : Number(row.storage_available_bytes),
      unenrolledAt: iso(row.unenrolled_at),
      unenrollReason: row.unenroll_reason ?? null,
      asset: {
        purchaseDate: row.purchase_date ? iso(row.purchase_date)!.slice(0, 10) : null,
        warrantyExpiry: row.warranty_expiry ? iso(row.warranty_expiry)!.slice(0, 10) : null,
        warrantyVendor: row.warranty_vendor ?? null,
        warrantyStatus: row.warranty_status ?? null,
        expectedLifetimeYears: row.expected_lifetime_years ?? null,
        lifecycleStatus: row.lifecycle_status ?? null,
      },
      enrollmentProfileId: row.enrollment_profile_id ?? null,
      privacy: { collected: collectedFields(r) },
    };
    if (r.storeDeviceName) detail.deviceName = row.device_name ?? null;
    const apple = await db('apple_devices').where({ device_id: id, tenant_id: deviceTenant }).first(
      'nano_enroll_type', 'proof', 'cert_not_after', 'identity_state', 'push_state', 'has_unlock_token',
      'activation_lock_enabled', 'find_my_enabled', 'activation_lock_bypass_ref', 'ddm_enabled', 'imei', 'udid',
      'last_device_info_at', 'last_security_info_at', 'last_apps_at', 'last_profiles_at', 'last_certificates_at',
    );
    if (apple) {
      const a: AppleDeviceDetail = {
        enrollmentType: apple.nano_enroll_type, proof: apple.proof,
        certNotAfter: iso(apple.cert_not_after), identityState: apple.identity_state, pushState: apple.push_state,
        hasUnlockToken: !!apple.has_unlock_token,
        activationLockEnabled: apple.activation_lock_enabled ?? null, findMyEnabled: apple.find_my_enabled ?? null,
        activationLockBypassEscrowed: !!apple.activation_lock_bypass_ref, ddmEnabled: !!apple.ddm_enabled,
        lastInventory: {
          deviceInfo: iso(apple.last_device_info_at), securityInfo: iso(apple.last_security_info_at),
          apps: iso(apple.last_apps_at), profiles: iso(apple.last_profiles_at), certificates: iso(apple.last_certificates_at),
        },
      };
      if (r.storeHardwareIds) {
        a.imei = apple.imei ?? null;
        a.udid = apple.udid ?? null;
      }
      detail.apple = a;
    }
    return detail;
  }

  /**
   * The operator's edits of a device of `tenantId` (of any tenant for the global view: PATCH
   * /api/mdm/devices/:id). The group, the end user and the ownership have their own routes. Returns the
   * record, or null when the device is out of reach.
   */
  async updateDevice(id: number, tenantId: number, data: Partial<{
    displayName: string | null;
    description: string | null;
    tags: string[];
    customFields: Record<string, string>;
    purchaseDate: string | null;
    warrantyExpiry: string | null;
    warrantyVendor: string | null;
    warrantyStatus: string | null;
    expectedLifetimeYears: number | null;
    lifecycleStatus: string | null;
  }>, view?: TenantView): Promise<DeviceDetail | null> {
    const isMaster = isGlobalView(tenantId, view);
    const lookup = db('devices').where({ id });
    if (!isMaster) lookup.where({ tenant_id: tenantId });
    const current = await lookup.first('id', 'tenant_id') as { id: number; tenant_id: number } | undefined;
    if (!current) return null;
    const deviceTenantId = Number(current.tenant_id);

    const updates: Record<string, unknown> = { updated_at: new Date() };
    if (data.displayName !== undefined) updates.display_name = data.displayName === null ? null : String(data.displayName).slice(0, 500);
    if (data.description !== undefined) updates.description = data.description;
    if (data.tags !== undefined) updates.tags = JSON.stringify(data.tags);
    if (data.customFields !== undefined) updates.custom_fields = JSON.stringify(data.customFields);
    if (data.purchaseDate !== undefined) updates.purchase_date = data.purchaseDate;
    if (data.warrantyExpiry !== undefined) updates.warranty_expiry = data.warrantyExpiry;
    if (data.warrantyVendor !== undefined) updates.warranty_vendor = data.warrantyVendor;
    if (data.warrantyStatus !== undefined) updates.warranty_status = data.warrantyStatus;
    if (data.expectedLifetimeYears !== undefined) updates.expected_lifetime_years = data.expectedLifetimeYears;
    if (data.lifecycleStatus !== undefined) updates.lifecycle_status = data.lifecycleStatus;

    // Written in the device's own tenant (the one resolved above).
    await db('devices').where({ id, tenant_id: deviceTenantId }).update(updates);
    this.emitChanged(deviceTenantId, [id], isMaster && deviceTenantId !== tenantId ? tenantId : null);
    return this.getDeviceById(id, deviceTenantId);
  }

  /**
   * DEVICE_UPDATED to the device's tenant (identifiers only: integration I12, T-4); the global view's echo
   * goes to the master tenant's admin room (platform administrators), never to its plain members.
   */
  emitChanged(tenantId: number, deviceIds: number[], echoTenantId: number | null = null): void {
    if (!this.io || deviceIds.length === 0) return;
    for (const id of deviceIds) {
      this.io.to(`tenant:${tenantId}`).emit(SocketEvents.DEVICE_UPDATED, { deviceId: id, tenantId });
      if (echoTenantId !== null) this.io.to(`tenant:${echoTenantId}:admin`).emit(SocketEvents.DEVICE_UPDATED, { deviceId: id, tenantId });
    }
  }

  /**
   * Immediately purge the data tied to a deleted device that no database cascade removes with it
   * (polymorphic references). Only for the ids the tenant-scoped DELETE actually removed.
   */
  private async purgeDeviceData(id: number) {
    try { await db('reports').where({ scope_type: 'device', scope_id: id }).delete(); } catch { /* ignore */ }
  }

  /**
   * Deletes the records of `tenantId` among `ids` that are out of management (enrollment_state
   * 'unenrolled': a record under management is never deleted, devices_guard_delete refuses it), and purges
   * the data of those actually deleted. Returns their ids. The guard engine (device.delete) is the caller.
   */
  async bulkDelete(ids: number[], tenantId: number): Promise<number[]> {
    if (ids.length === 0) return [];
    const deleted = await db('devices').whereIn('id', ids).where({ tenant_id: tenantId, enrollment_state: 'unenrolled' })
      .delete(['id']) as Array<{ id: number }>;
    await Promise.all(deleted.map((r) => this.purgeDeviceData(r.id)));
    await this.resolveDeletedDeviceAlerts(deleted.map((r) => r.id));
    if (this.io) {
      for (const r of deleted) this.io.to(`tenant:${tenantId}`).emit(SocketEvents.DEVICE_DELETED, { id: r.id });
    }
    return deleted.map((r) => Number(r.id));
  }

  /** A deleted device can never recover: its active live-alert incidents are resolved. */
  private async resolveDeletedDeviceAlerts(ids: number[]) {
    if (ids.length === 0) return;
    try {
      const { liveAlertService } = await import('./liveAlert.service');
      await liveAlertService.resolveDeviceIncidents(ids);
    } catch (err) {
      logger.error({ err, count: ids.length }, 'resolving the live alerts of deleted devices failed');
    }
  }

  /**
   * Self-healing: delete orphaned records that reference devices no longer in the platform. Run by the
   * job devices.clean-orphans, tenant by tenant in the tenant's database context. The steps are
   * independent: one that fails does not skip the next, and the run then fails (partial_failure).
   */
  async cleanOrphans(tenantId: number) {
    let total = 0;
    let failed = 0;
    try {
      const c = await db.raw(`
        DELETE FROM reports
        WHERE tenant_id = ?
          AND scope_type = 'device'
          AND scope_id IS NOT NULL
          AND scope_id NOT IN (SELECT id FROM devices WHERE tenant_id = ?)
      `, [tenantId, tenantId]);
      total += c?.rowCount ?? 0;
    } catch (err) {
      failed++;
      logger.error({ err: safeErr(err), tenantId }, 'cleanOrphans: reports of deleted devices not removed');
    }
    try {
      const { liveAlertService } = await import('./liveAlert.service');
      const resolved = await liveAlertService.resolveOrphanIncidents(tenantId);
      if (resolved.length > 0) {
        logger.warn({ tenantId, count: resolved.length }, 'cleanOrphans: resolved live alerts of deleted devices');
      }
    } catch (err) {
      failed++;
      logger.error({ err: safeErr(err), tenantId }, 'cleanOrphans: live alerts of deleted devices not resolved');
    }
    if (total > 0) logger.warn({ tenantId, total }, 'cleanOrphans: self-healing complete');
    if (failed > 0) throw new JobError('partial_failure', 'one cleanup step failed');
  }

  // ─── Fleet summary and series (dashboard) ─────────────────────────────────

  /**
   * The fleet of `tenantId` (of every tenant for the global view, unless `strictTenantScope`: the
   * snapshot jobs store a tenant's own fleet, the series sum them). Counts the devices under management
   * (every state but 'unenrolled'); 'stale' = no contact for mdmStaleAfterDays days, or none 24 h after
   * the enrollment.
   */
  async getFleetSummary(tenantId: number, opts?: { strictTenantScope?: boolean; globalView?: boolean }): Promise<MdmFleetSummary> {
    const isMaster = isGlobalView(tenantId, opts) && !opts?.strictTenantScope;
    const scope: number[] | 'all' = isMaster ? 'all' : [tenantId];
    const thresholds = await this.thresholds(scope);
    const days = this.staleDaysSql(thresholds);
    const managed = () => {
      const q = db('devices').whereNot('devices.enrollment_state', 'unenrolled');
      if (!isMaster) q.where('devices.tenant_id', tenantId);
      return q;
    };
    const row = await managed().first(db.raw(`
      count(*)::int AS total,
      count(*) FILTER (WHERE enrollment_state = 'enrolled')::int AS enrolled,
      count(*) FILTER (WHERE enrollment_state = 'enrolling')::int AS enrolling,
      count(*) FILTER (WHERE enrollment_state = 'awaiting_configuration')::int AS awaiting,
      count(*) FILTER (WHERE enrollment_state = 'unenrolling')::int AS unenrolling,
      count(*) FILTER (WHERE compliance_state = 'compliant')::int AS compliant,
      count(*) FILTER (WHERE compliance_state = 'non_compliant')::int AS non_compliant,
      count(*) FILTER (WHERE compliance_state = 'unknown')::int AS compliance_unknown,
      count(*) FILTER (WHERE config_state = 'error')::int AS config_errors,
      count(*) FILTER (WHERE config_state = 'pending')::int AS config_pending,
      count(*) FILTER (WHERE lost_mode_state <> 'off')::int AS lost_mode,
      count(*) FILTER (WHERE last_checkin_at IS NULL)::int AS c_never,
      count(*) FILTER (WHERE last_checkin_at >= now() - interval '24 hours')::int AS c_recent,
      count(*) FILTER (WHERE last_checkin_at < now() - interval '24 hours'
                         AND last_checkin_at >= now() - make_interval(days => ${days.sql}))::int AS c_quiet,
      count(*) FILTER (WHERE last_checkin_at < now() - make_interval(days => ${days.sql}))::int AS c_stale,
      count(*) FILTER (WHERE last_checkin_at < now() - make_interval(days => ${days.sql})
                         OR (last_checkin_at IS NULL AND enrolled_at < now() - interval '24 hours'))::int AS stale`,
    [...days.bindings, ...days.bindings, ...days.bindings])) as Record<string, number>;
    const byPlatform: Record<string, number> = {};
    const byOwnership: Record<string, number> = {};
    const groups = await managed().groupBy('devices.platform', 'devices.ownership')
      .select('devices.platform', 'devices.ownership').count<{ platform: string; ownership: string; n: string }[]>('devices.id as n');
    for (const g of groups) {
      byPlatform[g.platform] = (byPlatform[g.platform] ?? 0) + Number(g.n);
      byOwnership[g.ownership] = (byOwnership[g.ownership] ?? 0) + Number(g.n);
    }
    // Deltas against yesterday's snapshot of the tenant (null without one: the console hides them).
    const yesterday = isMaster ? null : await db('fleet_daily_snapshot')
      .where({ tenant_id: tenantId })
      .where('day', '<', new Date().toISOString().slice(0, 10))
      .orderBy('day', 'desc')
      .first('total', 'enrolled', 'non_compliant', 'stale') as { total: number; enrolled: number; non_compliant: number; stale: number } | undefined;
    const delta = (now: number, before: number | undefined) => (yesterday && before !== undefined ? now - Number(before) : null);
    return {
      total: row.total, enrolled: row.enrolled, enrolling: row.enrolling, awaitingConfiguration: row.awaiting,
      unenrolling: row.unenrolling, compliant: row.compliant, nonCompliant: row.non_compliant,
      complianceUnknown: row.compliance_unknown, configErrors: row.config_errors, configPending: row.config_pending,
      contact: { never: row.c_never, recent: row.c_recent, quiet: row.c_quiet, stale: row.c_stale },
      stale: row.stale, lostMode: row.lost_mode,
      byPlatform, byOwnership,
      staleAfterDays: isMaster ? MDM_STALE_AFTER_DAYS_DEFAULT : (thresholds.get(tenantId) ?? MDM_STALE_AFTER_DAYS_DEFAULT),
      deltas: {
        totalVsYesterday: delta(row.total, yesterday?.total),
        enrolledVsYesterday: delta(row.enrolled, yesterday?.enrolled),
        nonCompliantVsYesterday: delta(row.non_compliant, yesterday?.non_compliant),
        staleVsYesterday: delta(row.stale, yesterday?.stale),
      },
    };
  }

  private static pointOf(at: string, s: MdmFleetSummary): MdmFleetPoint {
    return {
      at, total: s.total, enrolled: s.enrolled, enrolling: s.enrolling + s.awaitingConfiguration,
      compliant: s.compliant, nonCompliant: s.nonCompliant, configErrors: s.configErrors, stale: s.stale,
    };
  }

  private static seriesSums() {
    return [
      db.raw('SUM(total)::int AS total'), db.raw('SUM(enrolled)::int AS enrolled'), db.raw('SUM(enrolling)::int AS enrolling'),
      db.raw('SUM(compliant)::int AS compliant'), db.raw('SUM(non_compliant)::int AS non_compliant'),
      db.raw('SUM(config_errors)::int AS config_errors'), db.raw('SUM(stale)::int AS stale'),
    ];
  }

  /** The daily series of the last `days` days, the current day synthesised from the live state. */
  async getFleetTimeseries(tenantId: number, days: number, view?: TenantView): Promise<MdmFleetPoint[]> {
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    const cutoff = new Date(today.getTime() - (Math.max(1, days) - 1) * 86_400_000).toISOString().slice(0, 10);
    const isMaster = isGlobalView(tenantId, view);
    const q = db('fleet_daily_snapshot').where('day', '>=', cutoff).groupBy('day').orderBy('day', 'asc')
      .select('day', ...DeviceService.seriesSums());
    if (!isMaster) q.where({ tenant_id: tenantId });
    const rows = await q as Array<Record<string, any>>;
    const todayStr = today.toISOString().slice(0, 10);
    const live = DeviceService.pointOf(todayStr, await this.getFleetSummary(tenantId, { globalView: isMaster }));
    const points = rows
      .map((r) => ({ at: (r.day instanceof Date ? r.day.toISOString() : String(r.day)).slice(0, 10), total: r.total,
        enrolled: r.enrolled, enrolling: r.enrolling, compliant: r.compliant, nonCompliant: r.non_compliant,
        configErrors: r.config_errors, stale: r.stale }))
      .filter((p) => p.at !== todayStr);
    return [...points, live];
  }

  /** The hourly series of the last `hours` hours (7 days at most), the current hour synthesised. */
  async getFleetHourlySeries(tenantId: number, hours: number, view?: TenantView): Promise<MdmFleetPoint[]> {
    const cap = Math.min(168, Math.max(2, hours));
    const cutoff = new Date(Date.now() - cap * 3_600_000);
    const isMaster = isGlobalView(tenantId, view);
    const q = db('fleet_hourly_snapshot').where('hour', '>=', cutoff).groupBy('hour').orderBy('hour', 'asc')
      .select('hour', ...DeviceService.seriesSums());
    if (!isMaster) q.where({ tenant_id: tenantId });
    const rows = await q as Array<Record<string, any>>;
    const nowHour = new Date();
    nowHour.setMinutes(0, 0, 0);
    const live = DeviceService.pointOf(nowHour.toISOString(), await this.getFleetSummary(tenantId, { globalView: isMaster }));
    const points = rows
      .map((r) => ({ at: r.hour instanceof Date ? r.hour.toISOString() : new Date(String(r.hour)).toISOString(), total: r.total,
        enrolled: r.enrolled, enrolling: r.enrolling, compliant: r.compliant, nonCompliant: r.non_compliant,
        configErrors: r.config_errors, stale: r.stale }))
      .filter((p) => p.at !== live.at);
    return [...points, live];
  }

  /** The MDM counters of a snapshot row (the columns of the removed agent are no longer written). */
  private static snapshotRow(s: MdmFleetSummary) {
    return {
      total: s.total, enrolled: s.enrolled, enrolling: s.enrolling + s.awaitingConfiguration,
      compliant: s.compliant, non_compliant: s.nonCompliant, config_errors: s.configErrors, stale: s.stale,
    };
  }

  /** Hourly snapshot of a tenant's own fleet (job devices.fleet-hourly); 7 days kept. */
  async snapshotFleetHourly(tenantId: number) {
    const now = new Date();
    now.setMinutes(0, 0, 0);
    const summary = await this.getFleetSummary(tenantId, { strictTenantScope: true });
    await db('fleet_hourly_snapshot')
      .insert({ tenant_id: tenantId, hour: now, ...DeviceService.snapshotRow(summary) })
      .onConflict(['tenant_id', 'hour'])
      .merge();
    const cutoff = new Date(Date.now() - 7 * 86_400_000);
    await db('fleet_hourly_snapshot').where({ tenant_id: tenantId }).where('hour', '<', cutoff).del();
    logger.debug({ tenantId }, 'Fleet hourly snapshot complete');
  }

  /** Daily snapshot of a tenant's own fleet (job devices.fleet-daily). */
  async snapshotFleetDaily(tenantId: number) {
    const today = new Date().toISOString().slice(0, 10);
    const summary = await this.getFleetSummary(tenantId, { strictTenantScope: true });
    await db('fleet_daily_snapshot')
      .insert({ tenant_id: tenantId, day: today, ...DeviceService.snapshotRow(summary) })
      .onConflict(['tenant_id', 'day'])
      .merge();
    logger.debug({ tenantId }, 'Fleet daily snapshot complete');
  }
}

export const deviceService = new DeviceService();
