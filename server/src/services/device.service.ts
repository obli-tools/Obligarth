import { Server as SocketIOServer } from 'socket.io';
import { db } from '../db';
import { logger } from '../utils/logger';
import { AppError } from '../middleware/errorHandler';
import { SocketEvents, isMasterTenant } from '@obligarth/shared';
import type { Device, DeviceIdentityFingerprint } from '@obligarth/shared';
import type { TenantView } from './deviceScope.service';

/** The master tenant's global view, as the caller passed it (TenantView). */
function isGlobalView(tenantId: number, view?: TenantView): boolean {
  return !!view?.globalView && isMasterTenant(tenantId);
}

// JSONB columns come back as either an already-parsed array (pg's default
// when the driver knows it's JSONB) or as a raw string in some edge paths.
// This shim normalises both shapes to a typed array, defaulting to [] on
// corruption so a bad row never crashes the device read path.
function safeParseFingerprints(raw: string): DeviceIdentityFingerprint[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}

class DeviceService {
  private io: SocketIOServer | null = null;

  setIO(io: SocketIOServer) { this.io = io; }

  // ─── Row mapper ────────────────────────────────────────────────────────────
  // The fields the removed agent used to report (metrics, privacy mode,
  // airgap, watchdog, identity fingerprints…) are still mapped from their
  // columns: the shared Device type declares them. Nothing writes them any
  // more; they go with the future base migration.
  rowToDevice(row: any): Device {
    return {
      id: row.id,
      uuid: row.uuid,
      tenantId: row.tenant_id,
      // Surfaces only when the row was joined with `tenants` (master/god
      // view queries do this so the UI can group devices by tenant).
      tenantName: row.tenant_name ?? null,
      groupId: row.group_id,
      apiKeyId: row.api_key_id,
      hostname: row.hostname,
      displayName: row.display_name,
      description: row.description,
      ipLocal: row.ip_local,
      ipPublic: row.ip_public,
      macAddress: row.mac_address,
      osType: row.os_type,
      osName: row.os_name,
      osVersion: row.os_version,
      osBuild: row.os_build,
      osArch: row.os_arch,
      cpuModel: row.cpu_model,
      cpuCores: row.cpu_cores,
      ramTotalGb: row.ram_total_gb,
      agentVersion: row.agent_version,
      // No agent on this server: never an agent update to offer.
      updateAvailable: false,
      status: row.status,
      approvalStatus: row.approval_status,
      approvedBy: row.approved_by,
      approvedAt: row.approved_at,
      lastSeenAt: row.last_seen_at,
      lastPushAt: row.last_push_at,
      pushIntervalSeconds: row.push_interval_seconds,
      scanIntervalSeconds: row.scan_interval_seconds ?? null,
      overrideGroupSettings: row.override_group_settings,
      maxMissedPushes: row.max_missed_pushes,
      complianceRemediationEnabled: row.compliance_remediation_enabled ?? true,
      privacyModeEnabled: row.privacy_mode_enabled ?? false,
      privacyPasswordSet: row.privacy_password_set ?? false,
      privacyPasswordSetAt: row.privacy_password_set_at ?? null,
      airgapEnabled: row.airgap_enabled ?? false,
      airgapEnabledAt: row.airgap_enabled_at ?? null,
      virtualizationHostType: row.virtualization_host_type ?? null,
      backupHostType: row.backup_host_type ?? null,
      watchdogRestartCount: row.watchdog_restart_count ?? 0,
      watchdogLastRestartAt: row.watchdog_last_restart_at ?? null,
      agentFlavor: (row.agent_flavor ?? 'modern') as 'modern' | 'legacy',
      lastLoggedInUser: row.last_logged_in_user ?? null,
      lastRebootAt: row.last_reboot_at ?? null,
      rebootPending: row.reboot_pending ?? false,
      timezone: row.timezone ?? null,
      tags: row.tags || [],
      customFields: row.custom_fields || {},
      thresholdsOverride: row.thresholds_override
        ? (typeof row.thresholds_override === 'string' ? JSON.parse(row.thresholds_override) : row.thresholds_override)
        : {},
      metricAlertsEnabled: typeof row.metric_alerts_enabled === 'boolean' ? row.metric_alerts_enabled : null,
      displayConfig: row.display_config || {},
      sensorDisplayNames: row.sensor_display_names || {},
      notificationTypes: row.notification_types || {},
      latestMetrics: row.latest_metrics || {},
      peakMetrics: row.peak_metrics || null,
      geoLat: row.geo_lat ? parseFloat(row.geo_lat) : null,
      geoLng: row.geo_lng ? parseFloat(row.geo_lng) : null,
      geoCity: row.geo_city ?? null,
      geoCountry: row.geo_country ?? null,
      geoRegion: row.geo_region ?? null,
      purchaseDate: row.purchase_date ?? null,
      warrantyExpiry: row.warranty_expiry ?? null,
      warrantyVendor: row.warranty_vendor ?? null,
      warrantyStatus: row.warranty_status ?? 'unknown',
      expectedLifetimeYears: row.expected_lifetime_years ?? null,
      lifecycleStatus: row.lifecycle_status ?? 'unknown',
      scheduleAlert: row.schedule_alert ? (typeof row.schedule_alert === 'string' ? JSON.parse(row.schedule_alert) : row.schedule_alert) : null,
      uninstallAt: row.uninstall_at ? new Date(row.uninstall_at).toISOString() : null,
      identityFingerprints: Array.isArray(row.identity_fingerprints)
        ? row.identity_fingerprints
        : (typeof row.identity_fingerprints === 'string' ? safeParseFingerprints(row.identity_fingerprints) : []),
      duplicateAgentIdSuspected: row.duplicate_agent_id_suspected ?? false,
      duplicateAgentIdAcknowledgedAt: row.duplicate_agent_id_acknowledged_at
        ? new Date(row.duplicate_agent_id_acknowledged_at).toISOString()
        : null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  // ─── CRUD ─────────────────────────────────────────────────────────────────
  async getDevices(tenantId: number, filters?: {
    groupId?: number; includeSubgroups?: boolean; status?: string; approvalStatus?: string;
    search?: string; osType?: string; page?: number; pageSize?: number;
    sortBy?: string; sortOrder?: 'asc' | 'desc';
    /** When true, only return devices with NULL group_id (the "Ungrouped"
     *  pseudo-group in the sidebar). Takes precedence over groupId. */
    ungrouped?: boolean;
    /** Dashboard hero "Injoignables 72h" → /devices?stale=72. Filter rows
     *  whose last_seen_at is older than the threshold (in hours). */
    staleHours?: number;
    /** Lot C 3-tier OS filter: marketing name (e.g. "Microsoft Windows 10
     *  IoT Enterprise LTSC 2021"). Accepts a single string (legacy
     *  single-select callers) OR an array of strings — multi-select
     *  in the DeviceTable picker. Translated to a WHERE IN clause. */
    osName?: string | string[];
    /** Lot C 3-tier OS filter: build / version string (e.g.
     *  "10.0.19044.7184"). Same single/multi semantics as osName. */
    osVersion?: string | string[];
    /** Restrict to devices carrying ANY of these tags (OR semantics).
     *  Empty/missing means no filter. Tags are matched against the
     *  JSONB array stored on `devices.tags`. */
    tags?: string[];
    /** Master-only: narrow the god-view to a subset of tenants. Sent
     *  by the DeviceTable tenant chips so the master admin can focus
     *  on one customer without losing the cross-tenant view they're
     *  attached to. Ignored without the global view. */
    tenantIds?: number[];
  }, view?: TenantView): Promise<{ items: Device[]; total: number; page: number; pageSize: number }> {
    const page = Math.max(1, filters?.page ?? 1);
    // Cap is intentionally high to support the sidebar which needs to render
    // the entire approved fleet in one request. Callers that paginate the
    // UI (DeviceTable) still use reasonable page sizes from the UI controls.
    const pageSize = Math.min(10000, Math.max(1, filters?.pageSize ?? 100));

    // The global view (platform administrator on the master tenant) drops
    // the tenant_id filter; `tenants` is joined so each row carries a
    // `tenant_name` for the UI to group/sort by. Every other caller stays
    // strictly scoped, on the master tenant too.
    const isMaster = isGlobalView(tenantId, view);
    let q = db('devices')
      .leftJoin('device_groups', 'devices.group_id', 'device_groups.id')
      .leftJoin('tenants', 'devices.tenant_id', 'tenants.id');
    if (!isMaster) q = q.where({ 'devices.tenant_id': tenantId });
    // Global-view narrow filter: subset of tenants. Silently dropped
    // for every other caller so a crafted query can't widen scope.
    if (isMaster && Array.isArray(filters?.tenantIds) && filters!.tenantIds!.length > 0) {
      q = q.whereIn('devices.tenant_id', filters!.tenantIds!.map(Number).filter(Number.isFinite));
    }
    // Never show pending_uninstall devices in normal listings
    q = q.whereNot({ 'devices.status': 'pending_uninstall' });
    if (filters?.ungrouped) {
      // "Ungrouped" pseudo-filter — devices without any group. Takes
      // precedence over groupId so an accidental ungrouped=true+groupId
      // combination stays predictable.
      q = q.whereNull('devices.group_id');
    } else if (filters?.groupId) {
      if (filters.includeSubgroups) {
        // Include devices from all descendant groups via closure table
        const descendants = await db('device_group_closure')
          .where('ancestor_id', filters.groupId)
          .select('descendant_id');
        const allGroupIds = [filters.groupId, ...descendants.map((d: any) => d.descendant_id)];
        q = q.whereIn('devices.group_id', allGroupIds);
      } else {
        q = q.where({ 'devices.group_id': filters.groupId });
      }
    }
    if (filters?.status === 'connected') {
      // Virtual status used by the dashboard "En ligne" KPI link —
      // expands to every reachable status (online / warning / critical /
      // updating). Keeps the URL ?status=connected human-friendly without
      // burning a dedicated multi-value query parameter convention.
      q = q.whereIn('devices.status', ['online', 'warning', 'critical', 'updating']);
    } else if (filters?.status === 'disconnected') {
      // Virtual status for the dashboard "Hors ligne" KPI link — offline
      // and update_error (an update that never completed).
      q = q.whereIn('devices.status', ['offline', 'update_error']);
    } else if (filters?.status === 'outdated') {
      // Former virtual status of the "agent update available" link: no agent
      // on this server, so no device matches (and the value never reaches
      // the device_status enum).
      q = q.whereRaw('false');
    } else if (filters?.status) {
      q = q.where({ 'devices.status': filters.status });
    }
    if (filters?.osType) q = q.where({ 'devices.os_type': filters.osType });
    if (filters?.osName) {
      const arr = Array.isArray(filters.osName) ? filters.osName : [filters.osName];
      if (arr.length === 1) q = q.where({ 'devices.os_name': arr[0] });
      else if (arr.length > 1) q = q.whereIn('devices.os_name', arr);
    }
    if (filters?.osVersion) {
      const arr = Array.isArray(filters.osVersion) ? filters.osVersion : [filters.osVersion];
      if (arr.length === 1) q = q.where({ 'devices.os_version': arr[0] });
      else if (arr.length > 1) q = q.whereIn('devices.os_version', arr);
    }
    if (filters?.approvalStatus === 'suspended') {
      q = q.where({ 'devices.status': 'suspended' });
    } else if (filters?.approvalStatus) {
      q = q.where({ 'devices.approval_status': filters.approvalStatus });
    }
    if (typeof filters?.staleHours === 'number' && filters.staleHours > 0) {
      const cutoff = new Date(Date.now() - filters.staleHours * 60 * 60 * 1000);
      q = q.where('devices.last_seen_at', '<', cutoff);
    }
    // Tags filter — `tags` is a JSONB array of strings on the
    // devices table. The Postgres `?|` operator returns true when
    // the JSONB value contains ANY of the given keys, which is the
    // OR-semantics we want for the chip-style filter ("show devices
    // with any of these tags"). The `?|` operator collides with
    // knex's own `?` parameter placeholder, so we escape it as
    // `\\?|`. The text[] cast lets us pass a JS array directly.
    if (Array.isArray(filters?.tags) && filters!.tags.length > 0) {
      q = q.whereRaw('devices.tags \\?| ?::text[]', [filters!.tags]);
    }
    if (filters?.search) q = q.where(function() {
      const pat = `%${filters.search}%`;
      // devices.uuid is the PG `uuid` type — ILIKE refuses to match it
      // directly, so cast to text. devices.tags is a JSONB array, also
      // cast to text so a substring match across all tag values works.
      // Other columns are varchar / text — plain ILIKE is fine.
      this.whereILike('devices.hostname', pat)
          .orWhereILike('devices.display_name', pat)
          .orWhereILike('devices.ip_local', pat)
          .orWhereILike('devices.ip_public', pat)
          .orWhereILike('devices.mac_address', pat)
          .orWhereILike('devices.last_logged_in_user', pat)
          .orWhereILike('devices.os_name', pat)
          .orWhereILike('devices.os_version', pat)
          .orWhereILike('devices.geo_city', pat)
          .orWhereILike('devices.geo_country', pat)
          .orWhereILike('devices.description', pat)
          .orWhereRaw('devices.uuid::text ILIKE ?', [pat])
          .orWhereRaw('devices.tags::text ILIKE ?', [pat]);
    });

    const countResult = await q.clone().count('devices.id as count').first();
    const total = Number(countResult?.count ?? 0);

    // Sortable columns. Empty/missing (or unknown) sortBy falls back to the
    // device's enrolment order (devices.id ASC), which is "the order they
    // were added" — the user expects this default rather than alpha-sort by
    // hostname when no explicit sort column is selected.
    const SORT_MAP: Record<string, string> = {
      name: 'devices.hostname', status: 'devices.status', os: 'devices.os_type',
      lastSeen: 'devices.last_seen_at', group: 'device_groups.name',
    };
    const sortDir = filters?.sortOrder === 'desc' ? 'desc' : 'asc';

    // Sort by name = sort by the DISPLAYED label (display name, falling back to
    // hostname when empty) so the table order matches the sidebar / dashboard
    // (e.g. "003-WEB, 015-DB, 017-APP" rather than raw hostname
    // order APP/DB/WEB).
    const nameSortExpr = `COALESCE(NULLIF(devices.display_name, ''), devices.hostname)`;

    // Sort by status = visual priority, NOT the raw enum string (whose
    // alphabetical order is meaningless). Mirrors the sidebar tiers:
    //   critical > warning > updating > other > offline > online
    // Offline is the lowest before online on purpose (a workstation powering
    // off is normal). asc → most-urgent first.
    const statusSortExpr = `CASE devices.status
        WHEN 'critical' THEN 0
        WHEN 'warning' THEN 1
        WHEN 'updating' THEN 2
        WHEN 'offline' THEN 4
        WHEN 'online' THEN 5
        ELSE 3 END`;

    let qOrdered = q;
    if (filters?.sortBy === 'name') {
      qOrdered = qOrdered.orderByRaw(`${nameSortExpr} ${sortDir}`);
    } else if (filters?.sortBy === 'status') {
      qOrdered = qOrdered.orderByRaw(`${statusSortExpr} ${sortDir}, ${nameSortExpr} asc`);
    } else if (filters?.sortBy && SORT_MAP[filters.sortBy]) {
      qOrdered = qOrdered.orderBy(SORT_MAP[filters.sortBy], sortDir);
    } else {
      // No explicit sort → enrolment order (devices.id ASC).
      qOrdered = qOrdered.orderBy('devices.id', 'asc');
    }

    const rows = await qOrdered
      .select('devices.*', 'device_groups.name as group_name', 'tenants.name as tenant_name')
      .limit(pageSize).offset((page - 1) * pageSize);

    const items = rows.map((row: any) => {
      const device = this.rowToDevice(row);
      (device as any).groupName = row.group_name ?? null;
      return device;
    });

    return { items, total, page, pageSize };
  }

  /** Legacy non-paginated list — used by sidebar and internal calls. */
  async getDevicesList(tenantId: number, filters?: { groupId?: number; status?: string; approvalStatus?: string; search?: string }, view?: TenantView): Promise<Device[]> {
    const result = await this.getDevices(tenantId, { ...filters, page: 1, pageSize: 10000 }, view);
    return result.items;
  }

  /**
   * Export-oriented query: same filter semantics as getDevices but no
   * pagination cap, returns every matching row. Used by the /export endpoint
   * to emit a full CSV/XLSX/PDF regardless of how many pages the UI is on.
   */
  async exportDevices(tenantId: number, filters?: {
    groupId?: number; includeSubgroups?: boolean; status?: string; approvalStatus?: string;
    search?: string; osType?: string; sortBy?: string; sortOrder?: 'asc' | 'desc';
    ungrouped?: boolean;
  }): Promise<Device[]> {
    let q = db('devices')
      .leftJoin('device_groups', 'devices.group_id', 'device_groups.id')
      .where({ 'devices.tenant_id': tenantId });
    q = q.whereNot({ 'devices.status': 'pending_uninstall' });
    if (filters?.ungrouped) {
      q = q.whereNull('devices.group_id');
    } else if (filters?.groupId) {
      if (filters.includeSubgroups) {
        const descendants = await db('device_group_closure')
          .where('ancestor_id', filters.groupId)
          .select('descendant_id');
        const allGroupIds = [filters.groupId, ...descendants.map((d: any) => d.descendant_id)];
        q = q.whereIn('devices.group_id', allGroupIds);
      } else {
        q = q.where({ 'devices.group_id': filters.groupId });
      }
    }
    if (filters?.status === 'connected') {
      // Virtual status used by the dashboard "En ligne" KPI link —
      // expands to every reachable status (online / warning / critical /
      // updating). Keeps the URL ?status=connected human-friendly without
      // burning a dedicated multi-value query parameter convention.
      q = q.whereIn('devices.status', ['online', 'warning', 'critical', 'updating']);
    } else if (filters?.status === 'disconnected') {
      // Virtual status for the dashboard "Hors ligne" KPI link — offline
      // and update_error (an update that never completed).
      q = q.whereIn('devices.status', ['offline', 'update_error']);
    } else if (filters?.status === 'outdated') {
      // Former "agent update available" virtual status: nothing matches (see getDevices).
      q = q.whereRaw('false');
    } else if (filters?.status) {
      q = q.where({ 'devices.status': filters.status });
    }
    if (filters?.osType) q = q.where({ 'devices.os_type': filters.osType });
    if (filters?.approvalStatus === 'suspended') {
      q = q.where({ 'devices.status': 'suspended' });
    } else if (filters?.approvalStatus) {
      q = q.where({ 'devices.approval_status': filters.approvalStatus });
    }
    if (filters?.search) q = q.where(function() {
      const pat = `%${filters.search}%`;
      // devices.uuid is the PG `uuid` type — ILIKE refuses to match it
      // directly, so cast to text. devices.tags is a JSONB array, also
      // cast to text so a substring match across all tag values works.
      // Other columns are varchar / text — plain ILIKE is fine.
      this.whereILike('devices.hostname', pat)
          .orWhereILike('devices.display_name', pat)
          .orWhereILike('devices.ip_local', pat)
          .orWhereILike('devices.ip_public', pat)
          .orWhereILike('devices.mac_address', pat)
          .orWhereILike('devices.last_logged_in_user', pat)
          .orWhereILike('devices.os_name', pat)
          .orWhereILike('devices.os_version', pat)
          .orWhereILike('devices.geo_city', pat)
          .orWhereILike('devices.geo_country', pat)
          .orWhereILike('devices.description', pat)
          .orWhereRaw('devices.uuid::text ILIKE ?', [pat])
          .orWhereRaw('devices.tags::text ILIKE ?', [pat]);
    });

    const SORT_MAP: Record<string, string> = {
      name: 'devices.hostname', status: 'devices.status', os: 'devices.os_type',
      lastSeen: 'devices.last_seen_at', group: 'device_groups.name',
    };
    const sortDir = filters?.sortOrder === 'desc' ? 'desc' : 'asc';
    // Same default as getDevices: empty/missing sortBy → enrolment order.
    // Name sorts by the displayed label (display name → hostname), matching the
    // table / sidebar order.
    const sortCol = (filters?.sortBy && SORT_MAP[filters.sortBy]) ? SORT_MAP[filters.sortBy] : 'devices.id';
    const exportDir = (filters?.sortBy && SORT_MAP[filters.sortBy]) ? sortDir : 'asc';

    let rowsQuery = q.select('devices.*', 'device_groups.name as group_name');
    if (filters?.sortBy === 'name') {
      rowsQuery = rowsQuery.orderByRaw(`COALESCE(NULLIF(devices.display_name, ''), devices.hostname) ${sortDir}`);
    } else if (filters?.sortBy === 'status') {
      // Visual priority, mirroring getDevices / the sidebar (offline lowest
      // before online), not the meaningless raw-enum alphabetical order.
      rowsQuery = rowsQuery.orderByRaw(`CASE devices.status
          WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 WHEN 'updating' THEN 2
          WHEN 'offline' THEN 4 WHEN 'online' THEN 5 ELSE 3 END ${sortDir},
          COALESCE(NULLIF(devices.display_name, ''), devices.hostname) asc`);
    } else {
      rowsQuery = rowsQuery.orderBy(sortCol, exportDir);
    }
    const rows = await rowsQuery;

    return rows.map((row: any) => {
      const device = this.rowToDevice(row);
      (device as any).groupName = row.group_name ?? null;
      return device;
    });
  }

  async getDeviceById(id: number, tenantId: number, view?: TenantView): Promise<Device | null> {
    // The global view reaches a device of any tenant; every other caller
    // only the devices of `tenantId`. We always join `tenants` so the row
    // carries `tenant_name` for the UI in both modes.
    const isMaster = isGlobalView(tenantId, view);
    const q = db('devices')
      .leftJoin('tenants', 'devices.tenant_id', 'tenants.id')
      .where('devices.id', id)
      .select('devices.*', 'tenants.name as tenant_name');
    if (!isMaster) q.where('devices.tenant_id', tenantId);
    const row = await q.first();
    if (!row) return null;
    return this.rowToDevice(row);
  }

  async getDeviceByUuid(uuid: string, tenantId: number, view?: TenantView): Promise<Device | null> {
    const isMaster = isGlobalView(tenantId, view);
    const q = db('devices').where({ uuid });
    if (!isMaster) q.where({ tenant_id: tenantId });
    const row = await q.first();
    return row ? this.rowToDevice(row) : null;
  }

  /**
   * Updates a device of `tenantId` (of any tenant for the global view: the
   * pencil of /devices renames across tenants). Returns null when the
   * device is not reachable. A group is always one of the DEVICE's tenant:
   * another tenant's group answers like an unknown one (404), since a
   * device placed in another tenant's tree would hand that tenant's teams a
   * scope on it through the closure.
   */
  async updateDevice(id: number, tenantId: number, data: Partial<{
    displayName: string;
    description: string;
    groupId: number | null;
    tags: string[];
    customFields: Record<string, string>;
    purchaseDate: string | null;
    warrantyExpiry: string | null;
    warrantyVendor: string | null;
    warrantyStatus: string | null;
    expectedLifetimeYears: number | null;
    lifecycleStatus: string | null;
  }>, view?: TenantView) {
    const isMaster = isGlobalView(tenantId, view);
    const lookup = db('devices').where({ id });
    if (!isMaster) lookup.where({ tenant_id: tenantId });
    const current = await lookup.first('id', 'tenant_id') as { id: number; tenant_id: number } | undefined;
    if (!current) return null;
    const deviceTenantId = Number(current.tenant_id);

    let groupId: number | null | undefined;
    if (data.groupId === null) {
      groupId = null;
    } else if (data.groupId !== undefined) {
      const gid = Number(data.groupId);
      const group = Number.isSafeInteger(gid) && gid > 0
        ? await db('device_groups').where({ id: gid, tenant_id: deviceTenantId }).first('id')
        : undefined;
      if (!group) throw new AppError(404, 'Group not found');
      groupId = gid;
    }

    const updates: any = { updated_at: new Date() };
    if (data.displayName !== undefined) updates.display_name = data.displayName;
    if (data.description !== undefined) updates.description = data.description;
    if (groupId !== undefined) updates.group_id = groupId;
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
    const updated = await this.getDeviceById(id, deviceTenantId);
    if (updated && this.io) {
      // Emit on the OWNING tenant's room so the device's home tenant
      // sees the live change too — not just the master room.
      this.io.to(`tenant:${updated.tenantId}`).emit(SocketEvents.DEVICE_UPDATED, updated);
      if (isMaster && updated.tenantId !== tenantId) {
        this.io.to(`tenant:${tenantId}`).emit(SocketEvents.DEVICE_UPDATED, updated);
      }
    }
    return updated;
  }

  // The state changes below (approve, refuse, suspend, unsuspend, delete)
  // reach the devices of `tenantId` only — never through the global view —
  // and return null (false for a deletion) when the device is not there.

  async approveDevice(id: number, tenantId: number, approvedBy: number) {
    const deviceRow = await db('devices').where({ id, tenant_id: tenantId }).first('id', 'group_id', 'api_key_id');
    if (!deviceRow) return null;
    // Check if the device's API key has a default group — adopted only when
    // it is a group of the device's own tenant.
    let groupId = deviceRow.group_id;
    if (!groupId && deviceRow.api_key_id) {
      const keyRow = await db('agent_api_keys as k')
        .join('device_groups as g', 'g.id', 'k.default_group_id')
        .where({ 'k.id': deviceRow.api_key_id, 'g.tenant_id': tenantId })
        .first('g.id as group_id') as { group_id: number } | undefined;
      if (keyRow?.group_id) groupId = keyRow.group_id;
    }

    await db('devices').where({ id, tenant_id: tenantId }).update({
      approval_status: 'approved',
      status: 'offline',
      approved_by: approvedBy,
      approved_at: new Date(),
      group_id: groupId ?? null,
      updated_at: new Date(),
    });
    const device = await this.getDeviceById(id, tenantId);
    if (device && this.io) {
      this.io.to(`tenant:${tenantId}`).emit(SocketEvents.DEVICE_APPROVED, device);
    }
    return device;
  }

  async refuseDevice(id: number, tenantId: number) {
    const changed = await db('devices').where({ id, tenant_id: tenantId }).update({
      approval_status: 'refused',
      status: 'suspended',
      updated_at: new Date(),
    });
    return changed ? this.getDeviceById(id, tenantId) : null;
  }

  async suspendDevice(id: number, tenantId: number) {
    const changed = await db('devices').where({ id, tenant_id: tenantId }).update({
      status: 'suspended',
      updated_at: new Date(),
    });
    return changed ? this.getDeviceById(id, tenantId) : null;
  }

  async unsuspendDevice(id: number, tenantId: number) {
    const changed = await db('devices').where({ id, tenant_id: tenantId }).update({
      status: 'offline',
      updated_at: new Date(),
    });
    return changed ? this.getDeviceById(id, tenantId) : null;
  }

  /**
   * Immediately purge the data tied to a hard-deleted device that no DB-level
   * CASCADE removes with it (polymorphic references), so no orphaned rows
   * remain. Only for the ids the tenant-scoped DELETE actually removed: an
   * id of another tenant's device never reaches it.
   */
  private async purgeDeviceData(id: number) {
    try { await db('reports').where({ scope_type: 'device', scope_id: id }).delete(); } catch { /* ignore */ }
  }

  /** Deletes a device of `tenantId`; false when it is not there. */
  async deleteDevice(id: number, tenantId: number): Promise<boolean> {
    const deleted = await db('devices').where({ id, tenant_id: tenantId }).delete(['id']) as Array<{ id: number }>;
    if (deleted.length === 0) return false;
    await Promise.all(deleted.map((r) => this.purgeDeviceData(r.id)));
    await this.resolveDeletedDeviceAlerts(deleted.map((r) => r.id));
    if (this.io) {
      this.io.to(`tenant:${tenantId}`).emit(SocketEvents.DEVICE_DELETED, { id });
    }
    return true;
  }

  /**
   * A deleted device can never recover: its active live-alert incidents
   * (offline, metric, disk health, duplicate id) are resolved so they leave
   * the web bell and the mobile "À traiter" instead of staying listed for
   * good. cleanOrphans catches any path that misses this.
   */
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
   * Self-healing: delete orphaned records that reference devices no longer
   * in the platform. Runs periodically so the DB stays consistent even if
   * a polymorphic reference (scope_id) has no FK at the DB level.
   */
  async cleanOrphans() {
    let total = 0;

    // Polymorphic references (no DB FK — must be cleaned in code)
    try {
      const c = await db.raw(`
        DELETE FROM reports
        WHERE scope_type = 'device'
          AND scope_id IS NOT NULL
          AND scope_id NOT IN (SELECT id FROM devices)
      `);
      total += c?.rowCount ?? 0;
    } catch { /* ignore */ }

    // Live alerts: active incident rows of devices that no longer exist are
    // resolved (NOT deleted — resolved rows age out through the trim).
    try {
      const { liveAlertService } = await import('./liveAlert.service');
      const resolved = await liveAlertService.resolveOrphanIncidents();
      if (resolved.length > 0) {
        logger.warn({ count: resolved.length }, 'cleanOrphans: resolved live alerts of deleted devices');
      }
    } catch (err) {
      logger.error(err, 'cleanOrphans: resolving orphaned live alerts failed');
    }

    if (total > 0) {
      logger.warn({ total }, 'cleanOrphans: self-healing complete');
    }
  }

  async bulkApprove(ids: number[], tenantId: number, approvedBy: number) {
    // Approve each device individually so default group from API key is assigned
    for (const id of ids) {
      await this.approveDevice(id, tenantId, approvedBy);
    }
  }

  /**
   * Deletes the devices of `tenantId` among `ids` (the others are skipped,
   * untouched) and purges the data of those actually deleted. Returns their
   * ids. The restriction matrix is the caller's (DELETE /bulk/delete).
   */
  async bulkDelete(ids: number[], tenantId: number): Promise<number[]> {
    if (ids.length === 0) return [];
    const deleted = await db('devices').whereIn('id', ids).where({ tenant_id: tenantId }).delete(['id']) as Array<{ id: number }>;
    await Promise.all(deleted.map((r) => this.purgeDeviceData(r.id)));
    await this.resolveDeletedDeviceAlerts(deleted.map((r) => r.id));
    if (this.io) {
      for (const r of deleted) this.io.to(`tenant:${tenantId}`).emit(SocketEvents.DEVICE_DELETED, { id: r.id });
    }
    return deleted.map((r) => Number(r.id));
  }

  // ─── Inventory pruning ────────────────────────────────────────────────────
  async pruneInventory() {
    try {
      const cfg = await db('app_config').where({ key: 'inventory_retention_days' }).first();
      const days = parseInt(cfg?.value || '90');
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

      // Keep only latest hardware snapshot per device
      // Delete old software scans
      await db('device_inventory_software')
        .where('scanned_at', '<', cutoff)
        .delete();

      logger.info({ days }, 'Inventory pruning complete');
    } catch (err) {
      logger.error(err, 'Error in inventory pruning job');
    }
  }

  // ─── OS facets (Lot C 3-tier filter) ──────────────────────────────────────
  // Returns the (osType, osName, osVersion) triplets present in the tenant's
  // approved fleet, with a count of matching devices for each. The client
  // uses these to populate the cascading filter dropdowns and to hide
  // options that no longer have any devices behind them.
  async getOsFacets(tenantId: number, view?: TenantView): Promise<Array<{
    osType: string; osName: string | null; osVersion: string | null; count: number;
  }>> {
    const isMaster = isGlobalView(tenantId, view);
    const q = db('devices')
      .where({ approval_status: 'approved' })
      .whereNot({ status: 'pending_uninstall' })
      .select('os_type', 'os_name', 'os_version')
      .count<{ os_type: string; os_name: string | null; os_version: string | null; count: string | number }[]>('* as count')
      .groupBy('os_type', 'os_name', 'os_version')
      .orderBy('os_type', 'asc')
      .orderBy('os_name', 'asc')
      .orderBy('os_version', 'asc');
    if (!isMaster) q.where({ tenant_id: tenantId });
    const rows = await q;
    return rows.map((r) => ({
      osType: r.os_type,
      osName: r.os_name,
      osVersion: r.os_version,
      count: typeof r.count === 'number' ? r.count : parseInt(r.count, 10),
    }));
  }

  // ─── Tag facets ──────────────────────────────────────────────────────────
  // Distinct tag list for the tenant with per-tag device counts. Used by
  // the /devices filter popover so admins pick from existing tags
  // (typo-free) and see which ones are actually populated.
  //
  // `tags` is a JSONB array on devices — `jsonb_array_elements_text`
  // unnests it so we can group by individual tag. The query skips
  // pending_uninstall to avoid surfacing stale data.
  async getTagFacets(tenantId: number, view?: TenantView): Promise<Array<{ tag: string; count: number }>> {
    const isMaster = isGlobalView(tenantId, view);
    const where = isMaster
      ? `d.approval_status = 'approved' AND d.status <> 'pending_uninstall'`
      : `d.tenant_id = ? AND d.approval_status = 'approved' AND d.status <> 'pending_uninstall'`;
    const rows = await db.raw(
      `SELECT t.tag::text AS tag, COUNT(*)::int AS count
         FROM devices d, jsonb_array_elements_text(COALESCE(d.tags, '[]'::jsonb)) AS t(tag)
        WHERE ${where}
        GROUP BY t.tag
        ORDER BY count DESC, tag ASC`,
      isMaster ? [] : [tenantId],
    ) as { rows: Array<{ tag: string; count: number }> };
    return rows.rows.map((r) => ({ tag: r.tag, count: Number(r.count) }));
  }

  // ─── Fleet summary ────────────────────────────────────────────────────────
  async getFleetSummary(tenantId: number, opts?: { strictTenantScope?: boolean; globalView?: boolean }) {
    // Only the global view (`globalView`, platform administrator on the
    // master tenant) counts the cross-tenant aggregate; any other caller
    // counts the devices of `tenantId`. `strictTenantScope` forces the
    // latter even with the global view: the daily snapshot job stores
    // master's own fleet in the row of tenant 1, not the install-wide sum
    // (the master timeseries SUMs across tenants and would double-count).
    const isMaster = isGlobalView(tenantId, opts) && !opts?.strictTenantScope;
    const statusQ = db('devices').select(db.raw('status, count(*) as count')).groupBy('status');
    if (!isMaster) statusQ.where({ tenant_id: tenantId });
    const rows = await statusQ;

    const counts: Record<string, number> = {};
    for (const r of rows) counts[r.status] = parseInt(r.count);

    // No OS update management on this server: never a pending update.
    const pendingUpdates = 0;

    // OS breakdown — total per OS family + online count per OS family. The
    // dashboard renders both: a donut (totals) AND a per-OS connectivity bar
    // (online vs offline) using osConnectivity below.
    const osQ = db('devices')
      .select(db.raw("os_type, status = 'online' as is_online, count(*) as count"))
      .groupBy('os_type', db.raw("status = 'online'"));
    if (!isMaster) osQ.where({ tenant_id: tenantId });
    const osRows = await osQ;
    const osByType = { windows: 0, macos: 0, linux: 0, other: 0 };
    const osConnectivity: Record<string, { online: number; total: number }> = {
      windows: { online: 0, total: 0 },
      macos:   { online: 0, total: 0 },
      linux:   { online: 0, total: 0 },
      other:   { online: 0, total: 0 },
    };
    for (const r of osRows) {
      const key = r.os_type as keyof typeof osByType;
      const c = parseInt(r.count);
      osByType[key] = (osByType[key] || 0) + c;
      if (osConnectivity[key]) {
        osConnectivity[key].total += c;
        if (r.is_online) osConnectivity[key].online += c;
      }
    }

    // No remote access on this server: never an active remote session.
    const activeRemoteSessions = 0;

    // No script schedules on this server: never an upcoming run.
    const upcomingSchedules = 0;

    // Stale devices (no contact in 72h)
    const now = new Date();
    const staleThreshold = new Date(now.getTime() - 72 * 60 * 60 * 1000);
    const staleQ = db('devices')
      .whereNotIn('status', ['pending', 'suspended', 'pending_uninstall'])
      .where('last_seen_at', '<', staleThreshold)
      .count('id as count');
    if (!isMaster) staleQ.where({ tenant_id: tenantId });
    const staleDevices = await staleQ.first().then(r => parseInt(String((r as any)?.count ?? 0)));

    // Total reflects the active managed fleet — devices the user can act on
    // today. pending (waiting for admin approval), suspended (admin-disabled),
    // and pending_uninstall (being removed) are admin/lifecycle states tracked
    // separately by the mini-stats and supervision pages, NOT part of the
    // daily-ops fleet. Excluding them keeps the breakdown cards (online +
    // offline + warning + critical + ...) summing to the displayed Total.
    const adminOnlyStatuses = new Set(['pending', 'suspended', 'pending_uninstall']);
    const total = Object.entries(counts)
      .filter(([s]) => !adminOnlyStatuses.has(s))
      .reduce((sum, [, c]) => sum + c, 0);

    // ── Deltas vs yesterday + week ago ─────────────────────────────────────
    // Read the two most recent snapshots so the dashboard can show
    // ↑/↓ comparisons. Missing snapshot → delta = null (UI hides it).
    const yesterdaySnap = await db('fleet_daily_snapshot')
      .where({ tenant_id: tenantId })
      .where('day', '<', new Date().toISOString().slice(0, 10))
      .orderBy('day', 'desc')
      .first();
    const weekAgoSnap = await db('fleet_daily_snapshot')
      .where({ tenant_id: tenantId })
      .where('day', '<=', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10))
      .orderBy('day', 'desc')
      .first();

    const deltas = {
      onlineVsYesterday:        yesterdaySnap ? (counts.online   || 0) - yesterdaySnap.online           : null,
      offlineVsYesterday:       yesterdaySnap ? (counts.offline  || 0) - yesterdaySnap.offline          : null,
      pendingUpdatesVsWeek:     weekAgoSnap   ? pendingUpdates           - weekAgoSnap.pending_updates  : null,
      staleVsYesterday:         yesterdaySnap ? staleDevices             - yesterdaySnap.stale_72h      : null,
      totalVsYesterday:         yesterdaySnap ? total                    - yesterdaySnap.total          : null,
    };

    return {
      total,
      online: counts.online || 0,
      offline: counts.offline || 0,
      warning: counts.warning || 0,
      critical: counts.critical || 0,
      // `updating` + `update_error` devices are still reachable (only an
      // update is in flight or failed): surfaced so the dashboard can fold
      // them into the "connected" KPI without changing the underlying
      // status semantics (the fields are optional in the shared type).
      updating: counts.updating || 0,
      updateError: counts.update_error || 0,
      maintenance: counts.maintenance || 0,
      pending: counts.pending || 0,
      suspended: counts.suspended || 0,
      pendingUpdates,
      complianceScore: null,
      // No agent on this server: no agent version to count or to offer.
      agentUpToDate: 0,
      agentOutdated: 0,
      latestAgentVersion: '',
      osByType,
      osConnectivity,
      activeRemoteSessions,
      upcomingSchedules,
      staleDevices,
      deltas,
    };
  }

  // ─── Fleet timeseries ─────────────────────────────────────────────────────
  // Returns {date, total, online, offline, pendingUpdates, stale72} for the
  // last N days. The current day is always synthesized from live state — the
  // nightly snapshot job is for historic comparison only.
  async getFleetTimeseries(tenantId: number, days: number, view?: TenantView) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const cutoff = new Date(today.getTime() - (days - 1) * 24 * 60 * 60 * 1000);

    // The global view gets the cross-tenant aggregate: each (day) row is
    // the sum of all tenant-scoped snapshots for that day. Every other
    // caller stays strictly scoped.
    const isMaster = isGlobalView(tenantId, view);
    let rows: any[];
    if (isMaster) {
      rows = await db('fleet_daily_snapshot')
        .where('day', '>=', cutoff.toISOString().slice(0, 10))
        .groupBy('day')
        .orderBy('day', 'asc')
        .select(
          'day',
          db.raw('SUM(total)::int as total'),
          db.raw('SUM(online)::int as online'),
          db.raw('SUM(offline)::int as offline'),
          db.raw('SUM(pending_updates)::int as "pendingUpdates"'),
          db.raw('SUM(stale_72h)::int as stale72'),
        );
    } else {
      rows = await db('fleet_daily_snapshot')
        .where({ tenant_id: tenantId })
        .where('day', '>=', cutoff.toISOString().slice(0, 10))
        .orderBy('day', 'asc')
        .select('day', 'total', 'online', 'offline', 'pending_updates as pendingUpdates', 'stale_72h as stale72');
    }

    // Synthesise the live "today" point from current state so the chart
    // always ends on the current value, regardless of whether the nightly
    // snapshot job has run.
    const live = await this.getFleetSummary(tenantId, { globalView: isMaster });
    const todayStr = today.toISOString().slice(0, 10);
    const todayRow = {
      day: todayStr,
      total: live.total,
      online: live.online,
      offline: live.offline,
      pendingUpdates: live.pendingUpdates,
      stale72: live.staleDevices,
    };
    const filtered = rows.filter((r: any) => String(r.day).slice(0, 10) !== todayStr);
    return [...filtered.map((r: any) => ({ ...r, day: String(r.day).slice(0, 10) })), todayRow];
  }

  // ─── Hourly snapshot job ─────────────────────────────────────────────────
  // Called once per hour by a start task of modules/devices.ts. Writes one row
  // per tenant in fleet_hourly_snapshot, used by the dashboard "Activité du
  // parc" 24h view. Retention is 7 days — older rows are pruned in the same
  // job so the table stays small (~168 rows per tenant max).
  async snapshotFleetHourly() {
    try {
      // Round to the current hour boundary so onConflict-merge keeps a
      // single row per hour even across multiple boots / clock skew.
      const now = new Date();
      now.setMinutes(0, 0, 0);
      const tenants = await db('tenants').select('id');
      for (const t of tenants) {
        // strictTenantScope: same rationale as snapshotFleetDaily —
        // master tenant snapshot must reflect master's OWN devices,
        // not the cross-tenant aggregate (the read-time SUM does that).
        const summary = await this.getFleetSummary(t.id, { strictTenantScope: true });
        await db('fleet_hourly_snapshot')
          .insert({
            tenant_id: t.id,
            hour: now,
            total: summary.total,
            online: summary.online,
            offline: summary.offline,
            warning: summary.warning,
            critical: summary.critical,
            pending_updates: summary.pendingUpdates,
            stale_72h: summary.staleDevices,
            active_remote_sessions: summary.activeRemoteSessions,
          })
          .onConflict(['tenant_id', 'hour'])
          .merge();
      }
      // Retention sweep: keep 7 days of hourly history. The daily table
      // covers anything beyond that.
      const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      await db('fleet_hourly_snapshot').where('hour', '<', cutoff).del();
      logger.info({ tenants: tenants.length }, 'Fleet hourly snapshot complete');
    } catch (err) {
      logger.error(err, 'Fleet hourly snapshot failed');
    }
  }

  // Returns up to N most-recent hourly points for the dashboard 24h view.
  // The current hour is always synthesised from live state so the chart
  // ends on "now" regardless of the cron cadence, mirroring the daily flow.
  async getFleetHourlySeries(tenantId: number, hours: number, view?: TenantView) {
    const cap = Math.min(168, Math.max(2, hours));
    const cutoff = new Date(Date.now() - cap * 60 * 60 * 1000);
    const isMaster = isGlobalView(tenantId, view);
    let rows: Array<{
      hour: Date | string; total: number; online: number; offline: number; pendingUpdates: number; stale72: number;
    }>;
    if (isMaster) {
      // Cross-tenant aggregate: SUM each metric per hour bucket.
      rows = await db('fleet_hourly_snapshot')
        .where('hour', '>=', cutoff)
        .groupBy('hour')
        .orderBy('hour', 'asc')
        .select(
          'hour',
          db.raw('SUM(total)::int as total'),
          db.raw('SUM(online)::int as online'),
          db.raw('SUM(offline)::int as offline'),
          db.raw('SUM(pending_updates)::int as "pendingUpdates"'),
          db.raw('SUM(stale_72h)::int as stale72'),
        ) as any;
    } else {
      rows = await db('fleet_hourly_snapshot')
        .where({ tenant_id: tenantId })
        .where('hour', '>=', cutoff)
        .orderBy('hour', 'asc')
        .select('hour', 'total', 'online', 'offline', 'pending_updates as pendingUpdates', 'stale_72h as stale72') as any;
    }

    const live = await this.getFleetSummary(tenantId, { globalView: isMaster });
    const nowHour = new Date();
    nowHour.setMinutes(0, 0, 0);
    const liveRow = {
      hour: nowHour.toISOString(),
      total: live.total,
      online: live.online,
      offline: live.offline,
      pendingUpdates: live.pendingUpdates,
      stale72: live.staleDevices,
    };
    const filtered = rows
      .map((r) => ({ ...r, hour: typeof r.hour === 'string' ? r.hour : r.hour.toISOString() }))
      .filter((r) => r.hour !== liveRow.hour);
    return [...filtered, liveRow];
  }

  // ─── Daily snapshot job ──────────────────────────────────────────────────
  // Called once a day by a start task of modules/devices.ts. Writes one row per
  // tenant in fleet_daily_snapshot, used by the dashboard for week-over-week
  // deltas and for the "Activité du parc" timeseries chart.
  async snapshotFleetDaily() {
    try {
      const today = new Date().toISOString().slice(0, 10);
      const tenants = await db('tenants').select('id');
      for (const t of tenants) {
        // strictTenantScope: snapshot reflects this tenant's OWN
        // devices only. Without it the master tenant's row would be
        // the install-wide aggregate, then the master timeseries
        // would SUM that with each child tenant's row → ~2× counted.
        const summary = await this.getFleetSummary(t.id, { strictTenantScope: true });
        await db('fleet_daily_snapshot')
          .insert({
            tenant_id: t.id,
            day: today,
            total: summary.total,
            online: summary.online,
            offline: summary.offline,
            warning: summary.warning,
            critical: summary.critical,
            pending_updates: summary.pendingUpdates,
            stale_72h: summary.staleDevices,
            active_remote_sessions: summary.activeRemoteSessions,
          })
          .onConflict(['tenant_id', 'day'])
          .merge();
      }
      logger.info({ tenants: tenants.length }, 'Fleet daily snapshot complete');
    } catch (err) {
      logger.error(err, 'Fleet daily snapshot failed');
    }
  }
}

export const deviceService = new DeviceService();
