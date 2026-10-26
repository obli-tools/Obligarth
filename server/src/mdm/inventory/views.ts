import { appArtifactKey, type DeviceAppManagedBy, type DeviceAppView, type DeviceCertificateView, type DeviceProfileView } from '@obligarth/shared';
import { db } from '../../db';
import { catalogIcon, categoryOf, familyOf, versionsOf } from './appView';

// =============================================================================
// Reads of the inventory of a device (docs: modele-donnees-mdm §5, §10.6:
// GET /api/mdm/devices/:id/apps, /profiles, /certificates), in the caller's
// context. What the privacy rules did not collect is not in the tables (the
// ingestion refilters): an unmanaged app of a personal or COPE device is never
// stored, so never listed.
// =============================================================================

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);
const num = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));

const jsonOf = <T>(v: unknown, fallback: T): T => {
  if (typeof v !== 'string') return (v ?? fallback) as T;
  try { return JSON.parse(v) as T; } catch { return fallback; }
};

/** The apps of a device's inventory and when its channel last collected them (GET /api/mdm/devices/:id/apps). Each
 *  app carries its category, its versions read by family, its icon (the catalog's https URL, else the one a device
 *  of the tenant sent), the catalog app of its identifier (the tenant's or a master app shared with it), the
 *  assignments that deliver it (device_effective_settings) and the state of its delivery (Apple: its artifact;
 *  bridge agent: its last app.install command; AMAPI: the device's report). */
export async function deviceApps(tenantId: number, deviceId: number): Promise<{ apps: DeviceAppView[]; collectedAt: string | null }> {
  const device = await db('devices').where({ tenant_id: tenantId, id: deviceId }).first('platform', 'management_channel') as
    { platform: string; management_channel: string } | undefined;
  if (!device) return { apps: [], collectedAt: null };
  const family = familyOf(device.platform);
  const channel = device.management_channel;
  const res = await db.raw(`
    SELECT da.*, cat.id AS cat_id, cat.uuid AS cat_uuid, cat.name AS cat_name, cat.icon_url AS cat_icon_url,
           cat.tenant_id AS cat_tenant_id, ic.sha256 AS icon_sha256
      FROM device_apps da
      LEFT JOIN LATERAL (
        SELECT a.id, a.uuid, a.name, a.icon_url, a.tenant_id FROM apps a
         WHERE a.archived_at IS NULL AND a.platform_family = :family AND a.identifier = da.identifier
           AND (a.tenant_id = da.tenant_id OR a.target_tenant_ids @> ARRAY[da.tenant_id])
         ORDER BY (a.id = da.app_id) IS TRUE DESC, (a.tenant_id = da.tenant_id) DESC, a.id
         LIMIT 1) cat ON true
      LEFT JOIN app_icons ic ON ic.tenant_id = da.tenant_id AND ic.platform_family = :family
           AND ic.identifier = da.identifier AND ic.state = 'stored'
     WHERE da.tenant_id = :tenantId AND da.device_id = :deviceId
     ORDER BY lower(COALESCE(da.name, da.identifier)) ASC, da.identifier ASC`, { family, tenantId, deviceId }) as { rows: Array<Record<string, any>> };
  const rows = res.rows;

  // The assignments that deliver each app (one effective setting per key: its winning assignment).
  const prefix = `${family}:app[`;
  const settings = await db('device_effective_settings').where({ tenant_id: tenantId, device_id: deviceId, removed: false })
    .where('setting_key', 'like', `${prefix}%`)
    .select('setting_key', 'source_assignment_id', 'source_scope', 'source_scope_id', 'availability') as Array<Record<string, any>>;
  const groupIds = [...new Set(settings.filter((s) => s.source_scope === 'group' && s.source_scope_id !== null).map((s) => Number(s.source_scope_id)))];
  const groupNames = new Map((groupIds.length ? await db('device_groups').where({ tenant_id: tenantId }).whereIn('id', groupIds)
    .select('id', 'name') as Array<{ id: number; name: string }> : []).map((g) => [Number(g.id), g.name]));
  const managedBy = new Map<string, DeviceAppManagedBy[]>();
  for (const s of settings) {
    const key = String(s.setting_key);
    if (!key.startsWith(prefix) || !key.endsWith(']')) continue;
    const identifier = key.slice(prefix.length, -1);
    const scopeId = s.source_scope_id === null ? null : Number(s.source_scope_id);
    const list = managedBy.get(identifier) ?? [];
    list.push({
      assignmentId: Number(s.source_assignment_id), scope: s.source_scope, scopeId,
      scopeName: s.source_scope === 'group' && scopeId !== null ? groupNames.get(scopeId) ?? null : null,
      availability: String(s.availability),
    });
    managedBy.set(identifier, list);
  }

  // The delivery, by channel.
  type Delivery = NonNullable<DeviceAppView['delivery']>;
  const delivery = new Map<string, Delivery>();
  let collectedAt: string | null = null;
  if (channel === 'legacy_agent') {
    const sat = await db('legacy_agent_devices').where({ tenant_id: tenantId, device_id: deviceId }).first('last_inventory_at') as
      { last_inventory_at: Date | null } | undefined;
    collectedAt = iso(sat?.last_inventory_at);
    const cmds = await db.raw(`
      SELECT DISTINCT ON (params->>'packageName') params->>'packageName' AS pkg, state, result_code, state_event_at
        FROM legacy_agent_commands
       WHERE tenant_id = :tenantId AND device_id = :deviceId AND request_type = 'app.install' AND params->>'packageName' IS NOT NULL
       ORDER BY params->>'packageName', created_at DESC`, { tenantId, deviceId }) as { rows: Array<Record<string, any>> };
    for (const c of cmds.rows) {
      delivery.set(String(c.pkg), { via: 'agent_command', state: String(c.state), reasons: c.result_code ? [String(c.result_code)] : [], at: iso(c.state_event_at) });
    }
  } else if (channel === 'amapi') {
    const sat = await db('android_devices').where({ tenant_id: tenantId, device_id: deviceId })
      .first('last_status_report_at', 'non_compliance') as { last_status_report_at: Date | null; non_compliance: unknown } | undefined;
    collectedAt = iso(sat?.last_status_report_at);
    const issues = new Map<string, string[]>();
    for (const n of jsonOf<Array<Record<string, string>>>(sat?.non_compliance, [])) {
      if (!n?.packageName) continue;
      const list = issues.get(n.packageName) ?? [];
      list.push([n.nonComplianceReason, n.specificReason].filter(Boolean).join(':'));
      issues.set(n.packageName, list);
    }
    // Only the settings that reach the policy (available): one not applicable is listed in managedBy with its
    // availability, never as delivered.
    for (const [identifier, by] of managedBy) {
      if (!by.some((m) => m.availability === 'available')) continue;
      const reasons = issues.get(identifier) ?? [];
      delivery.set(identifier, { via: 'amapi', state: reasons.length ? 'error' : 'applied', reasons, at: collectedAt });
    }
  } else {
    const sat = await db('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).first('last_apps_at') as
      { last_apps_at: Date | null } | undefined;
    collectedAt = iso(sat?.last_apps_at);
    const artifacts = await db('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('channel', ['app', 'ddm'])
      .whereNot('state', 'removed').select('artifact_key', 'state', 'state_reasons', 'state_at') as Array<Record<string, any>>;
    const byKey = new Map(artifacts.map((a) => [String(a.artifact_key), a]));
    for (const r of rows) {
      // The keys of mdm/apps/delivery.ts appKeysOf: the command, then the declaration.
      const a = [`app:${r.identifier}`, appArtifactKey(r.identifier, true)].map((k) => byKey.get(k)).find(Boolean);
      if (a) delivery.set(r.identifier, { via: 'artifact', state: String(a.state), reasons: jsonOf<string[]>(a.state_reasons, []).map(String), at: iso(a.state_at) });
    }
  }

  const apps = rows.map((r): DeviceAppView => {
    const isSystem = r.is_system === null || r.is_system === undefined ? null : !!r.is_system;
    const catalogUrl = catalogIcon(r.cat_icon_url);
    const sha = r.icon_sha256 ? String(r.icon_sha256).trim() : null;
    const updatedAt = iso(r.app_updated_at) ?? iso(r.version_changed_at);
    return {
      identifier: r.identifier, name: r.name ?? null, version: r.version ?? null, shortVersion: r.short_version ?? null,
      managed: !!r.managed, managementStatus: r.management_status ?? null, source: r.source,
      bundleSize: num(r.bundle_size), dynamicSize: num(r.dynamic_size), hasConfiguration: r.has_configuration ?? null,
      isValidated: r.is_validated ?? null, appId: num(r.app_id), firstSeenAt: iso(r.first_seen_at)!, lastSeenAt: iso(r.last_seen_at)!,
      platformFamily: family,
      category: categoryOf({ managed: !!r.managed, isSystem, identifier: r.identifier, platform: device.platform }),
      system: isSystem,
      launchable: r.launchable === null || r.launchable === undefined ? null : !!r.launchable,
      ...versionsOf(family, r.version ?? null, r.short_version ?? null),
      installer: r.installer ?? null, installedAt: iso(r.installed_at), updatedAt,
      iconUrl: catalogUrl ?? (sha && /^[0-9a-f]{64}$/.test(sha) ? `/api/mdm/devices/${deviceId}/app-icons/${sha}` : null),
      catalogApp: r.cat_id === null || r.cat_id === undefined ? null
        : { id: Number(r.cat_id), uuid: String(r.cat_uuid), name: String(r.cat_name), shared: Number(r.cat_tenant_id) !== tenantId },
      managedBy: managedBy.get(r.identifier) ?? [],
      delivery: delivery.get(r.identifier) ?? null,
    };
  });
  return { apps, collectedAt };
}

/** The bytes of a stored icon, for a device that has the app (GET /api/mdm/devices/:id/app-icons/:sha256); null
 *  otherwise (an icon of another tenant, or of an app absent from this device, is never served). */
export async function deviceAppIcon(tenantId: number, deviceId: number, sha256: string): Promise<Buffer | null> {
  if (!/^[0-9a-f]{64}$/.test(sha256)) return null;
  const device = await db('devices').where({ tenant_id: tenantId, id: deviceId }).first('platform') as { platform: string } | undefined;
  if (!device) return null;
  const res = await db.raw(`
    SELECT ic.bytes FROM app_icons ic
     WHERE ic.tenant_id = :tenantId AND ic.sha256 = :sha256 AND ic.state = 'stored' AND ic.platform_family = :family
       AND EXISTS (SELECT 1 FROM device_apps da WHERE da.tenant_id = ic.tenant_id AND da.device_id = :deviceId AND da.identifier = ic.identifier)
     LIMIT 1`, { tenantId, sha256, family: familyOf(device.platform), deviceId }) as { rows: Array<{ bytes: Buffer }> };
  const bytes = res.rows[0]?.bytes;
  return Buffer.isBuffer(bytes) ? bytes : null;
}

export async function deviceProfiles(tenantId: number, deviceId: number): Promise<DeviceProfileView[]> {
  const rows = await db('apple_device_profiles').where({ tenant_id: tenantId, device_id: deviceId })
    .orderBy('payload_identifier', 'asc') as Array<Record<string, any>>;
  return rows.map((r) => ({
    payloadIdentifier: r.payload_identifier, payloadUuid: r.payload_uuid ?? null, displayName: r.display_name ?? null,
    organization: r.organization ?? null, isManaged: r.is_managed ?? null, isEncrypted: r.is_encrypted ?? null,
    removalDisallowed: r.removal_disallowed ?? null, hasRemovalPasscode: r.has_removal_passcode ?? null,
    payloadTypes: Array.isArray(r.payload_types) ? r.payload_types.map(String) : [], artifactKey: r.artifact_key ?? null,
    firstSeenAt: iso(r.first_seen_at)!, lastSeenAt: iso(r.last_seen_at)!,
  }));
}

export async function deviceCertificates(tenantId: number, deviceId: number): Promise<DeviceCertificateView[]> {
  const rows = await db('device_certificates').where({ tenant_id: tenantId, device_id: deviceId })
    .orderByRaw('not_after asc NULLS LAST, sha256 asc') as Array<Record<string, any>>;
  return rows.map((r) => ({
    sha256: String(r.sha256).trim(), commonName: r.common_name ?? null, subject: r.subject ?? null, issuer: r.issuer ?? null,
    serialHex: r.serial_hex ?? null, notBefore: iso(r.not_before), notAfter: iso(r.not_after), isIdentity: !!r.is_identity,
    isMdmIdentity: !!r.is_mdm_identity, source: r.source, firstSeenAt: iso(r.first_seen_at)!, lastSeenAt: iso(r.last_seen_at)!,
  }));
}
