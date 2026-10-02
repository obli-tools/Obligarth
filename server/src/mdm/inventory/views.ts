import type { DeviceAppView, DeviceCertificateView, DeviceProfileView } from '@obligarth/shared';
import { db } from '../../db';

// =============================================================================
// Reads of the inventory of a device (docs: modele-donnees-mdm §5, §10.6:
// GET /api/mdm/devices/:id/apps, /profiles, /certificates), in the caller's
// context. What the privacy rules did not collect is not in the tables (the
// ingestion refilters): an unmanaged app of a personal or COPE device is never
// stored, so never listed.
// =============================================================================

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);
const num = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));

export async function deviceApps(tenantId: number, deviceId: number): Promise<DeviceAppView[]> {
  const rows = await db('device_apps').where({ tenant_id: tenantId, device_id: deviceId })
    .orderByRaw('lower(COALESCE(name, identifier)) asc, identifier asc') as Array<Record<string, any>>;
  return rows.map((r) => ({
    identifier: r.identifier, name: r.name ?? null, version: r.version ?? null, shortVersion: r.short_version ?? null,
    managed: !!r.managed, managementStatus: r.management_status ?? null, source: r.source,
    bundleSize: num(r.bundle_size), dynamicSize: num(r.dynamic_size), hasConfiguration: r.has_configuration ?? null,
    isValidated: r.is_validated ?? null, appId: num(r.app_id), firstSeenAt: iso(r.first_seen_at)!, lastSeenAt: iso(r.last_seen_at)!,
  }));
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
