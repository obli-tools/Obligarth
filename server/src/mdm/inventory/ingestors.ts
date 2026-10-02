import { createHash, X509Certificate } from 'node:crypto';
import type { Knex } from 'knex';
import type { NanoEnrollType, Ownership } from '@obligarth/shared';
import { canonicalJson } from '../../audit/canonical';
import { raiseInTx } from '../../apple/alerts/service';
import { privacyRulesFor, type PrivacyRules } from '../../apple/devices/privacy';
import { platformFromProductName } from '../registry/authenticateRules';

// =============================================================================
// The inventory contract (docs: modele-donnees-mdm §5.2 to §5.4, §10.4): the
// writes the ingestors of the integration (§7.6, §9.6) make into the tables of
// the data model, with its rules:
//   - the privacy rules of the device's ownership refilter every answer: a
//     key not collected but returned is not stored, a value not collected is
//     absent (EX-19); an unmanaged app of a personal or COPE device is never
//     stored (installedApps 'managed_only');
//   - monotony by kind (last_<kind>_at): an answer older than the last one
//     ingested of the same kind is set aside ('stale');
//   - device data never authorise anything (S10): lengths bounded by the
//     columns, a changed serial number or UDID raises an alert.
// In the caller's transaction and the tenant's context (the outbox handler's
// savepoint, or the job apple.command-result-ingest); no network. The return
// values tell the caller what changed, for the resolution and the compliance
// that follow (lot B5).
// =============================================================================

export type IngestOutcome = 'applied' | 'stale' | 'no_device';

interface DeviceFacts {
  ownership: Ownership;
  mode: string;
  serial: string | null;
  supervised: boolean;
  osVersion: string | null;
  lostModeState: string;
  udid: string | null;
  certSha256: string | null;
  last: Record<'device_info' | 'security_info' | 'apps' | 'profiles' | 'certificates', Date | null>;
}

const str = (v: unknown, max: number): string | null => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);
const bool = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const after = (at: Date, last: Date | null): boolean => !last || at.getTime() > new Date(last).getTime();
const nanoTypeOf = (mode: string): NanoEnrollType => (mode === 'user_enrollment' ? 'User Enrollment (Device)' : 'Device');

async function factsOf(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<DeviceFacts | null> {
  const r = await trx('devices as d')
    .leftJoin('apple_devices as a', function joinSat() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where({ 'd.tenant_id': tenantId, 'd.id': deviceId })
    // The record's row (never the nullable side of the outer join): one ingestion of a device at a time.
    .forUpdate('d')
    .first('d.ownership', 'd.management_mode', 'd.serial_number', 'd.supervised', 'd.os_version', 'd.lost_mode_state',
      'a.udid', 'a.cert_sha256', 'a.last_device_info_at', 'a.last_security_info_at', 'a.last_apps_at', 'a.last_profiles_at',
      'a.last_certificates_at') as Record<string, any> | undefined;
  if (!r) return null;
  return {
    ownership: r.ownership, mode: r.management_mode, serial: r.serial_number ?? null, supervised: !!r.supervised,
    osVersion: r.os_version ?? null, lostModeState: r.lost_mode_state, udid: r.udid ?? null,
    certSha256: r.cert_sha256 ? String(r.cert_sha256).trim() : null,
    last: {
      device_info: r.last_device_info_at ?? null, security_info: r.last_security_info_at ?? null, apps: r.last_apps_at ?? null,
      profiles: r.last_profiles_at ?? null, certificates: r.last_certificates_at ?? null,
    },
  };
}

function rulesOf(trx: Knex.Transaction, tenantId: number, f: DeviceFacts): Promise<PrivacyRules> {
  return privacyRulesFor(trx, tenantId, f.ownership, nanoTypeOf(f.mode));
}

/** The keys of a DeviceInformation answer the rules ask for: the others are dropped (refiltering). */
export function filterQueryResponses(responses: Record<string, unknown>, rules: PrivacyRules): Record<string, unknown> {
  const allowed = new Set(rules.deviceInformationQueries);
  return Object.fromEntries(Object.entries(responses ?? {}).filter(([k]) => allowed.has(k)));
}

/**
 * The privacy rules of a device applied to what its inventory already holds, once they narrowed (§5.2: a value
 * the rules do not collect is never kept; criterion 7: no unmanaged app of a personal or COPE device in base): a
 * new ownership (changeOwnership) or a new enrollment cycle under another profile (onAuthenticate). The unmanaged
 * apps leave the inventory when only the managed ones are collected, the reported name and the hardware
 * identifiers when they are not, and the last DeviceInformation answer keeps only the keys the rules ask for.
 * Returns the number of apps purged. In the caller's transaction and the tenant's context.
 */
export async function applyCollectionRules(trx: Knex.Transaction, tenantId: number, deviceId: number,
  rules: PrivacyRules): Promise<{ purgedApps: number }> {
  const purgedApps = rules.installedApps === 'managed_only'
    ? await trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId, managed: false }).del()
    : 0;
  if (!rules.storeDeviceName) {
    await trx('devices').where({ tenant_id: tenantId, id: deviceId }).whereNotNull('device_name')
      .update({ device_name: null, updated_at: new Date() });
  }
  const sat = await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId })
    .first('device_information', 'imei') as { device_information: unknown; imei: string | null } | undefined;
  if (sat) {
    const update: Record<string, unknown> = {};
    if (!rules.storeHardwareIds && sat.imei !== null) update.imei = null;
    const info = sat.device_information;
    if (info && typeof info === 'object' && !Array.isArray(info)) {
      const kept = filterQueryResponses(info as Record<string, unknown>, rules);
      if (Object.keys(kept).length !== Object.keys(info).length) update.device_information = JSON.stringify(kept);
    }
    if (Object.keys(update).length) {
      await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({ ...update, updated_at: new Date() });
    }
  }
  return { purgedApps };
}

/** Capacity in decimal gigabytes (DeviceCapacity, AvailableDeviceCapacity) → bytes [J1: units to confirm]. */
const gigabytes = (v: unknown): number | null => {
  const n = num(v);
  return n === null || n < 0 || n > 1e6 ? null : Math.round(n * 1e9);
};

export interface DeviceInformationEffects {
  outcome: IngestOutcome;
  osChanged?: boolean;
  supervisionChanged?: boolean;
  serialChanged?: boolean;
  udidMismatch?: boolean;
}

/**
 * DeviceInformation (§5.3, inline): the columns of the record and of the satellite, the rest (filtered) in
 * apple_devices.device_information. A known serial number that changes raises device.serial_changed; a UDID
 * that is not the identity's raises security.identity_mismatch (neither is stored over the known value).
 */
export async function ingestDeviceInformation(trx: Knex.Transaction, tenantId: number, deviceId: number,
  queryResponses: Record<string, unknown>, occurredAt: Date): Promise<DeviceInformationEffects> {
  const f = await factsOf(trx, tenantId, deviceId);
  if (!f) return { outcome: 'no_device' };
  if (!after(occurredAt, f.last.device_info)) return { outcome: 'stale' };
  const rules = await rulesOf(trx, tenantId, f);
  const q = filterQueryResponses(queryResponses, rules);
  const personal = f.ownership === 'personal';
  const device: Record<string, unknown> = { updated_at: new Date() };
  const sat: Record<string, unknown> = { last_device_info_at: occurredAt, updated_at: new Date() };
  const effects: DeviceInformationEffects = { outcome: 'applied' };

  const osVersion = str(q.OSVersion, 200);
  if (osVersion) { device.os_version = osVersion; effects.osChanged = osVersion !== f.osVersion; }
  const build = str(q.BuildVersion, 32);
  if (build) device.os_build = build;
  const productName = str(q.ProductName, 64);
  if (productName) {
    sat.product_name = productName;
    device.model = productName;
    const platform = platformFromProductName(productName);
    if (platform) device.platform = platform;
  }
  const modelName = str(q.ModelName, 128);
  if (modelName) {
    // The marketing name of the DDM status channel wins (device.model.marketing-name).
    const ddm = await trx('device_status_items').where({ tenant_id: tenantId, device_id: deviceId, item: 'device.model.marketing-name' }).first('value');
    if (!ddm || typeof ddm.value !== 'string') device.model_name = modelName;
  }
  const modelNumber = str(q.ModelNumber, 64) ?? str(q.Model, 64);
  if (modelNumber) sat.model_number = modelNumber;
  if (rules.storeDeviceName) { const n = str(q.DeviceName, 255); if (n) device.device_name = n; }
  if (rules.storeSerialNumber && !personal) {
    const serial = str(q.SerialNumber, 64);
    if (serial) {
      if (f.serial && serial.toUpperCase() !== f.serial.toUpperCase()) {
        effects.serialChanged = true;
        await raiseInTx(trx, tenantId, 'device.serial_changed', { discriminant: deviceId });
      } else if (!f.serial) {
        device.serial_number = serial.toUpperCase();
      }
    }
  }
  const udid = str(q.UDID, 128);
  if (udid && f.udid && udid.toUpperCase() !== f.udid.toUpperCase()) {
    effects.udidMismatch = true;
    await raiseInTx(trx, tenantId, 'security.identity_mismatch', { discriminant: deviceId, params: { field: 'UDID' } });
  }
  if (rules.storeHardwareIds) { const imei = str(q.IMEI, 32); if (imei) sat.imei = imei.replace(/\s+/g, ''); }
  const capacity = gigabytes(q.DeviceCapacity);
  if (capacity !== null) device.storage_capacity_bytes = capacity;
  const available = gigabytes(q.AvailableDeviceCapacity);
  if (available !== null) device.storage_available_bytes = available;
  const supervised = bool(q.IsSupervised);
  if (supervised !== null) { device.supervised = supervised; effects.supervisionChanged = supervised !== f.supervised; }
  const lostMode = bool(q.IsMDMLostModeEnabled);
  if (lostMode !== null && !personal) {
    // Reconciliation of the lost mode (§4.4): the device's word after an ack that went missing.
    if (lostMode && ['off', 'enabling'].includes(f.lostModeState)) { device.lost_mode_state = 'on'; device.lost_mode_changed_at = occurredAt; }
    if (!lostMode && ['on', 'disabling'].includes(f.lostModeState)) { device.lost_mode_state = 'off'; device.lost_mode_changed_at = occurredAt; }
  }
  const al = bool(q.IsActivationLockEnabled);
  if (al !== null) sat.activation_lock_enabled = al;
  const fm = bool(q.IsDeviceLocatorServiceEnabled);
  if (fm !== null) sat.find_my_enabled = fm;
  // The rest, filtered, for the display (identifiers kept only if the rules collect them).
  const kept = Object.fromEntries(Object.entries(q).filter(([k]) => !['SerialNumber', 'UDID', 'IMEI', 'DeviceName'].includes(k)
    || (k === 'SerialNumber' && rules.storeSerialNumber && !personal) || (k === 'IMEI' && rules.storeHardwareIds)
    || (k === 'DeviceName' && rules.storeDeviceName)));
  sat.device_information = JSON.stringify(kept);
  await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update(device);
  await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update(sat);
  return effects;
}

/** SecurityInfo (§5.3, inline): the last answer, for the display. */
export async function ingestSecurityInfo(trx: Knex.Transaction, tenantId: number, deviceId: number,
  securityInfo: Record<string, unknown>, occurredAt: Date): Promise<IngestOutcome> {
  const f = await factsOf(trx, tenantId, deviceId);
  if (!f) return 'no_device';
  if (!after(occurredAt, f.last.security_info)) return 'stale';
  await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({
    security_info: JSON.stringify(securityInfo ?? {}), last_security_info_at: occurredAt, updated_at: new Date(),
  });
  return 'applied';
}

/** The catalog app of an identifier (apps of the tenant, not archived), for device_apps.app_id (§8.4). */
async function catalogIds(trx: Knex.Transaction, tenantId: number, identifiers: string[]): Promise<Map<string, number>> {
  if (identifiers.length === 0) return new Map();
  const rows = await trx('apps').where({ tenant_id: tenantId, platform_family: 'apple' }).whereNull('archived_at')
    .whereIn('identifier', identifiers).select('id', 'identifier') as Array<{ id: number; identifier: string }>;
  return new Map(rows.map((r) => [r.identifier, Number(r.id)]));
}

/**
 * InstalledApplicationList (§5.3, deferred): the complete list of its source. The 'installed_list' rows
 * absent from it are deleted, the others updated or inserted. With installedApps 'managed_only' (personal,
 * COPE), an app is kept only if it is known as managed: an unmanaged app is never stored.
 */
export async function ingestInstalledApplicationList(trx: Knex.Transaction, tenantId: number, deviceId: number,
  list: Array<Record<string, unknown>>, occurredAt: Date): Promise<IngestOutcome> {
  const f = await factsOf(trx, tenantId, deviceId);
  if (!f) return 'no_device';
  if (!after(occurredAt, f.last.apps)) return 'stale';
  const rules = await rulesOf(trx, tenantId, f);
  const existing = await trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId }).select('identifier', 'managed', 'source') as
    Array<{ identifier: string; managed: boolean; source: string }>;
  const managed = new Set(existing.filter((e) => e.managed).map((e) => e.identifier));
  const seen = new Set<string>();
  const items = (Array.isArray(list) ? list : []).flatMap((a) => {
    const identifier = str(a?.Identifier, 255);
    if (!identifier || seen.has(identifier)) return [];
    seen.add(identifier);
    if (rules.installedApps === 'managed_only' && !managed.has(identifier)) return [];
    return [{ identifier, a }];
  });
  const ids = await catalogIds(trx, tenantId, items.map((i) => i.identifier));
  for (const { identifier, a } of items) {
    const row = {
      tenant_id: tenantId, device_id: deviceId, identifier, name: str(a.Name, 255), version: str(a.Version, 64),
      short_version: str(a.ShortVersion, 64), bundle_size: num(a.BundleSize), dynamic_size: num(a.DynamicSize),
      is_validated: bool(a.IsValidated), app_id: ids.get(identifier) ?? null, last_seen_at: occurredAt,
    };
    await trx('device_apps').insert({ ...row, source: 'installed_list', first_seen_at: occurredAt })
      .onConflict(['tenant_id', 'device_id', 'identifier'])
      .merge(['name', 'version', 'short_version', 'bundle_size', 'dynamic_size', 'is_validated', 'app_id', 'last_seen_at']);
  }
  // The rows of this source absent from the complete list leave the inventory.
  const keep = items.map((i) => i.identifier);
  const del = trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId, source: 'installed_list' });
  if (keep.length) del.whereNotIn('identifier', keep);
  await del.del();
  await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({ last_apps_at: occurredAt, updated_at: new Date() });
  return 'applied';
}

/**
 * ManagedApplicationList (§5.3, deferred): managed, management status and configuration of each managed
 * app; a managed app not installed yet gets a 'managed_list' row. An app that is no longer managed is
 * unmanaged again — and leaves the inventory when the rules keep the managed apps only.
 */
export async function ingestManagedApplicationList(trx: Knex.Transaction, tenantId: number, deviceId: number,
  apps: Record<string, Record<string, unknown>>, occurredAt: Date): Promise<IngestOutcome> {
  const f = await factsOf(trx, tenantId, deviceId);
  if (!f) return 'no_device';
  if (!after(occurredAt, f.last.apps)) return 'stale';
  const rules = await rulesOf(trx, tenantId, f);
  const entries = Object.entries(apps ?? {}).filter(([id]) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(id));
  const ids = await catalogIds(trx, tenantId, entries.map(([id]) => id));
  for (const [identifier, a] of entries) {
    await trx('device_apps').insert({
      tenant_id: tenantId, device_id: deviceId, identifier, managed: true, management_status: str(a?.Status, 32),
      has_configuration: bool(a?.HasConfiguration), source: 'managed_list', app_id: ids.get(identifier) ?? null,
      first_seen_at: occurredAt, last_seen_at: occurredAt,
    }).onConflict(['tenant_id', 'device_id', 'identifier'])
      .merge(['managed', 'management_status', 'has_configuration', 'app_id', 'last_seen_at']);
  }
  const still = entries.map(([id]) => id);
  const gone = trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId, managed: true }).whereNot('source', 'ddm_status');
  if (still.length) gone.whereNotIn('identifier', still);
  if (rules.installedApps === 'managed_only') await gone.del();
  else await gone.update({ managed: false, management_status: null });
  await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({ last_apps_at: occurredAt, updated_at: new Date() });
  return 'applied';
}

/** The artifact key of a profile of the policies (tools.obli.obligarth.p. / .raw.; never the enrollment profile). */
export function profileArtifactKey(payloadIdentifier: string): string | null {
  return /^tools\.obli\.obligarth\.(p|raw)\.[A-Za-z0-9._-]{1,140}$/.test(payloadIdentifier) ? `profile:${payloadIdentifier}` : null;
}

/** ProfileList (§5.3, deferred): the complete set of the installed profiles replaces the previous one. */
export async function ingestProfileList(trx: Knex.Transaction, tenantId: number, deviceId: number,
  profiles: Array<Record<string, unknown>>, occurredAt: Date): Promise<IngestOutcome> {
  const f = await factsOf(trx, tenantId, deviceId);
  if (!f) return 'no_device';
  if (!after(occurredAt, f.last.profiles)) return 'stale';
  const seen = new Set<string>();
  for (const p of Array.isArray(profiles) ? profiles : []) {
    const identifier = str(p?.PayloadIdentifier, 255);
    if (!identifier || seen.has(identifier)) continue;
    seen.add(identifier);
    const content = Array.isArray(p.PayloadContent) ? p.PayloadContent as Array<Record<string, unknown>> : [];
    const types = [...new Set(content.map((c) => str(c?.PayloadType, 128)).filter((t): t is string => !!t))].slice(0, 50);
    await trx('apple_device_profiles').insert({
      tenant_id: tenantId, device_id: deviceId, payload_identifier: identifier, payload_uuid: str(p.PayloadUUID, 64),
      display_name: str(p.PayloadDisplayName, 255), organization: str(p.PayloadOrganization, 255),
      is_managed: bool(p.IsManaged), is_encrypted: bool(p.IsEncrypted), removal_disallowed: bool(p.PayloadRemovalDisallowed),
      has_removal_passcode: bool(p.HasRemovalPasscode), payload_types: types, artifact_key: profileArtifactKey(identifier),
      first_seen_at: occurredAt, last_seen_at: occurredAt,
    }).onConflict(['tenant_id', 'device_id', 'payload_identifier'])
      .merge(['payload_uuid', 'display_name', 'organization', 'is_managed', 'is_encrypted', 'removal_disallowed',
        'has_removal_passcode', 'payload_types', 'artifact_key', 'last_seen_at']);
  }
  const del = trx('apple_device_profiles').where({ tenant_id: tenantId, device_id: deviceId });
  if (seen.size) del.whereNotIn('payload_identifier', [...seen]);
  await del.del();
  await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({ last_profiles_at: occurredAt, updated_at: new Date() });
  return 'applied';
}

/** One certificate of a CertificateList: read from its DER (never kept). null when unreadable. */
export function certificateFacts(der: Buffer): { sha256: string; commonName: string | null; subject: string; issuer: string;
  serialHex: string; notBefore: Date; notAfter: Date } | null {
  try {
    const c = new X509Certificate(der);
    const cn = /(?:^|\n)CN=([^\n]*)/.exec(c.subject)?.[1] ?? null;
    return {
      sha256: createHash('sha256').update(der).digest('hex'), commonName: cn ? cn.slice(0, 255) : null,
      subject: c.subject.slice(0, 2000), issuer: c.issuer.slice(0, 2000), serialHex: c.serialNumber.toLowerCase().slice(0, 64),
      notBefore: new Date(c.validFrom), notAfter: new Date(c.validTo),
    };
  } catch {
    return null;
  }
}

/** CertificateList (§5.3, deferred): replaces the 'certificate_list' set; the DER is read, never kept. */
export async function ingestCertificateList(trx: Knex.Transaction, tenantId: number, deviceId: number,
  certificates: Array<{ data: Buffer; isIdentity?: boolean }>, occurredAt: Date): Promise<IngestOutcome> {
  const f = await factsOf(trx, tenantId, deviceId);
  if (!f) return 'no_device';
  if (!after(occurredAt, f.last.certificates)) return 'stale';
  const seen = new Set<string>();
  for (const c of Array.isArray(certificates) ? certificates : []) {
    if (!Buffer.isBuffer(c?.data) || c.data.length > 64 * 1024) continue;
    const facts = certificateFacts(c.data);
    if (!facts || seen.has(facts.sha256)) continue;
    seen.add(facts.sha256);
    await trx('device_certificates').insert({
      tenant_id: tenantId, device_id: deviceId, sha256: facts.sha256, common_name: facts.commonName, subject: facts.subject,
      issuer: facts.issuer, serial_hex: facts.serialHex, not_before: facts.notBefore, not_after: facts.notAfter,
      is_identity: c.isIdentity === true, is_mdm_identity: facts.sha256 === f.certSha256, source: 'certificate_list',
      first_seen_at: occurredAt, last_seen_at: occurredAt,
    }).onConflict(['tenant_id', 'device_id', 'sha256'])
      .merge(['common_name', 'subject', 'issuer', 'serial_hex', 'not_before', 'not_after', 'is_identity', 'is_mdm_identity', 'last_seen_at']);
  }
  const del = trx('device_certificates').where({ tenant_id: tenantId, device_id: deviceId, source: 'certificate_list' });
  if (seen.size) del.whereNotIn('sha256', [...seen]);
  await del.del();
  await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({ last_certificates_at: occurredAt, updated_at: new Date() });
  return 'applied';
}

/** Status items whose history is kept, at the changes only (integration §4.9 whitelist). */
export const STATUS_HISTORY_ITEMS = new Set([
  'device.operating-system.version', 'device.operating-system.build-version', 'softwareupdate.install-state',
  'softwareupdate.pending-version', 'softwareupdate.failure-reason', 'passcode.is-present', 'passcode.is-compliant',
]);

export interface StatusItemsEffects {
  outcome: IngestOutcome;
  /** Items whose value changed (the caller enqueues the compliance or the resolution, §5.4). */
  changed: string[];
}

/**
 * The status items of a DDM status report (§5.4): the last value of each item the rules keep, its
 * fingerprint (change detection), the error of the item; the history of the whitelisted items at the
 * changes. An item older than the stored one is set aside.
 */
export async function ingestStatusItems(trx: Knex.Transaction, tenantId: number, deviceId: number,
  items: Array<{ item: string; value?: unknown; error?: unknown }>, observedAt: Date): Promise<StatusItemsEffects> {
  const f = await factsOf(trx, tenantId, deviceId);
  if (!f) return { outcome: 'no_device', changed: [] };
  const rules = await rulesOf(trx, tenantId, f);
  const allowed = new Set(rules.statusItems);
  const changed: string[] = [];
  for (const it of Array.isArray(items) ? items : []) {
    if (!it || typeof it.item !== 'string' || !allowed.has(it.item) || !/^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/.test(it.item)) continue;
    const value = it.value === undefined ? null : it.value;
    const sha = value === null ? null : createHash('sha256').update(canonicalJson(value)).digest('hex');
    const current = await trx('device_status_items').where({ tenant_id: tenantId, device_id: deviceId, item: it.item })
      .first('value_sha256', 'observed_at') as { value_sha256: string | null; observed_at: Date } | undefined;
    if (current && !after(observedAt, current.observed_at)) continue;
    const differs = !current || (current.value_sha256 ? String(current.value_sha256).trim() : null) !== sha;
    await trx('device_status_items').insert({
      tenant_id: tenantId, device_id: deviceId, item: it.item, value: JSON.stringify(value), value_sha256: sha,
      error: it.error === undefined || it.error === null ? null : JSON.stringify(it.error), observed_at: observedAt, updated_at: new Date(),
    }).onConflict(['tenant_id', 'device_id', 'item']).merge(['value', 'value_sha256', 'error', 'observed_at', 'updated_at']);
    if (differs) {
      changed.push(it.item);
      if (STATUS_HISTORY_ITEMS.has(it.item)) {
        await trx('device_status_history').insert({ tenant_id: tenantId, device_id: deviceId, item: it.item, value: JSON.stringify(value), observed_at: observedAt });
      }
    }
  }
  return { outcome: 'applied', changed };
}
