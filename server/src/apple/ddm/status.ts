import type { Knex } from 'knex';
import { canonicalJson } from '../../audit/canonical';
import { versionChangedMerge } from '../../mdm/inventory/appMerge';
import { certificateFacts, ingestStatusItems } from '../../mdm/inventory/ingestors';
import { requestDeviceResolution } from '../../mdm/policies/triggers';
import { requestGroupEvaluation } from '../../mdm/groups/triggers';
import { normalizeSerial, platformFromProductName } from '../../mdm/registry/authenticateRules';
import { raiseInTx } from '../alerts/service';
import { privacyRulesFor } from '../devices/privacy';
import type { NanoEnrollType, Ownership } from '@obligarth/shared';
import { majorMinor } from './baseline';
import { parseClientCapabilities, sameCapabilities } from './capabilities';
import { KNOWN_STATUS_ITEMS } from './core.provider';
import { ddmMetrics } from './metrics';
import { declarationStatuses, errorItems, flattenStatusItems, type DeclarationStatus, type StatusReport } from './report';

// =============================================================================
// Ingestion of the status reports of the devices (docs: integration-apple-edge
// §9.6; modele-donnees-mdm §5.4, §10.4). The relay stores a report in
// apple_ddm_status_inbox (push token and magic already removed) and sends
// apple.ddm.status-ingest; that job applies the reports of a device in the
// order they were received, each in its transaction, and deletes the row
// applied. A report is flattened into dotted item names; the items the engine
// does not know, and those the privacy rules of the device's ownership do not
// allow, are never written.
//   management.client-capabilities  apple_devices.ddm_client_capabilities; a
//                                   change synchronises the device again
//   management.declarations         apple_declaration_status of the device replaced
//   device.operating-system.*       devices.os_version, os_build; a change of
//                                   major version recomputes the set
//   device.model.*                  devices.model, model_name, platform
//   device.identifier.*             a check only: an identifier that differs
//                                   from the record raises security.identity_mismatch
//   app.managed.list                device_apps (source ddm_status), merged by
//                                   identifier; _removed deletes [J1]
//   security.certificate.list       device_certificates (source ddm_status) for
//                                   the elements that carry their certificate [J1]
//   every other allowed item        device_status_items (and its history)
//   Errors                          a counter per item; no content logged
// Device data never authorise anything: lengths bounded, a serial number or a
// UDID never written from a report. In the caller's transaction and the
// tenant's context; no network.
// =============================================================================

/** Reports of one device waiting in the inbox beyond which the relay drops the new ones. */
export const MAX_PENDING_REPORTS = 50;
/** A status value larger than this (bytes of its canonical JSON) is not kept in device_status_items. */
const MAX_ITEM_BYTES = 64 * 1024;
/** Items that have a home of their own and never go to device_status_items. */
const NOT_STATUS_ROWS = new Set(['management.client-capabilities', 'management.declarations', 'device.identifier.serial-number',
  'device.identifier.udid', 'app.managed.list']);

export interface StatusHook {
  name: string;
  /** Status items of the device whose value changed (compliance, resolution of the policies…). */
  onItemsChanged?(trx: Knex.Transaction, tenantId: number, deviceId: number, items: string[]): Promise<void>;
  /** The device reported management.declarations: the status of each declaration (state of the DDM artifacts). */
  onDeclarationStatus?(trx: Knex.Transaction, tenantId: number, deviceId: number, statuses: DeclarationStatus[]): Promise<void>;
}

const hooks: StatusHook[] = [];

/** A hook of the status channel, run in the transaction of the report (registered before jobs.start(); a name once). */
export function registerStatusHook(h: StatusHook): void {
  if (!h || !/^[a-z][a-z0-9_.-]{0,40}$/.test(String(h.name ?? ''))) throw new Error('status hook: invalid name');
  if (hooks.some((x) => x.name === h.name)) throw new Error(`status hook ${h.name}: registered twice`);
  hooks.push(h);
}

/** Tests: no hook again. */
export function resetStatusHooksForTests(): void {
  hooks.length = 0;
}

/** What the end of a report asks of the jobs module. */
let requestSync: ((trx: Knex.Transaction, tenantId: number, deviceId: number) => Promise<void>) | null = null;

export function setStatusSyncRequester(fn: (trx: Knex.Transaction, tenantId: number, deviceId: number) => Promise<void>): void {
  requestSync = fn;
}

/**
 * The relay's write (§9.5, one row): the report in the inbox of the device of an enrollment, when that device is
 * under management and fewer than MAX_PENDING_REPORTS of its reports already wait (a device that floods its own
 * inbox loses reports, never grows the table). Returns the device, or null when nothing was stored.
 */
export async function storeStatusReport(trx: Knex.Transaction, tenantId: number, enrollmentId: string, report: StatusReport): Promise<number | null> {
  const res = await trx.raw(`
    INSERT INTO obligarth.apple_ddm_status_inbox (tenant_id, device_id, report)
    SELECT a.tenant_id, a.device_id, ?::jsonb
      FROM obligarth.apple_devices a
      JOIN obligarth.devices d ON d.id = a.device_id AND d.tenant_id = a.tenant_id
     WHERE a.tenant_id = ? AND a.enrollment_id = ? AND d.enrollment_state <> 'unenrolled'
       AND (SELECT count(*) FROM obligarth.apple_ddm_status_inbox i WHERE i.tenant_id = a.tenant_id AND i.device_id = a.device_id) < ?
    RETURNING device_id`, [JSON.stringify(report), tenantId, enrollmentId, MAX_PENDING_REPORTS]) as { rows: Array<{ device_id: number }> };
  return res.rows[0] ? Number(res.rows[0].device_id) : null;
}

export interface StatusEffects {
  outcome: 'applied' | 'no_device' | 'not_managed';
  capabilitiesChanged: boolean;
  osChanged: boolean;
  majorChanged: boolean;
  declarations: number;
  changed: string[];
}

interface Facts {
  enrollment_state: string;
  ownership: Ownership;
  os_version: string | null;
  os_build: string | null;
  model: string | null;
  model_name: string | null;
  platform: string;
  serial_number: string | null;
  udid: string | null;
  nano_enroll_type: NanoEnrollType;
  ddm_client_capabilities: unknown;
  last_device_info_at: Date | null;
}

const str = (v: unknown, max: number): string | null => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);
const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const APP_IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;
const MAX_LIST = 2000;

/** Rows of device_apps written per statement (INT-B5a-R4: 2 000 apps were written one by one). */
const APPS_BATCH = 500;

/** app.managed.list: the managed apps the device reports, merged by identifier; an element marked _removed leaves
 *  (incremental reports [J1]). A row another source created keeps its source. Written by batches of APPS_BATCH
 *  rows (review of lot B5a, INT-B5a-R4). */
async function applyManagedApps(trx: Knex.Transaction, tenantId: number, deviceId: number, value: unknown, managedOnly: boolean, at: Date): Promise<void> {
  if (!Array.isArray(value)) return;
  const seen = new Set<string>();
  const removed: string[] = [];
  const rows: Array<Record<string, unknown>> = [];
  for (const a of value.slice(0, MAX_LIST)) {
    const identifier = isObject(a) ? str(a.identifier, 255) : null;
    if (!isObject(a) || !identifier || !APP_IDENTIFIER_RE.test(identifier) || seen.has(identifier)) continue;
    seen.add(identifier);
    if (a._removed === true) { removed.push(identifier); continue; }
    rows.push({
      tenant_id: tenantId, device_id: deviceId, identifier, name: str(a.name, 255), version: str(a.version, 64),
      short_version: str(a['short-version'], 64), managed: true, management_status: str(a.state, 32), source: 'ddm_status',
      first_seen_at: at, last_seen_at: at,
    });
  }
  for (let i = 0; i < removed.length; i += APPS_BATCH) {
    // No longer managed: a row of this source leaves; an installed app stays, unmanaged (unless only the managed apps
    // of this device are kept).
    const ids = removed.slice(i, i + APPS_BATCH);
    const gone = trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('identifier', ids);
    if (managedOnly) await gone.del();
    else {
      await trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId, source: 'ddm_status' }).whereIn('identifier', ids).del();
      await trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('identifier', ids).update({ managed: false, management_status: null });
    }
  }
  for (let i = 0; i < rows.length; i += APPS_BATCH) {
    // What the report does not say (a name, a version) keeps the value another source wrote.
    await trx('device_apps').insert(rows.slice(i, i + APPS_BATCH)).onConflict(['tenant_id', 'device_id', 'identifier']).merge({
      managed: trx.raw('excluded.managed'),
      management_status: trx.raw('excluded.management_status'),
      last_seen_at: trx.raw('excluded.last_seen_at'),
      name: trx.raw('COALESCE(excluded.name, device_apps.name)'),
      version: trx.raw('COALESCE(excluded.version, device_apps.version)'),
      short_version: trx.raw('COALESCE(excluded.short_version, device_apps.short_version)'),
      // The same COALESCE as version and short_version above (keepStored).
      version_changed_at: versionChangedMerge(trx, true),
    });
  }
}

/** A base64 certificate of a list element, under the keys Apple may use [J1]; null otherwise. */
function certificateOf(c: Record<string, unknown>): Buffer | null {
  for (const key of ['data', 'certificate', 'certificate-data']) {
    const v = c[key];
    if (typeof v === 'string' && v.length <= 96 * 1024 && /^[A-Za-z0-9+/=\s]+$/.test(v)) return Buffer.from(v, 'base64');
  }
  return null;
}

/** security.certificate.list: the elements that carry their certificate go to device_certificates (the DER is read,
 *  never kept); returns the list as it is stored in device_status_items, without the certificates. */
async function applyCertificates(trx: Knex.Transaction, tenantId: number, deviceId: number, value: unknown, mdmIdentitySha: string | null, at: Date): Promise<unknown> {
  if (!Array.isArray(value)) return value;
  const kept: unknown[] = [];
  for (const c of value.slice(0, MAX_LIST)) {
    if (!isObject(c)) continue;
    const { data: _d, certificate: _c, 'certificate-data': _cd, ...rest } = c;
    kept.push(rest);
    const der = certificateOf(c);
    const facts = der ? certificateFacts(der) : null;
    if (!facts) continue;
    if (c._removed === true) {
      await trx('device_certificates').where({ tenant_id: tenantId, device_id: deviceId, sha256: facts.sha256, source: 'ddm_status' }).del();
      continue;
    }
    await trx('device_certificates').insert({
      tenant_id: tenantId, device_id: deviceId, sha256: facts.sha256, common_name: facts.commonName, subject: facts.subject,
      issuer: facts.issuer, serial_hex: facts.serialHex, not_before: facts.notBefore, not_after: facts.notAfter,
      is_identity: c['is-identity'] === true, is_mdm_identity: facts.sha256 === mdmIdentitySha, source: 'ddm_status',
      first_seen_at: at, last_seen_at: at,
    }).onConflict(['tenant_id', 'device_id', 'sha256']).merge(['is_identity', 'is_mdm_identity', 'last_seen_at']);
  }
  return kept;
}

/**
 * Applies one status report of a device (§9.6). `receivedAt`: when the relay stored it (the observation time of
 * what it reports). Reports are applied in the order they were received; an item older than what is stored is set
 * aside by each writer.
 */
export async function applyStatusReport(trx: Knex.Transaction, tenantId: number, deviceId: number, report: StatusReport, receivedAt: Date): Promise<StatusEffects> {
  const none: StatusEffects = { outcome: 'no_device', capabilitiesChanged: false, osChanged: false, majorChanged: false, declarations: 0, changed: [] };
  // The record's row locked: one ingestion of a device at a time (the inventory ingestors lock it the same way).
  const f = await trx('devices as d')
    .join('apple_devices as a', function joinSat() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where({ 'd.tenant_id': tenantId, 'd.id': deviceId })
    .forUpdate('d')
    .first('d.enrollment_state', 'd.ownership', 'd.os_version', 'd.os_build', 'd.model', 'd.model_name', 'd.platform', 'd.serial_number',
      'a.udid', 'a.nano_enroll_type', 'a.ddm_client_capabilities', 'a.last_device_info_at', 'a.cert_sha256') as (Facts & { cert_sha256: string | null }) | undefined;
  if (!f) return none;
  if (f.enrollment_state === 'unenrolled') return { ...none, outcome: 'not_managed' };

  const rules = await privacyRulesFor(trx, tenantId, f.ownership, f.nano_enroll_type);
  const allowed = new Set(rules.statusItems);
  const flat = new Map<string, unknown>();
  for (const i of flattenStatusItems(report?.StatusItems, KNOWN_STATUS_ITEMS)) if (allowed.has(i.item)) flat.set(i.item, i.value);
  const effects: StatusEffects = { outcome: 'applied', capabilitiesChanged: false, osChanged: false, majorChanged: false, declarations: 0, changed: [] };

  // Errors: a counter per item, nothing of their content.
  for (const item of errorItems(report?.Errors, KNOWN_STATUS_ITEMS)) ddmMetrics.statusError(item);

  // management.client-capabilities
  if (flat.has('management.client-capabilities')) {
    const reported = parseClientCapabilities(flat.get('management.client-capabilities'));
    if (reported && !sameCapabilities(reported, parseClientCapabilities(f.ddm_client_capabilities))) {
      await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId })
        .update({ ddm_client_capabilities: JSON.stringify(reported), updated_at: new Date() });
      effects.capabilitiesChanged = true;
    }
  }

  // management.declarations: the device's whole view replaces the previous one.
  if (flat.has('management.declarations')) {
    const statuses = declarationStatuses(flat.get('management.declarations'));
    const newer = await trx('apple_declaration_status').where({ tenant_id: tenantId, device_id: deviceId }).where('observed_at', '>', receivedAt).first('identifier');
    if (!newer) {
      await trx('apple_declaration_status').where({ tenant_id: tenantId, device_id: deviceId }).del();
      for (let i = 0; i < statuses.length; i += 500) {
        await trx('apple_declaration_status').insert(statuses.slice(i, i + 500).map((s) => ({
          tenant_id: tenantId, device_id: deviceId, identifier: s.identifier, family: s.family, server_token: s.serverToken, active: s.active,
          valid: s.valid, reasons: s.reasons === null ? null : JSON.stringify(s.reasons), observed_at: receivedAt,
        })));
      }
      effects.declarations = statuses.length;
      for (const h of hooks) if (h.onDeclarationStatus) await h.onDeclarationStatus(trx, tenantId, deviceId, statuses);
    }
  }

  // device.operating-system.*, device.model.*: the columns of the record, unless a DeviceInformation answer is newer.
  let resolutionFacts = false;
  if (!f.last_device_info_at || receivedAt.getTime() >= new Date(f.last_device_info_at).getTime()) {
    const device: Record<string, unknown> = {};
    const osVersion = str(flat.get('device.operating-system.version'), 200);
    if (osVersion && osVersion !== f.os_version) {
      device.os_version = osVersion;
      effects.osChanged = true;
      effects.majorChanged = (majorMinor(osVersion)?.[0] ?? null) !== (majorMinor(f.os_version)?.[0] ?? null);
    }
    const build = str(flat.get('device.operating-system.build-version'), 32);
    if (build && build !== f.os_build) device.os_build = build;
    const model = str(flat.get('device.model.identifier'), 64);
    if (model && model !== f.model) device.model = model;
    const marketing = str(flat.get('device.model.marketing-name'), 128);
    if (marketing && marketing !== f.model_name) device.model_name = marketing;
    // The platform follows the model identifier (iPhone…, iPad…), within Apple's mobile platforms only.
    const platform = platformFromProductName(model ?? '');
    if ((platform === 'ios' || platform === 'ipados') && (f.platform === 'ios' || f.platform === 'ipados') && platform !== f.platform) device.platform = platform;
    if (Object.keys(device).length > 0) await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update({ ...device, updated_at: new Date() });
    // The platform and the model are read by the resolution of the policies (availability, variables).
    resolutionFacts = device.platform !== undefined || device.model_name !== undefined;
  }

  // device.identifier.*: a check only, never a write.
  const serial = normalizeSerial(flat.get('device.identifier.serial-number'));
  if (serial && f.serial_number && serial !== f.serial_number.toUpperCase()) {
    await raiseInTx(trx, tenantId, 'security.identity_mismatch', { discriminant: deviceId, params: { field: 'serial' } });
  }
  const udid = str(flat.get('device.identifier.udid'), 128);
  if (udid && f.udid && udid.toUpperCase() !== f.udid.toUpperCase()) {
    await raiseInTx(trx, tenantId, 'security.identity_mismatch', { discriminant: deviceId, params: { field: 'UDID' } });
  }

  // Lists with a home of their own.
  if (flat.has('app.managed.list')) await applyManagedApps(trx, tenantId, deviceId, flat.get('app.managed.list'), rules.installedApps === 'managed_only', receivedAt);
  if (flat.has('security.certificate.list')) {
    flat.set('security.certificate.list', await applyCertificates(trx, tenantId, deviceId, flat.get('security.certificate.list'),
      f.cert_sha256 ? String(f.cert_sha256).trim() : null, receivedAt));
  }

  // Every other item: its last value and its history (the data model's writer refilters with the privacy rules).
  const rows: Array<{ item: string; value: unknown }> = [];
  for (const [item, value] of flat) {
    if (NOT_STATUS_ROWS.has(item)) continue;
    let size: number;
    try { size = Buffer.byteLength(canonicalJson(value ?? null), 'utf8'); } catch { continue; }
    if (size <= MAX_ITEM_BYTES) rows.push({ item, value });
  }
  if (rows.length > 0) effects.changed = (await ingestStatusItems(trx, tenantId, deviceId, rows, receivedAt)).changed;

  // A contact of the device.
  await trx.raw('UPDATE obligarth.devices SET last_checkin_at = GREATEST(last_checkin_at, ?::timestamptz) WHERE tenant_id = ? AND id = ?',
    [receivedAt, tenantId, deviceId]);

  // What follows: the set (capabilities, major version), the resolution of the policies (what its availability reads).
  if ((effects.capabilitiesChanged || effects.majorChanged) && requestSync) await requestSync(trx, tenantId, deviceId);
  if (effects.capabilitiesChanged || effects.osChanged || resolutionFacts) await requestDeviceResolution(trx, tenantId, [deviceId]);
  // The dynamic groups: what the base marked of the facts the status carries (the OS version) is computed again.
  if (effects.osChanged || resolutionFacts) await requestGroupEvaluation(trx, tenantId, [deviceId]);
  if (effects.changed.length > 0) for (const h of hooks) if (h.onItemsChanged) await h.onItemsChanged(trx, tenantId, deviceId, effects.changed);
  return effects;
}
