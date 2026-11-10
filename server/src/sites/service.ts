import type { Knex } from 'knex';
import {
  AGENT_APPCONFIG_KEY_PREFIX, LEGACY_AGENT_POLICY_MIN_VERSION_CODE, SITE_LIMITS as L, siteDeviceReasons, siteDeviceState,
  type SiteCounts, type SiteDetail, type SiteDeviceView, type SiteImportResult, type SitesFromDevicesResult, type SiteView,
} from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../audit';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { deviceService } from '../services/device.service';
import { permissionService } from '../services/permission.service';
import { instanceSettings } from '../legacyAgent/config';
import { compileAgentPolicy } from '../legacyAgent/policyChannel';
import { customFieldsOf, loadResolutionInput } from '../mdm/policies/loader';
import { resolveDevices, type ResolutionDevice } from '../mdm/policies/resolver';
import { requestDeviceResolution } from '../mdm/policies/triggers';
import {
  checkSite, planFromDevices, planImport, siteValuesOf, type CleanSite, type FieldsDevice, type FromDevicesKeys, type FromDevicesPlan,
  type ImportPlan, type SiteRow,
} from './model';
import { lockSites } from './lock';
import { revokeSiteTokensInTx } from '../legacyAgent/tokens';

// =============================================================================
// The sites of a tenant (lot P1-SITE §2): reads with the state of their devices, the writes of the console and of the
// MCP (one site, an import, the sites made from the custom fields, the site of devices), each in one transaction under
// the tenant's sites lock (a plan made again inside it: an import or an approval never applies a plan another write
// overtook), audited, the resolution of the devices whose values change requested (their file templates rendered
// again). In the caller's tenant context (RLS); `visible`: the devices the caller sees ('all': every one); `who`: the
// human a change of what the templates read runs as, his rights on every device of the sites changed checked under
// the lock (requireSiteReach). The guard of these writes (sites.apply, the thresholds) is the callers' (sites/guard.ts).
// Never a move of group: the console files the device in the group of its site through the guarded move
// (mdm/policies/deviceMove.ts), the MCP leaves it to move_devices_to_group.
// =============================================================================

export type Visible = number[] | 'all';
type Q = Knex | Knex.Transaction;
/** Runs in the transaction of a write, after it (the MCP authorization closes there, exactly once). */
export type InTx<T> = (trx: Knex.Transaction, result: T) => Promise<void>;
/** The human a write runs as: a value of a site reaches every device of the site, so a change of what their templates
 *  read needs his read and write access on each of them ('admin': a platform administrator, every device). */
export interface SiteWho { userId: number; admin: boolean }
/** Runs under the sites lock before a write (the MCP compares there the plan it approved with the plan made again). */
export type Before<T> = (trx: Knex.Transaction, current: T) => Promise<void>;
export const planChanged = (): AppError => new AppError(409, 'The sites changed since this plan was made: nothing was applied', 'planChanged');

const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const siteNotFound = (): AppError => new AppError(404, 'Site not found', 'siteNotFound');
export const isSiteId = (v: unknown): v is string => typeof v === 'string' && UUID_RE.test(v);

/** The devices the caller sees, on a query of devices aliased d (siteDevices) or not (fieldsDevices). */
const restrictTo = (q: Knex.QueryBuilder, aliased: boolean, visible: Visible): void => {
  if (visible === 'all') return;
  if (aliased) q.whereRaw('d.id = ANY (?::int[])', [visible]);
  else q.whereRaw('id = ANY (?::int[])', [visible]);
};

const rowOf = (r: Record<string, any>): SiteRow => ({
  id: String(r.id), code: String(r.code), name: String(r.name), city: r.city ?? null, contact: r.contact ?? null,
  groupId: r.group_id === null || r.group_id === undefined ? null : Number(r.group_id), values: siteValuesOf(r.values),
  archived: !!r.archived_at,
});

/** Every site of the tenant, archived ones included (the plans). */
export async function existingSites(q: Q, tenantId: number): Promise<SiteRow[]> {
  const rows = await q('sites').where({ tenant_id: tenantId }).orderBy('code').select('*') as Array<Record<string, any>>;
  return rows.map(rowOf);
}

// ── States of the devices ────────────────────────────────────────────────────

/** The version the agent must reach: the instance's minimum, at least the one of the agent policies. */
async function minAgentVersion(): Promise<number> {
  const s = await instanceSettings();
  return Math.max(s.minVersionCode, LEGACY_AGENT_POLICY_MIN_VERSION_CODE);
}

interface DeviceFactRow {
  id: number; label: string | null; platform: string; management_channel: string; group_id: number | null; site_id: string;
  last_checkin_at: Date | null; storage_available_bytes: string | number | null; agent_version_code: number | null;
  agent_version_name: string | null; admin_active: boolean | null; revoked_at: Date | null; unresolved: number;
  unresolved_appconfig: number;
}

/** The devices under management of sites (all the sites of the tenant, or `siteIds`) the caller sees, with the facts
 *  of their state. */
async function siteDevices(q: Q, tenantId: number, visible: Visible, siteIds: string[] | null): Promise<DeviceFactRow[]> {
  const query = q('devices as d')
    .leftJoin('legacy_agent_devices as la', function joinAgent() { this.on('la.device_id', '=', 'd.id').andOn('la.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereNotNull('d.site_id').whereNot('d.enrollment_state', 'unenrolled')
    .orderBy('d.label').orderBy('d.id')
    .select('d.id', 'd.label', 'd.platform', 'd.management_channel', 'd.group_id', 'd.site_id', 'd.last_checkin_at', 'd.storage_available_bytes',
      'la.agent_version_code', 'la.agent_version_name', 'la.admin_active', 'la.revoked_at',
      // The files apart from the managed configurations of apps: "file not created" sends the store to the files.
      q.raw(`(SELECT count(*)::int FROM device_effective_settings x
               WHERE x.tenant_id = d.tenant_id AND x.device_id = d.id AND NOT x.removed
                 AND x.unavailable_reason = 'variable_unresolved' AND x.setting_key LIKE 'agent:%'
                 AND x.setting_key NOT LIKE ?) AS unresolved`, [`${AGENT_APPCONFIG_KEY_PREFIX}%`]),
      q.raw(`(SELECT count(*)::int FROM device_effective_settings x
               WHERE x.tenant_id = d.tenant_id AND x.device_id = d.id AND NOT x.removed
                 AND x.unavailable_reason = 'variable_unresolved' AND x.setting_key LIKE ?) AS unresolved_appconfig`,
      [`${AGENT_APPCONFIG_KEY_PREFIX}%`]));
  if (siteIds) query.whereIn('d.site_id', siteIds);
  restrictTo(query, true, visible);
  return await query as DeviceFactRow[];
}

/** The variables without a value of a device: of its file templates, of its managed configurations of apps. */
interface Missing { files: string[]; appConfigs: string[] }

function deviceView(r: DeviceFactRow, now: Date, minVersion: number, missing: Missing = { files: [], appConfigs: [] }): SiteDeviceView {
  const agent = r.management_channel === 'legacy_agent' && !r.revoked_at;
  const storage = r.storage_available_bytes === null || r.storage_available_bytes === undefined ? null : Number(r.storage_available_bytes);
  const reasons = siteDeviceReasons({
    lastCheckinAt: r.last_checkin_at, agentVersionCode: agent && r.agent_version_code !== null ? Number(r.agent_version_code) : null,
    adminActive: agent && r.admin_active !== null ? !!r.admin_active : null, storageAvailableBytes: storage, unresolvedSettings: Number(r.unresolved ?? 0),
    unresolvedAppConfigs: Number(r.unresolved_appconfig ?? 0),
  }, now, minVersion);
  return {
    id: Number(r.id), label: String(r.label ?? ''), platform: r.platform, channel: r.management_channel,
    groupId: r.group_id === null ? null : Number(r.group_id), lastCheckinAt: iso(r.last_checkin_at),
    agentVersionName: agent ? r.agent_version_name ?? null : null, storageAvailableBytes: storage,
    state: siteDeviceState(reasons), reasons, missingVariables: missing.files, missingAppConfigVariables: missing.appConfigs,
  };
}

const emptyCounts = (): SiteCounts => ({ devices: 0, ready: 0, todo: 0, stale: 0, fileNotCreated: 0 });

function count(c: SiteCounts, d: SiteDeviceView): void {
  c.devices++;
  c[d.state]++;
  if (d.reasons.includes('file_not_created')) c.fileNotCreated++;
}

function viewOf(r: Record<string, any>, counts: SiteCounts): SiteView {
  return {
    id: String(r.id), code: String(r.code), name: String(r.name), city: r.city ?? null, contact: r.contact ?? null,
    groupId: r.group_id === null || r.group_id === undefined ? null : Number(r.group_id), groupName: r.group_name ?? null,
    values: siteValuesOf(r.values), archivedAt: iso(r.archived_at), createdAt: iso(r.created_at) as string,
    updatedAt: iso(r.updated_at) as string, counts,
  };
}

const siteQuery = (q: Q, tenantId: number) => q('sites as s')
  .leftJoin('device_groups as g', function joinGroup() { this.on('g.id', '=', 's.group_id').andOn('g.tenant_id', '=', 's.tenant_id'); })
  .where('s.tenant_id', tenantId)
  .select('s.*', 'g.name as group_name');

/** The sites of the tenant (GET /api/sites): a search on the code, the name and the city, the archived ones on demand,
 *  each with the counts of its devices the caller sees. */
export async function listSites(tenantId: number, opts: { q?: string; archived?: boolean; visible: Visible }): Promise<SiteView[]> {
  const query = siteQuery(db, tenantId).orderBy('s.code').limit(L.perTenant);
  if (!opts.archived) query.whereNull('s.archived_at');
  const t = (opts.q ?? '').trim();
  if (t) {
    const pat = `%${t.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    query.where(function search() { this.whereILike('s.code', pat).orWhereILike('s.name', pat).orWhereILike('s.city', pat); });
  }
  const rows = await query as Array<Record<string, any>>;
  const counts = new Map<string, SiteCounts>(rows.map((r) => [String(r.id), emptyCounts()]));
  if (rows.length) {
    const now = new Date();
    const min = await minAgentVersion();
    for (const d of await siteDevices(db, tenantId, opts.visible, null)) {
      const c = counts.get(String(d.site_id));
      if (c) count(c, deviceView(d, now, min));
    }
  }
  return rows.map((r) => viewOf(r, counts.get(String(r.id))!));
}

/** One site with its devices, their state, what to do, and the variables their templates lack. */
export async function siteDetail(tenantId: number, id: string, visible: Visible): Promise<SiteDetail> {
  if (!isSiteId(id)) throw siteNotFound();
  const r = await siteQuery(db, tenantId).where('s.id', id.toLowerCase()).first() as Record<string, any> | undefined;
  if (!r) throw siteNotFound();
  const now = new Date();
  const min = await minAgentVersion();
  const rows = await siteDevices(db, tenantId, visible, [String(r.id)]);
  // The variables without a value, from the resolution of the devices whose file is not created (in memory, never
  // written): what "fill in the value X of the site" says.
  const missing = new Map<number, Missing>();
  const flagged = rows.filter((d) => Number(d.unresolved) > 0 || Number(d.unresolved_appconfig) > 0).map((d) => Number(d.id)).slice(0, 200);
  if (flagged.length) {
    const input = await loadResolutionInput(db, tenantId, flagged);
    const out = resolveDevices(input);
    for (const dev of out.devices) {
      const files = new Set<string>();
      const appConfigs = new Set<string>();
      for (const s of dev.settings) {
        if (s.kind === 'agent' && s.availability.status === 'not_applicable' && s.availability.reason === 'variable_unresolved' && s.availability.detail) {
          (s.settingKey.startsWith(AGENT_APPCONFIG_KEY_PREFIX) ? appConfigs : files).add(s.availability.detail);
        }
      }
      missing.set(dev.deviceId, { files: [...files].sort(), appConfigs: [...appConfigs].sort() });
    }
  }
  const devices = rows.map((d) => deviceView(d, now, min, missing.get(Number(d.id))));
  const counts = emptyCounts();
  for (const d of devices) count(counts, d);
  return { ...viewOf(r, counts), devices };
}

/** The site of a request, in the tenant (404 otherwise). */
export async function siteRow(q: Q, tenantId: number, id: string): Promise<SiteRow> {
  if (!isSiteId(id)) throw siteNotFound();
  const r = await q('sites').where({ tenant_id: tenantId, id: id.toLowerCase() }).first() as Record<string, any> | undefined;
  if (!r) throw siteNotFound();
  return rowOf(r);
}

/** The site an enrollment token names (lot P1-QR §3.2), in the token's transaction: under the sites lock (an archive in
 *  between waits), of the tenant (404) and not archived (409 siteArchived). */
export async function usableSiteInTx(trx: Knex.Transaction, tenantId: number, id: string): Promise<SiteRow> {
  await lockSites(trx, tenantId);
  const site = await siteRow(trx, tenantId, id);
  if (site.archived) throw new AppError(409, 'This site is archived', 'siteArchived');
  return site;
}

// ── Writes ───────────────────────────────────────────────────────────────────

const invalid = (issues: string[]): AppError => new AppError(400, `Invalid site: ${issues.join(', ')}`, 'invalidSite', { issues });

/** A group of the tenant the site may name (404 groupNotFound otherwise). */
async function checkGroup(q: Q, tenantId: number, groupId: number | null | undefined): Promise<void> {
  if (groupId === null || groupId === undefined) return;
  if (!(await q('device_groups').where({ tenant_id: tenantId, id: groupId }).first('id'))) throw new AppError(404, 'Group not found', 'groupNotFound');
}

const codeTaken = (err: unknown): boolean => (err as { code?: string; constraint?: string })?.code === '23505'
  && /sites_code_uq/.test(String((err as { constraint?: string }).constraint ?? ''));

/** The devices of sites (under management or not: a value of a site is theirs as soon as they come back). */
async function devicesOfSites(q: Q, tenantId: number, siteIds: string[]): Promise<number[]> {
  if (!siteIds.length) return [];
  return (await q('devices').where({ tenant_id: tenantId }).whereIn('site_id', siteIds).pluck('id') as number[]).map(Number);
}

/** The devices under management of sites (those a change of their values reaches; the scope of its restriction). */
export async function managedDevicesOfSites(q: Q, tenantId: number, siteIds: string[]): Promise<number[]> {
  if (!siteIds.length) return [];
  return (await q('devices').where({ tenant_id: tenantId }).whereIn('site_id', siteIds).whereNot('enrollment_state', 'unenrolled')
    .orderBy('id').pluck('id') as number[]).map(Number);
}

/** After a commit: the devices whose record changed (the console's live list). */
function emitAfter(tenantId: number, ids: number[]): void {
  if (ids.length) deviceService.emitChanged(tenantId, ids);
}

// ── Rights on the devices a write reaches ────────────────────────────────────

/** Read and write access of the human on each device (404 an unseen one, 403 one he may not write). */
export async function requireWritesOf(who: SiteWho, ids: number[]): Promise<void> {
  if (who.admin) return;
  for (const id of [...new Set(ids)]) {
    if (!(await permissionService.canReadDevice(who.userId, id, false))) throw new AppError(404, 'Device not found');
    if (!(await permissionService.canWriteDevice(who.userId, id, false))) throw new AppError(403, 'Insufficient permissions');
  }
}

/**
 * A change of what the templates of a site's devices read (its code, name, city or values) reaches every device under
 * management on the site: the human must see and write each one, or he would change the file deposited on phones
 * outside his rights (403 siteOutsidePerimeter, the devices he lacks counted, never named).
 */
export async function requireSiteReach(q: Q, tenantId: number, who: SiteWho, siteIds: string[]): Promise<void> {
  if (who.admin || !siteIds.length) return;
  const ids = (await q('devices').where({ tenant_id: tenantId }).whereIn('site_id', siteIds).whereNot('enrollment_state', 'unenrolled')
    .pluck('id') as number[]).map(Number);
  let outside = 0;
  for (const id of ids) {
    if (!(await permissionService.canReadDevice(who.userId, id, false)) || !(await permissionService.canWriteDevice(who.userId, id, false))) outside++;
  }
  if (outside) {
    throw new AppError(403, 'Some devices of this site are outside your rights: an administrator changes its values', 'siteOutsidePerimeter', { devices: outside });
  }
}

// ── Policy impact (D18) ──────────────────────────────────────────────────────

/** A site as the templates read it. */
export interface RenderedSite { code: string; name: string; city: string | null; values: Record<string, string> }
const renderedOf = (s: RenderedSite): NonNullable<ResolutionDevice['site']> =>
  ({ code: s.code, name: s.name, city: s.city ?? null, values: customFieldsOf(s.values) });

/** What a write changes in what the templates read: sites with their next fields, devices with their next site. */
export interface SiteImpactChange {
  sites?: Array<RenderedSite & { id: string }>;
  attach?: Array<{ deviceId: number; site: RenderedSite | null }>;
}

/**
 * How many devices' agent:policy a write changes (the publication thresholds, D18, as the import of per-device values):
 * their resolution compiled before and after, in memory. The devices under management of the sites changed and those
 * whose site changes.
 */
export async function sitePolicyImpact(q: Q, tenantId: number, change: SiteImpactChange): Promise<number> {
  const bySite = new Map((change.sites ?? []).map((s) => [s.id, s]));
  const attach = new Map((change.attach ?? []).map((a) => [a.deviceId, a.site]));
  const onSites = bySite.size
    ? await q('devices').where({ tenant_id: tenantId }).whereIn('site_id', [...bySite.keys()]).whereNot('enrollment_state', 'unenrolled')
      .select('id', 'site_id') as Array<{ id: number; site_id: string }>
    : [];
  const siteOfDevice = new Map(onSites.map((r) => [Number(r.id), String(r.site_id)]));
  const ids = [...new Set([...siteOfDevice.keys(), ...attach.keys()])].sort((a, b) => a - b);
  if (!ids.length) return 0;
  const input = await loadResolutionInput(q, tenantId, ids);
  const before = resolveDevices(input);
  const patched = input.devices.map((d) => {
    if (attach.has(d.id)) { const s = attach.get(d.id); return { ...d, site: s ? renderedOf(s) : null }; }
    const s = bySite.get(siteOfDevice.get(d.id) ?? '');
    return s ? { ...d, site: renderedOf(s) } : d;
  });
  const after = resolveDevices({ ...input, devices: patched });
  let n = 0;
  input.devices.forEach((d, i) => {
    const a = compileAgentPolicy(d, before.devices[i].settings, input.tenant, tenantId)?.hash ?? null;
    const b = compileAgentPolicy(patched[i], after.devices[i].settings, input.tenant, tenantId)?.hash ?? null;
    if (a !== b) n++;
  });
  return n;
}

// ── One site ─────────────────────────────────────────────────────────────────

/** What a change of a site changes: its columns, the fields named (the audit), the value keys that differ, and whether
 *  the templates of its devices read one of them (code, name, city, values). */
export function siteChanges(prev: SiteRow, site: CleanSite): { changes: Record<string, unknown>; fields: string[]; valueKeys: string[]; rendered: boolean } {
  const changes: Record<string, unknown> = {};
  const fields: string[] = [];
  if (site.code !== undefined && site.code !== prev.code) { changes.code = site.code; fields.push('code'); }
  if (site.name !== undefined && site.name !== prev.name) { changes.name = site.name; fields.push('name'); }
  if (site.city !== undefined && site.city !== prev.city) { changes.city = site.city; fields.push('city'); }
  if (site.contact !== undefined && site.contact !== prev.contact) { changes.contact = site.contact; fields.push('contact'); }
  if (site.groupId !== undefined && site.groupId !== prev.groupId) { changes.group_id = site.groupId; fields.push('groupId'); }
  const valueKeys: string[] = [];
  if (site.values !== undefined) {
    const keys = new Set([...Object.keys(prev.values), ...Object.keys(site.values)]);
    for (const k of keys) if (prev.values[k] !== site.values[k]) valueKeys.push(k);
    if (valueKeys.length) { changes.values = JSON.stringify(site.values); fields.push('values'); }
  }
  return { changes, fields, valueKeys: valueKeys.sort(), rendered: fields.some((f) => f !== 'contact' && f !== 'groupId') };
}

/** The site once a change is applied, as its templates read it. */
export const siteAfter = (prev: SiteRow, site: CleanSite): RenderedSite & { id: string } => ({
  id: prev.id, code: site.code ?? prev.code, name: site.name ?? prev.name, city: site.city !== undefined ? site.city : prev.city,
  values: site.values ?? prev.values,
});

/** Creates a site (POST /api/sites, upsert_site). A new site has no device: nothing rendered changes. */
export async function createSite(tenantId: number, body: CleanSite, ctx: AuditWriteContext, inTx?: InTx<SiteRow>,
  opts: { before?: Before<null> } = {}): Promise<SiteRow> {
  const { site, issues } = checkSite(body, true);
  if (issues.length) throw invalid(issues);
  return db.transaction(async (trx) => {
    await lockSites(trx, tenantId);
    if (opts.before) await opts.before(trx, null);
    await checkGroup(trx, tenantId, site.groupId);
    const n = await trx('sites').where({ tenant_id: tenantId }).count({ n: '*' }).first() as { n: string | number };
    if (Number(n?.n ?? 0) >= L.perTenant) throw new AppError(409, 'Too many sites in this tenant', 'tooManySites');
    let r: Record<string, any>;
    try {
      [r] = await trx('sites').insert({
        tenant_id: tenantId, code: site.code, name: site.name, city: site.city ?? null, contact: site.contact ?? null,
        group_id: site.groupId ?? null, values: JSON.stringify(site.values ?? {}),
      }).returning('*') as Array<Record<string, any>>;
    } catch (err) {
      if (codeTaken(err)) throw new AppError(409, 'A site of this tenant already has this code', 'siteCodeTaken');
      throw err;
    }
    await audit.appendInTx(trx, {
      tenantId, action: 'site.created', target: { type: 'site', id: String(r.id) },
      details: { code: r.code, name: r.name, groupId: r.group_id ?? null, valueKeys: Object.keys(site.values ?? {}).sort() },
    }, ctx);
    if (inTx) await inTx(trx, rowOf(r));
    return rowOf(r);
  });
}

/** Changes a site (PATCH /api/sites/:id, upsert_site): the fields given; `values` replaces the values. The devices of
 *  the site are resolved again when what their templates read changes (code, name, city, values); such a change needs,
 *  for `who`, his rights on every device of the site (requireSiteReach), checked again under the lock. */
export async function updateSite(tenantId: number, id: string, body: CleanSite, ctx: AuditWriteContext, inTx?: InTx<SiteRow>,
  opts: { who?: SiteWho; before?: Before<SiteRow> } = {}): Promise<SiteRow> {
  const { site, issues } = checkSite(body, false);
  if (issues.length) throw invalid(issues);
  const out = await db.transaction(async (trx) => {
    await lockSites(trx, tenantId);
    const prev = await siteRow(trx, tenantId, id);
    if (opts.before) await opts.before(trx, prev);
    if (prev.archived) throw new AppError(409, 'This site is archived', 'siteArchived');
    await checkGroup(trx, tenantId, site.groupId);
    const { changes, fields, valueKeys, rendered } = siteChanges(prev, site);
    if (!fields.length) { if (inTx) await inTx(trx, prev); return { row: prev, ids: [] as number[] }; }
    if (rendered && opts.who) await requireSiteReach(trx, tenantId, opts.who, [prev.id]);
    let r: Record<string, any>;
    try {
      [r] = await trx('sites').where({ tenant_id: tenantId, id: prev.id }).update({ ...changes, updated_at: new Date() }).returning('*') as Array<Record<string, any>>;
    } catch (err) {
      if (codeTaken(err)) throw new AppError(409, 'A site of this tenant already has this code', 'siteCodeTaken');
      throw err;
    }
    await audit.appendInTx(trx, {
      tenantId, action: 'site.updated', target: { type: 'site', id: prev.id },
      details: { code: r.code, fields, ...(valueKeys.length ? { valueKeys } : {}) },
    }, ctx);
    const ids = rendered ? await devicesOfSites(trx, tenantId, [prev.id]) : [];
    if (ids.length) await requestDeviceResolution(trx, tenantId, ids);
    if (inTx) await inTx(trx, rowOf(r));
    return { row: rowOf(r), ids };
  });
  emitAfter(tenantId, out.ids);
  return out.row;
}

/** The devices under management on a site (those its page shows to an administrator; archiving waits for them). */
export async function managedOnSite(q: Q, tenantId: number, siteId: string): Promise<number> {
  const n = await q('devices').where({ tenant_id: tenantId, site_id: siteId }).whereNot('enrollment_state', 'unenrolled')
    .count({ n: '*' }).first() as { n: string | number } | undefined;
  return Number(n?.n ?? 0);
}

/** The user a write runs as ('u:<id>'), null for another actor (a token it revokes then names its creator). */
const userOfActor = (ctx: AuditWriteContext): number | null => {
  const m = /^u:(\d+)$/.exec(ctx.actor.ref);
  return m ? Number(m[1]) : null;
};

/** Archives a site (POST /api/sites/:id/archive, archive_site): refused while devices under management are attached to
 *  it (their templates would lose its values); the unenrolled ones left on it (the site page does not show them) are
 *  detached, and the enrollment tokens still usable that name it revoked (lot P1-QR §3.2: its printed sheets would
 *  enroll phones without their site, their templates without its values; a restored site gets a new sheet). */
export async function archiveSite(tenantId: number, id: string, ctx: AuditWriteContext, archived = true, inTx?: InTx<SiteRow>,
  opts: { before?: Before<SiteRow> } = {}): Promise<SiteRow> {
  const out = await db.transaction(async (trx) => {
    await lockSites(trx, tenantId);
    const prev = await siteRow(trx, tenantId, id);
    if (opts.before) await opts.before(trx, prev);
    if (prev.archived === archived) { if (inTx) await inTx(trx, prev); return { row: prev, detached: [] as number[] }; }
    let detached: number[] = [];
    let revokedTokens = 0;
    if (archived) {
      const n = await managedOnSite(trx, tenantId, prev.id);
      if (n > 0) throw new AppError(409, 'Detach the devices of the site before archiving it', 'siteNotEmpty', { devices: n });
      const gone = (await trx('devices').where({ tenant_id: tenantId, site_id: prev.id }).pluck('id') as number[]).map(Number);
      if (gone.length) detached = (await setSiteInTx(trx, tenantId, gone, null, ctx)).changed;
      // Under the sites lock: an enrollment by one of these tokens (enroll.ts takes it too) ran before, and is counted
      // above, or finds its token revoked.
      revokedTokens = (await revokeSiteTokensInTx(trx, tenantId, prev.id, { by: userOfActor(ctx), ctx, reason: 'site_archived', sheetsOnly: false })).length;
    }
    const [r] = await trx('sites').where({ tenant_id: tenantId, id: prev.id })
      .update({ archived_at: archived ? new Date() : null, updated_at: new Date() }).returning('*') as Array<Record<string, any>>;
    await audit.appendInTx(trx, {
      tenantId, action: archived ? 'site.archived' : 'site.restored', target: { type: 'site', id: prev.id },
      details: { code: prev.code, ...(detached.length ? { detachedUnenrolled: detached.length } : {}), ...(revokedTokens ? { revokedTokens } : {}) },
    }, ctx);
    if (inTx) await inTx(trx, rowOf(r));
    return { row: rowOf(r), detached };
  });
  emitAfter(tenantId, out.detached);
  return out.row;
}

// ── The site of devices ──────────────────────────────────────────────────────

export interface AttachOutcome {
  /** Devices whose site changed. */
  changed: number[];
  unchanged: number[];
  /** The group of the site, and the devices of the change not in it (the console offers the guarded move). */
  siteGroupId: number | null;
  outsideGroup: number[];
}

/** Sets the site of devices (null: none) in a transaction already under the sites lock; one entry per device changed,
 *  their resolution requested. */
async function setSiteInTx(trx: Knex.Transaction, tenantId: number, deviceIds: number[], site: SiteRow | null, ctx: AuditWriteContext): Promise<AttachOutcome> {
  const ids = [...new Set(deviceIds)].sort((a, b) => a - b);
  const rows = await trx('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [ids]).orderBy('id').forUpdate()
    .select('id', 'site_id', 'group_id') as Array<{ id: number; site_id: string | null; group_id: number | null }>;
  if (rows.length !== ids.length) throw new AppError(404, 'Device not found');
  const target = site?.id ?? null;
  const changed = rows.filter((r) => (r.site_id ?? null) !== target);
  const now = new Date();
  if (changed.length) {
    await trx('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [changed.map((r) => Number(r.id))])
      .update({ site_id: target, updated_at: now });
    for (const r of changed) {
      await audit.appendInTx(trx, {
        tenantId, action: 'device.site_changed', target: { type: 'device', id: String(r.id), device: Number(r.id) },
        details: { from: r.site_id ?? null, to: target, ...(site ? { code: site.code } : {}) },
      }, ctx);
    }
    await requestDeviceResolution(trx, tenantId, changed.map((r) => Number(r.id)));
  }
  const groupId = site?.groupId ?? null;
  return {
    changed: changed.map((r) => Number(r.id)), unchanged: rows.filter((r) => (r.site_id ?? null) === target).map((r) => Number(r.id)),
    siteGroupId: groupId, outsideGroup: groupId === null ? [] : rows.filter((r) => r.group_id === null || Number(r.group_id) !== groupId).map((r) => Number(r.id)),
  };
}

/** Sets the site of devices (PUT /api/mdm/devices/:id/site, POST /api/sites/:id/devices, set_device_site). The caller
 *  checked its rights on each device. An archived site takes no device. */
export async function setDevicesSite(tenantId: number, deviceIds: number[], siteId: string | null, ctx: AuditWriteContext,
  inTx?: InTx<AttachOutcome>, opts: { before?: Before<null> } = {}): Promise<AttachOutcome> {
  if (deviceIds.length > L.bulkDevices) throw new AppError(400, `At most ${L.bulkDevices} devices per call`, 'invalidRequest');
  const out = await db.transaction(async (trx) => {
    await lockSites(trx, tenantId);
    if (opts.before) await opts.before(trx, null);
    const site = siteId === null ? null : await siteRow(trx, tenantId, siteId);
    if (site?.archived) throw new AppError(409, 'This site is archived', 'siteArchived');
    const o = await setSiteInTx(trx, tenantId, deviceIds, site, ctx);
    if (inTx) await inTx(trx, o);
    return o;
  });
  emitAfter(tenantId, out.changed);
  return out;
}

// ── Import and the sites from the custom fields ──────────────────────────────

/** A plan that cannot be made (no usable header): 400 with its reason. */
function planRefused(e: { error: string; column?: string }): AppError {
  return new AppError(400, `The file cannot be imported: ${e.error}${e.column ? ` (${e.column})` : ''}`, 'importRefused', { reason: e.error, column: e.column ?? null });
}

/** The plan of an import as the tenant stands (dry run), with its policy impact (outside the digest). */
export async function previewImport(tenantId: number, csv: string): Promise<SiteImportResult> {
  const existing = await existingSites(db, tenantId);
  const plan = planImport(csv, existing, { dryRun: true });
  if ('error' in plan) throw planRefused(plan);
  return { ...plan.result, policyImpact: await sitePolicyImpact(db, tenantId, importImpactChange(plan, existing)) };
}

/** The sites an import updates (the ones whose devices it reaches). */
export const importUpdatedSites = (plan: ImportPlan): string[] => plan.writes.filter((w) => w.kind === 'update').map((w) => w.id!);

/** What an import changes in what the templates read: the sites it updates (a new site has no device yet). */
export function importImpactChange(plan: ImportPlan, existing: SiteRow[]): SiteImpactChange {
  const byId = new Map(existing.map((x) => [x.id, x]));
  return {
    sites: plan.writes.filter((w) => w.kind === 'update' && byId.has(w.id!)).map((w) => {
      const prev = byId.get(w.id!)!;
      return { id: prev.id, code: w.site.code, name: w.site.name, city: w.site.city !== undefined ? w.site.city : prev.city, values: w.site.values };
    }),
  };
}

/** The plan of an import against the tenant as it stands, and the sites it read (the console's guard). */
export async function importPlanNow(tenantId: number, csv: string): Promise<{ plan: ImportPlan; existing: SiteRow[] }> {
  const existing = await existingSites(db, tenantId);
  const plan = planImport(csv, existing, { dryRun: false });
  if ('error' in plan) throw planRefused(plan);
  return { plan, existing };
}

/** The writes of an import plan, in its transaction; the devices of the sites updated resolved again. */
async function writeImport(trx: Knex.Transaction, tenantId: number, plan: ImportPlan): Promise<number[]> {
  const now = new Date();
  const updated: string[] = [];
  for (const w of plan.writes) {
    const row = {
      code: w.site.code, name: w.site.name, values: JSON.stringify(w.site.values),
      ...(w.site.city !== undefined ? { city: w.site.city } : {}), ...(w.site.contact !== undefined ? { contact: w.site.contact } : {}),
    };
    if (w.kind === 'create') await trx('sites').insert({ tenant_id: tenantId, ...row });
    else { await trx('sites').where({ tenant_id: tenantId, id: w.id }).update({ ...row, updated_at: now }); updated.push(w.id!); }
  }
  return devicesOfSites(trx, tenantId, updated);
}

/**
 * Applies an import (POST /api/sites/import with dryRun false, import_sites approved): the plan made again under the
 * lock; `expectDigest` (the dry run the operator saw, an approved MCP batch or approval): refused (409 planChanged) when
 * the plan differs from it; `who`: his rights on every device of the sites updated (requireSiteReach), under the lock.
 */
export async function applyImport(tenantId: number, csv: string, ctx: AuditWriteContext,
  opts: { expectDigest?: string; source: 'console' | 'mcp'; who?: SiteWho } = { source: 'console' },
  inTx?: (trx: Knex.Transaction, result: SiteImportResult) => Promise<void>): Promise<SiteImportResult> {
  const out = await db.transaction(async (trx) => {
    await lockSites(trx, tenantId);
    const plan = planImport(csv, await existingSites(trx, tenantId), { dryRun: false });
    if ('error' in plan) throw planRefused(plan);
    if (opts.expectDigest !== undefined && plan.result.digest !== opts.expectDigest) throw planChanged();
    if (opts.who) await requireSiteReach(trx, tenantId, opts.who, importUpdatedSites(plan));
    const ids = await writeImport(trx, tenantId, plan);
    const result = { ...plan.result, applied: true };
    await audit.appendInTx(trx, {
      tenantId, action: 'site.imported', target: { type: 'site', id: 'import' },
      details: {
        source: opts.source, created: result.created, updated: result.updated, unchanged: result.unchanged, errors: result.errors,
        codes: plan.writes.map((w) => w.site.code).slice(0, 100), columns: result.columns.values, digest: result.digest,
      },
    }, ctx);
    if (ids.length) await requestDeviceResolution(trx, tenantId, ids);
    if (inTx) await inTx(trx, result);
    return { result, ids };
  });
  emitAfter(tenantId, out.ids);
  return out.result;
}

/** The devices the plan from the custom fields reads: those the caller sees (and, for the MCP, inside its key). */
async function fieldsDevices(q: Q, tenantId: number, visible: Visible): Promise<FieldsDevice[]> {
  const query = q('devices').where({ tenant_id: tenantId }).whereNot('enrollment_state', 'unenrolled').orderBy('id')
    .select('id', 'label', 'site_id', 'custom_fields');
  restrictTo(query, false, visible);
  const rows = await query as Array<{ id: number; label: string | null; site_id: string | null; custom_fields: unknown }>;
  return rows.map((r) => ({ id: Number(r.id), label: String(r.label ?? ''), siteId: r.site_id ?? null, fields: siteValuesOf(r.custom_fields) }));
}

/** The plan of the sites from the custom fields (dry run). */
export async function previewFromDevices(tenantId: number, keys: FromDevicesKeys, visible: Visible): Promise<FromDevicesPlan> {
  return planFromDevices(await fieldsDevices(db, tenantId, visible), await existingSites(db, tenantId), keys, { dryRun: true });
}

/** The existing sites the plan from the custom fields completes (the ones whose devices it reaches). */
export const fromDevicesUpdatedSites = (plan: FromDevicesPlan): string[] => plan.writes.filter((w) => w.kind === 'update').map((w) => w.id!);

/** How many devices' agent policy the plan from the custom fields changes: the sites completed, the devices attached. */
export async function fromDevicesImpact(tenantId: number, plan: FromDevicesPlan): Promise<number> {
  const existing = await existingSites(db, tenantId);
  const byCode = new Map<string, RenderedSite>(existing.map((x) => [x.code.toLowerCase(), x]));
  const sites: Array<RenderedSite & { id: string }> = [];
  for (const w of plan.writes) {
    const prev = w.id ? existing.find((x) => x.id === w.id) : undefined;
    const next = { code: w.site.code, name: w.site.name, city: prev?.city ?? null, values: w.site.values };
    byCode.set(w.site.code.toLowerCase(), next);
    if (prev) sites.push({ ...next, id: prev.id });
  }
  return sitePolicyImpact(db, tenantId, {
    sites, attach: plan.attach.map((a) => ({ deviceId: a.deviceId, site: byCode.get(a.code.toLowerCase()) ?? null })),
  });
}

/** Applies the sites from the custom fields: the plan made again under the lock (and compared with the one shown or
 *  approved), the sites created or completed, the devices attached (never a move of group). `canWrite`: the devices the
 *  caller may attach; `who`: his rights on every device of the sites completed. */
export async function applyFromDevices(tenantId: number, keys: FromDevicesKeys, visible: Visible, ctx: AuditWriteContext,
  opts: { expectDigest?: string; source: 'console' | 'mcp'; canWrite?: (ids: number[]) => Promise<void>; who?: SiteWho } = { source: 'console' },
  inTx?: (trx: Knex.Transaction, result: SitesFromDevicesResult) => Promise<void>): Promise<SitesFromDevicesResult> {
  const out = await db.transaction(async (trx) => {
    await lockSites(trx, tenantId);
    const plan = planFromDevices(await fieldsDevices(trx, tenantId, visible), await existingSites(trx, tenantId), keys, { dryRun: false });
    if (opts.expectDigest !== undefined && plan.result.digest !== opts.expectDigest) throw planChanged();
    if (opts.canWrite) await opts.canWrite(plan.attach.map((a) => a.deviceId));
    if (opts.who) await requireSiteReach(trx, tenantId, opts.who, fromDevicesUpdatedSites(plan));
    const now = new Date();
    const idOf = new Map<string, string>();
    const updated: string[] = [];
    for (const w of plan.writes) {
      if (w.kind === 'create') {
        const [r] = await trx('sites').insert({ tenant_id: tenantId, code: w.site.code, name: w.site.name, values: JSON.stringify(w.site.values) })
          .returning('id') as Array<{ id: string }>;
        idOf.set(w.site.code.toLowerCase(), String(r.id));
      } else {
        await trx('sites').where({ tenant_id: tenantId, id: w.id }).update({ values: JSON.stringify(w.site.values), updated_at: now });
        updated.push(w.id!);
      }
    }
    for (const s of await existingSites(trx, tenantId)) if (!idOf.has(s.code.toLowerCase())) idOf.set(s.code.toLowerCase(), s.id);
    const byCode = new Map<string, number[]>();
    for (const a of plan.attach) byCode.set(a.code.toLowerCase(), [...(byCode.get(a.code.toLowerCase()) ?? []), a.deviceId]);
    const changed: number[] = [];
    const sites = await existingSites(trx, tenantId);
    for (const [code, ids] of byCode) {
      const site = sites.find((s) => s.id === idOf.get(code));
      if (!site) continue;
      for (let i = 0; i < ids.length; i += L.bulkDevices) {
        changed.push(...(await setSiteInTx(trx, tenantId, ids.slice(i, i + L.bulkDevices), site, ctx)).changed);
      }
    }
    const result = { ...plan.result, applied: true };
    await audit.appendInTx(trx, {
      tenantId, action: 'site.imported', target: { type: 'site', id: 'from-devices' },
      details: {
        source: opts.source, from: 'devices', keys: { code: keys.code, name: keys.name, values: keys.values },
        created: plan.writes.filter((w) => w.kind === 'create').length, updated: updated.length, attached: changed.length, digest: result.digest,
      },
    }, ctx);
    const again = (await devicesOfSites(trx, tenantId, updated)).filter((id) => !changed.includes(id));
    if (again.length) await requestDeviceResolution(trx, tenantId, again);
    if (inTx) await inTx(trx, result);
    return { result, ids: [...changed, ...again] };
  });
  emitAfter(tenantId, out.ids);
  return out.result;
}

/** The keys of the values of the tenant's sites (the variable picker of the templates). */
export async function siteValueKeys(tenantId: number): Promise<string[]> {
  const rows = await db('sites').where({ tenant_id: tenantId }).whereNull('archived_at').whereRaw(`jsonb_typeof("values") = 'object'`)
    .distinct(db.raw('jsonb_object_keys("values") AS k')).limit(200) as Array<{ k: string }>;
  return rows.map((r) => r.k).sort();
}
