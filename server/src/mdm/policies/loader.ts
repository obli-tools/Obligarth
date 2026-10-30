import type { Knex } from 'knex';
import type { AssignmentTargetScope, JsonValue, PolicyContentV1 } from '@obligarth/shared';
import { appleCatalog, type AppleCatalogView } from '../apple/catalog';
import { policyContributions, type Contribution } from './contributions';
import {
  resourceKey, type ResolutionAssignment, type ResolutionDevice, type ResolutionInput, type ResolvedResource,
} from './resolver';

// =============================================================================
// The SQL loader of the resolution (docs: modele-donnees-mdm §7.6): what the
// pure resolver reads, in the caller's database context and transaction (the
// tenant's): the assignments of the tenant, the published versions of the
// policies they name (their contributions computed once per version: a
// published version is immutable), the apps, the devices (out of management
// excluded) with the facts of their availability and variables, the ancestry
// of their groups and the dynamic groups they are members of (P0-5 T6).
// =============================================================================

export interface PolicyState {
  tenantId: number;
  tenant: { name: string; slug: string };
  assignments: ResolutionAssignment[];
  resources: Map<string, ResolvedResource>;
}

export interface DeviceSet {
  devices: ResolutionDevice[];
  groupAncestors: Map<number, Array<{ groupId: number; depth: number }>>;
}

// Contributions of the published versions, by tenant and version (immutable once published). They carry the values
// of the version (the compilation reads them): the cache is bounded by their size as well as by their number.
const CACHE_MAX = 1000;
const CACHE_MAX_BYTES = 64 * 1024 * 1024;
const contributionCache = new Map<string, { list: Contribution[]; bytes: number }>();
let cachedBytes = 0;

/** An estimate of what the contributions of a version hold (the JSON of their values). */
function sizeOf(list: Contribution[]): number {
  let n = 0;
  for (const c of list) n += 200 + (c.value === undefined ? 0 : JSON.stringify(c.value).length);
  return n;
}

/** The contributions kept for a version (most recently used last), undefined when they are not known. */
function knownContributions(key: string): Contribution[] | undefined {
  const hit = contributionCache.get(key);
  if (hit) {
    contributionCache.delete(key);
    contributionCache.set(key, hit);
  }
  return hit?.list;
}

function cachedContributions(key: string, compute: () => Contribution[]): Contribution[] {
  const hit = knownContributions(key);
  if (hit) return hit;
  const list = compute();
  const bytes = sizeOf(list);
  contributionCache.set(key, { list, bytes });
  cachedBytes += bytes;
  // The least recently used leave first; the entry just added always stays.
  while (contributionCache.size > 1 && (contributionCache.size > CACHE_MAX || cachedBytes > CACHE_MAX_BYTES)) {
    const oldest = contributionCache.keys().next().value as string;
    cachedBytes -= contributionCache.get(oldest)?.bytes ?? 0;
    contributionCache.delete(oldest);
  }
  return list;
}

/** For the tests: forget the cached contributions. */
export function clearContributionCache(): void {
  contributionCache.clear();
  cachedBytes = 0;
}

const parseJson = <T>(v: unknown): T => (typeof v === 'string' ? JSON.parse(v) as T : v as T);

/** The contributions of a version's content (cached by version once it is published). */
export function contributionsOf(tenantId: number, version: { id: number; content: unknown; state?: string },
  policyUuid: string, catalog: AppleCatalogView = appleCatalog()): Contribution[] {
  const compute = () => policyContributions(parseJson<PolicyContentV1>(version.content), catalog, policyUuid);
  return version.state === undefined || version.state === 'published' || version.state === 'superseded'
    ? cachedContributions(`${tenantId}:${version.id}`, compute)
    : compute();
}

/** The resources of a list of assignments: published policies (their current version), apps not archived. */
export async function loadResources(q: Knex | Knex.Transaction, tenantId: number, assignments: ResolutionAssignment[],
  catalog: AppleCatalogView = appleCatalog()): Promise<Map<string, ResolvedResource>> {
  const resources = new Map<string, ResolvedResource>();
  // By (owner tenant, id), as the assignments name them: the tenant itself, or the master's library (v1).
  const pairsOf = (type: 'policy' | 'app'): Array<[number, number]> => {
    const seen = new Map<string, [number, number]>();
    for (const a of assignments) if (a.resourceType === type) seen.set(`${a.resourceTenantId}:${a.resourceId}`, [a.resourceTenantId, a.resourceId]);
    return [...seen.values()];
  };
  const policyIds = pairsOf('policy');
  const appIds = pairsOf('app');
  if (policyIds.length) {
    const rows = await q('policies as p')
      .join('policy_versions as v', function joinVersion() { this.on('v.id', '=', 'p.current_version_id').andOn('v.tenant_id', '=', 'p.tenant_id'); })
      .whereIn(['p.tenant_id', 'p.id'], policyIds)
      .whereNot('p.state', 'archived')
      .select('p.id', 'p.tenant_id', 'p.uuid', 'p.name', 'v.id as version_id', 'v.state as version_state') as
      Array<{ id: number; tenant_id: number; uuid: string; name: string; version_id: number; version_state: string }>;
    // The content (up to 512 KiB a version) is read only for the versions whose contributions are not known yet:
    // a published version is immutable, and the resolution of one device reads every policy of its tenant.
    const cacheable = catalog === appleCatalog();
    const known = new Map<number, Contribution[]>();
    const unknown: typeof rows = [];
    for (const r of rows) {
      const hit = cacheable ? knownContributions(`${Number(r.tenant_id)}:${Number(r.version_id)}`) : undefined;
      if (hit) known.set(Number(r.version_id), hit); else unknown.push(r);
    }
    const contents = new Map<number, unknown>();
    for (let i = 0; i < unknown.length; i += 50) {
      const slice = await q('policy_versions').whereIn(['tenant_id', 'id'], unknown.slice(i, i + 50).map((r) => [Number(r.tenant_id), Number(r.version_id)]))
        .select('id', 'content') as Array<{ id: number; content: unknown }>;
      for (const c of slice) contents.set(Number(c.id), c.content);
    }
    for (const r of rows) {
      const versionId = Number(r.version_id);
      let contributions = known.get(versionId);
      if (!contributions) {
        if (!contents.has(versionId)) continue;   // gone between the two reads (its tenant deleted): nothing to bring
        const version = { id: versionId, content: contents.get(versionId), state: r.version_state };
        contributions = cacheable
          ? contributionsOf(Number(r.tenant_id), version, r.uuid, catalog)
          : policyContributions(parseJson<PolicyContentV1>(version.content), catalog, r.uuid);
      }
      resources.set(resourceKey('policy', Number(r.tenant_id), Number(r.id)), {
        type: 'policy', id: Number(r.id), tenantId: Number(r.tenant_id), versionId, name: r.name, contributions,
      });
    }
  }
  if (appIds.length) {
    const rows = await q('apps').whereIn(['tenant_id', 'id'], appIds).whereNull('archived_at')
      .select('id', 'tenant_id', 'identifier', 'name', 'supported_platforms', 'store_id', 'platform_family') as
      Array<{ id: number; tenant_id: number; identifier: string; name: string; supported_platforms: string[] | null; store_id: string | null; platform_family: string }>;
    for (const r of rows) {
      resources.set(resourceKey('app', Number(r.tenant_id), Number(r.id)), {
        type: 'app', id: Number(r.id), tenantId: Number(r.tenant_id), versionId: null, name: r.name, contributions: [],
        app: {
          identifier: r.identifier, supportedPlatforms: Array.isArray(r.supported_platforms) ? r.supported_platforms : [], storeId: r.store_id ?? null,
          platformFamily: r.platform_family === 'android' ? 'android' : 'apple',
        },
      });
    }
  }
  return resources;
}

export function rowToAssignment(r: Record<string, unknown>): ResolutionAssignment {
  return {
    id: Number(r.id),
    resourceType: r.resource_type as 'policy' | 'app',
    resourceId: Number(r.resource_id),
    resourceTenantId: Number(r.resource_tenant_id),
    targetScope: r.target_scope as AssignmentTargetScope,
    targetId: r.target_id === null || r.target_id === undefined ? null : Number(r.target_id),
    mode: r.mode as 'include' | 'exclude',
    priority: Number(r.priority),
    options: parseJson<Record<string, JsonValue>>(r.options ?? {}) ?? {},
  };
}

/** The assignments of the tenant. */
export async function loadAssignments(q: Knex | Knex.Transaction, tenantId: number): Promise<ResolutionAssignment[]> {
  const rows = await q('assignments').where({ tenant_id: tenantId }).orderBy('id')
    .select('id', 'resource_type', 'resource_id', 'resource_tenant_id', 'target_scope', 'target_id', 'mode', 'priority', 'options') as
    Array<Record<string, unknown>>;
  return rows.map(rowToAssignment);
}

/** The assignments, their resources and the tenant's names (variables). */
export async function loadPolicyState(q: Knex | Knex.Transaction, tenantId: number, catalog: AppleCatalogView = appleCatalog()): Promise<PolicyState> {
  const t = await q('tenants').where({ id: tenantId }).first('name', 'slug') as { name: string; slug: string } | undefined;
  const assignments = await loadAssignments(q, tenantId);
  const resources = await loadResources(q, tenantId, assignments, catalog);
  return { tenantId, tenant: { name: t?.name ?? '', slug: t?.slug ?? '' }, assignments, resources };
}

/**
 * The configuration types a device announced (management.client-capabilities, apple_devices.ddm_client_capabilities),
 * null until it did. Read in the forms the status channel may store them: the engine's view
 * ({ declarationTypes: { configuration: [...] } }, integration §9.2) or the device's report as it came
 * ({ "supported-payloads": { declarations: { configurations: [...] } } }). An unreadable value decides nothing.
 */
export function declarationTypesOf(capabilities: unknown): string[] | null {
  let caps: unknown;
  try { caps = parseJson<unknown>(capabilities); } catch { return null; }
  if (!caps || typeof caps !== 'object' || Array.isArray(caps)) return null;
  const c = caps as Record<string, unknown>;
  const families = (c.declarationTypes ?? (c['supported-payloads'] as Record<string, unknown> | undefined)?.declarations) as unknown;
  const list = families && typeof families === 'object' && !Array.isArray(families)
    ? (families as Record<string, unknown>).configuration ?? (families as Record<string, unknown>).configurations
    : families;
  return Array.isArray(list) ? list.filter((s): s is string => typeof s === 'string') : null;
}

/** devices.custom_fields as the templates of the bridge agent read them (lot PONT-POL §5.5): string values only (a
 *  number or a boolean as its text), 64 keys at most, an unreadable value as none. */
export function customFieldsOf(v: unknown): Record<string, string> {
  let o: unknown;
  try { o = parseJson<unknown>(v); } catch { return {}; }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return {};
  const out: Record<string, string> = {};
  for (const [k, x] of Object.entries(o as Record<string, unknown>).slice(0, 64)) {
    if (typeof x === 'string') out[k] = x;
    else if (typeof x === 'number' || typeof x === 'boolean') out[k] = String(x);
  }
  return out;
}

/** The devices under management of a tenant (all, or `deviceIds`), with the facts of their resolution, the dynamic
 *  groups they are members of (whatever the state of the group: the members of a held group or of one in error are
 *  frozen, they stay what applies), and the ancestry of their groups. */
export async function loadDevices(q: Knex | Knex.Transaction, tenantId: number, deviceIds: number[] | null): Promise<DeviceSet> {
  const query = q('devices as d')
    .leftJoin('apple_devices as a', function joinSat() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .leftJoin('end_users as u', function joinUser() { this.on('u.id', '=', 'd.end_user_id').andOn('u.tenant_id', '=', 'd.tenant_id'); })
    .leftJoin('legacy_agent_devices as la', function joinAgent() { this.on('la.device_id', '=', 'd.id').andOn('la.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId)
    .whereNot('d.enrollment_state', 'unenrolled')
    .orderBy('d.id')
    .select('d.id', 'd.uuid', 'd.label', 'd.group_id', 'd.platform', 'd.management_channel', 'd.os_version', 'd.management_mode', 'd.supervised',
      'd.ownership', 'd.serial_number', 'd.model_name', 'a.udid', 'a.ddm_enabled', 'a.ddm_client_capabilities',
      'u.id as end_user_id', 'u.email', 'u.display_name as end_user_name', 'u.managed_apple_account', 'u.external_id',
      'd.custom_fields', 'la.revoked_at as agent_revoked_at',
      q.raw(`(SELECT array_agg(m.smart_group_id ORDER BY m.smart_group_id) FROM smart_group_members m
               WHERE m.tenant_id = d.tenant_id AND m.device_id = d.id) AS smart_group_ids`));
  if (deviceIds) query.whereIn('d.id', deviceIds);
  const rows = await query as Array<Record<string, any>>;
  const devices: ResolutionDevice[] = rows.map((r) => ({
    id: Number(r.id),
    uuid: String(r.uuid),
    label: String(r.label ?? ''),
    groupId: r.group_id === null ? null : Number(r.group_id),
    platform: r.platform,
    channel: r.management_channel,
    osVersion: r.os_version ?? null,
    mode: r.management_mode,
    supervised: !!r.supervised,
    ownership: r.ownership,
    serialNumber: r.serial_number ?? null,
    udid: r.udid ?? null,
    modelName: r.model_name ?? null,
    ddmEnabled: !!r.ddm_enabled,
    declarationTypes: declarationTypesOf(r.ddm_client_capabilities),
    endUser: r.end_user_id === null || r.end_user_id === undefined ? null : {
      email: r.email ?? null, displayName: r.end_user_name ?? null, managedAppleAccount: r.managed_apple_account ?? null,
      externalId: r.external_id ?? null,
    },
    smartGroupIds: Array.isArray(r.smart_group_ids) ? r.smart_group_ids.map(Number) : [],
    customFields: customFieldsOf(r.custom_fields),
    revoked: r.agent_revoked_at !== null && r.agent_revoked_at !== undefined,
  }));
  const groupIds = [...new Set(devices.map((d) => d.groupId).filter((g): g is number => g !== null))];
  const groupAncestors = await loadGroupAncestors(q, tenantId, groupIds);
  return { devices, groupAncestors };
}

/** The ancestors of groups (closure), the group itself at depth 0. */
export async function loadGroupAncestors(q: Knex | Knex.Transaction, tenantId: number, groupIds: number[]):
  Promise<Map<number, Array<{ groupId: number; depth: number }>>> {
  const out = new Map<number, Array<{ groupId: number; depth: number }>>();
  if (!groupIds.length) return out;
  const rows = await q('device_group_closure').where({ tenant_id: tenantId }).whereIn('descendant_id', groupIds)
    .select('ancestor_id', 'descendant_id', 'depth') as Array<{ ancestor_id: number; descendant_id: number; depth: number }>;
  for (const r of rows) {
    const list = out.get(Number(r.descendant_id)) ?? [];
    list.push({ groupId: Number(r.ancestor_id), depth: Number(r.depth) });
    out.set(Number(r.descendant_id), list);
  }
  return out;
}

/** The devices a target reaches: one device, a group and its subtree, the members of a dynamic group, the whole tenant
 *  (under management: a member out of management is never reached, whatever the incremental computation left). */
export async function devicesOfTargets(q: Knex | Knex.Transaction, tenantId: number,
  targets: Array<{ scope: AssignmentTargetScope; id: number | null }>): Promise<number[]> {
  if (targets.some((t) => t.scope === 'tenant')) {
    return (await q('devices').where({ tenant_id: tenantId }).whereNot('enrollment_state', 'unenrolled').orderBy('id').pluck('id') as number[]).map(Number);
  }
  const groupIds = [...new Set(targets.filter((t) => t.scope === 'group' && t.id !== null).map((t) => t.id as number))];
  const deviceIds = [...new Set(targets.filter((t) => t.scope === 'device' && t.id !== null).map((t) => t.id as number))];
  const smartGroupIds = [...new Set(targets.filter((t) => t.scope === 'smart_group' && t.id !== null).map((t) => t.id as number))];
  const ids = new Set<number>();
  if (groupIds.length) {
    const rows = await q('devices as d')
      .join('device_group_closure as c', function joinClosure() { this.on('c.descendant_id', '=', 'd.group_id').andOn('c.tenant_id', '=', 'd.tenant_id'); })
      .where('d.tenant_id', tenantId).whereIn('c.ancestor_id', groupIds).whereNot('d.enrollment_state', 'unenrolled')
      .distinct('d.id') as Array<{ id: number }>;
    for (const r of rows) ids.add(Number(r.id));
  }
  if (deviceIds.length) {
    const rows = await q('devices').where({ tenant_id: tenantId }).whereIn('id', deviceIds).whereNot('enrollment_state', 'unenrolled')
      .pluck('id') as number[];
    for (const r of rows) ids.add(Number(r));
  }
  if (smartGroupIds.length) {
    const rows = await q('devices as d')
      .join('smart_group_members as m', function joinMembers() { this.on('m.device_id', '=', 'd.id').andOn('m.tenant_id', '=', 'd.tenant_id'); })
      .where('d.tenant_id', tenantId).whereIn('m.smart_group_id', smartGroupIds).whereNot('d.enrollment_state', 'unenrolled')
      .distinct('d.id') as Array<{ id: number }>;
    for (const r of rows) ids.add(Number(r.id));
  }
  return [...ids].sort((a, b) => a - b);
}

/** The whole input of the resolution of devices of a tenant. */
export async function loadResolutionInput(q: Knex | Knex.Transaction, tenantId: number, deviceIds: number[] | null,
  state?: PolicyState, catalog: AppleCatalogView = appleCatalog()): Promise<ResolutionInput> {
  const s = state ?? await loadPolicyState(q, tenantId, catalog);
  const set = await loadDevices(q, tenantId, deviceIds);
  return { tenantId, tenant: s.tenant, devices: set.devices, groupAncestors: set.groupAncestors,
    assignments: s.assignments, resources: s.resources, catalog };
}
