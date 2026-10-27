import type { Knex } from 'knex';
import { ruleConditionsOf, ruleFieldsOf, type RuleFieldKey, type RuleNode } from '@obligarth/shared';
import { loadGroupAncestors } from '../policies/loader';
import { ruleVisibility } from '../../privacy/collected';

// =============================================================================
// Facts of the rule language (P0-5 §2): what the TypeScript evaluator (evaluate.ts) reads of a device, loaded by
// batch for a tenant (loadRuleFacts, next to loadDevices of the resolution), and the privacy context of the SQL
// compiler (loadRulePrivacy). Both apply the same visibility (privacy/collected.ts, P0-13): the serial number of a
// device whose rules do not collect it, or whose list does not show it, is NOT COLLECTED (any condition on it is
// unknown: it never serves as an oracle, EX-19); the applications of a device whose rules collect only the managed
// ones are the managed ones only. buildRuleFacts is pure (the equivalence test builds the facts of its rows with it).
// =============================================================================

type Q = Knex | Knex.Transaction;

/** The devices whose privacy rules let a rule compare a datum, as privacyKey() values (tenant, channel, ownership,
 *  management mode): the serial number, every application (else the managed ones only). Bound by the compiler,
 *  never written into the SQL. */
export interface RulePrivacy {
  serialNumber: readonly string[];
  allApps: readonly string[];
}

/** No datum visible: the serial number is never compared, the managed applications only. */
export const NO_RULE_PRIVACY: RulePrivacy = Object.freeze({ serialNumber: [], allApps: [] });

/** The key of a device for RulePrivacy; the compiler builds the same text in SQL (compile.ts DEVICE_KEY_SQL). */
export const privacyKey = (tenantId: number, channel: string, ownership: string, mode: string): string =>
  `${tenantId}|${channel}|${ownership}|${mode}`;

/** A list of ids as one PostgreSQL array literal ('{1,2,3}'): a single binding whatever the number of ids. */
const pgIntArray = (ids: readonly number[]): string => `{${ids.map(Number).filter((n) => Number.isSafeInteger(n)).join(',')}}`;

/** Tenants whose privacy rules loadRulePrivacy resolves at the same time (the global view reaches every tenant). */
const RESOLVE_CONCURRENCY = 8;

/** The privacy context of the devices of these tenants (every tenant the caller's context reaches: 'all'): one
 *  resolution per (tenant, channel, ownership, management mode) present; the tenants RESOLVE_CONCURRENCY at a time,
 *  the combinations of a tenant one after the other (the first one loads the tenant's profiles, the others read them
 *  from their cache). */
export async function loadRulePrivacy(q: Q, tenants: readonly number[] | 'all'): Promise<RulePrivacy> {
  if (tenants !== 'all' && tenants.length === 0) return NO_RULE_PRIVACY;
  const query = q('devices').distinct('tenant_id', 'management_channel', 'ownership', 'management_mode');
  if (tenants !== 'all') query.whereRaw('tenant_id = ANY(?::integer[])', [pgIntArray(tenants)]);
  const combos = await query as Array<{ tenant_id: number; management_channel: string; ownership: string; management_mode: string }>;
  const byTenant = new Map<number, typeof combos>();
  for (const c of combos) {
    const tenantId = Number(c.tenant_id);
    byTenant.set(tenantId, [...(byTenant.get(tenantId) ?? []), c]);
  }
  const serialNumber: string[] = [];
  const allApps: string[] = [];
  const queue = [...byTenant.entries()];
  const worker = async (): Promise<void> => {
    for (let next = queue.shift(); next; next = queue.shift()) {
      const [tenantId, list] = next;
      for (const c of list) {
        const v = await ruleVisibility(q, tenantId, c.management_channel, c.ownership, c.management_mode);
        const key = privacyKey(tenantId, c.management_channel, c.ownership, c.management_mode);
        if (v.serialNumber) serialNumber.push(key);
        if (v.allApps) allApps.push(key);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(RESOLVE_CONCURRENCY, queue.length) }, worker));
  return { serialNumber: serialNumber.sort(), allApps: allApps.sort() };
}

/** What the evaluator reads of a device (absent: null). */
export interface RuleFacts {
  deviceId: number;
  tenantId: number;
  platform: string;
  osVersion: string | null;
  model: string | null;
  modelName: string | null;
  /** devices.label (the name shown by the list). */
  name: string;
  /** null when absent or not collected (then in notCollected). */
  serialNumber: string | null;
  ownership: string;
  managementMode: string;
  managementChannel: string;
  enrollmentType: string;
  supervised: boolean;
  usage: string;
  enrollmentState: string;
  lifecycleStatus: string | null;
  warrantyStatus: string | null;
  storageCapacityBytes: number | null;
  /** The string elements of devices.tags; null when it is not a JSON array. */
  tags: string[] | null;
  /** devices.custom_fields when it is a JSON object (only its string values are compared), else null. */
  customFields: Record<string, unknown> | null;
  endUserAssigned: boolean;
  endUser: { email: string | null; externalId: string | null; status: string | null } | null;
  /** Android Enterprise, else the bridge agent. */
  androidApiLevel: number | null;
  /** YYYY-MM-DD. */
  androidSecurityPatchLevel: string | null;
  groupId: number | null;
  /** The group and its ancestors (closure, depth 0 included); empty without a group. */
  groupAncestors: number[];
  /** The applications the privacy rules let compare (version: short_version, else version). */
  apps: Array<{ identifier: string; version: string | null }>;
  complianceState: string;
  configState: string;
  lastCheckinAt: Date | null;
  enrolledAt: Date | null;
  /** Fields whose value the privacy rules of the device do not collect or show: any condition on them is unknown. */
  notCollected: RuleFieldKey[];
}

/** A row of devices joined with its end user, as loadRuleFacts selects it. */
export interface RuleDeviceRow {
  id: number;
  tenant_id: number;
  platform: string;
  management_channel: string;
  ownership: string;
  enrollment_type: string;
  management_mode: string;
  supervised: boolean;
  usage: string;
  enrollment_state: string;
  os_version: string | null;
  model: string | null;
  model_name: string | null;
  label: string | null;
  serial_number: string | null;
  lifecycle_status: string | null;
  warranty_status: string | null;
  storage_capacity_bytes: number | string | null;
  tags: unknown;
  custom_fields: unknown;
  group_id: number | null;
  end_user_id: number | null;
  end_user_email: string | null;
  end_user_external_id: string | null;
  end_user_status: string | null;
  compliance_state: string;
  config_state: string;
  last_checkin_at: Date | string | null;
  enrolled_at: Date | string | null;
}

export interface RuleAndroidRow { api_level: number | null; security_patch_level: string | null }
export interface RuleAppRow { identifier: string; version: string | null; short_version: string | null; managed: boolean }

export interface RuleFactsInput {
  devices: readonly RuleDeviceRow[];
  /** By device: android_devices, legacy_agent_devices (security_patch as security_patch_level). */
  android?: ReadonlyMap<number, RuleAndroidRow>;
  legacyAgent?: ReadonlyMap<number, RuleAndroidRow>;
  apps?: ReadonlyMap<number, readonly RuleAppRow[]>;
  /** By group: its ancestors (loadGroupAncestors). */
  groupAncestors?: ReadonlyMap<number, ReadonlyArray<{ groupId: number; depth: number }>>;
  privacy: RulePrivacy;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const dateOf = (v: Date | string | null): Date | null => {
  if (v === null || v === undefined) return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
};
const intOrNull = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));

/** The facts of rows (pure). */
export function buildRuleFacts(input: RuleFactsInput): RuleFacts[] {
  const serialVisible = new Set(input.privacy.serialNumber);
  const appsVisible = new Set(input.privacy.allApps);
  return input.devices.map((r) => {
    const id = Number(r.id);
    const tenantId = Number(r.tenant_id);
    const key = privacyKey(tenantId, r.management_channel, r.ownership, r.management_mode);
    const notCollected: RuleFieldKey[] = [];
    if (!serialVisible.has(key)) notCollected.push('serial_number');
    const allApps = appsVisible.has(key);
    const android = input.android?.get(id);
    const legacy = input.legacyAgent?.get(id);
    const groupId = r.group_id === null || r.group_id === undefined ? null : Number(r.group_id);
    const endUserAssigned = r.end_user_id !== null && r.end_user_id !== undefined;
    return {
      deviceId: id,
      tenantId,
      platform: r.platform,
      osVersion: r.os_version ?? null,
      model: r.model ?? null,
      modelName: r.model_name ?? null,
      name: r.label ?? '',
      serialNumber: notCollected.includes('serial_number') ? null : r.serial_number ?? null,
      ownership: r.ownership,
      managementMode: r.management_mode,
      managementChannel: r.management_channel,
      enrollmentType: r.enrollment_type,
      supervised: !!r.supervised,
      usage: r.usage,
      enrollmentState: r.enrollment_state,
      lifecycleStatus: r.lifecycle_status ?? null,
      warrantyStatus: r.warranty_status ?? null,
      storageCapacityBytes: intOrNull(r.storage_capacity_bytes),
      tags: Array.isArray(r.tags) ? r.tags.filter((t): t is string => typeof t === 'string') : null,
      customFields: isPlainObject(r.custom_fields) ? r.custom_fields : null,
      endUserAssigned,
      endUser: endUserAssigned ? {
        email: r.end_user_email ?? null, externalId: r.end_user_external_id ?? null, status: r.end_user_status ?? null,
      } : null,
      androidApiLevel: intOrNull(android?.api_level ?? legacy?.api_level ?? null),
      androidSecurityPatchLevel: android?.security_patch_level ?? legacy?.security_patch_level ?? null,
      groupId,
      groupAncestors: groupId === null ? [] : (input.groupAncestors?.get(groupId) ?? []).map((a) => Number(a.groupId)),
      apps: (input.apps?.get(id) ?? []).filter((a) => allApps || a.managed)
        .map((a) => ({ identifier: a.identifier, version: a.short_version ?? a.version ?? null })),
      complianceState: r.compliance_state,
      configState: r.config_state,
      lastCheckinAt: dateOf(r.last_checkin_at),
      enrolledAt: dateOf(r.enrolled_at),
      notCollected,
    };
  });
}

export interface LoadRuleFactsOptions {
  /** The rules the facts serve: only what they read is loaded (the applications they name, the satellites, the
   *  groups). Absent: everything. */
  rules?: readonly RuleNode[];
  /** Devices out of management too (a view); never for a dynamic group (D9). */
  includeUnenrolled?: boolean;
  /** Already loaded (loadRulePrivacy of the tenant). */
  privacy?: RulePrivacy;
}

/** The facts of the devices of a tenant (all, or `deviceIds`), by id order. In the caller's connection or transaction
 *  (the tenant's context). */
export async function loadRuleFacts(q: Q, tenantId: number, deviceIds: readonly number[] | null, opts: LoadRuleFactsOptions = {}):
  Promise<RuleFacts[]> {
  if (deviceIds && deviceIds.length === 0) return [];
  const fields = opts.rules ? new Set(opts.rules.flatMap((r) => ruleFieldsOf(r))) : null;
  const needs = (k: RuleFieldKey): boolean => fields === null || fields.has(k);
  const appKeys = opts.rules
    ? [...new Set(opts.rules.flatMap((r) => ruleConditionsOf(r)).filter((c) => c.field === 'app.installed' && c.key).map((c) => c.key as string))]
    : null;

  const query = q('devices as d')
    .leftJoin('end_users as u', function joinUser() { this.on('u.id', '=', 'd.end_user_id').andOn('u.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId)
    .orderBy('d.id')
    .select('d.id', 'd.tenant_id', 'd.platform', 'd.management_channel', 'd.ownership', 'd.enrollment_type', 'd.management_mode',
      'd.supervised', 'd.usage', 'd.enrollment_state', 'd.os_version', 'd.model', 'd.model_name', 'd.label', 'd.serial_number',
      'd.lifecycle_status', 'd.warranty_status', 'd.storage_capacity_bytes', 'd.tags', 'd.custom_fields', 'd.group_id',
      'd.end_user_id', 'u.email as end_user_email', 'u.external_id as end_user_external_id', 'u.status as end_user_status',
      'd.compliance_state', 'd.config_state', 'd.last_checkin_at', 'd.enrolled_at');
  if (!opts.includeUnenrolled) query.whereNot('d.enrollment_state', 'unenrolled');
  if (deviceIds) query.whereRaw('d.id = ANY(?::integer[])', [pgIntArray(deviceIds)]);
  const devices = await query as RuleDeviceRow[];
  if (devices.length === 0) return [];
  const ids = pgIntArray(devices.map((d) => Number(d.id)));

  let android: Map<number, RuleAndroidRow> | undefined;
  let legacyAgent: Map<number, RuleAndroidRow> | undefined;
  if (needs('android.api_level') || needs('android.security_patch_level')) {
    const a = await q('android_devices').where('tenant_id', tenantId).whereRaw('device_id = ANY(?::integer[])', [ids])
      .select('device_id', 'api_level', q.raw("to_char(security_patch_level, 'YYYY-MM-DD') AS security_patch_level")) as Array<RuleAndroidRow & { device_id: number }>;
    android = new Map(a.map((r) => [Number(r.device_id), r]));
    const l = await q('legacy_agent_devices').where('tenant_id', tenantId).whereRaw('device_id = ANY(?::integer[])', [ids])
      .select('device_id', 'api_level', q.raw("to_char(security_patch, 'YYYY-MM-DD') AS security_patch_level")) as Array<RuleAndroidRow & { device_id: number }>;
    legacyAgent = new Map(l.map((r) => [Number(r.device_id), r]));
  }

  let apps: Map<number, RuleAppRow[]> | undefined;
  if (needs('app.installed') && (appKeys === null || appKeys.length > 0)) {
    const aq = q('device_apps').where('tenant_id', tenantId).whereRaw('device_id = ANY(?::integer[])', [ids])
      .select('device_id', 'identifier', 'version', 'short_version', 'managed');
    if (appKeys) aq.whereIn('identifier', appKeys);
    apps = new Map();
    for (const r of await aq as Array<RuleAppRow & { device_id: number }>) {
      const list = apps.get(Number(r.device_id)) ?? [];
      list.push({ identifier: r.identifier, version: r.version ?? null, short_version: r.short_version ?? null, managed: !!r.managed });
      apps.set(Number(r.device_id), list);
    }
  }

  let groupAncestors: Map<number, Array<{ groupId: number; depth: number }>> | undefined;
  if (needs('group')) {
    const groupIds = [...new Set(devices.map((d) => d.group_id).filter((g): g is number => g !== null && g !== undefined).map(Number))];
    groupAncestors = await loadGroupAncestors(q, tenantId, groupIds);
  }

  const privacy = opts.privacy ?? await loadRulePrivacy(q, [tenantId]);
  return buildRuleFacts({ devices, android, legacyAgent, apps, groupAncestors, privacy });
}
