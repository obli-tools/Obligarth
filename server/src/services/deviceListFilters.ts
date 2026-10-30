import type { Knex } from 'knex';
import { z } from 'zod';
import {
  COMPLIANCE_STATES, CONFIG_STATES, DEVICE_CONTACT_FILTERS, DEVICE_VIEW_LIMITS, ENROLLMENT_STATES, MDM_STALE_AFTER_DAYS_DEFAULT,
  OWNERSHIPS, PLATFORMS, RULE_FIELDS, isCleanText, parseRuleJson, ruleFieldsOf, validateRule, versionNum,
  type ContactState, type RuleCondition, type RuleNode,
} from '@obligarth/shared';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { compileRule } from '../mdm/rules/compile';
import { NO_RULE_PRIVACY, loadRulePrivacy, type RulePrivacy } from '../mdm/rules/facts';
import { privacyProfilesGeneration } from '../privacy/profiles';

// =============================================================================
// Filters of the device list (GET /api/mdm/devices and its export; P0-5 T2, coordination §2 "registre des filtres"):
// one registry, key → { parse of the query parameter, condition added to the query }, so that a lot adds its filter
// here (registerDeviceListFilter, its key declared on DeviceListFilters by interface merging) instead of rewriting
// services/device.service.ts and mdm/routes/devices.routes.ts. The same parse validates the filters a saved view keeps
// (mdm/views/deviceViewService.ts). The tenants of the list (scope) and the team scopes (visibleIds) are not filters:
// device.service.ts applies them first, whatever the registry holds.
// Every condition binds its values (the columns are the code's); a filter never names another tenant's rows (the
// query is already limited to the scope, and RLS keeps the tenants apart).
// =============================================================================

/** Filters of GET /api/mdm/devices (§10.6). A lot that registers a filter declares its key here by interface merging
 *  (declare module '…/services/deviceListFilters' { interface DeviceListFilters { … } }). */
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
  /** Only the devices whose lost mode is not off (enabling, on, disabling). */
  lostMode?: boolean;
  /** Free text: label, names, serial number (where the privacy rules show it), model, end user. */
  q?: string;
  /** The advanced filter (P0-5 §2): a valid rule, every field of the catalog permitted (a view, D2). */
  rule?: RuleNode;
  /** A dynamic group (P0-5 T4): its members, in the tenant of the group. */
  smartGroupId?: number;
  /** Global view only: a subset of tenants. */
  tenantIds?: number[];
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  page?: number;
  pageSize?: number;
  /** An exact row offset, in place of the page's (the MCP server's paging: any offset, not only a multiple of the size). */
  offset?: number;
  /** Non-administrators: the devices their teams see (permissionService.getVisibleDeviceIds). */
  visibleIds?: number[] | 'all';
}

/** Keys of DeviceListFilters that are not filters of the registry (the scope, the sort, the page, the team scopes). */
const NOT_FILTERS = ['tenantIds', 'sortBy', 'sortOrder', 'page', 'pageSize', 'visibleIds'] as const;
export type DeviceListFilterKey = Exclude<keyof DeviceListFilters, typeof NOT_FILTERS[number]> & string;

/** What a filter knows of the list it narrows. */
export interface DeviceListFilterContext {
  /** The tenant of the request. */
  tenantId: number;
  /** The tenants the list reaches (the request's, or every tenant or the chosen ones in the global view). */
  scope: readonly number[] | 'all';
  /** mdmStaleAfterDays of the tenants of the list. */
  thresholds: ReadonlyMap<number, number>;
  /** Every filter of the request (a filter that depends on another reads it here). */
  filters: Readonly<DeviceListFilters>;
  /** The instant of the request (relative conditions of the rules). */
  now: Date;
  /** The privacy context of the rule language for the scope (facts.ts loadRulePrivacy), loaded once per request. */
  rulePrivacy(): Promise<RulePrivacy>;
}

export interface DeviceListFilterDef<K extends DeviceListFilterKey = DeviceListFilterKey> {
  key: K;
  /** The parse of the query parameter (absent or empty: undefined), also of the value a saved view keeps. A refusal
   *  answers 400 invalidRequest; an issue with params { code, details } answers 400 with that code. */
  query: z.ZodTypeAny;
  /** Adds the filter's condition to the list's query (value set). */
  apply(q: Knex.QueryBuilder, value: NonNullable<DeviceListFilters[K]>, ctx: DeviceListFilterContext): void | Promise<void>;
}

// ── Query parameter parsers (shared with the lots that register a filter) ────

/** A list in the query: repeated parameter or comma-separated (20 values at most). */
export const listOf = <T extends string>(values: readonly T[]) => z.preprocess((v) => {
  if (v === undefined || v === '') return undefined;
  const arr = Array.isArray(v) ? v : String(v).split(',');
  return arr.map((s) => String(s).trim()).filter(Boolean);
}, z.array(z.enum(values as unknown as [T, ...T[]])).max(20).optional());
export const intOpt = z.preprocess((v) => (v === undefined || v === '' ? undefined : Number(v)), z.number().int().positive().max(2_147_483_647).optional());
export const boolOpt = z.preprocess((v) => (v === undefined || v === '' ? undefined : v === true || v === 'true'), z.boolean().optional());
/** A text of at most `max` characters that PostgreSQL stores and compares (no NUL, no lone surrogate: a saved view's
 *  jsonb would refuse it, 500 instead of 400). */
export const cleanText = (max: number) => z.string().max(max).refine(isCleanText, 'Invalid text');

/** An issue that answers 400 with its own code (parseDeviceListQuery, deviceViewService). */
export interface CodedIssueParams { code: string; details?: Record<string, unknown> }

/** The JSON of a rule in the query (?rule=…, 4 096 characters at most), validated (invalidRule: the issues). */
const ruleParam = z.preprocess((v) => (v === undefined || v === '' ? undefined : v), z.string()
  .max(DEVICE_VIEW_LIMITS.ruleParamMaxChars)
  .transform((text, ctx) => {
    const parsed = parseRuleJson(text);
    if (!parsed.ok) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid rule',
        params: { code: 'invalidRule', details: { issues: parsed.issues } } satisfies CodedIssueParams });
      return z.NEVER;
    }
    return parsed.rule;
  }).optional());

/** The rule of a saved view (a JSON object), validated as the parameter. */
export const ruleObject = z.unknown().transform((v, ctx) => {
  const issues = validateRule(v);
  if (issues.length) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid rule',
      params: { code: 'invalidRule', details: { issues } } satisfies CodedIssueParams });
    return z.NEVER;
  }
  return v as RuleNode;
});

/** The first issue of a refused parse as an AppError (400): its own code, or invalidRequest. */
export function parseError(error: z.ZodError): AppError {
  const issue = error.issues[0];
  const params = issue && issue.code === z.ZodIssueCode.custom ? (issue.params as CodedIssueParams | undefined) : undefined;
  if (params?.code) return new AppError(400, issue.message, params.code, params.details);
  return new AppError(400, issue?.message ?? 'Invalid query', 'invalidRequest');
}

// ── Registry ─────────────────────────────────────────────────────────────────

const registry = new Map<string, DeviceListFilterDef>();
let version = 0;

/** Registers a filter of the list (once, at module registration, before the routes serve). */
export function registerDeviceListFilter<K extends DeviceListFilterKey>(def: DeviceListFilterDef<K>): void {
  if (!/^[a-z][A-Za-z0-9]{0,47}$/.test(def.key) || (NOT_FILTERS as readonly string[]).includes(def.key)) {
    throw new Error(`invalid device list filter key '${def.key}'`);
  }
  if (registry.has(def.key)) throw new Error(`device list filter '${def.key}' registered twice`);
  registry.set(def.key, def as unknown as DeviceListFilterDef);
  version++;
}

/** The registered filters, in registration order. */
export const deviceListFilters = (): readonly DeviceListFilterDef[] => [...registry.values()];
/** Changes with each registration (a cached schema built from the registry is rebuilt). */
export const deviceListFiltersVersion = (): number => version;

/** The parse of each filter's query parameter, keyed by filter. */
export function deviceListQueryShape(): Record<string, z.ZodTypeAny> {
  return Object.fromEntries([...registry.values()].map((d) => [d.key, d.query]));
}

/** The privacy context of a list's scope, kept a few seconds: the free text and the advanced filter of each request,
 *  each page and each export would otherwise resolve again the privacy rules of every tenant the list reaches (the
 *  global view: all of them). Keyed by the generation of the privacy profiles (a publication in this process drops
 *  the entries at once; another process's within PRIVACY_TTL_MS, below the 30 s of the profiles' own cache), the
 *  tenant of the request and the scope. An entry holds the visibility of the (tenant, channel, ownership, mode)
 *  present in the devices its caller's context reached: the same for every caller, a combination it lacks never
 *  compared (a datum hidden a moment, never one shown). */
const PRIVACY_TTL_MS = 5_000;
const PRIVACY_CACHE_MAX = 500;
const privacyCache = new Map<string, { at: number; value: Promise<RulePrivacy> }>();
function listRulePrivacy(tenantId: number, scope: readonly number[] | 'all'): Promise<RulePrivacy> {
  const key = `${privacyProfilesGeneration()}|${tenantId}|${scope === 'all' ? 'all' : [...scope].sort((a, b) => a - b).join(',')}`;
  const now = Date.now();
  const hit = privacyCache.get(key);
  if (hit && now - hit.at < PRIVACY_TTL_MS) return hit.value;
  if (privacyCache.size >= PRIVACY_CACHE_MAX) {
    for (const [k, e] of privacyCache) if (now - e.at >= PRIVACY_TTL_MS) privacyCache.delete(k);
    if (privacyCache.size >= PRIVACY_CACHE_MAX) privacyCache.clear();
  }
  const value = loadRulePrivacy(db, scope === 'all' ? 'all' : [...scope]);
  privacyCache.set(key, { at: now, value });
  // A failure is never kept: the next request loads again.
  value.catch(() => { if (privacyCache.get(key)?.value === value) privacyCache.delete(key); });
  return value;
}

/** Adds the conditions of the filters set in `f` to the query, in registration order. */
export async function applyDeviceListFilters(q: Knex.QueryBuilder, f: DeviceListFilters,
  ctx: Omit<DeviceListFilterContext, 'filters' | 'rulePrivacy'>): Promise<void> {
  let privacy: Promise<RulePrivacy> | null = null;
  const full: DeviceListFilterContext = {
    ...ctx, filters: f,
    rulePrivacy: () => (privacy ??= listRulePrivacy(ctx.tenantId, ctx.scope)),
  };
  for (const def of registry.values()) {
    const value = (f as Record<string, unknown>)[def.key];
    if (value === undefined || value === null) continue;
    await def.apply(q, value as never, full);
  }
}

/** SQL of a tenant's stale threshold in days (a CASE over the tenants of the query), its values bound. */
export function staleDaysSql(thresholds: ReadonlyMap<number, number>): { sql: string; bindings: number[] } {
  const pairs = [...thresholds.entries()].filter(([, d]) => d !== MDM_STALE_AFTER_DAYS_DEFAULT);
  if (pairs.length === 0) return { sql: '?::int', bindings: [MDM_STALE_AFTER_DAYS_DEFAULT] };
  return {
    sql: `(CASE devices.tenant_id ${pairs.map(() => 'WHEN ?::int THEN ?::int').join(' ')} ELSE ?::int END)`,
    bindings: [...pairs.flat(), MDM_STALE_AFTER_DAYS_DEFAULT],
  };
}

/** Does a rule compare a datum of the privacy rules (serial number, applications)? */
const readsPrivacy = (rule: RuleNode): boolean => ruleFieldsOf(rule).some((k) => RULE_FIELDS[k].privacy !== undefined);

// ── The filters of the core (lot B2, P0-5 T2) ────────────────────────────────

const inList = (col: string) => (q: Knex.QueryBuilder, values: string[]) => {
  if (values.length > 0) q.whereIn(col, values);
};

registerDeviceListFilter({ key: 'platform', query: listOf(PLATFORMS), apply: inList('devices.platform') });
registerDeviceListFilter({ key: 'ownership', query: listOf(OWNERSHIPS), apply: inList('devices.ownership') });
registerDeviceListFilter({ key: 'enrollmentState', query: listOf(ENROLLMENT_STATES), apply: inList('devices.enrollment_state') });
registerDeviceListFilter({ key: 'compliance', query: listOf(COMPLIANCE_STATES), apply: inList('devices.compliance_state') });
registerDeviceListFilter({ key: 'config', query: listOf(CONFIG_STATES), apply: inList('devices.config_state') });
registerDeviceListFilter({
  key: 'supervised', query: boolOpt,
  apply: (q, v) => { q.where('devices.supervised', v); },
});
// The version is checked by the parse (a saved view with an invalid one is refused at its writing, 409
// deviceViewInvalid at its use), apply keeps a guard only.
registerDeviceListFilter({
  key: 'osBelow', query: cleanText(20).refine((v) => !v || versionNum(v) !== null, 'Invalid OS version').optional(),
  apply: (q, v) => {
    if (!v) return;
    const below = versionNum(v);
    if (below === null) throw new AppError(400, 'Invalid OS version', 'invalidRequest');
    q.where('devices.os_version_num', '<', below);
  },
});
// The group: ungrouped wins over groupId; includeSubgroups only qualifies groupId.
registerDeviceListFilter({
  key: 'ungrouped', query: boolOpt,
  apply: (q, v) => { if (v) q.whereNull('devices.group_id'); },
});
registerDeviceListFilter({
  key: 'groupId', query: intOpt,
  apply: (q, groupId, ctx) => {
    if (ctx.filters.ungrouped) return;
    if (ctx.filters.includeSubgroups) {
      q.whereIn('devices.group_id', db('device_group_closure').where('ancestor_id', groupId).select('descendant_id'));
    } else {
      q.where('devices.group_id', groupId);
    }
  },
});
registerDeviceListFilter({ key: 'includeSubgroups', query: boolOpt, apply: () => { /* read by groupId */ } });
// A dynamic group (P0-5 T4): its materialised members (smart_group_members; the computations leave out the devices out
// of management, D9).
// A member row names the tenant of its group: in the global view too, the list stays in the group's tenant.
registerDeviceListFilter({
  key: 'smartGroupId', query: intOpt,
  apply: (q, smartGroupId) => {
    q.whereRaw(`EXISTS (SELECT 1 FROM smart_group_members sgm
      WHERE sgm.tenant_id = devices.tenant_id AND sgm.smart_group_id = ? AND sgm.device_id = devices.id)`, [smartGroupId]);
  },
});
registerDeviceListFilter({
  key: 'tags',
  query: z.preprocess((v) => (v === undefined || v === '' ? undefined : (Array.isArray(v) ? v : String(v).split(',')).map((s) => String(s).trim()).filter(Boolean)),
    z.array(cleanText(100)).max(20).optional()),
  apply: (q, tags) => {
    // jsonb ?| text[]: the operator's '?' escaped for Knex.
    if (tags.length > 0) q.whereRaw('devices.tags \\?| ?::text[]', [tags]);
  },
});
registerDeviceListFilter({ key: 'endUserId', query: intOpt, apply: (q, v) => { q.where('devices.end_user_id', v); } });
registerDeviceListFilter({
  key: 'lostMode', query: boolOpt,
  apply: (q, v) => { if (v === true) q.whereNot('devices.lost_mode_state', 'off'); },
});
registerDeviceListFilter({
  key: 'contact', query: listOf(DEVICE_CONTACT_FILTERS),
  apply: (q, contact, ctx) => {
    if (contact.length === 0) return;
    const days = staleDaysSql(ctx.thresholds);
    q.where(function byContact() {
      for (const c of contact) {
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
  },
});
/** A text the free search compares with the serial numbers: three characters at least, those of a serial number (no
 *  space): any other text never loads the privacy context of the list (a search of a name costs its ILIKE only). */
const SERIAL_SEARCH = /^[A-Za-z0-9._:/-]{3,}$/;
registerDeviceListFilter({
  key: 'q', query: cleanText(200).optional(),
  apply: async (q, text, ctx) => {
    const t = text.trim();
    if (!t) return;
    const pat = `%${t.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    // The serial number only where the privacy rules of the device collect it and the list shows it (P0-13, EX-19):
    // the condition of the rule language, never a match on a serial the record does not show.
    const serial: RuleCondition = { field: 'serial_number', op: 'contains', value: t };
    const serialSql = SERIAL_SEARCH.test(t) && validateRule(serial).length === 0
      ? compileRule(serial, { now: ctx.now, privacy: await ctx.rulePrivacy() })
      : null;
    q.where(function search() {
      this.whereILike('devices.label', pat)
        .orWhereILike('devices.display_name', pat)
        .orWhereILike('devices.device_name', pat)
        .orWhereILike('devices.model', pat)
        .orWhereILike('devices.model_name', pat)
        .orWhereILike('end_users.display_name', pat)
        .orWhereILike('end_users.email', pat)
        .orWhereILike('end_users.external_id', pat)
        .orWhereRaw('devices.uuid::text ILIKE ?', [pat])
        .orWhereRaw('devices.tags::text ILIKE ?', [pat]);
      if (serialSql) this.orWhereRaw(serialSql.sql, serialSql.bindings);
    });
  },
});
// The advanced filter (P0-5 §2, §4.1): the compiled rule, NULL never matching; the privacy context loaded only when the
// rule compares a datum of the privacy rules.
registerDeviceListFilter({
  key: 'rule', query: ruleParam,
  apply: async (q, rule, ctx) => {
    const privacy = readsPrivacy(rule) ? await ctx.rulePrivacy() : NO_RULE_PRIVACY;
    const compiled = compileRule(rule, { now: ctx.now, privacy });
    q.whereRaw(compiled.sql, compiled.bindings);
  },
});
