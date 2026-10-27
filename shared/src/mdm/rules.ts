// =============================================================================
// Rule language of the device inventory (P0-5 §2: dynamic groups, assignment filters, saved views): one tree of
// AND / OR / NOT over a whitelist of fields (RULE_FIELDS), validated here, compiled to SQL and evaluated in
// TypeScript by the server (server/src/mdm/rules/: compile.ts, evaluate.ts, facts.ts), with the same semantics:
//   - three-valued logic: a condition on an absent value (NULL) is unknown, never true; NOT of unknown stays
//     unknown, and a rule matches a device only when it is TRUE ("NULL vaut faux");
//   - a value the privacy rules do not collect, or do not show, for a device (P0-13: the serial number of a
//     personal device, the applications not managed of a COPE device) is absent: a rule never serves as an
//     oracle on it (EX-19);
//   - text comparisons fold the ASCII letters only (A-Z), the same in SQL (translate) and in TypeScript;
//   - versions compare by versionNum (mirror of obligarth.version_num), dates as YYYY-MM-DD.
// Bounds (RULE_LIMITS): depth 4, 50 conditions, 16 KiB of JSON, 100 values per list, 200 characters per string.
// Where a field is permitted (D2): every field in a view and in a dynamic group that no assignment targets; only the
// fields marked targetable / filterable in a targeted dynamic group and in an assignment filter (neither derived,
// temporal, group nor apps fields, nor the name of the device, which its user can change).
// =============================================================================

import {
  COMPLIANCE_STATES, CONFIG_STATES, DEVICE_USAGES, END_USER_STATUSES, ENROLLMENT_METHODS, ENROLLMENT_STATES,
  MANAGEMENT_CHANNELS, MANAGEMENT_MODES, OWNERSHIPS, PLATFORMS,
} from './enums';
import { versionNum } from './states';
import { sha256Hex } from './apple/sha256';

export const RULE_OPS = ['eq', 'neq', 'in', 'not_in', 'lt', 'lte', 'gt', 'gte', 'between', 'contains', 'starts_with', 'ends_with',
  'exists', 'not_exists', 'has_any', 'has_all', 'has_none', 'older_than_days', 'within_days'] as const;
export type RuleOp = typeof RULE_OPS[number];

/** The fields of v1, in display order. `custom_field` and `app.installed` take a `key` (the custom field's name, the
 *  application's identifier). */
export const RULE_FIELD_KEYS = [
  'platform', 'os_version', 'model', 'model_name', 'name', 'serial_number', 'ownership', 'management_mode',
  'management_channel', 'enrollment_type', 'supervised', 'usage', 'enrollment_state', 'lifecycle_status', 'warranty_status',
  'storage_capacity_gb', 'tags', 'custom_field', 'end_user.assigned', 'end_user.email', 'end_user.external_id', 'end_user.status',
  'android.api_level', 'android.security_patch_level', 'group', 'app.installed', 'compliance_state', 'config_state',
  'last_checkin', 'enrolled_at',
] as const;
export type RuleFieldKey = typeof RULE_FIELD_KEYS[number];

/** How a field compares: enum (fixed values), string (ASCII-folded text), version (versionNum), bool, number, date
 *  (calendar day YYYY-MM-DD), timestamp (relative to now, in days), tags (jsonb array of strings), kv (a custom field,
 *  text), app (an installed application, optionally its version), group (the subtree of a static group). */
export type RuleFieldType = 'enum' | 'string' | 'version' | 'bool' | 'number' | 'date' | 'timestamp' | 'tags' | 'kv' | 'app' | 'group';

/** Families of marking (P0-5 §3 M2): the change of which facts makes a device's membership to be recomputed. */
export const DIRTY_FAMILIES = ['facts', 'tags', 'custom', 'user', 'android', 'group', 'apps', 'derived', 'temporal'] as const;
export type DirtyFamily = typeof DIRTY_FAMILIES[number];

/** A datum of the privacy rules (P0-13) a field depends on: absent from a device whose rules do not collect it. */
export type RulePrivacyDatum = 'serialNumber' | 'allApps';

export type RuleScalar = string | number | boolean;
export type RuleValue = RuleScalar | Array<string | number>;

export interface RuleCondition {
  field: RuleFieldKey;
  op: RuleOp;
  value?: RuleValue;
  /** custom_field: the field's name; app.installed: the application's identifier. */
  key?: string;
}
export type RuleNode = { all: RuleNode[] } | { any: RuleNode[] } | { not: RuleNode } | RuleCondition;

export interface RuleFieldDef {
  type: RuleFieldType;
  ops: readonly RuleOp[];
  /** enum: the values admitted. */
  values?: readonly string[];
  /** number: integers only, and the range of a value. */
  integer?: true;
  min?: number;
  max?: number;
  /** number: decimals admitted (storage in GB: 3). */
  decimals?: number;
  /** Takes a `key` (custom_field, app.installed). */
  keyed?: true;
  /** Derived from the configuration or the compliance (D2). */
  derived?: true;
  /** Relative to now (D2): recomputed by the schedule, never by the marking. */
  temporal?: true;
  /** Depends on the privacy rules of the device (absent when not collected). */
  privacy?: RulePrivacyDatum;
  family: DirtyFamily;
  /** Permitted in a dynamic group an assignment targets (D2). */
  targetable: boolean;
  /** Permitted in an assignment filter (D2). */
  filterable: boolean;
}

const ENUM_OPS = ['eq', 'neq', 'in', 'not_in'] as const satisfies readonly RuleOp[];
const ENUM_NULLABLE_OPS = [...ENUM_OPS, 'exists', 'not_exists'] as const satisfies readonly RuleOp[];
const STRING_OPS = ['eq', 'neq', 'in', 'not_in', 'contains', 'starts_with', 'ends_with', 'exists', 'not_exists'] as const satisfies readonly RuleOp[];
const ORDER_OPS = ['eq', 'neq', 'lt', 'lte', 'gt', 'gte', 'between', 'exists', 'not_exists'] as const satisfies readonly RuleOp[];
const RANGE_OPS = ['lt', 'lte', 'gt', 'gte', 'between', 'exists', 'not_exists'] as const satisfies readonly RuleOp[];
const INTEGER_OPS = ['eq', 'neq', 'in', 'not_in', 'lt', 'lte', 'gt', 'gte', 'between', 'exists', 'not_exists'] as const satisfies readonly RuleOp[];
const DATE_OPS = ['eq', 'lt', 'lte', 'gt', 'gte', 'between', 'exists', 'not_exists'] as const satisfies readonly RuleOp[];
const TIMESTAMP_OPS = ['older_than_days', 'within_days', 'exists', 'not_exists'] as const satisfies readonly RuleOp[];
const TAG_OPS = ['has_any', 'has_all', 'has_none'] as const satisfies readonly RuleOp[];
const BOOL_OPS = ['eq'] as const satisfies readonly RuleOp[];
const GROUP_OPS = ['eq', 'neq', 'in', 'not_in'] as const satisfies readonly RuleOp[];
const APP_OPS = ['exists', 'not_exists', 'eq', 'lt', 'lte', 'gt', 'gte'] as const satisfies readonly RuleOp[];

/** Values of the asset statuses (PATCH /api/mdm/devices/:id, devices.routes.ts). */
export const DEVICE_LIFECYCLE_STATUSES = ['active', 'aging', 'end_of_life', 'retired', 'unknown'] as const;
export const DEVICE_WARRANTY_STATUSES = ['active', 'expired', 'unknown'] as const;

const fact = (type: RuleFieldType, ops: readonly RuleOp[], more: Partial<RuleFieldDef> = {}): RuleFieldDef =>
  ({ type, ops, family: 'facts', targetable: true, filterable: true, ...more });

/** The catalog: the only fields a rule may name (the server maps each to its column, never the text received). */
export const RULE_FIELDS: Readonly<Record<RuleFieldKey, RuleFieldDef>> = {
  platform: fact('enum', ENUM_OPS, { values: PLATFORMS }),
  os_version: fact('version', ORDER_OPS),
  model: fact('string', STRING_OPS),
  model_name: fact('string', STRING_OPS),
  // The label of the device: the operator's name when given, else the name the device reports (its user renames it in
  // its settings). Never a target nor a filter (D2): an end user would put their device in the scope of a configuration.
  name: fact('string', STRING_OPS, { targetable: false, filterable: false }),
  serial_number: fact('string', STRING_OPS, { privacy: 'serialNumber' }),
  ownership: fact('enum', ENUM_OPS, { values: OWNERSHIPS }),
  management_mode: fact('enum', ENUM_OPS, { values: MANAGEMENT_MODES }),
  management_channel: fact('enum', ENUM_OPS, { values: MANAGEMENT_CHANNELS }),
  enrollment_type: fact('enum', ENUM_OPS, { values: ENROLLMENT_METHODS }),
  supervised: fact('bool', BOOL_OPS),
  usage: fact('enum', ENUM_OPS, { values: DEVICE_USAGES }),
  enrollment_state: fact('enum', ENUM_OPS, { values: ENROLLMENT_STATES }),
  lifecycle_status: fact('enum', ENUM_NULLABLE_OPS, { values: DEVICE_LIFECYCLE_STATUSES }),
  warranty_status: fact('enum', ENUM_NULLABLE_OPS, { values: DEVICE_WARRANTY_STATUSES }),
  storage_capacity_gb: fact('number', RANGE_OPS, { min: 0, max: 1_000_000, decimals: 3 }),
  tags: fact('tags', TAG_OPS, { family: 'tags' }),
  custom_field: fact('kv', STRING_OPS, { family: 'custom', keyed: true }),
  'end_user.assigned': fact('bool', BOOL_OPS, { family: 'user' }),
  'end_user.email': fact('string', STRING_OPS, { family: 'user' }),
  'end_user.external_id': fact('string', STRING_OPS, { family: 'user' }),
  'end_user.status': fact('enum', ENUM_NULLABLE_OPS, { family: 'user', values: END_USER_STATUSES }),
  'android.api_level': fact('number', INTEGER_OPS, { family: 'android', integer: true, min: 1, max: 1000 }),
  'android.security_patch_level': fact('date', DATE_OPS, { family: 'android' }),
  group: fact('group', GROUP_OPS, { family: 'group', targetable: false, filterable: false }),
  'app.installed': fact('app', APP_OPS, { family: 'apps', keyed: true, privacy: 'allApps', targetable: false, filterable: false }),
  compliance_state: fact('enum', ENUM_OPS, { family: 'derived', values: COMPLIANCE_STATES, derived: true, targetable: false, filterable: false }),
  config_state: fact('enum', ENUM_OPS, { family: 'derived', values: CONFIG_STATES, derived: true, targetable: false, filterable: false }),
  last_checkin: fact('timestamp', TIMESTAMP_OPS, { family: 'temporal', temporal: true, targetable: false, filterable: false }),
  enrolled_at: fact('timestamp', TIMESTAMP_OPS, { family: 'temporal', temporal: true, targetable: false, filterable: false }),
};

export const RULE_LIMITS = {
  /** Combinators (all, any, not) on the path from the root to a condition. */
  maxDepth: 4,
  maxConditions: 50,
  /** UTF-8 bytes of the JSON of the rule. */
  maxBytes: 16_384,
  /** Values of a list (in, not_in, has_*). */
  maxValues: 100,
  /** Characters of a string value. */
  maxString: 200,
  /** Characters of a key: a custom field's name (as PATCH), an application's identifier (device_apps.identifier). */
  maxCustomKey: 100,
  maxAppKey: 255,
  /** Days of older_than_days / within_days. */
  maxDays: 3650,
  /** Issues reported at most. */
  maxIssues: 20,
} as const;

/** Where a rule is used (D2): a view or an untargeted dynamic group admit every field. */
export type RuleUse = 'view' | 'targetable' | 'filterable';

export type RuleIssueCode =
  | 'invalidNode'        // not an object of one of the four forms, unknown property
  | 'emptyGroup'         // all / any without a child
  | 'tooDeep'            // beyond maxDepth
  | 'tooManyConditions'  // beyond maxConditions
  | 'tooLarge'           // beyond maxBytes
  | 'unknownField'
  | 'opNotAllowed'       // op unknown or not offered by the field
  | 'keyRequired'
  | 'keyNotAllowed'
  | 'invalidKey'
  | 'invalidValue'       // missing, of the wrong type, out of range, not a value of the enum, reversed range
  | 'tooManyValues'
  | 'stringTooLong';

export interface RuleIssue {
  /** JSON path of the node ('$', '$.all[1].not'). */
  path: string;
  code: RuleIssueCode;
  field?: string;
  op?: string;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const hasOwn = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
const isFieldKey = (v: unknown): v is RuleFieldKey => typeof v === 'string' && hasOwn(RULE_FIELDS, v);
const isOp = (v: unknown): v is RuleOp => typeof v === 'string' && (RULE_OPS as readonly string[]).includes(v);

/** UTF-8 length of a string (no TextEncoder in the shared package's lib). */
function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) { n += 4; i++; }
    else n += 3;
  }
  return n;
}

/** A text PostgreSQL stores and compares as the code does: no NUL, no lone surrogate. */
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
export const isCleanText = (s: string): boolean =>!s.includes('\u0000') && !LONE_SURROGATE.test(s);

const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
/** A calendar day YYYY-MM-DD that exists, years 1900 to 9999 (as the asset dates of devices.routes.ts). */
export function isRuleDay(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  const m = DAY_RE.exec(v);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const at = new Date(Date.UTC(y, mo - 1, d));
  return y >= 1900 && at.getUTCFullYear() === y && at.getUTCMonth() === mo - 1 && at.getUTCDate() === d;
}

/** Ops whose value is a list, a pair, or nothing. */
const LIST_OPS: ReadonlySet<RuleOp> = new Set<RuleOp>(['in', 'not_in', 'has_any', 'has_all', 'has_none']);
const NO_VALUE_OPS: ReadonlySet<RuleOp> = new Set<RuleOp>(['exists', 'not_exists']);
const DAYS_OPS: ReadonlySet<RuleOp> = new Set<RuleOp>(['older_than_days', 'within_days']);

type ScalarCheck = { ok: true } | { ok: false; code: 'invalidValue' | 'stringTooLong' };
const OK: ScalarCheck = { ok: true };
const BAD: ScalarCheck = { ok: false, code: 'invalidValue' };

/** Checks one scalar value of a field (a member of a list, a bound of a range, the value of a comparison). */
function checkScalar(def: RuleFieldDef, v: unknown): ScalarCheck {
  const text = (max: number): ScalarCheck => {
    if (typeof v !== 'string' || v.length === 0 || !isCleanText(v)) return BAD;
    return v.length > max ? { ok: false, code: 'stringTooLong' } : OK;
  };
  switch (def.type) {
    case 'enum':
      return typeof v === 'string' && (def.values ?? []).includes(v) ? OK : BAD;
    case 'string': case 'kv': case 'tags':
      return text(RULE_LIMITS.maxString);
    case 'version': case 'app': {
      const t = text(RULE_LIMITS.maxString);
      if (!t.ok) return t;
      return versionNum(v as string) === null ? BAD : OK;
    }
    case 'bool':
      return typeof v === 'boolean' ? OK : BAD;
    case 'number': {
      if (typeof v !== 'number' || !Number.isFinite(v)) return BAD;
      if (def.integer && !Number.isInteger(v)) return BAD;
      if (def.min !== undefined && v < def.min) return BAD;
      if (def.max !== undefined && v > def.max) return BAD;
      if (!def.integer && def.decimals !== undefined) {
        const scaled = v * 10 ** def.decimals;
        if (Math.abs(scaled - Math.round(scaled)) > 1e-6) return BAD;
      }
      return OK;
    }
    case 'date':
      return isRuleDay(v) ? OK : BAD;
    case 'group':
      return typeof v === 'number' && Number.isSafeInteger(v) && v > 0 && v <= 2_147_483_647 ? OK : BAD;
    case 'timestamp':
      return typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= RULE_LIMITS.maxDays ? OK : BAD;
  }
}

/** The order of two scalars of a field (between: the lower bound first). */
function compareScalars(def: RuleFieldDef, a: unknown, b: unknown): number {
  if (def.type === 'version') return (versionNum(a as string) ?? 0) - (versionNum(b as string) ?? 0);
  if (def.type === 'date') return (a as string) < (b as string) ? -1 : (a as string) > (b as string) ? 1 : 0;
  return (a as number) - (b as number);
}

/**
 * The issues of a rule (empty: valid): the shape of each node, the bounds, the field, its op, its key and its value.
 * Any input (the parse of a request body or query); never throws. At most RULE_LIMITS.maxIssues issues.
 */
export function validateRule(n: unknown): RuleIssue[] {
  const issues: RuleIssue[] = [];
  const add = (i: RuleIssue): void => { if (issues.length < RULE_LIMITS.maxIssues) issues.push(i); };
  let json: string | undefined;
  try { json = JSON.stringify(n); } catch { json = undefined; }
  if (json === undefined) return [{ path: '$', code: 'invalidNode' }];
  if (utf8Length(json) > RULE_LIMITS.maxBytes) return [{ path: '$', code: 'tooLarge' }];
  let conditions = 0;
  let tooMany = false;
  const walk = (node: unknown, path: string, depth: number): void => {
    if (!isPlainObject(node)) { add({ path, code: 'invalidNode' }); return; }
    const keys = Object.keys(node);
    if (keys.length === 1 && (keys[0] === 'all' || keys[0] === 'any')) {
      const children = node[keys[0]];
      if (!Array.isArray(children)) { add({ path, code: 'invalidNode' }); return; }
      if (children.length === 0) { add({ path, code: 'emptyGroup' }); return; }
      if (depth + 1 > RULE_LIMITS.maxDepth) { add({ path, code: 'tooDeep' }); return; }
      children.forEach((c, i) => walk(c, `${path}.${keys[0]}[${i}]`, depth + 1));
      return;
    }
    if (keys.length === 1 && keys[0] === 'not') {
      if (depth + 1 > RULE_LIMITS.maxDepth) { add({ path, code: 'tooDeep' }); return; }
      walk(node.not, `${path}.not`, depth + 1);
      return;
    }
    if (!hasOwn(node, 'field') || keys.some((k) => k !== 'field' && k !== 'op' && k !== 'value' && k !== 'key')) {
      add({ path, code: 'invalidNode' });
      return;
    }
    conditions++;
    if (conditions > RULE_LIMITS.maxConditions) {
      if (!tooMany) { tooMany = true; add({ path, code: 'tooManyConditions' }); }
      return;
    }
    checkCondition(node, path, add);
  };
  walk(n, '$', 0);
  return issues;
}

function checkCondition(node: Record<string, unknown>, path: string, add: (i: RuleIssue) => void): void {
  const { field, op, value, key } = node;
  if (!isFieldKey(field)) { add({ path, code: 'unknownField', field: typeof field === 'string' ? field.slice(0, 64) : undefined }); return; }
  const def = RULE_FIELDS[field];
  if (!isOp(op) || !def.ops.includes(op)) { add({ path, code: 'opNotAllowed', field, op: typeof op === 'string' ? op.slice(0, 32) : undefined }); return; }
  const at = { path, field, op };
  if (def.keyed) {
    const max = def.type === 'app' ? RULE_LIMITS.maxAppKey : RULE_LIMITS.maxCustomKey;
    if (key === undefined) add({ ...at, code: 'keyRequired' });
    else if (typeof key !== 'string' || key.length === 0 || key.length > max || !isCleanText(key)) add({ ...at, code: 'invalidKey' });
  } else if (key !== undefined) {
    add({ ...at, code: 'keyNotAllowed' });
  }
  if (NO_VALUE_OPS.has(op)) {
    if (value !== undefined) add({ ...at, code: 'invalidValue' });
    return;
  }
  if (DAYS_OPS.has(op)) {
    if (checkScalar(def, value).ok !== true) add({ ...at, code: 'invalidValue' });
    return;
  }
  if (LIST_OPS.has(op)) {
    if (!Array.isArray(value) || value.length === 0) { add({ ...at, code: 'invalidValue' }); return; }
    if (value.length > RULE_LIMITS.maxValues) { add({ ...at, code: 'tooManyValues' }); return; }
    for (const v of value) {
      const c = checkScalar(def, v);
      if (!c.ok) { add({ ...at, code: c.code }); return; }
    }
    return;
  }
  if (op === 'between') {
    if (!Array.isArray(value) || value.length !== 2) { add({ ...at, code: 'invalidValue' }); return; }
    for (const v of value) {
      const c = checkScalar(def, v);
      if (!c.ok) { add({ ...at, code: c.code }); return; }
    }
    if (compareScalars(def, value[0], value[1]) > 0) add({ ...at, code: 'invalidValue' });
    return;
  }
  const c = checkScalar(def, value);
  if (!c.ok) add({ ...at, code: c.code });
}

/** Parses the JSON of a rule (a query parameter, a body field) and validates it. */
export function parseRuleJson(text: string): { ok: true; rule: RuleNode } | { ok: false; issues: RuleIssue[] } {
  if (utf8Length(text) > RULE_LIMITS.maxBytes) return { ok: false, issues: [{ path: '$', code: 'tooLarge' }] };
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return { ok: false, issues: [{ path: '$', code: 'invalidNode' }] }; }
  const issues = validateRule(parsed);
  return issues.length ? { ok: false, issues } : { ok: true, rule: parsed as RuleNode };
}

/** Is the node a condition (not a combinator)? */
export const isRuleCondition = (n: RuleNode): n is RuleCondition => hasOwn(n, 'field');

/** The conditions of a (valid) rule, depth first. */
export function ruleConditionsOf(n: RuleNode): RuleCondition[] {
  const out: RuleCondition[] = [];
  const walk = (x: RuleNode): void => {
    if ('all' in x) x.all.forEach(walk);
    else if ('any' in x) x.any.forEach(walk);
    else if ('not' in x) walk(x.not);
    else out.push(x);
  };
  walk(n);
  return out;
}

/** The fields a (valid) rule names, in catalog order. */
export function ruleFieldsOf(n: RuleNode): RuleFieldKey[] {
  const used = new Set(ruleConditionsOf(n).map((c) => c.field));
  return RULE_FIELD_KEYS.filter((k) => used.has(k));
}

/** The static groups a (valid) rule names (field group), ascending, without duplicates. */
export function ruleGroupIdsOf(n: RuleNode): number[] {
  const ids = new Set<number>();
  for (const c of ruleConditionsOf(n)) {
    if (c.field !== 'group') continue;
    for (const v of Array.isArray(c.value) ? c.value : [c.value]) if (typeof v === 'number') ids.add(v);
  }
  return [...ids].sort((a, b) => a - b);
}

/** The families of marking of a (valid) rule, in DIRTY_FAMILIES order: smart_groups.rule_fields (the reasons the
 *  marking gives a device are families: smartGroups.ts). */
export function ruleFamiliesOf(n: RuleNode): DirtyFamily[] {
  const used = new Set(ruleFieldsOf(n).map((k) => RULE_FIELDS[k].family));
  return DIRTY_FAMILIES.filter((f) => used.has(f));
}

/** The fields of a (valid) rule a use does not permit (D2), in catalog order: empty for a view. */
export function ruleFieldsNotAllowed(n: RuleNode, use: RuleUse): RuleFieldKey[] {
  if (use === 'view') return [];
  return ruleFieldsOf(n).filter((k) => !RULE_FIELDS[k][use]);
}

/** May the rule define a dynamic group an assignment targets (D2)? */
export const isTargetableRule = (n: RuleNode): boolean => ruleFieldsNotAllowed(n, 'targetable').length === 0;

/** May the rule serve as an assignment filter (D2)? */
export const isFilterableRule = (n: RuleNode): boolean => ruleFieldsNotAllowed(n, 'filterable').length === 0;

/** The canonical form of a (valid) rule: the properties of each node in a fixed order (field, op, key, value), the
 *  same rule whatever the order of the JSON received. */
export function canonicalRule(n: RuleNode): RuleNode {
  if ('all' in n) return { all: n.all.map(canonicalRule) };
  if ('any' in n) return { any: n.any.map(canonicalRule) };
  if ('not' in n) return { not: canonicalRule(n.not) };
  const c: RuleCondition = { field: n.field, op: n.op };
  if (n.key !== undefined) c.key = n.key;
  if (n.value !== undefined) c.value = Array.isArray(n.value) ? [...n.value] : n.value;
  return c;
}

/** SHA-256 (hex) of the canonical JSON of a (valid) rule (smart_groups.rule_sha256, assignment_filters.rule_sha256). */
export const ruleSha256 = (n: RuleNode): string => sha256Hex(JSON.stringify(canonicalRule(n)));
