import type { Knex } from 'knex';
import {
  RULE_FIELDS, validateRule, versionNum, type RuleCondition, type RuleFieldKey, type RuleIssue, type RuleNode,
} from '@obligarth/shared';
import type { RulePrivacy } from './facts';
import { FOLD_SQL_PREFIX, FOLD_SQL_SUFFIX, daysBefore, likeEscape, asciiFold, storageBytes } from './values';

// =============================================================================
// SQL compiler of the rule language (P0-5 §2): a boolean expression over the row `devices` of the query (the
// alias of services/device.service.ts baseQuery; any query whose devices table is named `devices`), never NULL
// (`(…) IS TRUE`: an unknown rule does not match), to pass to whereRaw(sql, bindings) or to select.
//   - Every column comes from the constant tables below, keyed by the catalog's field (validated first), never from
//     the text received; every value, key and privacy key is a binding ('?' of Knex; the jsonb operators ?| and ?&
//     are written '\?|' and '\?&', as services/device.service.ts). The SQL text depends only on the shape of the rule
//     (fields, ops, nesting) and on whether a privacy list is empty, never on a value (testbed 118: no
//     interpolation of a value).
//   - The satellites, the end user, the applications and the groups are correlated subqueries on
//     tenant_id = devices.tenant_id: the expression needs no join.
//   - Three-valued logic, as evaluate.ts: a condition on NULL is NULL; a field the privacy rules of the device do
//     not collect (RulePrivacy, P0-13) is NULL for every op: it never serves as an oracle (EX-19).
// =============================================================================

export interface RuleCompileContext {
  /** The instant of older_than_days / within_days (bound). */
  now: Date;
  /** The devices whose privacy rules let a rule compare a datum (facts.ts loadRulePrivacy). */
  privacy: RulePrivacy;
}

export interface CompiledRule {
  sql: string;
  bindings: Knex.Value[];
}

/** A rule refused by validateRule: never compiled. */
export class InvalidRuleError extends Error {
  readonly code = 'invalidRule';
  readonly issues: RuleIssue[];
  constructor(issues: RuleIssue[]) {
    super('invalid rule');
    this.name = 'InvalidRuleError';
    this.issues = issues;
  }
}

interface Frag { sql: string; b: Knex.Value[] }

/** The key of a device for RulePrivacy (facts.ts privacyKey: tenant|channel|ownership|mode). */
const DEVICE_KEY_SQL = "(devices.tenant_id::text || '|' || devices.management_channel || '|' || devices.ownership || '|' || devices.management_mode)";

/** The column of each field that has one (custom_field, tags, group and app.installed have their own SQL). */
const COLUMN_SQL: Partial<Record<RuleFieldKey, string>> = {
  platform: 'devices.platform',
  os_version: 'devices.os_version_num',
  model: 'devices.model',
  model_name: 'devices.model_name',
  name: 'devices.label',
  serial_number: 'devices.serial_number',
  ownership: 'devices.ownership',
  management_mode: 'devices.management_mode',
  management_channel: 'devices.management_channel',
  enrollment_type: 'devices.enrollment_type',
  supervised: 'devices.supervised',
  usage: 'devices.usage',
  enrollment_state: 'devices.enrollment_state',
  lifecycle_status: 'devices.lifecycle_status',
  warranty_status: 'devices.warranty_status',
  storage_capacity_gb: 'devices.storage_capacity_bytes',
  'end_user.assigned': '(devices.end_user_id IS NOT NULL)',
  'end_user.email': '(SELECT eu.email FROM obligarth.end_users eu WHERE eu.tenant_id = devices.tenant_id AND eu.id = devices.end_user_id)',
  'end_user.external_id': '(SELECT eu.external_id FROM obligarth.end_users eu WHERE eu.tenant_id = devices.tenant_id AND eu.id = devices.end_user_id)',
  'end_user.status': '(SELECT eu.status FROM obligarth.end_users eu WHERE eu.tenant_id = devices.tenant_id AND eu.id = devices.end_user_id)',
  'android.api_level': `COALESCE(
    (SELECT ad.api_level FROM obligarth.android_devices ad WHERE ad.tenant_id = devices.tenant_id AND ad.device_id = devices.id),
    (SELECT la.api_level FROM obligarth.legacy_agent_devices la WHERE la.tenant_id = devices.tenant_id AND la.device_id = devices.id))`,
  'android.security_patch_level': `COALESCE(
    (SELECT ad.security_patch_level FROM obligarth.android_devices ad WHERE ad.tenant_id = devices.tenant_id AND ad.device_id = devices.id),
    (SELECT la.security_patch FROM obligarth.legacy_agent_devices la WHERE la.tenant_id = devices.tenant_id AND la.device_id = devices.id))`,
  compliance_state: 'devices.compliance_state',
  config_state: 'devices.config_state',
  last_checkin: 'devices.last_checkin_at',
  enrolled_at: 'devices.enrolled_at',
};

/** A custom field's text (NULL unless a JSON string): the key bound twice. */
const CUSTOM_FIELD_SQL = "(CASE WHEN jsonb_typeof(devices.custom_fields -> ?::text) = 'string' THEN devices.custom_fields ->> ?::text END)";

const TAGS_ANY_SQL = "(CASE WHEN jsonb_typeof(devices.tags) = 'array' THEN devices.tags \\?| ?::text[] END)";
const TAGS_ALL_SQL = "(CASE WHEN jsonb_typeof(devices.tags) = 'array' THEN devices.tags \\?& ?::text[] END)";

const GROUP_SQL = `EXISTS (SELECT 1 FROM obligarth.device_group_closure c
  WHERE c.tenant_id = devices.tenant_id AND c.descendant_id = devices.group_id AND c.ancestor_id = ANY(?::integer[]))`;

const APP_SQL = `SELECT 1 FROM obligarth.device_apps da
  WHERE da.tenant_id = devices.tenant_id AND da.device_id = devices.id AND da.identifier = ?::text`;
const APP_VERSION_SQL = 'obligarth.version_num(COALESCE(da.short_version, da.version))';
/** The applications a rule may see: the managed ones, every one where the privacy rules collect them all. */
const APP_GATE_ALL_SQL = `(da.managed OR ${DEVICE_KEY_SQL} = ANY(?::text[]))`;
const APP_GATE_MANAGED_SQL = 'da.managed';

const COMPARE_SQL = { eq: '=', neq: '<>', lt: '<', lte: '<=', gt: '>', gte: '>=' } as const;
type CompareOp = keyof typeof COMPARE_SQL;
const isCompare = (op: string): op is CompareOp => Object.prototype.hasOwnProperty.call(COMPARE_SQL, op);

/** The SQL cast of a value bound against a field's type. */
const CAST_SQL = { text: '::text', integer: '::integer', bigint: '::bigint', date: '::date', timestamptz: '::timestamptz', boolean: '::boolean' } as const;
type Cast = keyof typeof CAST_SQL;

/** Compiles a rule (validated here: an invalid rule throws InvalidRuleError, never reaches the SQL). */
export function compileRule(node: RuleNode, ctx: RuleCompileContext): CompiledRule {
  const issues = validateRule(node);
  if (issues.length) throw new InvalidRuleError(issues);
  const f = compileNode(node, ctx);
  return { sql: `(${f.sql} IS TRUE)`, bindings: f.b };
}

function compileNode(node: RuleNode, ctx: RuleCompileContext): Frag {
  if ('all' in node || 'any' in node) {
    const children = ('all' in node ? node.all : node.any).map((c) => compileNode(c, ctx));
    const joiner = 'all' in node ? ' AND ' : ' OR ';
    return { sql: `(${children.map((c) => c.sql).join(joiner)})`, b: children.flatMap((c) => c.b) };
  }
  if ('not' in node) {
    const c = compileNode(node.not, ctx);
    return { sql: `(NOT ${c.sql})`, b: c.b };
  }
  const cond = compileCondition(node, ctx);
  if (RULE_FIELDS[node.field].privacy === 'serialNumber') {
    // Unknown where the privacy rules of the device do not collect (or the list does not show) the serial number.
    if (ctx.privacy.serialNumber.length === 0) return { sql: '(NULL::boolean)', b: [] };
    return { sql: `(CASE WHEN ${DEVICE_KEY_SQL} = ANY(?::text[]) THEN ${cond.sql} END)`, b: [[...ctx.privacy.serialNumber], ...cond.b] };
  }
  return cond;
}

/** exists / not_exists, a comparison, a list, a range on an expression `lhs` (its own bindings first). */
function scalarCondition(lhs: Frag, op: string, value: unknown, cast: Cast, map: (v: unknown) => Knex.Value, raw: Frag = lhs): Frag {
  const c = CAST_SQL[cast];
  if (op === 'exists') return { sql: `(${raw.sql} IS NOT NULL)`, b: raw.b };
  if (op === 'not_exists') return { sql: `(${raw.sql} IS NULL)`, b: raw.b };
  if (isCompare(op)) return { sql: `(${lhs.sql} ${COMPARE_SQL[op]} ?${c})`, b: [...lhs.b, map(value)] };
  if (op === 'in') return { sql: `(${lhs.sql} = ANY(?${c}[]))`, b: [...lhs.b, (value as unknown[]).map(map) as Knex.Value] };
  if (op === 'not_in') return { sql: `(${lhs.sql} <> ALL(?${c}[]))`, b: [...lhs.b, (value as unknown[]).map(map) as Knex.Value] };
  if (op === 'between') {
    const [lo, hi] = value as unknown[];
    return { sql: `(${lhs.sql} BETWEEN ?${c} AND ?${c})`, b: [...lhs.b, map(lo), map(hi)] };
  }
  if (op === 'contains' || op === 'starts_with' || op === 'ends_with') {
    const v = likeEscape(map(value) as string);
    const pattern = op === 'contains' ? `%${v}%` : op === 'starts_with' ? `${v}%` : `%${v}`;
    return { sql: `(${lhs.sql} LIKE ?::text)`, b: [...lhs.b, pattern] };
  }
  throw new InvalidRuleError([{ path: '$', code: 'opNotAllowed', op }]);
}

function compileCondition(c: RuleCondition, ctx: RuleCompileContext): Frag {
  const def = RULE_FIELDS[c.field];
  const { op, value } = c;
  const column = (): Frag => ({ sql: COLUMN_SQL[c.field] as string, b: [] });
  switch (def.type) {
    case 'enum':
      return scalarCondition(column(), op, value, 'text', (v) => String(v));
    case 'string': case 'kv': {
      const raw: Frag = def.type === 'kv' ? { sql: CUSTOM_FIELD_SQL, b: [c.key as string, c.key as string] } : column();
      const folded: Frag = { sql: `${FOLD_SQL_PREFIX}${raw.sql}${FOLD_SQL_SUFFIX}`, b: raw.b };
      return scalarCondition(folded, op, value, 'text', (v) => asciiFold(String(v)), raw);
    }
    case 'version':
      return scalarCondition(column(), op, value, 'integer', (v) => versionNum(String(v)) as number);
    case 'bool':
      return scalarCondition(column(), op, value, 'boolean', (v) => v === true);
    case 'number':
      return c.field === 'storage_capacity_gb'
        ? scalarCondition(column(), op, value, 'bigint', (v) => storageBytes(Number(v)))
        : scalarCondition(column(), op, value, 'integer', (v) => Number(v));
    case 'date':
      return scalarCondition(column(), op, value, 'date', (v) => String(v));
    case 'timestamp': {
      const col = column();
      if (op === 'older_than_days') return { sql: `(${col.sql} < ?::timestamptz)`, b: [daysBefore(ctx.now, Number(value)).toISOString()] };
      if (op === 'within_days') return { sql: `(${col.sql} >= ?::timestamptz)`, b: [daysBefore(ctx.now, Number(value)).toISOString()] };
      return scalarCondition(col, op, value, 'timestamptz', (v) => String(v));
    }
    case 'tags': {
      const tags = (value as unknown[]).map(String);
      if (op === 'has_all') return { sql: TAGS_ALL_SQL, b: [tags] };
      if (op === 'has_none') return { sql: `(NOT ${TAGS_ANY_SQL})`, b: [tags] };
      return { sql: TAGS_ANY_SQL, b: [tags] };
    }
    case 'group': {
      const ids = (Array.isArray(value) ? value : [value]).map(Number);
      return op === 'eq' || op === 'in' ? { sql: `(${GROUP_SQL})`, b: [ids] } : { sql: `(NOT ${GROUP_SQL})`, b: [ids] };
    }
    case 'app': {
      const gate: Frag = ctx.privacy.allApps.length
        ? { sql: APP_GATE_ALL_SQL, b: [[...ctx.privacy.allApps]] }
        : { sql: APP_GATE_MANAGED_SQL, b: [] };
      const base: Frag = { sql: `${APP_SQL} AND ${gate.sql}`, b: [c.key as string, ...gate.b] };
      if (op === 'exists') return { sql: `(EXISTS (${base.sql}))`, b: base.b };
      if (op === 'not_exists') return { sql: `(NOT EXISTS (${base.sql}))`, b: base.b };
      if (!isCompare(op)) throw new InvalidRuleError([{ path: '$', code: 'opNotAllowed', field: c.field, op }]);
      return {
        sql: `(EXISTS (${base.sql} AND ${APP_VERSION_SQL} ${COMPARE_SQL[op]} ?::integer))`,
        b: [...base.b, versionNum(String(value)) as number],
      };
    }
  }
}
