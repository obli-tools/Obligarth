import { RULE_FIELDS, versionNum, type RuleCondition, type RuleFieldKey, type RuleNode, type RuleOp } from '@obligarth/shared';
import type { RuleFacts } from './facts';
import { asciiFold, daysBefore, storageBytes } from './values';

// =============================================================================
// TypeScript evaluator of the rule language (P0-5 §2), pure: the same semantics as the SQL of compile.ts, checked
// by the equivalence test (rules.test.ts). Three-valued logic: a condition on an absent value is unknown (null),
// unknown stays unknown through NOT, AND is false as soon as a child is false, OR true as soon as one is true; a
// device matches only when the rule is TRUE. A field the privacy rules of the device do not collect
// (facts.notCollected) is unknown for every op, exists and not_exists included. Expects a valid rule (validateRule).
// =============================================================================

/** true, false, or unknown (null). */
export type RuleTruth = boolean | null;

/** Does the device match the rule (TRUE only)? */
export function evaluateRule(node: RuleNode, facts: RuleFacts, now: Date): boolean {
  return evaluateNode(node, facts, now) === true;
}

/** The truth of a node (three-valued). */
export function evaluateNode(node: RuleNode, facts: RuleFacts, now: Date): RuleTruth {
  if ('all' in node) {
    let unknown = false;
    for (const c of node.all) {
      const t = evaluateNode(c, facts, now);
      if (t === false) return false;
      if (t === null) unknown = true;
    }
    return unknown ? null : true;
  }
  if ('any' in node) {
    let unknown = false;
    for (const c of node.any) {
      const t = evaluateNode(c, facts, now);
      if (t === true) return true;
      if (t === null) unknown = true;
    }
    return unknown ? null : false;
  }
  if ('not' in node) {
    const t = evaluateNode(node.not, facts, now);
    return t === null ? null : !t;
  }
  return evaluateCondition(node, facts, now);
}

/** A text field's value (null: absent). */
function textOf(field: RuleFieldKey, f: RuleFacts, key: string | undefined): string | null {
  switch (field) {
    case 'platform': return f.platform;
    case 'model': return f.model;
    case 'model_name': return f.modelName;
    case 'name': return f.name;
    case 'serial_number': return f.serialNumber;
    case 'ownership': return f.ownership;
    case 'management_mode': return f.managementMode;
    case 'management_channel': return f.managementChannel;
    case 'enrollment_type': return f.enrollmentType;
    case 'usage': return f.usage;
    case 'enrollment_state': return f.enrollmentState;
    case 'lifecycle_status': return f.lifecycleStatus;
    case 'warranty_status': return f.warrantyStatus;
    case 'end_user.email': return f.endUser?.email ?? null;
    case 'end_user.external_id': return f.endUser?.externalId ?? null;
    case 'end_user.status': return f.endUser?.status ?? null;
    case 'compliance_state': return f.complianceState;
    case 'config_state': return f.configState;
    case 'custom_field': {
      const cf = f.customFields;
      if (!cf || key === undefined || !Object.prototype.hasOwnProperty.call(cf, key)) return null;
      const v = cf[key];
      return typeof v === 'string' ? v : null;
    }
    default: return null;
  }
}

/** eq, neq, in, not_in, contains, starts_with, ends_with, exists, not_exists on a text (folded unless an enum). */
function textOp(v: string | null, op: RuleOp, value: unknown, fold: boolean): RuleTruth {
  if (op === 'exists') return v !== null;
  if (op === 'not_exists') return v === null;
  if (v === null) return null;
  const norm = (s: unknown): string => (fold ? asciiFold(String(s)) : String(s));
  const x = fold ? asciiFold(v) : v;
  switch (op) {
    case 'eq': return x === norm(value);
    case 'neq': return x !== norm(value);
    case 'in': return (value as unknown[]).map(norm).includes(x);
    case 'not_in': return !(value as unknown[]).map(norm).includes(x);
    case 'contains': return x.includes(norm(value));
    case 'starts_with': return x.startsWith(norm(value));
    case 'ends_with': return x.endsWith(norm(value));
    default: return null;
  }
}

/** eq, neq, in, not_in, lt, lte, gt, gte, between on an ordered value (numbers, or days YYYY-MM-DD). */
function orderOp<T extends number | string>(v: T | null, op: RuleOp, value: T | T[]): RuleTruth {
  if (v === null) return null;
  switch (op) {
    case 'eq': return v === value;
    case 'neq': return v !== value;
    case 'in': return (value as T[]).includes(v);
    case 'not_in': return !(value as T[]).includes(v);
    case 'lt': return v < (value as T);
    case 'lte': return v <= (value as T);
    case 'gt': return v > (value as T);
    case 'gte': return v >= (value as T);
    case 'between': { const [lo, hi] = value as T[]; return v >= lo && v <= hi; }
    default: return null;
  }
}

/** The truth of a condition. */
export function evaluateCondition(c: RuleCondition, f: RuleFacts, now: Date): RuleTruth {
  if (f.notCollected.includes(c.field)) return null;
  const def = RULE_FIELDS[c.field];
  const { op, value } = c;
  switch (def.type) {
    case 'enum':
      return textOp(textOf(c.field, f, c.key), op, value, false);
    case 'string': case 'kv':
      return textOp(textOf(c.field, f, c.key), op, value, true);
    case 'version': {
      const n = versionNum(f.osVersion);
      if (op === 'exists') return n !== null;
      if (op === 'not_exists') return n === null;
      const target = Array.isArray(value) ? value.map((x) => versionNum(String(x)) as number) : versionNum(String(value)) as number;
      return orderOp(n, op, target);
    }
    case 'bool': {
      const v = c.field === 'supervised' ? f.supervised : f.endUserAssigned;
      return v === value;
    }
    case 'number': {
      const v = c.field === 'storage_capacity_gb' ? f.storageCapacityBytes : f.androidApiLevel;
      if (op === 'exists') return v !== null;
      if (op === 'not_exists') return v === null;
      const scale = (x: unknown): number => (c.field === 'storage_capacity_gb' ? storageBytes(Number(x)) : Number(x));
      return orderOp(v, op, Array.isArray(value) ? value.map(scale) : scale(value));
    }
    case 'date': {
      const v = f.androidSecurityPatchLevel;
      if (op === 'exists') return v !== null;
      if (op === 'not_exists') return v === null;
      return orderOp(v, op, Array.isArray(value) ? value.map(String) : String(value));
    }
    case 'timestamp': {
      const at = c.field === 'last_checkin' ? f.lastCheckinAt : f.enrolledAt;
      if (op === 'exists') return at !== null;
      if (op === 'not_exists') return at === null;
      if (at === null) return null;
      const threshold = daysBefore(now, Number(value)).getTime();
      if (op === 'older_than_days') return at.getTime() < threshold;
      if (op === 'within_days') return at.getTime() >= threshold;
      return null;
    }
    case 'tags': {
      const tags = f.tags;
      if (tags === null) return null;
      const wanted = (value as unknown[]).map(String);
      if (op === 'has_any') return wanted.some((t) => tags.includes(t));
      if (op === 'has_all') return wanted.every((t) => tags.includes(t));
      if (op === 'has_none') return !wanted.some((t) => tags.includes(t));
      return null;
    }
    case 'group': {
      const ids = (Array.isArray(value) ? value : [value]).map(Number);
      const inside = ids.some((id) => f.groupAncestors.includes(id));
      return op === 'eq' || op === 'in' ? inside : !inside;
    }
    case 'app': {
      const rows = f.apps.filter((a) => a.identifier === c.key);
      if (op === 'exists') return rows.length > 0;
      if (op === 'not_exists') return rows.length === 0;
      const target = versionNum(String(value)) as number;
      return rows.some((a) => orderOp(versionNum(a.version), op, target) === true);
    }
  }
}
