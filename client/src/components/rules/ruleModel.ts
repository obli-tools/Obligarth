import {
  RULE_FIELDS, RULE_LIMITS, canonicalRule, ruleConditionsOf, validateRule,
  type RuleCondition, type RuleFieldKey, type RuleIssue, type RuleNode, type RuleOp, type RuleUse, type RuleValue,
} from '@obligarth/shared';
import { ruleRestrictionOf } from './ruleCatalog';

// =============================================================================
// The tree the rule builder edits: groups (all / any) and conditions, each with a stable id (React keys, focus) and a
// negation flag (the NOT of the language, kept on the node it negates). A condition may be incomplete while it is
// edited (no value yet): the rule it serialises to is checked by the shared validateRule, whose issues come back on
// the node they name (their JSON path). Serialisation: an empty root is no rule; a root with one child and no negation
// is that child alone; a negated node is { not: … }.
// =============================================================================

export interface EditorCondition {
  id: string;
  kind: 'cond';
  negated: boolean;
  field: RuleFieldKey;
  op: RuleOp;
  value?: RuleValue;
  key?: string;
}
export interface EditorGroup {
  id: string;
  kind: 'group';
  negated: boolean;
  mode: 'all' | 'any';
  children: EditorNode[];
}
export type EditorNode = EditorCondition | EditorGroup;

let seq = 0;
const nextId = (): string => `r${++seq}`;

/** Ops whose value is a list, a pair, a number of days, or nothing (the shared validation's sets). */
export const LIST_OPS: ReadonlySet<RuleOp> = new Set<RuleOp>(['in', 'not_in', 'has_any', 'has_all', 'has_none']);
export const NO_VALUE_OPS: ReadonlySet<RuleOp> = new Set<RuleOp>(['exists', 'not_exists']);
export const DAYS_OPS: ReadonlySet<RuleOp> = new Set<RuleOp>(['older_than_days', 'within_days']);

/** A new condition on a field: its first operator and a starting value. */
export function newCondition(field: RuleFieldKey = 'platform'): EditorCondition {
  const def = RULE_FIELDS[field];
  const op = def.ops[0];
  return { id: nextId(), kind: 'cond', negated: false, field, op, value: startValue(field, op), key: def.keyed ? '' : undefined };
}

export const newGroup = (mode: 'all' | 'any' = 'all'): EditorGroup =>
  ({ id: nextId(), kind: 'group', negated: false, mode, children: [newCondition()] });

/** The starting value of a field under an operator (the first value of an enum, yes for a boolean, 30 days). */
function startValue(field: RuleFieldKey, op: RuleOp): RuleValue | undefined {
  const def = RULE_FIELDS[field];
  if (NO_VALUE_OPS.has(op)) return undefined;
  if (DAYS_OPS.has(op)) return 30;
  if (LIST_OPS.has(op)) return [];
  if (op === 'between') return undefined;
  if (def.type === 'bool') return true;
  if (def.type === 'enum') return def.values?.[0];
  return undefined;
}

/** The value of a condition carried over to another operator of its field (a list keeps its first value, …). */
export function valueForOp(c: EditorCondition, op: RuleOp): RuleValue | undefined {
  const v = c.value;
  const first = Array.isArray(v) ? v[0] : v;
  if (NO_VALUE_OPS.has(op)) return undefined;
  if (DAYS_OPS.has(op)) return DAYS_OPS.has(c.op) ? v : 30;
  if (LIST_OPS.has(op)) {
    if (Array.isArray(v) && c.op !== 'between') return v;
    return first !== undefined && first !== '' && typeof first !== 'boolean' ? [first as string | number] : [];
  }
  if (op === 'between') return c.op === 'between' ? v : (first !== undefined && typeof first !== 'boolean' ? [first as string | number, ''] : undefined);
  if (first === undefined || first === '') return startValue(c.field, op);
  return DAYS_OPS.has(c.op) ? startValue(c.field, op) : first;
}

/** The condition moved to another field: its operator kept when the field offers it, else a new start. */
export function withField(c: EditorCondition, field: RuleFieldKey): EditorCondition {
  const def = RULE_FIELDS[field];
  const keepOp = def.ops.includes(c.op) && RULE_FIELDS[c.field].type === def.type;
  const op = keepOp ? c.op : def.ops[0];
  return {
    ...c, field, op,
    value: keepOp ? c.value : startValue(field, op),
    key: def.keyed ? (RULE_FIELDS[c.field].keyed && RULE_FIELDS[c.field].type === def.type ? c.key : '') : undefined,
  };
}

/** The editor tree of a rule (none: an empty root). */
export function fromRule(rule: RuleNode | null | undefined): EditorGroup {
  if (!rule) return { id: nextId(), kind: 'group', negated: false, mode: 'all', children: [] };
  const node = toEditor(rule);
  if (node.kind === 'group') return node;
  return { id: nextId(), kind: 'group', negated: false, mode: 'all', children: [node] };
}

function toEditor(n: RuleNode): EditorNode {
  let negated = false;
  let x: RuleNode = n;
  while ('not' in x) { negated = !negated; x = x.not; }
  if ('all' in x) return { id: nextId(), kind: 'group', negated, mode: 'all', children: x.all.map(toEditor) };
  if ('any' in x) return { id: nextId(), kind: 'group', negated, mode: 'any', children: x.any.map(toEditor) };
  const c = x as RuleCondition;
  return {
    id: nextId(), kind: 'cond', negated, field: c.field, op: c.op,
    value: Array.isArray(c.value) ? [...c.value] : c.value, key: c.key,
  };
}

/** The rule of the tree (null: no condition), and the editor node each JSON path of the rule names. */
export function toRule(root: EditorGroup): { rule: RuleNode | null; nodeOfPath: Map<string, string> } {
  const nodeOfPath = new Map<string, string>();
  if (root.children.length === 0) {
    nodeOfPath.set('$', root.id);
    return { rule: null, nodeOfPath };
  }
  const ser = (n: EditorNode, path: string): RuleNode => {
    nodeOfPath.set(path, n.id);
    const inner = n.negated ? `${path}.not` : path;
    if (n.negated) nodeOfPath.set(inner, n.id);
    let body: RuleNode;
    if (n.kind === 'group') {
      body = n.mode === 'all'
        ? { all: n.children.map((c, i) => ser(c, `${inner}.all[${i}]`)) }
        : { any: n.children.map((c, i) => ser(c, `${inner}.any[${i}]`)) };
    } else {
      const c: RuleCondition = { field: n.field, op: n.op };
      // An empty key is left out: the rule's issue is then keyRequired ("enter …"), not invalidKey.
      if (n.key !== undefined && n.key !== '') c.key = n.key;
      if (n.value !== undefined) c.value = Array.isArray(n.value) ? [...n.value] : n.value;
      body = c;
    }
    return n.negated ? { not: body } : body;
  };
  const rule = root.children.length === 1 && !root.negated ? ser(root.children[0], '$') : ser(root, '$');
  nodeOfPath.set('$', nodeOfPath.get('$') ?? root.id);
  return { rule, nodeOfPath };
}

/** The issues of the tree, by editor node (the root's are the rule's as a whole). */
export function issuesByNode(issues: RuleIssue[], nodeOfPath: Map<string, string>, rootId: string): Map<string, RuleIssue[]> {
  const out = new Map<string, RuleIssue[]>();
  for (const i of issues) {
    // The issue of a node is reported at its path; the closest named ancestor otherwise.
    let p = i.path;
    let id = nodeOfPath.get(p);
    while (!id) {
      const up = p.replace(/(\.not|\.(all|any)\[\d+\])$/, '');
      if (up === p) break;
      p = up;
      id = nodeOfPath.get(p);
    }
    const key = id ?? rootId;
    out.set(key, [...(out.get(key) ?? []), i]);
  }
  return out;
}

export interface RuleCheck {
  rule: RuleNode | null;
  issues: RuleIssue[];
  byNode: Map<string, RuleIssue[]>;
  /** The conditions whose field the use does not permit (D2), by editor node id. */
  restricted: Set<string>;
  conditions: number;
  valid: boolean;
}

/** Serialises and checks the tree for a use. */
export function checkTree(root: EditorGroup, use: RuleUse): RuleCheck {
  const { rule, nodeOfPath } = toRule(root);
  const issues = rule ? validateRule(rule) : [];
  const restricted = new Set<string>();
  const walk = (n: EditorNode): void => {
    if (n.kind === 'group') n.children.forEach(walk);
    else if (ruleRestrictionOf(RULE_FIELDS[n.field], use)) restricted.add(n.id);
  };
  walk(root);
  const conditions = rule && issues.length === 0 ? ruleConditionsOf(rule).length : countConditions(root);
  return {
    rule, issues, byNode: issuesByNode(issues, nodeOfPath, root.id), restricted, conditions,
    valid: issues.length === 0 && restricted.size === 0,
  };
}

const countConditions = (n: EditorNode): number => (n.kind === 'cond' ? 1 : n.children.reduce((s, c) => s + countConditions(c), 0));

/** The combinators from the root to the conditions of a group (a negation counts as one): the depth bound. */
export function depthOfGroup(root: EditorGroup, groupId: string): number {
  const find = (g: EditorGroup, depth: number): number | null => {
    const here = depth + 1 + (g.negated ? 1 : 0);
    if (g.id === groupId) return here;
    for (const c of g.children) {
      if (c.kind === 'group') {
        const d = find(c, here);
        if (d !== null) return d;
      }
    }
    return null;
  };
  return find(root, 0) ?? 1;
}

/** May a subgroup be added in this group without going beyond the depth bound, a negated condition in it included? */
export const canNest = (root: EditorGroup, groupId: string): boolean => depthOfGroup(root, groupId) + 2 <= RULE_LIMITS.maxDepth;

// ── Immutable updates of the tree ───────────────────────────────────────────

export function updateNode(root: EditorGroup, id: string, fn: (n: EditorNode) => EditorNode): EditorGroup {
  const walk = (n: EditorNode): EditorNode => {
    if (n.id === id) return fn(n);
    if (n.kind === 'group') {
      const children = n.children.map(walk);
      return children.some((c, i) => c !== n.children[i]) ? { ...n, children } : n;
    }
    return n;
  };
  return walk(root) as EditorGroup;
}

export function removeNode(root: EditorGroup, id: string): EditorGroup {
  const walk = (g: EditorGroup): EditorGroup => ({
    ...g,
    children: g.children.filter((c) => c.id !== id).map((c) => (c.kind === 'group' ? walk(c) : c)),
  });
  return walk(root);
}

export const appendChild = (root: EditorGroup, groupId: string, child: EditorNode): EditorGroup =>
  updateNode(root, groupId, (n) => (n.kind === 'group' ? { ...n, children: [...n.children, child] } : n));

/** The same rule whatever the order of the properties of its nodes (comparison of two definitions). */
export const ruleKey = (rule: RuleNode | null | undefined): string => (rule ? JSON.stringify(canonicalRule(rule)) : '');
