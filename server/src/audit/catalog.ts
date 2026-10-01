// Catalogue of the audit actions (docs: audit-durci §3.4): each action is
// declared by the module that emits it, with its class and its English label
// (the console translates it, key audit.actions.<action>). An undeclared
// action is accepted in class 'standard', with an error in strict mode
// (development, test, AUDIT_STRICT_CATALOG=true: the body is refused) and a
// warning otherwise. No database import (unit tests).
import type { AuditCriticality } from '@obligarth/shared';
import type { AuditActionDef } from './types';

/** An action name, as obligarth.audit_append checks it. */
export const ACTION_RE = /^[a-z][a-z0-9_]*([.][a-z0-9_]+){1,4}$/;
/** A family of actions: a prefix that ends with a dot ('sso_sync.'). */
const PREFIX_RE = /^[a-z][a-z0-9_]*([.][a-z0-9_]+){0,3}[.]$/;

const CLASSES: ReadonlySet<string> = new Set(['critical', 'protective', 'standard']);

const exact = new Map<string, AuditActionDef>();
const prefixes: AuditActionDef[] = [];

/** Declares an action (or a family, name ending with '.'). Throws on a bad
 *  name, an unknown class or a duplicate: a defect of the code, at start. */
export function registerAuditAction(def: AuditActionDef): void {
  const name = String(def?.name ?? '');
  const isPrefix = name.endsWith('.');
  if (isPrefix ? !PREFIX_RE.test(name) : (!ACTION_RE.test(name) || name.length > 100)) {
    throw new Error(`audit catalogue: invalid action name ${JSON.stringify(name)}`);
  }
  if (!CLASSES.has(def.criticality)) throw new Error(`audit catalogue: ${name}: unknown class ${String(def.criticality)}`);
  if (typeof def.label !== 'string' || !def.label.trim() || def.label.length > 200) {
    throw new Error(`audit catalogue: ${name}: an English label is required`);
  }
  if (exact.has(name) || prefixes.some((p) => p.name === name)) throw new Error(`audit catalogue: ${name} declared twice`);
  const frozen = Object.freeze({ name, criticality: def.criticality, label: def.label.trim() });
  if (isPrefix) {
    prefixes.push(frozen);
    prefixes.sort((a, b) => b.name.length - a.name.length);   // longest prefix first
  } else {
    exact.set(name, frozen);
  }
}

/** Declares several actions at once (same rules). */
export function registerAuditActions(defs: readonly AuditActionDef[]): void {
  for (const d of defs) registerAuditAction(d);
}

/** The definition of an action: its own, else the longest family that
 *  contains it. */
export function auditActionDef(action: string): AuditActionDef | undefined {
  return exact.get(action) ?? prefixes.find((p) => action.startsWith(p.name));
}

export function isDeclaredAction(action: string): boolean {
  return auditActionDef(action) !== undefined;
}

/** Every declared action and family (console, static checks). */
export function auditActionList(): AuditActionDef[] {
  return [...exact.values(), ...prefixes].sort((a, b) => a.name.localeCompare(b.name));
}

const RANK: Record<AuditCriticality, number> = { standard: 0, protective: 1, critical: 2 };

/**
 * The class of an entry: the catalogue's (standard when undeclared), raised
 * by the caller's request, never lowered. A protective action is never
 * raised to critical by accident of a lower request; 'critical' raises
 * anything.
 */
export function effectiveCriticality(action: string, requested?: AuditCriticality): AuditCriticality {
  const base = auditActionDef(action)?.criticality ?? 'standard';
  if (!requested || !CLASSES.has(requested)) return base;
  return RANK[requested] > RANK[base] ? requested : base;
}
