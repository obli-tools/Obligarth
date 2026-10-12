import { isPolicyVariable, isSecretRef, type JsonValue, type PolicyVariable } from '@obligarth/shared';

// =============================================================================
// Variables of the policies at rendering (docs: modele-donnees-mdm §7.2, DM22,
// CFG-07, S8): a closed list, resolved per device when an artifact is
// delivered. A variable is replaced in string values only, never in the name
// of a key nor in an identifier, in one pass (a rendered value is never read
// again as a template); the value goes to the plist or JSON serialiser, which
// escapes it. A variable without a value for the device makes the rendering
// fail (variable_unresolved): the resolution already found the setting not
// applicable, and nothing is ever sent empty nor literal.
// Pure: the unit tests load it.
// =============================================================================

export type RenderErrorCode = 'variable_unresolved' | 'secret_unavailable' | 'secret_invalid' | 'secret_in_declaration'
  | 'invalid_value' | 'forbidden_payload' | 'too_deep';

/** Why an artifact cannot be rendered for a device. `detail`: a variable or a key name, never a value. */
export class RenderError extends Error {
  readonly code: RenderErrorCode;
  readonly detail: string | null;
  constructor(code: RenderErrorCode, detail: string | null = null) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'RenderError';
    this.code = code;
    this.detail = detail;
  }
}

/** The values of the variables for one device: only those that have one. */
export type VariableValues = Partial<Record<PolicyVariable, string>>;

const TOKEN_RE = /\{\{([^{}]*)\}\}/g;
const MAX_DEPTH = 64;

/** A string with its variables replaced ('{{ device.name }}' and '{{device.name}}' alike). */
export function renderString(s: string, vars: VariableValues): string {
  if (!s.includes('{{')) return s;
  return s.replace(TOKEN_RE, (_m, raw: string) => {
    const name = raw.trim();
    const value = isPolicyVariable(name) ? vars[name] : undefined;
    if (typeof value !== 'string' || value === '') throw new RenderError('variable_unresolved', isPolicyVariable(name) ? name : null);
    return value;
  });
}

/** A value with the variables of its strings replaced; keys, secret references and typed values are left as they are. */
export function renderVariables(value: JsonValue, vars: VariableValues, depth = 0): JsonValue {
  if (depth > MAX_DEPTH) throw new RenderError('too_deep');
  if (typeof value === 'string') return renderString(value, vars);
  if (Array.isArray(value)) return value.map((v) => renderVariables(v, vars, depth + 1));
  if (value && typeof value === 'object') {
    if (isSecretRef(value)) return value;
    const out: Record<string, JsonValue> = {};
    for (const [k, v] of Object.entries(value)) out[k] = renderVariables(v, vars, depth + 1);
    return out;
  }
  return value;
}
