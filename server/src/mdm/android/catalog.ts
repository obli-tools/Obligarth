import { createHash } from 'node:crypto';
import { canonicalJson } from '../../audit/canonical';
import { AMAPI_POLICY_SCHEMA } from './schema/amapiPolicySchema';
import type { AmapiSchemaCatalog, AmapiSchemaNode } from './schemaTypes';

// =============================================================================
// The catalog of the AMAPI Policy resource, as the validation and the
// compilation of the Android policies read it: the schemas generated from the
// discovery document (pinned revision), and a checker of a JSON value against
// them (types, formats, enumerations, unknown and deprecated fields). The
// policy body is otherwise passed to Google as it is: the checker refuses what
// Google would refuse, nothing more, plus the deprecations (a deprecated field
// or value is refused at the write, with its replacement, by the overlay).
// Pure: no database, no logger; the unit tests load it.
// =============================================================================

export type SchemaIssueCode = 'unknown_key' | 'type_mismatch' | 'out_of_range' | 'field_deprecated' | 'value_deprecated' | 'too_deep';

export interface SchemaIssue {
  /** Path of the value ('fragment.passwordPolicies[0].passwordMinimumLength'). */
  path: string;
  code: SchemaIssueCode;
}

export interface AndroidCatalogView {
  release: { revision: string; sourceSha256: string };
  /** A top-level field of Policy; undefined when unknown. */
  field(name: string): AmapiSchemaNode | undefined;
  /** The top-level fields of Policy, sorted. */
  fields(): string[];
  /** A schema of the catalog by id. */
  schema(id: string): AmapiSchemaNode | undefined;
  /**
   * Checks `value` against `node` (a field of Policy, or a schema), adding the issues found. `skip(path, value)`:
   * a value the caller handles itself (a secret marker where a secret is allowed): not checked.
   */
  check(node: AmapiSchemaNode, value: unknown, path: string, issues: SchemaIssue[],
    skip?: (path: string, value: unknown) => boolean): void;
}

const MAX_DEPTH = 32;
const INT32_MIN = -(2 ** 31);
const INT32_MAX = 2 ** 31 - 1;
const INT64_RE = /^-?\d{1,19}$/;
const UINT64_RE = /^\d{1,20}$/;
const DURATION_RE = /^-?\d{1,12}(\.\d{1,9})?s$/;
const DATETIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const BYTE_RE = /^[A-Za-z0-9+/_-]*={0,2}$/;
const FIELD_MASK_RE = /^([A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*)(,[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*)*$/;

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v) && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);

/** The entry of a table under a name sent by an editor: its own entries only, never a member of Object.prototype. */
function own<T>(table: Readonly<Record<string, T>> | undefined, name: string): T | undefined {
  return table !== undefined && Object.prototype.hasOwnProperty.call(table, name) ? table[name] : undefined;
}

function checkString(node: AmapiSchemaNode, v: unknown): SchemaIssueCode | null {
  // 64-bit integers are strings in JSON; a safe integer number is accepted as Google accepts it.
  if (node.format === 'int64' || node.format === 'uint64') {
    if (typeof v === 'number') return Number.isSafeInteger(v) && (node.format === 'int64' || v >= 0) ? null : 'out_of_range';
    if (typeof v !== 'string') return 'type_mismatch';
    if (!(node.format === 'int64' ? INT64_RE : UINT64_RE).test(v)) return 'type_mismatch';
    const n = BigInt(v);
    if (node.format === 'int64' ? (n < -(2n ** 63n) || n > 2n ** 63n - 1n) : n > 2n ** 64n - 1n) return 'out_of_range';
    return null;
  }
  if (typeof v !== 'string') return 'type_mismatch';
  switch (node.format) {
    case 'google-duration': return DURATION_RE.test(v) ? null : 'type_mismatch';
    case 'google-datetime': return DATETIME_RE.test(v) && Number.isFinite(Date.parse(v)) ? null : 'type_mismatch';
    case 'byte': return BYTE_RE.test(v) ? null : 'type_mismatch';
    case 'google-fieldmask': return v === '' || FIELD_MASK_RE.test(v) ? null : 'type_mismatch';
    default: break;
  }
  if (node.enum) {
    if (!node.enum.includes(v)) return 'out_of_range';
    if (node.deprecatedValues?.includes(v)) return 'value_deprecated';
  }
  return null;
}

export function buildAndroidCatalog(catalog: AmapiSchemaCatalog): AndroidCatalogView {
  const root = own(catalog.schemas, catalog.root);
  if (!root?.properties) throw new Error('AMAPI catalog without its root schema');
  const fields = Object.keys(root.properties).sort();

  const resolve = (node: AmapiSchemaNode): AmapiSchemaNode | undefined => (node.$ref ? own(catalog.schemas, node.$ref) : node);

  function check(node: AmapiSchemaNode, value: unknown, path: string, issues: SchemaIssue[],
    skip?: (path: string, value: unknown) => boolean, depth = 0): void {
    if (skip?.(path, value)) return;
    if (depth > MAX_DEPTH) { issues.push({ path, code: 'too_deep' }); return; }
    if (node.deprecated) issues.push({ path, code: 'field_deprecated' });
    const n = resolve(node);
    if (!n) { issues.push({ path, code: 'unknown_key' }); return; }
    switch (n.type) {
      case 'any': return;
      case 'boolean': if (typeof value !== 'boolean') issues.push({ path, code: 'type_mismatch' }); return;
      case 'integer': {
        if (typeof value !== 'number' || !Number.isInteger(value)) { issues.push({ path, code: 'type_mismatch' }); return; }
        if ((n.format === 'int32' || !n.format) && (value < INT32_MIN || value > INT32_MAX)) issues.push({ path, code: 'out_of_range' });
        else if (n.format === 'uint32' && (value < 0 || value > 2 ** 32 - 1)) issues.push({ path, code: 'out_of_range' });
        return;
      }
      case 'number': if (typeof value !== 'number' || !Number.isFinite(value)) issues.push({ path, code: 'type_mismatch' }); return;
      case 'string': {
        const code = checkString(n, value);
        if (code) issues.push({ path, code });
        return;
      }
      case 'array': {
        if (!Array.isArray(value)) { issues.push({ path, code: 'type_mismatch' }); return; }
        if (n.items) value.forEach((x, i) => check(n.items!, x, `${path}[${i}]`, issues, skip, depth + 1));
        return;
      }
      case 'object': {
        if (!isPlainObject(value)) { issues.push({ path, code: 'type_mismatch' }); return; }
        for (const [k, x] of Object.entries(value)) {
          const p = `${path}.${k}`;
          const child = own(n.properties, k) ?? n.additionalProperties;
          if (!child) { issues.push({ path: p, code: 'unknown_key' }); continue; }
          check(child, x, p, issues, skip, depth + 1);
        }
        return;
      }
      default:
        issues.push({ path, code: 'type_mismatch' });
    }
  }

  return {
    release: { revision: catalog.revision, sourceSha256: catalog.sourceSha256 },
    field: (name) => own(root.properties, name),
    fields: () => [...fields],
    schema: (id) => own(catalog.schemas, id),
    check: (node, value, path, issues, skip) => check(node, value, path, issues, skip, 0),
  };
}

let current: AndroidCatalogView | null = null;

/** The current catalog (the one shipped with the server). */
export function androidCatalog(): AndroidCatalogView {
  if (!current) current = buildAndroidCatalog(AMAPI_POLICY_SCHEMA);
  return current;
}

/** A fingerprint of what the Android compilation depends on apart from the policies: the catalog's revision, the
 *  overlay and the compiler's version (a change resolves every tenant again, as for Apple). */
export function androidCatalogFingerprint(overlay: unknown, compilerVersion: number): string {
  const c = androidCatalog();
  return createHash('sha256').update(canonicalJson({ revision: c.release.revision, source: c.release.sourceSha256, overlay,
    compiler: compilerVersion })).digest('hex');
}
