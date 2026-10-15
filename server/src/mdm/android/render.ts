import { createHash } from 'node:crypto';
import { isSecretRef, type JsonValue } from '@obligarth/shared';
import { canonicalize } from '../../apple/ddm/canonical';
import { RenderError, renderVariables, type VariableValues } from '../apple/variables';

// =============================================================================
// Rendering of a compiled Android policy for one device, at the moment of the
// push: the variables are replaced (closed list, strings only, one pass), then
// the secret references by the values the caller read from the tenant's vault.
// The rendered policy exists in the memory of the push only: never logged,
// never stored; what is kept is its rendered hash, the SHA-256 of the
// canonical JSON of the body rendered WITHOUT the secret values (their
// references stay), so that it changes when a variable changes and never
// derives from a secret: two values of a secret give the same rendered hash.
// Pure (the secrets are passed in): the unit tests load it.
// =============================================================================

export { RenderError };

/** The values of the secrets a rendering needs, by reference (the caller read them from the vault). */
export type AndroidSecretValues = ReadonlyMap<string, Buffer>;

export interface RenderedAndroidPolicy {
  /** The policy to put to Google (secrets in clear): memory only. */
  policy: Record<string, JsonValue>;
  renderedHash: string;
}

const MAX_DEPTH = 64;

/** The rendered hash of a compiled body for the values of a device's variables (no secret needed). */
export function androidRenderedHash(body: Record<string, JsonValue>, vars: VariableValues): string {
  const rendered = renderVariables(body, vars);
  try {
    return createHash('sha256').update(canonicalize(rendered), 'utf8').digest('hex');
  } catch {
    throw new RenderError('invalid_value');
  }
}

function withSecrets(v: JsonValue, secrets: AndroidSecretValues, depth: number): JsonValue {
  if (depth > MAX_DEPTH) throw new RenderError('too_deep');
  if (Array.isArray(v)) return v.map((x) => withSecrets(x, secrets, depth + 1));
  if (v && typeof v === 'object') {
    if (isSecretRef(v)) {
      const bytes = secrets.get(v.$secret);
      if (!bytes) throw new RenderError('secret_unavailable');
      return bytes.toString('utf8');
    }
    const out: Record<string, JsonValue> = {};
    for (const [k, x] of Object.entries(v)) out[k] = withSecrets(x, secrets, depth + 1);
    return out;
  }
  return v;
}

/** The policy of a device: variables, then secrets; with its rendered hash. */
export function renderAndroidPolicy(body: Record<string, JsonValue>, vars: VariableValues, secrets: AndroidSecretValues): RenderedAndroidPolicy {
  const rendered = renderVariables(body, vars) as Record<string, JsonValue>;
  let renderedHash: string;
  try {
    renderedHash = createHash('sha256').update(canonicalize(rendered), 'utf8').digest('hex');
  } catch {
    throw new RenderError('invalid_value');
  }
  return { policy: withSecrets(rendered, secrets, 0) as Record<string, JsonValue>, renderedHash };
}
