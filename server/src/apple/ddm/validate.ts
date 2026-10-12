import { byIdentifier, canonicalize, declarationsTokenOf, serverTokenOf, type JsonValue } from './canonical';
import { DECLARATION_FAMILIES, type DdmClientCapabilities, type DeclarationFamily } from './capabilities';
import { findSecret } from './secrets';

// =============================================================================
// Validation of the declarations of a device's set (docs: integration-apple-
// edge §9.1, §9.4 steps 1 to 5, I8, EX-12). Pure: what the providers returned
// goes in, the set served (and what was set aside, with why) comes out.
//   1. each declaration: a known family, an identifier of apple-edge's
//      alphabet that its provider owns, a type whose prefix is the family's and
//      that the device announced (EX-12), a plain-object payload of 512 KiB at
//      most in canonical JSON, no secret (I8), no asset at the MVP (§9.8); an
//      identifier returned twice sets both aside;
//   2. activations: a reference (StandardConfigurations) to a configuration
//      that is not in the set is removed; an activation left without any
//      reference is set aside;
//   3. ServerToken of each declaration (of the payload actually served);
//   4. items sorted by identifier, 1 000 at most; DeclarationsToken.
// Self-contained (no database, no logger): the unit tests run under
// node --test.
// =============================================================================

export const DECLARATION_IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;
export const DECLARATION_TYPE_RE = /^com\.apple\.[A-Za-z0-9][A-Za-z0-9._-]{0,115}$/;
export const TYPE_PREFIX: Record<DeclarationFamily, string> = {
  activation: 'com.apple.activation.', asset: 'com.apple.asset.', configuration: 'com.apple.configuration.', management: 'com.apple.management.',
};
/** Largest payload of a declaration, in bytes of its canonical JSON. */
export const MAX_DECLARATION_BYTES = 512 * 1024;
/** Most declarations in the set of one device. */
export const MAX_DECLARATIONS_PER_DEVICE = 1000;
const SIMPLE_ACTIVATION = 'com.apple.activation.simple';

export interface DeclarationSpec {
  family: DeclarationFamily;
  identifier: string;
  /** 'com.apple.activation.simple', 'com.apple.configuration.passcode.settings'… */
  type: string;
  /** Never a secret (I8): the engine runs the secret scanner on it. */
  payload: { [k: string]: JsonValue };
}

export interface ProviderDeclarations {
  /** Provider name ('core', 'policies'…). */
  provider: string;
  /** Identifiers this provider owns. */
  owns: RegExp;
  declarations: DeclarationSpec[];
}

export type DropReason = 'invalid_family' | 'invalid_identifier' | 'not_owned' | 'invalid_type' | 'client_unsupported' | 'asset_unsupported'
  | 'invalid_payload' | 'too_large' | 'secret' | 'duplicate' | 'dangling_activation' | 'over_limit';

export interface DroppedDeclaration {
  provider: string;
  /** Empty when the identifier itself is not usable. */
  identifier: string;
  reason: DropReason;
  /** secret: where (keys only). */
  where?: string;
}

export interface SetDeclaration {
  family: DeclarationFamily;
  identifier: string;
  type: string;
  payload: { [k: string]: JsonValue };
  serverToken: string;
  provider: string;
}

export interface BuiltSet {
  /** Sorted by identifier. */
  declarations: SetDeclaration[];
  declarationsToken: string;
  dropped: DroppedDeclaration[];
}

const isPlainObject = (v: unknown): v is Record<string, unknown> => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};

/** Does a JSON value hold a NUL character in a string or a key? (PostgreSQL's jsonb refuses it.) */
function hasNul(v: unknown): boolean {
  if (typeof v === 'string') return v.includes('\u0000');
  if (Array.isArray(v)) return v.some(hasNul);
  if (v && typeof v === 'object') return Object.entries(v as Record<string, unknown>).some(([k, x]) => k.includes('\u0000') || hasNul(x));
  return false;
}

/** Does the provider's expression own the identifier? (A global or sticky expression keeps a cursor: reset.) */
function owns(re: RegExp, identifier: string): boolean {
  re.lastIndex = 0;
  const ok = re.test(identifier);
  re.lastIndex = 0;
  return ok;
}

/** The identifier of a declaration as far as it can be reported (never an arbitrary value of a provider). */
const reportable = (identifier: unknown): string => (typeof identifier === 'string' && DECLARATION_IDENTIFIER_RE.test(identifier) ? identifier : '');

/**
 * The set of a device from what the providers returned, for the capabilities the device announced. The answer of
 * a provider is never trusted: every refusal sets the declaration aside (and tells why), never throws.
 */
export function buildSet(sources: ProviderDeclarations[], capabilities: DdmClientCapabilities): BuiltSet {
  const dropped: DroppedDeclaration[] = [];
  const candidates = new Map<string, { family: DeclarationFamily; identifier: string; type: string; payload: Record<string, JsonValue>; provider: string }>();
  /** Every identifier a provider returned (and owns), whatever became of its declaration. */
  const seen = new Set<string>();

  // 1. Each declaration on its own.
  for (const src of sources) {
    for (const d of Array.isArray(src.declarations) ? src.declarations : []) {
      const drop = (reason: DropReason, where?: string): void => {
        dropped.push({ provider: src.provider, identifier: reportable(d?.identifier), reason, ...(where ? { where } : {}) });
      };
      if (!d || !DECLARATION_FAMILIES.includes(d.family)) { drop('invalid_family'); continue; }
      if (typeof d.identifier !== 'string' || !DECLARATION_IDENTIFIER_RE.test(d.identifier)) { drop('invalid_identifier'); continue; }
      if (!owns(src.owns, d.identifier)) { drop('not_owned'); continue; }
      if (seen.has(d.identifier)) {
        // Two declarations under one identifier: neither is served (the first one may already be set aside).
        const earlier = candidates.get(d.identifier);
        if (earlier) {
          candidates.delete(d.identifier);
          dropped.push({ provider: earlier.provider, identifier: d.identifier, reason: 'duplicate' });
        }
        drop('duplicate');
        continue;
      }
      seen.add(d.identifier);
      if (typeof d.type !== 'string' || !DECLARATION_TYPE_RE.test(d.type) || !d.type.startsWith(TYPE_PREFIX[d.family])) { drop('invalid_type'); continue; }
      if (d.family === 'asset') { drop('asset_unsupported'); continue; }
      if (!capabilities.declarationTypes[d.family].includes(d.type)) { drop('client_unsupported'); continue; }
      if (!isPlainObject(d.payload) || hasNul(d.payload)) { drop('invalid_payload'); continue; }
      let size: number;
      try {
        size = Buffer.byteLength(canonicalize(d.payload), 'utf8');
      } catch {
        drop('invalid_payload');
        continue;
      }
      if (size > MAX_DECLARATION_BYTES) { drop('too_large'); continue; }
      const secret = findSecret(d.payload);
      if (secret) { drop('secret', secret); continue; }
      // A copy: nothing a provider keeps a reference to is served nor hashed.
      candidates.set(d.identifier, {
        family: d.family, identifier: d.identifier, type: d.type, payload: JSON.parse(JSON.stringify(d.payload)) as Record<string, JsonValue>,
        provider: src.provider,
      });
    }
  }

  // 4 (limit). Beyond 1 000 declarations, the last identifiers are set aside (deterministic), before the activations
  //    are pruned: an activation never refers to a configuration that is not served.
  let kept = [...candidates.values()].sort(byIdentifier);
  if (kept.length > MAX_DECLARATIONS_PER_DEVICE) {
    for (const d of kept.slice(MAX_DECLARATIONS_PER_DEVICE)) dropped.push({ provider: d.provider, identifier: d.identifier, reason: 'over_limit' });
    kept = kept.slice(0, MAX_DECLARATIONS_PER_DEVICE);
  }

  // 2. Activations: references to absent configurations removed; an activation without reference left is set aside.
  const configurations = new Set(kept.filter((d) => d.family === 'configuration').map((d) => d.identifier));
  const served: typeof kept = [];
  for (const d of kept) {
    if (d.family === 'activation' && d.type === SIMPLE_ACTIVATION) {
      const refs = Array.isArray(d.payload.StandardConfigurations) ? d.payload.StandardConfigurations : [];
      const live = refs.filter((r): r is string => typeof r === 'string' && configurations.has(r));
      if (live.length === 0) {
        dropped.push({ provider: d.provider, identifier: d.identifier, reason: 'dangling_activation' });
        continue;
      }
      served.push({ ...d, payload: { ...d.payload, StandardConfigurations: [...new Set(live)] } });
    } else {
      served.push(d);
    }
  }

  // 3 and 4. Tokens.
  const declarations: SetDeclaration[] = served.map((d) => ({ ...d, serverToken: serverTokenOf(d) }));
  return { declarations, declarationsToken: declarationsTokenOf(declarations), dropped };
}
