import { createHash } from 'node:crypto';

// =============================================================================
// Canonical JSON and the tokens of the DDM engine (docs: integration-apple-edge
// §9.4, I7, annex C.2 and C.3). Everything a device compares is deterministic:
//   - canonical JSON = RFC 8785 (keys sorted by UTF-16 code units, no
//     whitespace, numbers and strings as JSON.stringify writes them);
//   - ServerToken of a declaration = SHA-256 (lower-case hexadecimal) of the
//     canonical JSON of { Identifier, Payload, Type };
//   - DeclarationsToken of a set = SHA-256 of the lines
//     identifier + "\t" + ServerToken + "\n", sorted by identifier.
// The bodies the relay serves (tokens, declaration-items, one declaration) are
// built here, so that the bytes signed are the bytes hashed. Self-contained
// (node:crypto only): the unit tests run under node --test.
// =============================================================================

export type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

export class CanonicalJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalJsonError';
  }
}

/** A lone surrogate is not a Unicode scalar value: RFC 8785 refuses it (JSON.stringify would escape it). */
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
/** Nesting accepted (a declaration is a small document; a cycle ends here). */
const MAX_DEPTH = 64;

function quote(s: string): string {
  if (LONE_SURROGATE_RE.test(s)) throw new CanonicalJsonError('lone surrogate in a string');
  return JSON.stringify(s);
}

function write(v: unknown, depth: number): string {
  if (depth > MAX_DEPTH) throw new CanonicalJsonError('value nested too deeply');
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean': return v ? 'true' : 'false';
    case 'string': return quote(v);
    case 'number':
      if (!Number.isFinite(v)) throw new CanonicalJsonError('non-finite number');
      return JSON.stringify(v);                         // ECMAScript Number-to-string, as RFC 8785 asks; -0 → 0
    case 'object': {
      if (Array.isArray(v)) return `[${v.map((x) => write(x, depth + 1)).join(',')}]`;
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) throw new CanonicalJsonError('not a plain object');
      const o = v as Record<string, unknown>;
      // Array.prototype.sort compares UTF-16 code units: the order of RFC 8785.
      return `{${Object.keys(o).sort().map((k) => `${quote(k)}:${write(o[k], depth + 1)}`).join(',')}}`;
    }
    default:
      throw new CanonicalJsonError(`unsupported value of type ${typeof v}`);
  }
}

/** The canonical JSON (RFC 8785) of a JSON value; throws CanonicalJsonError for anything else (undefined, a
 *  function, a non-finite number, a class instance, a lone surrogate). */
export function canonicalize(v: unknown): string {
  return write(v, 0);
}

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data).digest('hex');
}

export const SERVER_TOKEN_RE = /^[0-9a-f]{64}$/;

/** ServerToken: SHA-256 of the canonical JSON of { Identifier, Payload, Type }. */
export function serverTokenOf(d: { identifier: string; type: string; payload: unknown }): string {
  return sha256Hex(canonicalize({ Identifier: d.identifier, Payload: d.payload, Type: d.type }));
}

/** Identifiers compared by UTF-16 code units (their alphabet is ASCII: byte order). */
export function byIdentifier<T extends { identifier: string }>(a: T, b: T): number {
  return a.identifier < b.identifier ? -1 : a.identifier > b.identifier ? 1 : 0;
}

/** DeclarationsToken: SHA-256 of the lines "identifier \t ServerToken \n", sorted by identifier. */
export function declarationsTokenOf(items: ReadonlyArray<{ identifier: string; serverToken: string }>): string {
  const h = createHash('sha256');
  for (const i of [...items].sort(byIdentifier)) h.update(`${i.identifier}\t${i.serverToken}\n`, 'utf8');
  return h.digest('hex');
}

/** The token of a set without any declaration (a device that has not reported its capabilities yet). */
export const EMPTY_DECLARATIONS_TOKEN = declarationsTokenOf([]);

/** AAAA-MM-JJTHH:MM:SSZ (UTC, no fraction): the Timestamp of the synchronisation tokens. */
export function syncTimestamp(d: Date): string {
  if (Number.isNaN(d.getTime())) throw new CanonicalJsonError('invalid date');
  return `${d.toISOString().slice(0, 19)}Z`;
}

/** The answer to `tokens`, and the Data of the DeclarativeManagement command: the same bytes. */
export function syncTokensBody(declarationsToken: string, computedAt: Date): string {
  return canonicalize({ SyncTokens: { DeclarationsToken: declarationsToken, Timestamp: syncTimestamp(computedAt) } });
}

export type DeclarationFamilyName = 'activation' | 'asset' | 'configuration' | 'management';

const ITEMS_KEY: Record<DeclarationFamilyName, 'Activations' | 'Assets' | 'Configurations' | 'Management'> = {
  activation: 'Activations', asset: 'Assets', configuration: 'Configurations', management: 'Management',
};

/** The answer to `declaration-items`: every family present, each sorted by identifier. */
export function declarationItemsBody(items: ReadonlyArray<{ family: DeclarationFamilyName; identifier: string; serverToken: string }>,
  declarationsToken: string): string {
  const out: Record<string, Array<{ Identifier: string; ServerToken: string }>> = { Activations: [], Assets: [], Configurations: [], Management: [] };
  for (const i of [...items].sort(byIdentifier)) out[ITEMS_KEY[i.family]].push({ Identifier: i.identifier, ServerToken: i.serverToken });
  return canonicalize({ Declarations: out, DeclarationsToken: declarationsToken });
}

/** The answer to `declaration/<family>/<identifier>`. */
export function declarationBody(d: { identifier: string; type: string; payload: unknown; serverToken: string }): string {
  return canonicalize({ Identifier: d.identifier, Payload: d.payload, ServerToken: d.serverToken, Type: d.type });
}
