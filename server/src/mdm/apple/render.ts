import { createHash } from 'node:crypto';
import {
  RAW_PROFILE_TYPE, isSecretRef, subkeyNamed, typedValueKind,
  type ArtifactChannel, type JsonValue, type SchemaKey,
} from '@obligarth/shared';
import { PlistData, PlistError, PlistReal, plistFromTypedJson, type PlistDict, type PlistValue } from '../../apple/commands/plist';
import { canonicalize, serverTokenOf, sha256Hex } from '../../apple/ddm/canonical';
import { RAW_SECRET_PURPOSE } from '../policies/validate';
import type { AppleCatalogView } from './catalog';
import { RenderError, renderVariables, type VariableValues } from './variables';

export { RAW_SECRET_PURPOSE };

// =============================================================================
// Rendering of a compiled artifact for one device (docs: modele-donnees-mdm
// §7.9): the variables are replaced, then
//   - a declaration is its JSON payload (never a secret, never an asset); its
//     rendered hash IS its ServerToken, computed by the engine's own function,
//     so the server-token a device reports names a version of the artifact;
//   - a profile is the dictionary handed to the command bus: the plist types
//     come from the catalog (integer, real, date, data), the secrets are read
//     from the tenant's vault by the caller and put in at the last moment; its
//     PayloadUUID (and its payloads') derive from the rendered hash, so that
//     ProfileList tells which version is installed;
//   - a Settings item is its values, with their plist types.
// The rendered hash of a profile or of a setting is the SHA-256 of the
// canonical JSON of the body rendered WITHOUT the secret values (their
// references stay): it changes when a variable changes, never derives from a
// secret.
// A secret is stored as the text typed in the editor; under a key of type
// data it is the base64 of the bytes (a PKCS #12 identity, a shared secret in
// data form). The secrets of a raw profile (purpose policy.raw_secret) are
// the JSON of the typed value the import moved to the vault.
// Pure (the secrets are passed in): the unit tests load it.
// =============================================================================

/** What the rendering reads of a stored artifact (mdm_artifacts). */
export interface StoredArtifact {
  channel: ArtifactChannel;
  artifactType: string;
  identifier: string;
  body: Record<string, JsonValue>;
  encrypt: boolean;
}

/** Payload types a profile of the policies never carries (S6): a second MDM enrollment, an identity request, a
 *  removal password. Refused at the import of a raw profile, and again here. */
export const FORBIDDEN_PAYLOAD_TYPES: ReadonlySet<string> = new Set([
  'com.apple.mdm', 'com.apple.security.scep', 'com.apple.security.acme', 'com.apple.profileremovalpassword',
]);

const MAX_DEPTH = 64;

const isObject = (v: unknown): v is Record<string, JsonValue> => !!v && typeof v === 'object' && !Array.isArray(v);

/** The body of an artifact with the variables of its values replaced (the envelope of a profile is never a
 *  template: a tenant's name or a display name is written as it is). Secret references stay. */
export function renderBody(a: StoredArtifact, vars: VariableValues): Record<string, JsonValue> {
  if (a.channel === 'ddm') return { ...a.body, Payload: renderVariables(a.body.Payload ?? {}, vars) };
  if (a.channel === 'setting') return { ...a.body, values: renderVariables(a.body.values ?? {}, vars) };
  if (a.channel === 'app') return a.body.Configuration !== undefined ? { ...a.body, Configuration: renderVariables(a.body.Configuration, vars) } : a.body;
  if (a.channel === 'profile') {
    const content = Array.isArray(a.body.PayloadContent) ? a.body.PayloadContent : [];
    return {
      ...a.body,
      PayloadContent: content.map((p) => (isObject(p) ? { ...p, values: renderVariables(p.values ?? {}, vars) } : p)),
    };
  }
  return a.body;
}

/** A typed JSON value as plain JSON (a declaration): a date as its text, data as base64, a real or a big integer
 *  as a number. A secret reference has no place in a declaration. */
function plainJson(v: JsonValue, depth = 0): JsonValue {
  if (depth > MAX_DEPTH) throw new RenderError('too_deep');
  if (Array.isArray(v)) return v.map((x) => plainJson(x, depth + 1));
  if (isObject(v)) {
    if (isSecretRef(v)) throw new RenderError('secret_in_declaration');
    switch (typedValueKind(v)) {
      case 'data': return (v as unknown as { $data: string }).$data;
      case 'date': return (v as unknown as { $date: string }).$date;
      case 'real': return (v as unknown as { $real: number }).$real;
      case 'int': {
        const n = Number((v as unknown as { $int: string }).$int);
        return Number.isSafeInteger(n) ? n : (v as unknown as { $int: string }).$int;
      }
      default: {
        const out: Record<string, JsonValue> = {};
        for (const [k, x] of Object.entries(v)) out[k] = plainJson(x, depth + 1);
        return out;
      }
    }
  }
  return v;
}

/** The payload of a declaration as the device reads it. */
export function declarationPayload(a: StoredArtifact, vars: VariableValues): Record<string, JsonValue> {
  const payload = plainJson(renderBody(a, vars).Payload ?? {});
  if (!isObject(payload)) throw new RenderError('invalid_value', 'Payload');
  return payload;
}

/**
 * The rendered hash of an artifact for the values of a device's variables: the ServerToken of a declaration, else
 * the SHA-256 of the canonical JSON of the rendered body (secret references in place of the secrets).
 */
export function renderedHash(a: StoredArtifact, vars: VariableValues): string {
  try {
    if (a.channel === 'ddm') return serverTokenOf({ identifier: a.identifier, type: a.artifactType, payload: declarationPayload(a, vars) });
    return sha256Hex(canonicalize(renderBody(a, vars)));
  } catch (err) {
    if (err instanceof RenderError) throw err;
    throw new RenderError('invalid_value');
  }
}

/** An upper-case UUID derived from a rendered hash (version 8: a value of our own making, never random). */
export function derivedUuid(hash: string, salt: string | number): string {
  const b = createHash('sha256').update(`${hash}:${salt}`, 'utf8').digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x80;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex').toUpperCase();
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** The PayloadUUID ProfileList reports for a profile delivered at this rendered hash. */
export const profileUuid = (hash: string): string => derivedUuid(hash, 'profile');

/** The values of the secrets a rendering needs, by reference (the caller read them from the vault). */
export type SecretValues = ReadonlyMap<string, Buffer>;

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

interface PlistCtx { secrets: SecretValues; raw: boolean }

function secretValue(x: PlistCtx, id: string, key: SchemaKey | undefined, depth: number): PlistValue {
  const bytes = x.secrets.get(id);
  if (!bytes) throw new RenderError('secret_unavailable');
  const text = bytes.toString('utf8');
  if (x.raw) {
    // The typed value the import of the raw profile moved to the vault, as JSON.
    let typed: unknown;
    try { typed = JSON.parse(text); } catch { throw new RenderError('secret_invalid'); }
    try { return plistFromTypedJson(typed, depth); } catch { throw new RenderError('secret_invalid'); }
  }
  if (key?.type === 'data') {
    const b64 = text.replace(/\s+/g, '');
    if (b64 === '' || b64.length % 4 !== 0 || !BASE64_RE.test(b64)) throw new RenderError('secret_invalid', key.name);
    return new PlistData(Buffer.from(b64, 'base64'));
  }
  return text;
}

/** A value of a payload as a plist value, typed by its schema key when there is one. null has no plist form: the
 *  key is left out (undefined). */
function toPlist(x: PlistCtx, v: JsonValue, key: SchemaKey | undefined, depth: number): PlistValue | undefined {
  if (depth > MAX_DEPTH) throw new RenderError('too_deep');
  if (v === null) return undefined;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new RenderError('invalid_value', key?.name ?? null);
    return key?.type === 'real' || !Number.isSafeInteger(v) ? new PlistReal(v) : v;
  }
  if (typeof v === 'string' || typeof v === 'boolean') return v;
  if (Array.isArray(v)) {
    const element = key?.type === 'array' ? key.subkeys?.[0] : undefined;
    return v.map((e) => toPlist(x, e, element, depth + 1)).filter((e): e is PlistValue => e !== undefined);
  }
  if (isSecretRef(v)) return secretValue(x, v.$secret, key, depth);
  if (typedValueKind(v) !== null) {
    try { return plistFromTypedJson(v, depth); } catch { throw new RenderError('invalid_value', key?.name ?? null); }
  }
  const out: PlistDict = {};
  const subkeys = key === undefined || key.type === 'dictionary' ? key?.subkeys : undefined;
  for (const [k, e] of Object.entries(v)) {
    const p = toPlist(x, e, subkeyNamed(subkeys, k), depth + 1);
    if (p !== undefined) out[k] = p;
  }
  return out;
}

/**
 * The configuration profile of an artifact for a device: the dictionary the command bus installs (PayloadContent
 * in clear: the bus encrypts it for the device when it carries a secret). `hash`: the rendered hash of the
 * artifact for this device (PayloadUUIDs derive from it). The payloads of a raw profile keep their own
 * identifiers and UUIDs (they may refer to each other by UUID).
 */
export function profilePlist(a: StoredArtifact, vars: VariableValues, hash: string, secrets: SecretValues, catalog: AppleCatalogView): PlistDict {
  if (a.channel !== 'profile') throw new RenderError('invalid_value');
  const body = renderBody(a, vars);
  const raw = a.artifactType === RAW_PROFILE_TYPE;
  const content = Array.isArray(body.PayloadContent) ? body.PayloadContent : [];
  if (content.length === 0) throw new RenderError('invalid_value', 'PayloadContent');
  const x: PlistCtx = { secrets, raw };
  const payloads = content.map((p, i): PlistDict => {
    if (!isObject(p) || typeof p.PayloadType !== 'string' || !p.PayloadType) throw new RenderError('invalid_value', 'PayloadType');
    const type = p.PayloadType;
    if (FORBIDDEN_PAYLOAD_TYPES.has(type.toLowerCase())) throw new RenderError('forbidden_payload');
    const entry = raw ? undefined : catalog.entry(type);
    const values = toPlist(x, isObject(p.values) ? p.values : {}, entry ? { name: type, type: 'dictionary', subkeys: entry.keys } : undefined, 1) as PlistDict;
    const own = (k: string): string | null => (raw && typeof values[k] === 'string' && values[k] !== '' ? values[k] as string : null);
    return {
      ...values,
      PayloadType: type,
      PayloadVersion: raw && typeof values.PayloadVersion === 'number' ? values.PayloadVersion : 1,
      PayloadIdentifier: own('PayloadIdentifier') ?? `${a.identifier}.${i + 1}`,
      PayloadUUID: own('PayloadUUID') ?? derivedUuid(hash, i),
    };
  });
  return {
    PayloadType: 'Configuration',
    PayloadVersion: 1,
    PayloadIdentifier: a.identifier,
    PayloadUUID: profileUuid(hash),
    PayloadDisplayName: typeof body.PayloadDisplayName === 'string' ? body.PayloadDisplayName : a.identifier,
    ...(typeof body.PayloadOrganization === 'string' && body.PayloadOrganization ? { PayloadOrganization: body.PayloadOrganization } : {}),
    PayloadContent: payloads,
  };
}

/** The item of a Settings command of an artifact: its name and its rendered values (typed JSON: the command
 *  catalogue gives them their plist types). Checked here, so that a value with no plist form fails the rendering
 *  and not the command. */
export function settingsItem(a: StoredArtifact, vars: VariableValues): { item: string; values: Record<string, JsonValue> } {
  if (a.channel !== 'setting') throw new RenderError('invalid_value');
  const body = renderBody(a, vars);
  const values = isObject(body.values) ? body.values : {};
  if (typeof body.Item !== 'string' || !/^[A-Z][A-Za-z0-9]{0,63}$/.test(body.Item)) throw new RenderError('invalid_value', 'Item');
  try {
    plistFromTypedJson(values);
  } catch (err) {
    if (err instanceof PlistError) throw new RenderError('invalid_value', body.Item);
    throw err;
  }
  return { item: body.Item, values };
}
