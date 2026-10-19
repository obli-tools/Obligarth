import { RAW_PROFILE_TYPE, type AppleItem, type JsonValue } from '@obligarth/shared';
import { verifySignedData, type CmsSignatureCheck } from '../../apple/commands/cmsVerify';
import { DerError, signedDataContent } from '../../apple/commands/der';
import { PlistData, PlistDate, PlistError, PlistReal, parsePlist, type PlistValue } from '../../apple/commands/plist';
import { PEM_PRIVATE_KEY_RE, SECRET_KEY_RE } from '../../apple/commands/sensitive';
import { RAW_PROFILE_MAX_DEPTH } from '../policies/validate';
import { FORBIDDEN_PAYLOAD_TYPES } from './render';

export { RAW_PROFILE_MAX_DEPTH };

// =============================================================================
// Reading of an imported configuration profile (docs: modele-donnees-mdm §7.2,
// CFG-06, S6): a .mobileconfig becomes the values of a raw.profile item.
//   - 1 MiB at most; a CMS signature, when there is one, is verified, then
//     removed (the content it carries is read; the profile is delivered by
//     the MDM channel, re-rendered, never signed by its author's key): a
//     signature that does not verify refuses the profile (invalid_signature),
//     one of an algorithm not verified here (RSA-PSS…) is reported as such and
//     never shown as a signature (S6; MDM-B5c-R8, decision of the owners of
//     15/10/2026; apple/commands/cmsVerify.ts);
//   - an XML property list read by the strict reader of the brain (the plist
//     subset only, no internal DTD, no entity besides the five predefined
//     ones and character references); a binary property list is refused;
//   - a configuration profile in clear (an encrypted one cannot be inspected:
//     refused), 1 to 50 payloads, 24 levels at most;
//   - payloads refused: a second MDM enrollment (com.apple.mdm), an identity
//     request (SCEP, ACME), a removal password;
//   - typed JSON: {"$data": "<base64>"}, {"$date": "<RFC 3339>"}, {"$real": n}
//     for a real of integer value, {"$int": "<decimal>"} beyond 2^53;
//   - every value that looks like a secret is listed for the caller, which
//     moves it to the tenant's vault before anything is stored: the keys the
//     overlay names for the payload type, any key that ends like a secret
//     (the rule of the command scanner), the content of a PKCS #12 payload,
//     a PEM private key. Nothing guarantees this inventory is complete for a
//     payload the overlay does not know: a raw profile always travels
//     encrypted for the device (section 7.9).
// Pure: the unit tests load it.
// =============================================================================

export type RawProfileErrorCode = 'too_large' | 'binary_plist' | 'unreadable_signature' | 'invalid_signature' | 'invalid_plist' | 'not_a_profile'
  | 'encrypted_profile' | 'no_payload' | 'too_many_payloads' | 'forbidden_payload' | 'too_deep' | 'invalid_value';

export class RawProfileError extends Error {
  readonly code: RawProfileErrorCode;
  /** A payload type or a key name: never a value. */
  readonly detail: string | null;
  constructor(code: RawProfileErrorCode, detail: string | null = null) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'RawProfileError';
    this.code = code;
    this.detail = detail;
  }
}

export const RAW_PROFILE_MAX_BYTES = 1024 * 1024;
export const RAW_PROFILE_MAX_PAYLOADS = 50;

const LEADING = new Set([0xef, 0xbb, 0xbf, 0x20, 0x09, 0x0d, 0x0a]);
/** What no jsonb column holds: U+0000, a lone surrogate (a character reference may write either). A profile that
 *  carries one in a key or a value is refused at its import, never left to fail at the insertion. */
const UNSTORABLE_RE = /\u0000|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const UNSTORABLE_ALL_RE = new RegExp(UNSTORABLE_RE.source, 'g');

/** A plist value as typed JSON. */
export function plistToTypedJson(v: PlistValue, depth = 0): JsonValue {
  if (depth > RAW_PROFILE_MAX_DEPTH) throw new RawProfileError('too_deep');
  if (typeof v === 'string') {
    if (UNSTORABLE_RE.test(v)) throw new RawProfileError('invalid_value');
    return v;
  }
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v;
  if (typeof v === 'bigint') return { $int: v.toString(10) };
  if (v instanceof PlistReal) return Number.isInteger(v.value) ? { $real: v.value } : v.value;
  if (v instanceof PlistDate) return { $date: `${v.value.toISOString().slice(0, 19)}Z` };
  if (v instanceof PlistData) return { $data: v.value.toString('base64') };
  if (Array.isArray(v)) return v.map((e) => plistToTypedJson(e, depth + 1));
  const out: Record<string, JsonValue> = {};
  for (const [k, e] of Object.entries(v)) {
    // A key that would read as a marker of the stored form ($secret, $data…) or as a template is refused.
    if (k.startsWith('$') || k.includes('{{')) throw new RawProfileError('invalid_value', k.slice(0, 64));
    // '__proto__' would set the prototype of the object instead of a key, and be dropped without a word.
    if (k === '__proto__' || UNSTORABLE_RE.test(k)) throw new RawProfileError('invalid_value');
    out[k] = plistToTypedJson(e, depth + 1);
  }
  return out;
}

export interface RawProfile {
  displayName: string;
  originalIdentifier: string;
  payloads: Array<Record<string, JsonValue>>;
  /** The file carried a signature that verifies (signature.status 'valid'). */
  signed: boolean;
  /** The check of the signature the file carried; null when it was not signed. */
  signature: CmsSignatureCheck | null;
}

/** Reads the bytes of an imported .mobileconfig. Throws RawProfileError. */
export function readRawProfile(bytes: Buffer): RawProfile {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) throw new RawProfileError('invalid_plist');
  if (bytes.length > RAW_PROFILE_MAX_BYTES) throw new RawProfileError('too_large');
  let content = bytes;
  let signature: CmsSignatureCheck | null = null;
  if (bytes[0] === 0x30) {
    try {
      const inner = signedDataContent(bytes);
      if (inner === null) throw new RawProfileError('invalid_plist');
      signature = verifySignedData(bytes, inner);
      content = inner;
    } catch (err) {
      if (err instanceof DerError) throw new RawProfileError('unreadable_signature');
      throw err;
    }
    if (signature.status === 'invalid') throw new RawProfileError('invalid_signature');
  }
  let start = 0;
  while (start < content.length && LEADING.has(content[start])) start++;
  if (content.subarray(start, start + 6).toString('latin1') === 'bplist') throw new RawProfileError('binary_plist');
  let root: PlistValue;
  try {
    root = parsePlist(content.subarray(start).toString('utf8'));
  } catch (err) {
    if (err instanceof PlistError) throw new RawProfileError('invalid_plist');
    throw err;
  }
  const isDict = (v: unknown): v is Record<string, PlistValue> => !!v && typeof v === 'object' && !Array.isArray(v)
    && !(v instanceof PlistData) && !(v instanceof PlistDate) && !(v instanceof PlistReal);
  if (!isDict(root) || typeof root.PayloadType !== 'string' || root.PayloadType.toLowerCase() !== 'configuration') throw new RawProfileError('not_a_profile');
  if (root.EncryptedPayloadContent !== undefined) throw new RawProfileError('encrypted_profile');
  const list = root.PayloadContent;
  if (!Array.isArray(list) || list.length === 0) throw new RawProfileError('no_payload');
  if (list.length > RAW_PROFILE_MAX_PAYLOADS) throw new RawProfileError('too_many_payloads');
  const payloads = list.map((p) => {
    if (!isDict(p) || typeof p.PayloadType !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(p.PayloadType)) throw new RawProfileError('not_a_profile');
    if (FORBIDDEN_PAYLOAD_TYPES.has(p.PayloadType.toLowerCase())) throw new RawProfileError('forbidden_payload', p.PayloadType);
    return plistToTypedJson(p, 1) as Record<string, JsonValue>;
  });
  // The names are labels: control characters and what jsonb does not hold are blanked, never refused.
  const text = (v: unknown, max: number): string => (typeof v === 'string'
    ? v.slice(0, 4 * max).replace(UNSTORABLE_ALL_RE, ' ').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max).replace(UNSTORABLE_ALL_RE, '') : '');
  return {
    displayName: text(root.PayloadDisplayName, 200) || 'Imported profile',
    originalIdentifier: text(root.PayloadIdentifier, 255),
    payloads,
    signed: signature?.status === 'valid',
    signature,
  };
}

/** A value of a raw profile to move to the vault: where it is (key names and indexes), its typed value. */
export interface RawSecretSite { path: Array<string | number>; value: JsonValue }

const nonEmpty = (v: JsonValue): boolean => (typeof v === 'string' ? v !== ''
  : !!v && typeof v === 'object' && !Array.isArray(v) && typeof (v as { $data?: unknown }).$data === 'string' && (v as { $data: string }).$data !== '');

/** The import's own rule, beyond the command scanner's (MDM-B5c-R9; decision of the owners of 15/10/2026): whatever
 *  their case, a key that names a password, a secret, a token, an API key, a credential or an authorization header
 *  goes to the vault. For the import only: a value moved there is still delivered, encrypted for each device. */
export const IMPORT_SECRET_KEY_RE = /pass(word|wd|phrase)|secret|token|api[-_]?key|credential|authori[sz]ation/i;

/**
 * The secrets of the payloads of a raw profile. `secretKeyOf(payloadType, dottedPath)`: true when the overlay names
 * the key as a secret of this payload type (the path of its dictionary keys, array indexes left out).
 */
export function rawSecretSites(payloads: Array<Record<string, JsonValue>>, secretKeyOf: (type: string, path: string) => boolean): RawSecretSite[] {
  const sites: RawSecretSite[] = [];
  const walk = (type: string, v: JsonValue, path: Array<string | number>, names: string[], depth: number): void => {
    if (depth > RAW_PROFILE_MAX_DEPTH + 2 || v === null || typeof v !== 'object') return;
    if (Array.isArray(v)) {
      v.forEach((e, i) => walk(type, e, [...path, i], names, depth + 1));
      return;
    }
    for (const [k, e] of Object.entries(v)) {
      if (k.startsWith('$')) continue;                  // a typed value: no key of its own
      const here = [...names, k];
      const candidate = typeof e === 'string' || (!!e && typeof e === 'object' && !Array.isArray(e) && typeof (e as { $data?: unknown }).$data === 'string');
      const pkcs12 = names.length === 0 && k === 'PayloadContent' && type.toLowerCase() === 'com.apple.security.pkcs12';
      const pem = typeof e === 'string' && PEM_PRIVATE_KEY_RE.test(e);
      const pemData = !pem && candidate && typeof e !== 'string'
        && PEM_PRIVATE_KEY_RE.test(Buffer.from((e as { $data: string }).$data, 'base64').toString('latin1'));
      if (candidate && nonEmpty(e) && (pkcs12 || pem || pemData || SECRET_KEY_RE.test(k) || IMPORT_SECRET_KEY_RE.test(k) || secretKeyOf(type, here.join('.')))) {
        sites.push({ path: [...path, k], value: e });
        continue;
      }
      walk(type, e, [...path, k], here, depth + 1);
    }
  };
  payloads.forEach((p, i) => walk(typeof p.PayloadType === 'string' ? p.PayloadType : '', p, [i], [], 1));
  return sites;
}

/** Key names that look like a secret to a reader, whatever their case, beyond the words of Apple that
 *  rawSecretSites moves to the vault (MDM-B5c-R9): an API token, a lower-case password, an authorization header. */
const SUSPECT_KEY_RE = /pass(word|wd|phrase)|pwd|secret|token|api[-_]?key|credential|authori[sz]ation|bearer|private[-_]?key|psk|pin(code)?$/i;
/** Suspect keys reported at most (names only). */
const SUSPECT_KEYS_MAX = 50;

/**
 * The keys of an imported profile that look like secrets and stay in clear in the policy because no rule moves
 * them to the vault (MDM-B5c-R9): their dotted names (payload indexes left out), never a value, for the editor to
 * check before publishing. A non-empty string or data only; the sites already moved are not reported.
 */
export function rawSuspectKeys(payloads: Array<Record<string, JsonValue>>, sites: RawSecretSite[]): string[] {
  const moved = new Set(sites.map((s) => JSON.stringify(s.path)));
  const out = new Set<string>();
  const walk = (v: JsonValue, path: Array<string | number>, names: string[], depth: number): void => {
    if (out.size >= SUSPECT_KEYS_MAX || depth > RAW_PROFILE_MAX_DEPTH + 2 || v === null || typeof v !== 'object') return;
    if (Array.isArray(v)) {
      v.forEach((e, i) => walk(e, [...path, i], names, depth + 1));
      return;
    }
    for (const [k, e] of Object.entries(v)) {
      // The bound holds inside one dictionary too (a payload of 60 suspect keys answered 60 names).
      if (out.size >= SUSPECT_KEYS_MAX) return;
      if (k.startsWith('$')) continue;
      const here = [...names, k];
      const leaf = typeof e === 'string' || (!!e && typeof e === 'object' && !Array.isArray(e) && typeof (e as { $data?: unknown }).$data === 'string');
      if (leaf) {
        if (nonEmpty(e) && SUSPECT_KEY_RE.test(k) && !moved.has(JSON.stringify([...path, k]))) out.add(here.join('.'));
        continue;
      }
      walk(e, [...path, k], here, depth + 1);
    }
  };
  payloads.forEach((p, i) => walk(p, [i], [], 1));
  return [...out].sort();
}

/** The payloads with each secret site replaced by a reference (ids in the order of the sites). A copy. */
export function withRawSecretRefs(payloads: Array<Record<string, JsonValue>>, sites: RawSecretSite[], ids: string[]): Array<Record<string, JsonValue>> {
  const copy = JSON.parse(JSON.stringify(payloads)) as Array<Record<string, JsonValue>>;
  sites.forEach((s, n) => {
    let node: unknown = copy;
    for (let i = 0; i < s.path.length - 1; i++) node = (node as Record<string | number, unknown>)[s.path[i]];
    (node as Record<string | number, unknown>)[s.path[s.path.length - 1]] = { $secret: ids[n] };
  });
  return copy;
}

/** What a reader sees of a raw profile (review of lot B5b, MDM-B5b-C9): its name, its identifier and the types of
 *  its payloads; never their content, whose inventory of secrets nothing guarantees complete. */
export function redactRawProfileValues(values: Record<string, JsonValue> | undefined): Record<string, JsonValue> {
  const payloads = Array.isArray(values?.payloads) ? values.payloads : [];
  return {
    displayName: typeof values?.displayName === 'string' ? values.displayName : '',
    originalIdentifier: typeof values?.originalIdentifier === 'string' ? values.originalIdentifier : '',
    payloads: payloads.map((p) => ({
      PayloadType: p && typeof p === 'object' && !Array.isArray(p) && typeof (p as Record<string, JsonValue>).PayloadType === 'string'
        ? (p as Record<string, JsonValue>).PayloadType : '',
    })),
  };
}

/** An item as a reader sees it: a raw profile reduced to redactRawProfileValues, any other item as it is. */
export function redactRawProfileItem<T extends Pick<AppleItem, 'type' | 'values'>>(item: T): T {
  return item.type === RAW_PROFILE_TYPE && item.values ? { ...item, values: redactRawProfileValues(item.values) } : item;
}
