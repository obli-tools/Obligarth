import { X509Certificate, constants, createCipheriv, publicEncrypt, randomBytes } from 'node:crypto';
import { DerError, envelopedData, issuerAndSerialOf, signedDataContent } from './der';
import { PlistData, PlistError, looksLikeXmlPlist, parsePlist, serializePlist, type PlistDict, type PlistValue } from './plist';

// =============================================================================
// Sensitive payloads of the MDM commands (docs: integration-apple-edge §8.8,
// EX-09; apple-edge §5.4, RC2): no secret in clear in a plist handed to
// apple-edge, where it would stay in nanomdm.commands until the device
// acknowledges it, and in the backups meanwhile.
//   1. Detection, before a command is written: the closed rules apple-edge
//      applies again at its door (internal/queue/sensitive.go), so that a
//      regression here is refused there (422 secret_in_command) instead of
//      being stored:
//        - a non-empty string or data whose key ends with a known secret
//          word (Password, Passphrase, Secret, Challenge, PIN, PrivateKey,
//          UnlockToken, BootstrapToken…), anywhere in the Command dictionary
//          or in a configuration profile it carries; no boundary on the left
//          (CalDAVPassword: review of lot B0, AE-B0-R2). Booleans and numbers
//          are never secrets (PasswordRequired, forcePIN, MinPINLength);
//        - the PayloadContent of a PKCS#12 payload;
//        - a string or data holding a PEM private key;
//        - a data that is a profile the brain cannot examine (binary property
//          list, unreadable signed profile): refused, never passed unread;
//        - the prefix of the secret placeholders anywhere else than the
//          UnlockToken of a ClearPasscode.
//      EncryptedPayloadContent is opaque (encrypted for the device).
//   2. The UnlockToken placeholder of ClearPasscode: apple-edge substitutes
//      the secret at delivery (queue.go, unlockKeyRe).
//   3. EncryptedPayloadContent (I9): the PayloadContent of a profile that
//      carries a secret, encrypted for the identity certificate of the
//      device (CMS EnvelopedData, AES-256-CBC, RSA PKCS#1 v1.5 key transport
//      to the certificate's issuer and serial number; algorithms to confirm
//      on a real device, annex D J-1). The profiles come from sources the
//      sister specifications register (policies, Wi-Fi…).
// Pure but for the registry of the sources: the unit tests load it.
// =============================================================================

/** The keys that hold a secret in Apple's payloads and commands, as the end of any key: the same expression
 *  as apple-edge's secretKeyRe. */
export const SECRET_KEY_RE = /(Password|Passphrase|Secret|SharedSecret|Challenge|PIN|PrivateKey|AuthPassword|IncomingPassword|OutgoingPassword|UnlockToken|BootstrapToken)$/;
export const PEM_PRIVATE_KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
/** The prefix of the placeholders apple-edge replaces at delivery. */
export const PLACEHOLDER_PREFIX = 'obligarth-secret:';
/** The one placeholder of the MVP: the UnlockToken of a single-target ClearPasscode. */
export const UNLOCK_PLACEHOLDER = `${PLACEHOLDER_PREFIX}unlock_token`;

export type SecretRule = 'key' | 'pkcs12' | 'pem' | 'unreadable_profile' | 'placeholder';

export interface SecretFinding {
  /** Where: key names only, never a value. */
  path: string;
  rule: SecretRule;
}

/** A profile inside a profile inside a command, as apple-edge. */
const MAX_PROFILE_NESTING = 2;
/** What apple-edge trims before it looks for a property list: the bytes of a UTF-8 BOM, space, tab, CR, LF. */
const LEADING_BYTES: ReadonlySet<number> = new Set([0xef, 0xbb, 0xbf, 0x20, 0x09, 0x0d, 0x0a]);
const MAX_DEPTH = 64;
const MAX_FINDINGS = 20;

interface Scan { requestType: string; findings: SecretFinding[] }

const isDict = (v: unknown): v is PlistDict => v !== null && typeof v === 'object' && !Array.isArray(v)
  && !(v instanceof PlistData) && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);

function nonEmpty(v: PlistValue): boolean {
  if (typeof v === 'string') return v !== '';
  if (v instanceof PlistData) return v.value.length > 0;
  return false;
}

function add(s: Scan, path: string, rule: SecretRule): void {
  if (s.findings.length < MAX_FINDINGS) s.findings.push({ path: path.slice(0, 200), rule });
}

/**
 * The configuration profile a data value holds, if any. undefined: not a profile (a certificate, an image, any
 * other property list). 'unreadable': it looks like a property list, or a signed one, the brain cannot examine.
 */
function profileOf(bytes: Buffer): PlistDict | 'unreadable' | undefined {
  let content = bytes;
  if (bytes.length > 0 && bytes[0] === 0x30) {
    try {
      const signed = signedDataContent(bytes);
      if (signed === null) return undefined;             // some other DER: not a signed property list
      content = signed;
    } catch (err) {
      if (err instanceof DerError) return 'unreadable';
      throw err;
    }
  }
  // Like apple-edge (sensitive.go, profileOf), the bytes of a BOM and white space before the property list are
  // skipped first: what it would examine is never passed unread here (review of lot B4).
  let start = 0;
  while (start < content.length && LEADING_BYTES.has(content[start])) start++;
  // A binary property list: apple-edge reads it, the brain does not (it never writes one): refused unread.
  if (content.subarray(start, start + 8).toString('latin1') === 'bplist00') return 'unreadable';
  const text = content.subarray(start).toString('utf8');
  if (!looksLikeXmlPlist(text)) return undefined;
  let root: PlistValue;
  try {
    root = parsePlist(text);
  } catch (err) {
    if (err instanceof PlistError) return 'unreadable';
    throw err;
  }
  if (!isDict(root)) return undefined;
  const type = root.PayloadType;
  return typeof type === 'string' && type.toLowerCase() === 'configuration' ? root : undefined;
}

function walk(s: Scan, v: PlistValue, path: string, key: string | null, depth: number, nesting: number): void {
  if (depth > MAX_DEPTH) { add(s, path, 'unreadable_profile'); return; }
  if (typeof v === 'string') {
    if (PEM_PRIVATE_KEY_RE.test(v)) add(s, `${path} (PEM private key)`, 'pem');
    if (v.includes(PLACEHOLDER_PREFIX)) {
      const allowed = s.requestType === 'ClearPasscode' && path === 'Command.UnlockToken' && nesting === 0 && v === UNLOCK_PLACEHOLDER;
      if (!allowed) add(s, path, 'placeholder');
    }
    return;
  }
  if (v instanceof PlistData) {
    if (PEM_PRIVATE_KEY_RE.test(v.value.toString('latin1'))) add(s, `${path} (PEM private key)`, 'pem');
    if (nesting >= MAX_PROFILE_NESTING) return;
    const p = profileOf(v.value);
    if (p === 'unreadable') add(s, `${path} (profile)`, 'unreadable_profile');
    else if (p) walk(s, p, `${path}>profile`, null, 0, nesting + 1);
    return;
  }
  if (Array.isArray(v)) {
    v.forEach((e, i) => walk(s, e, `${path}[${i}]`, key, depth + 1, nesting));
    return;
  }
  if (isDict(v)) {
    if (v.PayloadType === 'com.apple.security.pkcs12' && v.PayloadContent !== undefined && nonEmpty(v.PayloadContent)) {
      add(s, `${path}.PayloadContent (PKCS#12)`, 'pkcs12');
    }
    for (const k of Object.keys(v).sort()) {
      const val = v[k];
      if (k.includes(PLACEHOLDER_PREFIX)) add(s, path, 'placeholder');
      if (k === 'EncryptedPayloadContent') continue;       // opaque: encrypted for the device
      const placeholder = k === 'UnlockToken' && val === UNLOCK_PLACEHOLDER;
      if (SECRET_KEY_RE.test(k) && nonEmpty(val) && !placeholder) add(s, `${path}.${k}`, 'key');
      walk(s, val, `${path}.${k}`, k, depth + 1, nesting);
    }
  }
}

/**
 * The secrets a Command dictionary would carry in clear (§8.8, rule 1); empty: none. `command` is the Command
 * dictionary without its RequestType. The UnlockToken placeholder is allowed once, for ClearPasscode.
 */
export function findSecrets(requestType: string, command: PlistDict): SecretFinding[] {
  const s: Scan = { requestType, findings: [] };
  walk(s, command, 'Command', null, 0, 0);
  if (requestType === 'ClearPasscode') {
    const others = Object.keys(command).filter((k) => k !== 'UnlockToken');
    if (command.UnlockToken !== UNLOCK_PLACEHOLDER || others.length > 0) add(s, 'Command.UnlockToken', 'placeholder');
  }
  return s.findings;
}

/** Does the PayloadContent of a profile carry a secret (which then travels encrypted for the device)? */
export function profileCarriesSecret(profile: PlistDict): boolean {
  const s: Scan = { requestType: 'InstallProfile', findings: [] };
  walk(s, profile, 'Profile', null, 0, 1);
  return s.findings.length > 0;
}

// ── EncryptedPayloadContent (I9) ───────────────────────────────────────────────

export class IdentityCertificateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdentityCertificateError';
  }
}

/** CMS EnvelopedData (DER) of the XML plist of payloadContent, for the device's identity certificate. */
export function encryptForDevice(identityCertPem: string, payloadContent: PlistValue[]): Buffer {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(identityCertPem);
  } catch {
    throw new IdentityCertificateError('the identity certificate of the device cannot be read');
  }
  const key = cert.publicKey;
  if (key.asymmetricKeyType !== 'rsa') throw new IdentityCertificateError('the identity certificate of the device is not an RSA one');
  let who: { issuer: Buffer; serial: Buffer };
  try {
    who = issuerAndSerialOf(cert.raw);
  } catch {
    throw new IdentityCertificateError('the identity certificate of the device cannot be read');
  }
  const plain = Buffer.from(serializePlist(payloadContent), 'utf8');
  const cek = randomBytes(32);
  const iv = randomBytes(16);
  try {
    const cipher = createCipheriv('aes-256-cbc', cek, iv);
    const encryptedContent = Buffer.concat([cipher.update(plain), cipher.final()]);
    const encryptedKey = publicEncrypt({ key, padding: constants.RSA_PKCS1_PADDING }, cek);
    return envelopedData({ issuer: who.issuer, serial: who.serial, encryptedKey, iv, encryptedContent });
  } finally {
    cek.fill(0);
    plain.fill(0);
  }
}

// ── Profile sources ────────────────────────────────────────────────────────────

/** What a profile source needs to know of the device (the catalogue's CommandDeviceContext carries it). */
export interface ProfileDevice {
  deviceId: number;
  enrollmentId: string;
  ownership: string | null;
  supervised: boolean | null;
  platform: string | null;
  osVersion: string | null;
  identityCertPem: string | null;
}

export interface ResolvedProfile {
  /** The configuration profile dictionary (PayloadType 'Configuration'), PayloadContent included. */
  profile: PlistDict;
  /** True when PayloadContent carries a secret; the scanner is also run (both must agree to send in clear). */
  containsSecrets: boolean;
}

export interface ProfileSource<Trx = unknown> {
  /** 'policy' (CFG-01), 'wifi' (RES-01)… */
  kind: string;
  /** In the caller's transaction (the tenant's context): reads only, no network. The clear secrets are read
   *  here, at the construction of the command, and written nowhere. */
  resolve(trx: Trx, tenantId: number, ref: string, device: ProfileDevice): Promise<ResolvedProfile>;
}

const sources = new Map<string, ProfileSource<any>>();

/** A source of profiles for InstallProfile; registered before anything starts, a kind once. */
export function registerProfileSource<Trx>(source: ProfileSource<Trx>): void {
  const kind = String(source?.kind ?? '');
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(kind)) throw new Error('profile source: invalid kind');
  if (sources.has(kind)) throw new Error(`profile source ${kind}: registered twice`);
  if (typeof source.resolve !== 'function') throw new Error(`profile source ${kind}: resolve is required`);
  sources.set(kind, source);
}

export function profileSource(kind: string): ProfileSource<any> | undefined {
  return sources.get(kind);
}

export type InstallPayload =
  | { ok: true; payload: PlistData; encrypted: boolean; identifier: string | null }
  | { ok: false; code: 'identity_unavailable' };

/**
 * The Payload of an InstallProfile from a resolved profile: in clear when it carries no secret, else with its
 * PayloadContent encrypted for the device (the profile is not signed by the brain: its encrypted content is
 * readable by the device alone). Without the identity certificate of the device, the target is refused
 * (identity_unavailable) and the source tries again later.
 */
export function installPayload(resolved: ResolvedProfile, device: { identityCertPem: string | null }): InstallPayload {
  const profile = resolved.profile;
  if (!isDict(profile) || profile.PayloadType !== 'Configuration' || !Array.isArray(profile.PayloadContent)) {
    throw new PlistError('invalid_value', 'a profile source must hand a configuration profile with its PayloadContent');
  }
  const identifier = typeof profile.PayloadIdentifier === 'string' ? profile.PayloadIdentifier : null;
  const secret = resolved.containsSecrets === true || profileCarriesSecret({ PayloadContent: profile.PayloadContent });
  if (!secret) return { ok: true, payload: new PlistData(Buffer.from(serializePlist(profile), 'utf8')), encrypted: false, identifier };
  if (!device.identityCertPem) return { ok: false, code: 'identity_unavailable' };
  let encrypted: Buffer;
  try {
    encrypted = encryptForDevice(device.identityCertPem, profile.PayloadContent);
  } catch (err) {
    if (err instanceof IdentityCertificateError) return { ok: false, code: 'identity_unavailable' };
    throw err;
  }
  const { PayloadContent: _clear, ...rest } = profile;
  const sealed: PlistDict = { ...rest, EncryptedPayloadContent: new PlistData(encrypted) };
  return { ok: true, payload: new PlistData(Buffer.from(serializePlist(sealed), 'utf8')), encrypted: true, identifier };
}
