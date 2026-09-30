import crypto, { X509Certificate } from 'node:crypto';
import {
  DerError, CLASS_CONTEXT, TAG_INTEGER,
  parseDer, asSequence, asSet, asInt, asBigInt, asEnumerated, asBooleanBer, asNull, asOctetString,
  explicitInner, isUniversal, parseCertificateTbs, derTimeMs, serialHex,
  type Tlv, type CertTbs,
} from './der';

// ── Android key attestation verification (device-bound 2FA, §4.3) ─────────
//
// docs/mobile/device-bound-2fa.md §4.3 steps 1..11, frozen contract §13.1
// item 7 (key parameters and attestation requirements). Enrolment only.
//
// Pure: every input (pins, allowed app ids/signers, revocation list, time)
// comes from the caller, so node --test can inject a synthetic root. The
// production caller (deviceKey.service.ts) passes the real Google pins
// (attestationRoots.ts) and the cached Google status list
// (attestationStatus.ts).
//
// Schema (source.android.com "Key and ID attestation", KeyDescription):
//   KeyDescription ::= SEQUENCE {
//     attestationVersion INTEGER, attestationSecurityLevel SecurityLevel,
//     keyMintVersion INTEGER, keyMintSecurityLevel SecurityLevel,
//     attestationChallenge OCTET STRING, uniqueId OCTET STRING,
//     softwareEnforced AuthorizationList, hardwareEnforced AuthorizationList }
//   SecurityLevel ::= ENUMERATED { Software(0), TrustedEnvironment(1), StrongBox(2) }
//   AuthorizationList ::= SEQUENCE { [n] EXPLICIT ... OPTIONAL, ... }
//   RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked
//     BOOLEAN, verifiedBootState ENUMERATED { Verified(0), SelfSigned(1),
//     Unverified(2), Failed(3) }, verifiedBootHash OCTET STRING (v3+) }
//   AttestationApplicationId ::= SEQUENCE { package_infos SET OF
//     SEQUENCE { package_name OCTET STRING, version INTEGER },
//     signature_digests SET OF OCTET STRING }
//
// Erasable TypeScript only (node --test).

export const KEY_DESCRIPTION_OID = '1.3.6.1.4.1.11129.2.1.17';
/** RKP "provisioning info" extension, carried by the remotely provisioned
 *  attestation-key certificate (chain index 1). Used for the [D5] signal. */
export const PROVISIONING_INFO_OID = '1.3.6.1.4.1.11129.2.1.30';

/** KeyMint tag numbers (Tag.aidl, low 28 bits). */
export const KM_TAG = Object.freeze({
  PURPOSE: 1,
  ALGORITHM: 2,
  KEY_SIZE: 3,
  DIGEST: 5,
  EC_CURVE: 10,
  ROLLBACK_RESISTANCE: 303,
  NO_AUTH_REQUIRED: 503,
  USER_AUTH_TYPE: 504,
  AUTH_TIMEOUT: 505,
  UNLOCKED_DEVICE_REQUIRED: 509,
  ALL_APPLICATIONS: 600,
  ORIGIN: 702,
  ROOT_OF_TRUST: 704,
  OS_VERSION: 705,
  OS_PATCH_LEVEL: 706,
  ATTESTATION_APPLICATION_ID: 709,
  VENDOR_PATCH_LEVEL: 718,
  BOOT_PATCH_LEVEL: 719,
});

export const KM_PURPOSE_SIGN = 2;
export const KM_PURPOSE_ATTEST_KEY = 7;
export const KM_ALGORITHM_EC = 3;
export const KM_EC_CURVE_P256 = 1;
export const KM_ORIGIN_GENERATED = 0;
/** HardwareAuthenticatorType bits. */
export const HW_AUTH_PASSWORD = 1;
export const HW_AUTH_BIOMETRIC = 2;
export const SECURITY_LEVEL_SOFTWARE = 0;
export const SECURITY_LEVEL_TEE = 1;
export const SECURITY_LEVEL_STRONGBOX = 2;
export const BOOT_STATE_NAMES = ['verified', 'self_signed', 'unverified', 'failed'] as const;

/** Chain bounds (§4.3 step 1) and per-certificate size cap. */
export const CHAIN_MIN = 2;
export const CHAIN_MAX = 10;
export const CERT_MAX_B64 = 16384;
/** Clock tolerance on non-leaf validity (§4.3 step 2). */
export const VALIDITY_SKEW_MS = 5 * 60 * 1000;

export type AttestationFailureReason =
  | 'chain_shape'            // step 1: 2..10 base64 DER certificates
  | 'chain_signature'        // step 2: issuer / signature link broken
  | 'chain_validity'         // step 2: a non-leaf certificate outside its validity
  | 'root_unknown'           // step 3: not self-signed or key not pinned
  | 'status_unavailable'     // step 4: no revocation list younger than 7 days [D4]
  | 'revoked'                // step 4: a serial is REVOKED / SUSPENDED
  | 'key_mismatch'           // step 5: leaf SPKI != publicKey
  | 'extension_missing'      // step 6: no KeyDescription in the leaf
  | 'extension_misplaced'    // step 6: KeyDescription in a non-leaf certificate
  | 'malformed'              // step 7: KeyDescription / tag unreadable
  | 'security_level'         // step 7: software, or attestation != KeyMint level
  | 'challenge'              // step 7: attestationChallenge != ticket nonce
  | 'purpose'                // step 8
  | 'algorithm'              // step 8: EC / P-256 / 256
  | 'origin'                 // step 8: not GENERATED
  | 'no_auth_required'       // step 8
  | 'all_applications'       // step 8
  | 'user_auth'              // step 8: biometric bit 1, password bit 0
  | 'auth_timeout'           // step 8: authentication per use only
  | 'root_of_trust'          // step 9: missing / unreadable
  | 'bootloader_unlocked'    // step 9: deviceLocked false [D3]
  | 'boot_state'             // step 9: verifiedBootState != Verified [D3]
  | 'app_id'                 // step 10: package missing / not allowed
  | 'app_signer'             // step 10: signing certificate digest not allowed [D19]
  | 'rkp_required';          // step 11: RKP chain required and absent [D5]

export interface RevocationView {
  /** serial (lowercase hex, no leading zeros) → 'REVOKED' | 'SUSPENDED'. */
  entries: ReadonlyMap<string, string>;
  /** When the list was fetched from Google (epoch ms). */
  fetchedAt: number;
}

export interface AttestationPolicy {
  /** hex sha256 of the accepted root SPKI DER (production: PINNED_ROOT_SPKI_SHA256). */
  pinnedRootSpkiSha256: ReadonlyArray<string>;
  /** Accepted package names (DEVICE_KEY_APP_IDS). */
  appPackages: ReadonlyArray<string>;
  /** Accepted signing-certificate digests, lowercase hex sha256 (DEVICE_KEY_APP_SIGNERS). */
  appSigners: ReadonlyArray<string>;
  /** Release signer digests: anything else accepted is flagged debugSigner. */
  releaseSigners?: ReadonlyArray<string>;
  /** Google status list, or null when none younger than 7 days is available. */
  revocation: RevocationView | null;
  /** Evaluation time (epoch ms), default Date.now(). */
  now?: number;
  /** [D5] refuse non-RKP chains on Android 13+ (default false: logged only). */
  requireRkp?: boolean;
}

export interface AttestationSummary {
  attestationVersion: number;
  keyMintVersion: number;
  securityLevel: 'strongbox' | 'tee';
  osVersion: number | null;
  osPatchLevel: number | null;
  vendorPatchLevel: number | null;
  bootPatchLevel: number | null;
  bootState: string | null;
  deviceLocked: boolean | null;
  /** deviceLocked was a non-canonical BER BOOLEAN (tolerated, recorded). */
  deviceLockedNonDer?: boolean;
  appPackage: string | null;
  appVersion: string | null;
  appSigners: string[];
  debugSigner: boolean;
  rkp: boolean;
  rollbackResistance: boolean;
  unlockedDeviceRequired: boolean;
  revocationCheckedAt: string | null;
  serials: string[];
}

export type AttestationOutcome =
  | { ok: true; level: 'strongbox' | 'tee'; summary: AttestationSummary }
  | { ok: false; reason: AttestationFailureReason; detail?: string; summary: Partial<AttestationSummary> };

// ── Parsing ─────────────────────────────────────────────────────────────────

export interface RootOfTrust {
  verifiedBootKey: Buffer;
  deviceLocked: boolean;
  /** False when deviceLocked was a non-canonical (BER) BOOLEAN. */
  deviceLockedDer: boolean;
  verifiedBootState: number;
  verifiedBootHash: Buffer | null;
}

export interface AttestationApplicationId {
  packages: Array<{ name: string; version: bigint }>;
  signatureDigests: Buffer[];
}

export interface AuthorizationList {
  /** Every tag present, inner element of the [n] EXPLICIT wrapper. */
  tags: Map<number, Tlv>;
}

export interface KeyDescription {
  attestationVersion: number;
  attestationSecurityLevel: number;
  keyMintVersion: number;
  keyMintSecurityLevel: number;
  attestationChallenge: Buffer;
  uniqueId: Buffer;
  softwareEnforced: AuthorizationList;
  hardwareEnforced: AuthorizationList;
}

/** AuthorizationList: tags in ANY order (tolerated), each at most once. */
export function parseAuthorizationList(t: Tlv): AuthorizationList {
  const tags = new Map<number, Tlv>();
  for (const item of asSequence(t)) {
    if (item.cls !== CLASS_CONTEXT) throw new DerError('AuthorizationList: context tag expected');
    if (tags.has(item.tag)) throw new DerError(`AuthorizationList: duplicate tag [${item.tag}]`);
    tags.set(item.tag, explicitInner(item));
  }
  return { tags };
}

export function parseKeyDescription(extValue: Buffer): KeyDescription {
  const seq = asSequence(parseDer(extValue));
  if (seq.length < 8) throw new DerError('KeyDescription: 8 elements expected');
  return {
    attestationVersion: asInt(seq[0]),
    attestationSecurityLevel: asEnumerated(seq[1]),
    keyMintVersion: asInt(seq[2]),
    keyMintSecurityLevel: asEnumerated(seq[3]),
    attestationChallenge: asOctetString(seq[4]),
    uniqueId: asOctetString(seq[5]),
    softwareEnforced: parseAuthorizationList(seq[6]),
    hardwareEnforced: parseAuthorizationList(seq[7]),
  };
}

export function parseRootOfTrust(t: Tlv): RootOfTrust {
  const seq = asSequence(t);
  if (seq.length < 3) throw new DerError('RootOfTrust: 3 elements expected');
  // deviceLocked: BER boolean tolerated (see asBooleanBer — real KeyMint
  // output, accepted by Google's verifier). Every other field stays strict.
  const locked = asBooleanBer(seq[1]);
  return {
    verifiedBootKey: asOctetString(seq[0]),
    deviceLocked: locked.value,
    deviceLockedDer: locked.der,
    verifiedBootState: asEnumerated(seq[2]),
    verifiedBootHash: seq[3] ? asOctetString(seq[3]) : null,
  };
}

export function parseAttestationApplicationId(octets: Buffer): AttestationApplicationId {
  const seq = asSequence(parseDer(octets));
  if (seq.length !== 2) throw new DerError('AttestationApplicationId: 2 elements expected');
  const packages = asSet(seq[0]).map((p) => {
    const f = asSequence(p);
    if (f.length !== 2) throw new DerError('AttestationPackageInfo: 2 elements expected');
    return { name: asOctetString(f[0]).toString('utf8'), version: asBigInt(f[1]) };
  });
  const signatureDigests = asSet(seq[1]).map((d) => asOctetString(d));
  return { packages, signatureDigests };
}

function intTag(list: AuthorizationList, tag: number): number | null {
  const t = list.tags.get(tag);
  if (!t) return null;
  // Some tags are declared INTEGER, some ENUMERATED by older schemas.
  return isUniversal(t, TAG_INTEGER) ? asInt(t) : asEnumerated(t);
}

function intSetTag(list: AuthorizationList, tag: number): number[] | null {
  const t = list.tags.get(tag);
  if (!t) return null;
  return asSet(t).map((x) => (isUniversal(x, TAG_INTEGER) ? asInt(x) : asEnumerated(x)));
}

function nullTag(list: AuthorizationList, tag: number): boolean {
  const t = list.tags.get(tag);
  if (!t) return false;
  asNull(t);
  return true;
}

function hasTag(list: AuthorizationList, tag: number): boolean {
  return list.tags.has(tag);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function strictB64(s: unknown): Buffer | null {
  if (typeof s !== 'string' || s.length === 0 || s.length > CERT_MAX_B64) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s) || s.length % 4 !== 0) return null;
  const b = Buffer.from(s, 'base64');
  return b.toString('base64') === s ? b : null;
}

function spkiDer(c: X509Certificate): Buffer {
  return c.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
}

function sha256hex(b: Uint8Array): string {
  return crypto.createHash('sha256').update(b).digest('hex');
}

function normHex(s: string): string {
  return s.replace(/[:\s]/g, '').toLowerCase();
}

function fail(reason: AttestationFailureReason, summary: Partial<AttestationSummary>, detail?: string): AttestationOutcome {
  return detail ? { ok: false, reason, detail, summary } : { ok: false, reason, summary };
}

// ── The verifier ────────────────────────────────────────────────────────────

/**
 * Verifies an Android key attestation chain (leaf first, base64 DER) for
 * `publicKeySpki` (the SPKI DER the app sent) and `nonce` (the enrolment
 * ticket nonce, set by the app with setAttestationChallenge). Steps and
 * order: §4.3. Never throws on bad input: every failure is a reason.
 */
export function verifyAttestation(
  chainB64: unknown,
  publicKeySpki: Buffer,
  nonce: Buffer,
  policy: AttestationPolicy,
): AttestationOutcome {
  const now = policy.now ?? Date.now();
  const summary: Partial<AttestationSummary> = {};

  // 1. Shape: 2..10 certificates, each readable by crypto.X509Certificate,
  //    with nothing trailing the DER.
  if (!Array.isArray(chainB64) || chainB64.length < CHAIN_MIN || chainB64.length > CHAIN_MAX) {
    return fail('chain_shape', summary);
  }
  const certs: X509Certificate[] = [];
  const tbs: CertTbs[] = [];
  for (const item of chainB64) {
    const der = strictB64(item);
    if (!der) return fail('chain_shape', summary, 'base64');
    let c: X509Certificate;
    let t: CertTbs;
    try {
      c = new X509Certificate(der);
      if (!Buffer.from(c.raw).equals(der)) return fail('chain_shape', summary, 'trailing bytes');
      t = parseCertificateTbs(der);
    } catch {
      return fail('chain_shape', summary, 'certificate');
    }
    certs.push(c);
    tbs.push(t);
  }
  summary.serials = tbs.map((t) => serialHex(t.serial, t.serialBytes));
  const n = certs.length;

  // 2. Chain: each certificate issued and signed by the next one. Validity
  //    of every NON-leaf certificate (±5 min); the leaf's is ignored
  //    (Android writes arbitrary dates there).
  //    SPEC DEVIATION (documented): §4.3 writes `checkIssued && verify`.
  //    OpenSSL's X509_check_issued also requires keyCertSign in the
  //    issuer's keyUsage, and factory-provisioned attestation keys (Pixel 2,
  //    Sony Xperia 10 III… see android/keyattestation testdata) are
  //    certified with CA:FALSE / keyUsage=digitalSignature: the literal rule
  //    refuses genuine phones. The link is therefore "issuer name == next
  //    subject name (checkIssued, or the same printed name) AND the
  //    signature verifies with the next key". The trick this would allow —
  //    an attested key signing a forged leaf — is what step 6 blocks (the
  //    KeyDescription extension may appear in the leaf only).
  for (let i = 0; i < n - 1; i++) {
    let linked = false;
    try {
      const sameName = certs[i].checkIssued(certs[i + 1]) || certs[i].issuer === certs[i + 1].subject;
      linked = sameName && certs[i].verify(certs[i + 1].publicKey);
    } catch { linked = false; }
    if (!linked) return fail('chain_signature', summary, `link ${i}`);
  }
  // Validity of the non-leaf certificates, as the spec writes it (fail
  // closed). NOTE for the owner: Google's reference verifier
  // (android/keyattestation KeyAttestationCertPathValidator) IGNORES an
  // expired certificate in a factory-provisioned chain (keys that cannot be
  // rotated) and relies on the status list instead. Phones whose factory
  // keybox chains expired (e.g. the 2016 batch, expired 2026-05-24) are
  // therefore refused here with 'chain_validity'. Relaxing it is a policy
  // decision, not taken in this lot.
  for (let i = 1; i < n; i++) {
    let nb: number;
    let na: number;
    try {
      nb = derTimeMs(tbs[i].notBefore);
      na = derTimeMs(tbs[i].notAfter);
    } catch {
      return fail('chain_validity', summary, `certificate ${i}: time`);
    }
    if (now + VALIDITY_SKEW_MS < nb || now - VALIDITY_SKEW_MS > na) {
      return fail('chain_validity', summary, `certificate ${i}`);
    }
  }

  // 3. Root: self-signed, and its key is pinned.
  const root = certs[n - 1];
  let selfSigned = false;
  try { selfSigned = root.checkIssued(root) && root.verify(root.publicKey); } catch { selfSigned = false; }
  const pins = new Set(policy.pinnedRootSpkiSha256.map(normHex));
  if (!selfSigned || !pins.has(sha256hex(spkiDer(root)))) return fail('root_unknown', summary);

  // 4. Revocation: no serial of the chain REVOKED / SUSPENDED; a list
  //    younger than 7 days must be available [D4] (the caller passes null
  //    otherwise).
  if (!policy.revocation) return fail('status_unavailable', summary);
  summary.revocationCheckedAt = new Date(policy.revocation.fetchedAt).toISOString();
  for (const serial of summary.serials) {
    const st = policy.revocation.entries.get(serial);
    if (st === 'REVOKED' || st === 'SUSPENDED') return fail('revoked', summary, serial);
  }

  // 5. The leaf certifies exactly the key the app sent.
  if (!Buffer.isBuffer(publicKeySpki) || !spkiDer(certs[0]).equals(publicKeySpki)) return fail('key_mismatch', summary);

  // 6. KeyDescription in the leaf, and in no other certificate (an attested
  //    key used as a CA would otherwise pass its own extension down).
  for (let i = 1; i < n; i++) {
    if (tbs[i].extensions.some((e) => e.oid === KEY_DESCRIPTION_OID)) return fail('extension_misplaced', summary, `certificate ${i}`);
  }
  const ext = tbs[0].extensions.find((e) => e.oid === KEY_DESCRIPTION_OID);
  if (!ext) return fail('extension_missing', summary);

  // 7. KeyDescription: equal levels, TEE or StrongBox; challenge = nonce.
  let kd: KeyDescription;
  try { kd = parseKeyDescription(ext.value); } catch (e) {
    return fail('malformed', summary, e instanceof Error ? e.message : undefined);
  }
  summary.attestationVersion = kd.attestationVersion;
  summary.keyMintVersion = kd.keyMintVersion;
  if (kd.attestationSecurityLevel !== kd.keyMintSecurityLevel
    || (kd.attestationSecurityLevel !== SECURITY_LEVEL_TEE && kd.attestationSecurityLevel !== SECURITY_LEVEL_STRONGBOX)) {
    return fail('security_level', summary, `${kd.attestationSecurityLevel}/${kd.keyMintSecurityLevel}`);
  }
  const level: 'strongbox' | 'tee' = kd.attestationSecurityLevel === SECURITY_LEVEL_STRONGBOX ? 'strongbox' : 'tee';
  summary.securityLevel = level;
  if (!Buffer.isBuffer(nonce) || nonce.length === 0 || kd.attestationChallenge.length !== nonce.length
    || !crypto.timingSafeEqual(kd.attestationChallenge, nonce)) {
    return fail('challenge', summary);
  }

  const hw = kd.hardwareEnforced;
  const sw = kd.softwareEnforced;
  try {
    summary.osVersion = intTag(hw, KM_TAG.OS_VERSION);
    summary.osPatchLevel = intTag(hw, KM_TAG.OS_PATCH_LEVEL);
    summary.vendorPatchLevel = intTag(hw, KM_TAG.VENDOR_PATCH_LEVEL);
    summary.bootPatchLevel = intTag(hw, KM_TAG.BOOT_PATCH_LEVEL);
    summary.rollbackResistance = nullTag(hw, KM_TAG.ROLLBACK_RESISTANCE);
    summary.unlockedDeviceRequired = nullTag(hw, KM_TAG.UNLOCKED_DEVICE_REQUIRED) || nullTag(sw, KM_TAG.UNLOCKED_DEVICE_REQUIRED);
  } catch (e) {
    return fail('malformed', summary, e instanceof Error ? e.message : undefined);
  }

  // 8. Authorization list — read ONLY in the hardware list of the attested
  //    level (never in softwareEnforced).
  try {
    const purposes = intSetTag(hw, KM_TAG.PURPOSE);
    if (!purposes || !purposes.includes(KM_PURPOSE_SIGN) || purposes.includes(KM_PURPOSE_ATTEST_KEY)) {
      return fail('purpose', summary);
    }
    if (intTag(hw, KM_TAG.ALGORITHM) !== KM_ALGORITHM_EC
      || intTag(hw, KM_TAG.EC_CURVE) !== KM_EC_CURVE_P256
      || intTag(hw, KM_TAG.KEY_SIZE) !== 256) {
      return fail('algorithm', summary);
    }
    if (intTag(hw, KM_TAG.ORIGIN) !== KM_ORIGIN_GENERATED) return fail('origin', summary);
    // Refused wherever they appear (a key that is usable without
    // authentication, by every app, or for a time window is not ours).
    if (hasTag(hw, KM_TAG.NO_AUTH_REQUIRED) || hasTag(sw, KM_TAG.NO_AUTH_REQUIRED)) return fail('no_auth_required', summary);
    if (hasTag(hw, KM_TAG.ALL_APPLICATIONS) || hasTag(sw, KM_TAG.ALL_APPLICATIONS)) return fail('all_applications', summary);
    const authType = intTag(hw, KM_TAG.USER_AUTH_TYPE);
    if (authType === null || (authType & HW_AUTH_BIOMETRIC) === 0 || (authType & HW_AUTH_PASSWORD) !== 0) {
      return fail('user_auth', summary, authType === null ? 'absent' : String(authType));
    }
    if (hasTag(hw, KM_TAG.AUTH_TIMEOUT) || hasTag(sw, KM_TAG.AUTH_TIMEOUT)) return fail('auth_timeout', summary);
  } catch (e) {
    return fail('malformed', summary, e instanceof Error ? e.message : undefined);
  }

  // 9. Root of trust (hardware list): locked bootloader, Verified boot [D3].
  const rotTlv = hw.tags.get(KM_TAG.ROOT_OF_TRUST);
  if (!rotTlv) return fail('root_of_trust', summary, 'absent');
  let rot: RootOfTrust;
  try { rot = parseRootOfTrust(rotTlv); } catch (e) {
    return fail('root_of_trust', summary, e instanceof Error ? e.message : undefined);
  }
  summary.deviceLocked = rot.deviceLocked;
  if (!rot.deviceLockedDer) summary.deviceLockedNonDer = true;
  summary.bootState = BOOT_STATE_NAMES[rot.verifiedBootState] ?? `unknown_${rot.verifiedBootState}`;
  if (!rot.deviceLocked) return fail('bootloader_unlocked', summary);
  if (rot.verifiedBootState !== 0) return fail('boot_state', summary, summary.bootState);

  // 10. attestationApplicationId — the one tag Android puts in
  //     softwareEnforced (keystore adds it). Read there, or in the hardware
  //     list if a KeyMint puts it there; both present must agree.
  const appSw = sw.tags.get(KM_TAG.ATTESTATION_APPLICATION_ID);
  const appHw = hw.tags.get(KM_TAG.ATTESTATION_APPLICATION_ID);
  let app: AttestationApplicationId;
  try {
    const octSw = appSw ? asOctetString(appSw) : null;
    const octHw = appHw ? asOctetString(appHw) : null;
    if (octSw && octHw && !octSw.equals(octHw)) return fail('app_id', summary, 'conflicting lists');
    const oct = octSw ?? octHw;
    if (!oct) return fail('app_id', summary, 'absent');
    app = parseAttestationApplicationId(oct);
  } catch (e) {
    return fail('app_id', summary, e instanceof Error ? e.message : 'malformed');
  }
  const allowedPackages = new Set(policy.appPackages);
  summary.appPackage = app.packages[0]?.name ?? null;
  summary.appVersion = app.packages[0] ? app.packages[0].version.toString() : null;
  if (app.packages.length === 0 || app.packages.some((p) => !allowedPackages.has(p.name))) {
    return fail('app_id', summary, app.packages.map((p) => p.name).join(',').slice(0, 200));
  }
  const signers = app.signatureDigests.map((d) => d.toString('hex'));
  summary.appSigners = signers;
  const allowedSigners = new Set(policy.appSigners.map(normHex));
  if (signers.length === 0 || signers.some((s) => !allowedSigners.has(s))) return fail('app_signer', summary);
  const release = new Set((policy.releaseSigners ?? policy.appSigners).map(normHex));
  summary.debugSigner = signers.some((s) => !release.has(s));

  // 11. RKP signal [D5]: the remotely provisioned attestation-key
  //     certificate carries the provisioning-info extension. Logged in v1;
  //     enforced only when policy.requireRkp (Android 13+).
  const rkp = tbs.slice(1, n - 1).some((t) => t.extensions.some((e) => e.oid === PROVISIONING_INFO_OID));
  summary.rkp = rkp;
  if (policy.requireRkp && !rkp && (summary.osVersion ?? 0) >= 130000) return fail('rkp_required', summary);

  return { ok: true, level, summary: summary as AttestationSummary };
}

/** Exposed for the tests: the extension bytes as read by the verifier. */
export function keyDescriptionOf(leafDer: Buffer): KeyDescription | null {
  const ext = parseCertificateTbs(leafDer).extensions.find((e) => e.oid === KEY_DESCRIPTION_OID);
  return ext ? parseKeyDescription(ext.value) : null;
}

