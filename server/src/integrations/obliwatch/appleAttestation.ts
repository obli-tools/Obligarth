import { X509Certificate, createHash, randomBytes } from 'node:crypto';
import type { Knex } from 'knex';
import { certificateExtensions } from '../../services/deviceKey/der';
import { logger } from '../../utils/logger';
import { obliwatchIntegrationEnabled } from './config';
import { touchSignalInTx } from './marker';
import { pushActiveInTx, recordStateSignalInTx } from './signals';

// =============================================================================
// Apple managed device attestation (brief GTH-08; lot L5): its failure is the signal D-MOB-ATTEST-FAILED
// (reason code attestation_failed).
//
// Design (the smallest correct one in the existing architecture): the attestation is asked through the MDM command
// queue, not through an ACME server. Apple delivers the same Apple-signed attestation two ways (Apple Platform
// Deployment, "Managed device attestation"; Device Management: DeviceInformationCommand.Command.Queries
// DevicePropertiesAttestation and DeviceAttestationNonce; ACME payload, com.apple.security.acme, Attest):
//   - ACME device-attest-01 binds a hardware key to a certificate Obligarth would ISSUE (an ACME server, a CA, a
//     profile, renewals): its value is the key, not the detection, and nothing of it exists in apple-edge (the prefix
//     acme/ is only reserved);
//   - DeviceInformation with the query DevicePropertiesAttestation (iOS, iPadOS and tvOS 16+, macOS 14+) answers the
//     chain of DER certificates of that attestation: leaf then Apple's intermediate, rooted in the Apple Enterprise
//     Attestation Root CA. The leaf carries the serial number (OID 1.2.840.113635.100.8.9.1) and the UDID (…8.9.2) of
//     the device (none for a User Enrollment), its OS and sepOS versions (…8.10.1, …8.10.2) and, when the command
//     carried DeviceAttestationNonce, the freshness code SHA-256(nonce) (…8.11.1). The values are the raw bytes of the
//     extension (as the ACME verifiers read them). A device makes a NEW attestation at most once every 7 days: within
//     that time it answers the cached one, whose freshness code is the one of an earlier nonce.
// apple-edge forwards the answer as it forwards any (Data → base64, outbox/plistjson.go): no Go change. Here:
//   - planAttestationNoncesInTx (the daily Apple inventory, apple/commands/inventory.ts): for the company devices
//     (corporate, COPE; device enrollment) of a tenant with OBLIWATCH_INTEGRATION=on and the push consent, on an OS that
//     has the query, a fresh 32-byte nonce per device at most once every 7 days; its SHA-256 kept (the last 4);
//   - ingestAttestationInTx (the DeviceInformation ingestor, apple/commands/results.ts, in its transaction, under a
//     savepoint: never a failure of the inventory): the chain verified against the PINNED root (never downloaded), each
//     certificate in its validity, the UDID and the serial number compared with the record's when both are known, the
//     freshness code compared with the nonces sent. Verdict:
//       verified                                  → D-MOB-ATTEST-FAILED cleared;
//       failed: chain_invalid, malformed,         → D-MOB-ATTEST-FAILED active, reason codes [attestation_failed,
//               identity_mismatch,                  <cause>];
//               freshness_mismatch (no nonce of the last 4 matches while the first nonce is more than 8 days old)
//       pending: the freshness does not match yet (first nonce less than 8 days old: the cached attestation of the
//               7 days), or an expired leaf (a new nonce is asked at the next run): nothing decided.
//     No attestation in the answer (an OS without the query, a device that refuses it): nothing decided.
// What is stored: the verdict, its reason code, its date and the nonce hashes (apple_device_attestations). NEVER a
// certificate, a serial number, a UDID nor any value read from the attestation; the identifiers are compared in memory.
// =============================================================================

/** Apple Enterprise Attestation Root CA, ECDSA P-384, 2022-02-16 → 2047-02-20, certificate SHA-256
 *  CC:F5:9E:F8:FC:B3:01:7D:97:F8:B5:FA:6F:A9:0E:7A:3F:92:83:F7:6B:55:AC:6C:F6:ED:A8:B8:B9:49:F0:5B, SPKI SHA-256
 *  4179683e87e3f483849848b3eb80e08ecdf52e3f1a99dd1340f29b88ecbc2041. Fetched on 2026-11-19 from
 *  https://www.apple.com/certificateauthority/Apple_Enterprise_Attestation_Root_CA.pem (Apple PKI). Public data,
 *  pinned: never downloaded at run time. */
const APPLE_ENTERPRISE_ATTESTATION_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIICJDCCAamgAwIBAgIUQsDCuyxyfFxeq/bxpm8frF15hzcwCgYIKoZIzj0EAwMw
UTEtMCsGA1UEAwwkQXBwbGUgRW50ZXJwcmlzZSBBdHRlc3RhdGlvbiBSb290IENB
MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yMjAyMTYxOTAx
MjRaFw00NzAyMjAwMDAwMDBaMFExLTArBgNVBAMMJEFwcGxlIEVudGVycHJpc2Ug
QXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UE
BhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT6Jigq+Ps9Q4CoT8t8q+UnOe2p
oT9nRaUfGhBTbgvqSGXPjVkbYlIWYO+1zPk2Sz9hQ5ozzmLrPmTBgEWRcHjA2/y7
7GEicps9wn2tj+G89l3INNDKETdxSPPIZpPj8VmjQjBAMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFPNqTQGd8muBpV5du+UIbVbi+d66MA4GA1UdDwEB/wQEAwIB
BjAKBggqhkjOPQQDAwNpADBmAjEA1xpWmTLSpr1VH4f8Ypk8f3jMUKYz4QPG8mL5
8m9sX/b2+eXpTv2pH4RZgJjucnbcAjEA4ZSB6S45FlPuS/u4pTnzoz632rA+xW/T
ZwFEh9bhKjJ+5VQ9/Do1os0u3LEkgN/r
-----END CERTIFICATE-----
`;
export const APPLE_ATTESTATION_ROOT_SPKI_SHA256 = '4179683e87e3f483849848b3eb80e08ecdf52e3f1a99dd1340f29b88ecbc2041';

export const OID_APPLE_SERIAL = '1.2.840.113635.100.8.9.1';
export const OID_APPLE_UDID = '1.2.840.113635.100.8.9.2';
export const OID_APPLE_FRESHNESS = '1.2.840.113635.100.8.11.1';

/** The DeviceInformation query and the command key (Device Management). */
export const ATTESTATION_QUERY = 'DevicePropertiesAttestation';
export const ATTESTATION_NONCE_KEY = 'DeviceAttestationNonce';

/** A device makes a new attestation at most once every 7 days (Apple): one nonce per device per 7 days. */
export const NONCE_EVERY_MS = 7 * 86_400_000;
/** The freshness may lag the first nonce by the 7 days of the cached attestation (and a day of delivery). */
const FRESHNESS_GRACE_MS = 8 * 86_400_000;
const MAX_NONCES = 4;
const MAX_CERTS = 4;
const MAX_CERT_B64 = 16_384;
const SKEW_MS = 5 * 60_000;

let roots: X509Certificate[] = [new X509Certificate(APPLE_ENTERPRISE_ATTESTATION_ROOT_PEM)];

/** Tests only: the roots trusted instead of Apple's (a fake root generated at run time); null puts Apple's back. */
export function _setAppleAttestationRootsForTests(pems: string[] | null): void {
  roots = (pems ?? [APPLE_ENTERPRISE_ATTESTATION_ROOT_PEM]).map((p) => new X509Certificate(p));
}

export type AttestationFailure = 'chain_invalid' | 'malformed' | 'identity_mismatch' | 'freshness_mismatch';
export type AttestationVerdict =
  | { outcome: 'verified' }
  | { outcome: 'failed'; reason: AttestationFailure }
  | { outcome: 'pending'; reason: 'freshness_pending' | 'leaf_expired' };

export interface AttestationExpectation {
  /** apple_devices.udid (the enrollment's), when known. */
  udid: string | null;
  /** devices.serial_number, when the record holds it. */
  serial: string | null;
  /** SHA-256 (hex) of the nonces sent, newest first. */
  nonceHashes: string[];
  /** When the first of them was sent (null: none). */
  firstNonceAt: Date | null;
}

const spkiSha256 = (c: X509Certificate): string =>
  createHash('sha256').update(c.publicKey.export({ type: 'spki', format: 'der' }) as Buffer).digest('hex');

const inValidity = (c: X509Certificate, now: number): boolean =>
  now >= Date.parse(c.validFrom) - SKEW_MS && now <= Date.parse(c.validTo) + SKEW_MS;

/** An extension's value as text (raw bytes; a DER UTF8String or OCTET STRING wrapper is also accepted). */
function textOf(value: Buffer): string {
  if (value.length >= 2 && (value[0] === 0x0c || value[0] === 0x04 || value[0] === 0x13) && value[1] === value.length - 2) {
    return value.subarray(2).toString('utf8').trim();
  }
  return value.toString('utf8').trim();
}

function bytesOf(value: Buffer): Buffer {
  if (value.length === 34 && value[0] === 0x04 && value[1] === 32) return value.subarray(2);
  return value;
}

const fold = (s: string): string => s.replace(/[^A-Za-z0-9]/g, '').toUpperCase();

/**
 * The verdict of a DevicePropertiesAttestation answer (pure: no I/O). `certs`: the base64 DER certificates as apple-edge
 * forwards them (leaf first). Never logs nor returns a value read from them.
 */
export function verifyAppleAttestation(certs: unknown, expected: AttestationExpectation, now = Date.now()): AttestationVerdict {
  if (!Array.isArray(certs) || certs.length === 0 || certs.length > MAX_CERTS) return { outcome: 'failed', reason: 'malformed' };
  let chain: X509Certificate[];
  let ders: Buffer[];
  try {
    ders = certs.map((c) => {
      if (typeof c !== 'string' || c.length > MAX_CERT_B64 || !/^[A-Za-z0-9+/=\s]+$/.test(c)) throw new Error('not base64');
      return Buffer.from(c, 'base64');
    });
    chain = ders.map((d) => new X509Certificate(d));
  } catch {
    return { outcome: 'failed', reason: 'malformed' };
  }
  // 1. The chain: each certificate signed by the next, an intermediate is a CA; the last one is a pinned root, or is
  //    issued by one.
  for (let i = 0; i < chain.length - 1; i++) {
    const c = chain[i];
    const issuer = chain[i + 1];
    if (!issuer.ca || !c.checkIssued(issuer) || !c.verify(issuer.publicKey)) return { outcome: 'failed', reason: 'chain_invalid' };
  }
  const last = chain[chain.length - 1];
  const pins = new Set(roots.map(spkiSha256));
  const anchored = pins.has(spkiSha256(last))
    ? last.verify(last.publicKey)
    : roots.some((r) => last.checkIssued(r) && last.verify(r.publicKey) && inValidity(r, now));
  if (!anchored || chain.length < (pins.has(spkiSha256(last)) ? 2 : 1)) return { outcome: 'failed', reason: 'chain_invalid' };
  // 2. The validity: an intermediate out of it breaks the chain; an expired leaf is an old cached attestation.
  for (const c of chain.slice(1)) if (!inValidity(c, now)) return { outcome: 'failed', reason: 'chain_invalid' };
  if (!inValidity(chain[0], now)) return { outcome: 'pending', reason: 'leaf_expired' };
  // 3. The device: its identifiers, compared in memory, never kept.
  let ext: Array<{ oid: string; value: Buffer }>;
  try {
    ext = certificateExtensions(ders[0]);
  } catch {
    return { outcome: 'failed', reason: 'malformed' };
  }
  const value = (oid: string): Buffer | null => ext.find((e) => e.oid === oid)?.value ?? null;
  const udid = value(OID_APPLE_UDID);
  const serial = value(OID_APPLE_SERIAL);
  if (udid && expected.udid && fold(textOf(udid)) !== fold(expected.udid)) return { outcome: 'failed', reason: 'identity_mismatch' };
  if (serial && expected.serial && fold(textOf(serial)) !== fold(expected.serial)) return { outcome: 'failed', reason: 'identity_mismatch' };
  // 4. The freshness: the code of one of the nonces sent.
  if (expected.nonceHashes.length > 0) {
    const fresh = value(OID_APPLE_FRESHNESS);
    const code = fresh ? bytesOf(fresh).toString('hex') : null;
    if (!code || !expected.nonceHashes.includes(code)) {
      const first = expected.firstNonceAt ? expected.firstNonceAt.getTime() : now;
      return now - first > FRESHNESS_GRACE_MS ? { outcome: 'failed', reason: 'freshness_mismatch' } : { outcome: 'pending', reason: 'freshness_pending' };
    }
  }
  return { outcome: 'verified' };
}

// ── The nonces of the daily inventory ─────────────────────────────────────────────────────────────────────

const major = (v: unknown): number => {
  const m = /^(\d{1,3})(?:\.(\d{1,3}))?/.exec(typeof v === 'string' ? v : '');
  return m ? Number(m[1]) + Number(m[2] ?? 0) / 1000 : 0;
};

/** Does this OS have the query DevicePropertiesAttestation (iOS, tvOS 16; iPadOS 16.1; macOS 14)? */
export function attestationSupported(platform: string, osVersion: string | null): boolean {
  const v = major(osVersion);
  if (platform === 'ios' || platform === 'tvos') return v >= 16;
  if (platform === 'ipados') return v >= 16.001;
  if (platform === 'macos') return v >= 14;
  return false;
}

async function guarded<T>(trx: Knex.Transaction, what: string, fn: (sp: Knex.Transaction) => Promise<T>): Promise<T | null> {
  try {
    return await trx.transaction(async (sp) => fn(sp));
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, what }, 'obliwatch attestation: not done (the caller goes on)');
    return null;
  }
}

/**
 * The devices among `deviceIds` (the DeviceInformation due today, apple/commands/inventory.ts) that get a nonce of
 * attestation in this run, and that nonce (base64 of 32 random bytes) each; its SHA-256 recorded. Empty while the
 * integration is off or the tenant has no push consent. In the caller's transaction; never throws.
 */
export async function planAttestationNoncesInTx(trx: Knex.Transaction, tenantId: number, deviceIds: number[], now = new Date()):
  Promise<Map<number, string>> {
  const out = new Map<number, string>();
  if (deviceIds.length === 0 || !obliwatchIntegrationEnabled()) return out;
  if (!(await pushActiveInTx(trx, tenantId))) return out;
  const planned = await guarded(trx, 'plan', async (sp) => {
    const rows = await sp('devices as d')
      .leftJoin('apple_device_attestations as x', function j() { this.on('x.device_id', '=', 'd.id').andOn('x.tenant_id', '=', 'd.tenant_id'); })
      .where({ 'd.tenant_id': tenantId, 'd.management_channel': 'apple_mdm', 'd.management_mode': 'device', 'd.enrollment_state': 'enrolled' })
      .whereIn('d.ownership', ['corporate', 'corporate_personal']).whereIn('d.id', deviceIds)
      .where((q) => q.whereNull('x.last_nonce_at').orWhere('x.last_nonce_at', '<', new Date(now.getTime() - NONCE_EVERY_MS + 3_600_000)))
      .select('d.id', 'd.platform', 'd.os_version', 'x.nonce_hashes', 'x.first_nonce_at') as
      Array<{ id: number; platform: string; os_version: string | null; nonce_hashes: string[] | null; first_nonce_at: Date | null }>;
    const map = new Map<number, string>();
    for (const r of rows) {
      if (!attestationSupported(r.platform, r.os_version)) continue;
      const nonce = randomBytes(32);
      const hash = createHash('sha256').update(nonce).digest('hex');
      const hashes = [hash, ...(r.nonce_hashes ?? [])].slice(0, MAX_NONCES);
      await sp('apple_device_attestations')
        .insert({ tenant_id: tenantId, device_id: Number(r.id), nonce_hashes: hashes, first_nonce_at: now, last_nonce_at: now, updated_at: now })
        .onConflict(['tenant_id', 'device_id'])
        .merge({ nonce_hashes: hashes, last_nonce_at: now, updated_at: now, first_nonce_at: sp.raw('COALESCE(apple_device_attestations.first_nonce_at, EXCLUDED.first_nonce_at)') });
      map.set(Number(r.id), nonce.toString('base64'));
    }
    return map;
  });
  return planned ?? out;
}

// ── The answer ─────────────────────────────────────────────────────────────────────────────────────────

/**
 * The attestation of a DeviceInformation answer (the ingestor, in its transaction): verified, recorded, and the state of
 * D-MOB-ATTEST-FAILED written. Nothing when the answer holds none, while the integration is off or without the push
 * consent. Never throws (a savepoint): the inventory goes on whatever happens here.
 */
export async function ingestAttestationInTx(trx: Knex.Transaction, tenantId: number, deviceId: number,
  queryResponses: Record<string, unknown>, occurredAt: Date): Promise<AttestationVerdict | null> {
  if (!(ATTESTATION_QUERY in queryResponses) || !obliwatchIntegrationEnabled()) return null;
  if (!(await pushActiveInTx(trx, tenantId))) return null;
  return guarded(trx, 'ingest', async (sp) => {
    const r = await sp('devices as d')
      .join('apple_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
      .leftJoin('apple_device_attestations as x', function j() { this.on('x.device_id', '=', 'd.id').andOn('x.tenant_id', '=', 'd.tenant_id'); })
      .where({ 'd.tenant_id': tenantId, 'd.id': deviceId })
      .first('d.serial_number', 'd.ownership', 'a.udid', 'x.state', 'x.reason', 'x.checked_at', 'x.nonce_hashes', 'x.first_nonce_at') as
      Record<string, any> | undefined;
    if (!r || r.ownership === 'personal') return null;
    // An answer older than the last verdict is not read again (results may be consumed out of order).
    if (r.checked_at && new Date(r.checked_at).getTime() > occurredAt.getTime()) return null;
    const verdict = verifyAppleAttestation(queryResponses[ATTESTATION_QUERY], {
      udid: r.udid ? String(r.udid) : null, serial: r.serial_number ? String(r.serial_number) : null,
      nonceHashes: Array.isArray(r.nonce_hashes) ? r.nonce_hashes : [], firstNonceAt: r.first_nonce_at ? new Date(r.first_nonce_at) : null,
    }, occurredAt.getTime());
    if (verdict.outcome === 'pending') {
      // An expired cached attestation: a new nonce at the next run.
      if (verdict.reason === 'leaf_expired') {
        await sp('apple_device_attestations').where({ tenant_id: tenantId, device_id: deviceId }).update({ last_nonce_at: null, updated_at: new Date() });
      }
      return verdict;
    }
    const state = verdict.outcome === 'verified' ? 'verified' : 'failed';
    const reason = verdict.outcome === 'failed' ? verdict.reason : null;
    await sp('apple_device_attestations')
      .insert({ tenant_id: tenantId, device_id: deviceId, state, reason, checked_at: occurredAt, updated_at: new Date() })
      .onConflict(['tenant_id', 'device_id']).merge(['state', 'reason', 'checked_at', 'updated_at']);
    if (r.state !== state || (r.reason ?? null) !== reason) await touchSignalInTx(sp, tenantId, [deviceId]);
    await recordStateSignalInTx(sp, tenantId, deviceId, 'D-MOB-ATTEST-FAILED', state === 'failed' ? 'active' : 'cleared',
      state === 'failed' ? ['attestation_failed', reason as string] : []);
    return verdict;
  });
}
