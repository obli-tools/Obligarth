import { createHash, createPublicKey, verify, X509Certificate } from 'node:crypto';
import { derChildren, derOid, derRead, TAG, type DerNode } from '../commands/der';
import { PlistData, parsePlist, type PlistDict, type PlistValue } from '../commands/plist';

// =============================================================================
// The exchange files of the push certificate workflow (docs: integration-
// apple-edge §11.1, I16; FND-06), pure (the unit tests load it without the
// server):
//   - obligarth.push-csr-request (v1): what the vendor's offline signing tool
//     receives (the CSR of the tenant's push key, made by apple-edge; neither
//     the client's name nor its Apple account);
//   - obligarth.push-csr-signed (v1): what it gives back, checked here before
//     anything is kept: same instance, same request, same CSR, a plist of
//     exactly three keys whose CSR is ours, a readable chain whose first
//     certificate is the vendor's (fingerprint, valid now, each certificate
//     issued and signed by the next), the signature of the CSR verified with
//     the vendor's public key (SHA-256 with RSA [J1]);
//   - the certificate Apple issues: one certificate, valid now, subject UID
//     com.apple.mgmt.…, public key equal to the CSR's.
// Every refusal is a VendorFileError or a PushCertificateError with a reason
// (a code the console shows); no file content is ever logged.
// =============================================================================

export const REQUEST_FORMAT = 'obligarth.push-csr-request';
export const SIGNED_FORMAT = 'obligarth.push-csr-signed';
export const FILE_VERSION = 1;

const OID_UID = derOid('0.9.2342.19200300.100.1.1');
const PLIST_KEYS = ['PushCertCertificateChain', 'PushCertRequestCSR', 'PushCertSignature'];
const HEX64 = /^[0-9a-f]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class VendorFileError extends Error {
  readonly reason: string;
  constructor(reason: string, message: string) {
    super(message);
    this.name = 'VendorFileError';
    this.reason = reason;
  }
}

export class PushCertificateError extends Error {
  /** pushCertificateInvalid, pushCertificateExpired, pushCertificateNotForRequest, pushCertificateNoTopic. */
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'PushCertificateError';
    this.code = code;
  }
}

export const sha256Hex = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');

export interface PushRequestFile {
  format: typeof REQUEST_FORMAT;
  version: 1;
  instance_id: string;
  request_id: string;
  tenant_ref: string;
  purpose: string;
  csr_der_b64: string;
  csr_sha256: string;
  created_at: string;
}

/** The request file for the vendor (§11.1). */
export function buildRequestFile(r: { instanceId: string; requestId: string; tenantRef: string; purpose: string; csrDer: Buffer; createdAt: Date }):
  PushRequestFile {
  return {
    format: REQUEST_FORMAT, version: FILE_VERSION, instance_id: r.instanceId, request_id: r.requestId, tenant_ref: r.tenantRef,
    purpose: r.purpose, csr_der_b64: r.csrDer.toString('base64'), csr_sha256: sha256Hex(r.csrDer), created_at: r.createdAt.toISOString(),
  };
}

/** The PEM blocks of a text: [type, DER]. */
export function pemBlocks(text: string): Array<{ type: string; der: Buffer }> {
  const out: Array<{ type: string; der: Buffer }> = [];
  const re = /-----BEGIN ([A-Z0-9 ]{1,40})-----([\s\S]*?)-----END \1-----/g;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const b64 = m[2].replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new Error('invalid PEM body');
    out.push({ type: m[1], der: Buffer.from(b64, 'base64') });
    if (out.length > 16) throw new Error('too many PEM blocks');
  }
  return out;
}

const STRICT_B64 = /^[A-Za-z0-9+/\r\n]*={0,2}\s*$/;

function decodeB64(v: string, what: string): Buffer {
  if (typeof v !== 'string' || !STRICT_B64.test(v)) throw new VendorFileError('encoding', `${what} is not base64`);
  return Buffer.from(v.replace(/\s+/g, ''), 'base64');
}

/** The SubjectPublicKeyInfo (DER) of a PKCS#10 certification request. */
export function csrPublicKey(csrDer: Buffer): Buffer {
  const req = derRead(csrDer, 0);
  if (req.tag !== TAG.SEQUENCE || req.end !== csrDer.length) throw new Error('not a certification request');
  const info = derChildren(csrDer, req)[0];
  if (!info || info.tag !== TAG.SEQUENCE) throw new Error('not a certification request');
  const fields = derChildren(csrDer, info);
  const spki = fields[2];
  if (!fields[0] || fields[0].tag !== TAG.INTEGER || !fields[1] || fields[1].tag !== TAG.SEQUENCE || !spki || spki.tag !== TAG.SEQUENCE) {
    throw new Error('not a certification request');
  }
  return Buffer.from(csrDer.subarray(spki.start, spki.end));
}

/** The DER of a public key, normalised (SPKI), to compare two keys. */
const spkiOf = (key: ReturnType<typeof createPublicKey>): Buffer => key.export({ type: 'spki', format: 'der' }) as Buffer;

/** The value of the first attribute `oid` of the subject of a certificate (a string), or null. */
export function subjectAttribute(certDer: Buffer, oid: Buffer = OID_UID): string | null {
  const cert = derRead(certDer, 0);
  const tbs = derChildren(certDer, cert)[0];
  if (!tbs || tbs.tag !== TAG.SEQUENCE) throw new Error('not a certificate');
  const fields = derChildren(certDer, tbs);
  const i = fields[0]?.tag === TAG.CTX0 ? 1 : 0;                       // version
  const subject: DerNode | undefined = fields[i + 4];                  // serial, signature, issuer, validity, subject
  if (!subject || subject.tag !== TAG.SEQUENCE) throw new Error('not a certificate');
  for (const rdn of derChildren(certDer, subject)) {
    for (const atv of derChildren(certDer, rdn)) {
      const [type, value] = derChildren(certDer, atv);
      if (!type || !value) continue;
      if (certDer.subarray(type.start, type.end).equals(oid)) {
        // UTF8String, PrintableString, IA5String, T61String; BMPString (UTF-16BE)
        const raw = certDer.subarray(value.contentStart, value.end);
        if (value.tag === 0x1e) return Buffer.from(raw).swap16().toString('utf16le');
        return raw.toString(value.tag === 0x14 ? 'latin1' : 'utf8');
      }
    }
  }
  return null;
}

function validNow(c: X509Certificate, now: Date): boolean {
  return new Date(c.validFrom).getTime() <= now.getTime() + 3_600_000 && now.getTime() < new Date(c.validTo).getTime();
}

function stringOrData(v: PlistValue | undefined): string | Buffer | null {
  if (typeof v === 'string') return v;
  if (v instanceof PlistData) return v.value;
  return null;
}

export interface SignedFileCheck {
  /** base64 of the plist Apple expects (vendor_request_b64). */
  appleRequestB64: string;
  vendorCertSha256: string;
  vendorCertNotAfter: Date;
  /** Common name of the vendor certificate (an organisation, never a person): the label of its deadline. */
  vendorCertLabel: string;
  signedAt: Date | null;
  /** The vendor certificate is pinned by the platform (checkVendorTrust): only then may it set the instance's deadline. */
  vendorTrusted?: boolean;
}

/**
 * Checks the vendor's signed file against the open request (§11.1). Throws VendorFileError (reason) on any
 * difference.
 */
export function checkSignedFile(text: string, expect: { instanceId: string; requestId: string; csrDer: Buffer }, now = new Date()):
  SignedFileCheck {
  let doc: Record<string, unknown>;
  try {
    const v = JSON.parse(text) as unknown;
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
    doc = v as Record<string, unknown>;
  } catch {
    throw new VendorFileError('json', 'The file is not the JSON file of the vendor\'s signing tool');
  }
  if (doc.format !== SIGNED_FORMAT) throw new VendorFileError('format', `format: ${SIGNED_FORMAT} expected`);
  if (doc.version !== FILE_VERSION) throw new VendorFileError('version', 'version: 1 expected');
  if (typeof doc.instance_id !== 'string' || doc.instance_id.toLowerCase() !== expect.instanceId.toLowerCase()) {
    throw new VendorFileError('instance', 'The file was signed for another instance');
  }
  if (typeof doc.request_id !== 'string' || !UUID_RE.test(doc.request_id.toLowerCase()) || doc.request_id.toLowerCase() !== expect.requestId) {
    throw new VendorFileError('request', 'The file answers another request');
  }
  const csrSha = sha256Hex(expect.csrDer);
  if (typeof doc.csr_sha256 !== 'string' || doc.csr_sha256.toLowerCase() !== csrSha) {
    throw new VendorFileError('csr_sha256', 'The fingerprint of the CSR differs from the request\'s');
  }
  if (typeof doc.apple_request_b64 !== 'string' || doc.apple_request_b64.length > 48 * 1024) {
    throw new VendorFileError('apple_request', 'apple_request_b64 is missing or too large');
  }
  const xml = decodeB64(doc.apple_request_b64, 'apple_request_b64').toString('utf8');
  let plist: PlistValue;
  try {
    plist = parsePlist(xml);
  } catch {
    throw new VendorFileError('plist', 'apple_request_b64 is not a property list');
  }
  if (!plist || typeof plist !== 'object' || Array.isArray(plist) || plist instanceof PlistData) {
    throw new VendorFileError('plist', 'apple_request_b64 is not a dictionary');
  }
  const dict = plist as PlistDict;
  const keys = Object.keys(dict).sort();
  if (keys.length !== 3 || keys.some((k, i) => k !== PLIST_KEYS[i])) {
    throw new VendorFileError('plist_keys', `The request must hold exactly ${PLIST_KEYS.join(', ')}`);
  }
  const csrValue = stringOrData(dict.PushCertRequestCSR);
  const csrInFile = typeof csrValue === 'string' ? decodeB64(csrValue, 'PushCertRequestCSR') : csrValue;
  if (!csrInFile || !csrInFile.equals(expect.csrDer)) {
    throw new VendorFileError('plist_csr', 'PushCertRequestCSR is not the CSR of this request');
  }
  const chainText = stringOrData(dict.PushCertCertificateChain);
  if (typeof chainText !== 'string') throw new VendorFileError('chain', 'PushCertCertificateChain is not a PEM text');
  let chain: X509Certificate[];
  try {
    const blocks = pemBlocks(chainText);
    if (blocks.length === 0 || blocks.some((b) => b.type !== 'CERTIFICATE')) throw new Error('certificates only');
    chain = blocks.map((b) => new X509Certificate(b.der));
  } catch {
    throw new VendorFileError('chain', 'PushCertCertificateChain cannot be read');
  }
  const vendor = chain[0];
  const vendorSha = sha256Hex(vendor.raw);
  if (typeof doc.vendor_cert_sha256 !== 'string' || doc.vendor_cert_sha256.toLowerCase() !== vendorSha) {
    throw new VendorFileError('vendor_cert', 'The first certificate of the chain is not the vendor certificate the file names');
  }
  if (!validNow(vendor, now)) throw new VendorFileError('vendor_cert_expired', 'The vendor certificate is expired or not yet valid');
  for (let i = 0; i + 1 < chain.length; i++) {
    if (!chain[i].checkIssued(chain[i + 1]) || !chain[i].verify(chain[i + 1].publicKey)) {
      throw new VendorFileError('chain_order', 'The chain is not ordered vendor, intermediate, root');
    }
  }
  const sigValue = stringOrData(dict.PushCertSignature);
  const sig = typeof sigValue === 'string' ? decodeB64(sigValue, 'PushCertSignature') : sigValue;
  let good = false;
  try {
    good = !!sig && sig.length > 0 && verify('sha256', expect.csrDer, vendor.publicKey, sig);
  } catch {
    good = false;
  }
  if (!good) throw new VendorFileError('signature', 'The signature of the CSR does not verify with the vendor certificate');
  const signedAt = typeof doc.signed_at === 'string' && !Number.isNaN(Date.parse(doc.signed_at)) ? new Date(doc.signed_at) : null;
  const cn = /(?:^|\n)CN=([^\n]{1,200})/.exec(vendor.subject)?.[1] ?? 'MDM Vendor';
  return {
    appleRequestB64: doc.apple_request_b64.replace(/\s+/g, ''), vendorCertSha256: vendorSha, vendorCertNotAfter: new Date(vendor.validTo),
    vendorCertLabel: cn.slice(0, 200), signedAt,
  };
}

/**
 * The trust anchor of the vendor certificate (§11.1, review of lot C3, R2): the file names its own certificate, so
 * only the fingerprints pinned by the platform (APPLE_MDM_VENDOR_CERT_SHA256; the vendor is the single operator) are
 * trusted. Pinned: true. Not pinned while some are: VendorFileError vendor_not_trusted. None pinned: refused when
 * `pinRequired` (production), otherwise accepted untrusted (false): such a file never touches a deadline of the
 * instance.
 */
export function checkVendorTrust(vendorCertSha256: string, pins: readonly string[], pinRequired: boolean): boolean {
  const sha = vendorCertSha256.toLowerCase();
  if (pins.length > 0) {
    if (!pins.includes(sha)) throw new VendorFileError('vendor_not_trusted', 'The vendor certificate is not one the instance trusts');
    return true;
  }
  if (pinRequired) throw new VendorFileError('vendor_not_trusted', 'No vendor certificate is pinned on this instance (APPLE_MDM_VENDOR_CERT_SHA256)');
  return false;
}

export interface PushCertificateCheck {
  certPem: string;
  topic: string;
  sha256: string;
  notAfter: Date;
}

/** Checks the certificate Apple issued for the request's CSR (§11.1). Throws PushCertificateError. */
export function checkAppleCertificate(text: string, csrDer: Buffer, now = new Date()): PushCertificateCheck {
  let blocks: Array<{ type: string; der: Buffer }>;
  try {
    blocks = pemBlocks(text);
  } catch {
    throw new PushCertificateError('pushCertificateInvalid', 'The file is not a PEM certificate');
  }
  if (blocks.some((b) => /PRIVATE KEY/.test(b.type))) {
    throw new PushCertificateError('pushCertificateInvalid', 'The file holds a private key: import the certificate of Apple alone');
  }
  if (blocks.length !== 1 || blocks[0].type !== 'CERTIFICATE') {
    throw new PushCertificateError('pushCertificateInvalid', 'The file must hold exactly one certificate (PEM)');
  }
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(blocks[0].der);
  } catch {
    throw new PushCertificateError('pushCertificateInvalid', 'The certificate cannot be read');
  }
  if (!validNow(cert, now)) throw new PushCertificateError('pushCertificateExpired', 'The certificate is expired or not yet valid');
  let topic: string | null = null;
  try {
    topic = subjectAttribute(cert.raw);
  } catch {
    topic = null;
  }
  if (!topic || !topic.startsWith('com.apple.mgmt.') || topic.length > 255) {
    throw new PushCertificateError('pushCertificateNoTopic', 'The certificate carries no MDM push topic (UID com.apple.mgmt.…)');
  }
  let same = false;
  try {
    same = spkiOf(cert.publicKey).equals(spkiOf(createPublicKey({ key: csrPublicKey(csrDer), format: 'der', type: 'spki' })));
  } catch {
    same = false;
  }
  if (!same) {
    throw new PushCertificateError('pushCertificateNotForRequest',
      'This certificate was not issued for the request of this tenant: the client uploaded another file at Apple');
  }
  const pem = `-----BEGIN CERTIFICATE-----\n${cert.raw.toString('base64').replace(/.{1,64}/g, '$&\n')}-----END CERTIFICATE-----\n`;
  return { certPem: pem, topic, sha256: sha256Hex(cert.raw), notAfter: new Date(cert.validTo) };
}

export const isHex64 = (s: unknown): s is string => typeof s === 'string' && HEX64.test(s);
