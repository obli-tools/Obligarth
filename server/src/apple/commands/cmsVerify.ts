import { X509Certificate, createHash, verify as cryptoVerify, constants as cryptoConstants } from 'node:crypto';
import { rootCertificates } from 'node:tls';
import { DerError, TAG, derChildren, derOid, derRead, issuerAndSerialOf, type DerNode } from './der';

// =============================================================================
// Verification of the signature of a CMS SignedData (RFC 5652): a signed
// configuration profile (docs: modele-donnees-mdm S6, "verified when
// present"; review of lot B5c, MDM-B5c-R8; decision of the owners of
// 15/10/2026). Each signer's signature is checked against a certificate of the
// SignedData: over the signed attributes (whose messageDigest must be the
// digest of the content) or, without them, over the content. RSA PKCS #1 v1.5
// and ECDSA, with SHA-1, SHA-256, SHA-384 or SHA-512; any other algorithm (RSA-
// PSS…) is 'unsupported', never taken for valid. The chain of the signer is
// then looked for up to a root of Node's store (tls.rootCertificates),
// through the certificates the SignedData carries (each intermediate a CA),
// each within its dates:
// `trusted` says whether one was found (an author's own certificate is valid,
// not trusted). Definite DER only (der.ts). Pure; no network.
// =============================================================================

export type CmsSignatureStatus = 'valid' | 'invalid' | 'unsupported';

export interface CmsSignatureCheck {
  status: CmsSignatureStatus;
  /** The signer's certificate, when the signature is valid. */
  signer?: { subject: string; issuer: string; notAfter: string; sha256: string };
  /** The signer's certificate chains up to a root of Node's store, every certificate within its dates. */
  trusted?: boolean;
}

const oid = (dotted: string): string => derOid(dotted).toString('hex');

const DIGESTS: Record<string, string> = {
  [oid('1.3.14.3.2.26')]: 'sha1',
  [oid('2.16.840.1.101.3.4.2.1')]: 'sha256',
  [oid('2.16.840.1.101.3.4.2.2')]: 'sha384',
  [oid('2.16.840.1.101.3.4.2.3')]: 'sha512',
};

type SigKind = { kind: 'rsa' | 'ecdsa'; hash: string | null };
const SIGNATURES: Record<string, SigKind> = {
  [oid('1.2.840.113549.1.1.1')]: { kind: 'rsa', hash: null },       // rsaEncryption: the digest algorithm's hash
  [oid('1.2.840.113549.1.1.5')]: { kind: 'rsa', hash: 'sha1' },
  [oid('1.2.840.113549.1.1.11')]: { kind: 'rsa', hash: 'sha256' },
  [oid('1.2.840.113549.1.1.12')]: { kind: 'rsa', hash: 'sha384' },
  [oid('1.2.840.113549.1.1.13')]: { kind: 'rsa', hash: 'sha512' },
  [oid('1.2.840.10045.2.1')]: { kind: 'ecdsa', hash: null },        // id-ecPublicKey, as some signers write it
  [oid('1.2.840.10045.4.1')]: { kind: 'ecdsa', hash: 'sha1' },
  [oid('1.2.840.10045.4.3.2')]: { kind: 'ecdsa', hash: 'sha256' },
  [oid('1.2.840.10045.4.3.3')]: { kind: 'ecdsa', hash: 'sha384' },
  [oid('1.2.840.10045.4.3.4')]: { kind: 'ecdsa', hash: 'sha512' },
};

const OID_SIGNED_DATA = oid('1.2.840.113549.1.7.2');
const OID_MESSAGE_DIGEST = oid('1.2.840.113549.1.9.4');
const CTX1 = 0xa1;
const MAX_CHAIN = 8;

const bytes = (buf: Buffer, n: DerNode): Buffer => buf.subarray(n.start, n.end);
const content = (buf: Buffer, n: DerNode): Buffer => buf.subarray(n.contentStart, n.end);
/** The OID of an AlgorithmIdentifier (its first child), as hex of the full TLV. */
const algOf = (buf: Buffer, n: DerNode): string => {
  const first = derChildren(buf, n)[0];
  if (!first || first.tag !== TAG.OID) throw new DerError('invalid AlgorithmIdentifier');
  return bytes(buf, first).toString('hex');
};

let roots: X509Certificate[] | null = null;
function rootStore(): X509Certificate[] {
  if (!roots) {
    roots = [];
    for (const pem of rootCertificates) {
      try { roots.push(new X509Certificate(pem)); } catch { /* a root Node cannot read is skipped */ }
    }
  }
  return roots;
}

const within = (c: X509Certificate, now: Date): boolean => new Date(c.validFrom) <= now && now <= new Date(c.validTo);

/** Does `cert` chain up to a root of the store through `pool`, every certificate within its dates? */
function chainsToRoot(cert: X509Certificate, pool: X509Certificate[], now: Date, store: X509Certificate[]): boolean {
  let current = cert;
  for (let depth = 0; depth < MAX_CHAIN; depth++) {
    if (!within(current, now)) return false;
    const root = store.find((r) => current.checkIssued(r) && current.verify(r.publicKey));
    if (root) return within(root, now);
    if (current.checkIssued(current)) return false;                     // self-signed, not a root of the store
    // An intermediate must be a CA (basicConstraints cA): a leaf a public CA issued (a TLS server certificate, say)
    // never issues a signer that would then read as trusted.
    const next = pool.find((p) => p !== current && p.ca && current.checkIssued(p) && current.verify(p.publicKey));
    if (!next) return false;
    current = next;
  }
  return false;
}

function signatureMatches(cert: X509Certificate, sig: SigKind, hash: string, data: Buffer, signature: Buffer): boolean {
  const keyType = cert.publicKey.asymmetricKeyType;
  try {
    if (sig.kind === 'rsa') {
      if (keyType !== 'rsa') return false;
      return cryptoVerify(hash, data, { key: cert.publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING }, signature);
    }
    if (keyType !== 'ec') return false;
    return cryptoVerify(hash, data, { key: cert.publicKey, dsaEncoding: 'der' }, signature);
  } catch {
    return false;
  }
}

/**
 * Checks the signature(s) of the CMS SignedData `buf` over its encapsulated content `inner` (signedDataContent).
 * Throws DerError when `buf` cannot be read as a SignedData.
 */
export function verifySignedData(buf: Buffer, inner: Buffer,
  o: { now?: Date; /** Tests: the roots in place of Node's store. */ roots?: X509Certificate[] } = {}): CmsSignatureCheck {
  const now = o.now ?? new Date();
  const info = derRead(buf, 0);
  const parts = derChildren(buf, info);
  if (parts.length < 2 || parts[0].tag !== TAG.OID || bytes(buf, parts[0]).toString('hex') !== OID_SIGNED_DATA || parts[1].tag !== TAG.CTX0) {
    throw new DerError('not a SignedData');
  }
  const sd = derChildren(buf, parts[1])[0];
  if (!sd || sd.tag !== TAG.SEQUENCE) throw new DerError('unreadable SignedData');
  const fields = derChildren(buf, sd);
  // version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos (last)
  const signerInfos = fields[fields.length - 1];
  if (!signerInfos || signerInfos.tag !== TAG.SET || fields.length < 4) throw new DerError('unreadable SignedData');
  const certNode = fields.slice(3, -1).find((f) => f.tag === TAG.CTX0);
  const certs: Array<{ x509: X509Certificate; der: Buffer }> = [];
  if (certNode) {
    for (const c of derChildren(buf, certNode)) {
      if (c.tag !== TAG.SEQUENCE) continue;                             // an attribute certificate or another choice
      const der = Buffer.from(bytes(buf, c));
      try { certs.push({ x509: new X509Certificate(der), der }); } catch { /* unreadable: never a signer */ }
    }
  }
  const signers = derChildren(buf, signerInfos);
  if (!signers.length) return { status: 'invalid' };
  let first: CmsSignatureCheck | null = null;
  for (const si of signers) {
    const f = derChildren(buf, si);
    if (f.length < 5 || f[0].tag !== TAG.INTEGER) throw new DerError('unreadable SignerInfo');
    const sid = f[1];
    const digestAlg = algOf(buf, f[2]);
    let i = 3;
    const signedAttrs = f[i]?.tag === TAG.CTX0 ? f[i++] : null;
    const sigAlg = algOf(buf, f[i++]);
    const sigNode = f[i];
    if (!sigNode || sigNode.tag !== TAG.OCTET_STRING) throw new DerError('unreadable SignerInfo');
    if (f[i + 1] && f[i + 1].tag !== CTX1) throw new DerError('unreadable SignerInfo');
    const hash = DIGESTS[digestAlg];
    const sig = SIGNATURES[sigAlg];
    if (!hash || !sig || (sig.hash !== null && sig.hash !== hash)) return { status: 'unsupported' };
    let data: Buffer;
    if (signedAttrs) {
      // The messageDigest attribute must be the digest of the content; the signature is over the attributes as a SET.
      let digest: Buffer | null = null;
      for (const attr of derChildren(buf, signedAttrs)) {
        const [type, values] = derChildren(buf, attr);
        if (type?.tag === TAG.OID && bytes(buf, type).toString('hex') === OID_MESSAGE_DIGEST && values?.tag === TAG.SET) {
          const v = derChildren(buf, values);
          if (v.length !== 1 || v[0].tag !== TAG.OCTET_STRING || digest) return { status: 'invalid' };
          digest = Buffer.from(content(buf, v[0]));
        }
      }
      if (!digest || !digest.equals(createHash(hash).update(inner).digest())) return { status: 'invalid' };
      data = Buffer.concat([Buffer.from([TAG.SET]), buf.subarray(signedAttrs.start + 1, signedAttrs.end)]);
    } else {
      data = inner;
    }
    const signature = Buffer.from(content(buf, sigNode));
    // The certificate the SignerIdentifier names (issuer and serial number); with a subject key identifier ([0]), the
    // certificate whose key verifies the signature.
    let candidates = certs;
    if (sid.tag === TAG.SEQUENCE) {
      const [issuer, serial] = derChildren(buf, sid);
      candidates = certs.filter((c) => {
        try {
          const is = issuerAndSerialOf(c.der);
          return !!issuer && !!serial && is.issuer.equals(bytes(buf, issuer)) && is.serial.equals(bytes(buf, serial));
        } catch { return false; }
      });
    }
    const signer = candidates.find((c) => signatureMatches(c.x509, sig, hash, data, signature));
    if (!signer) return { status: 'invalid' };
    if (!first) {
      first = {
        status: 'valid',
        signer: {
          subject: signer.x509.subject.replace(/\n/g, ', ').slice(0, 300),
          issuer: signer.x509.issuer.replace(/\n/g, ', ').slice(0, 300),
          notAfter: new Date(signer.x509.validTo).toISOString(),
          sha256: createHash('sha256').update(signer.der).digest('hex'),
        },
        trusted: chainsToRoot(signer.x509, certs.map((c) => c.x509), now, o.roots ?? rootStore()),
      };
    }
  }
  return first ?? { status: 'invalid' };
}
