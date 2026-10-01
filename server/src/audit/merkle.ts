// Merkle tree of the chain heads (docs: audit-durci §6.2): RFC 6962 hashes,
// inclusion proofs PATH(m, D[n]) of RFC 6962 §2.1.1, verified by the
// algorithm of RFC 9162 §2.1.3.2. No import beyond node:crypto (offline
// tool, unit tests).
import { createHash } from 'node:crypto';

const sha = (...parts: Buffer[]): Buffer => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};

export const leafHash = (data: Buffer): Buffer => sha(Buffer.from([0x00]), data);
const nodeHash = (l: Buffer, r: Buffer): Buffer => sha(Buffer.from([0x01]), l, r);
/** Largest power of 2 strictly below n. */
const split = (n: number): number => { let k = 1; while (k * 2 < n) k *= 2; return k; };

/** Data of a leaf (44 bytes): tenant id on 4 bytes, chain sequence on 8 bytes
 *  (unsigned, big-endian), chain hash (32 bytes). */
export function leafData(tenantId: number, seq: bigint | number, chainHash: Buffer): Buffer {
  const b = Buffer.alloc(12);
  b.writeUInt32BE(tenantId, 0);
  b.writeBigUInt64BE(BigInt(seq), 4);
  return Buffer.concat([b, chainHash]);
}

/** Merkle Tree Hash of RFC 6962 §2.1 (leaves: their data). */
export function treeHash(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return sha(Buffer.alloc(0));
  if (leaves.length === 1) return leafHash(leaves[0]);
  const k = split(leaves.length);
  return nodeHash(treeHash(leaves.slice(0, k)), treeHash(leaves.slice(k)));
}

/** Audit path PATH(m, D[n]) of RFC 6962 §2.1.1. */
export function inclusionProof(m: number, leaves: Buffer[]): Buffer[] {
  if (leaves.length <= 1) return [];
  const k = split(leaves.length);
  return m < k
    ? [...inclusionProof(m, leaves.slice(0, k)), treeHash(leaves.slice(k))]
    : [...inclusionProof(m - k, leaves.slice(k)), treeHash(leaves.slice(0, k))];
}

/** RFC 9162 §2.1.3.2: does `proof` lead the leaf hash `leaf` (index of
 *  `size`) to `root`? */
export function verifyInclusion(index: number, size: number, leaf: Buffer, proof: Buffer[], root: Buffer): boolean {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.equals(root);
}

/** The signed text of a seal (§6.3): the same in SQL
 *  (obligarth.audit_seal_message); seal_hash = SHA-256 of it. */
export function sealMessage(f: {
  instance: string; seq: number | bigint; sealedAt: string; leaves: number; root: Buffer; prev: Buffer; keyId: string;
}): string {
  return [
    'obligarth-audit-seal/v1',
    `instance=${f.instance}`,
    `seq=${String(f.seq)}`,
    `sealed_at=${f.sealedAt}`,
    `leaves=${f.leaves}`,
    `root=${f.root.toString('hex')}`,
    `prev=${f.prev.toString('hex')}`,
    `key=${f.keyId}`,
  ].join('\n');
}

/** Identifier of a seal key: the 16 first hexadecimal characters of
 *  SHA-256(raw public key). */
export function sealKeyId(publicRaw: Buffer): string {
  return createHash('sha256').update(publicRaw).digest('hex').slice(0, 16);
}

/** DER prefix of an Ed25519 SubjectPublicKeyInfo (12 bytes before the raw key). */
export const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** PEM of a raw Ed25519 public key (openssl pkeyutl -verify -pubin). */
export function ed25519PublicPem(publicRaw: Buffer): string {
  const b64 = Buffer.concat([ED25519_SPKI_PREFIX, publicRaw]).toString('base64');
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`;
}
