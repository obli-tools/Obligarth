// A link of a tenant's chain (docs: audit-durci §4.1, annex B):
// hash = SHA-256(prev_hash ‖ seq on 8 bytes, big-endian ‖ body in UTF-8),
// the same as obligarth.audit_link_hash in SQL. No import beyond node:crypto:
// the offline verification tool uses it without a server.
import { createHash } from 'node:crypto';

/** 32 zero bytes: the prev_hash of the genesis entry of a chain. */
export const GENESIS_HASH = Buffer.alloc(32);

export function linkHash(prev: Buffer, seq: bigint | number, body: string): Buffer {
  if (prev.length !== 32) throw new TypeError('audit: a chain hash has 32 bytes');
  const s = Buffer.alloc(8);
  s.writeBigUInt64BE(BigInt(seq));
  return createHash('sha256').update(prev).update(s).update(Buffer.from(body, 'utf8')).digest();
}

export const sha256 = (data: Buffer | string): Buffer => createHash('sha256').update(data).digest();

export function hexToBuf(hex: string, bytes = 32): Buffer {
  if (typeof hex !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(hex)) {
    throw new TypeError(`audit: expected ${bytes * 2} lower-case hexadecimal characters`);
  }
  return Buffer.from(hex, 'hex');
}
