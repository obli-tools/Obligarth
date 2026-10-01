import { createHash } from 'node:crypto';

/**
 * A deterministic job id (UUID version 8): SHA-256 of `namespace \0 key`,
 * first 16 bytes, version and variant bits set (RFC 9562). Sending twice
 * with the same id creates one job while the first is kept in the database:
 * one job per business event (an outbox event_id, a pending action).
 */
export function jobIdFor(namespace: string, key: string): string {
  const b = createHash('sha256').update(`${namespace}\0${key}`).digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x80;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Stable offset in [0, spreadSeconds) for a tenant and a job: the same
 *  tenant runs at the same point of each period (fan-outs per tenant). */
export function jitterSeconds(salt: string, tenantId: number, spreadSeconds: number): number {
  const h = createHash('sha256').update(`${salt}:${tenantId}`).digest();
  return h.readUInt32BE(0) % Math.max(1, Math.floor(spreadSeconds));
}
