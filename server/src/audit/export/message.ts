// The common message of the SIEM export (docs: audit-durci §8.2): one JSON
// object per entry, seal, signal or test, on one line. The exact body (the
// proof) travels as a JSON string; `event` is the parsed copy for the
// indexing, dropped when the message would exceed the destination's limit.

export const SCHEMA = 'obligarth.audit/1';

export interface EntryMessageInput {
  instance: string;
  tenant: number;
  tenantSlug: string | null;
  seq: number;
  prev: string;
  hash: string;
  body: string;
}

export interface SealMessageLeaf { tenant: number; index: number; seq: number; hash: string; proof: string[] }

export interface SealMessageInput {
  instance: string;
  seq: number;
  sealedAt: string;
  leaves: number;
  root: string;
  prev: string;
  hash: string;
  keyId: string;
  signature: string;
  tsa: { status: string; genTime: string | null; token: string | null };
  leafList: SealMessageLeaf[];
}

/** An entry message, `event` included unless it would exceed `maxBytes`. */
export function entryMessage(m: EntryMessageInput, o: { includeEvent: boolean; maxBytes?: number }): string {
  const base = {
    schema: SCHEMA, type: 'entry', instance: m.instance, tenant: m.tenant, tenantSlug: m.tenantSlug,
    seq: m.seq, prev: m.prev, hash: m.hash, body: m.body,
  };
  if (o.includeEvent) {
    let event: unknown = null;
    try { event = JSON.parse(m.body); } catch { event = null; }
    const full = JSON.stringify({ ...base, event });
    if (o.maxBytes === undefined || Buffer.byteLength(full, 'utf8') <= o.maxBytes) return full;
    return JSON.stringify({ ...base, truncated: 'event' });
  }
  return JSON.stringify(base);
}

/** A seal message; a destination of one tenant only gets that tenant's leaf. */
export function sealMessageOf(m: SealMessageInput, scopeTenantId: number | null): string {
  const leaves = scopeTenantId === null ? m.leafList : m.leafList.filter((l) => l.tenant === scopeTenantId);
  return JSON.stringify({
    schema: SCHEMA, type: 'seal', instance: m.instance,
    seal: {
      seq: m.seq, sealedAt: m.sealedAt, leaves: m.leaves, root: m.root, prev: m.prev, hash: m.hash, keyId: m.keyId,
      signature: m.signature, tsa: m.tsa,
    },
    leaves,
  });
}

/** Entries purged before a destination received them (a destination that is
 *  not required for the purge only). */
export function gapMessage(instance: string, tenant: number, fromSeq: number, toSeq: number): string {
  return JSON.stringify({ schema: SCHEMA, type: 'gap', instance, tenant, fromSeq, toSeq, reason: 'purged_before_export' });
}

export function testMessage(instance: string, destination: string): string {
  return JSON.stringify({ schema: SCHEMA, type: 'test', instance, destination, sentAt: new Date().toISOString() });
}

/** Syslog severity (RFC 5424) of a message: 4 for a denied or failed
 *  action, 5 for a critical entry, a seal or a signal, 6 otherwise. */
export function severityOf(message: string): number {
  try {
    const m = JSON.parse(message) as { type?: string; body?: string };
    if (m.type !== 'entry') return 5;
    const b = JSON.parse(String(m.body)) as { outcome?: string; crit?: string };
    if (b.outcome === 'denied' || b.outcome === 'failure') return 4;
    return b.crit === 'critical' ? 5 : 6;
  } catch {
    return 6;
  }
}
