// Pure verification of a chain and of its seals (docs: audit-durci §6.6,
// §6.7): used by the online verification (verify.ts) and by the offline
// tool (cli.ts verify-export). No database, no network: SHA-256 of the
// stored bodies (never re-serialised), Merkle proofs, Ed25519 signatures.
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { linkHash } from './chain';
import { ED25519_SPKI_PREFIX, leafData, leafHash, sealMessage, verifyInclusion } from './merkle';

export interface ChainEntry {
  seq: number;
  prev: Buffer;
  hash: Buffer;
  body: string;
  /** Columns to compare with the body (online only). */
  tenantId?: number;
  uuid?: string;
  action?: string;
  createdAt?: Date;
}

export interface ChainProblem {
  type: 'gap' | 'prev_mismatch' | 'hash_mismatch' | 'body_unreadable' | 'body_mismatch' | 'head_mismatch'
    | 'seal_leaf_mismatch' | 'seal_proof' | 'seal_hash' | 'seal_signature' | 'seal_chain' | 'seal_key' | 'tsa_imprint'
    | 'targets_digest' | 'anchor_mismatch';
  seq?: number;
  sealSeq?: number;
  message: string;
}

export interface ChainCursor { seq: number; hash: Buffer }

/** Walks `entries` (ascending, contiguous expected) from `start`; returns
 *  the last link and the first problem. Dangling intents are collected
 *  (information, not a break). */
export function walkChain(tenantId: number, start: ChainCursor, entries: readonly ChainEntry[],
  intents?: Map<string, { seq: number; at: Date | null }>): { last: ChainCursor; problem: ChainProblem | null; count: number } {
  let cur = start;
  let count = 0;
  for (const e of entries) {
    if (e.seq !== cur.seq + 1) {
      return { last: cur, count, problem: { type: 'gap', seq: cur.seq + 1, message: `entry ${cur.seq + 1} is missing (next is ${e.seq})` } };
    }
    if (!e.prev.equals(cur.hash)) {
      return { last: cur, count, problem: { type: 'prev_mismatch', seq: e.seq, message: `entry ${e.seq} does not follow the previous one` } };
    }
    const h = linkHash(e.prev, e.seq, e.body);
    if (!h.equals(e.hash)) {
      return { last: cur, count, problem: { type: 'hash_mismatch', seq: e.seq, message: `entry ${e.seq}: its hash does not match its body` } };
    }
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(e.body) as Record<string, unknown>;
    } catch {
      return { last: cur, count, problem: { type: 'body_unreadable', seq: e.seq, message: `entry ${e.seq}: unreadable body` } };
    }
    if (Number(parsed.tenant) !== tenantId
      || (e.uuid !== undefined && String(parsed.id) !== e.uuid)
      || (e.action !== undefined && String(parsed.action) !== e.action)) {
      return { last: cur, count, problem: { type: 'body_mismatch', seq: e.seq, message: `entry ${e.seq}: the body does not match its columns` } };
    }
    if (intents) {
      const links = parsed.links as { intent?: unknown } | undefined;
      if (links && typeof links.intent === 'string') intents.delete(links.intent);
      if (parsed.outcome === 'requested' && parsed.crit === 'critical' && typeof parsed.action === 'string'
        && !String(parsed.action).startsWith('guard.')) {
        intents.set(String(parsed.id), { seq: e.seq, at: e.createdAt ?? null });
      }
    }
    cur = { seq: e.seq, hash: e.hash };
    count++;
  }
  return { last: cur, count, problem: null };
}

export interface SealRecord {
  seq: number;
  instance: string;
  sealedAt: string;
  leaves: number;
  root: Buffer;
  prev: Buffer;
  hash: Buffer;
  keyId: string;
  signature: Buffer;
  tsaStatus?: string;
  tsaImprint?: string | null;
}

export interface SealLeaf { tenantId: number; index: number; seq: number; hash: Buffer; proof: Buffer[] }

/** A raw Ed25519 public key as a KeyObject. */
function publicKeyOf(raw: Buffer) {
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

/** Checks one seal: its hash against the rebuilt message, its signature with
 *  `publicRaw`, the previous seal's hash (when known), a time-stamp imprint,
 *  and (with a leaf) the inclusion proof up to the root. */
export function checkSeal(s: SealRecord, publicRaw: Buffer | null, prevHash: Buffer | null, leaf: SealLeaf | null): ChainProblem | null {
  const message = sealMessage({ instance: s.instance, seq: s.seq, sealedAt: s.sealedAt, leaves: s.leaves, root: s.root, prev: s.prev, keyId: s.keyId });
  const h = createHash('sha256').update(message, 'utf8').digest();
  if (!h.equals(s.hash)) return { type: 'seal_hash', sealSeq: s.seq, message: `seal ${s.seq}: its hash does not match its fields` };
  if (!publicRaw) return { type: 'seal_key', sealSeq: s.seq, message: `seal ${s.seq}: key ${s.keyId} is not trusted` };
  let ok = false;
  try {
    ok = verifySignature(null, Buffer.from(message, 'utf8'), publicKeyOf(publicRaw), s.signature);
  } catch {
    ok = false;
  }
  if (!ok) return { type: 'seal_signature', sealSeq: s.seq, message: `seal ${s.seq}: invalid signature` };
  if (prevHash && !s.prev.equals(prevHash)) return { type: 'seal_chain', sealSeq: s.seq, message: `seal ${s.seq} does not follow seal ${s.seq - 1}` };
  if (s.tsaImprint !== undefined && s.tsaImprint !== null && s.tsaImprint !== s.hash.toString('hex')) {
    return { type: 'tsa_imprint', sealSeq: s.seq, message: `seal ${s.seq}: the time stamp is not of this seal` };
  }
  if (leaf) {
    const lh = leafHash(leafData(leaf.tenantId, leaf.seq, leaf.hash));
    if (!verifyInclusion(leaf.index, s.leaves, lh, leaf.proof, s.root)) {
      return { type: 'seal_proof', sealSeq: s.seq, message: `seal ${s.seq}: the proof of tenant ${leaf.tenantId} does not lead to the root` };
    }
  }
  return null;
}
