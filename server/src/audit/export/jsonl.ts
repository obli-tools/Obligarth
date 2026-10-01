// Downloadable export of a tenant's chain (docs: audit-durci §8.6): a JSONL
// file verifiable offline (header, entries with their links, the seals that
// cover the range and their keys, a footer with the SHA-256 of the previous
// lines), or a readable CSV (not verifiable). One tenant per file, one
// million entries at most. Read in the context of the request (the route
// picked it: the tenant's, the global view's, or a deleted tenant's chain).
import { createHash } from 'node:crypto';
import type { Writable } from 'node:stream';
import { db } from '../../db';
import { ed25519PublicPem } from '../merkle';

export const EXPORT_MAX_ENTRIES = 1_000_000;
const PAGE = 5_000;

export interface ExportRange { fromSeq: number; toSeq: number; anchor: { seq: number; hash: string } }

/** The range of an export: explicit numbers, or instants converted, within
 *  [anchor + 1, head]. Empty chain: toSeq < fromSeq. */
export async function exportRange(tenantId: number, p: { fromSeq?: number; toSeq?: number; since?: Date; until?: Date }): Promise<ExportRange> {
  const head = await db('audit_chain_heads').where({ tenant_id: tenantId }).first('last_seq') as { last_seq: string | number } | undefined;
  const anchor = await db('audit_chain_anchors').where({ tenant_id: tenantId }).first('anchor_seq') as { anchor_seq: string | number } | undefined;
  const lo = Number(anchor?.anchor_seq ?? 0) + 1;
  const hi = Number(head?.last_seq ?? 0);
  let fromSeq = Math.max(lo, p.fromSeq ?? lo);
  let toSeq = Math.min(hi, p.toSeq ?? hi);
  if (p.since) {
    const r = await db('audit_logs').where({ tenant_id: tenantId }).andWhere('created_at', '>=', p.since).min({ s: 'chain_seq' }).first() as { s: string | number | null };
    fromSeq = Math.max(fromSeq, r?.s != null ? Number(r.s) : hi + 1);
  }
  if (p.until) {
    const r = await db('audit_logs').where({ tenant_id: tenantId }).andWhere('created_at', '<=', p.until).max({ s: 'chain_seq' }).first() as { s: string | number | null };
    toSeq = Math.min(toSeq, r?.s != null ? Number(r.s) : 0);
  }
  let anchorHash = '0'.repeat(64);
  if (fromSeq <= toSeq) {
    const first = await db('audit_logs').where({ tenant_id: tenantId, chain_seq: fromSeq }).first('prev_hash') as { prev_hash: Buffer } | undefined;
    if (first) anchorHash = first.prev_hash.toString('hex');
  }
  return { fromSeq, toSeq, anchor: { seq: fromSeq - 1, hash: anchorHash } };
}

type EntryRow = { chain_seq: string | number; prev_hash: Buffer; hash: Buffer; body: string };

async function* entryPages(tenantId: number, fromSeq: number, toSeq: number): AsyncGenerator<EntryRow[]> {
  let after = fromSeq - 1;
  while (after < toSeq) {
    const rows = await db('audit_logs').where('tenant_id', tenantId).andWhere('chain_seq', '>', after).andWhere('chain_seq', '<=', toSeq)
      .orderBy('chain_seq').limit(PAGE).select('chain_seq', 'prev_hash', 'hash', 'body') as EntryRow[];
    if (!rows.length) return;
    yield rows;
    after = Number(rows[rows.length - 1].chain_seq);
  }
}

type SealRow = {
  seal_seq: string | number; instance_id: string; sealed_at: Date; leaf_count: number; merkle_root: Buffer; prev_seal_hash: Buffer;
  seal_hash: Buffer; key_id: string; signature: Buffer; tsa_status: string; tsa_token: Buffer | null; tsa_gen_time: Date | null;
  leaf_index: number; chain_seq: string | number; chain_hash: Buffer; proof: Buffer[];
};

/** Lines of a JSONL export, written to `out`; returns the counts. */
export async function writeJsonlExport(out: Writable, p: {
  tenantId: number; tenantSlug: string | null; instance: string; exportedBy: string; range: ExportRange;
}): Promise<{ entries: number; seals: number }> {
  const sha = createHash('sha256');
  const write = (o: unknown): Promise<void> => new Promise((resolve, reject) => {
    const line = `${JSON.stringify(o)}\n`;
    sha.update(line, 'utf8');
    if (out.write(line, 'utf8')) resolve();
    else { out.once('drain', resolve); out.once('error', reject); }
  });
  const { fromSeq, toSeq } = p.range;
  await write({
    type: 'header', format: 'obligarth.audit-export/1', instance: p.instance, tenant: p.tenantId, tenantSlug: p.tenantSlug,
    fromSeq, toSeq, anchor: p.range.anchor, exportedAt: new Date().toISOString(), exportedBy: p.exportedBy,
  });
  let entries = 0;
  if (fromSeq <= toSeq) {
    for await (const rows of entryPages(p.tenantId, fromSeq, toSeq)) {
      for (const r of rows) {
        await write({ type: 'entry', seq: Number(r.chain_seq), prev: r.prev_hash.toString('hex'), hash: r.hash.toString('hex'), body: r.body });
        entries++;
      }
    }
  }
  // Seals whose leaf of the tenant falls in the range, plus the first after it.
  const cols = ['s.seal_seq', 's.instance_id', 's.sealed_at', 's.leaf_count', 's.merkle_root', 's.prev_seal_hash', 's.seal_hash', 's.key_id',
    's.signature', 's.tsa_status', 's.tsa_token', 's.tsa_gen_time', 'l.leaf_index', 'l.chain_seq', 'l.chain_hash', 'l.proof'];
  const seals = fromSeq <= toSeq ? await db('audit_seal_leaves as l').join('audit_seals as s', 's.id', 'l.seal_id')
    .where('l.tenant_id', p.tenantId).andWhere('l.chain_seq', '>=', fromSeq).andWhere('l.chain_seq', '<=', toSeq)
    .orderBy('s.seal_seq').select(...cols) as SealRow[] : [];
  const after = await db('audit_seal_leaves as l').join('audit_seals as s', 's.id', 'l.seal_id')
    .where('l.tenant_id', p.tenantId).andWhere('l.chain_seq', '>', toSeq)
    .orderBy('l.chain_seq').first(...cols) as SealRow | undefined;
  if (after && fromSeq <= toSeq) seals.push(after);
  const keyIds = new Set<string>();
  for (const s of seals) {
    keyIds.add(s.key_id);
    await write({
      type: 'seal',
      seal: {
        seq: Number(s.seal_seq), instance: s.instance_id, sealedAt: new Date(s.sealed_at).toISOString(), leaves: Number(s.leaf_count),
        root: s.merkle_root.toString('hex'), prev: s.prev_seal_hash.toString('hex'), hash: s.seal_hash.toString('hex'), keyId: s.key_id,
        signature: s.signature.toString('hex'),
        tsa: { status: s.tsa_status, genTime: s.tsa_gen_time ? new Date(s.tsa_gen_time).toISOString() : null, token: s.tsa_token ? s.tsa_token.toString('base64') : null },
      },
      leaf: { index: Number(s.leaf_index), seq: Number(s.chain_seq), hash: s.chain_hash.toString('hex'), proof: (s.proof ?? []).map((x) => Buffer.from(x).toString('hex')) },
    });
  }
  if (keyIds.size) {
    const keys = await db('audit_seal_keys').whereIn('key_id', [...keyIds]).orderBy('created_at')
      .select('key_id', 'public_key', 'created_at', 'retired_at') as Array<{ key_id: string; public_key: Buffer; created_at: Date; retired_at: Date | null }>;
    for (const k of keys) {
      await write({
        type: 'key', keyId: k.key_id, algorithm: 'ed25519', publicKey: k.public_key.toString('hex'), publicKeyPem: ed25519PublicPem(k.public_key),
        createdAt: new Date(k.created_at).toISOString(), retiredAt: k.retired_at ? new Date(k.retired_at).toISOString() : null,
      });
    }
  }
  const digest = sha.digest('hex');
  const footer = `${JSON.stringify({ type: 'footer', entries, seals: seals.length, sha256: digest })}\n`;
  await new Promise<void>((resolve) => { if (out.write(footer, 'utf8')) resolve(); else out.once('drain', resolve); });
  return { entries, seals: seals.length };
}

/** A CSV cell: quoted, and a leading formula character neutralised. */
function cell(v: unknown): string {
  let s = v === null || v === undefined ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

/** A readable CSV of the range (not verifiable). */
export async function writeCsvExport(out: Writable, p: { tenantId: number; range: ExportRange }): Promise<{ entries: number }> {
  const write = (line: string): Promise<void> => new Promise((resolve) => {
    if (out.write(line, 'utf8')) resolve(); else out.once('drain', resolve);
  });
  await write(['seq', 'recorded_at', 'occurred_at', 'action', 'outcome', 'criticality', 'actor', 'side', 'role', 'target', 'target_count',
    'reason', 'ticket', 'ip_address'].join(',') + '\n');
  let entries = 0;
  const { fromSeq, toSeq } = p.range;
  let after = fromSeq - 1;
  while (fromSeq <= toSeq && after < toSeq) {
    const rows = await db('audit_logs').where('tenant_id', p.tenantId).andWhere('chain_seq', '>', after).andWhere('chain_seq', '<=', toSeq)
      .orderBy('chain_seq').limit(PAGE) as Array<Record<string, any>>;
    if (!rows.length) break;
    for (const r of rows) {
      let role: string | null = null;
      try { role = (JSON.parse(String(r.body)) as { actor?: { role?: string } }).actor?.role ?? null; } catch { role = null; }
      await write([
        r.chain_seq, new Date(r.created_at).toISOString(), new Date(r.occurred_at).toISOString(), r.action, r.outcome, r.criticality,
        r.actor_label ?? r.actor_ref, r.actor_side, role,
        r.resource_type ? `${r.resource_type}:${r.resource_path ?? ''}` : '', r.target_count, r.reason, r.ticket, r.ip_address,
      ].map(cell).join(',') + '\n');
      entries++;
    }
    after = Number(rows[rows.length - 1].chain_seq);
  }
  return { entries };
}
