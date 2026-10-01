// Online verification of a tenant's chain (docs: audit-durci §6.6): in the
// tenant's context (actor j:audit.verify-tenant; a deleted tenant's chain is
// read the same way, without foreign key it stays in place), from the last
// verification that succeeded (incremental) or from the anchor or the genesis
// (full); every link recomputed from the stored body (never re-serialised),
// the head reached, and the seals new since the previous verification checked
// (leaf against the entry, proof up to the root, seal hash, signature,
// previous seal, time-stamp imprint). One row of audit_verifications per run;
// a break raises critical alerts in the tenant and the master tenant and
// writes audit.chain_broken.
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { db } from '../db';
import { asTenant, type DbActor } from '../db/context';
import { logger } from '../utils/logger';
import { GENESIS_HASH } from './chain';
import { auditMetrics } from './metrics';
import { checkSeal, walkChain, type ChainCursor, type ChainProblem } from './offline';
import { tokenImprint } from './tsa';
import { fromJob } from './actor';
import { append } from './writer';

export const VERIFY_ACTOR: DbActor = { type: 'job', name: 'audit.verify-tenant' };
const PAGE = 5_000;
const DANGLING_INTENT_MS = 15 * 60_000;

export type VerificationKind = 'incremental' | 'full' | 'on_demand';

export interface VerificationOutcome {
  id: number;
  status: 'ok' | 'broken' | 'error';
  entries: number;
  seals: number;
  problem: ChainProblem | null;
  danglingIntents: number[];
}

const brokenChains = new Set<number>();

/** Starts a verification row (the route answers its id at once). */
export async function startVerificationRow(tenantId: number, kind: VerificationKind, requestedBy: number | null): Promise<number> {
  return asTenant(tenantId, VERIFY_ACTOR, async () => {
    const [row] = await db('audit_verifications').insert({
      tenant_id: tenantId, kind, status: 'running', requested_by: requestedBy,
    }).returning('id') as Array<{ id: string | number }>;
    return Number(row.id);
  });
}

/** A verification running (or queued) for the tenant: the route refuses a
 *  second one. */
export async function runningVerification(tenantId: number): Promise<number | null> {
  return asTenant(tenantId, VERIFY_ACTOR, async () => {
    const row = await db('audit_verifications').where({ tenant_id: tenantId, status: 'running' })
      .where('started_at', '>', db.raw("now() - interval '1 hour'")).first('id') as { id: string | number } | undefined;
    return row ? Number(row.id) : null;
  });
}

type LeafRow = {
  seal_seq: string | number; instance_id: string; sealed_at: Date; leaf_count: number; merkle_root: Buffer;
  prev_seal_hash: Buffer; seal_hash: Buffer; key_id: string; signature: Buffer; tsa_status: string; tsa_token: Buffer | null;
  leaf_index: number; chain_seq: string | number; chain_hash: Buffer; proof: Buffer[];
};

/** Verifies a tenant's chain (§6.6). Never throws: an unexpected failure is a
 *  row 'error'. */
export async function verifyTenantChain(tenantId: number, kind: VerificationKind,
  o: { verificationId?: number; requestedBy?: number | null; requestId?: string } = {}): Promise<VerificationOutcome> {
  return asTenant(tenantId, VERIFY_ACTOR, async () => {
    const vid = o.verificationId ?? Number(((await db('audit_verifications').insert({
      tenant_id: tenantId, kind, status: 'running', requested_by: o.requestedBy ?? null,
    }).returning('id')) as Array<{ id: string | number }>)[0].id);
    try {
      const outcome = await verifyInContext(tenantId, kind, vid);
      await finish(tenantId, vid, outcome, o.requestId);
      return outcome;
    } catch (err) {
      logger.error({ code: 'AUDIT_VERIFY_ERROR', tenantId, err: { name: (err as Error).name, code: (err as { code?: unknown }).code } },
        'audit: chain verification failed to run');
      await db('audit_verifications').where({ id: vid }).update({
        status: 'error', finished_at: db.fn.now(), problem: JSON.stringify({ type: 'error', message: 'verification failed to run' }),
      }).catch(() => undefined);
      return { id: vid, status: 'error', entries: 0, seals: 0, problem: null, danglingIntents: [] };
    }
  });
}

async function verifyInContext(tenantId: number, kind: VerificationKind, vid: number): Promise<VerificationOutcome> {
  const head = await db('audit_chain_heads').where({ tenant_id: tenantId }).first('last_seq', 'last_hash') as
    { last_seq: string | number; last_hash: Buffer } | undefined;
  const anchor = await db('audit_chain_anchors').where({ tenant_id: tenantId }).first('anchor_seq', 'anchor_hash') as
    { anchor_seq: string | number; anchor_hash: Buffer } | undefined;
  const anchorCursor: ChainCursor = anchor ? { seq: Number(anchor.anchor_seq), hash: anchor.anchor_hash } : { seq: 0, hash: GENESIS_HASH };

  // Starting point: the last verification that succeeded (incremental), if
  // its entry still has that hash; else the anchor, or the genesis.
  let start = anchorCursor;
  let sealsSince: Date | null = null;
  if (kind === 'incremental') {
    const prev = await db('audit_verifications').where({ tenant_id: tenantId, status: 'ok' }).whereNot({ id: vid })
      .whereNotNull('to_seq').orderBy('id', 'desc').first('to_seq', 'to_hash', 'started_at') as
      { to_seq: string | number; to_hash: Buffer | null; started_at: Date } | undefined;
    if (prev && prev.to_hash && Number(prev.to_seq) > anchorCursor.seq) {
      const e = await db('audit_logs').where({ tenant_id: tenantId, chain_seq: Number(prev.to_seq) }).first('hash') as { hash: Buffer } | undefined;
      if (e && e.hash.equals(prev.to_hash)) {
        start = { seq: Number(prev.to_seq), hash: prev.to_hash };
        sealsSince = prev.started_at;
      }
    }
  }
  const fromSeq = start.seq;
  const headSeq = head ? Number(head.last_seq) : 0;

  // Leaves of the seals to check, and the entries they name.
  const leafQuery = db('audit_seal_leaves as l').join('audit_seals as s', 's.id', 'l.seal_id')
    .where('l.tenant_id', tenantId)
    .orderBy('s.seal_seq')
    .select('s.seal_seq', 's.instance_id', 's.sealed_at', 's.leaf_count', 's.merkle_root', 's.prev_seal_hash', 's.seal_hash',
      's.key_id', 's.signature', 's.tsa_status', 's.tsa_token', 'l.leaf_index', 'l.chain_seq', 'l.chain_hash', 'l.proof');
  if (sealsSince) leafQuery.where('s.recorded_at', '>=', sealsSince);
  const leaves = await leafQuery as LeafRow[];
  const wanted = new Set(leaves.map((l) => Number(l.chain_seq)).filter((s) => s > anchorCursor.seq));
  const seen = new Map<number, Buffer>();

  // The chain, by pages of 5,000.
  const intents = new Map<string, { seq: number; at: Date | null }>();
  let cur = start;
  let entries = 0;
  let problem: ChainProblem | null = null;
  let headHashSeen: Buffer | null = null;
  for (;;) {
    const rows = await db('audit_logs').where('tenant_id', tenantId).andWhere('chain_seq', '>', cur.seq)
      .orderBy('chain_seq').limit(PAGE)
      .select('chain_seq', 'prev_hash', 'hash', 'body', 'uuid', 'action', 'created_at') as
      Array<{ chain_seq: string | number; prev_hash: Buffer; hash: Buffer; body: string; uuid: string; action: string; created_at: Date }>;
    if (!rows.length) break;
    const walk = walkChain(tenantId, cur, rows.map((r) => ({
      seq: Number(r.chain_seq), prev: r.prev_hash, hash: r.hash, body: r.body, uuid: r.uuid, action: r.action, createdAt: r.created_at,
    })), intents);
    for (const r of rows) {
      const s = Number(r.chain_seq);
      if (s > walk.last.seq) break;
      if (wanted.has(s)) seen.set(s, r.hash);
      if (s === headSeq) headHashSeen = r.hash;
    }
    entries += walk.count;
    cur = walk.last;
    if (walk.problem) { problem = walk.problem; break; }
    if (rows.length < PAGE) break;
  }

  // The head read at the start must have been reached, with its hash.
  if (!problem && head && headSeq > anchorCursor.seq) {
    if (cur.seq < headSeq) {
      problem = { type: 'head_mismatch', seq: cur.seq + 1, message: `the chain ends at ${cur.seq}, its head is ${headSeq}` };
    } else if (headHashSeen && !headHashSeen.equals(head.last_hash)) {
      problem = { type: 'head_mismatch', seq: headSeq, message: `entry ${headSeq} is not the head` };
    }
  }

  // Seals new since the previous verification.
  let seals = 0;
  if (!problem && leaves.length) {
    const keys = new Map((await db('audit_seal_keys').select('key_id', 'public_key') as Array<{ key_id: string; public_key: Buffer }>)
      .map((k) => [k.key_id, k.public_key]));
    for (const l of leaves) {
      const sealSeq = Number(l.seal_seq);
      const chainSeq = Number(l.chain_seq);
      if (chainSeq > anchorCursor.seq) {
        let h = seen.get(chainSeq);
        if (!h) {
          const e = await db('audit_logs').where({ tenant_id: tenantId, chain_seq: chainSeq }).first('hash') as { hash: Buffer } | undefined;
          h = e?.hash;
        }
        if (!h) { problem = { type: 'seal_leaf_mismatch', sealSeq, seq: chainSeq, message: `seal ${sealSeq}: sealed entry ${chainSeq} is missing` }; break; }
        if (!h.equals(l.chain_hash)) { problem = { type: 'seal_leaf_mismatch', sealSeq, seq: chainSeq, message: `seal ${sealSeq}: entry ${chainSeq} is not the sealed one` }; break; }
      }
      const prevSeal = sealSeq > 1
        ? await db('audit_seals').where({ seal_seq: sealSeq - 1 }).first('seal_hash') as { seal_hash: Buffer } | undefined
        : { seal_hash: Buffer.alloc(32) };
      const p = checkSeal({
        seq: sealSeq, instance: String(l.instance_id), sealedAt: new Date(l.sealed_at).toISOString(), leaves: Number(l.leaf_count),
        root: l.merkle_root, prev: l.prev_seal_hash, hash: l.seal_hash, keyId: l.key_id, signature: l.signature,
        tsaImprint: l.tsa_token ? tokenImprint(l.tsa_token) ?? 'unreadable' : null,
      }, keys.get(l.key_id) ?? null, prevSeal?.seal_hash ?? null, {
        tenantId, index: Number(l.leaf_index), seq: chainSeq, hash: l.chain_hash, proof: (l.proof ?? []).map((x) => Buffer.from(x)),
      });
      if (p) { problem = p; break; }
      seals++;
    }
  }

  const now = Date.now();
  const dangling = [...intents.values()].filter((i) => i.at && now - i.at.getTime() > DANGLING_INTENT_MS).map((i) => i.seq);
  await db('audit_verifications').where({ id: vid }).update({
    from_seq: fromSeq, to_seq: problem ? null : cur.seq, to_hash: problem ? null : cur.hash,
    entries, seals,
  });
  return { id: vid, status: problem ? 'broken' : 'ok', entries, seals, problem, danglingIntents: dangling };
}

async function finish(tenantId: number, vid: number, out: VerificationOutcome, requestId?: string): Promise<void> {
  const problem = out.problem
    ? { ...out.problem }
    : (out.danglingIntents.length ? { info: { danglingIntents: out.danglingIntents.slice(0, 100) } } : null);
  await db('audit_verifications').where({ id: vid }).update({
    status: out.status, finished_at: db.fn.now(), problem: problem ? JSON.stringify(problem) : null,
  });
  const ctx = fromJob({ name: VERIFY_ACTOR.type === 'job' ? VERIFY_ACTOR.name : 'audit.verify-tenant', requestId: requestId ?? `verify-${vid}` });
  const kind = (await db('audit_verifications').where({ id: vid }).first('kind') as { kind: string } | undefined)?.kind;
  // A deleted tenant's chain takes no entry any more: its entries go to the
  // master tenant's chain, naming it.
  const exists = await db('tenants').where({ id: tenantId }).first('id').catch(() => undefined);
  if (out.status === 'broken') {
    brokenChains.add(tenantId);
    auditMetrics.set('obligarth_audit_broken_chains', brokenChains.size);
    logger.error({ code: 'AUDIT_CHAIN_BROKEN', tenantId, problem: out.problem?.type, seq: out.problem?.seq, sealSeq: out.problem?.sealSeq },
      'audit: chain verification found a break');
    const details = { verificationId: vid, problem: out.problem?.type, seq: out.problem?.seq ?? null, sealSeq: out.problem?.sealSeq ?? null };
    if (exists) await append({ tenantId, action: 'audit.chain_broken', outcome: 'failure', details }, ctx);
    await append({ tenantId: MASTER_TENANT_ID, action: 'audit.chain_broken', outcome: 'failure', onBehalfOf: tenantId === MASTER_TENANT_ID ? undefined : tenantId, details: { ...details, tenantId } }, ctx);
    const { raiseJobAlert } = await import('../jobs/alerts');
    await raiseJobAlert(VERIFY_ACTOR, {
      stableKey: `audit:broken:${tenantId}`, severity: 'critical',
      title: 'Audit chain broken',
      message: `The audit chain of tenant ${tenantId} failed its verification (${out.problem?.type ?? 'unknown'}).`,
    });
    if (exists && tenantId !== MASTER_TENANT_ID) {
      const { liveAlertService } = await import('../services/liveAlert.service');
      await liveAlertService.add(tenantId, {
        severity: 'critical', title: 'Audit chain broken',
        message: `The audit log failed its integrity verification (${out.problem?.type ?? 'unknown'}).`,
        navigateTo: '/admin/security?tab=audit', stableKey: `audit:broken:${tenantId}`,
      }).catch(() => undefined);
    }
  } else if (out.status === 'ok') {
    if (brokenChains.delete(tenantId)) auditMetrics.set('obligarth_audit_broken_chains', brokenChains.size);
  }
  if (kind === 'on_demand') {
    const details = { verificationId: vid, status: out.status, entries: out.entries, seals: out.seals };
    await append(exists
      ? { tenantId, action: 'audit.verified', outcome: out.status === 'ok' ? 'success' : 'failure', details }
      : { tenantId: MASTER_TENANT_ID, action: 'audit.verified', outcome: out.status === 'ok' ? 'success' : 'failure', onBehalfOf: tenantId,
        details: { ...details, tenantId } }, ctx);
  }
}
