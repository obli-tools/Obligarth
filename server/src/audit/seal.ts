// The hourly seal (docs: audit-durci §6.1, §6.5): the chain heads that moved
// since their last seal become the leaves of a Merkle tree (RFC 6962), whose
// root goes into the signed seal message with the instance, the seal number,
// its instant, the leaf count, the previous seal and the key; signed in
// Ed25519 (key of the vault), time-stamped (RFC 3161) when an authority is
// configured, then recorded by obligarth.audit_seal_record, which refuses a
// seal that does not follow the previous one, whose hash does not match its
// fields, or whose leaf names no entry. Each tenant gets its leaf and its
// inclusion proof. A seal without leaf (nothing moved) is made anyway: it
// proves the sealing works. Runs as the job audit.seal (context 'none').
import { createHash, sign } from 'node:crypto';
import { config } from '../config';
import { db } from '../db';
import { logger } from '../utils/logger';
import { inclusionProof, leafData, sealMessage, treeHash } from './merkle';
import { auditMetrics } from './metrics';
import { ensureSealKey } from './sealKeys';
import { requestTimeStamp, TsaError } from './tsa';

let consecutiveTsaFailures = 0;

export interface SealResult {
  seq: number;
  leaves: number;
  tsaStatus: 'ok' | 'disabled' | 'failed';
  keyId: string;
}

type Candidate = { tenant_id: number; chain_seq: string | number; chain_hash: Buffer };

/** The instance's identifier (app_config.instance_id, created by the migration). */
export async function instanceId(): Promise<string> {
  const row = await db('app_config').where({ key: 'instance_id' }).first('value') as { value: string } | undefined;
  if (!row?.value) throw new Error('audit: app_config.instance_id is missing (migration audit_hardening)');
  return row.value;
}

/** One seal of the instance. Retries once when another seal got in first
 *  (40001). Throws on any other failure (the job retries it). */
export async function runSeal(o: { requestId?: string } = {}): Promise<SealResult> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await sealOnce(o);
    } catch (err) {
      if ((err as { code?: unknown }).code === '40001' && attempt === 0) continue;
      throw err;
    }
  }
}

async function sealOnce(o: { requestId?: string }): Promise<SealResult> {
  const candidates = (await db.raw('SELECT tenant_id, chain_seq, chain_hash FROM obligarth.audit_seal_candidates()') as { rows: Candidate[] }).rows;
  const last = await db('audit_seals').orderBy('seal_seq', 'desc').first('seal_seq', 'seal_hash') as
    { seal_seq: string | number; seal_hash: Buffer } | undefined;
  const instance = await instanceId();
  const key = await ensureSealKey({ requestId: o.requestId });

  const leaves = candidates.map((c) => leafData(Number(c.tenant_id), BigInt(c.chain_seq), c.chain_hash));
  const root = treeHash(leaves);
  const seq = Number(last?.seal_seq ?? 0) + 1;
  const prev = last?.seal_hash ?? Buffer.alloc(32);
  const sealedAt = new Date().toISOString();
  const message = sealMessage({ instance, seq, sealedAt, leaves: leaves.length, root, prev, keyId: key.keyId });
  const sealHash = createHash('sha256').update(message, 'utf8').digest();
  const signature = sign(null, Buffer.from(message, 'utf8'), key.privateKey);

  // Time stamp, outside any transaction (§6.5, step 3).
  let tsaStatus: 'ok' | 'disabled' | 'failed' = 'disabled';
  let tsaToken: Buffer | null = null;
  let tsaGenTime: string | null = null;
  if (config.audit.tsaUrl) {
    try {
      const ts = await requestTimeStamp(sealHash, {
        url: config.audit.tsaUrl, timeoutMs: config.audit.tsaTimeoutMs,
        authFile: config.audit.tsaAuthFile || undefined, certSha256: config.audit.tsaCertSha256 || undefined,
      });
      tsaStatus = 'ok';
      tsaToken = ts.token;
      tsaGenTime = ts.genTime;
      consecutiveTsaFailures = 0;
    } catch (err) {
      tsaStatus = 'failed';
      consecutiveTsaFailures++;
      const code = err instanceof TsaError ? err.code : 'error';
      auditMetrics.inc('obligarth_audit_seal_tsa_failures_total', { code });
      logger.warn({ code: 'AUDIT_TSA_FAILED', reason: code, consecutive: consecutiveTsaFailures }, 'audit: seal not time-stamped');
      if (consecutiveTsaFailures === 3) {
        const { raiseJobAlert } = await import('../jobs/alerts');
        await raiseJobAlert({ type: 'job', name: 'audit.seal' }, {
          stableKey: 'audit:tsa-failing',
          severity: 'warning',
          title: 'Audit seals not time-stamped',
          message: `The time-stamping authority failed three seals in a row (${code}).`,
        });
      }
    }
  }

  const leafRows = candidates.map((c, i) => ({
    tenant: Number(c.tenant_id),
    index: i,
    seq: Number(c.chain_seq),
    hash: c.chain_hash.toString('hex'),
    proof: inclusionProof(i, leaves).map((p) => p.toString('hex')),
  }));
  await db.raw('SELECT obligarth.audit_seal_record(?, ?::uuid, ?::timestamptz, ?, ?, ?, ?, ?, ?, ?, ?::timestamptz, ?::jsonb) AS id', [
    seq, instance, sealedAt, root, prev, sealHash, key.keyId, signature, tsaStatus, tsaToken, tsaGenTime, JSON.stringify(leafRows),
  ]);
  auditMetrics.set('obligarth_audit_seal_last_success_timestamp_seconds', Math.floor(Date.now() / 1000));
  auditMetrics.set('obligarth_audit_seal_leaves', leaves.length);
  logger.info({ seq, leaves: leaves.length, tsa: tsaStatus, keyId: key.keyId }, 'audit: seal recorded');
  return { seq, leaves: leaves.length, tsaStatus, keyId: key.keyId };
}
