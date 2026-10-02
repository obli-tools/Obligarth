// Commands of the audit journal (docs: audit-durci §5.5, §6.7, §7.5), in the
// server's image:
//   node dist/src/audit/cli.js <command> [options]      (image: docker compose run --rm server …)
//   npx tsx src/audit/cli.ts <command> [options]        (development)
//
//   verify-export --file <export.jsonl> --trusted-key <id> [--trusted-key <id>…]
//                 [--tsa-ca <authority.pem>] [--require-seal]
//       offline, without database nor network: the footer, the chain from the
//       anchor, the seals (signature by a TRUSTED key only, proof, chain of
//       the seals, time-stamp imprint; with --tsa-ca the CMS signature of the
//       tokens by OpenSSL), the target digests. JSON report on the output.
//       Exit 0 intact, 2 broken, 1 error.
//   spool-import --dir <folder>
//       with the administration DSN (DATABASE_ADMIN_URL, the server-migrate
//       service): imports the spooled or rejected bodies of the folder without
//       the time window; journaled (audit.spool_replayed, forced). Exit 0, 1.
//   restore-reconcile [--siem-heads <file.json>]
//       after a restore (server in JOBS_MODE=paused): one audit.chain_resumed
//       per chain (restored head, range lost, last head known by the SIEM or
//       'unknown'), an immediate seal, export cursors brought back to the
//       restored heads. Runs as the server does (runtime role, signed contexts
//       with RLS_CONTEXT_KEY_FILE, the vault's KEK). Exit 0, 1.
//
// The trusted key ids come from elsewhere (the console's seal keys page, the
// seal messages received by the SIEM): the keys inside a file only prove its
// internal consistency.
import '../env';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { canonicalJson } from './canonical';
import { GENESIS_HASH } from './chain';
import { sealKeyId, sealMessage } from './merkle';
import { checkSeal, walkChain, type ChainEntry, type ChainProblem } from './offline';
import { tokenImprint } from './tsa';
import { targetsDigest } from './body';

class CliExit extends Error {
  constructor(readonly code: number, message: string) {
    super(message);
  }
}

function out(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, process.stdout.isTTY ? 2 : undefined)}\n`);
}

function arg(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function args(all: string[], name: string): string[] {
  const res: string[] = [];
  all.forEach((a, i) => { if (a === name && all[i + 1] !== undefined) res.push(all[i + 1]); });
  return res;
}

const HEX64 = /^[0-9a-f]{64}$/;

// ── verify-export ───────────────────────────────────────────────────────────

export interface ExportReport {
  ok: boolean;
  tenant: number | null;
  fromSeq: number | null;
  toSeq: number | null;
  entries: number;
  seals: number;
  sealsVerified: number;
  coveredThrough: number;
  trustedKeys: string[];
  tsa: { checked: number; ok: number };
  problems: ChainProblem[];
}

/** The offline verification of an export (pure but for the optional
 *  OpenSSL check of the time stamps). */
export function verifyExportText(text: string, o: { trustedKeys: string[]; requireSeal?: boolean; tsaCaPem?: string }): ExportReport {
  const problems: ChainProblem[] = [];
  const report: ExportReport = {
    ok: false, tenant: null, fromSeq: null, toSeq: null, entries: 0, seals: 0, sealsVerified: 0, coveredThrough: 0,
    trustedKeys: [...o.trustedKeys], tsa: { checked: 0, ok: 0 }, problems,
  };
  const raw = text.split('\n');
  if (raw[raw.length - 1] === '') raw.pop();
  if (raw.length < 2) throw new CliExit(1, 'verify-export: not an export (too short)');
  const lines = raw.map((l, i) => {
    try { return JSON.parse(l) as Record<string, any>; } catch { throw new CliExit(1, `verify-export: line ${i + 1} is not JSON`); }
  });
  const header = lines[0];
  const footer = lines[lines.length - 1];
  if (header.type !== 'header' || header.format !== 'obligarth.audit-export/1') throw new CliExit(1, 'verify-export: no export header');
  if (footer.type !== 'footer') {
    problems.push({ type: 'gap', message: 'the export has no footer (truncated file)' });
    return report;
  }
  // The footer: SHA-256 of every previous line, line feeds included.
  const sha = createHash('sha256');
  for (const l of raw.slice(0, -1)) sha.update(`${l}\n`, 'utf8');
  if (sha.digest('hex') !== footer.sha256) problems.push({ type: 'hash_mismatch', message: 'the footer digest does not match the file' });

  const tenant = Number(header.tenant);
  report.tenant = tenant;
  report.fromSeq = Number(header.fromSeq);
  report.toSeq = Number(header.toSeq);
  const anchorHash = typeof header.anchor?.hash === 'string' && HEX64.test(header.anchor.hash) ? Buffer.from(header.anchor.hash, 'hex') : GENESIS_HASH;
  const entries: ChainEntry[] = [];
  const bySeq = new Map<number, Buffer>();
  const bodies: Array<Record<string, any>> = [];
  for (const l of lines) {
    if (l.type !== 'entry') continue;
    if (!HEX64.test(String(l.prev)) || !HEX64.test(String(l.hash)) || typeof l.body !== 'string') {
      problems.push({ type: 'body_unreadable', seq: Number(l.seq), message: `entry ${l.seq}: malformed line` });
      continue;
    }
    entries.push({ seq: Number(l.seq), prev: Buffer.from(l.prev, 'hex'), hash: Buffer.from(l.hash, 'hex'), body: l.body });
    bySeq.set(Number(l.seq), Buffer.from(l.hash, 'hex'));
    try { bodies.push(JSON.parse(l.body)); } catch { /* reported by the walk */ }
  }
  report.entries = entries.length;
  if (entries.length !== Number(footer.entries)) problems.push({ type: 'gap', message: `the footer announces ${footer.entries} entries, the file holds ${entries.length}` });
  if (entries.length) {
    if (entries[0].seq !== report.fromSeq) problems.push({ type: 'gap', seq: entries[0].seq, message: 'the first entry is not the first of the range' });
    if (entries[entries.length - 1].seq !== report.toSeq) problems.push({ type: 'gap', seq: entries[entries.length - 1].seq, message: 'the last entry is not the last of the range' });
    const walk = walkChain(tenant, { seq: Number(header.anchor?.seq ?? entries[0].seq - 1), hash: anchorHash }, entries);
    if (walk.problem) problems.push(walk.problem);
  }

  // Target digests of the large lists (§3.6).
  for (const b of bodies) {
    const t = b?.targets as { digest?: string; chunks?: number; count?: number } | undefined;
    if (!t?.digest) continue;
    const ids: number[] = [];
    for (const c of bodies) {
      // A continuation names its entry's action (details.of_action): two
      // entries of one guarded action (request, execution) share links.action.
      if ((c?.action === 'audit.targets' || c?.action === 'guard.action_targets') && c?.links?.action === (b?.links?.action ?? b?.id)
        && (c?.details?.of_action === undefined || c.details.of_action === b?.action) && Array.isArray(c?.targets?.devices)) ids.push(...c.targets.devices);
    }
    if (ids.length === Number(t.count) && targetsDigest(ids) !== t.digest) {
      problems.push({ type: 'targets_digest', message: `entry ${String(b.id)}: its target digest does not match its continuation entries` });
    }
  }

  // Keys: the identifier is the key's own digest; only trusted ids sign.
  const keys = new Map<string, Buffer>();
  for (const l of lines) {
    if (l.type !== 'key') continue;
    const pub = typeof l.publicKey === 'string' && /^[0-9a-f]{64}$/.test(l.publicKey) ? Buffer.from(l.publicKey, 'hex') : null;
    if (!pub || sealKeyId(pub) !== l.keyId) {
      problems.push({ type: 'seal_key', message: `key ${String(l.keyId)}: its identifier is not the digest of its public key` });
      continue;
    }
    keys.set(String(l.keyId), pub);
  }
  const trusted = new Set(o.trustedKeys);
  let prevSeal: { seq: number; hash: Buffer } | null = null;
  let tsaDir: string | null = null;
  for (const l of lines) {
    if (l.type !== 'seal') continue;
    report.seals++;
    const s = l.seal as Record<string, any>;
    const leaf = l.leaf as Record<string, any>;
    const rec = {
      seq: Number(s.seq), instance: String(s.instance ?? header.instance), sealedAt: String(s.sealedAt), leaves: Number(s.leaves),
      root: Buffer.from(String(s.root), 'hex'), prev: Buffer.from(String(s.prev), 'hex'), hash: Buffer.from(String(s.hash), 'hex'),
      keyId: String(s.keyId), signature: Buffer.from(String(s.signature), 'hex'),
      tsaImprint: s.tsa?.token ? tokenImprint(Buffer.from(String(s.tsa.token), 'base64')) ?? 'unreadable' : null,
    };
    const pub = trusted.has(rec.keyId) ? keys.get(rec.keyId) ?? null : null;
    const prevHash = prevSeal && prevSeal.seq === rec.seq - 1 ? prevSeal.hash : null;
    const lf = { tenantId: tenant, index: Number(leaf.index), seq: Number(leaf.seq), hash: Buffer.from(String(leaf.hash), 'hex'), proof: (leaf.proof ?? []).map((p: string) => Buffer.from(p, 'hex')) };
    const p = checkSeal(rec, pub, prevHash, lf);
    if (p) problems.push(p);
    else report.sealsVerified++;
    const inFile = bySeq.get(lf.seq);
    if (lf.seq >= Number(report.fromSeq) && lf.seq <= Number(report.toSeq)) {
      if (!inFile || !inFile.equals(lf.hash)) problems.push({ type: 'seal_leaf_mismatch', sealSeq: rec.seq, seq: lf.seq, message: `seal ${rec.seq}: entry ${lf.seq} is not the sealed one` });
    }
    if (!p) report.coveredThrough = Math.max(report.coveredThrough, lf.seq);
    prevSeal = { seq: rec.seq, hash: rec.hash };
    if (o.tsaCaPem && s.tsa?.token) {
      report.tsa.checked++;
      tsaDir ??= mkdtempSync(path.join(tmpdir(), 'obligarth-tsa-'));
      const msg = sealMessage({ instance: rec.instance, seq: rec.seq, sealedAt: rec.sealedAt, leaves: rec.leaves, root: rec.root, prev: rec.prev, keyId: rec.keyId });
      const mf = path.join(tsaDir, `m${rec.seq}.txt`);
      const tf = path.join(tsaDir, `t${rec.seq}.der`);
      const cf = path.join(tsaDir, 'ca.pem');
      writeFileSync(mf, msg);
      writeFileSync(tf, Buffer.from(String(s.tsa.token), 'base64'));
      writeFileSync(cf, o.tsaCaPem);
      const r = spawnSync('openssl', ['ts', '-verify', '-data', mf, '-in', tf, '-CAfile', cf], { encoding: 'utf8' });
      if (r.error) throw new CliExit(1, 'verify-export: --tsa-ca needs the openssl command');
      if (r.status === 0 && /Verification: OK/.test(`${r.stdout}${r.stderr}`)) report.tsa.ok++;
      else problems.push({ type: 'tsa_imprint', sealSeq: rec.seq, message: `seal ${rec.seq}: the time stamp does not verify against the authority` });
    }
  }
  if (tsaDir) rmSync(tsaDir, { recursive: true, force: true });
  if (!trusted.size) problems.push({ type: 'seal_key', message: 'no trusted key given (--trusted-key)' });
  if (o.requireSeal && entries.length && report.coveredThrough < Number(report.toSeq)) {
    problems.push({ type: 'seal_leaf_mismatch', seq: report.coveredThrough + 1, message: `entries after ${report.coveredThrough} are covered by no verified seal` });
  }
  report.ok = problems.length === 0;
  return report;
}

async function verifyExport(all: string[]): Promise<number> {
  const file = arg(all, '--file');
  if (!file) throw new CliExit(1, 'verify-export: --file <export.jsonl> is required');
  const trustedKeys = args(all, '--trusted-key').map((k) => k.trim().toLowerCase());
  if (trustedKeys.some((k) => !/^[0-9a-f]{16}$/.test(k))) throw new CliExit(1, 'verify-export: --trusted-key takes a key id (16 hexadecimal characters)');
  const ca = arg(all, '--tsa-ca');
  const report = verifyExportText(readFileSync(file, 'utf8'), {
    trustedKeys, requireSeal: all.includes('--require-seal'), tsaCaPem: ca ? readFileSync(ca, 'utf8') : undefined,
  });
  out(report);
  return report.ok ? 0 : 2;
}

// ── spool-import ────────────────────────────────────────────────────────────

async function spoolImport(all: string[]): Promise<number> {
  const dir = arg(all, '--dir');
  if (!dir) throw new CliExit(1, 'spool-import: --dir <folder> is required');
  const adminUrl = process.env.DATABASE_ADMIN_URL;
  if (!adminUrl) throw new CliExit(1, 'spool-import: DATABASE_ADMIN_URL (the administration DSN of server-migrate) is required');
  const { readSpoolFile, rejectedFiles, rewriteSpoolFile } = await import('./spool');
  const { buildBody } = await import('./body');
  const pg = (await import('pg')).default;
  const client = new pg.Client({ connectionString: adminUrl, application_name: 'obligarth-audit-spool-import' });
  await client.connect();
  let imported = 0;
  let duplicates = 0;
  let refused = 0;
  let oldest: string | null = null;
  try {
    await client.query('SET ROLE obligarth_owner');
    for (const file of rejectedFiles(path.resolve(dir))) {
      const { lines } = readSpoolFile(file);
      const kept = [];
      for (const l of lines) {
        try {
          await client.query('SELECT * FROM obligarth.audit_append($1)', [l.body]);
          imported++;
          const ts = /"ts":"([0-9T:.\-]+Z)"/.exec(l.body)?.[1] ?? null;
          if (ts && (oldest === null || ts < oldest)) oldest = ts;
        } catch (err) {
          if ((err as { code?: string }).code === '23505') { duplicates++; continue; }
          refused++;
          kept.push(l);
        }
      }
      rewriteSpoolFile(file, kept);
    }
    if (imported > 0) {
      const b = buildBody({
        tenantId: MASTER_TENANT_ID, action: 'audit.spool_replayed',
        details: { count: imported, oldestTs: oldest, duplicates, refused, forced: true },
      }, { actor: { type: 'job', ref: 'j:audit.spool-import', side: 'system' }, origin: { requestId: 'cli' } }, { criticality: 'standard' });
      await client.query('SELECT * FROM obligarth.audit_append($1)', [b.text]);
    }
  } finally {
    await client.end().catch(() => undefined);
  }
  out({ imported, duplicates, refused });
  return refused ? 1 : 0;
}

// ── restore-reconcile ───────────────────────────────────────────────────────

async function restoreReconcile(all: string[]): Promise<number> {
  const headsFile = arg(all, '--siem-heads');
  let siem: Record<string, { seq: number; hash: string }> = {};
  if (headsFile) {
    const parsed = JSON.parse(readFileSync(headsFile, 'utf8')) as unknown;
    if (Array.isArray(parsed)) for (const h of parsed as Array<{ tenant: number; seq: number; hash: string }>) siem[String(h.tenant)] = { seq: Number(h.seq), hash: String(h.hash) };
    else siem = parsed as typeof siem;
  }
  const { db } = await import('../db');
  const { asNone, asTenant, configureContextSigningFromFile } = await import('../db/context');
  const { config } = await import('../config');
  // Signed database context (rls-tenant §4.6, R12): this command queries as the runtime role, like the server.
  try {
    configureContextSigningFromFile(config.rlsContextKeyFile);
  } catch (err) {
    throw new CliExit(1, (err as Error).message);
  }
  const { vault, vaultConfigErrors, VaultStartupError } = await import('../vault');
  const { registerAuditModule } = await import('./module');
  const { append } = await import('./writer');
  const { fromJob } = await import('./actor');
  const { runSeal } = await import('./seal');
  registerAuditModule();
  const actor = { type: 'job' as const, name: 'audit.restore-reconcile' };
  const errors = vaultConfigErrors({ warn: () => undefined });
  if (errors.length) throw new CliExit(1, errors.join('\n'));
  try {
    await asNone(actor, () => vault.init());
  } catch (err) {
    if (err instanceof VaultStartupError) throw new CliExit(1, err.refusal);
    throw err;
  }
  const report: Array<Record<string, unknown>> = [];
  try {
    const chains = (await asNone(actor, () => db.raw('SELECT tenant_id, last_seq, tenant_exists FROM obligarth.audit_chains()')) as {
      rows: Array<{ tenant_id: number; last_seq: string | number; tenant_exists: boolean }>;
    }).rows;
    const ctx = fromJob({ name: actor.name, requestId: `restore-${new Date().toISOString()}` });
    for (const c of chains) {
      const tenantId = Number(c.tenant_id);
      const head = await asTenant(tenantId, actor, () => db('audit_chain_heads').where({ tenant_id: tenantId }).first('last_seq', 'last_hash')) as
        { last_seq: string | number; last_hash: Buffer } | undefined;
      const known = siem[String(tenantId)];
      const restored = { seq: Number(head?.last_seq ?? 0), hash: head ? head.last_hash.toString('hex') : '0'.repeat(64) };
      const details = {
        restoredHead: restored,
        lastKnownHead: known ? { seq: Number(known.seq), hash: String(known.hash) } : 'unknown',
        lostRange: known && Number(known.seq) > restored.seq ? { fromSeq: restored.seq + 1, toSeq: Number(known.seq) } : null,
      };
      const chain = c.tenant_exists ? tenantId : MASTER_TENANT_ID;
      await (c.tenant_exists ? asTenant(tenantId, actor, () => append({ tenantId, action: 'audit.chain_resumed', details }, ctx))
        : asNone(actor, () => append({ tenantId: MASTER_TENANT_ID, action: 'audit.chain_resumed', onBehalfOf: tenantId, details: { ...details, tenantId } }, ctx)));
      // Cursors beyond the restored head come back to it (the SIEM sees the
      // fork, documented by the entry above).
      const moved = await asNone(actor, () => db('audit_export_cursors').where({ tenant_id: tenantId }).andWhere('last_seq', '>', restored.seq)
        .update({ last_seq: restored.seq }));
      report.push({ tenantId, chain, ...details, cursorsMovedBack: Number(moved) });
    }
    const maxSeal = await asNone(actor, () => db('audit_seals').max({ s: 'seal_seq' }).first()) as { s: string | number | null } | undefined;
    await asNone(actor, () => db('audit_export_destinations').where('last_seal_seq', '>', Number(maxSeal?.s ?? 0))
      .update({ last_seal_seq: Number(maxSeal?.s ?? 0) }));
    const seal = await asNone({ type: 'job', name: 'audit.seal' }, () => runSeal({ requestId: 'restore-reconcile' }));
    out({ chains: report, seal });
  } finally {
    await vault.close().catch(() => undefined);
    await db.destroy().catch(() => undefined);
  }
  return 0;
}

const COMMANDS: Record<string, (args: string[]) => Promise<number>> = {
  'verify-export': verifyExport,
  'spool-import': spoolImport,
  'restore-reconcile': restoreReconcile,
};

async function main(): Promise<number> {
  const [command, ...rest] = process.argv.slice(2);
  const run = command ? COMMANDS[command] : undefined;
  if (!run) {
    process.stderr.write(`usage: audit <${Object.keys(COMMANDS).join(' | ')}> [options]\n`);
    return 1;
  }
  return run(rest);
}

if (require.main === module) {
  main().then((code) => { process.exitCode = code; }, (err) => {
    if (err instanceof CliExit) {
      process.stderr.write(`${err.message}\n`);
      process.exitCode = err.code;
    } else {
      process.stderr.write(`${(err as Error)?.message ?? String(err)}\n`);
      process.exitCode = 1;
    }
  });
}

/** For the unit tests. */
export const cliInternals = { canonicalJson };
