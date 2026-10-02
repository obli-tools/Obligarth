// Commands of the vault (docs: coffre-secrets §11.2), in the server's image:
//   node dist/src/vault/cli.js <command> [options]      (image: docker compose run --rm server …)
//   npx tsx src/vault/cli.ts <command> [options]        (development)
//
//   status                                   state of the vault (JSON)              0
//   check-kek --file <f> [--database]        kek_id of a file; with --database,     0 same, 2 different
//                                            compared with data_keys
//   verify [--tenant <id>] [--full]          every DEK unwraps; one sealed value     0, 2 failures
//                                            per column and DEK opens (--full: all)
//   backfill                                 backfill of the inherited secrets      0, 1
//   dek-rotate --operation <uuid>            a DEK rotation, in the foreground      0, 1
//   kek-rotate --operation <uuid>            SERVER STOPPED: rewraps every DEK      0; 4 server running;
//              [--resume] [--dry-run]        under the new KEK (SERVER_KEK_FILE),    5 not authorized; 1 other
//                                            the previous one in SERVER_KEK_PREVIOUS_FILE
//   recover-lost-kek --confirm-lost <id>     SERVER STOPPED: the KEK is lost and     0, 4, 1
//                                            not escrowed; every sealed value is
//                                            dropped, new keys under SERVER_KEK_FILE
//   escrow split --kek server=<f> [--kek edge=<f>] [--extra <name>=<f>]      0, 2, 1
//                [--threshold 2] [--shares 3]   the escrow bundle in printed shares
//   escrow combine --out-dir <dir>           shares on stdin: the keys rebuilt     0, 2, 1
//                                            into <dir> (never over a file)
//   escrow verify --expect server=<kek_id> [--expect edge=<kek_id>]               0, 2, 1
//                                            shares on stdin, nothing written
//
// The escrow commands (vault/escrow.ts, coffre-secrets §9.2) need neither the
// database nor the network (`docker run --network none`); they alone load the
// Shamir library. "Server stopped": the command takes the vault's online lock
// exclusively (vault/lock.ts). Never a value, a key or a sealed value on the
// output: identifiers, kek_ids, counts (escrow split prints the shares, which
// is its purpose). The commands that query the database run as the runtime
// role with signed contexts (RLS_CONTEXT_KEY_FILE, rls-tenant §4.6).
import '../env';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { config } from '../config';
import { db } from '../db';
import { asNone, configureContextSigningFromFile, type DbActor } from '../db/context';
import { auditService } from '../services/audit.service';
import { withVaultIntent } from './events';
import { logger } from '../utils/logger';
import { registerDeviceModule } from '../modules/devices';
import { backfillLegacySecrets, vault, vaultConfigErrors } from './index';
import { readVaultConfig } from './config';
import { isVaultError } from './errors';
import { FileKekProvider, inspectKekFile, readKekFile } from './kek';
import { tryExclusiveOnlineLock } from './lock';
import { operationError, vaultOperations } from './operations';
import { secretColumns } from './registry';
import { runDekRotation } from './reseal';
import { scopesOf } from './scopes';
import { verifyVault } from './verify';
import { vaultInternals, VaultStartupError } from './vault';

const CLI_ACTOR: DbActor = { type: 'job', name: 'vault.cli' };
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEK_ID_RE = /^[0-9a-f]{16}$/;

class CliExit extends Error {
  constructor(readonly code: number, message: string) {
    super(message);
  }
}

/** The result of a command: indented on a terminal, one line otherwise (next
 *  to the server's JSON log lines, for a script). */
function out(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, process.stdout.isTTY ? 2 : undefined)}\n`);
}

function arg(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function requireConfig(): void {
  const errors = vaultConfigErrors({ warn: (m) => logger.warn(m) });
  if (errors.length) throw new CliExit(1, errors.join('\n'));
}

async function init(): Promise<void> {
  requireConfig();
  try {
    await asNone(CLI_ACTOR, () => vault.init());
  } catch (err) {
    if (err instanceof VaultStartupError) throw new CliExit(1, err.refusal);
    throw err;
  }
}

/** The exclusive online lock, or exit 4 while a server holds it. */
async function offline(): Promise<{ release: () => Promise<void> }> {
  const client = await tryExclusiveOnlineLock(config.databaseUrl);
  if (!client) throw new CliExit(4, 'A server holds the vault lock: stop it first (docker compose stop server).');
  return { release: () => client.end().catch(() => undefined) };
}

async function master(action: string, details: Record<string, unknown>, resourcePath?: string): Promise<void> {
  await asNone(CLI_ACTOR, () => auditService.log({
    tenantId: MASTER_TENANT_ID, action, resourceType: 'vault_operation', resourcePath, details: { ...details, via: 'cli' },
  }));
}

// ── Commands ────────────────────────────────────────────────────────────────

async function status(): Promise<number> {
  await init();
  out(await asNone(CLI_ACTOR, () => vault.status()));
  return 0;
}

async function checkKek(args: string[]): Promise<number> {
  const file = arg(args, '--file');
  if (!file) throw new CliExit(1, 'check-kek: --file <path> is required');
  const check = inspectKekFile(file);
  if (!check.ok) throw new CliExit(1, `check-kek: ${check.reason}`);
  check.kek.key.fill(0);
  if (!args.includes('--database')) {
    out({ kekId: check.kek.id });
    return 0;
  }
  const rows = await asNone(CLI_ACTOR, () => db('data_keys').whereNotNull('dek_wrapped').distinct('kek_id')) as Array<{ kek_id: string }>;
  const ids = rows.map((r) => r.kek_id).sort();
  const same = ids.length > 0 && ids.every((id) => id === check.kek.id);
  out({ kekId: check.kek.id, database: ids, match: same });
  return same ? 0 : 2;
}

async function verify(args: string[]): Promise<number> {
  await init();
  const t = arg(args, '--tenant');
  const tenantId = t === undefined ? undefined : Number(t);
  if (tenantId !== undefined && !(Number.isSafeInteger(tenantId) && tenantId > 0)) throw new CliExit(1, 'verify: --tenant <id>');
  const report = await verifyVault({ actor: CLI_ACTOR, full: args.includes('--full'), tenantId });
  await asNone(CLI_ACTOR, () => vaultOperations.create(db, {
    kind: 'verify', state: report.failures ? 'failed' : 'done', tenantId: tenantId ?? null,
    startedAt: new Date(), finishedAt: new Date(), progress: { report }, params: { full: args.includes('--full') },
  }));
  if (report.failures) {
    const failed = Object.fromEntries(Object.entries(report.columns).filter(([, c]) => c.failed > 0).map(([k, c]) => [k, c.failed]));
    await master('vault.verify_failed', { deksFailed: report.deks.failed, columns: failed });
  }
  out(report);
  return report.failures ? 2 : 0;
}

async function backfill(): Promise<number> {
  await init();
  out(await asNone(CLI_ACTOR, () => backfillLegacySecrets()));
  return 0;
}

async function dekRotate(args: string[]): Promise<number> {
  const id = arg(args, '--operation');
  if (!id || !UUID_RE.test(id)) throw new CliExit(1, 'dek-rotate: --operation <uuid> is required');
  await init();
  const r = await runDekRotation(id, { actor: CLI_ACTOR });
  out(r);
  return 0;
}

async function kekRotate(args: string[]): Promise<number> {
  const id = arg(args, '--operation');
  if (!id || !UUID_RE.test(id)) throw new CliExit(1, 'kek-rotate: --operation <uuid> is required');
  const resume = args.includes('--resume');
  const dryRun = args.includes('--dry-run');
  requireConfig();
  const cfg = readVaultConfig();
  if (!cfg.kekPreviousFile) throw new CliExit(1, 'kek-rotate: SERVER_KEK_PREVIOUS_FILE (the previous KEK) is required');
  const current = new FileKekProvider(readKekFile(cfg.kekFile));
  const previous = new FileKekProvider(readKekFile(cfg.kekPreviousFile));
  try {
    if (current.id === previous.id) throw new CliExit(1, 'kek-rotate: the new and the previous KEK are the same key');
    const lock = await offline();
    try {
      return await asNone(CLI_ACTOR, async () => {
        await vaultOperations.expireStale(db);
        const op = await vaultOperations.get(db, id);
        const ok = op && op.kind === 'kek_rotation' && (
          (op.state === 'authorized' && op.authorizedUntil !== null && new Date(op.authorizedUntil).getTime() > Date.now())
          || (resume && op.state === 'running'));
        if (!op || !ok) {
          throw new CliExit(5, `kek-rotate: operation ${id} is not an authorized KEK rotation`
            + (resume ? ' (nor a running one)' : '') + ': request it in the console (double validation), within 24 hours.');
        }
        // The double validation authorized the rotation AWAY from one KEK (the
        // server's at the time): the previous file must hold that one (review
        // of lot A4; integration of lot A).
        const authorized = op.params && typeof op.params === 'object' ? (op.params as Record<string, unknown>).kekId : undefined;
        if (typeof authorized === 'string' && authorized !== previous.id) {
          throw new CliExit(5, `kek-rotate: operation ${id} authorized the rotation of kek_id ${authorized}, `
            + `but SERVER_KEK_PREVIOUS_FILE holds kek_id ${previous.id}`);
        }
        const rows = await db('data_keys').whereNotNull('dek_wrapped')
          .select('id', 'tenant_id', 'version', 'kek_id', 'dek_wrapped') as Array<{
            id: string; tenant_id: number | null; version: number; kek_id: string; dek_wrapped: string;
          }>;
        const unknown = rows.find((r) => r.kek_id !== previous.id && r.kek_id !== current.id);
        if (unknown) throw new CliExit(1, `kek-rotate: a data key is wrapped by another KEK (kek_id ${unknown.kek_id})`);
        const todo = rows.filter((r) => r.kek_id === previous.id);
        if (dryRun) {
          out({ operationId: id, oldKekId: previous.id, newKekId: current.id, toRewrap: todo.length, done: rows.length - todo.length });
          return 0;
        }
        // P2 (critical): the intent before any key is rewrapped, the result after.
        const rewrapped = await withVaultIntent({
          tenantId: MASTER_TENANT_ID, action: 'vault.kek_rotated', resourceType: 'vault_operation', resourcePath: id,
          details: { operationId: id, oldKekId: previous.id, newKekId: current.id, resume, via: 'cli' },
        }, async () => {
        await vaultOperations.update(db, id, {
          state: 'running', startedAt: op.startedAt ? new Date(op.startedAt) : new Date(), error: null,
          params: { ...op.params, oldKekId: previous.id, newKekId: current.id },
        });
        let rewrapped = 0;
        try {
          for (const r of todo) {
            const dek = await previous.unwrap(r.id, r.tenant_id ?? null, r.dek_wrapped, r.kek_id);
            try {
              const wrapped = await current.wrap(r.id, r.tenant_id ?? null, dek);
              rewrapped += await db('data_keys').where({ id: r.id, kek_id: previous.id })
                .update({ kek_id: current.id, dek_wrapped: wrapped });
            } finally {
              dek.fill(0);
            }
          }
          const left = await db('data_keys').whereNotNull('dek_wrapped').whereNot({ kek_id: current.id }).count<{ n: string }[]>({ n: '*' });
          if (Number(left[0]?.n ?? 0) > 0) throw new CliExit(1, 'kek-rotate: data keys remain under another KEK');
          // The canary with the new KEK alone.
          const inst = await db('data_keys').whereNull('tenant_id').where({ state: 'active' })
            .first('id', 'tenant_id', 'kek_id', 'dek_wrapped') as { id: string; tenant_id: null; kek_id: string; dek_wrapped: string } | undefined;
          if (!inst) throw new CliExit(1, 'kek-rotate: no active instance data key');
          (await current.unwrap(inst.id, null, inst.dek_wrapped, inst.kek_id)).fill(0);
        } catch (err) {
          await vaultOperations.update(db, id, { state: 'failed', error: operationError(err), progress: { rewrapped } }).catch(() => undefined);
          throw err;
        }
        await vaultOperations.update(db, id, { state: 'done', finishedAt: new Date(), progress: { rewrapped, total: rows.length } });
        return rewrapped;
        }, (n) => ({ keys: n }));
        out({ operationId: id, oldKekId: previous.id, newKekId: current.id, rewrapped });
        return 0;
      });
    } finally {
      await lock.release();
    }
  } finally {
    current.dispose();
    previous.dispose();
  }
}

async function recoverLostKek(args: string[]): Promise<number> {
  const lost = arg(args, '--confirm-lost');
  if (!lost || !KEK_ID_RE.test(lost)) throw new CliExit(1, 'recover-lost-kek: --confirm-lost <kek_id of the lost KEK> is required');
  requireConfig();
  const cfg = readVaultConfig();
  const provider = new FileKekProvider(readKekFile(cfg.kekFile));
  const lock = await offline();
  try {
    return await asNone(CLI_ACTOR, async () => {
      const ids = (await db('data_keys').whereNotNull('dek_wrapped').distinct('kek_id') as Array<{ kek_id: string }>).map((r) => r.kek_id);
      if (ids.includes(provider.id)) {
        throw new CliExit(1, 'recover-lost-kek: the KEK of SERVER_KEK_FILE opens keys of this database: nothing is lost (restore instead?)');
      }
      if (!ids.includes(lost)) {
        throw new CliExit(1, `recover-lost-kek: no data key of this database is under kek_id ${lost} (found: ${ids.join(', ') || 'none'})`);
      }
      vaultInternals.keyring.configure(provider, 0);
      // P2 (critical): the intent before any key or value is destroyed.
      const recovered = await withVaultIntent({
        tenantId: MASTER_TENANT_ID, action: 'vault.kek_loss_recovered', resourceType: 'vault_operation', resourcePath: 'kek_loss_recovery',
        details: { lostKekId: lost, newKekId: provider.id, via: 'cli' },
      }, async () => {
      // 1. Every DEK destroyed; a new one for the instance and each tenant.
      const destroyed = await db.transaction(async (trx) => {
        const before = await trx('data_keys').whereNot({ state: 'destroyed' }).forUpdate().select('id') as Array<{ id: string }>;
        await trx('data_keys').whereNot({ state: 'destroyed' })
          .update({ state: 'destroyed', dek_wrapped: null, destroyed_at: trx.fn.now(), destroy_after: null });
        const versions = await trx.raw(`SELECT coalesce(tenant_id, 0) AS t, max(version)::int AS v FROM data_keys GROUP BY 1`) as
          { rows: Array<{ t: number; v: number }> };
        const next = new Map(versions.rows.map((r) => [Number(r.t), Number(r.v) + 1]));
        const tenants = (await trx.raw('SELECT obligarth.tenant_ids_all() AS ids') as { rows: Array<{ ids: number[] | null }> }).rows[0]?.ids ?? [];
        for (const t of [null, ...tenants.map(Number)]) {
          const d = await vaultInternals.keyring.newWrappedDek(t, next.get(t ?? 0) ?? 1);
          await trx('data_keys').insert({ id: d.id, tenant_id: t, version: d.version, kek_id: d.kek_id, dek_wrapped: d.dek_wrapped, state: 'active' });
          d.discard();
        }
        return before.length;
      });
      // 2. Every sealed value dropped, by context (scopes.ts).
      const report: Record<string, Record<string, number>> = {};
      for (const def of secretColumns()) {
        if (def.transient) continue;
        const label = `${def.table}.${def.column}`;
        for (const scope of await scopesOf(def, CLI_ACTOR)) {
          const n = await scope.run(async () => {
            const qb = scope.filter(db(def.table).whereNotNull(def.column));
            return def.onLoss === 'delete' ? qb.delete() : qb.update({ [def.column]: null, ...(def.lossPatch ?? {}) });
          });
          if (n) (report[label] ??= {})[scope.tenantId === null ? 'instance' : String(scope.tenantId)] = Number(n);
        }
      }
      const op = await vaultOperations.create(db, {
        kind: 'kek_loss_recovery', state: 'done', startedAt: new Date(), finishedAt: new Date(),
        params: { lostKekId: lost, newKekId: provider.id }, progress: { destroyedKeys: destroyed, report },
      });
      return { op, destroyed, report };
      }, (r) => ({ operationId: r.op.id, destroyedKeys: r.destroyed, report: r.report }));
      const { op, destroyed, report } = recovered;
      out({ operationId: op.id, lostKekId: lost, newKekId: provider.id, destroyedKeys: destroyed, toEnterAgain: report });
      return 0;
    });
  } finally {
    vaultInternals.keyring.reset();
    provider.dispose();
    await lock.release();
  }
}

const COMMANDS: Record<string, (args: string[]) => Promise<number>> = {
  status: () => status(),
  'check-kek': checkKek,
  verify,
  backfill: () => backfill(),
  'dek-rotate': dekRotate,
  'kek-rotate': kekRotate,
  'recover-lost-kek': recoverLostKek,
  escrow,
};

/** stdin read to its end (shares of escrow combine and verify). */
function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on('data', (b: Buffer) => chunks.push(b));
    process.stdin.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      for (const c of chunks) c.fill(0);
      resolve(text);
    });
    process.stdin.on('error', reject);
  });
}

async function escrow(args: string[]): Promise<number> {
  const { EscrowError, escrowCli } = await import('./escrow');
  try {
    return await escrowCli(args, { readStdin, write: (text) => process.stdout.write(text) });
  } catch (err) {
    if (err instanceof EscrowError) throw new CliExit(err.exitCode, err.message);
    throw err;
  }
}

async function main(): Promise<number> {
  const [first, ...rest] = process.argv.slice(2);
  // Escrow (coffre-secrets §9.2): neither the database nor the network.
  if (first === 'escrow') return escrow(rest);
  // Signed database context (rls-tenant §4.6, R12): the commands below query
  // as the runtime role, like the server.
  try {
    configureContextSigningFromFile(config.rlsContextKeyFile);
  } catch (err) {
    throw new CliExit(1, (err as Error).message);
  }
  // The modules' sealed columns, as index.ts registers them (no I/O): every
  // walk of the registry (verify, recovery) must see them all.
  registerDeviceModule();
  // The journal's sealed column (SIEM destinations) and its seal key name.
  const { registerDestinationSecretColumn } = await import('../audit/export/destinations');
  const { registerSealKeySecretName } = await import('../audit/sealKeys');
  registerDestinationSecretColumn();
  registerSealKeySecretName();
  const [command, ...args] = process.argv.slice(2);
  const run = command ? COMMANDS[command] : undefined;
  if (!run) {
    process.stderr.write(`usage: vault <${Object.keys(COMMANDS).join(' | ')}> [options]\n`);
    return 1;
  }
  return run(args);
}

if (require.main === module) {
  main().then((code) => { process.exitCode = code; }, (err) => {
    if (err instanceof CliExit) {
      process.stderr.write(`${err.message}\n`);
      process.exitCode = err.code;
    } else if (isVaultError(err)) {
      process.stderr.write(`${err.message}\n`);
      process.exitCode = err.code === 'operation_not_authorized' ? 5 : err.code === 'server_running' ? 4 : 1;
    } else {
      process.stderr.write(`vault: ${(err as { code?: string })?.code ?? 'error'}: ${operationError(err)}\n`);
      process.exitCode = 1;
    }
  }).finally(async () => {
    // The process ends by itself once the pools are closed (the output is
    // flushed first; no forced exit).
    await vault.close().catch(() => undefined);
    await db.destroy().catch(() => undefined);
  });
}

export { main as vaultCli };
