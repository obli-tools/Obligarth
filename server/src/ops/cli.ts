// Commands of the operations of the instance (P0-13 T10, FND-09; procedure of the owners sauvegarde-reprise), in the
// server's image:
//   node dist/src/ops/cli.js <command> [options]      (image: docker compose run --rm server …)
//   npx tsx src/ops/cli.ts <command> [options]        (development)
//
//   restore-reconcile [--siem-heads <file.json>] [--full-vault]
//       after a restore, the server in JOBS_MODE=paused (refused otherwise: exit 4, this command's JOBS_MODE and a
//       server seen running its jobs against the database alike: jobs.heartbeat less than
//       JOBS_HEALTH_MAX_HEARTBEAT_AGE_S old, what GET /health/jobs reads), once the migrations have run: the
//       recovery in one command (ops/restore.ts), each step with its JSON report, stopping at the first that fails:
//       context probe, guard restore-reconcile (guarded actions paused, approval requests expired), audit
//       restore-reconcile (--siem-heads: the last heads the SIEM received; a chain already resumed by this restore,
//       since the last successful ops.restore_reconciled, is left as it is), vault verify (--full-vault: every sealed
//       value), the jobs of the queues never replayed still waiting, the recovery work queued for the return to
//       JOBS_MODE=all (apple-edge.restore-check, vpp.sync-all, android.reconcile-tenant of every linked tenant);
//       ops.restore_reconciled in the master tenant's journal. Exit 0, 1 error, 2 a check failed, 4 jobs not paused.
//   verify-restore [--full] [--edge-password-file <file>] [--edge-kek-id <id>] [--summary-file <file>] [--no-report]
//       the restored database checked, read only (but for the journal's verification rows and the vault's first
//       keys of a tenant without one): its migrations against this image's, the kek_id of the data keys against
//       SERVER_KEK_FILE and, with --edge-password-file (role apple_edge_app), apple-edge's migrations and the kek_id
//       of its data keys against --edge-kek-id (the id of edge_kek, computed apart: service drill-edge-kek of the
//       profile restore-drill; this process never holds apple-edge's KEK, one KEK per service); the vault (every
//       data key, one sealed value per column and key); the
//       journal (each chain verified from its last verification, --full: from its anchor); the rows of every table
//       by tenant; the age of the last command. The report restore_verify (ops_backup_reports, unless --no-report)
//       and, with --summary-file, its detail written to that file (the profile restore-drill reads it). Exit 0, 1
//       error, 2 a check failed.
//
// Both run as the server does (runtime role, DATABASE_URL, signed contexts with RLS_CONTEXT_KEY_FILE, the vault's
// KEK), with the registries of every module of index.ts (registerServerModules: the sealed columns, the audit
// actions, the jobs). Never a value, a key nor a secret on the output: codes, counts, identifiers, hashes.
import '../env';
import { readFileSync, writeFileSync } from 'node:fs';
import pg from 'pg';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { config } from '../config';
import { db } from '../db';
import { asNone, asTenant, configureContextSigningFromFile, type DbActor } from '../db/context';
import { migrationStem, shippedMigrations } from '../db/migrationFiles';
import { audit } from '../audit';
import { readSiemHeads, reconcileAuditChains } from '../audit/cli';
import { verifyTenantChain } from '../audit/verify';
import { defaultRuntime, jobs } from '../jobs';
import { vault, vaultConfigErrors, VaultStartupError } from '../vault';
import { verifyAndRecord } from '../vault/cli';
import { readVaultConfig } from '../vault/config';
import { inspectKekFile } from '../vault/kek';
import { verifyVault } from '../vault/verify';
import { restoreReconcile as guardRestoreReconcile } from '../guard/executor';
import { sendRestoreCheck } from '../apple/reconcile/jobs';
import { androidConfig } from '../android/config';
import { requestReconcileAll } from '../android/operations/raccord';
import { registerCoreJobs } from '../jobs/core.jobs';
import { registerOutboxJobs } from '../jobs/outbox/jobs';
import { registerDeviceModule } from '../modules/devices';
import { registerReportsModule } from '../modules/reports';
import { registerSsoSyncJobs } from '../routes/obligateCallback.routes';
import { registerVaultJobs } from '../vault/jobs';
import { registerAuditModule } from '../audit/module';
import { registerGuardModule } from '../guard/module';
import { registerAppleModule } from '../modules/apple';
import { registerLegacyAgentModule } from '../modules/legacyAgent';
import { registerRemoteModule } from '../modules/remote';
import { registerMdmModule } from '../mdm';
import { registerPrivacyModule } from '../modules/privacy';
import { registerAndroidModule } from '../modules/android';
import { registerOpsModule } from '../modules/ops';
import {
  compareKek, compareMigrations, errorCode, RESTORE_EXIT, restoreAuditDetails, runRestoreReconcile, verifyFindings, verifySummary,
  type KekComparison, type RestoreStep, type StepOutcome,
} from './restore';

class CliExit extends Error {
  constructor(readonly code: number, message: string) {
    super(message);
  }
}

/** The result of a command: indented on a terminal, one line otherwise (next to the server's JSON log lines). */
function out(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, process.stdout.isTTY ? 2 : undefined)}\n`);
}

function arg(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

const RECONCILE_ACTOR = { type: 'job', name: 'ops.restore-reconcile' } as const;
const GUARD_ACTOR = { type: 'job', name: 'actions.restore-reconcile' } as const;
const VERIFY_ACTOR = { type: 'job', name: 'ops.verify-restore' } as const;
/** States of a pg-boss job still to run. */
const WAITING_STATES = ['created', 'retry', 'active'];
const IDENT_RE = /^[a-z_][a-z0-9_]*$/;
/** A kek_id: the first 16 hexadecimal characters of SHA-256(KEK), as both vaults compute it. */
const KEK_ID_RE = /^[0-9a-f]{16}$/;

/** The registries of every module, in the order of index.ts (no I/O): the sealed columns the vault walks, the audit
 *  actions the steps write, the jobs (queues never replayed, recovery work). Kept equal to index.ts (test:ops). */
export function registerServerModules(): void {
  registerDeviceModule();
  registerReportsModule();
  registerCoreJobs();
  registerSsoSyncJobs();
  registerOutboxJobs();
  registerVaultJobs();
  registerAuditModule();
  registerGuardModule();
  registerMdmModule();
  registerAppleModule();
  registerLegacyAgentModule();
  registerRemoteModule();
  registerPrivacyModule();
  registerAndroidModule();
  registerOpsModule();
}

function configureSigning(): void {
  try {
    configureContextSigningFromFile(config.rlsContextKeyFile);
  } catch (err) {
    throw new CliExit(1, (err as Error).message);
  }
}

/** The probe of guard/cli.ts: a context the database does not accept would hide every row and change nothing. */
async function contextAccepted(actor: DbActor): Promise<boolean> {
  try {
    const probe = await asTenant(MASTER_TENANT_ID, actor, () => db.raw('SELECT obligarth.ctx_tenant() AS t')) as { rows: Array<{ t: number | null }> };
    return Number(probe.rows[0]?.t) === MASTER_TENANT_ID;
  } catch {
    return false;
  }
}

const CONTEXT_REFUSED = 'the database refused the context of this command (set RLS_CONTEXT_KEY_FILE to the key of the server)';

/** The vault opened as the server opens it; the refusal on stderr (its message names no secret). */
async function openVault(actor: DbActor): Promise<{ ok: true } | { ok: false; code: string }> {
  if (vault.isReady()) return { ok: true };
  const errors = vaultConfigErrors({ warn: () => undefined });
  if (errors.length) {
    process.stderr.write(`${errors.join('\n')}\n`);
    return { ok: false, code: 'vault_config' };
  }
  try {
    await asNone(actor, () => vault.init());
    return { ok: true };
  } catch (err) {
    if (err instanceof VaultStartupError) {
      process.stderr.write(`${err.refusal}\n`);
      return { ok: false, code: 'vault_refused' };
    }
    throw err;
  }
}

// ── restore-reconcile ───────────────────────────────────────────────────────────────────────────────────────────

/** The jobs of the queues never replayed (redrivable: false: destructive, each checks its conditions again) still
 *  waiting: to cancel or to confirm from the administration of the jobs before the return to JOBS_MODE=all. */
async function waitingNonReplayable(): Promise<StepOutcome> {
  const names = defaultRuntime.registry.list().filter((d) => !d.redrivable).map((d) => d.name).sort();
  const rows = names.length ? await asNone(RECONCILE_ACTOR, () => db.withSchema('pgboss').from('job')
    .whereIn('name', names).whereIn('state', WAITING_STATES).groupBy('name', 'state')
    .select('name', db.raw('state::text AS state'), db.raw('count(*)::int AS n'), db.raw('min(created_on) AS oldest'))) as
    Array<{ name: string; state: string; n: number; oldest: Date | null }> : [];
  const queues = names.map((queue) => {
    const mine = rows.filter((r) => r.name === queue);
    const count = (s: string) => Number(mine.find((r) => r.state === s)?.n ?? 0);
    const oldest = mine.map((r) => (r.oldest ? new Date(r.oldest).getTime() : null)).filter((t): t is number => t !== null).sort()[0];
    return { queue, created: count('created'), retry: count('retry'), active: count('active'), oldest: oldest ? new Date(oldest).toISOString() : null };
  });
  const waiting = queues.reduce((n, q) => n + q.created + q.retry + q.active, 0);
  return { ok: true, code: waiting ? 'jobs_to_review' : undefined, report: { waiting, queues: queues.filter((q) => q.created + q.retry + q.active > 0), checked: names } };
}

/** A server runs its jobs against this database: its heartbeat (jobs.heartbeat, every minute in JOBS_MODE=all)
 *  succeeded less than JOBS_HEALTH_MAX_HEARTBEAT_AGE_S ago, by the clock of the database. A server just stopped, or a
 *  copy restored to a time minutes ago, is seen until then: the refusal says to wait. */
async function schedulerRunning(): Promise<boolean> {
  const r = await asNone(RECONCILE_ACTOR, () => db.raw(`SELECT EXISTS (SELECT 1 FROM obligarth.job_status
      WHERE queue = 'jobs.heartbeat' AND key = '' AND last_succeeded_at > now() - make_interval(secs => ?)) AS running`,
  [config.jobs.healthMaxHeartbeatAgeS])) as { rows: Array<{ running: boolean }> };
  return r.rows[0]?.running === true;
}

/** The recovery work, queued while the jobs are paused (run at the return to JOBS_MODE=all). */
async function queueRecovery(): Promise<StepOutcome> {
  const report: Record<string, string | number> = {};
  if (config.apple.mode === 'on') {
    // The queues and schedules as the paused server keeps them (same registry), then the two sends.
    await jobs.start({ mode: 'paused' });
    report.appleRestoreCheck = (await sendRestoreCheck()) ? 'queued' : 'already_queued';
    const vpp = defaultRuntime.registry.get('vpp.sync-all');
    report.vppSyncAll = vpp ? ((await defaultRuntime.sendJob(vpp, {}, {}, null)) ? 'queued' : 'already_queued') : 'not_registered';
  } else {
    report.appleRestoreCheck = 'apple_edge_off';
    report.vppSyncAll = 'apple_edge_off';
  }
  report.androidTenants = androidConfig().mode === 'off' ? 'android_off' : await requestReconcileAll('restore');
  return { ok: true, report };
}

async function restoreReconcileCommand(args: string[]): Promise<number> {
  let siem;
  try {
    siem = readSiemHeads(arg(args, '--siem-heads'));
  } catch {
    throw new CliExit(1, 'restore-reconcile: --siem-heads <file.json> is not a readable JSON file of heads');
  }
  configureSigning();
  registerServerModules();
  const requestId = `restore-${new Date().toISOString()}`;
  const steps: RestoreStep[] = [
    { name: 'context', run: async () => ((await contextAccepted(RECONCILE_ACTOR)) ? { ok: true } : { ok: false, code: 'context_refused' }) },
    { name: 'guard', run: async () => ({ ok: true, report: await guardRestoreReconcile(GUARD_ACTOR, requestId) }) },
    {
      name: 'audit',
      run: async () => {
        const opened = await openVault(RECONCILE_ACTOR);
        if (!opened.ok) return { ok: false, code: opened.code };
        return { ok: true, report: await reconcileAuditChains(siem, { onceForThisRestore: true }) };
      },
    },
    {
      name: 'vault',
      run: async () => {
        const r = await verifyAndRecord({ full: args.includes('--full-vault') });
        return { ok: r.failures === 0, code: r.failures ? 'vault_verify_failed' : undefined, report: r };
      },
    },
    { name: 'queues', run: waitingNonReplayable },
    { name: 'resume', run: queueRecovery },
  ];
  const { code, report } = await runRestoreReconcile({
    jobsMode: config.jobs.mode,
    steps,
    schedulerRunning,
    record: (r) => asTenant(MASTER_TENANT_ID, RECONCILE_ACTOR, () => audit.append({
      tenantId: MASTER_TENANT_ID, action: 'ops.restore_reconciled', outcome: r.ok ? 'success' : 'failure',
      target: { type: 'platform', id: 'restore' }, details: restoreAuditDetails(r),
    }, audit.fromJob({ name: RECONCILE_ACTOR.name, requestId }))).then(() => undefined),
  });
  out(report);
  if (code === RESTORE_EXIT.notPaused && report.scheduler === 'running') {
    process.stderr.write(`restore-reconcile: a server runs its jobs against this database (jobs.heartbeat less than ${config.jobs.healthMaxHeartbeatAgeS} s ` +
      'ago): set JOBS_MODE=paused in .env, then docker compose up -d server, and run this again once GET /health/jobs answers 503 ' +
      `(${config.jobs.healthMaxHeartbeatAgeS} s at most after the server stopped running its jobs): nothing was done\n`);
  } else if (code === RESTORE_EXIT.notPaused) {
    process.stderr.write('restore-reconcile: JOBS_MODE must be paused (in .env, then docker compose up -d server): nothing was done\n');
  } else if (report.stoppedAt === 'context') {
    process.stderr.write(`restore-reconcile: ${CONTEXT_REFUSED}: nothing was done\n`);
  } else if (report.stoppedAt) {
    process.stderr.write(`restore-reconcile: stopped at the step ${report.stoppedAt}; the steps before it are done (run again once fixed)\n`);
  }
  return code;
}

// ── verify-restore ──────────────────────────────────────────────────────────────────────────────────────────────

function kekIdOfFile(file: string): string | 'unreadable' {
  const check = inspectKekFile(file);
  if (!check.ok) return 'unreadable';
  check.kek.key.fill(0);
  return check.kek.id;
}

const kekOf = (fileId: string | 'unreadable', ids: string[]): KekComparison | 'unreadable' =>
  (fileId === 'unreadable' ? 'unreadable' : compareKek(fileId, ids));

interface EdgeReading {
  checked: boolean;
  error: boolean;
  schema: boolean;
  components: Array<{ component: string; version: number; migrations: number }>;
  kekIds: string[];
  kek: KekComparison | 'unreadable';
}

/** apple-edge's schema as its own role reads it (apple_edge_app: the restored database keeps its password), read only;
 *  the kek_id of its data keys against the id of edge_kek given (never the key itself). */
async function readEdge(passwordFile: string | undefined, kekId: string | undefined): Promise<EdgeReading> {
  const reading: EdgeReading = { checked: false, error: false, schema: false, components: [], kekIds: [], kek: 'not_checked' };
  if (!passwordFile) return reading;
  reading.checked = true;
  let password: string;
  try {
    password = readFileSync(passwordFile, 'utf8').trim();
  } catch {
    reading.error = true;
    return reading;
  }
  const url = new URL(config.databaseUrl);
  const client = new pg.Client({
    host: url.hostname, port: Number(url.port || 5432), database: decodeURIComponent(url.pathname.slice(1)),
    user: 'apple_edge_app', password, application_name: 'obligarth-verify-restore', connectionTimeoutMillis: 10_000,
  });
  try {
    await client.connect();
    await client.query('BEGIN READ ONLY');
    const t = (await client.query(`SELECT to_regclass('apple_edge.schema_migrations') IS NOT NULL AS m,
                                          to_regclass('apple_edge.data_keys') IS NOT NULL AS k`)).rows[0] as { m: boolean; k: boolean };
    reading.schema = t.m && t.k;
    if (t.m) {
      reading.components = (await client.query(`SELECT component, max(version)::int AS version, count(*)::int AS migrations
                                                  FROM apple_edge.schema_migrations GROUP BY component ORDER BY component`)).rows;
    }
    if (t.k) {
      reading.kekIds = (await client.query(`SELECT DISTINCT kek_id FROM apple_edge.data_keys WHERE dek_wrapped IS NOT NULL ORDER BY 1`)).rows
        .map((r: { kek_id: string }) => String(r.kek_id));
    }
    await client.query('COMMIT');
  } catch {
    reading.error = true;
    return reading;
  } finally {
    await client.end().catch(() => undefined);
  }
  if (kekId !== undefined) reading.kek = kekOf(KEK_ID_RE.test(kekId.trim()) ? kekId.trim() : 'unreadable', reading.kekIds);
  return reading;
}

/** The tables of the schema that carry a tenant and that the runtime role may read (no partition: their parent). */
async function tenantTables(): Promise<string[]> {
  const r = await asNone(VERIFY_ACTOR, () => db.raw(`SELECT c.relname AS name
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
      WHERE n.nspname = 'obligarth' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
        AND has_table_privilege(c.oid, 'SELECT')
      ORDER BY 1`)) as { rows: Array<{ name: string }> };
  return r.rows.map((x) => x.name).filter((n) => IDENT_RE.test(n));
}

/** The count of one table, its name bound (a value and an identifier, never written into the SQL). */
const countOf = (t: string) => db.withSchema('obligarth').from(t).select(db.raw('?::text AS t', [t]), db.raw('count(*)::bigint AS n'));

/** The rows of each table in the context of a tenant (what it sees), and the time of its last command. */
async function countTenant(tenantId: number, tables: string[]): Promise<{ counts: Record<string, number>; unreadable: string[]; lastCommandAt: Date | null }> {
  const counts: Record<string, number> = {};
  const unreadable: string[] = [];
  const take = (rows: Array<{ t: string; n: string | number }>) => { for (const r of rows) if (Number(r.n) > 0) counts[r.t] = Number(r.n); };
  try {
    if (tables.length) {
      take(await asTenant(tenantId, VERIFY_ACTOR, () => countOf(tables[0]).unionAll(tables.slice(1).map(countOf), true)) as unknown as Array<{ t: string; n: string }>);
    }
  } catch {
    // One table its policies refuse in this context: each one alone.
    for (const t of tables) {
      try {
        take(await asTenant(tenantId, VERIFY_ACTOR, () => countOf(t)) as unknown as Array<{ t: string; n: string }>);
      } catch {
        unreadable.push(t);
      }
    }
  }
  let lastCommandAt: Date | null = null;
  if (tables.includes('mdm_commands') && !unreadable.includes('mdm_commands')) {
    const r = await asTenant(tenantId, VERIFY_ACTOR, () => db('mdm_commands').max({ at: 'created_at' }).first()) as { at: Date | null } | undefined;
    lastCommandAt = r?.at ? new Date(r.at) : null;
  }
  return { counts, unreadable, lastCommandAt };
}

async function verifyRestoreCommand(args: string[]): Promise<number> {
  const started = new Date();
  const full = args.includes('--full');
  const summaryFile = arg(args, '--summary-file');
  const writeSummary = (detail: Record<string, unknown>) => {
    if (!summaryFile) return;
    try {
      writeFileSync(summaryFile, `${JSON.stringify(detail)}\n`, { mode: 0o600 });
    } catch {
      process.stderr.write('verify-restore: the summary file could not be written\n');
    }
  };
  configureSigning();
  registerServerModules();
  if (!(await contextAccepted(VERIFY_ACTOR))) {
    process.stderr.write(`verify-restore: ${CONTEXT_REFUSED}\n`);
    const detail = { code: 'context_refused', failures: ['context_refused'], warnings: [] };
    writeSummary(detail);
    out({ ok: false, ...detail });
    return RESTORE_EXIT.failed;
  }

  // 1. The migrations of the database against this image's.
  const applied = (await asNone(VERIFY_ACTOR, () => db('obligarth_migrations').select('name')) as Array<{ name: string }>).map((r) => migrationStem(r.name));
  const schema = compareMigrations(shippedMigrations().map(migrationStem), applied);

  // 2. The kek_id of the server's data keys against SERVER_KEK_FILE; 3. apple-edge's.
  const serverIds = (await asNone(VERIFY_ACTOR, () => db('data_keys').whereNotNull('dek_wrapped').distinct('kek_id')) as Array<{ kek_id: string }>)
    .map((r) => String(r.kek_id)).sort();
  const kekFile = readVaultConfig().kekFile;
  const serverKek = { fileKekId: null as string | null, database: serverIds, result: 'not_checked' as KekComparison | 'unreadable' };
  if (kekFile) {
    const id = kekIdOfFile(kekFile);
    serverKek.fileKekId = id === 'unreadable' ? null : id;
    serverKek.result = kekOf(id, serverIds);
  }
  const edge = await readEdge(arg(args, '--edge-password-file'), arg(args, '--edge-kek-id'));

  // 4. The vault: every data key, one sealed value per column and key.
  const vaultReading: { ready: boolean; code: string | null; deks: number; failures: number; columnsFailed: Record<string, number> } =
    { ready: false, code: null, deks: 0, failures: 0, columnsFailed: {} };
  const opened = await openVault(VERIFY_ACTOR);
  if (opened.ok) {
    const r = await verifyVault({ actor: VERIFY_ACTOR, full: false });
    vaultReading.ready = true;
    vaultReading.deks = r.deks.checked;
    vaultReading.failures = r.failures;
    vaultReading.columnsFailed = Object.fromEntries(Object.entries(r.columns).filter(([, c]) => c.failed > 0).map(([k, c]) => [k, c.failed]));
  } else {
    vaultReading.code = opened.code;
  }

  // 5. The journal: every chain (deleted tenants' too).
  const chains = (await asNone(VERIFY_ACTOR, () => db.raw('SELECT tenant_id FROM obligarth.audit_chains()')) as { rows: Array<{ tenant_id: number }> }).rows
    .map((c) => Number(c.tenant_id));
  const auditReading = { chains: chains.length, ok: 0, broken: 0, errors: 0, problems: [] as Array<{ tenantId: number; status: string; type: string | null; seq: number | null }> };
  for (const tenantId of chains) {
    const v = await verifyTenantChain(tenantId, full ? 'full' : 'incremental', { requestId: `verify-restore-${started.toISOString()}` });
    if (v.status === 'ok') auditReading.ok++;
    else {
      if (v.status === 'broken') auditReading.broken++;
      else auditReading.errors++;
      auditReading.problems.push({ tenantId, status: v.status, type: v.problem?.type ?? null, seq: v.problem?.seq ?? null });
    }
  }

  // 6. The rows of each table by tenant; 7. the last command.
  const tenants = ((await asNone(VERIFY_ACTOR, () => db.raw('SELECT obligarth.tenant_ids_all() AS ids')) as { rows: Array<{ ids: number[] | null }> }).rows[0]?.ids ?? [])
    .map(Number);
  const tables = await tenantTables();
  const byTenant: Record<string, Record<string, number>> = {};
  const byTable: Record<string, number> = {};
  const unreadable = new Set<string>();
  let lastCommandAt: Date | null = null;
  const lastCommandByTenant: Record<string, string | null> = {};
  for (const tenantId of tenants) {
    const c = await countTenant(tenantId, tables);
    byTenant[String(tenantId)] = c.counts;
    for (const [t, n] of Object.entries(c.counts)) byTable[t] = (byTable[t] ?? 0) + n;
    for (const t of c.unreadable) unreadable.add(t);
    lastCommandByTenant[String(tenantId)] = c.lastCommandAt ? c.lastCommandAt.toISOString() : null;
    if (c.lastCommandAt && (!lastCommandAt || c.lastCommandAt > lastCommandAt)) lastCommandAt = c.lastCommandAt;
  }
  const rows = Object.values(byTable).reduce((a, b) => a + b, 0);
  const lastCommandAgeSeconds = lastCommandAt ? Math.max(0, Math.round((Date.now() - lastCommandAt.getTime()) / 1000)) : null;

  const { failures, warnings } = verifyFindings({
    schema, serverKek, edge, vault: vaultReading, audit: auditReading, counts: { unreadable: unreadable.size },
  });
  const seconds = Math.round((Date.now() - started.getTime()) / 1000);
  const detail = verifySummary({
    failures, warnings, schema, tenants: tenants.length, tables: tables.length, rows, chains: auditReading.chains,
    chainsBroken: auditReading.broken + auditReading.errors, deks: vaultReading.deks, vaultFailures: vaultReading.failures,
    lastCommandAgeSeconds, seconds,
  });
  let reportId: number | null = null;
  if (!args.includes('--no-report')) {
    try {
      const r = await asNone(VERIFY_ACTOR, () => db.raw('SELECT obligarth.ops_restore_verify_record(?, ?, ?::jsonb) AS id',
        [failures.length === 0, started, JSON.stringify(detail)])) as { rows: Array<{ id: string | number }> };
      reportId = Number(r.rows[0]?.id ?? 0) || null;
    } catch (err) {
      process.stderr.write(`verify-restore: the report restore_verify was not written (${errorCode(err)})\n`);
    }
  }
  writeSummary(detail);
  out({
    ok: failures.length === 0, failures, warnings, startedAt: started.toISOString(), seconds, reportId,
    schema, serverKek, edge, vault: vaultReading, audit: auditReading,
    counts: { tenants: tenants.length, tables: tables.length, rows, unreadable: [...unreadable].sort(), byTable, byTenant },
    mdmCommands: { lastAt: lastCommandAt ? lastCommandAt.toISOString() : null, ageSeconds: lastCommandAgeSeconds, byTenant: lastCommandByTenant },
  });
  return failures.length ? RESTORE_EXIT.failed : RESTORE_EXIT.ok;
}

const COMMANDS: Record<string, (args: string[]) => Promise<number>> = {
  'restore-reconcile': restoreReconcileCommand,
  'verify-restore': verifyRestoreCommand,
};

async function main(): Promise<number> {
  const [command, ...args] = process.argv.slice(2);
  const run = command ? COMMANDS[command] : undefined;
  if (!run) {
    process.stderr.write(`usage: ops <${Object.keys(COMMANDS).join(' | ')}> [options]\n`);
    return 1;
  }
  return run(args);
}

if (require.main === module) {
  main().then((code) => { process.exitCode = code; }, (err) => {
    if (err instanceof CliExit) {
      process.stderr.write(`${err.message}\n`);
      process.exitCode = err.code;
    } else {
      process.stderr.write(`ops: ${errorCode(err)}: ${String((err as Error)?.message ?? err).slice(0, 500)}\n`);
      process.exitCode = 1;
    }
  }).finally(async () => {
    // The process ends by itself once the pools are closed (the output is flushed first; no forced exit).
    await jobs.stop().catch(() => undefined);
    await vault.close().catch(() => undefined);
    await db.destroy().catch(() => undefined);
  });
}
