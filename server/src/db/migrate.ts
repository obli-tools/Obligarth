import '../env';
import { readFileSync } from 'node:fs';
import knex from 'knex';
import pg from 'pg';
import { migrationConfig } from '../../knexfile';
import { BOOTSTRAP_ROLES_SQL, BOOTSTRAP_SQL, PGBOSS_OWNERSHIP_SQL, PRE_RLS_GRANTS_SQL, PRIVILEGED_ROLES_SQL } from './bootstrap';
import { contextKeyId, loadContextKeyFile } from './context';
import { missingMigrations, shippedMigrations } from './migrationFiles';
import { logger } from '../utils/logger';

// =============================================================================
// server-migrate (rls-tenant §3.3, §3.4, §10.1; R3)
// =============================================================================
//
// One-shot service, same image as the server, run before it (compose:
// `server` depends on it completing successfully). With the administration
// DSN (DATABASE_ADMIN_URL, role obligarth_admin) that the server never sees:
//   1. refuses a database created before the RLS (role `obligarth`
//      superuser, or owner of objects: recreate the development volume,
//      rls-tenant §10.5, or adopt it with annex B);
//   2. bootstrap (annex A.1): roles, schemas, pgboss;
//   3. the runtime role's password (DB_APP_PASSWORD / DB_APP_PASSWORD_FILE),
//      client-side escaped, never logged;
//   4. Knex tracking tables found in `public` moved to `obligarth`;
//   5. the Knex migrations, every connection as obligarth_owner;
//   6. before the RLS migration (C): plain privileges of the runtime role;
//   7. signed context (migration D): key(s) of RLS_CONTEXT_KEY_FILE;
//   8. once the RLS is active: obligarth.rls_audit() must be empty.
// `--check`: the controls only (roles, schemas, migrations, audit), nothing
// is changed; exit code 1 on any finding.
//
//   node dist/src/db/migrate.js [--check]      (image)
//   npx tsx src/db/migrate.ts [--check]        (development)

export interface MigrateOptions {
  adminUrl: string;
  /** Password of the runtime role (required to migrate, unused by --check). */
  appPassword?: string | null;
  /** Signed context (rls-tenant §4.6): current and previous key. */
  contextKey?: Buffer | null;
  previousContextKey?: Buffer | null;
}

export interface MigrateReport {
  applied: string[];
  preRlsGrants: boolean;
  rlsActive: boolean;
  contextKeys: string[];
  warnings: string[];
}

export class MigrateRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MigrateRefusal';
  }
}

const ADOPTION_HINT =
  'This database was created before the row level security (rls-tenant §10.5): recreate the development volume ' +
  '(docker compose down -v; POSTGRES_USER=obligarth_admin only acts on a new volume), or adopt it once with the ' +
  'procedure of annex B (backup first).';

/** PostgreSQL refused the administrator's sign-in (28P01, 28000). On a
 *  volume created before the row level security, obligarth_admin does not
 *  even exist: the refusal of step 1 cannot be reached, hence the hint. */
function adminSignInRefused(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  return code === '28P01' || code === '28000';
}

const SIGN_IN_HINT =
  'The administrator of DATABASE_ADMIN_URL cannot sign in: check DB_ADMIN_PASSWORD. A database volume created before ' +
  'the row level security has no role obligarth_admin (POSTGRES_USER only acts on a new volume): recreate it ' +
  '(docker compose down -v), or adopt it once with the procedure of annex B of rls-tenant (backup first).';

type Q = (sql: string, values?: unknown[]) => Promise<pg.QueryResult>;

/** Is the RLS active: does any table of the schema have it enabled
 *  (migration C)? Before, the runtime role gets plain privileges. */
export async function rlsActive(q: Q): Promise<boolean> {
  const { rows } = await q(
    `SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = 'obligarth' AND c.relkind IN ('r', 'p') AND c.relrowsecurity) AS active`,
  );
  return rows[0]?.active === true;
}

async function withAdmin<T>(adminUrl: string, fn: (q: Q, client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: adminUrl, application_name: 'obligarth-migrate' });
  await client.connect();
  try {
    return await fn((sql, values) => client.query(sql, values as unknown[] | undefined), client);
  } finally {
    await client.end().catch(() => {});
  }
}

/** Step 1: a runtime role that is a superuser, or owns objects of this
 *  database (outside pgboss, which it owns by design), is refused. */
async function refuseLegacyDatabase(q: Q): Promise<void> {
  const role = await q(`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'obligarth'`);
  if (role.rowCount === 0) return;
  if (role.rows[0].rolsuper || role.rows[0].rolbypassrls) {
    throw new MigrateRefusal(`The role obligarth is a superuser (or BYPASSRLS). ${ADOPTION_HINT}`);
  }
  const owned = await q(`
    SELECT
      (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relowner = 'obligarth'::regrole AND n.nspname NOT IN ('pgboss', 'pg_toast')) +
      (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE p.proowner = 'obligarth'::regrole AND n.nspname <> 'pgboss') +
      (SELECT count(*) FROM pg_namespace n WHERE n.nspowner = 'obligarth'::regrole AND n.nspname <> 'pgboss') +
      (SELECT count(*) FROM pg_database d WHERE d.datname = current_database() AND d.datdba = 'obligarth'::regrole)
      AS n`);
  if (Number(owned.rows[0]?.n ?? 0) > 0) {
    throw new MigrateRefusal(`The role obligarth owns objects of this database. ${ADOPTION_HINT}`);
  }
}

/** The two inner blocks of HMAC-SHA256 of a key (annex A.5). */
function hmacBlocks(key: Buffer): { ikey: Buffer; okey: Buffer } {
  const block = Buffer.alloc(64);
  key.copy(block);
  return {
    ikey: Buffer.from(block.map((b) => b ^ 0x36)),
    okey: Buffer.from(block.map((b) => b ^ 0x5c)),
  };
}

/** Runs server-migrate (steps 1 to 8 of the header). Throws MigrateRefusal
 *  (or a database error) when it cannot. */
export async function runMigrations(opts: MigrateOptions): Promise<MigrateReport> {
  if (!opts.adminUrl) throw new MigrateRefusal('DATABASE_ADMIN_URL is not set: the administration DSN (obligarth_admin).');
  if (!opts.appPassword) {
    throw new MigrateRefusal('DB_APP_PASSWORD (or DB_APP_PASSWORD_FILE) is not set: the password of the runtime role obligarth.');
  }
  const report: MigrateReport = { applied: [], preRlsGrants: false, rlsActive: false, contextKeys: [], warnings: [] };

  // ── 1 to 4: bootstrap, as the administrator ───────────────────────────────
  await withAdmin(opts.adminUrl, async (q, client) => {
    const ver = await q(`SELECT current_setting('server_version_num')::int AS v, current_user AS admin,
                                (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser`);
    const { v, admin, superuser } = ver.rows[0] as { v: number; admin: string; superuser: boolean };
    if (v < 160000) throw new MigrateRefusal(`PostgreSQL 16 or later is required (found ${v}).`);
    await refuseLegacyDatabase(q);

    if (superuser) {
      await q(BOOTSTRAP_SQL);
    } else {
      // An external database without superuser [to check on a real external
      // database, rls-tenant §3.3]: the administrator (CREATEROLE, owner of
      // the database) must be able to SET ROLE obligarth_owner.
      await q(BOOTSTRAP_ROLES_SQL);
      await q(`GRANT obligarth_owner TO ${client.escapeIdentifier(admin)} WITH INHERIT FALSE, SET TRUE`);
      await q(BOOTSTRAP_SQL);
    }
    // Never logged: the statement carries the password.
    await q(`ALTER ROLE obligarth PASSWORD ${client.escapeLiteral(String(opts.appPassword))}`);

    const pgboss = await q(`SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname = 'pgboss'`);
    if (pgboss.rowCount === 1 && pgboss.rows[0].owner !== 'obligarth') {
      await q(PGBOSS_OWNERSHIP_SQL);
      logger.info('schema pgboss: ownership moved to the runtime role obligarth');
    }

    for (const t of ['obligarth_migrations', 'obligarth_migrations_lock']) {
      const where = await q(`SELECT to_regclass('public.' || $1::text) IS NOT NULL AS in_public,
                                    to_regclass('obligarth.' || $1::text) IS NOT NULL AS in_schema`, [t]);
      if (where.rows[0].in_public && !where.rows[0].in_schema) {
        await q(`ALTER TABLE public.${t} SET SCHEMA obligarth`);
        await q(`ALTER TABLE obligarth.${t} OWNER TO obligarth_owner`);
        logger.info({ table: t }, 'Knex tracking table moved from public to obligarth');
      }
    }

    // Each in its own statement: they need a superuser (ignored with a
    // warning on an external database without one).
    for (const setting of ['log_parameter_max_length', 'log_parameter_max_length_on_error']) {
      try {
        await q(`ALTER ROLE obligarth SET ${setting} = 0`);
      } catch (err) {
        const msg = `ALTER ROLE obligarth SET ${setting} = 0 refused (${(err as Error).message}): ` +
          'query parameters of the runtime role may reach the PostgreSQL logs';
        report.warnings.push(msg);
        logger.warn(msg);
      }
    }
  });

  // ── 5: Knex migrations, as obligarth_owner ────────────────────────────────
  const migrator = knex(migrationConfig(opts.adminUrl));
  try {
    const [, log] = await migrator.migrate.latest() as [number, string[]];
    report.applied = log;
    if (log.length) logger.info({ migrations: log }, `${log.length} migration(s) applied`);
    else logger.info('database schema up to date');
  } finally {
    await migrator.destroy();
  }

  // ── 6 to 8: privileges, signed context, audit ─────────────────────────────
  await withAdmin(opts.adminUrl, async (q) => {
    report.rlsActive = await rlsActive(q);
    if (!report.rlsActive) {
      await q('SET ROLE obligarth_owner');
      await q(PRE_RLS_GRANTS_SQL);
      await q('RESET ROLE');
      report.preRlsGrants = true;
      logger.info('row level security not active yet (migration C): plain privileges granted to the runtime role');
    }

    const keysTable = await q(`SELECT to_regclass('obligarth_private.context_keys') IS NOT NULL AS present`);
    if (keysTable.rows[0].present) {
      const keys = [opts.contextKey, opts.previousContextKey].filter((k): k is Buffer => Buffer.isBuffer(k));
      if (keys.length === 0) {
        const msg = 'signed context migration applied but RLS_CONTEXT_KEY_FILE is not set: the server will refuse to start';
        report.warnings.push(msg);
        logger.warn(msg);
      }
      for (const key of keys) {
        const kid = contextKeyId(key);
        const { ikey, okey } = hmacBlocks(key);
        await q(`INSERT INTO obligarth_private.context_keys (kid, ikey, okey) VALUES ($1, $2, $3) ON CONFLICT (kid) DO NOTHING`,
          [kid, ikey, okey]);
        report.contextKeys.push(kid);
      }
    }

    if (report.rlsActive) {
      const audit = await q('SELECT object_name, problem FROM obligarth.rls_audit()');
      if (audit.rowCount) {
        const lines = audit.rows.map((r) => `${r.object_name}: ${r.problem}`);
        throw new MigrateRefusal(`row level security audit failed:\n${lines.join('\n')}`);
      }
    }
  });
  return report;
}

export interface CheckReport {
  ok: boolean;
  findings: string[];
  rlsActive: boolean;
  pending: string[];
}

/** `--check`: roles (attributes and memberships), schemas, migrations and RLS
 *  audit, without any change. */
export async function checkDatabase(adminUrl: string): Promise<CheckReport> {
  if (!adminUrl) throw new MigrateRefusal('DATABASE_ADMIN_URL is not set.');
  return withAdmin(adminUrl, async (q) => {
    const findings: string[] = [];
    const roles = await q(`SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin
                             FROM pg_roles WHERE rolname IN ('obligarth', 'obligarth_owner', 'obligarth_reader')`);
    const byName = new Map(roles.rows.map((r) => [r.rolname as string, r]));
    for (const name of ['obligarth', 'obligarth_owner', 'obligarth_reader']) {
      const r = byName.get(name);
      if (!r) { findings.push(`role ${name} missing (run server-migrate)`); continue; }
      if (r.rolsuper || r.rolbypassrls || r.rolcreaterole || r.rolcreatedb) findings.push(`role ${name} has a forbidden attribute`);
      if ((name === 'obligarth') !== r.rolcanlogin) findings.push(`role ${name}: unexpected LOGIN attribute`);
    }
    // The runtime role must not be able to take on a privileged role either
    // (SET ROLE, or an inherited membership): same check as the boot guard.
    if (byName.has('obligarth')) {
      const reach = await q(`${PRIVILEGED_ROLES_SQL}
           AND (pg_has_role('obligarth', r.oid, 'SET') OR pg_has_role('obligarth', r.oid, 'USAGE'))
           AND r.rolname <> 'obligarth'
         ORDER BY r.rolname`);
      if (reach.rowCount) {
        findings.push(`role obligarth can take on ${reach.rows.map((x) => String(x.rolname)).join(', ')} (membership): revoke it`);
      }
    }
    const schemas = await q(`SELECT nspname, pg_get_userbyid(nspowner) AS owner FROM pg_namespace
                              WHERE nspname IN ('obligarth', 'obligarth_private', 'pgboss')`);
    const owners = new Map(schemas.rows.map((r) => [r.nspname as string, r.owner as string]));
    if (owners.get('obligarth') !== 'obligarth_owner') findings.push('schema obligarth missing or not owned by obligarth_owner');
    if (owners.get('obligarth_private') !== 'obligarth_owner') findings.push('schema obligarth_private missing or not owned by obligarth_owner');
    if (owners.get('pgboss') !== 'obligarth') findings.push('schema pgboss missing or not owned by obligarth');
    let pending: string[] = shippedMigrations();
    const tracking = await q(`SELECT to_regclass('obligarth.obligarth_migrations') IS NOT NULL AS present`);
    if (tracking.rows[0].present) {
      const applied = await q('SELECT name FROM obligarth.obligarth_migrations ORDER BY id');
      pending = missingMigrations(applied.rows.map((r) => String(r.name)));
    }
    if (pending.length) findings.push(`migrations not applied: ${pending.join(', ')}`);
    const active = owners.has('obligarth') ? await rlsActive(q) : false;
    if (active) {
      const audit = await q('SELECT object_name, problem FROM obligarth.rls_audit()');
      for (const r of audit.rows) findings.push(`rls_audit: ${r.object_name}: ${r.problem}`);
    }
    return { ok: findings.length === 0, findings, rlsActive: active, pending };
  });
}

function readSecret(value: string | undefined, file: string | undefined): string | null {
  if (file) return readFileSync(file, 'utf8').trim() || null;
  return value ? value : null;
}

async function main(): Promise<void> {
  const check = process.argv.includes('--check');
  const adminUrl = process.env.DATABASE_ADMIN_URL || '';
  if (check) {
    const res = await checkDatabase(adminUrl);
    for (const f of res.findings) logger.error(f);
    logger.info({ ok: res.ok, rlsActive: res.rlsActive, pending: res.pending.length }, 'server-migrate --check');
    process.exitCode = res.ok ? 0 : 1;
    return;
  }
  const report = await runMigrations({
    adminUrl,
    appPassword: readSecret(process.env.DB_APP_PASSWORD, process.env.DB_APP_PASSWORD_FILE),
    contextKey: loadContextKeyFile(process.env.RLS_CONTEXT_KEY_FILE),
    previousContextKey: loadContextKeyFile(process.env.RLS_CONTEXT_KEY_PREVIOUS_FILE),
  });
  logger.info({
    applied: report.applied.length, rlsActive: report.rlsActive, preRlsGrants: report.preRlsGrants,
    contextKeys: report.contextKeys, warnings: report.warnings.length,
  }, 'server-migrate complete');
}

if (require.main === module) {
  main().catch((err) => {
    if (err instanceof MigrateRefusal) logger.fatal(err.message);
    else {
      logger.fatal({ err }, 'server-migrate failed');
      if (adminSignInRefused(err)) logger.fatal(SIGN_IN_HINT);
    }
    process.exitCode = 1;
  }).finally(() => {
    // pino writes asynchronously: give the last lines a moment.
    setTimeout(() => process.exit(process.exitCode ?? 0), 50).unref();
  });
}
