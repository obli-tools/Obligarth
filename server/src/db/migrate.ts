import '../env';
import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import knex from 'knex';
import pg from 'pg';
import { migrationConfig } from '../../knexfile';
import {
  BOOTSTRAP_BACKUP_ROLE_SQL, BOOTSTRAP_ROLES_SQL, BOOTSTRAP_SQL, PGBOSS_OWNERSHIP_SQL, PRE_RLS_GRANTS_SQL, PRIVILEGED_ROLES_SQL, READER_REACHES_SQL,
} from './bootstrap';
import { contextKeyId, loadContextKeyFile } from './context';
import { missingMigrations, rlsMigrationApplied, shippedMigrations } from './migrationFiles';
import { logger } from '../utils/logger';

// =============================================================================
// Migrations (rls-tenant §3.3, §3.4, §10.1; R3)
// =============================================================================
//
// Run by the server itself at start, before anything else touches the
// database, as the rest of the suite does (index.ts, whenever
// DATABASE_ADMIN_URL is set), or by hand with the command below. With the
// administration DSN (DATABASE_ADMIN_URL, role obligarth_admin); the server
// then works as the runtime role only:
//   1. refuses a database created before the RLS (role `obligarth`
//      superuser, or owner of objects: recreate the development volume,
//      rls-tenant §10.5, or adopt it with annex B);
//   2. bootstrap (annex A.1): roles, schemas, pgboss;
//   3. the runtime role's password (DB_APP_PASSWORD / DB_APP_PASSWORD_FILE),
//      sent as its SCRAM-SHA-256 verifier (the password itself never reaches
//      the database, nor its statement log), never logged; the role of the
//      backups (obligarth_backup, P0-13 T9) and its password
//      (DB_BACKUP_PASSWORD_FILE) the same way, when given;
//   4. Knex tracking tables found in `public` moved to `obligarth`;
//   5. the Knex migrations, every connection as obligarth_owner;
//   6. before the RLS migration (C): plain privileges of the runtime role;
//   7. signed context (migration D): key(s) of RLS_CONTEXT_KEY_FILE (and
//      RLS_CONTEXT_KEY_PREVIOUS_FILE) deposited, every other key retired;
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
  /** Password of the role of the backups obligarth_backup (P0-13 T9; absent: left as it is). */
  backupPassword?: string | null;
  /** Signed context (rls-tenant §4.6): current and previous key. */
  contextKey?: Buffer | null;
  previousContextKey?: Buffer | null;
}

export interface MigrateReport {
  applied: string[];
  preRlsGrants: boolean;
  rlsActive: boolean;
  contextKeys: string[];
  /** Keys of the signed context retired by this run (no longer configured). */
  retiredContextKeys: string[];
  /** The role of the backups (P0-13 T9): created and its password set, created without a new password, or not
   *  available on this database (an administrator refused the REPLICATION attribute). */
  backupRole: 'ready' | 'no_password' | 'unavailable';
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

/** Is the RLS active: does any table of the schema have it enabled, or is
 *  migration C recorded? Before, the runtime role gets plain privileges. A
 *  database whose RLS was turned off after migration C (by hand, a partial
 *  restore) counts as active: audited and refused, never given the plain
 *  privileges of before the RLS (review of lot A5). */
export async function rlsActive(q: Q): Promise<boolean> {
  const { rows } = await q(
    `SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = 'obligarth' AND c.relkind IN ('r', 'p') AND c.relrowsecurity) AS active,
            to_regclass('obligarth.obligarth_migrations') IS NOT NULL AS tracked`,
  );
  if (rows[0]?.active === true) return true;
  if (rows[0]?.tracked !== true) return false;
  const applied = await q('SELECT name FROM obligarth.obligarth_migrations');
  return rlsMigrationApplied(applied.rows.map((r) => String(r.name)));
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

/**
 * Step 7, signed context (rls-tenant §4.6, annex A.5; lot A8): the key of
 * RLS_CONTEXT_KEY_FILE, and the previous one during a rotation
 * (RLS_CONTEXT_KEY_PREVIOUS_FILE), are deposited as their two inner HMAC
 * blocks; every other active key is retired (retired_at), so a rotation is:
 * the migrations with the new key and the previous one, restart of the
 * server on the new key, then the migrations with the new key alone. A key
 * retired once is refused (a rotation never brings a key back). Without any
 * key, nothing changes (warning: the server refuses to start without one).
 * Written as the owner role (an administrator without superuser can SET ROLE
 * obligarth_owner, step 2).
 */
async function depositContextKeys(q: Q, opts: MigrateOptions, report: MigrateReport): Promise<void> {
  const given = new Map<string, Buffer>();
  for (const key of [opts.contextKey, opts.previousContextKey]) {
    if (Buffer.isBuffer(key)) given.set(contextKeyId(key), key);
  }
  if (given.size === 0) {
    const msg = 'signed context migration applied but RLS_CONTEXT_KEY_FILE is not set: the server will refuse to start';
    report.warnings.push(msg);
    logger.warn(msg);
    return;
  }
  const kids = [...given.keys()];
  await q('SET ROLE obligarth_owner');
  try {
    const retired = await q('SELECT kid FROM obligarth_private.context_keys WHERE kid = ANY ($1::text[]) AND retired_at IS NOT NULL', [kids]);
    if (retired.rowCount) {
      throw new MigrateRefusal(`context key ${retired.rows.map((r) => String(r.kid)).join(', ')} was retired: a retired key is never ` +
        'used again; generate a new key for RLS_CONTEXT_KEY_FILE (rotation, rls-tenant §4.6)');
    }
    for (const [kid, key] of given) {
      const { ikey, okey } = hmacBlocks(key);
      try {
        await q('INSERT INTO obligarth_private.context_keys (kid, ikey, okey) VALUES ($1, $2, $3) ON CONFLICT (kid) DO NOTHING',
          [kid, ikey, okey]);
        // Same kid, other key (64-bit prefix of SHA-256): refused rather than signing with a key the
        // database would never accept.
        const same = await q('SELECT ikey = $2 AND okey = $3 AS same FROM obligarth_private.context_keys WHERE kid = $1', [kid, ikey, okey]);
        if (same.rows[0]?.same !== true) throw new MigrateRefusal(`context key ${kid}: another key with the same identifier is registered`);
      } finally {
        ikey.fill(0);
        okey.fill(0);
      }
      report.contextKeys.push(kid);
    }
    const out = await q(`UPDATE obligarth_private.context_keys SET retired_at = now()
                          WHERE retired_at IS NULL AND NOT (kid = ANY ($1::text[])) RETURNING kid`, [kids]);
    report.retiredContextKeys = out.rows.map((r) => String(r.kid));
    if (report.retiredContextKeys.length) {
      logger.info({ retired: report.retiredContextKeys, active: kids }, 'signed context: keys no longer configured retired');
    }
  } finally {
    await q('RESET ROLE');
  }
}

/**
 * The SCRAM-SHA-256 verifier of a password, in PostgreSQL's stored form
 * (RFC 5802, RFC 7677: SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>),
 * which ALTER ROLE stores as it is. PostgreSQL normalises a password with
 * SASLprep before hashing it, which is the identity for printable ASCII; a
 * password with any other character is not converted here (null: sent as it
 * is, as before).
 */
export function scramVerifier(password: string, o: { salt?: Buffer; iterations?: number } = {}): string | null {
  if (!/^[\x20-\x7e]+$/.test(password)) return null;
  const salt = o.salt ?? randomBytes(16);
  const iterations = o.iterations ?? 4096;
  const salted = pbkdf2Sync(Buffer.from(password, 'utf8'), salt, iterations, 32, 'sha256');
  const storedKey = createHash('sha256').update(createHmac('sha256', salted).update('Client Key').digest()).digest();
  const serverKey = createHmac('sha256', salted).update('Server Key').digest();
  return `SCRAM-SHA-256$${iterations}:${salt.toString('base64')}$${storedKey.toString('base64')}:${serverKey.toString('base64')}`;
}

/** Runs the migrations (steps 1 to 8 of the header). Throws MigrateRefusal
 *  (or a database error) when it cannot. */
export async function runMigrations(opts: MigrateOptions): Promise<MigrateReport> {
  if (!opts.adminUrl) throw new MigrateRefusal('DATABASE_ADMIN_URL is not set: the administration DSN (obligarth_admin).');
  if (!opts.appPassword) {
    throw new MigrateRefusal('DB_APP_PASSWORD (or DB_APP_PASSWORD_FILE) is not set: the password of the runtime role obligarth.');
  }
  const report: MigrateReport = {
    applied: [], preRlsGrants: false, rlsActive: false, contextKeys: [], retiredContextKeys: [], backupRole: 'unavailable', warnings: [],
  };

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
    // Never logged. The statement carries the SCRAM-SHA-256 verifier, not the
    // password: a database that logs DDL (log_statement = ddl or all) or a
    // failed statement (log_min_error_statement) records only the verifier
    // (review of lot A1; integration of lot A).
    const secret = String(opts.appPassword);
    await q(`ALTER ROLE obligarth PASSWORD ${client.escapeLiteral(scramVerifier(secret) ?? secret)}`);

    // The role of the backups (P0-13 T9), after the schemas. Refused to an administrator that may not grant the
    // REPLICATION attribute: a warning, never a failure of the migrations (the backups of an external database are
    // its operator's). Its password the same way as the runtime role's, when given.
    try {
      await q(BOOTSTRAP_BACKUP_ROLE_SQL);
      report.backupRole = 'no_password';
    } catch (err) {
      if (superuser) throw err;
      const msg = `role obligarth_backup not created or not updated (${(err as Error).message}): the services of the ` +
        'compose profile backup cannot run against this database';
      report.warnings.push(msg);
      logger.warn(msg);
    }
    if (report.backupRole === 'no_password' && opts.backupPassword) {
      const backupSecret = String(opts.backupPassword);
      await q(`ALTER ROLE obligarth_backup PASSWORD ${client.escapeLiteral(scramVerifier(backupSecret) ?? backupSecret)}`);
      report.backupRole = 'ready';
    }

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
      await depositContextKeys(q, opts, report);
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
export async function checkDatabase(adminUrl: string, contextKey: Buffer | null = null): Promise<CheckReport> {
  if (!adminUrl) throw new MigrateRefusal('DATABASE_ADMIN_URL is not set.');
  return withAdmin(adminUrl, async (q) => {
    const findings: string[] = [];
    const roles = await q(`SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin
                             FROM pg_roles WHERE rolname IN ('obligarth', 'obligarth_owner', 'obligarth_reader')`);
    const byName = new Map(roles.rows.map((r) => [r.rolname as string, r]));
    for (const name of ['obligarth', 'obligarth_owner', 'obligarth_reader']) {
      const r = byName.get(name);
      if (!r) { findings.push(`role ${name} missing (run the migrations: restart the server with DATABASE_ADMIN_URL)`); continue; }
      if (r.rolsuper || r.rolbypassrls || r.rolcreaterole || r.rolcreatedb) findings.push(`role ${name} has a forbidden attribute`);
      if ((name === 'obligarth') !== r.rolcanlogin) findings.push(`role ${name}: unexpected LOGIN attribute`);
    }
    // The runtime role must not be able to take on a privileged role either
    // (SET ROLE, or an inherited membership, directly or through the reader
    // role): same check as the boot guard.
    if (byName.has('obligarth')) {
      const reach = await q(`${PRIVILEGED_ROLES_SQL}
           AND (pg_has_role('obligarth', r.oid, 'SET') OR pg_has_role('obligarth', r.oid, 'USAGE')
                OR ${READER_REACHES_SQL})
           AND r.rolname <> 'obligarth'
         ORDER BY r.rolname`);
      if (reach.rowCount) {
        findings.push(`role obligarth can take on ${reach.rows.map((x) => String(x.rolname)).join(', ')} (membership): revoke it`);
      }
    }
    // The role of the backups (P0-13 T9), when it exists: REPLICATION and LOGIN, no other attribute; nobody's member
    // and member of nothing; the insert of the backup reports and the usage of the schema obligarth only: any other
    // grant to it (a table, a column, a sequence or a function of obligarth, obligarth_private, pgboss or apple_edge,
    // any privilege on a schema but the usage of obligarth) is a finding. What PUBLIC holds is not its own.
    const backup = await q(`SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin,
                                   EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid OR m.roleid = r.oid) AS member,
                                   (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                                     CROSS JOIN LATERAL aclexplode(c.relacl) a
                                     WHERE n.nspname IN ('obligarth', 'obligarth_private', 'pgboss', 'apple_edge') AND a.grantee = r.oid
                                       AND NOT (n.nspname = 'obligarth' AND c.relname = 'ops_backup_reports' AND a.privilege_type = 'INSERT')
                                       AND NOT (n.nspname = 'obligarth' AND c.relname = 'ops_backup_reports_id_seq' AND a.privilege_type = 'USAGE'))
                                   + (SELECT count(*)::int FROM pg_attribute t JOIN pg_class c ON c.oid = t.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                                       CROSS JOIN LATERAL aclexplode(t.attacl) a
                                       WHERE n.nspname IN ('obligarth', 'obligarth_private', 'pgboss', 'apple_edge') AND a.grantee = r.oid)
                                   + (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                                       CROSS JOIN LATERAL aclexplode(p.proacl) a
                                       WHERE n.nspname IN ('obligarth', 'obligarth_private', 'pgboss', 'apple_edge') AND a.grantee = r.oid)
                                   + (SELECT count(*)::int FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a
                                       WHERE a.grantee = r.oid AND NOT (n.nspname = 'obligarth' AND a.privilege_type = 'USAGE')) AS extra
                              FROM pg_roles r WHERE r.rolname = 'obligarth_backup'`);
    const b = backup.rows[0];
    if (b) {
      if (b.rolsuper || b.rolbypassrls || b.rolcreaterole || b.rolcreatedb) findings.push('role obligarth_backup has a forbidden attribute');
      if (!b.rolreplication || !b.rolcanlogin) findings.push('role obligarth_backup: LOGIN REPLICATION expected (run the migrations: restart the server with DATABASE_ADMIN_URL)');
      if (b.member) findings.push('role obligarth_backup is a member of a role, or has members: revoke them');
      if (Number(b.extra) > 0) findings.push('role obligarth_backup holds privileges beyond the insert of the backup reports: revoke them');
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
    // Signed context (lot A8): an active key, and the key of RLS_CONTEXT_KEY_FILE among them when given.
    const keysTable = await q(`SELECT to_regclass('obligarth_private.context_keys') IS NOT NULL AS present`);
    if (keysTable.rows[0].present) {
      await q('SET ROLE obligarth_owner');
      try {
        const keys = await q('SELECT kid FROM obligarth_private.context_keys WHERE retired_at IS NULL');
        const kids = keys.rows.map((r) => String(r.kid));
        if (kids.length === 0) findings.push('signed context: no active key (run the migrations with RLS_CONTEXT_KEY_FILE: restart the server with DATABASE_ADMIN_URL)');
        if (contextKey && !kids.includes(contextKeyId(contextKey))) {
          findings.push(`signed context: the key of RLS_CONTEXT_KEY_FILE (${contextKeyId(contextKey)}) is not an active key of ` +
            'the database: the server would refuse to start (run the migrations with it: restart the server with DATABASE_ADMIN_URL)');
        }
      } finally {
        await q('RESET ROLE');
      }
    }
    return { ok: findings.length === 0, findings, rlsActive: active, pending };
  });
}

function readSecret(value: string | undefined, file: string | undefined): string | null {
  if (file) return readFileSync(file, 'utf8').trim() || null;
  return value ? value : null;
}

/** An optional secret (the password of the role of the backups): a file that cannot be read is a warning, the role
 *  then keeps the password it has (none on a new database: the backup services cannot sign in). */
function readOptionalSecret(name: string, value: string | undefined, file: string | undefined): string | null {
  try {
    return readSecret(value, file);
  } catch (err) {
    logger.warn(`${name}: ${file} cannot be read (${(err as NodeJS.ErrnoException).code ?? 'error'}): the password of the role obligarth_backup is left as it is`);
    return null;
  }
}

/** The runtime role's password the migration sets: DB_APP_PASSWORD(_FILE), else the one of DATABASE_URL. */
function appPasswordFromEnv(): string | null {
  const explicit = readSecret(process.env.DB_APP_PASSWORD, process.env.DB_APP_PASSWORD_FILE);
  if (explicit) return explicit;
  try {
    const pw = new URL(process.env.DATABASE_URL || '').password;
    return pw ? decodeURIComponent(pw) : null;
  } catch {
    return null;
  }
}

/**
 * The migrations from the environment, as the rest of the suite does at start: run by the server itself before it
 * starts (index.ts, whenever DATABASE_ADMIN_URL is set) and by this command. `contextKey`: the key already loaded by
 * the caller, else RLS_CONTEXT_KEY_FILE.
 */
export async function migrateFromEnv(contextKey?: Buffer | null): Promise<MigrateReport> {
  const report = await runMigrations({
    adminUrl: process.env.DATABASE_ADMIN_URL || '',
    appPassword: appPasswordFromEnv(),
    backupPassword: readOptionalSecret('DB_BACKUP_PASSWORD_FILE', process.env.DB_BACKUP_PASSWORD, process.env.DB_BACKUP_PASSWORD_FILE),
    contextKey: contextKey !== undefined ? contextKey : loadContextKeyFile(process.env.RLS_CONTEXT_KEY_FILE),
    previousContextKey: loadContextKeyFile(process.env.RLS_CONTEXT_KEY_PREVIOUS_FILE, 'RLS_CONTEXT_KEY_PREVIOUS_FILE'),
  });
  logger.info({
    applied: report.applied.length, rlsActive: report.rlsActive, preRlsGrants: report.preRlsGrants,
    contextKeys: report.contextKeys, retiredContextKeys: report.retiredContextKeys, backupRole: report.backupRole,
    warnings: report.warnings.length,
  }, 'migrations complete');
  return report;
}

/** Logs a failed migration the way the operator can act on it. */
export function logMigrateFailure(err: unknown): void {
  if (err instanceof MigrateRefusal) logger.fatal(err.message);
  else {
    logger.fatal({ err }, 'migrations failed');
    if (adminSignInRefused(err)) logger.fatal(SIGN_IN_HINT);
  }
}

async function main(): Promise<void> {
  const check = process.argv.includes('--check');
  if (check) {
    const res = await checkDatabase(process.env.DATABASE_ADMIN_URL || '', loadContextKeyFile(process.env.RLS_CONTEXT_KEY_FILE));
    for (const f of res.findings) logger.error(f);
    logger.info({ ok: res.ok, rlsActive: res.rlsActive, pending: res.pending.length }, 'migrate --check');
    process.exitCode = res.ok ? 0 : 1;
    return;
  }
  await migrateFromEnv();
}

if (require.main === module) {
  main().catch((err) => {
    logMigrateFailure(err);
    process.exitCode = 1;
  }).finally(() => {
    // pino writes asynchronously: give the last lines a moment.
    setTimeout(() => process.exit(process.exitCode ?? 0), 50).unref();
  });
}
