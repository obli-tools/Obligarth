import { db } from './index';
import { PRIVILEGED_ROLES_SQL, READER_REACHES_SQL } from './bootstrap';
import { asNone, asTenant, contextMode, contextSigningEnabled, type DbActor } from './context';
import { missingMigrations, rlsMigrationApplied } from './migrationFiles';
import { logger } from '../utils/logger';

// =============================================================================
// Boot guard (rls-tenant §7.9)
// =============================================================================
//
// Called by index.ts before any other database access, in the context
// 'none' (actor a:boot). The server refuses to start (exit code 1) on any
// finding:
//   1. the current role is `obligarth`, without SUPERUSER, BYPASSRLS,
//      CREATEROLE nor CREATEDB, and it cannot take on (SET ROLE, or an
//      inherited membership, directly or through the reader role) a role
//      that has one of them, the owner role or a role of the server's files
//      and programs or of all the data;
//   2. it owns no object of the schemas obligarth and obligarth_private;
//   3. obligarth.rls_audit() is empty — once the RLS is active (migration
//      C applied, or any table under RLS): before it, no table is
//      classified yet;
//   4. every migration shipped in the image is applied (otherwise: "database
//      schema incompatible, run server-migrate");
//   5. context self-test: asTenant(1) then obligarth.ctx_tenant() = 1 (in
//      signed mode, proves that the database knows the server's key);
//   6. DB_CONTEXT_MODE=audit is refused once the RLS is active.

const BOOT_ACTOR: DbActor = { type: 'anonymous', name: 'boot' };

export class BootGuardError extends Error {
  constructor(readonly findings: string[]) {
    super(`database boot guard: ${findings.join('; ')}`);
    this.name = 'BootGuardError';
  }
}

type Rows<T> = { rows: T[] };

/** Runs the checks; throws BootGuardError with every finding. */
export async function bootGuard(): Promise<void> {
  const findings: string[] = [];
  let rlsActive = false;
  let contextFunctions = false;
  await asNone(BOOT_ACTOR, async () => {
    // 1. role
    const role = await db.raw(`
      SELECT current_user AS name, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb
        FROM pg_roles r WHERE r.rolname = current_user`) as Rows<{
      name: string; rolsuper: boolean; rolbypassrls: boolean; rolcreaterole: boolean; rolcreatedb: boolean;
    }>;
    const r = role.rows[0];
    if (!r || r.name !== 'obligarth') {
      findings.push(`the server connects as "${r?.name ?? '?'}", not as the runtime role obligarth (DATABASE_URL)`);
    }
    if (r && (r.rolsuper || r.rolbypassrls || r.rolcreaterole || r.rolcreatedb)) {
      findings.push(`the role ${r.name} has SUPERUSER, BYPASSRLS, CREATEROLE or CREATEDB: row level security would not hold`);
    }
    // A membership carries the role past the row level security just as well
    // (a GRANT made by hand on an external database, say): SET ROLE to a
    // superuser or to the owner, or the owner's rights inherited, directly
    // or through the reader role it can always take on.
    if (r && !r.rolsuper) {
      const reachable = await db.raw(`${PRIVILEGED_ROLES_SQL}
           AND (pg_has_role(current_user, r.oid, 'SET') OR pg_has_role(current_user, r.oid, 'USAGE')
                OR ${READER_REACHES_SQL})
           AND r.rolname <> current_user
         ORDER BY r.rolname`) as Rows<{ rolname: string }>;
      if (reachable.rows.length > 0) {
        findings.push(`the role ${r.name} can take on ${reachable.rows.map((x) => x.rolname).join(', ')} (SET ROLE or inherited ` +
          'membership): row level security would not hold, revoke the membership');
      }
    }

    // 2. ownership
    const owned = await db.raw(`
      SELECT
        (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname IN ('obligarth', 'obligarth_private') AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)) +
        (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname IN ('obligarth', 'obligarth_private') AND p.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)) +
        (SELECT count(*) FROM pg_namespace n
          WHERE n.nspname IN ('obligarth', 'obligarth_private') AND n.nspowner = (SELECT oid FROM pg_roles WHERE rolname = current_user))
        AS n,
        (SELECT count(*) FROM pg_namespace WHERE nspname = 'obligarth') AS schema_present`) as Rows<{ n: string; schema_present: string }>;
    if (Number(owned.rows[0]?.schema_present ?? 0) === 0) {
      findings.push('database schema obligarth missing: run server-migrate');
      return;
    }
    if (Number(owned.rows[0]?.n ?? 0) > 0) {
      findings.push('the runtime role owns objects of the schemas obligarth / obligarth_private (they belong to obligarth_owner)');
    }

    // 4. migrations
    const tracking = await db.raw(`SELECT to_regclass('obligarth.obligarth_migrations') IS NOT NULL AS present`) as Rows<{ present: boolean }>;
    if (!tracking.rows[0]?.present) {
      findings.push('database schema incompatible: no migration applied, run server-migrate');
      return;
    }
    const applied = await db('obligarth_migrations').select('name') as Array<{ name: string }>;
    const missing = missingMigrations(applied.map((m) => m.name));
    if (missing.length) {
      findings.push(`database schema incompatible, run server-migrate (missing: ${missing.join(', ')})`);
    }
    // Once migration C is applied, the RLS is expected even when no table
    // has it any more (turned off by hand, partial restore): the audit below
    // then names every table (review of lot A5).
    const rlsMigrated = rlsMigrationApplied(applied.map((m) => m.name));

    const state = await db.raw(`
      SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                      WHERE n.nspname = 'obligarth' AND c.relkind IN ('r', 'p') AND c.relrowsecurity) AS rls_active,
             to_regprocedure('obligarth.ctx_tenant()') IS NOT NULL AS context_functions,
             COALESCE((SELECT p.prosecdef FROM pg_proc p WHERE p.oid = to_regprocedure('obligarth.ctx_raw()')), false) AS signed`) as
      Rows<{ rls_active: boolean; context_functions: boolean; signed: boolean }>;
    rlsActive = state.rows[0]?.rls_active === true || rlsMigrated;
    contextFunctions = state.rows[0]?.context_functions === true;

    // 3. audit of the classification, once the RLS is active
    if (rlsActive) {
      const audit = await db.raw('SELECT object_name, problem FROM obligarth.rls_audit()') as Rows<{ object_name: string; problem: string }>;
      for (const a of audit.rows) findings.push(`rls_audit: ${a.object_name}: ${a.problem}`);
    }
    // 6. audit mode only before the RLS
    if (rlsActive && contextMode() === 'audit') {
      findings.push('DB_CONTEXT_MODE=audit is refused once the row level security is active: remove it (strict)');
    }
    if (state.rows[0]?.signed && !contextSigningEnabled()) {
      findings.push('the signed database context is applied: RLS_CONTEXT_KEY_FILE is required');
    }
  });

  // 5. context self-test
  if (findings.length === 0 && contextFunctions) {
    const res = await asTenant(1, BOOT_ACTOR, () => db.raw('SELECT obligarth.ctx_tenant() AS t')) as Rows<{ t: number | null }>;
    if (Number(res.rows[0]?.t) !== 1) {
      findings.push('database context self-test failed: obligarth.ctx_tenant() did not return the tenant of the context' +
        (contextSigningEnabled() ? ' (the database does not know the server\'s context key: run server-migrate)' : ''));
    }
  }

  if (findings.length) throw new BootGuardError(findings);
  logger.info({ rlsActive, contextMode: contextMode(), signed: contextSigningEnabled() }, 'database boot guard passed');
}
