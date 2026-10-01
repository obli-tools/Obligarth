// =============================================================================
// Bootstrap of server-migrate (rls-tenant §3.3, annex A.1)
// =============================================================================
//
// Run by src/db/migrate.ts with the administration DSN, BEFORE the Knex
// migrations, in one statement batch (simple protocol). Idempotent: creates
// the brain's roles when missing and re-asserts their attributes, grants the
// reader role to the runtime role (INHERIT FALSE, SET TRUE: PostgreSQL 16 or
// later), sets the runtime role's settings, creates the schemas, and the
// schema of pg-boss owned by the runtime role (file-durable §4.1).
// The runtime role's password is set separately (client-side literal
// escaping, never logged), as are the settings that need a superuser.

/** The roles alone (first block of the bootstrap): run first when the
 *  administrator is not a superuser, which must then be granted
 *  obligarth_owner before it creates the schemas in its name. */
export const BOOTSTRAP_ROLES_SQL = String.raw`
-- Bootstrap, run by the migrate command with the administration DSN, outside the Knex migrations.
-- Idempotent. The password of the runtime role is set separately (client-side literal escaping).
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'obligarth_owner') THEN
    CREATE ROLE obligarth_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'obligarth_reader') THEN
    CREATE ROLE obligarth_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'obligarth') THEN
    CREATE ROLE obligarth LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
  END IF;
END $$;
`;

export const BOOTSTRAP_SQL = BOOTSTRAP_ROLES_SQL + String.raw`
ALTER ROLE obligarth WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
GRANT obligarth_reader TO obligarth WITH INHERIT FALSE, SET TRUE;
ALTER ROLE obligarth SET search_path = obligarth;
ALTER ROLE obligarth SET idle_in_transaction_session_timeout = '60s';
CREATE SCHEMA IF NOT EXISTS obligarth AUTHORIZATION obligarth_owner;
CREATE SCHEMA IF NOT EXISTS obligarth_private AUTHORIZATION obligarth_owner;
ALTER SCHEMA obligarth OWNER TO obligarth_owner;
ALTER SCHEMA obligarth_private OWNER TO obligarth_owner;
REVOKE ALL ON SCHEMA obligarth, obligarth_private FROM PUBLIC;
GRANT USAGE ON SCHEMA obligarth TO obligarth, obligarth_reader;
-- Schema of pg-boss (file-durable.md, FND-04): owned by the runtime role, outside RLS.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_namespace WHERE nspname = 'pgboss') THEN
    CREATE SCHEMA pgboss AUTHORIZATION obligarth;
  END IF;
END $$;
`;

/** Ownership of an existing pgboss schema (a database created before the
 *  runtime role existed) moved to the runtime role, with every object of it
 *  (file-durable §10.5). */
export const PGBOSS_OWNERSHIP_SQL = String.raw`
DO $$
DECLARE r record;
BEGIN
  EXECUTE 'ALTER SCHEMA pgboss OWNER TO obligarth';
  -- tables, partitions, views (their indexes and row types follow)
  FOR r IN SELECT c.relname, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'pgboss' AND c.relkind IN ('r', 'p', 'v', 'm') LOOP
    EXECUTE format('ALTER %s pgboss.%I OWNER TO obligarth',
      CASE r.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' ELSE 'TABLE' END, r.relname);
  END LOOP;
  -- free-standing sequences only (a sequence owned by a column follows its table)
  FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'pgboss' AND c.relkind = 'S'
              AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass
                                AND d.objid = c.oid AND d.deptype IN ('a', 'i')) LOOP
    EXECUTE format('ALTER SEQUENCE pgboss.%I OWNER TO obligarth', r.relname);
  END LOOP;
  FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'pgboss' LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO obligarth', r.sig);
  END LOOP;
  FOR r IN SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
            WHERE n.nspname = 'pgboss' AND t.typtype = 'e' LOOP
    EXECUTE format('ALTER TYPE pgboss.%I OWNER TO obligarth', r.typname);
  END LOOP;
END $$;
`;

/**
 * Privileges of the runtime role BEFORE the row level security is active
 * (step 1 of rls-tenant §10.4: the server runs as `obligarth`, the RLS
 * migration C is not applied yet). Plain DML on the tables of the schema —
 * read only for the reader role, never on the Knex tracking tables, insert
 * only on the grants journal — and the sequences of those tables. Applied by
 * server-migrate after the migrations, only while no table of the schema has
 * the RLS enabled: from migration C on, obligarth_private.rls_apply grants
 * per class (and revokes these first). Idempotent.
 */
export const PRE_RLS_GRANTS_SQL = String.raw`
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.oid::regclass::text AS qualified, c.relname
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'obligarth' AND c.relkind IN ('r', 'p') LOOP
    IF r.relname IN ('obligarth_migrations', 'obligarth_migrations_lock') THEN
      CONTINUE;
    ELSIF r.relname = 'platform_access_grants' THEN
      EXECUTE format('GRANT SELECT, INSERT ON %s TO obligarth', r.qualified);
    ELSE
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO obligarth', r.qualified);
      -- The reader role (contexts member and platform) never reads the
      -- identity tables, the session store nor the grants journal.
      IF r.relname NOT IN ('session', 'password_reset_tokens', 'tfa_trusted_sessions', 'step_up_throttle',
                           'user_device_keys', 'device_key_challenges', 'sso_foreign_users') THEN
        EXECUTE format('GRANT SELECT ON %s TO obligarth_reader', r.qualified);
      END IF;
    END IF;
  END LOOP;
  FOR r IN SELECT s.oid::regclass::text AS qualified, s.relname
             FROM pg_class s JOIN pg_namespace n ON n.oid = s.relnamespace
            WHERE n.nspname = 'obligarth' AND s.relkind = 'S'
              AND s.relname NOT IN ('obligarth_migrations_id_seq', 'obligarth_migrations_lock_index_seq') LOOP
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO obligarth', r.qualified);
  END LOOP;
  -- the boot guard checks the migrations applied (rls-tenant §7.9, point 4)
  IF to_regclass('obligarth.obligarth_migrations') IS NOT NULL THEN
    GRANT SELECT ON obligarth.obligarth_migrations TO obligarth;
  END IF;
END $$;
`;
