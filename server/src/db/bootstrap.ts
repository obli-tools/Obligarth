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
-- pg_temp last (lot A8): a temporary table never stands for a table of the brain (the leases set it again)
ALTER ROLE obligarth SET search_path = obligarth, pg_temp;
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

/**
 * The role of the backup services (P0-13 T9, FND-09; compose profile backup):
 * pg_receivewal and pg_basebackup connect with it (REPLICATION; the line of
 * pg_hba.conf that admits it is added by the postgres service of
 * docker-compose.yml), and it inserts the reports of the backups in
 * obligarth.ops_backup_reports, nothing else: no other attribute, no
 * membership, no privilege on any other table, sequence or function of the
 * brain, nor on the schemas obligarth_private, pgboss and apple_edge or their
 * objects (revoked at every run; server-migrate --check also reports any
 * such grant, column and schema privileges included, and a membership of it
 * or in it). Run after BOOTSTRAP_SQL (the schema exists);
 * the grants on the table of the reports are given once its migration
 * (ops_backups) is applied, here at the next run and by the migration itself.
 * Its password is set separately (DB_BACKUP_PASSWORD_FILE), like the runtime
 * role's. An administrator that is not a superuser may be refused the
 * REPLICATION attribute (PostgreSQL 16: CREATEROLE grants it only to a holder
 * of it): server-migrate then warns, the database has no backup role and
 * its own backups are the operator's.
 */
export const BOOTSTRAP_BACKUP_ROLE_SQL = String.raw`
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'obligarth_backup') THEN
    CREATE ROLE obligarth_backup LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT CONNECTION LIMIT 8;
  END IF;
END $$;
ALTER ROLE obligarth_backup WITH LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT CONNECTION LIMIT 8;
ALTER ROLE obligarth_backup SET search_path = pg_catalog, pg_temp;
ALTER ROLE obligarth_backup SET idle_in_transaction_session_timeout = '60s';
GRANT USAGE ON SCHEMA obligarth TO obligarth_backup;
REVOKE ALL ON ALL TABLES IN SCHEMA obligarth FROM obligarth_backup;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA obligarth FROM obligarth_backup;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA obligarth FROM obligarth_backup;
REVOKE CREATE ON SCHEMA obligarth FROM obligarth_backup;
-- The other schemas of the database (the brain's private one, pg-boss, apple-edge's, when they exist): nothing,
-- whatever was granted by hand. apple-edge's objects may belong to a role this administrator cannot speak for: a
-- refusal there is left to server-migrate --check, which reports any grant that stays.
DO $$
DECLARE
  s text;
BEGIN
  FOREACH s IN ARRAY ARRAY['obligarth_private', 'pgboss', 'apple_edge'] LOOP
    CONTINUE WHEN to_regnamespace(s) IS NULL;
    BEGIN
      EXECUTE format('REVOKE ALL ON SCHEMA %I FROM obligarth_backup', s);
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM obligarth_backup', s);
      EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM obligarth_backup', s);
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM obligarth_backup', s);
    EXCEPTION WHEN insufficient_privilege THEN
      RAISE WARNING 'obligarth_backup: the grants of the schema % could not be revoked by this administrator', s;
    END;
  END LOOP;
END $$;
DO $$
BEGIN
  IF to_regclass('obligarth.ops_backup_reports') IS NOT NULL THEN
    GRANT INSERT ON obligarth.ops_backup_reports TO obligarth_backup;
    GRANT USAGE ON SEQUENCE obligarth.ops_backup_reports_id_seq TO obligarth_backup;
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
 * The roles that would carry the runtime role past the row level security if
 * it could take them on (rls-tenant §7.9, point 1): any role with SUPERUSER,
 * BYPASSRLS, CREATEROLE or CREATEDB, the owner role, PostgreSQL's predefined
 * roles of the server's files and programs (superuser-level access, as
 * PostgreSQL documents them) and those of all the data (every table of every
 * schema: obligarth_private, apple-edge's). The caller appends the membership
 * condition (pg_has_role … 'SET' or 'USAGE') and the ORDER BY. Checked by the
 * boot guard and by server-migrate --check, as rule 14 of
 * obligarth.rls_audit() does from the RLS migration C on.
 */
export const PRIVILEGED_ROLES_SQL = String.raw`
SELECT r.rolname FROM pg_catalog.pg_roles r
 WHERE (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb
        OR r.rolname IN ('obligarth_owner', 'pg_execute_server_program', 'pg_read_server_files', 'pg_write_server_files',
                         'pg_read_all_data', 'pg_write_all_data'))`;

/**
 * The same reach from the reader role, which the runtime role can always
 * take on (SET ROLE obligarth_reader, rls-tenant §3.1): a privileged role
 * granted to the reader WITH INHERIT TRUE, SET FALSE is reached that way
 * although pg_has_role(<runtime role>, …) answers false for it (review of
 * lot A5). Appended by the callers of PRIVILEGED_ROLES_SQL with OR; false
 * when the reader role does not exist.
 */
export const READER_REACHES_SQL = String.raw`EXISTS (SELECT 1 FROM pg_catalog.pg_roles rr WHERE rr.rolname = 'obligarth_reader'
            AND (pg_catalog.pg_has_role(rr.oid, r.oid, 'SET') OR pg_catalog.pg_has_role(rr.oid, r.oid, 'USAGE')))`;

/**
 * Privileges of the runtime role BEFORE the row level security is active
 * (step 1 of rls-tenant §10.4: the server runs as `obligarth`, the RLS
 * migration C is not applied yet). Plain DML on the tables of the schema —
 * read only for the reader role, never on the Knex tracking tables, insert
 * only on the grants journal, never an update of the audit journal — and the
 * sequences of those tables. Applied by server-migrate after the migrations,
 * only while no table of the schema has the RLS enabled: from migration C
 * on, obligarth_private.rls_apply grants per class (and revokes these first).
 * Idempotent.
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
    ELSIF r.relname = 'audit_logs' THEN
      -- The audit journal is never updated (rls-tenant §5.3.5): what
      -- migration C grants it (block C.8), and no more.
      EXECUTE format('REVOKE UPDATE ON %s FROM obligarth', r.qualified);
      EXECUTE format('GRANT SELECT, INSERT, DELETE ON %s TO obligarth', r.qualified);
      EXECUTE format('GRANT SELECT ON %s TO obligarth_reader', r.qualified);
    ELSE
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO obligarth', r.qualified);
      -- The reader role (contexts member and platform) never reads the
      -- identity tables, the session store, the grants journal nor the
      -- vault's technical tables (keys, instance secrets, key operations:
      -- class technical of migration C, coffre-secrets §4.1).
      IF r.relname NOT IN ('session', 'password_reset_tokens', 'tfa_trusted_sessions', 'step_up_throttle',
                           'user_device_keys', 'device_key_challenges', 'sso_foreign_users',
                           'data_keys', 'instance_secrets', 'vault_operations') THEN
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
