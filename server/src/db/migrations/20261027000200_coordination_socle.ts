import type { Knex } from 'knex';

// =============================================================================
// Shared ground of the P0 lots (coordination P0 §1.2 S3 and §2, slice S3 of the common phase)
// =============================================================================
//   - obligarth_private.widen_in_check(table, constraint, values[]): widens a CHECK of the form `column IN (…)` by
//     the values it lacks, idempotently (nothing changes, no ALTER and no lock on the table, when every value is
//     already there). Before widening, its shape is checked: the constraint must be exactly `column IN (its own
//     literals)` on one column (any other CHECK is refused, never rewritten), and a value longer than a varchar(n)
//     column is refused. A real widening takes an ACCESS EXCLUSIVE lock on the table (lock_timeout 5s: it fails
//     rather than holding up the table's queue behind a long transaction) and revalidates every row under it: the
//     knex transaction of a migration keeps ADD … NOT VALID and VALIDATE from being split. The lots
//     widen the shared CHECKs through it (assignments_resource_type_check, assignments_target_scope_check,
//     apps_kind_check, mdm_commands_origin_check, integration_deadline_items_kind_check…), in place of the
//     preconditions that fail when another lot widened the same list first: the order of the lots no longer
//     matters. Owner only (migrations), never the runtime role.
//   - obligarth_private.assignment_ref_kinds: the references of the assignments, one row per resource type
//     ('resource': the table of the resource, its liveness predicate, its column of target tenants when the master
//     tenant shares it) and per target scope ('target': the table of the target, none for 'tenant').
//     obligarth.check_assignment_reference() is generated from it by obligarth_private.assignment_ref_rebuild(),
//     run again by a statement trigger at every change of the table: a lot adds its row (INSERT) and widens the
//     CHECK (widen_in_check), nothing else. The generated function stays SECURITY INVOKER with static SQL (the RLS
//     of the referenced tables applies as before, no dynamic statement per row). Its seed (policy, app; tenant,
//     group, device) generates a function that behaves exactly as mdm_model_expand's: same lookups, same errors
//     (foreign_key_violation, constraints assignments_resource_reference and assignments_target_reference, same
//     messages), same order. Only a kind absent from the table is now refused instead of read as an app (the
//     resource) or left unchecked (the target): the CHECKs allow none today. obligarth.assignments_cleanup() is
//     generated from the same rows (obligarth_private.assignment_cleanup_rebuild(), same trigger): the deletion of
//     a row of a kind's table removes the assignments naming it, and the AFTER DELETE trigger
//     <table>_assignments_cleanup is created on a new table (P0-5 smart_groups, P0-11 end_user_groups).
//   - obligarth_private.scope_ref_kinds: the kinds of the scope references (reports, settings, team_permissions,
//     notification_bindings, maintenance_windows, maintenance_window_disables) → their table;
//     obligarth.check_scope_reference() is generated from it by obligarth_private.scope_ref_rebuild() (same
//     trigger pattern): P0-12, P0-8 and P0-5 add their kinds (INSERT) instead of rewriting the shared body. A kind
//     absent from the table stays unchecked, as before (tenant…). Seed (group, device): the body of rls_foundation.
// Precondition (method of legacy_agent): check_assignment_reference and assignments_cleanup are still the bodies of
// mdm_model_expand, check_scope_reference that of rls_foundation, assignments_resource_type_check and
// assignments_target_scope_check still have their lists of mdm_model_expand.
// Rules of the specs README §3: SQL by String.raw, no question mark, functions with SET search_path = pg_catalog,
// pg_temp and EXECUTE revoked from PUBLIC, rls_assert_clean() last. Runs as obligarth_owner (server-migrate),
// after ops_command_backlog.
// =============================================================================

// md5 of the body of obligarth.check_assignment_reference() written by 20261002120000_mdm_model_expand.
const ORIGINAL_BODY_MD5 = '0e231864117f0eaa11f4b81a3fedfc82';
// md5 of the body of obligarth.assignments_cleanup() written by 20261002120000_mdm_model_expand.
const CLEANUP_BODY_MD5 = 'e223d8c2fb25d50807d9ab60663ce14a';
// md5 of the body of obligarth.check_scope_reference() written by 20261001110000_rls_foundation.
const SCOPE_BODY_MD5 = 'eb7975d3cdccd4c91d3307e8c60d83c2';

const UP = String.raw`-- =============================================================================
-- Shared ground of the P0 lots: widening of the CHECK lists, references of the assignments (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

-- 0. Preconditions ------------------------------------------------------------------
DO $$
DECLARE v_found text[];
BEGIN
  IF to_regclass('obligarth.assignments') IS NULL
     OR to_regprocedure('obligarth.check_assignment_reference()') IS NULL THEN
    RAISE EXCEPTION 'coordination_socle: apply mdm_model_expand first';
  END IF;
  IF (SELECT md5(p.prosrc) FROM pg_proc p WHERE p.oid = 'obligarth.check_assignment_reference()'::regprocedure)
     IS DISTINCT FROM '${ORIGINAL_BODY_MD5}' THEN
    RAISE EXCEPTION 'coordination_socle: obligarth.check_assignment_reference() differs from mdm_model_expand: move its branches into obligarth_private.assignment_ref_kinds';
  END IF;
  IF to_regprocedure('obligarth.assignments_cleanup()') IS NULL
     OR (SELECT md5(p.prosrc) FROM pg_proc p WHERE p.oid = 'obligarth.assignments_cleanup()'::regprocedure)
        IS DISTINCT FROM '${CLEANUP_BODY_MD5}' THEN
    RAISE EXCEPTION 'coordination_socle: obligarth.assignments_cleanup() differs from mdm_model_expand: move its branches into obligarth_private.assignment_ref_kinds';
  END IF;
  IF to_regprocedure('obligarth.check_scope_reference()') IS NULL
     OR (SELECT md5(p.prosrc) FROM pg_proc p WHERE p.oid = 'obligarth.check_scope_reference()'::regprocedure)
        IS DISTINCT FROM '${SCOPE_BODY_MD5}' THEN
    RAISE EXCEPTION 'coordination_socle: obligarth.check_scope_reference() differs from rls_foundation: move its branches into obligarth_private.scope_ref_kinds';
  END IF;
  SELECT COALESCE(array_agg(DISTINCT m[1] ORDER BY m[1]), '{}'::text[]) INTO v_found
    FROM pg_constraint c CROSS JOIN LATERAL regexp_matches(pg_get_constraintdef(c.oid), '''([a-z_]+)''', 'g') AS m
   WHERE c.conrelid = 'obligarth.assignments'::regclass AND c.conname = 'assignments_resource_type_check';
  IF v_found IS DISTINCT FROM ARRAY['app', 'policy']::text[] THEN
    RAISE EXCEPTION 'coordination_socle: assignments_resource_type_check differs from mdm_model_expand (%)', v_found;
  END IF;
  SELECT COALESCE(array_agg(DISTINCT m[1] ORDER BY m[1]), '{}'::text[]) INTO v_found
    FROM pg_constraint c CROSS JOIN LATERAL regexp_matches(pg_get_constraintdef(c.oid), '''([a-z_]+)''', 'g') AS m
   WHERE c.conrelid = 'obligarth.assignments'::regclass AND c.conname = 'assignments_target_scope_check';
  IF v_found IS DISTINCT FROM ARRAY['device', 'group', 'tenant']::text[] THEN
    RAISE EXCEPTION 'coordination_socle: assignments_target_scope_check differs from mdm_model_expand (%)', v_found;
  END IF;
END $$;

-- 1. Idempotent widening of a CHECK list ------------------------------------------------------------------------
-- p_table: a table of schema obligarth; p_constraint: a CHECK of the form "column IN ('a', 'b', …)" on one column;
-- p_values: the values the list must hold (those already there are kept, in their order; the others are appended,
-- in the order given). Returns true when the constraint was replaced, false when it already held every value.
-- Nothing to add: false at once, without any ALTER (no lock taken on the table; the shape is then not probed).
-- Otherwise the shape is probed and the CHECK replaced: ACCESS EXCLUSIVE on the table until the end of the
-- migration's transaction, with a scan of every row (the new constraint is validated: one transaction cannot split
-- ADD NOT VALID and VALIDATE); lock_timeout 5s makes it fail cleanly rather than queue every reader and writer of the
-- table behind a long transaction (an old server container still running during an update).
CREATE FUNCTION obligarth_private.widen_in_check(p_table regclass, p_constraint text, p_values text[])
  RETURNS boolean LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp SET lock_timeout = '5s' AS $$
DECLARE
  v_name   text := p_table::text;          -- schema-qualified: obligarth is not in search_path here
  v_con    record;
  v_col    text;
  v_typmod integer;
  v_type   oid;
  v_have   text[];
  v_add    text[] := '{}';
  v_v      text;
  v_probe  text;
BEGIN
  IF v_name !~ '^obligarth\.[a-z_][a-z0-9_]*$' THEN
    RAISE EXCEPTION 'widen_in_check: % is not a table of schema obligarth', v_name;
  END IF;
  IF p_values IS NULL OR cardinality(p_values) = 0 OR array_position(p_values, NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'widen_in_check: % on %: no value, or a NULL value', p_constraint, v_name;
  END IF;
  SELECT c.oid, c.conname, c.contype, c.conkey, c.convalidated, pg_get_constraintdef(c.oid) AS def INTO v_con
    FROM pg_constraint c WHERE c.conrelid = p_table AND c.conname = p_constraint;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'widen_in_check: no constraint % on %', p_constraint, v_name;
  END IF;
  IF v_con.contype <> 'c' OR cardinality(v_con.conkey) <> 1 OR NOT v_con.convalidated THEN
    RAISE EXCEPTION 'widen_in_check: % on % is not a validated CHECK on one column', p_constraint, v_name;
  END IF;
  SELECT a.attname, a.atttypmod, a.atttypid INTO v_col, v_typmod, v_type
    FROM pg_attribute a WHERE a.attrelid = p_table AND a.attnum = v_con.conkey[1];
  -- Its literals, in the order of the definition ('' is a quote inside a literal).
  SELECT COALESCE(array_agg(replace(m[1], '''''', '''') ORDER BY n), '{}'::text[]) INTO v_have
    FROM regexp_matches(v_con.def, '''(([^'']|'''')*)''', 'g') WITH ORDINALITY AS t(m, n);
  IF cardinality(v_have) = 0 THEN
    RAISE EXCEPTION 'widen_in_check: % on % holds no literal', p_constraint, v_name;
  END IF;
  -- The values it lacks, before any ALTER.
  FOREACH v_v IN ARRAY p_values LOOP
    IF NOT (v_v = ANY (v_have)) AND NOT (v_v = ANY (v_add)) THEN
      IF v_type IN ('varchar'::regtype::oid, 'bpchar'::regtype::oid) AND v_typmod > 4 AND length(v_v) > v_typmod - 4 THEN
        RAISE EXCEPTION 'widen_in_check: % is longer than column %.% (%)', v_v, v_name, v_col, v_typmod - 4;
      END IF;
      v_add := v_add || v_v;
    END IF;
  END LOOP;
  IF cardinality(v_add) = 0 THEN
    RETURN false;                            -- every value is there: no ALTER, no lock on the table
  END IF;
  -- Its shape: the same definition as "column IN (its literals)", compared on a probe added NOT VALID (no scan),
  -- then dropped. Anything else (another column, an AND, a NOT, NO INHERIT, a literal that is no value of the
  -- column…) is refused, never rewritten.
  BEGIN
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT obligarth_widen_probe CHECK (%I IN (%s)) NOT VALID',
                   v_name, v_col, (SELECT string_agg(quote_literal(x), ', ' ORDER BY n) FROM unnest(v_have) WITH ORDINALITY AS u(x, n)));
    SELECT regexp_replace(pg_get_constraintdef(c.oid), ' NOT VALID$', '') INTO v_probe
      FROM pg_constraint c WHERE c.conrelid = p_table AND c.conname = 'obligarth_widen_probe';
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT obligarth_widen_probe', v_name);
  EXCEPTION WHEN OTHERS THEN
    v_probe := NULL;                         -- the probe itself failed (e.g. a literal of another type): not an IN list
  END;
  IF v_probe IS DISTINCT FROM v_con.def THEN
    RAISE EXCEPTION 'widen_in_check: % on % is not of the form % IN (…): %', p_constraint, v_name, v_col, v_con.def;
  END IF;
  -- Widening only: every row that met the old list meets the new one (the ADD validates it all the same).
  EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK (%I IN (%s))',
                 v_name, v_con.conname, v_con.conname, v_col,
                 (SELECT string_agg(quote_literal(x), ', ' ORDER BY n) FROM unnest(v_have || v_add) WITH ORDINALITY AS u(x, n)));
  RETURN true;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.widen_in_check(regclass, text, text[]) FROM PUBLIC;
COMMENT ON FUNCTION obligarth_private.widen_in_check(regclass, text, text[]) IS
  'migrations: widens a CHECK "column IN (...)" by the values it lacks, idempotently (P0 coordination S3)';

-- 2. References of the assignments, by table ----------------------------------------------------------------------
-- side 'resource': resource_type → ref_table (a row of it with id = resource_id and tenant_id = resource_tenant_id,
--   live_predicate true; shared_column: the array of the tenants a master resource is shared with, NULL when the
--   resource must belong to the tenant of the assignment).
-- side 'target': target_scope → ref_table (a row of it with id = target_id in the tenant of the assignment, then
--   live_predicate), or NULL when the scope has no target row ('tenant').
-- live_predicate: a boolean SQL expression on the alias r (the referenced row); written by the migrations only.
CREATE TABLE obligarth_private.assignment_ref_kinds (
  side            text        NOT NULL CHECK (side IN ('resource', 'target')),
  kind            text        NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{0,15}$'),
  ref_table       text        CHECK (ref_table ~ '^[a-z_][a-z0-9_]{0,62}$'),
  live_predicate  text        CHECK (length(live_predicate) BETWEEN 1 AND 500 AND live_predicate !~ '[;$]'),
  shared_column   text        CHECK (shared_column ~ '^[a-z_][a-z0-9_]{0,62}$'),
  note            text,
  registered_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (side, kind),
  CONSTRAINT assignment_ref_kinds_resource_table CHECK (side = 'target' OR ref_table IS NOT NULL),
  CONSTRAINT assignment_ref_kinds_shared_resource CHECK (side = 'resource' OR shared_column IS NULL),
  CONSTRAINT assignment_ref_kinds_no_table CHECK (ref_table IS NOT NULL OR live_predicate IS NULL)
);
REVOKE ALL ON obligarth_private.assignment_ref_kinds FROM PUBLIC;

-- The generator: obligarth.check_assignment_reference() from the rows above (kinds in alphabetical order).
CREATE FUNCTION obligarth_private.assignment_ref_rebuild() RETURNS void
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r       record;
  v_res   text := '';
  v_tgt   text := '';
  v_kw    text;
  v_cols  text[];
BEGIN
  FOR r IN SELECT k.* FROM obligarth_private.assignment_ref_kinds k ORDER BY k.side, k.kind LOOP
    IF r.ref_table IS NOT NULL THEN
      IF to_regclass(format('obligarth.%I', r.ref_table)) IS NULL THEN
        RAISE EXCEPTION 'assignment_ref_rebuild: % % references obligarth.%, which does not exist', r.side, r.kind, r.ref_table;
      END IF;
      SELECT array_agg(a.attname::text) INTO v_cols FROM pg_attribute a
       WHERE a.attrelid = to_regclass(format('obligarth.%I', r.ref_table)) AND a.attnum > 0 AND NOT a.attisdropped;
      IF NOT (ARRAY['id', 'tenant_id'] <@ v_cols) OR (r.shared_column IS NOT NULL AND NOT (r.shared_column = ANY (v_cols))) THEN
        RAISE EXCEPTION 'assignment_ref_rebuild: obligarth.% lacks id, tenant_id or %', r.ref_table, COALESCE(r.shared_column, 'its shared column');
      END IF;
    END IF;
    IF r.side = 'resource' THEN
      v_kw := CASE WHEN v_res = '' THEN 'IF' ELSE 'ELSIF' END;
      v_res := v_res || format(E'  %s NEW.resource_type = %L THEN\n'
        '    SELECT EXISTS (SELECT 1 FROM obligarth.%I r\n'
        '                   WHERE r.id = NEW.resource_id AND r.tenant_id = NEW.resource_tenant_id%s\n'
        '                     AND %s) INTO v_ok;\n',
        v_kw, r.kind, r.ref_table,
        CASE WHEN r.live_predicate IS NULL THEN '' ELSE format(' AND (%s)', r.live_predicate) END,
        CASE WHEN r.shared_column IS NULL THEN 'r.tenant_id = NEW.tenant_id'
             ELSE format('(r.tenant_id = NEW.tenant_id OR r.%I @> ARRAY[NEW.tenant_id])', r.shared_column) END);
    ELSE
      v_kw := CASE WHEN v_tgt = '' THEN 'IF' ELSE 'ELSIF' END;
      IF r.ref_table IS NULL THEN
        v_tgt := v_tgt || format(E'  %s NEW.target_scope = %L THEN\n    v_ok := true;\n', v_kw, r.kind);
      ELSE
        v_tgt := v_tgt || format(E'  %s NEW.target_scope = %L THEN\n'
          '    PERFORM 1 FROM obligarth.%I r WHERE r.id = NEW.target_id AND r.tenant_id = NEW.tenant_id%s;\n'
          '    v_ok := FOUND;\n',
          v_kw, r.kind, r.ref_table,
          CASE WHEN r.live_predicate IS NULL THEN '' ELSE format(' AND (%s)', r.live_predicate) END);
      END IF;
    END IF;
  END LOOP;
  v_res := CASE WHEN v_res = '' THEN E'  v_ok := false;\n' ELSE v_res || E'  ELSE\n    v_ok := false;\n  END IF;\n' END;
  v_tgt := CASE WHEN v_tgt = '' THEN E'  v_ok := false;\n' ELSE v_tgt || E'  ELSE\n    v_ok := false;\n  END IF;\n' END;
  EXECUTE format(E'CREATE OR REPLACE FUNCTION obligarth.check_assignment_reference() RETURNS trigger\n'
    '  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$\n'
    '-- Generated by obligarth_private.assignment_ref_rebuild() from obligarth_private.assignment_ref_kinds:\n'
    '-- never edited by hand (a lot adds its row to the table).\n'
    'DECLARE\n'
    '  v_ok boolean;\n'
    'BEGIN\n'
    '%s'
    '  IF NOT v_ok THEN\n'
    '    RAISE EXCEPTION USING ERRCODE = ''foreign_key_violation'', CONSTRAINT = ''assignments_resource_reference'',\n'
    '      MESSAGE = ''assignments: no such resource for the tenant of the row'';\n'
    '  END IF;\n'
    '%s'
    '  IF NOT v_ok THEN\n'
    '    RAISE EXCEPTION USING ERRCODE = ''foreign_key_violation'', CONSTRAINT = ''assignments_target_reference'',\n'
    '      MESSAGE = ''assignments: no such target in the tenant of the row'';\n'
    '  END IF;\n'
    '  RETURN NEW;\n'
    'END $fn$', v_res, v_tgt);
  REVOKE ALL ON FUNCTION obligarth.check_assignment_reference() FROM PUBLIC;
  COMMENT ON FUNCTION obligarth.check_assignment_reference() IS
    'assignments: resource and target references, generated from obligarth_private.assignment_ref_kinds';
END $$;
REVOKE ALL ON FUNCTION obligarth_private.assignment_ref_rebuild() FROM PUBLIC;

-- The cleanup of the assignments at the deletion of what they name: obligarth.assignments_cleanup() from the same
-- rows (every kind with a table), and its AFTER DELETE trigger <table>_assignments_cleanup on each of these tables
-- (created when missing; those of mdm_model_expand already have this name). Tables in alphabetical order, then
-- side and kind.
CREATE FUNCTION obligarth_private.assignment_cleanup_rebuild() RETURNS void
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r       record;
  v_body  text := '';
  v_table text := NULL;
  v_trg   text;
BEGIN
  FOR r IN SELECT k.* FROM obligarth_private.assignment_ref_kinds k WHERE k.ref_table IS NOT NULL
            ORDER BY k.ref_table, k.side, k.kind LOOP
    IF r.ref_table IS DISTINCT FROM v_table THEN
      v_body := v_body || format(E'  %s TG_TABLE_NAME = %L THEN\n', CASE WHEN v_table IS NULL THEN 'IF' ELSE 'ELSIF' END, r.ref_table);
      v_table := r.ref_table;
      v_trg := left(r.ref_table, 43) || '_assignments_cleanup';
      IF NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = to_regclass(format('obligarth.%I', r.ref_table))
                                                 AND t.tgname = v_trg AND NOT t.tgisinternal) THEN
        EXECUTE format('CREATE TRIGGER %I AFTER DELETE ON obligarth.%I FOR EACH ROW EXECUTE FUNCTION obligarth.assignments_cleanup()',
                       v_trg, r.ref_table);
      END IF;
    END IF;
    IF r.side = 'resource' THEN
      v_body := v_body || format(E'    DELETE FROM obligarth.assignments a\n'
        '     WHERE a.resource_type = %L AND a.resource_tenant_id = OLD.tenant_id AND a.resource_id = OLD.id;\n', r.kind);
    ELSE
      v_body := v_body || format(E'    DELETE FROM obligarth.assignments a\n'
        '     WHERE a.tenant_id = OLD.tenant_id AND a.target_scope = %L AND a.target_id = OLD.id;\n', r.kind);
    END IF;
  END LOOP;
  IF v_body <> '' THEN
    v_body := v_body || E'  END IF;\n';
  END IF;
  EXECUTE format(E'CREATE OR REPLACE FUNCTION obligarth.assignments_cleanup() RETURNS trigger\n'
    '  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$\n'
    '-- Generated by obligarth_private.assignment_cleanup_rebuild() from obligarth_private.assignment_ref_kinds:\n'
    '-- never edited by hand (a lot adds its row to the table).\n'
    'BEGIN\n'
    '%s'
    '  RETURN OLD;\n'
    'END $fn$', v_body);
  REVOKE ALL ON FUNCTION obligarth.assignments_cleanup() FROM PUBLIC;
  COMMENT ON FUNCTION obligarth.assignments_cleanup() IS
    'assignments: removed with what they name, generated from obligarth_private.assignment_ref_kinds';
END $$;
REVOKE ALL ON FUNCTION obligarth_private.assignment_cleanup_rebuild() FROM PUBLIC;

CREATE FUNCTION obligarth_private.assignment_ref_kinds_changed() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM obligarth_private.assignment_ref_rebuild();
  PERFORM obligarth_private.assignment_cleanup_rebuild();
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.assignment_ref_kinds_changed() FROM PUBLIC;
CREATE TRIGGER assignment_ref_kinds_rebuild
  AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON obligarth_private.assignment_ref_kinds
  FOR EACH STATEMENT EXECUTE FUNCTION obligarth_private.assignment_ref_kinds_changed();

-- The references of mdm_model_expand (one statement: one rebuild).
INSERT INTO obligarth_private.assignment_ref_kinds (side, kind, ref_table, live_predicate, shared_column, note) VALUES
  ('resource', 'policy', 'policies',      'r.state <> ''archived''', 'target_tenant_ids', 'mdm_model_expand'),
  ('resource', 'app',    'apps',          'r.archived_at IS NULL',   'target_tenant_ids', 'mdm_model_expand'),
  ('target',   'tenant', NULL,            NULL,                      NULL,                'mdm_model_expand: no target row'),
  ('target',   'group',  'device_groups', NULL,                      NULL,                'mdm_model_expand'),
  ('target',   'device', 'devices',       NULL,                      NULL,                'mdm_model_expand');

-- 3. References of a scope (scope_type/scope_id, scope/scope_id), by table ---------------------------------------
-- obligarth.check_scope_reference(type column, id column) guards reports, settings, team_permissions,
-- notification_bindings, maintenance_windows and maintenance_window_disables: a kind of this table names a row of
-- ref_table with id = the scope id in the tenant of the row (then live_predicate on r). A kind absent from the table
-- is not checked (as before: 'tenant' and the like have no row): a lot that adds a kind with a row adds it here.
CREATE TABLE obligarth_private.scope_ref_kinds (
  kind            text        PRIMARY KEY CHECK (kind ~ '^[a-z][a-z0-9_]{0,15}$'),
  ref_table       text        NOT NULL CHECK (ref_table ~ '^[a-z_][a-z0-9_]{0,62}$'),
  live_predicate  text        CHECK (length(live_predicate) BETWEEN 1 AND 500 AND live_predicate !~ '[;$]'),
  note            text,
  registered_at   timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON obligarth_private.scope_ref_kinds FROM PUBLIC;

-- The generator: obligarth.check_scope_reference() from the rows above (kinds in alphabetical order), same lookups,
-- same error (23503, constraint <table>_scope_tenant, same message) as the body of rls_foundation.
CREATE FUNCTION obligarth_private.scope_ref_rebuild() RETURNS void
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r       record;
  v_br    text := '';
  v_cols  text[];
BEGIN
  FOR r IN SELECT k.* FROM obligarth_private.scope_ref_kinds k ORDER BY k.kind LOOP
    IF to_regclass(format('obligarth.%I', r.ref_table)) IS NULL THEN
      RAISE EXCEPTION 'scope_ref_rebuild: % references obligarth.%, which does not exist', r.kind, r.ref_table;
    END IF;
    SELECT array_agg(a.attname::text) INTO v_cols FROM pg_attribute a
     WHERE a.attrelid = to_regclass(format('obligarth.%I', r.ref_table)) AND a.attnum > 0 AND NOT a.attisdropped;
    IF NOT (ARRAY['id', 'tenant_id'] <@ v_cols) THEN
      RAISE EXCEPTION 'scope_ref_rebuild: obligarth.% lacks id or tenant_id', r.ref_table;
    END IF;
    v_br := v_br || format(E'  %s v_type = %L THEN\n'
      '    SELECT EXISTS (SELECT 1 FROM obligarth.%I r WHERE r.id = v_id AND r.tenant_id = NEW.tenant_id%s) INTO v_ok;\n',
      CASE WHEN v_br = '' THEN 'IF' ELSE 'ELSIF' END, r.kind, r.ref_table,
      CASE WHEN r.live_predicate IS NULL THEN '' ELSE format(' AND (%s)', r.live_predicate) END);
  END LOOP;
  IF v_br <> '' THEN
    v_br := v_br || E'  END IF;\n';
  END IF;
  -- Concatenation, not format(): the generated body holds format() placeholders of its own.
  EXECUTE E'CREATE OR REPLACE FUNCTION obligarth.check_scope_reference() RETURNS trigger\n'
    '  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$\n'
    '-- Generated by obligarth_private.scope_ref_rebuild() from obligarth_private.scope_ref_kinds:\n'
    '-- never edited by hand (a lot adds its row to the table).\n'
    'DECLARE\n'
    '  v_type text := to_jsonb(NEW) ->> TG_ARGV[0];\n'
    '  v_id   bigint := (to_jsonb(NEW) ->> TG_ARGV[1])::bigint;\n'
    '  v_ok   boolean := true;\n'
    'BEGIN\n'
    || v_br ||
    E'  IF NOT v_ok THEN\n'
    '    RAISE EXCEPTION USING ERRCODE = ''23503'', CONSTRAINT = TG_TABLE_NAME || ''_scope_tenant'',\n'
    '      MESSAGE = format(''%s: %s %s is not a %s of tenant %s'', TG_TABLE_NAME, TG_ARGV[1], v_id, v_type, NEW.tenant_id);\n'
    '  END IF;\n'
    '  RETURN NEW;\n'
    'END $fn$';
  COMMENT ON FUNCTION obligarth.check_scope_reference() IS
    'scope references (scope type, scope id) of the tenant of the row, generated from obligarth_private.scope_ref_kinds';
END $$;
REVOKE ALL ON FUNCTION obligarth_private.scope_ref_rebuild() FROM PUBLIC;

CREATE FUNCTION obligarth_private.scope_ref_kinds_changed() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM obligarth_private.scope_ref_rebuild();
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.scope_ref_kinds_changed() FROM PUBLIC;
CREATE TRIGGER scope_ref_kinds_rebuild
  AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON obligarth_private.scope_ref_kinds
  FOR EACH STATEMENT EXECUTE FUNCTION obligarth_private.scope_ref_kinds_changed();

-- The references of rls_foundation (one statement: one rebuild).
INSERT INTO obligarth_private.scope_ref_kinds (kind, ref_table, live_predicate, note) VALUES
  ('group',  'device_groups', NULL, 'rls_foundation'),
  ('device', 'devices',       NULL, 'rls_foundation');

SELECT obligarth.rls_assert_clean();
`;

// The body of mdm_model_expand, put back as it was.
const DOWN = String.raw`
SET LOCAL search_path = pg_catalog, pg_temp;
DROP TRIGGER scope_ref_kinds_rebuild ON obligarth_private.scope_ref_kinds;
DROP TABLE obligarth_private.scope_ref_kinds;
DROP FUNCTION obligarth_private.scope_ref_kinds_changed();
DROP FUNCTION obligarth_private.scope_ref_rebuild();
CREATE OR REPLACE FUNCTION obligarth.check_scope_reference() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_type text := to_jsonb(NEW) ->> TG_ARGV[0];
  v_id   bigint := (to_jsonb(NEW) ->> TG_ARGV[1])::bigint;
  v_ok   boolean := true;
BEGIN
  IF v_type = 'group' THEN
    SELECT EXISTS (SELECT 1 FROM obligarth.device_groups g WHERE g.id = v_id AND g.tenant_id = NEW.tenant_id) INTO v_ok;
  ELSIF v_type = 'device' THEN
    SELECT EXISTS (SELECT 1 FROM obligarth.devices d WHERE d.id = v_id AND d.tenant_id = NEW.tenant_id) INTO v_ok;
  END IF;
  IF NOT v_ok THEN
    RAISE EXCEPTION USING ERRCODE = '23503', CONSTRAINT = TG_TABLE_NAME || '_scope_tenant',
      MESSAGE = format('%s: %s %s is not a %s of tenant %s', TG_TABLE_NAME, TG_ARGV[1], v_id, v_type, NEW.tenant_id);
  END IF;
  RETURN NEW;
END $$;
COMMENT ON FUNCTION obligarth.check_scope_reference() IS NULL;
DROP TRIGGER assignment_ref_kinds_rebuild ON obligarth_private.assignment_ref_kinds;
DROP TABLE obligarth_private.assignment_ref_kinds;
DROP FUNCTION obligarth_private.assignment_ref_kinds_changed();
DROP FUNCTION obligarth_private.assignment_cleanup_rebuild();
DROP FUNCTION obligarth_private.assignment_ref_rebuild();
DROP FUNCTION obligarth_private.widen_in_check(regclass, text, text[]);
CREATE OR REPLACE FUNCTION obligarth.assignments_cleanup() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_TABLE_NAME = 'device_groups' THEN
    DELETE FROM obligarth.assignments a
     WHERE a.tenant_id = OLD.tenant_id AND a.target_scope = 'group' AND a.target_id = OLD.id;
  ELSIF TG_TABLE_NAME = 'devices' THEN
    DELETE FROM obligarth.assignments a
     WHERE a.tenant_id = OLD.tenant_id AND a.target_scope = 'device' AND a.target_id = OLD.id;
  ELSIF TG_TABLE_NAME = 'policies' THEN
    DELETE FROM obligarth.assignments a
     WHERE a.resource_type = 'policy' AND a.resource_tenant_id = OLD.tenant_id AND a.resource_id = OLD.id;
  ELSIF TG_TABLE_NAME = 'apps' THEN
    DELETE FROM obligarth.assignments a
     WHERE a.resource_type = 'app' AND a.resource_tenant_id = OLD.tenant_id AND a.resource_id = OLD.id;
  END IF;
  RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION obligarth.assignments_cleanup() FROM PUBLIC;
COMMENT ON FUNCTION obligarth.assignments_cleanup() IS NULL;
CREATE OR REPLACE FUNCTION obligarth.check_assignment_reference() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_ok boolean;
BEGIN
  IF NEW.resource_type = 'policy' THEN
    SELECT EXISTS (SELECT 1 FROM obligarth.policies p
                   WHERE p.id = NEW.resource_id AND p.tenant_id = NEW.resource_tenant_id AND p.state <> 'archived'
                     AND (p.tenant_id = NEW.tenant_id OR p.target_tenant_ids @> ARRAY[NEW.tenant_id])) INTO v_ok;
  ELSE
    SELECT EXISTS (SELECT 1 FROM obligarth.apps a
                   WHERE a.id = NEW.resource_id AND a.tenant_id = NEW.resource_tenant_id AND a.archived_at IS NULL
                     AND (a.tenant_id = NEW.tenant_id OR a.target_tenant_ids @> ARRAY[NEW.tenant_id])) INTO v_ok;
  END IF;
  IF NOT v_ok THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'assignments_resource_reference',
      MESSAGE = 'assignments: no such resource for the tenant of the row';
  END IF;
  IF NEW.target_scope = 'group' THEN
    PERFORM 1 FROM obligarth.device_groups g WHERE g.id = NEW.target_id AND g.tenant_id = NEW.tenant_id;
  ELSIF NEW.target_scope = 'device' THEN
    PERFORM 1 FROM obligarth.devices d WHERE d.id = NEW.target_id AND d.tenant_id = NEW.tenant_id;
  END IF;
  IF NEW.target_scope IN ('group', 'device') AND NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'assignments_target_reference',
      MESSAGE = 'assignments: no such target in the tenant of the row';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth.check_assignment_reference() FROM PUBLIC;
COMMENT ON FUNCTION obligarth.check_assignment_reference() IS NULL;
SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw(DOWN);
}
