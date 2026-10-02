import type { Knex } from 'knex';

// Row level security, hardening (migration D, docs: rls-tenant §4.6, annex A.5, R12): the database context
// becomes a signed one, and the functions the policies and the triggers rely on no longer depend on the
// search_path of the session.
//   - D.1 obligarth_private.context_keys: the two inner HMAC blocks of each context key, deposited by
//     server-migrate from RLS_CONTEXT_KEY_FILE (and RLS_CONTEXT_KEY_PREVIOUS_FILE during a rotation),
//     unreadable by the runtime roles (no USAGE on the schema).
//   - D.2 obligarth.ctx_raw() verifies the context: format (the grammar of A and C, checked in two cheaper
//     steps), HMAC-SHA256 of an active key (computed in SQL, no pgcrypto), expiry. SECURITY DEFINER, in
//     plpgsql (its key lookup keeps its plan for the connection: measured cheaper than the SQL form of
//     annex A.5, which is planned again at every call).
//   - D.3 the field functions (ctx_kind, ctx_tenant, ctx_actor, ctx_actor_user, ctx_grant) get SQL-standard
//     bodies: parsed once, here, with this migration's search_path, so a function or an operator shadowed
//     in a schema the runtime role owns (pgboss) no longer changes them (review of lot A5), and still inlined
//     in the InitPlans of the policies; each calls ctx_raw() once, and parses it with a pure ctx_*_of(text).
//     D.3b: the definer helpers that need several fields (read set, platform grant, visible tenants) call
//     ctx_raw() once, and user_labels() reads the context once per call instead of once per row.
//   - D.4 the invoker functions written as plain text (integrity triggers, account guards, link hash and
//     seal message of the journal) get SET search_path = pg_catalog, pg_temp, for the same reason.
//   - D.5 review of the SECURITY DEFINER functions: the purge of the grants journal is reserved to a job,
//     the list of the audit chains to the jobs, the integrations and the platform administrators (AUD-A6-R11).
//   - D.6 obligarth.rls_audit() gains the checks this hardening relies on: every function of the two schemas
//     with a fixed search_path or a SQL-standard body; no column privilege to PUBLIC nor REFERENCES on a
//     column to the runtime roles; no function executable by PUBLIC; nothing of obligarth_private reachable
//     by the runtime roles; no privileged role reached through the reader role; ctx_raw() the verifier of the
//     signatures once the keys table exists.
// Runs as obligarth_owner (server-migrate) and ends with obligarth.rls_assert_clean(). The SQL holds no
// question mark (knex.raw would bind it) and is kept verbatim by String.raw (regular expressions contain
// backslashes).
const UP = String.raw`-- =============================================================================
-- Migration D: signed database context (run as obligarth_owner; ends with obligarth.rls_assert_clean())
-- =============================================================================

-- Every name below is qualified: the SQL-standard bodies of D.3 are bound with this search_path only.
SET LOCAL search_path = pg_catalog, pg_temp;

-- D.1 Keys of the signed context: kid = 16 first hex characters of SHA-256(key); ikey and okey = the key
-- padded with zeros to 64 bytes, XOR 0x36 and XOR 0x5c (the inner and outer blocks of HMAC-SHA256).
CREATE TABLE obligarth_private.context_keys (
  kid        text        PRIMARY KEY CHECK (kid ~ '^[0-9a-f]{16}$'),
  ikey       bytea       NOT NULL CHECK (length(ikey) = 64),
  okey       bytea       NOT NULL CHECK (length(okey) = 64),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
REVOKE ALL ON obligarth_private.context_keys FROM PUBLIC;

-- D.2 The context of the session, verified: format, signature of an active key, expiry. NULL otherwise
-- (no row of any tenant is then visible). obligarth.ctx = 'v1|<kind>|<tenant>|<actor>|<grant>|<expiry>',
-- obligarth.ctx_sig = '<kid>.<HMAC-SHA256 of obligarth.ctx, hexadecimal>'.
-- The grammar is that of migrations A and C, checked in two steps: a regular expression without bounded
-- repetitions, then the lengths of the fields and the form of the grant (the single expression of A and C,
-- with its bounded repetitions, costs 40 to 60 µs a call, two to four times as much: measured). The
-- signature needs no expression: the key lookup and the comparison of the HMAC accept only 16 and 64
-- lowercase hexadecimal characters on either side of the dot.
CREATE OR REPLACE FUNCTION obligarth.ctx_raw() RETURNS text
  LANGUAGE plpgsql STABLE SECURITY DEFINER PARALLEL SAFE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_ctx  text := current_setting('obligarth.ctx', true);
  v_sig  text := current_setting('obligarth.ctx_sig', true);
  v_ikey bytea;
  v_okey bytea;
BEGIN
  IF v_ctx IS NULL OR v_sig IS NULL OR length(v_sig) <> 81 OR substr(v_sig, 17, 1) <> '.'
     OR v_ctx !~ '^v1\|(tenant|member|platform|identity|none)\|[0-9]*\|[a-z]:[A-Za-z0-9._:-]+\|[0-9a-f-]*\|[0-9]+$'
     OR length(split_part(v_ctx, '|', 3)) > 10 OR length(split_part(v_ctx, '|', 4)) > 66
     OR length(split_part(v_ctx, '|', 6)) > 12
     OR (split_part(v_ctx, '|', 5) <> ''
         AND split_part(v_ctx, '|', 5) !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') THEN
    RETURN NULL;
  END IF;
  IF split_part(v_ctx, '|', 6)::bigint < extract(epoch FROM statement_timestamp())::bigint THEN
    RETURN NULL;                                         -- expired (30 minutes after it was signed)
  END IF;
  SELECT k.ikey, k.okey INTO v_ikey, v_okey
    FROM obligarth_private.context_keys k
   WHERE k.kid = substr(v_sig, 1, 16) AND k.retired_at IS NULL;
  IF NOT FOUND
     OR encode(sha256(v_okey || sha256(v_ikey || convert_to(v_ctx, 'UTF8'))), 'hex') <> substr(v_sig, 18) THEN
    RETURN NULL;                                         -- unknown or retired key, or a wrong signature
  END IF;
  RETURN v_ctx;
END $$;
REVOKE ALL ON FUNCTION obligarth.ctx_raw() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.ctx_raw() TO obligarth, obligarth_reader;
INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note)
VALUES ('function', 'obligarth.ctx_raw', 'definer', 'signed context: format, HMAC-SHA256 of an active key, expiry')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

-- D.3 Fields of the verified context. SQL-standard bodies: bound here (operators and functions of
-- pg_catalog), inlined by the planner in the InitPlans of the policies, one ctx_raw() call each. Same
-- results as migrations A and C (malformed, absent or refused context: NULL). The parsing lives in the
-- ctx_*_of(text) functions, which take a context ctx_raw() has verified: pure (IMMUTABLE), they reveal
-- nothing and check nothing; the definer helpers of D.3b call them on a single ctx_raw() result. Each
-- reads its argument once (a function inlined with ctx_raw() as argument may not read it twice), except
-- ctx_grant_of (below).
CREATE FUNCTION obligarth.ctx_kind_of(p_ctx text) RETURNS text
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN NULLIF(split_part(p_ctx, '|', 2), '');

-- The tenant of a context of kind 'tenant': in a verified context, '|tenant|' can only be the kind (no other
-- field may be 'tenant'), so the text after it, up to the next '|', is the tenant field. Same result as
-- substring(p_ctx, '^v1\|tenant\|([0-9]{1,10})\|'), at 1 µs instead of 15 (measured): this function sits
-- in the InitPlan of every policy of a tenant table.
CREATE FUNCTION obligarth.ctx_tenant_of(p_ctx text) RETURNS integer
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN CAST(NULLIF(split_part(split_part(p_ctx, '|tenant|', 2), '|', 1), '') AS integer);

CREATE FUNCTION obligarth.ctx_actor_of(p_ctx text) RETURNS text
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN NULLIF(split_part(p_ctx, '|', 4), '');

CREATE FUNCTION obligarth.ctx_actor_user_of(p_ctx text) RETURNS integer
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN CAST(substring(p_ctx, '^v1\|[a-z]+\|[0-9]*\|u:([0-9]{1,9})\|') AS integer);

-- The grant: read by the definer helpers of D.3b from a variable, where this form costs 1 µs (a regular
-- expression that reaches the fifth field costs 25 to 120 µs, measured); obligarth.ctx_grant(), which
-- passes ctx_raw() itself, is therefore not inlined (no policy calls it).
CREATE FUNCTION obligarth.ctx_grant_of(p_ctx text) RETURNS uuid
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN CASE WHEN split_part(p_ctx, '|', 2) = 'platform' THEN CAST(NULLIF(split_part(p_ctx, '|', 5), '') AS uuid) END;

CREATE OR REPLACE FUNCTION obligarth.ctx_kind() RETURNS text
  LANGUAGE sql STABLE PARALLEL SAFE
  RETURN obligarth.ctx_kind_of(obligarth.ctx_raw());

CREATE OR REPLACE FUNCTION obligarth.ctx_tenant() RETURNS integer
  LANGUAGE sql STABLE PARALLEL SAFE
  RETURN obligarth.ctx_tenant_of(obligarth.ctx_raw());

CREATE OR REPLACE FUNCTION obligarth.ctx_actor() RETURNS text
  LANGUAGE sql STABLE PARALLEL SAFE
  RETURN obligarth.ctx_actor_of(obligarth.ctx_raw());

CREATE OR REPLACE FUNCTION obligarth.ctx_actor_user() RETURNS integer
  LANGUAGE sql STABLE PARALLEL SAFE
  RETURN obligarth.ctx_actor_user_of(obligarth.ctx_raw());

CREATE OR REPLACE FUNCTION obligarth.ctx_grant() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  RETURN obligarth.ctx_grant_of(obligarth.ctx_raw());

REVOKE ALL ON FUNCTION obligarth.ctx_kind_of(text), obligarth.ctx_tenant_of(text), obligarth.ctx_actor_of(text),
  obligarth.ctx_actor_user_of(text), obligarth.ctx_grant_of(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.ctx_kind_of(text), obligarth.ctx_tenant_of(text), obligarth.ctx_actor_of(text),
  obligarth.ctx_actor_user_of(text), obligarth.ctx_grant_of(text) TO obligarth, obligarth_reader;

-- D.3b The definer helpers verify the context once per call: each ctx_raw() call computes an HMAC, and
-- the helpers of migration C called it once per field they read, and once per row scanned when the call
-- sat in a WHERE clause (users, user_tenants; on the testbed: 5 calls for the read set of the context
-- 'platform', 15 for that of a member, 16 for the tenants visible to a member). They now read it once,
-- into a variable. Same results as migration C. The check of a platform grant, needed by two of them, is
-- obligarth_private.platform_grant_ok (called by the definers only: no USAGE on the schema for the
-- runtime roles).
CREATE OR REPLACE FUNCTION obligarth.ctx_actor_is_platform_admin() RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_user integer := obligarth.ctx_actor_user();
BEGIN
  RETURN EXISTS (SELECT 1 FROM obligarth.users u WHERE u.id = v_user AND u.role = 'admin' AND u.is_active);
END $$;

CREATE OR REPLACE FUNCTION obligarth.actor_member_tenant_ids() RETURNS integer[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_user integer := obligarth.ctx_actor_user();
BEGIN
  RETURN (SELECT COALESCE(array_agg(ut.tenant_id ORDER BY ut.tenant_id), '{}'::integer[])
            FROM obligarth.user_tenants ut WHERE ut.user_id = v_user);
END $$;

CREATE FUNCTION obligarth_private.platform_grant_ok(p_grant uuid, p_actor text) RETURNS boolean
  LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM obligarth.platform_access_grants g
    WHERE g.id = p_grant
      AND g.expires_at > statement_timestamp()
      AND g.actor = p_actor
      AND (g.actor_type <> 'user' OR EXISTS (
            SELECT 1 FROM obligarth.users u
            WHERE u.id = g.user_id AND u.role = 'admin' AND u.is_active)));
END $$;
REVOKE ALL ON FUNCTION obligarth_private.platform_grant_ok(uuid, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION obligarth.ctx_platform_grant_valid() RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_ctx text := obligarth.ctx_raw();
BEGIN
  RETURN obligarth_private.platform_grant_ok(obligarth.ctx_grant_of(v_ctx), obligarth.ctx_actor_of(v_ctx));
END $$;

CREATE OR REPLACE FUNCTION obligarth.ctx_read_tenants() RETURNS integer[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_ctx text := obligarth.ctx_raw();
BEGIN
  RETURN CASE obligarth.ctx_kind_of(v_ctx)
    WHEN 'tenant'   THEN COALESCE(ARRAY[obligarth.ctx_tenant_of(v_ctx)], '{}'::integer[])
    WHEN 'member'   THEN (SELECT COALESCE(array_agg(ut.tenant_id ORDER BY ut.tenant_id), '{}'::integer[])
                            FROM obligarth.user_tenants ut WHERE ut.user_id = obligarth.ctx_actor_user_of(v_ctx))
    WHEN 'platform' THEN CASE WHEN obligarth_private.platform_grant_ok(obligarth.ctx_grant_of(v_ctx), obligarth.ctx_actor_of(v_ctx))
                              THEN ARRAY(SELECT t.id FROM obligarth.tenants t)
                              ELSE '{}'::integer[] END
    ELSE '{}'::integer[] END;
END $$;

CREATE OR REPLACE FUNCTION obligarth.actor_visible_tenant_ids() RETURNS integer[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_user integer := obligarth.ctx_actor_user_of(obligarth.ctx_raw());
BEGIN
  IF EXISTS (SELECT 1 FROM obligarth.users u WHERE u.id = v_user AND u.role = 'admin' AND u.is_active) THEN
    RETURN ARRAY(SELECT t.id FROM obligarth.tenants t ORDER BY t.id);
  END IF;
  RETURN (SELECT COALESCE(array_agg(ut.tenant_id ORDER BY ut.tenant_id), '{}'::integer[])
            FROM obligarth.user_tenants ut WHERE ut.user_id = v_user);
END $$;

-- Labels of accounts: the actor and the read set as InitPlans (once per call), no longer evaluated for each
-- account and each membership read. Same results as migration A.
CREATE OR REPLACE FUNCTION obligarth.user_labels(p_ids integer[]) RETURNS TABLE (id integer, username text, display_name text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT u.id, u.username::text, u.display_name::text
  FROM obligarth.users u
  WHERE u.id = ANY (p_ids)
    AND (u.role = 'admin'
         OR u.id = (SELECT obligarth.ctx_actor_user())
         OR EXISTS (SELECT 1 FROM obligarth.user_tenants ut
                    WHERE ut.user_id = u.id
                      AND ut.tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[]))))
$$;

-- D.4 Invoker functions with a body in plain text: parsed at run time with the search_path of the session
-- unless they fix it (an operator shadowed in pgboss would otherwise disable a guard or a check).
ALTER FUNCTION obligarth.check_scope_reference() SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION obligarth.check_channel_reference() SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION obligarth.users_guard_privileged_columns() SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION obligarth.users_bump_credential_version() SET search_path = pg_catalog, pg_temp;
DO $$
BEGIN
  -- the journal's pure helpers (audit-durci annex A.1), when the hardened journal is there
  IF to_regprocedure('obligarth.audit_link_hash(bytea, bigint, text)') IS NOT NULL THEN
    ALTER FUNCTION obligarth.audit_link_hash(bytea, bigint, text) SET search_path = pg_catalog, pg_temp;
  END IF;
  IF to_regprocedure('obligarth.audit_seal_message(uuid, bigint, timestamptz, integer, bytea, bytea, text)') IS NOT NULL THEN
    ALTER FUNCTION obligarth.audit_seal_message(uuid, bigint, timestamptz, integer, bytea, bytea, text)
      SET search_path = pg_catalog, pg_temp;
  END IF;
END $$;

-- D.5 Review of the SECURITY DEFINER functions. The checks on the actor of the context only hold with a
-- signed context (D.2): before it, an injected set_config could name any actor.
-- Purge of the grants journal: the purge job only, for the runtime role (it ran in any context).
CREATE OR REPLACE FUNCTION obligarth.platform_access_grants_purge(p_keep interval) RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_count integer;
BEGIN
  IF session_user = 'obligarth' AND COALESCE(obligarth.ctx_actor(), '') !~ '^j:' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'platform_access_grants_purge: reserved to a job';
  END IF;
  IF p_keep < interval '30 days' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'platform_access_grants_purge: keep at least 30 days';
  END IF;
  DELETE FROM obligarth.platform_access_grants WHERE expires_at < now() - p_keep;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END $$;

-- Chains of every tenant (identifiers and lengths): jobs, integrations and platform administrators only,
-- for the runtime role (review AUD-A6-R11: it answered in any context).
DO $$
BEGIN
  IF to_regprocedure('obligarth.audit_chains()') IS NOT NULL THEN
    EXECUTE $f$
CREATE OR REPLACE FUNCTION obligarth.audit_chains()
  RETURNS TABLE (tenant_id integer, last_seq bigint, anchor_seq bigint, tenant_exists boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $b$
BEGIN
  IF session_user = 'obligarth' AND COALESCE(obligarth.ctx_actor(), '') !~ '^[ji]:'
     AND NOT obligarth.ctx_actor_is_platform_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'audit_chains: reserved to the jobs, the integrations and the platform administrators';
  END IF;
  RETURN QUERY
    SELECT h.tenant_id, h.last_seq, COALESCE(a.anchor_seq, 0::bigint),
           EXISTS (SELECT 1 FROM obligarth.tenants t WHERE t.id = h.tenant_id)
      FROM obligarth.audit_chain_heads h
      LEFT JOIN obligarth.audit_chain_anchors a ON a.tenant_id = h.tenant_id
     ORDER BY h.tenant_id;
END $b$;
$f$;
  END IF;
END $$;

-- D.6 Checks of the catalog: rules 1 to 14 of migration C, and the controls of this hardening
-- (rules 11b, 12b to 12d, 14b, 15).
CREATE OR REPLACE FUNCTION obligarth.rls_audit() RETURNS TABLE (object_name text, problem text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH reg AS (
  SELECT r.object_name, r.rls_class FROM obligarth_private.rls_registry r WHERE r.object_kind = 'table'
), rel AS (
  SELECT c.oid, n.nspname || '.' || c.relname AS name, n.nspname, c.relkind,
         c.relrowsecurity, c.relforcerowsecurity, c.relowner, c.relacl, c.reloptions
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname IN ('obligarth', 'obligarth_private')
), fn AS (
  SELECT p.oid, n.nspname || '.' || p.proname AS name, p.prosecdef, p.proconfig, p.prokind, p.proowner, p.proacl,
         l.lanname, p.prosqlbody IS NOT NULL AS standard_body
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang
  WHERE n.nspname IN ('obligarth', 'obligarth_private')
), privileged AS (
  SELECT r.oid, r.rolname FROM pg_roles r
  WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb
     OR r.rolname IN ('obligarth_owner', 'pg_execute_server_program', 'pg_read_server_files', 'pg_write_server_files',
                      'pg_read_all_data', 'pg_write_all_data')
)
-- 1 to 10: classification, row level security, owners, tenant columns, foreign keys, views
SELECT rel.name, 'table not classified (obligarth_private.rls_apply)'
FROM rel WHERE rel.nspname = 'obligarth' AND rel.relkind IN ('r', 'p')
  AND NOT EXISTS (SELECT 1 FROM reg WHERE reg.object_name = rel.name)
UNION ALL
SELECT reg.object_name, 'registered table does not exist'
FROM reg WHERE to_regclass(reg.object_name) IS NULL
UNION ALL
SELECT rel.name, 'row level security not enabled and forced'
FROM rel JOIN reg ON reg.object_name = rel.name
WHERE reg.rls_class <> 'technical' AND NOT (rel.relrowsecurity AND rel.relforcerowsecurity)
UNION ALL
SELECT rel.name, 'no rls_owner policy'
FROM rel JOIN reg ON reg.object_name = rel.name
WHERE reg.rls_class <> 'technical'
  AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = rel.oid AND p.polname = 'rls_owner')
UNION ALL
SELECT rel.name, 'no policy for the runtime role'
FROM rel JOIN reg ON reg.object_name = rel.name
WHERE reg.rls_class <> 'technical'
  AND NOT EXISTS (SELECT 1 FROM pg_policy p
                  WHERE p.polrelid = rel.oid AND 'obligarth'::regrole::oid = ANY (p.polroles))
UNION ALL
SELECT rel.name, 'owner is ' || pg_get_userbyid(rel.relowner)
FROM rel WHERE rel.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
  AND pg_get_userbyid(rel.relowner) <> 'obligarth_owner'
UNION ALL
SELECT reg.object_name, 'tenant_id missing or nullable'
FROM reg WHERE reg.rls_class IN ('tenant', 'tenant_shared')
  AND NOT EXISTS (SELECT 1 FROM pg_attribute a
                  WHERE a.attrelid = to_regclass(reg.object_name) AND a.attname = 'tenant_id'
                    AND a.attnotnull AND NOT a.attisdropped)
UNION ALL
SELECT con.conrelid::regclass::text,
       'foreign key ' || con.conname || ' to ' || con.confrelid::regclass::text || ' without tenant_id on both sides'
FROM pg_constraint con
JOIN reg r1 ON r1.object_name = con.conrelid::regclass::text AND r1.rls_class IN ('tenant', 'tenant_shared')
JOIN reg r2 ON r2.object_name = con.confrelid::regclass::text AND r2.rls_class IN ('tenant', 'tenant_shared')
WHERE con.contype = 'f'
  AND NOT ((SELECT a.attnum FROM pg_attribute a WHERE a.attrelid = con.conrelid AND a.attname = 'tenant_id') = ANY (con.conkey)
       AND (SELECT a.attnum FROM pg_attribute a WHERE a.attrelid = con.confrelid AND a.attname = 'tenant_id') = ANY (con.confkey))
UNION ALL
SELECT rel.name, 'view without security_invoker = true'
FROM rel WHERE rel.relkind = 'v'
  AND NOT COALESCE((SELECT o.option_value::boolean FROM pg_options_to_table(rel.reloptions) o
                    WHERE o.option_name = 'security_invoker'), false)
UNION ALL
SELECT rel.name, 'materialized view (no row level security)'
FROM rel WHERE rel.relkind = 'm'
-- 11: SECURITY DEFINER functions registered and with a search_path
UNION ALL
SELECT fn.name, 'security definer function not registered or without search_path'
FROM fn
WHERE fn.prosecdef
  AND (NOT EXISTS (SELECT 1 FROM obligarth_private.rls_registry r
                   WHERE r.object_kind = 'function' AND r.object_name = fn.name)
       OR NOT EXISTS (SELECT 1 FROM unnest(fn.proconfig) cfg WHERE cfg LIKE 'search\_path=%'))
-- 11b: every function: search_path fixed to pg_catalog, pg_temp, or a SQL-standard body (bound at creation)
UNION ALL
SELECT fn.name, 'function parsed with the session''s search_path (SET search_path = pg_catalog, pg_temp, or a SQL-standard body)'
FROM fn
WHERE fn.prokind IN ('f', 'p')
  AND NOT ('search_path=pg_catalog, pg_temp' = ANY (COALESCE(fn.proconfig, '{}'::text[])))
  AND NOT (fn.lanname = 'sql' AND fn.standard_body)
-- 12: relations: nothing to PUBLIC; never TRUNCATE, REFERENCES nor TRIGGER to the runtime roles
UNION ALL
SELECT rel.name, 'privilege ' || acl.privilege_type || ' granted to '
       || CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END
FROM rel CROSS JOIN LATERAL aclexplode(COALESCE(rel.relacl, acldefault(CAST(CASE WHEN rel.relkind = 'S' THEN 's' ELSE 'r' END AS "char"), rel.relowner))) acl
WHERE rel.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
  AND (acl.grantee = 0
       OR (acl.grantee IN ('obligarth'::regrole::oid, 'obligarth_reader'::regrole::oid)
           AND acl.privilege_type IN ('TRUNCATE', 'REFERENCES', 'TRIGGER')))
-- 12b: column privileges: nothing to PUBLIC; never REFERENCES to the runtime roles (a foreign key created
-- in pgboss would probe the rows of every tenant: the check of a foreign key ignores the RLS)
UNION ALL
SELECT rel.name || '.' || a.attname, 'column privilege ' || acl.privilege_type || ' granted to '
       || CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END
FROM rel
JOIN pg_attribute a ON a.attrelid = rel.oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
CROSS JOIN LATERAL aclexplode(a.attacl) acl
WHERE acl.grantee = 0
   OR (acl.grantee IN ('obligarth'::regrole::oid, 'obligarth_reader'::regrole::oid) AND acl.privilege_type = 'REFERENCES')
-- 12c: no function of the two schemas executable by PUBLIC
UNION ALL
SELECT fn.name, 'function executable by PUBLIC'
FROM fn CROSS JOIN LATERAL aclexplode(COALESCE(fn.proacl, acldefault('f', fn.proowner))) acl
WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
-- 12d: obligarth_private (registry, keys of the signed context): out of reach of the runtime roles
UNION ALL
SELECT rel.name, 'private object: privilege ' || acl.privilege_type || ' granted to '
       || CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END
FROM rel CROSS JOIN LATERAL aclexplode(COALESCE(rel.relacl, acldefault(CAST(CASE WHEN rel.relkind = 'S' THEN 's' ELSE 'r' END AS "char"), rel.relowner))) acl
WHERE rel.nspname = 'obligarth_private'
  AND acl.grantee IN (0, 'obligarth'::regrole::oid, 'obligarth_reader'::regrole::oid)
UNION ALL
SELECT 'obligarth_private', 'schema usable by ' || r.rolname
FROM pg_roles r
WHERE r.rolname IN ('obligarth', 'obligarth_reader') AND has_schema_privilege(r.oid, 'obligarth_private', 'USAGE')
-- 13: attributes of the brain's roles
UNION ALL
SELECT r.rolname, 'role attribute: ' || concat_ws(', ',
         CASE WHEN r.rolsuper THEN 'SUPERUSER' END, CASE WHEN r.rolbypassrls THEN 'BYPASSRLS' END,
         CASE WHEN r.rolcreaterole THEN 'CREATEROLE' END, CASE WHEN r.rolcreatedb THEN 'CREATEDB' END)
FROM pg_roles r
WHERE r.rolname IN ('obligarth', 'obligarth_reader', 'obligarth_owner')
  AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb)
-- 14: memberships of the runtime role
UNION ALL
SELECT 'obligarth', 'membership in obligarth_reader must be INHERIT FALSE, SET TRUE'
FROM pg_auth_members m
WHERE m.roleid = 'obligarth_reader'::regrole AND m.member = 'obligarth'::regrole
  AND (m.inherit_option OR NOT m.set_option)
UNION ALL
SELECT 'obligarth', 'runtime role is a member of ' || pg_get_userbyid(m.roleid)
FROM pg_auth_members m
WHERE m.member = 'obligarth'::regrole AND pg_get_userbyid(m.roleid) IN ('obligarth_owner')
UNION ALL
SELECT 'obligarth', 'runtime role can take on ' || p.rolname || ' (SET ROLE or inherited membership)'
FROM privileged p
WHERE p.rolname <> 'obligarth'
  AND (pg_has_role('obligarth', p.oid, 'SET') OR pg_has_role('obligarth', p.oid, 'USAGE'))
-- 14b: nor through the reader role, which the runtime role can always take on (review of lot A5)
UNION ALL
SELECT 'obligarth_reader', 'reader role can take on ' || p.rolname || ' (SET ROLE or inherited membership)'
FROM privileged p
WHERE p.rolname <> 'obligarth_reader'
  AND (pg_has_role('obligarth_reader', p.oid, 'SET') OR pg_has_role('obligarth_reader', p.oid, 'USAGE'))
-- 15: once the keys of the signed context exist, ctx_raw() is their SECURITY DEFINER verifier
UNION ALL
SELECT 'obligarth.ctx_raw', 'signed context keys present, but ctx_raw() does not verify the signature'
WHERE to_regclass('obligarth_private.context_keys') IS NOT NULL
  AND NOT COALESCE((SELECT p.prosecdef AND p.prosrc LIKE '%obligarth\_private.context\_keys%'
                      FROM pg_proc p WHERE p.oid = to_regprocedure('obligarth.ctx_raw()')), false)
$$;

-- D.7 Nothing may remain unclassified, unfixed or reachable
SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the migration');
}
