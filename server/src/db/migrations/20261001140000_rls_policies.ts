import type { Knex } from 'knex';

// Row level security, part 3 of 3 (docs: rls-tenant §5, annex A.4): every table of the schema obligarth is
// classified (obligarth_private.rls_apply), the RLS enabled and forced, and the policies and privileges of the
// runtime role (obligarth) and of the reader role (obligarth_reader) put in place. From this migration on, a
// query sees only the rows of its database context, and the boot guard refuses DB_CONTEXT_MODE=audit.
//   - C.0 rewrites the context functions of migration A whose body had a FROM clause (ctx_raw, ctx_tenant,
//     ctx_actor_user, ctx_grant) as single expressions, same results: the planner inlines them in the
//     InitPlans of the policies, as rls-tenant §4.3 intends (a non-inlined call costs 0.1 to 0.2 ms each);
//     and the definer helpers of the read sets and of the platform grant in plpgsql (plans kept by the
//     connection), same results.
//   - C.8 (audit_logs) is the conditional block of audit-durci annex A.3 (review RLS-RC8): skipped once the
//     hardened journal (PLT-12) exists, which classifies the table itself.
//   - C.11 classifies the tables of the sibling specifications of lot A that ran first (durable jobs,
//     vault: rls-tenant §5.7), with DELETE on instance_secrets (an erased instance secret, coffre-secrets
//     notes of lot A4) and on apple_edge_dead_letters (purge job, file-durable notes of lot A3), and the
//     default tenant_id of tenant_secrets taken from the context (rule 5 of §5.4).
//   - C.12 extends rule 14 of obligarth.rls_audit() as the boot guard and server-migrate --check already
//     check it (review of lot A1): the runtime role must not be able to take on (SET ROLE, or an inherited
//     membership, direct or transitive) a role with SUPERUSER, BYPASSRLS, CREATEROLE or CREATEDB, the owner
//     role, nor a predefined role of the server's files and programs or of all the data.
// Runs as obligarth_owner (server-migrate) and ends with obligarth.rls_assert_clean(). The SQL holds no
// question mark (knex.raw would bind it) and is kept verbatim by String.raw (regular expressions and LIKE
// patterns contain backslashes).
const UP = String.raw`-- =============================================================================
-- Migration C: row level security on every table of schema obligarth
-- (run as obligarth_owner; ends with obligarth.rls_assert_clean())
-- =============================================================================

-- C.0 Context functions inlinable, as rls-tenant §4.3 describes them: a body that is one expression (no FROM
-- clause) is inlined by the planner, so the InitPlan of a policy evaluates current_setting() and the regular
-- expression instead of calling SQL functions (measured: 0.12 to 0.19 ms per InitPlan, several per statement).
-- Same results as migration A, in every case (malformed or absent context: NULL).
CREATE OR REPLACE FUNCTION obligarth.ctx_raw() RETURNS text
  LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT CASE WHEN current_setting('obligarth.ctx', true) ~ '^v1\|(tenant|member|platform|identity|none)\|[0-9]{0,10}\|[a-z]:[A-Za-z0-9._:-]{1,64}\|([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|)\|[0-9]{1,12}$'
              THEN current_setting('obligarth.ctx', true) END
$$;

CREATE OR REPLACE FUNCTION obligarth.ctx_tenant() RETURNS integer
  LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT CASE WHEN split_part(obligarth.ctx_raw(), '|', 2) = 'tenant'
              THEN NULLIF(split_part(obligarth.ctx_raw(), '|', 3), '')::integer END
$$;

CREATE OR REPLACE FUNCTION obligarth.ctx_actor_user() RETURNS integer
  LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT CASE WHEN obligarth.ctx_actor() ~ '^u:[0-9]{1,9}$' THEN substr(obligarth.ctx_actor(), 3)::integer END
$$;

CREATE OR REPLACE FUNCTION obligarth.ctx_grant() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT CASE WHEN split_part(obligarth.ctx_raw(), '|', 2) = 'platform'
              THEN NULLIF(split_part(obligarth.ctx_raw(), '|', 5), '')::uuid END
$$;

-- The definer helpers of the read sets and of the platform grant (never inlined, SECURITY DEFINER) in
-- plpgsql: their plans are kept by the connection instead of being made again at every statement (measured:
-- 0.9 to 0.6 ms for the InitPlan of the context 'platform', criterion 11). Same results as migration A.
CREATE OR REPLACE FUNCTION obligarth.ctx_actor_is_platform_admin() RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RETURN EXISTS (SELECT 1 FROM obligarth.users u
                 WHERE u.id = obligarth.ctx_actor_user() AND u.role = 'admin' AND u.is_active);
END $$;

CREATE OR REPLACE FUNCTION obligarth.actor_member_tenant_ids() RETURNS integer[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RETURN (SELECT COALESCE(array_agg(ut.tenant_id ORDER BY ut.tenant_id), '{}'::integer[])
            FROM obligarth.user_tenants ut WHERE ut.user_id = obligarth.ctx_actor_user());
END $$;

CREATE OR REPLACE FUNCTION obligarth.actor_visible_tenant_ids() RETURNS integer[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_actor_is_platform_admin() THEN
    RETURN ARRAY(SELECT t.id FROM obligarth.tenants t ORDER BY t.id);
  END IF;
  RETURN obligarth.actor_member_tenant_ids();
END $$;

CREATE OR REPLACE FUNCTION obligarth.ctx_platform_grant_valid() RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM obligarth.platform_access_grants g
    WHERE g.id = obligarth.ctx_grant()
      AND g.expires_at > statement_timestamp()
      AND g.actor = obligarth.ctx_actor()
      AND (g.actor_type <> 'user' OR EXISTS (
            SELECT 1 FROM obligarth.users u
            WHERE u.id = g.user_id AND u.role = 'admin' AND u.is_active)));
END $$;

CREATE OR REPLACE FUNCTION obligarth.ctx_read_tenants() RETURNS integer[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RETURN CASE obligarth.ctx_kind()
    WHEN 'tenant'   THEN COALESCE(ARRAY[obligarth.ctx_tenant()], '{}'::integer[])
    WHEN 'member'   THEN obligarth.actor_member_tenant_ids()
    WHEN 'platform' THEN CASE WHEN obligarth.ctx_platform_grant_valid()
                              THEN ARRAY(SELECT t.id FROM obligarth.tenants t)
                              ELSE '{}'::integer[] END
    ELSE '{}'::integer[] END;
END $$;

-- C.1 Tenant data
SELECT obligarth_private.rls_apply(t::regclass, 'tenant') FROM unnest(ARRAY[
  'obligarth.device_groups', 'obligarth.device_group_closure', 'obligarth.user_teams',
  'obligarth.team_memberships', 'obligarth.team_permissions', 'obligarth.settings',
  'obligarth.notification_bindings', 'obligarth.notification_log', 'obligarth.live_alerts',
  'obligarth.maintenance_windows', 'obligarth.maintenance_window_disables', 'obligarth.agent_api_keys',
  'obligarth.devices', 'obligarth.device_inventory_hardware', 'obligarth.device_inventory_software',
  'obligarth.reports', 'obligarth.report_outputs', 'obligarth.device_licenses',
  'obligarth.software_repo_packages', 'obligarth.pending_approvals',
  'obligarth.fleet_daily_snapshot', 'obligarth.fleet_hourly_snapshot']) AS t;

-- C.2 Platform-wide rows next to tenant rows
SELECT obligarth_private.rls_apply('obligarth.smtp_servers', 'tenant_or_global', 'tenant_id NULL: server of the platform');

-- C.3 Identity and platform settings
SELECT obligarth_private.rls_apply('obligarth.password_reset_tokens', 'identity');
SELECT obligarth_private.rls_apply(t::regclass, 'identity_self') FROM unnest(ARRAY[
  'obligarth.tfa_trusted_sessions', 'obligarth.step_up_throttle',
  'obligarth.user_device_keys', 'obligarth.device_key_challenges']) AS t;
SELECT obligarth_private.rls_apply('obligarth.app_config', 'catalog');
SELECT obligarth_private.rls_apply('obligarth.permission_sets', 'catalog');

-- C.4 Technical tables (no RLS, explicit privileges)
SELECT obligarth_private.rls_apply('obligarth.session', 'technical', 'express-session store, own pool (connect-pg-simple)');
GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.session TO obligarth;
SELECT obligarth_private.rls_apply('obligarth.obligarth_migrations', 'technical', 'Knex tracking table');
GRANT SELECT ON obligarth.obligarth_migrations TO obligarth;
SELECT obligarth_private.rls_apply('obligarth.obligarth_migrations_lock', 'technical', 'Knex lock table');

-- C.5 Tenants registry
SELECT obligarth_private.rls_apply('obligarth.tenants', 'custom', 'registry; INSERT and DELETE through tenant_create / tenant_delete');
CREATE POLICY rls_visible ON obligarth.tenants FOR SELECT TO obligarth
  USING (id = (SELECT obligarth.ctx_tenant())
         OR id = ANY (CAST((SELECT obligarth.actor_visible_tenant_ids()) AS integer[]))
         OR (SELECT obligarth.ctx_actor()) ~ '^[ji]:');          -- jobs and integrations: the registry
CREATE POLICY rls_update_own ON obligarth.tenants FOR UPDATE TO obligarth
  USING (id = (SELECT obligarth.ctx_tenant())) WITH CHECK (id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_reader ON obligarth.tenants FOR SELECT TO obligarth_reader
  USING (id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
GRANT SELECT ON obligarth.tenants TO obligarth, obligarth_reader;
GRANT UPDATE (name, two_step_approval, action_restrictions, repo_enabled, repo_quota_bytes,
              repo_access_key_hash, repo_access_key_prefix, updated_at) ON obligarth.tenants TO obligarth;

-- C.6 Memberships
SELECT obligarth_private.rls_apply('obligarth.user_tenants', 'custom', 'memberships; written in the identity context');
CREATE POLICY rls_identity ON obligarth.user_tenants TO obligarth
  USING ((SELECT obligarth.ctx_kind()) = 'identity') WITH CHECK ((SELECT obligarth.ctx_kind()) = 'identity');
CREATE POLICY rls_tenant_read ON obligarth.user_tenants FOR SELECT TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_self_read ON obligarth.user_tenants FOR SELECT TO obligarth
  USING (user_id = (SELECT obligarth.ctx_actor_user()));
CREATE POLICY rls_reader ON obligarth.user_tenants FOR SELECT TO obligarth_reader
  USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.user_tenants TO obligarth;
GRANT SELECT ON obligarth.user_tenants TO obligarth_reader;

-- C.7 Accounts
SELECT obligarth_private.rls_apply('obligarth.users', 'custom', 'accounts; privileged columns guarded by users_guard_privileged_columns');
CREATE POLICY rls_identity ON obligarth.users TO obligarth
  USING ((SELECT obligarth.ctx_kind()) = 'identity') WITH CHECK ((SELECT obligarth.ctx_kind()) = 'identity');
CREATE POLICY rls_self_read ON obligarth.users FOR SELECT TO obligarth
  USING (id = (SELECT obligarth.ctx_actor_user()));
CREATE POLICY rls_self_update ON obligarth.users FOR UPDATE TO obligarth
  USING (id = (SELECT obligarth.ctx_actor_user())) WITH CHECK (id = (SELECT obligarth.ctx_actor_user()));
CREATE POLICY rls_tenant_members_read ON obligarth.users FOR SELECT TO obligarth
  USING (EXISTS (SELECT 1 FROM obligarth.user_tenants ut
                 WHERE ut.user_id = users.id AND ut.tenant_id = (SELECT obligarth.ctx_tenant())));
CREATE POLICY rls_reader ON obligarth.users FOR SELECT TO obligarth_reader
  USING (EXISTS (SELECT 1 FROM obligarth.user_tenants ut
                 WHERE ut.user_id = users.id
                   AND ut.tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[]))));
GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.users TO obligarth;
GRANT SELECT ON obligarth.users TO obligarth_reader;

SELECT obligarth_private.rls_apply('obligarth.sso_foreign_users', 'custom', 'SSO links; identity context, read by the account itself');
CREATE POLICY rls_identity ON obligarth.sso_foreign_users TO obligarth
  USING ((SELECT obligarth.ctx_kind()) = 'identity') WITH CHECK ((SELECT obligarth.ctx_kind()) = 'identity');
CREATE POLICY rls_self_read ON obligarth.sso_foreign_users FOR SELECT TO obligarth
  USING (local_user_id = (SELECT obligarth.ctx_actor_user()));
GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.sso_foreign_users TO obligarth;

-- C.8 Audit journal: classified here only while the journal is not hardened (PLT-12 classifies it itself)
DO $$
BEGIN
  IF to_regprocedure('obligarth.audit_append(text)') IS NULL THEN
    PERFORM obligarth_private.rls_apply('obligarth.audit_logs', 'custom', 'journal; platform events filed under the master tenant');
    CREATE POLICY rls_tenant_read ON obligarth.audit_logs FOR SELECT TO obligarth
      USING (tenant_id = (SELECT obligarth.ctx_tenant()));
    CREATE POLICY rls_insert ON obligarth.audit_logs FOR INSERT TO obligarth
      WITH CHECK (tenant_id = (SELECT obligarth.ctx_tenant())
                  OR (tenant_id = 1 AND (SELECT obligarth.ctx_kind()) IN ('identity', 'none')));
    CREATE POLICY rls_tenant_delete ON obligarth.audit_logs FOR DELETE TO obligarth
      USING (tenant_id = (SELECT obligarth.ctx_tenant()));
    CREATE POLICY rls_reader ON obligarth.audit_logs FOR SELECT TO obligarth_reader
      USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
    GRANT SELECT, INSERT, DELETE ON obligarth.audit_logs TO obligarth;
    GRANT SELECT ON obligarth.audit_logs TO obligarth_reader;
    GRANT USAGE ON SEQUENCE obligarth.audit_logs_id_seq TO obligarth;
  END IF;
END $$;

-- C.9 Notification channels shared by the master tenant
SELECT obligarth_private.rls_apply('obligarth.notification_channel_tenants', 'custom', 'shares of master channels');
CREATE POLICY rls_owner_tenant ON obligarth.notification_channel_tenants TO obligarth
  USING (owner_tenant_id = (SELECT obligarth.ctx_tenant()))
  WITH CHECK (owner_tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_target_read ON obligarth.notification_channel_tenants FOR SELECT TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_reader ON obligarth.notification_channel_tenants FOR SELECT TO obligarth_reader
  USING (owner_tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[]))
         OR tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
GRANT SELECT, INSERT, DELETE ON obligarth.notification_channel_tenants TO obligarth;
GRANT SELECT ON obligarth.notification_channel_tenants TO obligarth_reader;

SELECT obligarth_private.rls_apply('obligarth.notification_channels', 'custom', 'tenant channels; master channels shared read-only');
CREATE POLICY rls_tenant ON obligarth.notification_channels TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant())) WITH CHECK (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_shared_read ON obligarth.notification_channels FOR SELECT TO obligarth
  USING (EXISTS (SELECT 1 FROM obligarth.notification_channel_tenants s
                 WHERE s.channel_id = notification_channels.id AND s.tenant_id = (SELECT obligarth.ctx_tenant())));
CREATE POLICY rls_reader ON obligarth.notification_channels FOR SELECT TO obligarth_reader
  USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[]))
         OR EXISTS (SELECT 1 FROM obligarth.notification_channel_tenants s
                    WHERE s.channel_id = notification_channels.id
                      AND s.tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[]))));
GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.notification_channels TO obligarth;
GRANT SELECT ON obligarth.notification_channels TO obligarth_reader;
GRANT USAGE ON SEQUENCE obligarth.notification_channels_id_seq TO obligarth;

-- C.10 Journal of the cross-tenant read grants
SELECT obligarth_private.rls_apply('obligarth.platform_access_grants', 'custom', 'insert-only journal (purge by function)');
CREATE POLICY rls_insert ON obligarth.platform_access_grants FOR INSERT TO obligarth
  WITH CHECK (actor = (SELECT obligarth.ctx_actor())
              AND ((actor_type = 'user' AND (SELECT obligarth.ctx_actor_is_platform_admin()))
                   OR (actor_type IN ('job', 'integration') AND (SELECT obligarth.ctx_kind()) = 'none')));
CREATE POLICY rls_admin_read ON obligarth.platform_access_grants FOR SELECT TO obligarth
  USING ((SELECT obligarth.ctx_actor_is_platform_admin()));
GRANT SELECT, INSERT ON obligarth.platform_access_grants TO obligarth;

-- C.11 Tables of the sibling specifications of lot A, when their migrations ran first
-- (a sibling migration that runs after this one classifies its tables itself, same statements)
DO $$
BEGIN
  -- vault (coffre-secrets.md, FND-03): read across tenants by design, no RLS
  IF to_regclass('obligarth.data_keys') IS NOT NULL THEN
    PERFORM obligarth_private.rls_apply('obligarth.data_keys', 'technical', 'vault DEKs (FND-03): no RLS by design');
    GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.data_keys TO obligarth;
  END IF;
  IF to_regclass('obligarth.instance_secrets') IS NOT NULL THEN
    PERFORM obligarth_private.rls_apply('obligarth.instance_secrets', 'technical', 'vault (FND-03): sealed secrets of the instance');
    -- DELETE: an instance secret erased (Obligate settings), recover-lost-kek (notes of lot A4)
    GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.instance_secrets TO obligarth;
  END IF;
  IF to_regclass('obligarth.vault_operations') IS NOT NULL THEN
    PERFORM obligarth_private.rls_apply('obligarth.vault_operations', 'technical', 'vault (FND-03): key operations, never a secret');
    GRANT SELECT, INSERT, UPDATE ON obligarth.vault_operations TO obligarth;
  END IF;
  IF to_regclass('obligarth.tenant_secrets') IS NOT NULL THEN
    PERFORM obligarth_private.rls_apply('obligarth.tenant_secrets', 'tenant', 'vault (FND-03): secrets referenced from documents');
    -- rule 5 of rls-tenant §5.4, as migration B did for the tables it knew: tenant_id from the context
    ALTER TABLE obligarth.tenant_secrets ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
  END IF;
  -- durable jobs (file-durable.md, FND-04)
  IF to_regclass('obligarth.job_status') IS NOT NULL THEN
    PERFORM obligarth_private.rls_apply('obligarth.job_status', 'technical', 'jobs (FND-04): last run per queue');
    GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.job_status TO obligarth;
  END IF;
  IF to_regclass('obligarth.job_once') IS NOT NULL THEN
    PERFORM obligarth_private.rls_apply('obligarth.job_once', 'technical', 'jobs (FND-04): side effects already done');
    GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.job_once TO obligarth;
  END IF;
  IF to_regclass('obligarth.apple_edge_inbox_attempts') IS NOT NULL THEN
    PERFORM obligarth_private.rls_apply('obligarth.apple_edge_inbox_attempts', 'technical', 'jobs (FND-04): outbox attempts, ids only');
    GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.apple_edge_inbox_attempts TO obligarth;
  END IF;
  IF to_regclass('obligarth.apple_edge_dead_letters') IS NOT NULL THEN
    PERFORM obligarth_private.rls_apply('obligarth.apple_edge_dead_letters', 'custom', 'jobs (FND-04): outbox dead letters');
    CREATE POLICY rls_job ON obligarth.apple_edge_dead_letters TO obligarth
      USING ((SELECT obligarth.ctx_kind()) = 'none' AND (SELECT obligarth.ctx_actor()) LIKE 'j:%')
      WITH CHECK ((SELECT obligarth.ctx_kind()) = 'none' AND (SELECT obligarth.ctx_actor()) LIKE 'j:%');
    CREATE POLICY rls_tenant_read ON obligarth.apple_edge_dead_letters FOR SELECT TO obligarth
      USING (tenant_id = (SELECT obligarth.ctx_tenant()));
    CREATE POLICY rls_reader ON obligarth.apple_edge_dead_letters FOR SELECT TO obligarth_reader
      USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[]))
             OR (tenant_id IS NULL AND (SELECT obligarth.ctx_kind()) = 'platform'
                 AND (SELECT obligarth.ctx_platform_grant_valid())));
    -- DELETE: purge of the dead letters by their job (notes of lot A3), under the policy rls_job
    GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.apple_edge_dead_letters TO obligarth;
    GRANT SELECT ON obligarth.apple_edge_dead_letters TO obligarth_reader;
  END IF;
END $$;

-- C.12 Rule 14 of the audit, extended (review of lot A1): the runtime role can take on no privileged role,
-- directly or through other roles, by SET ROLE or by an inherited membership (same list as the boot guard)
CREATE OR REPLACE FUNCTION obligarth.rls_audit() RETURNS TABLE (object_name text, problem text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH reg AS (
  SELECT r.object_name, r.rls_class FROM obligarth_private.rls_registry r WHERE r.object_kind = 'table'
), rel AS (
  SELECT c.oid, n.nspname || '.' || c.relname AS name, n.nspname, c.relkind,
         c.relrowsecurity, c.relforcerowsecurity, c.relowner, c.relacl, c.reloptions
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname IN ('obligarth', 'obligarth_private')
)
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
UNION ALL
SELECT n.nspname || '.' || p.proname, 'security definer function not registered or without search_path'
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('obligarth', 'obligarth_private') AND p.prosecdef
  AND (NOT EXISTS (SELECT 1 FROM obligarth_private.rls_registry r
                   WHERE r.object_kind = 'function' AND r.object_name = n.nspname || '.' || p.proname)
       OR NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) cfg WHERE cfg LIKE 'search\_path=%'))
UNION ALL
SELECT rel.name, 'privilege ' || acl.privilege_type || ' granted to '
       || CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END
FROM rel CROSS JOIN LATERAL aclexplode(COALESCE(rel.relacl, acldefault('r', rel.relowner))) acl
WHERE rel.relkind IN ('r', 'p', 'v')
  AND (acl.grantee = 0
       OR (acl.grantee IN ('obligarth'::regrole::oid, 'obligarth_reader'::regrole::oid)
           AND acl.privilege_type IN ('TRUNCATE', 'REFERENCES', 'TRIGGER')))
UNION ALL
SELECT r.rolname, 'role attribute: ' || concat_ws(', ',
         CASE WHEN r.rolsuper THEN 'SUPERUSER' END, CASE WHEN r.rolbypassrls THEN 'BYPASSRLS' END,
         CASE WHEN r.rolcreaterole THEN 'CREATEROLE' END, CASE WHEN r.rolcreatedb THEN 'CREATEDB' END)
FROM pg_roles r
WHERE r.rolname IN ('obligarth', 'obligarth_reader', 'obligarth_owner')
  AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb)
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
SELECT 'obligarth', 'runtime role can take on ' || r.rolname || ' (SET ROLE or inherited membership)'
FROM pg_roles r
WHERE r.rolname <> 'obligarth'
  AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb
       OR r.rolname IN ('obligarth_owner', 'pg_execute_server_program', 'pg_read_server_files', 'pg_write_server_files',
                        'pg_read_all_data', 'pg_write_all_data'))
  AND (pg_has_role('obligarth', r.oid, 'SET') OR pg_has_role('obligarth', r.oid, 'USAGE'))
$$;

-- C.13 Nothing may remain unclassified
SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the migration');
}
