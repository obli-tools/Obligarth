import type { Knex } from 'knex';

// =============================================================================
// Remote assistance: settings of the tenants, counts of the instance (P0-15 T3; §4.1, §4.6, D14; §0.1 rule 4)
// =============================================================================
//   - remote_settings (class tenant, one row per tenant, absent: the defaults of shared/src/mdm/remote.ts
//     DEFAULT_REMOTE_SETTINGS): mspSessionsNeedClientApproval (every session asked by the MSP approved by a client
//     approver; an option of the tenant, false by default), the maximum duration of a session (15 to 240 minutes, D14), the permanent long wait of the bridge
//     agents (D9, read from T4). Written by server/src/remote/settings.ts only, at the execution of an approved request
//     (restriction remote.settings_change, floor 'restricted').
//   - obligarth.remote_sessions_open_summary(): the open sessions of the instance by state, counts only: the quota of the
//     instance (40 open sessions, §4.1) read in a tenant's context, the gauge obligarth_remote_sessions_active (context
//     none of a job), the sessions orphaned by a restart. Never a tenant, a device nor an id.
//   - obligarth.remote_sessions_due_tenants(): the tenants that hold an open session past its deadline (the deadline of
//     its state, its maximum duration), for the minute sweep of the job legacy-agent.commands-expire (no new minute job,
//     C5): the sweep visits those tenants only. Context none of a job only; ids of tenants only.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, functions with SET
// search_path = pg_catalog, pg_temp and EXECUTE revoked from PUBLIC, rls_assert_clean() last, a down that raises.
// Runs as obligarth_owner (server-migrate), after p015_remote_retention.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Remote assistance: settings, counts of the instance (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.remote_sessions') IS NULL
     OR to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL THEN
    RAISE EXCEPTION 'p015_remote_settings: apply the RLS migrations and p015_remote_sessions first';
  END IF;
END $$;

-- 1. remote_settings ---------------------------------------------------------------------
CREATE TABLE obligarth.remote_settings (
  tenant_id                          integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  msp_sessions_need_client_approval  boolean      NOT NULL DEFAULT false,
  max_minutes                        smallint     NOT NULL DEFAULT 60,
  wait_channel                       boolean      NOT NULL DEFAULT false,
  updated_by                         integer,
  updated_at                         timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT remote_settings_pkey PRIMARY KEY (tenant_id),
  CONSTRAINT remote_settings_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT remote_settings_max_minutes_check CHECK (max_minutes BETWEEN 15 AND 240)
);
SELECT obligarth_private.rls_apply('obligarth.remote_settings', 'tenant',
  'remote assistance settings of a tenant (P0-15): written by server/src/remote/settings.ts at an approved request');

-- 2. Counts of the instance ----------------------------------------------------------------
CREATE FUNCTION obligarth.remote_sessions_open_summary()
  RETURNS TABLE (state text, sessions bigint)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF NOT (obligarth.ctx_kind() = 'tenant'
          OR (obligarth.ctx_kind() = 'none' AND obligarth.ctx_actor() ~ '^j:[a-z]')) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'remote_sessions_open_summary: a tenant or a job of the platform only';
  END IF;
  RETURN QUERY
    SELECT s.state::text, count(*)::bigint
      FROM obligarth.remote_sessions s
     WHERE s.ended_at IS NULL
     GROUP BY 1
     ORDER BY 1;
END $$;

CREATE FUNCTION obligarth.remote_sessions_due_tenants()
  RETURNS integer[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() !~ '^j:[a-z]' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'remote_sessions_due_tenants: a job of the platform only';
  END IF;
  RETURN (SELECT COALESCE(array_agg(DISTINCT s.tenant_id ORDER BY s.tenant_id), ARRAY[]::integer[])
            FROM obligarth.remote_sessions s
           WHERE s.ended_at IS NULL
             AND (s.expires_at <= now() OR (s.max_ends_at IS NOT NULL AND s.max_ends_at <= now())));
END $$;

REVOKE ALL ON FUNCTION obligarth.remote_sessions_open_summary(), obligarth.remote_sessions_due_tenants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.remote_sessions_open_summary(), obligarth.remote_sessions_due_tenants() TO obligarth;
COMMENT ON FUNCTION obligarth.remote_sessions_open_summary() IS
  'remote assistance (P0-15): open sessions of the instance by state, counts only (quota of the instance, gauge)';
COMMENT ON FUNCTION obligarth.remote_sessions_due_tenants() IS
  'remote assistance (P0-15): ids of the tenants holding an open session past a deadline (minute sweep, jobs only)';

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.remote_sessions_open_summary', 'definer',
   'remote assistance: open sessions of the instance by state (counts only; tenant context or platform job)'),
  ('function', 'obligarth.remote_sessions_due_tenants', 'definer',
   'remote assistance: tenants with an open session past a deadline (ids only; platform job)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
