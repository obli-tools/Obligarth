import type { Knex } from 'knex';

// =============================================================================
// Observability: the backlog of the MDM commands, all tenants, as counts only (P0-13 T8, metrics of the S2 slice)
// =============================================================================
//   - obligarth.ops_command_backlog(): per platform (apple, android, legacy_agent) and open state, the number of
//     targets and the age in seconds of the oldest one in that state. Read by the metrics collector of the server
//     (GET /metrics on the internal listener, obligarth_mdm_command_targets_open and
//     obligarth_mdm_command_oldest_open_seconds) and by the platform's ops status: context 'none' of the actor
//     j:ops.metrics only. Never a tenant, a device, a command id nor a parameter: the metrics carry no tenant label.
//   - Reads the open targets only (the partial indexes mdm_command_targets_open and legacy_agent_commands_open);
//     the server caches the result 60 s.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last. Runs as
// obligarth_owner (server-migrate), after reports_requester.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Observability: backlog of the commands, counts only (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth.ctx_kind()') IS NULL
     OR to_regclass('obligarth.mdm_command_targets') IS NULL
     OR to_regclass('obligarth.legacy_agent_commands') IS NULL THEN
    RAISE EXCEPTION 'ops_command_backlog: apply the RLS migrations, mdm_commands and legacy_agent first';
  END IF;
END $$;

CREATE FUNCTION obligarth.ops_command_backlog()
  RETURNS TABLE (platform text, state text, targets bigint, oldest_seconds double precision)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'j:ops.metrics' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ops_command_backlog: reserved to the metrics of the platform';
  END IF;
  RETURN QUERY
    SELECT c.platform::text, t.state::text, count(*)::bigint,
           GREATEST(0, extract(epoch FROM now() - min(t.state_event_at)))::double precision
      FROM obligarth.mdm_command_targets t
      JOIN obligarth.mdm_commands c ON c.tenant_id = t.tenant_id AND c.id = t.command_id
     WHERE t.state IN ('pending', 'queued', 'sent', 'notnow')
     GROUP BY 1, 2
    UNION ALL
    SELECT 'legacy_agent'::text, l.state::text, count(*)::bigint,
           GREATEST(0, extract(epoch FROM now() - min(l.state_event_at)))::double precision
      FROM obligarth.legacy_agent_commands l
     WHERE l.state IN ('pending', 'sent')
     GROUP BY 2
     ORDER BY 1, 2;
END $$;
REVOKE ALL ON FUNCTION obligarth.ops_command_backlog() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.ops_command_backlog() TO obligarth;
COMMENT ON FUNCTION obligarth.ops_command_backlog() IS
  'observability: open command targets per platform and state, all tenants, counts only (actor j:ops.metrics)';

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.ops_command_backlog', 'definer', 'observability: open command targets per platform and state (counts only)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

const DOWN = String.raw`
SET LOCAL search_path = pg_catalog, pg_temp;
DELETE FROM obligarth_private.rls_registry WHERE object_kind = 'function' AND object_name = 'obligarth.ops_command_backlog';
DROP FUNCTION obligarth.ops_command_backlog();
SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw(DOWN);
}
