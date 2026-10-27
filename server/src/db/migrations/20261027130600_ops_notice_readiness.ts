import type { Knex } from 'knex';

// =============================================================================
// Stage of the instance: the notices of the tenants as counts only (P0-13 T11, D7, D8)
// =============================================================================
//   - obligarth.ops_notice_readiness(): the number of tenants and of those whose notice is incomplete (no data
//     controller, or neither the contact of the DPO nor another contact: noticeCompleteness of shared/src/privacy.ts;
//     a tenant without settings is incomplete). Read by the ops status of the platform (GET /api/admin/ops/status,
//     prerequisites of a pilot): context 'none' of the actor j:ops.status only. Never a tenant, a name nor a value.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last. Runs as
// obligarth_owner (server-migrate), after ops_restore_verify.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Stage of the instance: notices of the tenants, counts only (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth.ctx_kind()') IS NULL
     OR to_regclass('obligarth.tenant_notice_settings') IS NULL THEN
    RAISE EXCEPTION 'ops_notice_readiness: apply the RLS migrations and notices first';
  END IF;
END $$;

CREATE FUNCTION obligarth.ops_notice_readiness()
  RETURNS TABLE (tenants bigint, incomplete bigint)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'j:ops.status' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ops_notice_readiness: reserved to the ops status of the platform';
  END IF;
  RETURN QUERY
    SELECT count(*)::bigint,
           count(*) FILTER (WHERE s.controller_name IS NULL OR btrim(s.controller_name) = ''
                               OR (COALESCE(btrim(s.dpo_contact), '') = '' AND COALESCE(btrim(s.contact), '') = ''))::bigint
      FROM obligarth.tenants t
      LEFT JOIN obligarth.tenant_notice_settings s ON s.tenant_id = t.id;
END $$;
REVOKE ALL ON FUNCTION obligarth.ops_notice_readiness() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.ops_notice_readiness() TO obligarth;
COMMENT ON FUNCTION obligarth.ops_notice_readiness() IS
  'stage of the instance: tenants and tenants whose employee notice is incomplete, counts only (actor j:ops.status)';

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.ops_notice_readiness', 'definer', 'stage of the instance: notices of the tenants (counts only, j:ops.status)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

const DOWN = String.raw`
SET LOCAL search_path = pg_catalog, pg_temp;
DELETE FROM obligarth_private.rls_registry WHERE object_kind = 'function' AND object_name = 'obligarth.ops_notice_readiness';
DROP FUNCTION obligarth.ops_notice_readiness();
SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw(DOWN);
}
