import type { Knex } from 'knex';

// =============================================================================
// Assignments of a shared app, in every tenant (review F011, second round)
// =============================================================================
//   obligarth.assignments is of class 'tenant': in the context of the master tenant, the assignments a child tenant
//   made of an app of the master's shared library (resource_tenant_id = 1, assignments_resource_owner) are invisible.
//   The guards that refuse to archive an app or to change its platforms while it is assigned (appCatalogService
//   hasAssignments), and the VPP synchronisation that keeps the platforms of an assigned app, then missed them.
//   - obligarth.app_assigned_anywhere(p_resource_tenant, p_app): a boolean only (never a tenant, a target or a count),
//     for the resource tenant itself (tenant context of that tenant) or the platform context.
// A function only: no table, no row written, no lock taken on a table.
// Rules of the specs README §3: SQL by String.raw, no question mark, a definer function with SET search_path =
// pg_catalog, pg_temp, EXECUTE revoked from PUBLIC, registered (rls_registry), rls_assert_clean() last, a down that
// raises. Runs as obligarth_owner (server-migrate).
// =============================================================================

const UP = String.raw`-- =============================================================================
-- obligarth.app_assigned_anywhere (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.assignments') IS NULL THEN
    RAISE EXCEPTION 'app_assignments_any_tenant: apply the mdm_model_expand migration first';
  END IF;
END $$;

-- Whether an assignment of any tenant names this app of the resource tenant: a boolean only.
CREATE FUNCTION obligarth.app_assigned_anywhere(p_resource_tenant integer, p_app integer) RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT ((obligarth.ctx_kind() = 'tenant' AND obligarth.ctx_tenant() IS NOT DISTINCT FROM p_resource_tenant)
          OR obligarth.ctx_kind() = 'platform') THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'app_assigned_anywhere: the tenant of the app only';
  END IF;
  RETURN EXISTS (SELECT 1 FROM obligarth.assignments a
                  WHERE a.resource_type = 'app' AND a.resource_tenant_id = p_resource_tenant AND a.resource_id = p_app);
END $$;
REVOKE ALL ON FUNCTION obligarth.app_assigned_anywhere(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.app_assigned_anywhere(integer, integer) TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.app_assigned_anywhere', 'definer', 'apps: an assignment of any tenant names this app of the resource tenant (boolean)');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
