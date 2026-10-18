import type { Knex } from 'knex';

// Android, part 5a (lot AN-E1, android-amapi §9.6): the apps of the catalog need no new table and no change of an
// existing one (apps admits the kinds play, private and web of the family android; the package goes in identifier,
// store_id stays null; the options of an assignment go in assignments.options). This part adds one function only:
//   - android_apps_due() (SECURITY DEFINER, context none of android.maintenance): the tenants with a linked
//     enterprise and Android apps whose metadata were never read or are a day old (android.app-metadata, once a day
//     at most per app).
// The CHECK apps_android_identifier of section 4.6 (migration 5) ALTERs apps: it is prepared for the junction
// AN-A2/AN-P (D:/Obligarth-android/.local/raccord/AN-E1-migration-5-apps.sql); until then the catalog checks the
// package in the code. Runs as obligarth_owner (server-migrate); ends with obligarth.rls_assert_clean(). No question
// mark in the SQL.

const UP = String.raw`-- =============================================================================
-- Android, part 5a: apps (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_enterprises') IS NULL OR to_regclass('obligarth.apps') IS NULL THEN
    RAISE EXCEPTION 'android_apps: apply android_enterprises and the model expansion first';
  END IF;
END $$;

CREATE FUNCTION obligarth.android_apps_due()
  RETURNS TABLE (tenant_id integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.maintenance' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_apps_due: context none of the maintenance required';
  END IF;
  RETURN QUERY
  SELECT DISTINCT a.tenant_id
    FROM obligarth.apps a
    JOIN obligarth.android_enterprises e ON e.tenant_id = a.tenant_id AND e.state = 'linked'
   WHERE a.platform_family = 'android' AND a.archived_at IS NULL
     AND (a.metadata_refreshed_at IS NULL OR a.metadata_refreshed_at < now() - interval '24 hours')
   ORDER BY 1;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_apps_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_apps_due() TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.android_apps_due', 'definer', 'android maintenance: tenants with Android apps whose metadata are due')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
