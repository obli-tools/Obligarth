import type { Knex } from 'knex';

// =============================================================================
// Bridge agent 1.2.0: packages sent back by the devices (app.pull)
// =============================================================================
//   - legacy_agent_packages.created_by becomes optional: a package pulled automatically (job legacy-agent.apk-harvest)
//     has no author; one pulled at a console request keeps the requester.
//   - legacy_agent_packages.source_device_id: the device the APK came from (NULL for an upload). No foreign key: the
//     package outlives the device.
//   - index (tenant_id, package_name, version_code): the harvest looks for the apps of the fleet without a package.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last, a down that raises.
// Runs as obligarth_owner (server-migrate), after p015_remote_settings.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Bridge agent: packages pulled from the devices (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.legacy_agent_packages') IS NULL THEN
    RAISE EXCEPTION 'legacy_agent_pulled_packages: apply the legacy_agent migration first';
  END IF;
END $$;

ALTER TABLE obligarth.legacy_agent_packages ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE obligarth.legacy_agent_packages ADD COLUMN source_device_id integer;
CREATE INDEX legacy_agent_packages_tenant_name_version_index
  ON obligarth.legacy_agent_packages (tenant_id, package_name, version_code);
COMMENT ON COLUMN obligarth.legacy_agent_packages.source_device_id IS
  'bridge agent 1.2.0: the device that sent the APK back (app.pull); NULL for an upload';

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
