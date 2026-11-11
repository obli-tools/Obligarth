import type { Knex } from 'knex';

// =============================================================================
// Bridge agent, review round 3 (decisions of the owners F028 and F115)
// =============================================================================
//   - legacy_agent_packages.confirmed_at / confirmed_by (F028): a package sent back by a device (app.pull, the harvest)
//     is "to confirm" (NULL) until a holder of mdm.apps.manage confirms it; an app.install of it is refused until then.
//     EVERY package that exists when this runs is confirmed (grandfathered: confirmed_at = created_at, confirmed_by =
//     created_by, NULL for a harvested one), so that nothing installed in production today stops working.
//     confirmed_by has no foreign key, as created_by (the package outlives the account).
//   - tenant_guard_settings.legacy_agent_commands_sensitive (F115): the per-tenant guard setting that makes the
//     commands of the bridge agent ask a second factor; false by default (the current behaviour).
// Both are ADD COLUMN with a constant default or none (no table rewrite), then one UPDATE of the packages (a few
// thousand rows at most), safe on a live database at start.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last, a down that raises.
// Runs as obligarth_owner (server-migrate).
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Bridge agent: packages to confirm, guard setting of its commands (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.legacy_agent_packages') IS NULL OR to_regclass('obligarth.tenant_guard_settings') IS NULL THEN
    RAISE EXCEPTION 'legacy_agent_package_confirm: apply the legacy_agent and guard_foundation migrations first';
  END IF;
END $$;

ALTER TABLE obligarth.legacy_agent_packages
  ADD COLUMN confirmed_at timestamptz,
  ADD COLUMN confirmed_by integer;
UPDATE obligarth.legacy_agent_packages SET confirmed_at = created_at, confirmed_by = created_by WHERE confirmed_at IS NULL;
ALTER TABLE obligarth.legacy_agent_packages
  ADD CONSTRAINT legacy_agent_packages_confirmed_by CHECK (confirmed_by IS NULL OR confirmed_at IS NOT NULL);
COMMENT ON COLUMN obligarth.legacy_agent_packages.confirmed_at IS
  'review F028: NULL for a package sent back by a device until a human confirms it (no app.install before); the packages existing at the migration are confirmed';
COMMENT ON COLUMN obligarth.legacy_agent_packages.confirmed_by IS
  'review F028: the account that confirmed the package (its uploader for an upload); NULL for a grandfathered harvested package';

ALTER TABLE obligarth.tenant_guard_settings
  ADD COLUMN legacy_agent_commands_sensitive boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN obligarth.tenant_guard_settings.legacy_agent_commands_sensitive IS
  'review F115: the commands of the bridge agent (install, uninstall, agent update, restart, kiosk suspension) ask a second factor';

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
