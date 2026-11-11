import type { Knex } from 'knex';

// =============================================================================
// Apple devices: a timestamp of the managed list of apps of its own (review F004)
// =============================================================================
//   The InstalledApplicationList and the ManagedApplicationList shared apple_devices.last_apps_at, as their order
//   (an older answer set aside as stale) and as the date of the last inventory of the apps. Both are ingested later,
//   possibly out of order, and the delivery of the apps asks for a managed list at every pass: the weekly installed
//   list (apple/commands/inventory.ts, due on last_apps_at) was never asked again, and an installed list received with
//   a managed one could be set aside without ever being read.
//   - apple_devices.last_managed_apps_at: the order and the date of the managed list (mdm/inventory/ingestors.ts);
//     last_apps_at stays the installed list's (the weekly refresh, the date shown with the inventory).
// A nullable column without a default: a change of the catalog only, no row rewritten, a brief lock (lock_timeout 5s).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last, a down that raises. Runs
// as obligarth_owner (server-migrate).
// =============================================================================

const UP = String.raw`-- =============================================================================
-- apple_devices.last_managed_apps_at (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;
-- The ALTER takes an ACCESS EXCLUSIVE lock on a busy table (check-ins, inventory): fail fast rather than queue every
-- reader and writer of apple_devices behind a long transaction (an old server container still running).
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
  IF to_regclass('obligarth.apple_devices') IS NULL THEN
    RAISE EXCEPTION 'apple_managed_apps_at: apply the mdm_model_expand migration first';
  END IF;
END $$;

ALTER TABLE obligarth.apple_devices ADD COLUMN IF NOT EXISTS last_managed_apps_at timestamptz;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
