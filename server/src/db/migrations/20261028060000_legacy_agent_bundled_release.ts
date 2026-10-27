import type { Knex } from 'knex';

// =============================================================================
// Version of the bridge agent embedded in the server image (lot AGENT-RU T1)
// =============================================================================
//   - legacy_agent_releases.origin: 'upload' (a platform administrator, second factor: created_by is set) or
//     'bundled' (registered at start from /app/server/agent-release by the start task legacy-agent.bundled-release:
//     no user, created_by NULL, bundled_in = the version of the server image that first brought it). One constraint
//     ties the three columns together (legacy_agent_releases_origin). The rows written before are uploads.
// The queue of the agent is left as it is (rule of the PONT-R review: no later migration touches it): the automatic
// update (legacy-agent.auto-update) reads it through its existing indexes (the open commands of a device, the
// commands of a tenant by date).
// The table stays a catalog (read by every context, written in the identity context). Rules of the specs README §3:
// SQL by String.raw, no question mark, rls_assert_clean() last, a down that raises. Runs as obligarth_owner
// (server-migrate), after the migrations of P0-5.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Version of the bridge agent embedded in the server image (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.legacy_agent_releases') IS NULL THEN
    RAISE EXCEPTION 'legacy_agent_bundled_release: apply the migration legacy_agent first';
  END IF;
END $$;

ALTER TABLE obligarth.legacy_agent_releases
  ADD COLUMN origin      varchar(16) NOT NULL DEFAULT 'upload',
  ADD COLUMN bundled_in  varchar(32),
  ALTER COLUMN created_by DROP NOT NULL;

ALTER TABLE obligarth.legacy_agent_releases
  ADD CONSTRAINT legacy_agent_releases_origin CHECK (
       (origin = 'upload' AND created_by IS NOT NULL AND bundled_in IS NULL)
    OR (origin = 'bundled' AND bundled_in IS NOT NULL AND bundled_in ~ '^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$'));

COMMENT ON COLUMN obligarth.legacy_agent_releases.origin IS
  'upload: added by a platform administrator (created_by); bundled: embedded in the server image, registered at start';
COMMENT ON COLUMN obligarth.legacy_agent_releases.bundled_in IS
  'version of the server image that first brought a bundled release (NULL for an upload)';

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
