import type { Knex } from 'knex';

// =============================================================================
// Bench stations: the references to a user no longer block the deletion of that user (review F047)
// =============================================================================
//   The bench_stations migration declared four foreign keys to obligarth.users without an ON DELETE action
//   (bench_stations.approved_by, suspended_by, revoked_by, bench_station_targets.created_by): once a platform
//   administrator approved, suspended or revoked a station, or added a target, that account could never be deleted
//   (23503, from the console and from the Obligate push alike), a revoked station being never deleted itself. Every
//   other reference to users in the schema is SET NULL or CASCADE.
//   - The four keys become ON DELETE SET NULL: the station and its target stay (history), the actor becomes unknown,
//     like bench_sessions.closed_by.
//   - bench_stations_lifecycle no longer requires approved_by (approved, suspended) nor revoked_by (revoked by an
//     administrator): approved_at and revoked_reason keep the lifecycle; the routes still write the actor.
//   - bench_station_targets.created_by may be NULL (the creator's account was deleted).
//   - bench_stations_no_unrevoke lets revoked_by of a revoked station go to NULL (the SET NULL of a deleted account),
//     and only that: the status, the date, the reason and any other actor stay frozen.
// Small platform tables (a few stations): the constraints are re-validated at once, under a brief lock.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last, a down that raises. Runs
// as obligarth_owner (server-migrate), after bench_stations.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Bench stations: ON DELETE SET NULL on the references to users (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.bench_stations') IS NULL OR to_regclass('obligarth.bench_station_targets') IS NULL THEN
    RAISE EXCEPTION 'bench_stations_user_fks: apply the bench_stations migration first';
  END IF;
END $$;

ALTER TABLE obligarth.bench_stations
  DROP CONSTRAINT IF EXISTS bench_stations_approved_by_foreign,
  DROP CONSTRAINT IF EXISTS bench_stations_suspended_by_foreign,
  DROP CONSTRAINT IF EXISTS bench_stations_revoked_by_foreign,
  DROP CONSTRAINT IF EXISTS bench_stations_lifecycle,
  ADD CONSTRAINT bench_stations_approved_by_foreign FOREIGN KEY (approved_by) REFERENCES obligarth.users (id) ON DELETE SET NULL,
  ADD CONSTRAINT bench_stations_suspended_by_foreign FOREIGN KEY (suspended_by) REFERENCES obligarth.users (id) ON DELETE SET NULL,
  ADD CONSTRAINT bench_stations_revoked_by_foreign FOREIGN KEY (revoked_by) REFERENCES obligarth.users (id) ON DELETE SET NULL,
  -- approved_by / revoked_by: NULL once the account of the administrator is deleted.
  ADD CONSTRAINT bench_stations_lifecycle CHECK (CASE status
    WHEN 'pending' THEN approved_at IS NULL AND approved_by IS NULL AND suspended_at IS NULL AND suspended_by IS NULL
                    AND revoked_at IS NULL AND revoked_by IS NULL AND revoked_reason IS NULL
    WHEN 'approved' THEN approved_at IS NOT NULL AND suspended_at IS NULL AND suspended_by IS NULL
                    AND revoked_at IS NULL AND revoked_by IS NULL AND revoked_reason IS NULL
    WHEN 'suspended' THEN approved_at IS NOT NULL AND suspended_at IS NOT NULL
                    AND revoked_at IS NULL AND revoked_by IS NULL AND revoked_reason IS NULL
    WHEN 'revoked' THEN revoked_at IS NOT NULL AND revoked_reason IS NOT NULL
    ELSE false END);

ALTER TABLE obligarth.bench_station_targets
  DROP CONSTRAINT IF EXISTS bench_station_targets_created_by_foreign,
  ALTER COLUMN created_by DROP NOT NULL,
  ADD CONSTRAINT bench_station_targets_created_by_foreign FOREIGN KEY (created_by) REFERENCES obligarth.users (id) ON DELETE SET NULL;

-- The SET NULL of a deleted account is an UPDATE of the station: a revoked station accepts it on revoked_by alone.
CREATE OR REPLACE FUNCTION obligarth_private.bench_stations_no_unrevoke() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.token_sha256 IS DISTINCT FROM OLD.token_sha256 THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_stations: the token of a station never changes';
  END IF;
  IF OLD.status = 'revoked' AND (NEW.status IS DISTINCT FROM OLD.status OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR (NEW.revoked_by IS DISTINCT FROM OLD.revoked_by AND NEW.revoked_by IS NOT NULL)
       OR NEW.revoked_reason IS DISTINCT FROM OLD.revoked_reason) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_stations: a revoked station stays revoked';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.bench_stations_no_unrevoke() FROM PUBLIC;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
