import type { Knex } from 'knex';

// =============================================================================
// Reports: the requester of an output (P0-12 T1, socle des rapports)
// =============================================================================
//   - report_outputs.requested_by: the user who asked for the output. The generation (job reports.generate) reads
//     the devices this user sees (permissionService.getVisibleDeviceIds; a platform administrator sees them all),
//     whoever downloads it later (every reader of the tenant's reports, `reports` or `supervision:read`, P0-12 §3).
//     NULL: an output filed before this migration, or whose requester was deleted since (ON DELETE SET NULL): one
//     still 'generating' is never generated (fail closed); one already ready stays downloadable.
// The planning columns of the spec (schedule_state, next_run_at…) come with the planning (P0-12, after P0-4 T4 and
// P0-10 T8): nothing here runs a schedule.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last. Runs as
// obligarth_owner (server-migrate), after app_icons.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Reports: requester of an output (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.report_outputs') IS NULL THEN
    RAISE EXCEPTION 'reports_requester: apply the base schema and the RLS migrations first';
  END IF;
END $$;

ALTER TABLE obligarth.report_outputs
  ADD COLUMN requested_by integer REFERENCES obligarth.users (id) ON DELETE SET NULL;
COMMENT ON COLUMN obligarth.report_outputs.requested_by IS
  'reports: the user whose visible devices the output holds (NULL: before P0-12 or account deleted; never generated)';
-- The deletion of an account sets its outputs' requester to NULL: an index, not a scan of the table.
CREATE INDEX report_outputs_requested_by ON obligarth.report_outputs (requested_by) WHERE requested_by IS NOT NULL;

SELECT obligarth.rls_assert_clean();
`;

const DOWN = String.raw`
SET LOCAL search_path = pg_catalog, pg_temp;
DROP INDEX obligarth.report_outputs_requested_by;
ALTER TABLE obligarth.report_outputs DROP COLUMN requested_by;
SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw(DOWN);
}
