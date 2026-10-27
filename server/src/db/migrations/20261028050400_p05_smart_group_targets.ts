import type { Knex } from 'knex';

// =============================================================================
// Dynamic groups as targets of the assignments (P0-5 T6, M3 of the spec; §4.4, D1, D2, D3)
// =============================================================================
//   - assignments_target_scope_check admits 'smart_group' (varchar(16)), through the S3 brick widen_in_check: the order of
//     the lots that widen the same list (P0-11 user_group) no longer matters, a list already widened is left alone.
//   - obligarth_private.assignment_ref_kinds gains ('target', 'smart_group') → smart_groups: the generated
//     obligarth.check_assignment_reference() checks that the group is one of the tenant of the assignment, and the
//     generated obligarth.assignments_cleanup() removes the assignments of a dynamic group deleted (its AFTER DELETE
//     trigger smart_groups_assignments_cleanup is created by the rebuild). No liveness predicate: a group held or in
//     error keeps its assignments (its members are frozen, the resolution reads them as they are); whether a rule may be
//     targeted (D2) is the service's (publish.ts, normalizeChanges: 409 smartGroupNotTargetable).
//   - device_effective_settings_scope_check admits 'smart_group' (varchar(12): 11 characters): the provenance of a
//     setting won through a dynamic group (source_scope 'smart_group', source_scope_id its id).
//   Both widenings take an ACCESS EXCLUSIVE lock on their table for the rest of the migration and revalidate its rows
//   (widen_in_check, lock_timeout 5s); nothing at all when the list already holds the value.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last. Runs as obligarth_owner
// (server-migrate), after p05_smart_group_marking.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Dynamic groups as targets of the assignments (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.smart_groups') IS NULL
     OR to_regclass('obligarth_private.assignment_ref_kinds') IS NULL
     OR to_regprocedure('obligarth_private.widen_in_check(regclass, text, text[])') IS NULL THEN
    RAISE EXCEPTION 'p05_smart_group_targets: apply coordination_socle and p05_smart_groups first';
  END IF;
END $$;

-- 1. The target scope smart_group -----------------------------------------------------------------------------------
SELECT obligarth_private.widen_in_check('obligarth.assignments', 'assignments_target_scope_check', ARRAY['smart_group']);

-- 2. Its reference and its cleanup (regenerates check_assignment_reference and assignments_cleanup, creates the trigger
--    smart_groups_assignments_cleanup) ------------------------------------------------------------------------------
INSERT INTO obligarth_private.assignment_ref_kinds (side, kind, ref_table, live_predicate, shared_column, note) VALUES
  ('target', 'smart_group', 'smart_groups', NULL, NULL, 'P0-5 T6: dynamic groups (members in smart_group_members)');

-- 3. The provenance of an effective setting ---------------------------------------------------------------------------
SELECT obligarth_private.widen_in_check('obligarth.device_effective_settings', 'device_effective_settings_scope_check', ARRAY['smart_group']);

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
