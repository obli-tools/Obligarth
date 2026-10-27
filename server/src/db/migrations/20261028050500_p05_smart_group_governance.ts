import type { Knex } from 'knex';

// =============================================================================
// Governed changes of the dynamic groups (P0-5 T7; §4.4, D3, D4, D11)
// =============================================================================
//   - mdm_change_ledger_kind_check admits the four governed kinds of P0-5: smart_group_rule (the rule of a group an
//     assignment targets), smart_group_delete (its deletion), smart_group_release (the release of a held group) and
//     device_facts (the facts of a device that make it enter or leave such a group, D11). Written without a second
//     approver, they count in the cumulative thresholds of DM23 as the other changes of the configuration
//     (changeLedger.ts, recordDirectChange). varchar(32): 19 characters at most. Through the S3 brick widen_in_check:
//     the lots that add their kinds of change (P0-5 T8 filter_change, P0-4, P0-8, P0-11) no longer depend on each
//     other's order, a list already widened is left alone.
//   The widening takes an ACCESS EXCLUSIVE lock on the ledger for the rest of the migration and revalidates its rows
//   (widen_in_check, lock_timeout 5s); nothing at all when the list already holds the values.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last. Runs as obligarth_owner
// (server-migrate), after p05_smart_group_targets.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Governed changes of the dynamic groups (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.smart_groups') IS NULL
     OR to_regclass('obligarth.mdm_change_ledger') IS NULL
     OR to_regprocedure('obligarth_private.widen_in_check(regclass, text, text[])') IS NULL THEN
    RAISE EXCEPTION 'p05_smart_group_governance: apply coordination_socle and p05_smart_groups first';
  END IF;
END $$;

SELECT obligarth_private.widen_in_check('obligarth.mdm_change_ledger', 'mdm_change_ledger_kind_check',
  ARRAY['smart_group_rule', 'smart_group_delete', 'smart_group_release', 'device_facts']);

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
