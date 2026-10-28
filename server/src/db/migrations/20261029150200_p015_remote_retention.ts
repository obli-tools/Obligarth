import type { Knex } from 'knex';

// =============================================================================
// Retention of the remote assistance sessions (P0-15 T1, M3 of the spec; D7)
// =============================================================================
//   - obligarth_private.retention_catalog() gains the category remote_sessions_months (12 months by default, 6 to 36):
//     how long a tenant keeps the journal of its remote assistance sessions (purge: server/src/remote/retention.ts,
//     privacy.retention-tenant). Copy of RETENTION_CATEGORIES of shared/src/privacy.ts (testbed 172 compares them).
//     The catalogue is generated again from its own rows plus this one, in their order: a category another lot added
//     meanwhile is kept, and nothing changes when the category is there already. retention_values_valid() reads the
//     catalogue: the values of the tenants stay valid (a new key only widens what the CHECKs admit), the function is
//     left as it is.
// Precondition: the eight categories of retention_policies (P0-13 T4) are still in the catalogue, with their bounds.
// Rules of the specs README §3: SQL by String.raw, no question mark, functions with SET search_path = pg_catalog,
// pg_temp and EXECUTE revoked from PUBLIC (kept by CREATE OR REPLACE), rls_assert_clean() last, a down that raises.
// Runs as obligarth_owner (server-migrate), after p015_privacy_remote_assistance.
// =============================================================================

/** The categories of retention_policies (P0-13 T4), frozen there. */
const P013: ReadonlyArray<readonly [key: string, def: number, min: number, max: number, unit: 'days' | 'months']> = [
  ['unenrolled_corporate_days', 90, 30, 365, 'days'],
  ['unenrolled_corporate_personal_days', 90, 30, 365, 'days'],
  ['unenrolled_personal_days', 30, 30, 365, 'days'],
  ['departed_end_user_days', 90, 30, 365, 'days'],
  ['lost_mode_location_days', 30, 1, 62, 'days'],
  ['technical_log_months', 6, 3, 12, 'months'],
  ['status_history_days', 90, 30, 365, 'days'],
  ['notice_ack_months', 36, 12, 72, 'months'],
];
const p013Rows = P013.map(([k, d, lo, hi, u]) => `('${k}', ${d}, ${lo}, ${hi}, '${u}')`).join(',\n           ');

const UP = String.raw`-- =============================================================================
-- Retention of the remote assistance sessions (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
DECLARE
  v_missing integer;
  v_rows    text;
BEGIN
  IF to_regprocedure('obligarth_private.retention_catalog()') IS NULL
     OR to_regprocedure('obligarth_private.retention_values_valid(jsonb)') IS NULL THEN
    RAISE EXCEPTION 'p015_remote_retention: apply retention_policies first';
  END IF;
  SELECT count(*) INTO v_missing
    FROM (VALUES
           ${p013Rows}) AS e (category, default_value, min_value, max_value, unit)
   WHERE NOT EXISTS (SELECT 1 FROM obligarth_private.retention_catalog() c
                      WHERE c.category = e.category AND c.default_value = e.default_value AND c.min_value = e.min_value
                        AND c.max_value = e.max_value AND c.unit = e.unit);
  IF v_missing > 0 THEN
    RAISE EXCEPTION 'p015_remote_retention: retention_catalog() differs from retention_policies (% categories changed): merge the catalogues', v_missing;
  END IF;
  IF EXISTS (SELECT 1 FROM obligarth_private.retention_catalog() c WHERE c.category = 'remote_sessions_months') THEN
    RETURN;
  END IF;
  SELECT string_agg(format('(%L::text, %s, %s, %s, %L::text)', r.category, r.default_value, r.min_value, r.max_value, r.unit),
                    ', ' ORDER BY r.ord)
    INTO v_rows
    FROM (SELECT c.category, c.default_value, c.min_value, c.max_value, c.unit, row_number() OVER () AS ord
            FROM obligarth_private.retention_catalog() c
          UNION ALL
          SELECT 'remote_sessions_months', 12, 6, 36, 'months', 1000000) r;
  EXECUTE format($f$CREATE OR REPLACE FUNCTION obligarth_private.retention_catalog()
  RETURNS TABLE (category text, default_value integer, min_value integer, max_value integer, unit text)
  LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS %L$f$,
    'SELECT * FROM (VALUES ' || v_rows || ') AS c (category, default_value, min_value, max_value, unit)');
END $$;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
