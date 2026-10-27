import type { Knex } from 'knex';

// =============================================================================
// Report of the verification of a restore (P0-13 T10, FND-09; M4 of the spec, continued)
// =============================================================================
//   - obligarth.ops_restore_verify_record(p_ok, p_started_at, p_detail): the report 'restore_verify' of the command
//     ops verify-restore (ops/cli.ts), inserted in ops_backup_reports (P0-13 T9) for the runtime role, which may not
//     insert there itself (obligarth_backup alone may, and the verification runs in the server's image). Context
//     'none' of the actor j:ops.verify-restore only; the kind is fixed here, the detail obeys the CHECKs of the table
//     (JSON object of 4 KiB at most, never an address with credentials) and the trigger stamps recorded_at and brings
//     an end in the future back to now. Returns the id of the report.
//   The report of the restore drill ('drill') is inserted by the service drill-report of the compose profile
//   restore-drill, as obligarth_backup, into the database of the instance (never into the copy the drill restored).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last. Runs as obligarth_owner
// (server-migrate), after ops_backups.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Report of the verification of a restore (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.ops_backup_reports') IS NULL
     OR to_regprocedure('obligarth.ctx_kind()') IS NULL
     OR to_regprocedure('obligarth.ctx_actor()') IS NULL THEN
    RAISE EXCEPTION 'ops_restore_verify: apply the RLS migrations and ops_backups first';
  END IF;
END $$;

CREATE FUNCTION obligarth.ops_restore_verify_record(p_ok boolean, p_started_at timestamptz, p_detail jsonb)
  RETURNS bigint
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_id bigint;
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'j:ops.verify-restore' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ops_restore_verify_record: reserved to ops verify-restore';
  END IF;
  IF p_ok IS NULL OR p_detail IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '22004', MESSAGE = 'ops_restore_verify_record: outcome and detail are required';
  END IF;
  INSERT INTO obligarth.ops_backup_reports (kind, started_at, finished_at, ok, detail)
  VALUES ('restore_verify', LEAST(COALESCE(p_started_at, now()), now()), now(), p_ok, p_detail)
  RETURNING id INTO v_id;
  RETURN v_id;
END $$;
REVOKE ALL ON FUNCTION obligarth.ops_restore_verify_record(boolean, timestamptz, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.ops_restore_verify_record(boolean, timestamptz, jsonb) TO obligarth;
COMMENT ON FUNCTION obligarth.ops_restore_verify_record(boolean, timestamptz, jsonb) IS
  'FND-09: report restore_verify of ops verify-restore (actor j:ops.verify-restore, context none)';

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.ops_restore_verify_record', 'definer', 'FND-09: report of the verification of a restore (j:ops.verify-restore)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
