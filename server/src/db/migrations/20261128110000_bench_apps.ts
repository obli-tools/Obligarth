import type { Knex } from 'knex';

// =============================================================================
// The bench installs the required apps by ADB (lot BANC-A; spec banc-apps)
// =============================================================================
//   a) bench_provisionings_kind_check admits 'apps': a device ALREADY enrolled brought back to the bench to complete
//      its required apps (« compléter les apps »), found by the server inside the station's targets from the identity
//      the station proves (bench/apps.service.ts). Through widen_in_check (coordination_socle): idempotent, nothing at
//      all when the list already holds the value.
//   b) obligarth_private.bench_provisionings_transition: a provisioning of kind 'apps' starts 'enrolled' with its device
//      (as a conversion does); every other rule unchanged (kind, station and serial never change; enrolled -> completed |
//      failed | abandoned | expired). bench_provisionings_convert_check (kind = 'new' OR no token) already holds: a
//      provisioning of kind 'apps' never has an enrollment token.
// Precondition (method of legacy_agent): the body of the trigger function is still the one of bench_stations (md5).
// The step 'apps' of the journal needs nothing: bench_provisionings_steps_check bounds the array, not its entries.
// Rules of the specs README §3: SQL by String.raw, no question mark, functions with SET search_path = pg_catalog,
// pg_temp and EXECUTE revoked from PUBLIC, rls_assert_clean() last, a down that raises. Runs as obligarth_owner
// (server-migrate), after bench_station_owner.
// =============================================================================

// md5 of the body of obligarth_private.bench_provisionings_transition() written by 20261102100000_bench_stations.
const TRANSITION_BODY_MD5 = 'ee5f588c4c81eafa6887697b6fe1aff8';

const UP = String.raw`-- =============================================================================
-- The bench installs the required apps (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.bench_provisionings') IS NULL
     OR to_regprocedure('obligarth_private.widen_in_check(regclass, text, text[])') IS NULL
     OR to_regprocedure('obligarth_private.bench_provisionings_transition()') IS NULL THEN
    RAISE EXCEPTION 'bench_apps: apply coordination_socle and bench_stations first';
  END IF;
  IF (SELECT md5(p.prosrc) FROM pg_catalog.pg_proc p WHERE p.oid = 'obligarth_private.bench_provisionings_transition()'::regprocedure)
     IS DISTINCT FROM '${TRANSITION_BODY_MD5}' THEN
    RAISE EXCEPTION 'bench_apps: obligarth_private.bench_provisionings_transition() is no longer the body of bench_stations';
  END IF;
END $$;

-- a) The kind of a provisioning ------------------------------------------------------------
SELECT obligarth_private.widen_in_check('obligarth.bench_provisionings', 'bench_provisionings_kind_check', ARRAY['apps']);

-- b) Its transitions: 'apps' starts enrolled, with its device ------------------------------
CREATE OR REPLACE FUNCTION obligarth_private.bench_provisionings_transition() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF (NEW.state = 'planned' AND NEW.kind = 'new')
       OR (NEW.state = 'enrolled' AND NEW.kind IN ('convert', 'apps') AND NEW.device_id IS NOT NULL) THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_provisionings_transition',
      MESSAGE = 'bench_provisionings: a provisioning starts planned (new) or enrolled (convert, apps: with its device)';
  END IF;
  IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.station_id IS DISTINCT FROM OLD.station_id OR NEW.adb_serial IS DISTINCT FROM OLD.adb_serial THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_provisionings_transition',
      MESSAGE = 'bench_provisionings: the kind, the station and the serial of a provisioning never change';
  END IF;
  IF NEW.state = OLD.state THEN
    RETURN NEW;
  END IF;
  IF (OLD.state = 'planned' AND NEW.state IN ('token_issued', 'failed', 'abandoned', 'expired'))
     OR (OLD.state = 'token_issued' AND NEW.state IN ('enrolled', 'failed', 'abandoned', 'expired'))
     OR (OLD.state = 'enrolled' AND NEW.state IN ('completed', 'failed', 'abandoned', 'expired')) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_provisionings_transition',
    MESSAGE = format('bench_provisionings: %s -> %s is not a transition', OLD.state, NEW.state);
END $$;
REVOKE ALL ON FUNCTION obligarth_private.bench_provisionings_transition() FROM PUBLIC;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('bench_apps cannot be rolled back: restore the backup taken before the upgrade');
}
