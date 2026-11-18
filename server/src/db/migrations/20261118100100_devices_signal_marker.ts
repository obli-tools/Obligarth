import type { Knex } from 'knex';

// =============================================================================
// Obliwatch integration, lot L2 (brief GTH-03): the change marker of the devices read by Obliwatch
// =============================================================================
//   devices.updated_at is not a reliable cursor (no trigger; the AMAPI status report updates devices and its satellite
//   without touching it). GET /api/integrations/obliwatch/v1/devices?updatedSince= reads a marker of its own:
//   - devices.signal_updated_at timestamptz NOT NULL: the last change of a datum the read API exposes. Added with the
//     constant default of the migration's time (a fast default: a change of the catalog only, no row rewritten), then
//     clock_timestamp() for the rows inserted later;
//   - trigger devices_signal_marker, BEFORE UPDATE OF the exposed columns, WHEN one of them really changes: it sets
//     NEW.signal_updated_at in the row being written (owner decision Q-L2a: no extra write). The data exposed from
//     other tables (AMAPI posture and patch, bridge agent's patch, the end user's e-mail, the first inventory of the
//     apps) is marked by the application inside the transaction that writes it (integrations/obliwatch/marker.ts).
//   The index (tenant_id, signal_updated_at, uuid) of the read is built CONCURRENTLY by the next migration.
// Additive, re-runnable (IF NOT EXISTS, CREATE OR REPLACE, DROP TRIGGER IF EXISTS). Nothing reads the column while
// OBLIWATCH_INTEGRATION is not 'on'; the trigger costs one row comparison per update of devices.
// Rules of the specs README §3: SQL by String.raw, no question mark, the trigger function with SET search_path and
// EXECUTE revoked from PUBLIC, rls_assert_clean() last, a down that raises. Runs as obligarth_owner (server-migrate).
// =============================================================================

const UP = String.raw`-- =============================================================================
-- devices.signal_updated_at and its trigger (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;
-- The ALTER takes an ACCESS EXCLUSIVE lock on the most written table: fail fast rather than queue every reader and
-- writer of devices behind a long transaction (an old server container still running).
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
  IF to_regclass('obligarth.devices') IS NULL THEN
    RAISE EXCEPTION 'devices_signal_marker: devices is missing';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'obligarth.devices'::regclass
                  AND attname = 'lost_mode_state' AND NOT attisdropped) THEN
    RAISE EXCEPTION 'devices_signal_marker: apply the mdm_model_expand migration first';
  END IF;
END $$;

-- now() is stable: a fast default, evaluated once (the existing rows read the migration's time, none is rewritten).
ALTER TABLE obligarth.devices ADD COLUMN IF NOT EXISTS signal_updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE obligarth.devices ALTER COLUMN signal_updated_at SET DEFAULT clock_timestamp();
COMMENT ON COLUMN obligarth.devices.signal_updated_at IS
  'Obliwatch read API (GTH-03): last change of a datum it exposes (trigger devices_signal_marker, plus the marks of the application for the satellites)';

CREATE OR REPLACE FUNCTION obligarth_private.devices_signal_marker() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  -- clock_timestamp, not now(): two changes of one long transaction keep their order.
  NEW.signal_updated_at := clock_timestamp();
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.devices_signal_marker() FROM PUBLIC;

DROP TRIGGER IF EXISTS devices_signal_marker ON obligarth.devices;
CREATE TRIGGER devices_signal_marker BEFORE UPDATE OF
    platform, management_channel, ownership, management_mode, supervised, os_version, compliance_state,
    compliance_reasons, lost_mode_state, last_checkin_at, enrollment_state, end_user_id, display_name, device_name,
    serial_number
  ON obligarth.devices
  FOR EACH ROW WHEN (
    ROW(OLD.platform, OLD.management_channel, OLD.ownership, OLD.management_mode, OLD.supervised, OLD.os_version,
        OLD.compliance_state, OLD.compliance_reasons, OLD.lost_mode_state, OLD.last_checkin_at, OLD.enrollment_state,
        OLD.end_user_id, OLD.display_name, OLD.device_name, OLD.serial_number)
    IS DISTINCT FROM
    ROW(NEW.platform, NEW.management_channel, NEW.ownership, NEW.management_mode, NEW.supervised, NEW.os_version,
        NEW.compliance_state, NEW.compliance_reasons, NEW.lost_mode_state, NEW.last_checkin_at, NEW.enrollment_state,
        NEW.end_user_id, NEW.display_name, NEW.device_name, NEW.serial_number))
  EXECUTE FUNCTION obligarth_private.devices_signal_marker();

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
