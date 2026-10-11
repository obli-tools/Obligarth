import type { Knex } from 'knex';

// =============================================================================
// Indexes of the retention purges (CNF-04; docs: file-durable annex B, modele-donnees-mdm §5.5,
// integration-apple-edge §4.9, §13.3; modules/privacy.ts, apple/retention.ts, mdm/inventory/retention.ts)
// =============================================================================
//   - device_status_history (tenant_id, observed_at): the rule device_status_history reads one tenant's
//     rows by observed_at (the index on observed_at alone mixes the tenants);
//   - enrollment_sessions (tenant_id, state_at): enrollment.purge-expired reads one tenant's ended sessions
//     by state_at;
//   - apple_device_events (tenant_id, occurred_at): the rule apple_device_events reads one tenant's timeline
//     by date (the timeline index starts with the device);
//   - device_enrollments (tenant_id, channel_enrollment_id): before the enrollments of a record due are
//     purged at apple-edge, the retention looks for another record of the tenant that holds one of them.
// The other purges are served by existing indexes: notification_log (tenant_id, created_at), mdm_commands
// (tenant_id, created_at) and the primary key of mdm_command_targets, end_users_departed,
// lost_mode_locations_purge, devices_retention, apple_devices_enrollment_id_uq.
// No table, no function, no policy: the classification of the RLS is unchanged. Runs as obligarth_owner
// (server-migrate), after apple_ddm; ends with obligarth.rls_assert_clean(). No question mark in the SQL
// (knex.raw would bind it); kept verbatim by String.raw.

const UP = String.raw`-- =============================================================================
-- Indexes of the retention purges (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.device_status_history') IS NULL OR to_regclass('obligarth.device_enrollments') IS NULL
     OR to_regclass('obligarth.enrollment_sessions') IS NULL OR to_regclass('obligarth.apple_device_events') IS NULL THEN
    RAISE EXCEPTION 'retention_indexes: apply mdm_model_expand and apple_enrollment first';
  END IF;
END $$;

CREATE INDEX device_status_history_tenant_observed
  ON obligarth.device_status_history (tenant_id, observed_at);
CREATE INDEX enrollment_sessions_tenant_state_at
  ON obligarth.enrollment_sessions (tenant_id, state_at);
CREATE INDEX apple_device_events_tenant_occurred
  ON obligarth.apple_device_events (tenant_id, occurred_at);
CREATE INDEX device_enrollments_tenant_channel
  ON obligarth.device_enrollments (tenant_id, channel_enrollment_id);

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
