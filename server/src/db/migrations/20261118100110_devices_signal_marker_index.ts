import type { Knex } from 'knex';

// =============================================================================
// Index of the change marker of the devices (Obliwatch read API, lot L2): GET /devices?updatedSince=&cursor= reads
// the devices of one tenant in the order (signal_updated_at, uuid). Built CONCURRENTLY, out of a transaction (base
// schema's rule: the only case of `transaction: false`): devices is the most written table, a plain CREATE INDEX would
// hold its writers for the whole build. An index left invalid by an interrupted build is dropped and built again; a
// valid one is kept (IF NOT EXISTS). One statement per call (CONCURRENTLY refuses a transaction block). Runs as
// obligarth_owner (server-migrate); the names are schema-qualified (no SET LOCAL out of a transaction).
// =============================================================================

export const config = { transaction: false };

export async function up(knex: Knex): Promise<void> {
  const r = await knex.raw(String.raw`SELECT i.indisvalid AS valid FROM pg_catalog.pg_index i
    WHERE i.indexrelid = pg_catalog.to_regclass('obligarth.devices_signal_marker_idx')`) as { rows: Array<{ valid: boolean }> };
  if (r.rows.length > 0 && !r.rows[0].valid) {
    await knex.raw(String.raw`DROP INDEX CONCURRENTLY IF EXISTS obligarth.devices_signal_marker_idx`);
  }
  await knex.raw(String.raw`CREATE INDEX CONCURRENTLY IF NOT EXISTS devices_signal_marker_idx
    ON obligarth.devices (tenant_id, signal_updated_at, uuid)`);
  await knex.raw(String.raw`SELECT obligarth.rls_assert_clean()`);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
