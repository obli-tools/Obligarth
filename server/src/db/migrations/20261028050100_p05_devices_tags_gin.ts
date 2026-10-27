import type { Knex } from 'knex';

// =============================================================================
// GIN index of the tags of the devices (P0-5 T2, M1 of the spec): the jsonb operators ?| and ?& of the keys (the tag
// filter of the list, the rule language). Built CONCURRENTLY, out of a transaction (base_schema's rule: the only case
// of `transaction: false`): devices is the most written table (check-ins, inventory, Android ingestion, bridge agent),
// and a plain CREATE INDEX would hold its writers for the whole build. An index left invalid by an interrupted build
// (CONCURRENTLY leaves one behind) is dropped and built again; a valid one is kept (IF NOT EXISTS: a run started again,
// or the same index created by another lot). One statement per call: CONCURRENTLY refuses a transaction block, and a
// string of several statements is one. Runs as obligarth_owner (server-migrate); the names are schema-qualified (no
// SET LOCAL out of a transaction).
// =============================================================================

export const config = { transaction: false };

export async function up(knex: Knex): Promise<void> {
  const r = await knex.raw(String.raw`SELECT i.indisvalid AS valid FROM pg_catalog.pg_index i
    WHERE i.indexrelid = pg_catalog.to_regclass('obligarth.devices_tags_gin')`) as { rows: Array<{ valid: boolean }> };
  if (r.rows.length > 0 && !r.rows[0].valid) {
    await knex.raw(String.raw`DROP INDEX CONCURRENTLY IF EXISTS obligarth.devices_tags_gin`);
  }
  await knex.raw(String.raw`CREATE INDEX CONCURRENTLY IF NOT EXISTS devices_tags_gin ON obligarth.devices USING gin (tags)`);
  await knex.raw(String.raw`SELECT obligarth.rls_assert_clean()`);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
