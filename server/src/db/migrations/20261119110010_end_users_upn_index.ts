import type { Knex } from 'knex';

// =============================================================================
// Unique indexes of the UPN and of the Entra object id of the end users (Obliwatch integration, lot L4, GTH-02): one
// UPN (case insensitive, like the e-mail's end_users_email_uq) and one Entra object id per tenant. Built CONCURRENTLY,
// out of a transaction (base schema's rule: the only case of `transaction: false`): end_users is written by the
// enrollments, a plain CREATE INDEX would hold them for the whole build. The columns were added by the previous
// migration and are NULL everywhere: the partial indexes are empty, a duplicate cannot fail the build. An index left
// invalid by an interrupted build is dropped and built again; a valid one is kept (IF NOT EXISTS). One statement per
// call (CONCURRENTLY refuses a transaction block). Runs as obligarth_owner (server-migrate); the names are
// schema-qualified (no SET LOCAL out of a transaction).
// =============================================================================

export const config = { transaction: false };

const INDEXES: Array<{ name: string; ddl: string }> = [
  {
    name: 'end_users_upn_uq',
    ddl: String.raw`CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS end_users_upn_uq
      ON obligarth.end_users (tenant_id, lower(upn)) WHERE upn IS NOT NULL`,
  },
  {
    name: 'end_users_entra_uq',
    ddl: String.raw`CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS end_users_entra_uq
      ON obligarth.end_users (tenant_id, entra_object_id) WHERE entra_object_id IS NOT NULL`,
  },
];

export async function up(knex: Knex): Promise<void> {
  for (const ix of INDEXES) {
    const r = await knex.raw(String.raw`SELECT i.indisvalid AS valid FROM pg_catalog.pg_index i
      WHERE i.indexrelid = pg_catalog.to_regclass('obligarth.' || :name)`, { name: ix.name }) as { rows: Array<{ valid: boolean }> };
    if (r.rows.length > 0 && !r.rows[0].valid) {
      if (ix.name === 'end_users_upn_uq') await knex.raw(String.raw`DROP INDEX CONCURRENTLY IF EXISTS obligarth.end_users_upn_uq`);
      else await knex.raw(String.raw`DROP INDEX CONCURRENTLY IF EXISTS obligarth.end_users_entra_uq`);
    }
    await knex.raw(ix.ddl);
  }
  await knex.raw(String.raw`SELECT obligarth.rls_assert_clean()`);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
