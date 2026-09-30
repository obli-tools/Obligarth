import type { Knex } from 'knex';

// ObliReach automatic install / update by the Obliance agent.
//
// devices.oblireach_status: the last state the agent reported in its push
// body (`oblireach`: state, installed / target version, running, error,
// attempts, last / next attempt), normalised by the server, plus `since`
// (when that exact report was first received). Written only when the report
// changes, so a stable fleet writes nothing. NULL = never reported (legacy
// agent, agent older than the feature).
//
// The switches need no schema: app_config 'oblireach_auto_install'
// (platform-wide, absent = on) and the settings key 'oblireachAutoInstall'
// (tenant → group → device cascade, default on).
//
// Nullable, no default: a catalog-only change in PostgreSQL (no table
// rewrite). Idempotent.
export async function up(knex: Knex): Promise<void> {
  if (!(await knex.schema.hasColumn('devices', 'oblireach_status'))) {
    await knex.schema.alterTable('devices', (t) => {
      t.jsonb('oblireach_status').nullable();
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  if (await knex.schema.hasColumn('devices', 'oblireach_status')) {
    await knex.schema.alterTable('devices', (t) => t.dropColumn('oblireach_status'));
  }
}
