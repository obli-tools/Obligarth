import type { Knex } from 'knex';

// =============================================================================
// Obligarth — base seed: master tenant, permission sets, platform settings
// =============================================================================
//
// Rows the server needs on an empty database, right after the base schema
// (20261001090000_base_schema). Idempotent: a row that already exists is kept
// as it is.

/**
 * Restrictions of the master tenant (tenants.action_restrictions): the
 * recommended defaults of the restrictions matrix, i.e. those of the core
 * (restriction.service.ts) and of the device registry (modules/devices.ts).
 * A tenant created later starts with none ('{}', the column default).
 */
const MASTER_TENANT_RESTRICTIONS = {
  'device.delete': 'sensitive',
  'device.bulk_group_change': 'sensitive',
  'device.transfer_tenant': 'sensitive',
  'audit.clear': 'restricted',
};

/**
 * Default permission sets (tenant roles). Only the tenant capabilities of
 * @obligarth/shared (capabilities.ts), with the rights the inherited sets
 * gave once reduced to that vocabulary. A tenant administrator ('admin')
 * holds every tenant capability whatever its set says (permissionService);
 * the set is what the matrix shows.
 */
const PERMISSION_SETS = [
  {
    name: 'Admin',
    slug: 'admin',
    capabilities: ['devices.manage', 'groups.manage', 'reports', 'settings', 'users.manage', 'agent_config:approval'],
  },
  { name: 'User', slug: 'user', capabilities: ['agent_config:approval'] },
  { name: 'Viewer', slug: 'viewer', capabilities: [] },
];

/** Platform settings (app_config): values are strings, read as such. */
const APP_CONFIG: Array<{ key: string; value: string | null }> = [
  { key: 'allow_2fa', value: 'true' },
  { key: 'force_2fa', value: 'false' },
  { key: 'otp_smtp_server_id', value: null },
  { key: 'inventory_retention_days', value: '90' },
  { key: 'app_name', value: 'Obligarth' },
  { key: 'default_language', value: 'en' },
];

export async function up(knex: Knex): Promise<void> {
  // Master tenant: id 1 is hard-wired (isMasterTenant). The explicit id does
  // not advance tenants_id_seq: realign it, or the first tenant created
  // afterwards would get id 1 and fail on the primary key.
  await knex('tenants')
    .insert({ id: 1, name: 'Default', slug: 'default', action_restrictions: JSON.stringify(MASTER_TENANT_RESTRICTIONS) })
    .onConflict('id')
    .ignore();
  await knex.raw(`SELECT setval(pg_get_serial_sequence('tenants', 'id'), (SELECT max(id) FROM tenants))`);

  await knex('permission_sets')
    .insert(PERMISSION_SETS.map((s) => ({
      name: s.name,
      slug: s.slug,
      capabilities: JSON.stringify(s.capabilities),
      is_default: true,
    })))
    .onConflict('slug')
    .ignore();

  await knex('app_config').insert(APP_CONFIG).onConflict('key').ignore();
}

export async function down(_knex: Knex): Promise<void> {
  // Nothing: rolling back the base schema drops these tables with their rows,
  // and removing the master tenant alone would delete everything it owns.
}
