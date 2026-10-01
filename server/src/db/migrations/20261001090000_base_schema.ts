import type { Knex } from 'knex';

// =============================================================================
// Obligarth — base schema
// =============================================================================
//
// First migration of Obligarth. It replaces the 140 migrations inherited from
// Obliance (no Obligarth database existed before it, so there is no upgrade
// path to keep) and creates, in one transaction, the schema they left on an
// empty database, reduced to what this server still uses:
//   - the core tables (tenants, accounts, sessions, second factors, phone
//     keys, teams and permission sets, restrictions and approvals, audit,
//     platform settings, SMTP) and the ones the MDM adapts (devices, groups,
//     settings cascade, notifications, live alerts, fleet snapshots,
//     enrollment keys, inventory, maintenance, reports, software repository,
//     licenses);
//   - the columns the code still reads or writes. None of the removed RMM's
//     tables (scripts, schedules, scenarios, updates, compliance, CVE,
//     remote access and its sessions, SSH bastion, metrics history, Hyper-V,
//     Veeam, network discovery…) and none of the agent's per-device columns
//     (metric levels included).
//
// Invariants carried over from the inherited schema, on purpose:
//   - trigger users_credential_version (function users_bump_credential_version):
//     a change of password, TOTP secret or activation, account activation or
//     SSO identity bumps users.credential_version, which revokes the phone
//     keys enrolled under the previous value, whatever code path made it;
//   - users.totp_last_step / totp_last_session (TOTP anti-replay) and
//     step_up_throttle (persisted caps on second-factor failures);
//   - settings: partial unique indexes settings_global_uq (scope_id IS NULL)
//     and settings_scoped_uq (scope_id IS NOT NULL); a plain UNIQUE would let
//     duplicate global rows in, NULLs being distinct;
//   - live_alerts: partial indexes on the active rows (resolved_at IS NULL);
//   - user_tenants.role: varchar(64), the slug of a permission set;
//   - team_permissions.scope 'ungrouped' (scope_id 0 by convention);
//   - pending_approvals: description text, sealed_payload (executor-only data,
//     wiped at resolution), execution_error;
//   - phone keys: user_device_keys, device_key_challenges.
// New: team_permissions is unique on (team_id, scope, scope_id), the conflict
// target of teamService.addPermission.
//
// Rules for this migration and the ones after it:
//   - one change = one new timestamped file (YYYYMMDDhhmmss_name.ts), never
//     edited once released; a schema fix ported from Obliance is a NEW
//     migration here, never a copy under its original name;
//   - no import of application code (`import type { Knex }` only): every
//     pending migration is loaded before the first one runs, so one import
//     that no longer resolves blocks the server's start;
//   - no PostgreSQL enum type: varchar + CHECK (<table>_<column>_check), which
//     a later migration widens or narrows in a transaction (an enum value
//     cannot be removed, nor used in the transaction that adds it);
//   - `transaction: false` only when unavoidable (CREATE INDEX CONCURRENTLY).
//
// The seed (tenant 1, permission sets, platform settings) is the next
// migration, 20261001090100_base_seed.

/** Varchar value sets, checked by the database (see the rules above). */
const VALUES = {
  userRole: ['admin', 'user'],
  teamScope: ['group', 'device', 'ungrouped'],
  teamLevel: ['ro', 'rw'],
  osType: ['windows', 'macos', 'linux', 'freebsd', 'other'],
  deviceStatus: [
    'pending', 'online', 'offline', 'maintenance', 'warning', 'critical',
    'suspended', 'pending_uninstall', 'updating', 'update_error',
  ],
  approvalStatus: ['pending', 'approved', 'refused'],
  alertSeverity: ['info', 'warning', 'critical'],
  notificationChannelType: [
    'telegram', 'discord', 'slack', 'teams', 'smtp',
    'webhook', 'gotify', 'ntfy', 'pushover', 'freemobile',
  ],
  overrideMode: ['merge', 'replace', 'exclude'],
  maintenanceScope: ['global', 'group', 'device'],
  maintenanceSchedule: ['one_time', 'recurring'],
  reportType: ['fleet', 'software', 'custom'],
  reportFormat: ['json', 'csv', 'pdf', 'excel', 'html'],
  reportStatus: ['generating', 'ready', 'error'],
} as const;

/** CHECK (column IN (values)), named like Knex names its own column checks. */
async function checkIn(knex: Knex, table: string, column: string, values: readonly string[]): Promise<void> {
  // DDL takes no bind parameters: the values are this file's constants.
  const list = values.map((v) => `'${v.replace(/'/g, "''")}'`).join(', ');
  await knex.raw(`ALTER TABLE ?? ADD CONSTRAINT ?? CHECK (?? IN (${list}))`, [table, `${table}_${column}_check`, column]);
}

export async function up(knex: Knex): Promise<void> {
  // ===========================================================================
  // SESSIONS (connect-pg-simple, createTableIfMissing: false)
  // ===========================================================================
  await knex.schema.createTable('session', (t) => {
    t.string('sid').primary().notNullable();
    t.json('sess').notNullable();
    t.timestamp('expire', { useTz: false }).notNullable().index();
  });

  // ===========================================================================
  // ACCOUNTS
  // ===========================================================================
  await knex.schema.createTable('users', (t) => {
    t.increments('id').primary();
    t.string('username', 100).notNullable().unique();
    t.string('password_hash');                        // NULL for an SSO-only account
    t.string('display_name', 200);
    t.string('role', 32).notNullable().defaultTo('user');   // platform role
    t.boolean('is_active').notNullable().defaultTo(true);
    t.string('email').unique();
    t.string('preferred_language', 10).defaultTo('en');
    t.integer('enrollment_version').defaultTo(0);
    t.jsonb('preferences').defaultTo('{}');
    t.string('totp_secret');
    t.boolean('totp_enabled').notNullable().defaultTo(false);
    t.boolean('email_otp_enabled').notNullable().defaultTo(false);
    t.timestamps(true, true);
    // SSO identity (Obligate)
    t.string('foreign_source', 64);
    t.integer('foreign_id');
    t.string('foreign_source_url', 512);
    t.text('avatar');
    // TOTP anti-replay: last accepted step, and the session that used it
    t.bigInteger('totp_last_step');
    t.string('totp_last_session', 64);
    // Bumped by users_credential_version (below)
    t.integer('credential_version').notNullable().defaultTo(1);
  });
  await checkIn(knex, 'users', 'role', VALUES.userRole);

  // Kept by the database, whatever path changes a credential: phone keys
  // store the version they were enrolled under.
  await knex.raw(`
    CREATE FUNCTION users_bump_credential_version() RETURNS trigger AS $$
    BEGIN
      IF NEW.password_hash  IS DISTINCT FROM OLD.password_hash
      OR NEW.totp_secret    IS DISTINCT FROM OLD.totp_secret
      OR NEW.totp_enabled   IS DISTINCT FROM OLD.totp_enabled
      OR NEW.is_active      IS DISTINCT FROM OLD.is_active
      OR NEW.foreign_source IS DISTINCT FROM OLD.foreign_source
      OR NEW.foreign_id     IS DISTINCT FROM OLD.foreign_id THEN
        NEW.credential_version := OLD.credential_version + 1;
      END IF;
      RETURN NEW;
    END $$ LANGUAGE plpgsql;
  `);
  await knex.raw(`
    CREATE TRIGGER users_credential_version BEFORE UPDATE ON users
      FOR EACH ROW EXECUTE FUNCTION users_bump_credential_version()
  `);

  // ===========================================================================
  // TENANTS (id 1 = master tenant, seeded by the next migration)
  // ===========================================================================
  await knex.schema.createTable('tenants', (t) => {
    t.increments('id').primary();
    t.string('name', 200).notNullable();
    t.string('slug', 100).notNullable().unique();     // join key with Obligate
    t.timestamps(true, true);
    t.boolean('two_step_approval').notNullable().defaultTo(false);
    // Restrictions matrix: { "<action>": level | { level, scope } }
    t.jsonb('action_restrictions').notNullable().defaultTo('{}');
    // Software repository of the tenant
    t.boolean('repo_enabled').notNullable().defaultTo(true);
    t.bigInteger('repo_quota_bytes');
    t.string('repo_access_key_hash', 128);
    t.string('repo_access_key_prefix', 32);
  });

  await knex.schema.createTable('user_tenants', (t) => {
    t.integer('user_id').notNullable()
      .references('id').inTable('users').onDelete('CASCADE');
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    // Tenant role = slug of a permission set (no foreign key)
    t.string('role', 64).notNullable().defaultTo('user');
    t.primary(['user_id', 'tenant_id']);
  });

  await knex.schema.createTable('password_reset_tokens', (t) => {
    t.increments('id').primary();
    t.integer('user_id').notNullable()
      .references('id').inTable('users').onDelete('CASCADE');
    t.string('token_hash').notNullable().unique();
    t.timestamp('expires_at').notNullable();
    t.timestamp('used_at');
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
  });

  // ===========================================================================
  // PLATFORM SETTINGS (key-value)
  // ===========================================================================
  await knex.schema.createTable('app_config', (t) => {
    t.string('key').primary();
    t.text('value');
  });

  // ===========================================================================
  // DEVICE GROUPS (tree + closure table)
  // ===========================================================================
  await knex.schema.createTable('device_groups', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('parent_id')
      .references('id').inTable('device_groups').onDelete('SET NULL');
    t.string('name', 200).notNullable();
    t.string('slug', 200).notNullable();
    t.text('description');
    t.integer('sort_order').defaultTo(0);
    t.boolean('group_notifications').notNullable().defaultTo(false);
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.timestamps(true, true);
    t.unique(['slug', 'tenant_id']);
  });

  await knex.schema.createTable('device_group_closure', (t) => {
    t.integer('ancestor_id').notNullable()
      .references('id').inTable('device_groups').onDelete('CASCADE');
    t.integer('descendant_id').notNullable()
      .references('id').inTable('device_groups').onDelete('CASCADE');
    t.integer('depth').notNullable();
    t.primary(['ancestor_id', 'descendant_id']);
  });

  // ===========================================================================
  // TEAMS: members, and scopes ("where": groups, devices, ungrouped devices)
  // ===========================================================================
  await knex.schema.createTable('user_teams', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('name', 200).notNullable();
    t.boolean('can_create').notNullable().defaultTo(false);
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.timestamps(true, true);
    t.text('description');
  });

  await knex.schema.createTable('team_memberships', (t) => {
    t.integer('team_id').notNullable()
      .references('id').inTable('user_teams').onDelete('CASCADE');
    t.integer('user_id').notNullable()
      .references('id').inTable('users').onDelete('CASCADE');
    t.primary(['team_id', 'user_id']);
  });

  await knex.schema.createTable('team_permissions', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('team_id').notNullable()
      .references('id').inTable('user_teams').onDelete('CASCADE');
    t.string('scope', 32).notNullable();
    t.integer('scope_id').notNullable();              // group id, device id, 0 for 'ungrouped'
    t.string('level', 32).notNullable().defaultTo('ro');
    // Device capabilities of the row (shared capabilities.ts)
    t.jsonb('capabilities').defaultTo('["monitor"]');
    t.unique(['team_id', 'scope', 'scope_id']);
  });
  await checkIn(knex, 'team_permissions', 'scope', VALUES.teamScope);
  await checkIn(knex, 'team_permissions', 'level', VALUES.teamLevel);

  // ===========================================================================
  // SETTINGS (cascade: global → group → device)
  // ===========================================================================
  await knex.schema.createTable('settings', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('scope', 20).notNullable();              // 'global' | 'group' | 'device'
    t.integer('scope_id');                            // NULL for 'global'
    t.string('key', 100).notNullable();
    t.jsonb('value');
    t.timestamps(true, true);
  });
  await knex.raw(`
    CREATE UNIQUE INDEX settings_global_uq
      ON settings (tenant_id, scope, key)
      WHERE scope_id IS NULL
  `);
  await knex.raw(`
    CREATE UNIQUE INDEX settings_scoped_uq
      ON settings (tenant_id, scope, scope_id, key)
      WHERE scope_id IS NOT NULL
  `);

  // ===========================================================================
  // SMTP SERVERS
  // ===========================================================================
  await knex.schema.createTable('smtp_servers', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id')
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('name', 200).notNullable();
    t.string('host').notNullable();
    t.integer('port').notNullable().defaultTo(587);
    t.boolean('secure').notNullable().defaultTo(false);
    t.string('username');
    t.string('password');
    t.string('from_address');
    t.timestamps(true, true);
  });

  // ===========================================================================
  // NOTIFICATIONS
  // ===========================================================================
  await knex.schema.createTable('notification_channels', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('name', 200).notNullable();
    t.string('type', 32).notNullable();
    t.jsonb('config').notNullable().defaultTo('{}');
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.timestamps(true, true);
    t.boolean('is_enabled').notNullable().defaultTo(true);
    t.integer('created_by')
      .references('id').inTable('users').onDelete('SET NULL');
  });
  await checkIn(knex, 'notification_channels', 'type', VALUES.notificationChannelType);

  // Sharing of a master-tenant channel with other tenants
  await knex.schema.createTable('notification_channel_tenants', (t) => {
    t.integer('channel_id').notNullable()
      .references('id').inTable('notification_channels').onDelete('CASCADE');
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.primary(['channel_id', 'tenant_id']);
    t.index(['tenant_id']);
  });

  await knex.schema.createTable('notification_bindings', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('channel_id').notNullable()
      .references('id').inTable('notification_channels').onDelete('CASCADE');
    t.string('scope', 20).notNullable();              // 'global' | 'group' | 'device'
    t.integer('scope_id');
    t.string('override_mode', 32).notNullable().defaultTo('merge');
  });
  await checkIn(knex, 'notification_bindings', 'override_mode', VALUES.overrideMode);

  await knex.schema.createTable('notification_log', (t) => {
    t.increments('id').primary();
    t.integer('channel_id')
      .references('id').inTable('notification_channels').onDelete('SET NULL');
    t.string('scope', 20);
    t.integer('scope_id');
    t.string('event_type', 100);
    t.string('status', 20);
    t.text('error_message');
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
  });

  // ===========================================================================
  // LIVE ALERTS
  // ===========================================================================
  await knex.schema.createTable('live_alerts', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('severity', 32).notNullable().defaultTo('info');
    t.string('title', 500).notNullable();
    t.text('message');
    t.string('navigate_to', 500);
    t.string('stable_key', 500);                      // deduplication / incident key
    t.timestamp('read_at');
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    t.timestamp('resolved_at');                       // NULL = active
    t.index(['tenant_id', 'created_at']);
    t.index(['tenant_id', 'stable_key']);
  });
  await checkIn(knex, 'live_alerts', 'severity', VALUES.alertSeverity);
  // The active rows only: the lists and the incident lookups never read the
  // resolved ones, which age out through the trim.
  await knex.raw(`
    CREATE INDEX live_alerts_active_stable_key_idx
      ON live_alerts (stable_key)
      WHERE resolved_at IS NULL
  `);
  await knex.raw(`
    CREATE INDEX live_alerts_active_tenant_id_idx
      ON live_alerts (tenant_id, id DESC)
      WHERE resolved_at IS NULL
  `);

  // ===========================================================================
  // MAINTENANCE WINDOWS
  // ===========================================================================
  await knex.schema.createTable('maintenance_windows', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('name', 200).notNullable();
    t.string('scope_type', 32).notNullable().defaultTo('global');
    t.integer('scope_id');                            // NULL when scope_type = 'global'
    t.string('schedule_type', 32).notNullable().defaultTo('one_time');
    t.timestamp('starts_at').notNullable();
    t.timestamp('ends_at').notNullable();
    t.jsonb('recurrence_rule').defaultTo('{}');
    t.string('timezone', 100).defaultTo('UTC');
    t.jsonb('notification_channels').defaultTo('[]');
    t.string('last_dedup_key', 500);
    t.integer('created_by').references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });
  await checkIn(knex, 'maintenance_windows', 'scope_type', VALUES.maintenanceScope);
  await checkIn(knex, 'maintenance_windows', 'schedule_type', VALUES.maintenanceSchedule);

  await knex.schema.createTable('maintenance_window_disables', (t) => {
    t.increments('id').primary();
    t.integer('window_id').notNullable()
      .references('id').inTable('maintenance_windows').onDelete('CASCADE');
    t.string('scope_type', 20).notNullable();         // 'group' | 'device'
    t.integer('scope_id').notNullable();
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
  });

  // ===========================================================================
  // ENROLLMENT KEYS (a key's default group is the pre-approval scope claim of
  // the devices enrolled with it: permissionService)
  // ===========================================================================
  await knex.schema.createTable('agent_api_keys', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('name', 200);
    t.string('key', 200).notNullable().unique();
    t.integer('created_by').references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    t.timestamp('last_used_at');
    t.integer('default_group_id')
      .references('id').inTable('device_groups').onDelete('SET NULL');
  });

  // ===========================================================================
  // DEVICES: the registry every authorization path joins (tenant, group,
  // enrollment key), with the columns the code still reads or writes
  // ===========================================================================
  await knex.schema.createTable('devices', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().unique().defaultTo(knex.raw('gen_random_uuid()'));
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('group_id')
      .references('id').inTable('device_groups').onDelete('SET NULL');
    t.integer('api_key_id')
      .references('id').inTable('agent_api_keys').onDelete('SET NULL');

    t.string('hostname', 500).notNullable();
    t.string('display_name', 500);
    t.text('description');

    t.string('ip_local', 45);
    t.string('ip_public', 45);
    t.string('mac_address', 50);

    t.string('os_type', 32).notNullable().defaultTo('other');
    t.string('os_name', 200);
    t.string('os_version', 200);

    t.string('status', 32).notNullable().defaultTo('pending');
    t.string('approval_status', 32).notNullable().defaultTo('pending');
    t.integer('approved_by').references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('approved_at');
    t.timestamp('last_seen_at');

    t.jsonb('tags').defaultTo('[]');
    t.jsonb('custom_fields').defaultTo('{}');
    t.timestamps(true, true);

    t.string('last_logged_in_user', 255);
    t.string('geo_city', 200);
    t.string('geo_country', 100);

    // Asset management
    t.date('purchase_date');
    t.date('warranty_expiry');
    t.string('warranty_vendor', 200);
    t.string('warranty_status', 20).defaultTo('unknown');
    t.integer('expected_lifetime_years');
    t.string('lifecycle_status', 20).defaultTo('unknown');

    t.index(['tenant_id', 'status']);
    t.index(['tenant_id', 'group_id']);
    t.index(['approval_status']);
  });
  await checkIn(knex, 'devices', 'os_type', VALUES.osType);
  await checkIn(knex, 'devices', 'status', VALUES.deviceStatus);
  await checkIn(knex, 'devices', 'approval_status', VALUES.approvalStatus);
  // Frequent row updates (check-ins): autovacuum keeps up before the heap and
  // indexes bloat. Kept from the agent's push flow until the MDM's load is
  // measured.
  await knex.raw(`
    ALTER TABLE devices SET (
      autovacuum_vacuum_scale_factor = 0.01,
      autovacuum_analyze_scale_factor = 0.01,
      autovacuum_vacuum_cost_delay = 0,
      autovacuum_vacuum_threshold = 200
    )
  `);

  // ===========================================================================
  // INVENTORY
  // ===========================================================================
  await knex.schema.createTable('device_inventory_hardware', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    t.jsonb('cpu').defaultTo('{}');
    t.jsonb('memory').defaultTo('{}');
    t.jsonb('disks').defaultTo('[]');
    t.jsonb('network_interfaces').defaultTo('[]');
    t.jsonb('gpu').defaultTo('[]');
    t.jsonb('motherboard').defaultTo('{}');
    t.jsonb('bios').defaultTo('{}');
    t.jsonb('raw').defaultTo('{}');
    t.timestamp('scanned_at').notNullable().defaultTo(knex.fn.now());
    t.jsonb('bitlocker').defaultTo('[]');
    t.jsonb('os');
    t.jsonb('battery');
    t.jsonb('printers').defaultTo('[]');
    t.jsonb('com_ports').defaultTo('[]');
    t.index(['device_id', 'scanned_at']);
  });

  await knex.schema.createTable('device_inventory_software', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    t.string('name', 500).notNullable();
    t.string('version', 200);
    t.string('publisher', 500);
    t.string('install_date', 50);
    t.text('install_location');
    t.string('source', 50);
    t.string('package_id', 500);
    t.timestamp('scanned_at').notNullable().defaultTo(knex.fn.now());
    t.index(['device_id', 'scanned_at']);
    t.index(['device_id', 'name']);
  });

  // ===========================================================================
  // REPORTS
  // ===========================================================================
  await knex.schema.createTable('reports', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('name', 300).notNullable();
    t.text('description');
    t.string('type', 32).notNullable().defaultTo('fleet');
    t.string('format', 32).notNullable().defaultTo('pdf');
    t.string('scope_type', 20).notNullable().defaultTo('tenant');   // 'tenant' | 'group' | 'device'
    t.integer('scope_id');
    t.jsonb('sections').defaultTo('["hardware", "software"]');
    t.jsonb('filters').defaultTo('{}');
    t.string('schedule_cron', 200);
    t.string('timezone', 100).defaultTo('UTC');
    t.boolean('is_enabled').notNullable().defaultTo(true);
    t.timestamp('last_generated_at');
    t.integer('created_by').references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });
  await checkIn(knex, 'reports', 'type', VALUES.reportType);
  await checkIn(knex, 'reports', 'format', VALUES.reportFormat);

  await knex.schema.createTable('report_outputs', (t) => {
    t.increments('id').primary();
    t.integer('report_id').notNullable()
      .references('id').inTable('reports').onDelete('CASCADE');
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('status', 32).notNullable().defaultTo('generating');
    t.string('file_path', 1000);
    t.bigInteger('file_size_bytes');
    t.integer('row_count');
    t.text('error_message');
    t.timestamp('expires_at');
    t.timestamp('generated_at');
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    t.index(['report_id', 'created_at']);
  });
  await checkIn(knex, 'report_outputs', 'status', VALUES.reportStatus);

  // ===========================================================================
  // SSO (Obligate): link between a remote identity and a local account
  // ===========================================================================
  await knex.schema.createTable('sso_foreign_users', (t) => {
    t.increments('id').primary();
    t.string('foreign_source', 64).notNullable();
    t.integer('foreign_user_id').notNullable();
    t.integer('local_user_id').notNullable()
      .references('id').inTable('users').onDelete('CASCADE');
    t.timestamps(true, true);
    t.unique(['foreign_source', 'foreign_user_id']);
  });

  // ===========================================================================
  // AUDIT LOG
  // ===========================================================================
  await knex.schema.createTable('audit_logs', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('user_id')
      .references('id').inTable('users').onDelete('SET NULL');
    t.integer('device_id')
      .references('id').inTable('devices').onDelete('SET NULL');
    t.string('action', 100).notNullable();
    t.string('resource_type', 50);
    t.text('resource_path');
    t.jsonb('details');
    t.string('ip_address', 45);
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
  });
  await knex.raw('CREATE INDEX idx_audit_logs_tenant ON audit_logs (tenant_id)');
  await knex.raw('CREATE INDEX idx_audit_logs_device ON audit_logs (device_id)');
  await knex.raw('CREATE INDEX idx_audit_logs_action ON audit_logs (action)');
  await knex.raw('CREATE INDEX idx_audit_logs_created ON audit_logs (created_at)');

  // ===========================================================================
  // SOFTWARE LICENSES
  // ===========================================================================
  await knex.schema.createTable('device_licenses', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('software_name', 500).notNullable();
    t.string('license_key', 500);
    t.string('license_type', 50);
    t.integer('seats');
    t.date('expiry_date');
    t.string('vendor', 200);
    t.text('notes');
    t.timestamps(true, true);
    t.index(['tenant_id', 'device_id']);
  });

  // ===========================================================================
  // PERMISSION SETS: tenant roles ("what"), global to the instance; seeded by
  // the next migration
  // ===========================================================================
  await knex.schema.createTable('permission_sets', (t) => {
    t.increments('id').primary();
    t.string('name', 64).notNullable();
    t.string('slug', 64).notNullable().unique();
    t.jsonb('capabilities').notNullable().defaultTo('[]');
    t.boolean('is_default').notNullable().defaultTo(false);
    t.timestamp('created_at').defaultTo(knex.fn.now());
  });

  // ===========================================================================
  // SOFTWARE REPOSITORY
  // ===========================================================================
  await knex.schema.createTable('software_repo_packages', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('filename', 500).notNullable();
    t.string('display_name', 500);
    t.bigInteger('file_size').notNullable();
    t.string('file_hash', 128).notNullable();
    t.string('mime_type', 100);
    t.string('platform', 20).notNullable();
    t.integer('uploaded_by').references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('created_at').defaultTo(knex.fn.now());
    t.index(['tenant_id']);
  });

  // ===========================================================================
  // TWO-STEP APPROVALS
  // ===========================================================================
  await knex.schema.createTable('pending_approvals', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('requested_by').notNullable()
      .references('id').inTable('users').onDelete('CASCADE');
    t.string('request_type', 64).notNullable();
    t.text('description').notNullable();
    t.jsonb('payload').notNullable();                 // shown to reviewers: never a secret
    t.string('status', 16).notNullable().defaultTo('pending');
    t.integer('reviewed_by')
      .references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('reviewed_at');
    t.string('review_reason', 500);
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    t.timestamp('expires_at').notNullable();
    t.timestamp('executed_at');
    t.jsonb('sealed_payload');                        // executor-only, wiped at resolution
    t.string('execution_error', 1000);
    t.index(['tenant_id', 'status']);
    t.index(['expires_at']);
  });

  // ===========================================================================
  // SECOND FACTOR: trusted IPs, failure caps
  // ===========================================================================
  await knex.schema.createTable('tfa_trusted_sessions', (t) => {
    t.increments('id').primary();
    t.integer('user_id').notNullable()
      .references('id').inTable('users').onDelete('CASCADE');
    t.string('ip_address', 64).notNullable();
    t.timestamp('trusted_until').notNullable();
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    t.unique(['user_id', 'ip_address']);
    t.index('trusted_until');
  });

  await knex.schema.createTable('step_up_throttle', (t) => {
    t.integer('user_id').notNullable()
      .references('id').inTable('users').onDelete('CASCADE');
    t.string('kind', 16).notNullable();
    t.timestamp('window_start');
    t.integer('window_failures').notNullable().defaultTo(0);
    t.timestamp('day_start');
    t.integer('day_failures').notNullable().defaultTo(0);
    t.boolean('locked').notNullable().defaultTo(false);
    t.timestamp('locked_until');
    t.timestamp('notified_at');
    t.primary(['user_id', 'kind']);
  });

  // ===========================================================================
  // FLEET SNAPSHOTS (dashboard deltas and charts)
  // ===========================================================================
  await knex.schema.createTable('fleet_daily_snapshot', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.date('day').notNullable();
    t.integer('total').notNullable().defaultTo(0);
    t.integer('online').notNullable().defaultTo(0);
    t.integer('offline').notNullable().defaultTo(0);
    t.integer('warning').notNullable().defaultTo(0);
    t.integer('critical').notNullable().defaultTo(0);
    t.integer('pending_updates').notNullable().defaultTo(0);
    t.integer('stale_72h').notNullable().defaultTo(0);
    t.integer('active_remote_sessions').notNullable().defaultTo(0);
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    t.unique(['tenant_id', 'day']);
    t.index(['tenant_id', 'day']);
  });

  await knex.schema.createTable('fleet_hourly_snapshot', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.timestamp('hour').notNullable();
    t.integer('total').notNullable().defaultTo(0);
    t.integer('online').notNullable().defaultTo(0);
    t.integer('offline').notNullable().defaultTo(0);
    t.integer('warning').notNullable().defaultTo(0);
    t.integer('critical').notNullable().defaultTo(0);
    t.integer('pending_updates').notNullable().defaultTo(0);
    t.integer('stale_72h').notNullable().defaultTo(0);
    t.integer('active_remote_sessions').notNullable().defaultTo(0);
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    t.unique(['tenant_id', 'hour']);
    t.index(['tenant_id', 'hour']);
  });

  // ===========================================================================
  // PHONE KEYS (device-bound second factor): keys and single-use challenges
  // ===========================================================================
  await knex.schema.createTable('user_device_keys', (t) => {
    t.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));   // = keyId
    t.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.string('platform', 16).notNullable().defaultTo('android');
    t.binary('public_key_spki').notNullable();
    t.string('public_key_fp', 64).notNullable().unique();              // sha256 hex of the SPKI DER
    t.string('origin', 255).notNullable();
    t.string('install_id', 64).notNullable();
    t.string('label', 120);
    t.string('app_version', 32);
    t.string('security_level', 16).notNullable();                      // strongbox | tee | unverified
    t.jsonb('attestation');
    t.integer('credential_version').notNullable();                     // users.credential_version at enrolment
    t.integer('sso_epoch');                                            // NULL for a local account
    t.string('status', 16).notNullable().defaultTo('active');          // active | revoked
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('last_used_at', { useTz: true });
    t.string('last_used_ip', 64);
    t.integer('use_count').notNullable().defaultTo(0);
    t.timestamp('revoked_at', { useTz: true });
    t.integer('revoked_by').references('id').inTable('users').onDelete('SET NULL');
    t.string('revoke_reason', 40);
    t.index(['user_id', 'status']);
  });

  await knex.schema.createTable('device_key_challenges', (t) => {
    t.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    t.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.uuid('key_id').references('id').inTable('user_device_keys').onDelete('CASCADE');   // NULL for an enrolment ticket
    t.string('purpose', 16).notNullable();                             // stepup | login | enrol
    t.string('session_hash', 64).notNullable();
    t.integer('tenant_id');
    t.uuid('bulk_id');
    t.binary('nonce').notNullable();
    t.string('action_key', 120);
    t.string('binding_hash', 64);
    t.specificType('device_ids', 'integer[]');
    t.string('ip', 64);
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('expires_at', { useTz: true }).notNullable();
    t.timestamp('consumed_at', { useTz: true });
    t.string('result', 24);
    t.integer('credential_version');
    t.integer('sso_epoch');
    t.index(['user_id', 'created_at']);
    t.index(['key_id', 'consumed_at']);
    t.index(['expires_at']);
  });
}

export async function down(knex: Knex): Promise<void> {
  // Dependents first. Drops the whole schema: the seed goes with it.
  const tables = [
    'device_key_challenges',
    'user_device_keys',
    'fleet_hourly_snapshot',
    'fleet_daily_snapshot',
    'step_up_throttle',
    'tfa_trusted_sessions',
    'pending_approvals',
    'software_repo_packages',
    'permission_sets',
    'device_licenses',
    'audit_logs',
    'sso_foreign_users',
    'report_outputs',
    'reports',
    'device_inventory_software',
    'device_inventory_hardware',
    'devices',
    'agent_api_keys',
    'maintenance_window_disables',
    'maintenance_windows',
    'live_alerts',
    'notification_log',
    'notification_bindings',
    'notification_channel_tenants',
    'notification_channels',
    'smtp_servers',
    'settings',
    'team_permissions',
    'team_memberships',
    'user_teams',
    'device_group_closure',
    'device_groups',
    'app_config',
    'password_reset_tokens',
    'user_tenants',
    'tenants',
    'users',
    'session',
  ];
  for (const table of tables) {
    await knex.schema.dropTableIfExists(table);
  }
  await knex.raw('DROP FUNCTION IF EXISTS users_bump_credential_version()');
}
