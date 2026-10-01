import type { Knex } from 'knex';

// Row level security, part 2 of 3 (docs: rls-tenant annex A.3): tenant_id on every tenant row (added to
// the six tables that lacked it, backfilled from the parent, NOT NULL, default from the database context),
// composite foreign keys (a foreign key check ignores the RLS: only (tenant_id, x_id) keeps a reference in
// its tenant), triggers of the polymorphic scope references and of the channel bindings, and the guard
// of the privileged columns of the accounts.
// audit_logs: its default and composite key only while the journal is not hardened (audit-durci annex A.3,
// review RLS-RC8): the delivery order of the two specifications stays free.
// Runs as obligarth_owner; the RLS is not enabled yet, the backfills see every row. No question mark,
// String.raw (see migration A).
const UP = String.raw`-- =============================================================================
-- Migration B: tenant_id on every tenant row, composite foreign keys, scope checks
-- (run as obligarth_owner; RLS not enabled yet, backfills see every row)
-- =============================================================================

-- B.1 Parents: (tenant_id, id) unique, target of the composite foreign keys
ALTER TABLE obligarth.device_groups         ADD CONSTRAINT device_groups_tenant_id_id_unique         UNIQUE (tenant_id, id);
ALTER TABLE obligarth.devices               ADD CONSTRAINT devices_tenant_id_id_unique               UNIQUE (tenant_id, id);
ALTER TABLE obligarth.user_teams            ADD CONSTRAINT user_teams_tenant_id_id_unique            UNIQUE (tenant_id, id);
ALTER TABLE obligarth.maintenance_windows   ADD CONSTRAINT maintenance_windows_tenant_id_id_unique   UNIQUE (tenant_id, id);
ALTER TABLE obligarth.agent_api_keys        ADD CONSTRAINT agent_api_keys_tenant_id_id_unique        UNIQUE (tenant_id, id);
ALTER TABLE obligarth.reports               ADD CONSTRAINT reports_tenant_id_id_unique               UNIQUE (tenant_id, id);
ALTER TABLE obligarth.notification_channels ADD CONSTRAINT notification_channels_tenant_id_id_unique UNIQUE (tenant_id, id);

-- B.2 Children without tenant_id: column, backfill from the parent, NOT NULL, default from the context
ALTER TABLE obligarth.device_group_closure ADD COLUMN tenant_id integer;
UPDATE obligarth.device_group_closure c SET tenant_id = g.tenant_id
  FROM obligarth.device_groups g WHERE g.id = c.descendant_id;
DELETE FROM obligarth.device_group_closure c USING obligarth.device_groups a
  WHERE a.id = c.ancestor_id AND a.tenant_id <> c.tenant_id;           -- cross-tenant closure rows (none expected)

ALTER TABLE obligarth.team_memberships ADD COLUMN tenant_id integer;
UPDATE obligarth.team_memberships m SET tenant_id = t.tenant_id
  FROM obligarth.user_teams t WHERE t.id = m.team_id;

ALTER TABLE obligarth.maintenance_window_disables ADD COLUMN tenant_id integer;
UPDATE obligarth.maintenance_window_disables d SET tenant_id = w.tenant_id
  FROM obligarth.maintenance_windows w WHERE w.id = d.window_id;

ALTER TABLE obligarth.device_inventory_hardware ADD COLUMN tenant_id integer;
UPDATE obligarth.device_inventory_hardware h SET tenant_id = d.tenant_id
  FROM obligarth.devices d WHERE d.id = h.device_id;

ALTER TABLE obligarth.device_inventory_software ADD COLUMN tenant_id integer;
UPDATE obligarth.device_inventory_software s SET tenant_id = d.tenant_id
  FROM obligarth.devices d WHERE d.id = s.device_id;

ALTER TABLE obligarth.notification_log ADD COLUMN tenant_id integer;
UPDATE obligarth.notification_log l SET tenant_id = c.tenant_id
  FROM obligarth.notification_channels c WHERE c.id = l.channel_id;
DELETE FROM obligarth.notification_log WHERE tenant_id IS NULL;      -- log rows without a channel: unattributable

ALTER TABLE obligarth.notification_channel_tenants ADD COLUMN owner_tenant_id integer;
UPDATE obligarth.notification_channel_tenants s SET owner_tenant_id = c.tenant_id
  FROM obligarth.notification_channels c WHERE c.id = s.channel_id;

ALTER TABLE obligarth.device_group_closure        ALTER COLUMN tenant_id SET NOT NULL, ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.team_memberships            ALTER COLUMN tenant_id SET NOT NULL, ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.maintenance_window_disables ALTER COLUMN tenant_id SET NOT NULL, ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.device_inventory_hardware   ALTER COLUMN tenant_id SET NOT NULL, ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.device_inventory_software   ALTER COLUMN tenant_id SET NOT NULL, ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.notification_log            ALTER COLUMN tenant_id SET NOT NULL, ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.notification_channel_tenants ALTER COLUMN owner_tenant_id SET NOT NULL,
  ALTER COLUMN owner_tenant_id SET DEFAULT obligarth.ctx_tenant(),
  ADD CONSTRAINT notification_channel_tenants_owner_master CHECK (owner_tenant_id = 1);

-- Every other tenant table: the context fills tenant_id when the code omits it
ALTER TABLE obligarth.device_groups          ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.user_teams             ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.team_permissions       ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.settings               ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.notification_channels  ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.notification_bindings  ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.live_alerts            ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.maintenance_windows    ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.agent_api_keys         ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.devices                ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.reports                ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.report_outputs         ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.device_licenses        ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.software_repo_packages ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.pending_approvals      ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.fleet_daily_snapshot   ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.fleet_hourly_snapshot  ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();

-- B.3 Composite foreign keys: a reference never crosses tenants (FK checks bypass RLS)
ALTER TABLE obligarth.device_groups
  DROP CONSTRAINT device_groups_parent_id_foreign,
  ADD CONSTRAINT device_groups_parent_id_tenant_fk FOREIGN KEY (tenant_id, parent_id)
      REFERENCES obligarth.device_groups (tenant_id, id) ON DELETE SET NULL (parent_id);
ALTER TABLE obligarth.device_group_closure
  DROP CONSTRAINT device_group_closure_ancestor_id_foreign,
  DROP CONSTRAINT device_group_closure_descendant_id_foreign,
  ADD CONSTRAINT device_group_closure_ancestor_id_tenant_fk FOREIGN KEY (tenant_id, ancestor_id)
      REFERENCES obligarth.device_groups (tenant_id, id) ON DELETE CASCADE,
  ADD CONSTRAINT device_group_closure_descendant_id_tenant_fk FOREIGN KEY (tenant_id, descendant_id)
      REFERENCES obligarth.device_groups (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE obligarth.team_memberships
  DROP CONSTRAINT team_memberships_team_id_foreign,
  ADD CONSTRAINT team_memberships_team_id_tenant_fk FOREIGN KEY (tenant_id, team_id)
      REFERENCES obligarth.user_teams (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE obligarth.team_permissions
  DROP CONSTRAINT team_permissions_team_id_foreign,
  ADD CONSTRAINT team_permissions_team_id_tenant_fk FOREIGN KEY (tenant_id, team_id)
      REFERENCES obligarth.user_teams (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE obligarth.maintenance_window_disables
  DROP CONSTRAINT maintenance_window_disables_window_id_foreign,
  ADD CONSTRAINT maintenance_window_disables_window_id_tenant_fk FOREIGN KEY (tenant_id, window_id)
      REFERENCES obligarth.maintenance_windows (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE obligarth.agent_api_keys
  DROP CONSTRAINT agent_api_keys_default_group_id_foreign,
  ADD CONSTRAINT agent_api_keys_default_group_id_tenant_fk FOREIGN KEY (tenant_id, default_group_id)
      REFERENCES obligarth.device_groups (tenant_id, id) ON DELETE SET NULL (default_group_id);
ALTER TABLE obligarth.devices
  DROP CONSTRAINT devices_group_id_foreign,
  DROP CONSTRAINT devices_api_key_id_foreign,
  ADD CONSTRAINT devices_group_id_tenant_fk FOREIGN KEY (tenant_id, group_id)
      REFERENCES obligarth.device_groups (tenant_id, id) ON DELETE SET NULL (group_id),
  ADD CONSTRAINT devices_api_key_id_tenant_fk FOREIGN KEY (tenant_id, api_key_id)
      REFERENCES obligarth.agent_api_keys (tenant_id, id) ON DELETE SET NULL (api_key_id);
ALTER TABLE obligarth.device_inventory_hardware
  DROP CONSTRAINT device_inventory_hardware_device_id_foreign,
  ADD CONSTRAINT device_inventory_hardware_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE obligarth.device_inventory_software
  DROP CONSTRAINT device_inventory_software_device_id_foreign,
  ADD CONSTRAINT device_inventory_software_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE obligarth.report_outputs
  DROP CONSTRAINT report_outputs_report_id_foreign,
  ADD CONSTRAINT report_outputs_report_id_tenant_fk FOREIGN KEY (tenant_id, report_id)
      REFERENCES obligarth.reports (tenant_id, id) ON DELETE CASCADE;
-- audit_logs: only while the journal is not hardened (PLT-12 removes its foreign keys)
DO $$
BEGIN
  IF to_regprocedure('obligarth.audit_append(text)') IS NULL THEN
    ALTER TABLE obligarth.audit_logs ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
    ALTER TABLE obligarth.audit_logs
      DROP CONSTRAINT audit_logs_device_id_foreign,
      ADD CONSTRAINT audit_logs_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
          REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (device_id);
  END IF;
END $$;
ALTER TABLE obligarth.device_licenses
  DROP CONSTRAINT device_licenses_device_id_foreign,
  ADD CONSTRAINT device_licenses_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE obligarth.notification_channel_tenants
  DROP CONSTRAINT notification_channel_tenants_channel_id_foreign,
  ADD CONSTRAINT notification_channel_tenants_channel_id_tenant_fk FOREIGN KEY (owner_tenant_id, channel_id)
      REFERENCES obligarth.notification_channels (tenant_id, id) ON DELETE CASCADE;

-- Indexes led by tenant_id on the children that had none
CREATE INDEX device_group_closure_tenant_descendant ON obligarth.device_group_closure (tenant_id, descendant_id);
CREATE INDEX team_memberships_tenant_user ON obligarth.team_memberships (tenant_id, user_id);
CREATE INDEX device_inventory_hardware_tenant_device ON obligarth.device_inventory_hardware (tenant_id, device_id, scanned_at);
CREATE INDEX device_inventory_software_tenant_device ON obligarth.device_inventory_software (tenant_id, device_id, name);
CREATE INDEX notification_log_tenant_created ON obligarth.notification_log (tenant_id, created_at);

-- B.4 Polymorphic scope references and channel bindings
CREATE TRIGGER team_permissions_scope_tenant BEFORE INSERT OR UPDATE OF scope, scope_id, tenant_id
  ON obligarth.team_permissions FOR EACH ROW EXECUTE FUNCTION obligarth.check_scope_reference('scope', 'scope_id');
CREATE TRIGGER settings_scope_tenant BEFORE INSERT OR UPDATE OF scope, scope_id, tenant_id
  ON obligarth.settings FOR EACH ROW EXECUTE FUNCTION obligarth.check_scope_reference('scope', 'scope_id');
CREATE TRIGGER notification_bindings_scope_tenant BEFORE INSERT OR UPDATE OF scope, scope_id, tenant_id
  ON obligarth.notification_bindings FOR EACH ROW EXECUTE FUNCTION obligarth.check_scope_reference('scope', 'scope_id');
CREATE TRIGGER maintenance_windows_scope_tenant BEFORE INSERT OR UPDATE OF scope_type, scope_id, tenant_id
  ON obligarth.maintenance_windows FOR EACH ROW EXECUTE FUNCTION obligarth.check_scope_reference('scope_type', 'scope_id');
CREATE TRIGGER maintenance_window_disables_scope_tenant BEFORE INSERT OR UPDATE OF scope_type, scope_id, tenant_id
  ON obligarth.maintenance_window_disables FOR EACH ROW EXECUTE FUNCTION obligarth.check_scope_reference('scope_type', 'scope_id');
CREATE TRIGGER reports_scope_tenant BEFORE INSERT OR UPDATE OF scope_type, scope_id, tenant_id
  ON obligarth.reports FOR EACH ROW EXECUTE FUNCTION obligarth.check_scope_reference('scope_type', 'scope_id');
CREATE TRIGGER notification_bindings_channel_tenant BEFORE INSERT OR UPDATE OF channel_id, tenant_id
  ON obligarth.notification_bindings FOR EACH ROW EXECUTE FUNCTION obligarth.check_channel_reference();
CREATE TRIGGER users_guard_privileged_columns BEFORE UPDATE
  ON obligarth.users FOR EACH ROW EXECUTE FUNCTION obligarth.users_guard_privileged_columns();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the migration');
}
