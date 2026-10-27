import type { Knex } from 'knex';

// =============================================================================
// Dynamic groups (P0-5 T4, M2 of the spec; §4.2, D3, D7, D8, D9, D10)
// =============================================================================
//   - smart_groups (class tenant): a group of devices of a tenant defined by a rule of the rule language
//     (shared/src/mdm/rules.ts: a JSON object, 16 KiB of compact JSON at most, validated by the service before it is
//     written), with:
//       rule_fields   the families of marking of its rule (shared DIRTY_FAMILIES, ruleFamiliesOf), not its field keys:
//                     the reasons the marking gives a device (smart_group_dirty.reasons, P0-5 T5) are families, so a
//                     group is computed again for a device when rule_fields meets its reasons ('new' meets them all),
//                     and the statement trigger of device_apps runs only when a group holds 'apps'. The field keys
//                     (D2: may an assignment target the group?) are read from the rule;
//       rule_version  up by one at every change of the rule (a computation reads it FOR SHARE, a change of the rule
//                     holds the row FOR UPDATE: P0-5 §11);
//       rule_sha256   SHA-256 of the canonical JSON of the rule (shared ruleSha256: the fingerprint an approval keeps);
//       state         active, held (an automatic computation beyond the mass guard, D4: P0-5 T5) or error (a static
//                     group of the rule was deleted: the members are frozen, alert smart_group.rule_invalid);
//                     state_reason and state_since say why and since when (both NULL exactly when active);
//       pending_added, pending_removed (held), guard_window_start, guard_window_changes (the sliding hour of the mass
//                     guard): P0-5 T5;
//       member_count, computed_at: written with the members.
//     One name per tenant (lower), 200 groups per tenant (the service, under its advisory lock). The tenant, the uuid
//     and the creator never change: the runtime role updates the other columns only.
//   - smart_group_members (class tenant): the materialised members, (tenant, group, device), gone with the group or the
//     device (composite keys ON DELETE CASCADE). A device out of management is never a member (D9): the computations
//     leave it out (the service). Inserted and deleted, never updated.
//   - smart_group_dirty (class tenant): the devices whose membership is to be computed again, with the union of their
//     reasons (families, or 'new'); written by the marking triggers and read by the queue mdm.groups.evaluate, both
//     P0-5 T5: no trigger writes it yet (no marking is active in this migration).
//   - smart_group_membership_log (class tenant): every entry ('+') and exit ('-') of a device, with its cause ('rule':
//     a rule written; 'inventory': the incremental computation; 'release': a held group released), kept 90 days (D7:
//     the generic retention, rule smart_group_membership_log of mdm/inventory/retention.ts). Gone with the group or
//     the device; inserted and deleted, never updated.
//   - obligarth_private.scope_ref_kinds gains 'smart_group' → smart_groups (P0 coordination, S3 brick): a table guarded
//     by check_scope_reference that admits the scope smart_group (P0-12 reports) has its reference checked. Its CHECKs
//     are left as they are: a dynamic group gives no team scope (D8).
//   The target smart_group of the assignments (check_assignment_reference, assignments_cleanup, the CHECK of
//   target_scope and of device_effective_settings) is M3's (P0-5 T6, through obligarth_private.assignment_ref_kinds and
//   widen_in_check).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean() last.
// Runs as obligarth_owner (server-migrate), after p05_devices_tags_gin.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Dynamic groups (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.devices') IS NULL
     OR to_regclass('obligarth.users') IS NULL
     OR to_regclass('obligarth_private.scope_ref_kinds') IS NULL THEN
    RAISE EXCEPTION 'p05_smart_groups: apply the RLS migrations, mdm_model_expand and coordination_socle first';
  END IF;
END $$;

-- 1. smart_groups ------------------------------------------------------------------------
CREATE TABLE obligarth.smart_groups (
  id                    serial        PRIMARY KEY,
  uuid                  uuid          NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  tenant_id             integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  name                  varchar(200)  NOT NULL,
  description           varchar(1000),
  rule                  jsonb         NOT NULL,                -- RuleNode (shared/src/mdm/rules.ts)
  rule_fields           text[]        NOT NULL DEFAULT '{}',   -- families of marking of the rule (DIRTY_FAMILIES)
  rule_version          integer       NOT NULL DEFAULT 1,
  rule_sha256           char(64)      NOT NULL,
  state                 varchar(12)   NOT NULL DEFAULT 'active',
  state_reason          varchar(24),
  state_since           timestamptz,
  pending_added         integer       NOT NULL DEFAULT 0,
  pending_removed       integer       NOT NULL DEFAULT 0,
  guard_window_start    timestamptz,
  guard_window_changes  integer       NOT NULL DEFAULT 0,
  member_count          integer       NOT NULL DEFAULT 0,
  computed_at           timestamptz,
  created_by            integer       REFERENCES obligarth.users (id) ON DELETE SET NULL,
  updated_by            integer       REFERENCES obligarth.users (id) ON DELETE SET NULL,
  created_at            timestamptz   NOT NULL DEFAULT now(),
  updated_at            timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT smart_groups_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT smart_groups_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  -- A name of the console: not blank, no control character.
  CONSTRAINT smart_groups_name_check CHECK (btrim(name) <> '' AND name !~ '[\x01-\x1f\x7f]'),
  CONSTRAINT smart_groups_description_check CHECK (description IS NULL OR description !~ '[\x01-\x08\x0b-\x1f\x7f]'),
  -- 16 KiB of compact JSON at most (validateRule); the text of a jsonb adds a space after each comma and colon: a
  -- guard of twice that size, never reached by a rule the service accepted.
  CONSTRAINT smart_groups_rule_check CHECK (
        COALESCE(jsonb_typeof(rule) = 'object', false)
    AND octet_length(rule::text) <= 32768),
  CONSTRAINT smart_groups_rule_fields_check CHECK (
        rule_fields <@ ARRAY['facts', 'tags', 'custom', 'user', 'android', 'group', 'apps', 'derived', 'temporal']::text[]
    AND array_position(rule_fields, NULL) IS NULL),
  CONSTRAINT smart_groups_rule_version_check CHECK (rule_version >= 1),
  CONSTRAINT smart_groups_rule_sha256_check CHECK (rule_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT smart_groups_state_check CHECK (state IN ('active', 'held', 'error')),
  CONSTRAINT smart_groups_state_reason_check CHECK (state_reason IN ('mass_change', 'group_deleted', 'rule_invalid')),
  -- A reason and a date exactly when the group is not active.
  CONSTRAINT smart_groups_state_coherent CHECK (
    (state = 'active') = (state_reason IS NULL) AND (state_reason IS NULL) = (state_since IS NULL)),
  CONSTRAINT smart_groups_counts_check CHECK (
    pending_added >= 0 AND pending_removed >= 0 AND guard_window_changes >= 0 AND member_count >= 0)
);
-- One name per tenant.
CREATE UNIQUE INDEX smart_groups_name_uq ON obligarth.smart_groups (tenant_id, lower(name));
SELECT obligarth_private.rls_apply('obligarth.smart_groups', 'tenant',
  'dynamic groups (P0-5): a rule of the rule language over the inventory, members materialised');
-- The tenant, the uuid and the creator of a group never change.
REVOKE UPDATE ON obligarth.smart_groups FROM obligarth;
GRANT UPDATE (name, description, rule, rule_fields, rule_version, rule_sha256, state, state_reason, state_since,
  pending_added, pending_removed, guard_window_start, guard_window_changes, member_count, computed_at, updated_by,
  updated_at) ON obligarth.smart_groups TO obligarth;

-- 2. smart_group_members -----------------------------------------------------------------
CREATE TABLE obligarth.smart_group_members (
  tenant_id       integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  smart_group_id  integer      NOT NULL,
  device_id       integer      NOT NULL,
  added_at        timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT smart_group_members_pkey PRIMARY KEY (tenant_id, smart_group_id, device_id),
  CONSTRAINT smart_group_members_group_fk FOREIGN KEY (tenant_id, smart_group_id)
    REFERENCES obligarth.smart_groups (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT smart_group_members_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
-- The groups of a device (the resolution, P0-5 T6; the marking, T5).
CREATE INDEX smart_group_members_device ON obligarth.smart_group_members (tenant_id, device_id);
SELECT obligarth_private.rls_apply('obligarth.smart_group_members', 'tenant',
  'members of the dynamic groups (P0-5), never a device out of management');
REVOKE UPDATE ON obligarth.smart_group_members FROM obligarth;

-- 3. smart_group_dirty -------------------------------------------------------------------
CREATE TABLE obligarth.smart_group_dirty (
  tenant_id  integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id  integer      NOT NULL,
  reasons    text[]       NOT NULL,
  queued_at  timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT smart_group_dirty_pkey PRIMARY KEY (tenant_id, device_id),
  CONSTRAINT smart_group_dirty_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT smart_group_dirty_reasons_check CHECK (
        cardinality(reasons) >= 1
    AND reasons <@ ARRAY['new', 'facts', 'tags', 'custom', 'user', 'android', 'group', 'apps', 'derived', 'temporal']::text[]
    AND array_position(reasons, NULL) IS NULL)
);
SELECT obligarth_private.rls_apply('obligarth.smart_group_dirty', 'tenant',
  'devices whose membership of the dynamic groups is to be computed again (P0-5), with their reasons');
REVOKE UPDATE ON obligarth.smart_group_dirty FROM obligarth;
GRANT UPDATE (reasons, queued_at) ON obligarth.smart_group_dirty TO obligarth;

-- 4. smart_group_membership_log ----------------------------------------------------------
CREATE TABLE obligarth.smart_group_membership_log (
  id              bigserial    PRIMARY KEY,
  tenant_id       integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  smart_group_id  integer      NOT NULL,
  device_id       integer      NOT NULL,
  change          char(1)      NOT NULL,
  cause           varchar(12)  NOT NULL,
  at              timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT smart_group_membership_log_group_fk FOREIGN KEY (tenant_id, smart_group_id)
    REFERENCES obligarth.smart_groups (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT smart_group_membership_log_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT smart_group_membership_log_change_check CHECK (change IN ('+', '-')),
  CONSTRAINT smart_group_membership_log_cause_check CHECK (cause IN ('rule', 'inventory', 'release'))
);
-- The purge (D7, 90 days) and the history of a tenant; the history of a group and of a device.
CREATE INDEX smart_group_membership_log_at ON obligarth.smart_group_membership_log (tenant_id, at);
CREATE INDEX smart_group_membership_log_group ON obligarth.smart_group_membership_log (tenant_id, smart_group_id, at);
CREATE INDEX smart_group_membership_log_device ON obligarth.smart_group_membership_log (tenant_id, device_id, at);
SELECT obligarth_private.rls_apply('obligarth.smart_group_membership_log', 'tenant',
  'entries and exits of the devices of the dynamic groups (P0-5, D7: 90 days)');
REVOKE UPDATE ON obligarth.smart_group_membership_log FROM obligarth;

-- 5. Scope references: smart_group (S3 brick; regenerates obligarth.check_scope_reference) ------------------------
INSERT INTO obligarth_private.scope_ref_kinds (kind, ref_table, live_predicate, note) VALUES
  ('smart_group', 'smart_groups', NULL, 'P0-5 T4: dynamic groups');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
