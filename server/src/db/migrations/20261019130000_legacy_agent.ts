import type { Knex } from 'knex';

// =============================================================================
// Android bridge agent, channel 'legacy_agent' (docs: agent-pont-android §3, §15)
// =============================================================================
//   - widens the CHECK constraints of devices and device_apps and the function
//     ownership_allows (§3.1), after checking that their definitions are still
//     those main left them in (mdm_model_expand, then android_junction for the
//     enrollment types, the unenroll reasons and ownership_allows): merged after
//     the Android junction AN-A2, this migration writes the union of both lists
//     and fails if a later branch widened them again;
//   - legacy_agent_enrollment_tokens: enrollment tokens of a tenant, the SHA-256
//     of their secret only (never the value);
//   - legacy_agent_devices: 1-1 satellite of devices (key of the Keystore,
//     sequence, versions, state of the administrator and of Knox, identifiers);
//   - legacy_agent_commands: the queue of the agents, one row per device, the
//     columns, states, origins and actors of mdm_commands + mdm_command_targets
//     (joined to mdm_commands at the PONT-R stitching, like AN-D1);
//   - legacy_agent_packages: the client APKs of a tenant (stored by content);
//   - legacy_agent_releases: the versions of the agent, platform-wide (class
//     catalog: read by every context, written in the identity context);
//   - two SECURITY DEFINER lookups for the agent surface in the context 'none'
//     (actor i:legacy-agent only): the tenant of a token, the tenant of an agent.
// Rules of the specs README §3: SQL by String.raw, no question mark (chr(63)),
// rls_apply for each table, functions with SET search_path = pg_catalog,
// pg_temp and EXECUTE revoked from PUBLIC, rls_assert_clean() last, a down that
// raises. Runs as obligarth_owner (server-migrate), after outbox_definer_reads
// (renamed from 20261019120000 at the merge into main, PONT-R).
// =============================================================================

const ORIGINS = ['console', 'bulk', 'policy', 'ddm', 'inventory', 'enrollment', 'setup', 'system', 'approval', 'guard'];
const COMMAND_STATES = ['pending', 'sent', 'acknowledged', 'error', 'rejected', 'expired', 'cancelled'];
const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');
const sqlArray = (values: readonly string[]): string => `ARRAY[${[...values].sort().map((v) => `'${v}'`).join(', ')}]::text[]`;

// The literals of each constraint as main left them (mdm_model_expand, android_junction; sorted, deduplicated).
const EXPECTED: Record<string, { table: string; values: string[] }> = {
  devices_management_channel_check: { table: 'devices', values: ['amapi', 'apple_mdm'] },
  devices_channel_platform_check: { table: 'devices', values: ['amapi', 'android'] },
  devices_enrollment_type_check: {
    table: 'devices', values: ['account_device', 'ade', 'android_afw', 'android_byod_link', 'android_kme', 'android_nfc', 'android_qr',
      'android_signin_url', 'android_token', 'android_zero_touch', 'byod_account', 'configurator', 'migration', 'ota'],
  },
  devices_management_mode_check: {
    table: 'devices', values: ['dedicated', 'device', 'fully_managed', 'user_enrollment', 'work_profile_corporate', 'work_profile_personal'],
  },
  devices_unenroll_reason_check: {
    table: 'devices', values: ['apns_inactive', 'checkout', 'disabled_in_edge', 'missing_in_provider', 'presumed_gone', 'purged',
      'removed_by_command', 'retired', 'superseded', 'superseded_by_proof', 'transfer', 'wiped'],
  },
  device_apps_source_check: { table: 'device_apps', values: ['amapi_report', 'ddm_status', 'installed_list', 'managed_list'] },
};

const preconditions = Object.entries(EXPECTED).map(([name, e]) => String.raw`
  SELECT COALESCE(array_agg(DISTINCT m[1] ORDER BY m[1]), '{}'::text[]) INTO v_found
    FROM pg_constraint c CROSS JOIN LATERAL regexp_matches(pg_get_constraintdef(c.oid), '''([a-z_]+)''', 'g') AS m
   WHERE c.conrelid = 'obligarth.${e.table}'::regclass AND c.conname = '${name}';
  IF v_found IS DISTINCT FROM ${sqlArray(e.values)} THEN
    RAISE EXCEPTION 'legacy_agent: % differs from main (mdm_model_expand, android_junction) (%): merge the widenings of both branches', '${name}', v_found;
  END IF;`).join('\n');

const UP = String.raw`-- =============================================================================
-- Android bridge agent (legacy_agent): widenings, tables, lookups (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

-- 0. Preconditions ------------------------------------------------------------------
DO $$
DECLARE v_found text[];
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.mdm_commands') IS NULL OR to_regclass('obligarth.device_apps') IS NULL
     OR to_regclass('obligarth.android_devices') IS NULL THEN
    RAISE EXCEPTION 'legacy_agent: apply the RLS migrations, mdm_commands, mdm_model_expand and android_junction first';
  END IF;
${preconditions}
END $$;

-- 1. Widenings (§3.1) --------------------------------------------------------------------
-- Ownership locks the management mode: one more branch under 'corporate' (the bridge agent); the other branches are
-- those of android_junction, word for word. Mirror of shared/src/mdm/ownership.ts (ownershipAllows); both change together.
CREATE OR REPLACE FUNCTION obligarth.ownership_allows(p_ownership text, p_enrollment_type text, p_mode text)
  RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN (CASE p_ownership
    WHEN 'personal' THEN
         (p_mode = 'user_enrollment' AND p_enrollment_type = 'byod_account')
      OR (p_mode = 'work_profile_personal' AND p_enrollment_type IN ('android_byod_link', 'android_signin_url'))
    WHEN 'corporate_personal' THEN
         (p_mode = 'device' AND p_enrollment_type IN ('ade', 'configurator', 'migration'))
      OR (p_mode = 'work_profile_corporate' AND p_enrollment_type LIKE 'android\_%'
          AND p_enrollment_type NOT IN ('android_byod_link', 'android_nfc'))
    WHEN 'corporate' THEN
         (p_mode = 'device' AND p_enrollment_type IN ('ade', 'configurator', 'ota', 'account_device', 'migration'))
      OR (p_mode IN ('fully_managed', 'dedicated') AND p_enrollment_type LIKE 'android\_%'
          AND p_enrollment_type <> 'android_byod_link')
      OR (p_mode = 'device_admin' AND p_enrollment_type = 'agent_token')
    ELSE false
  END);
REVOKE ALL ON FUNCTION obligarth.ownership_allows(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.ownership_allows(text, text, text) TO obligarth, obligarth_reader;

ALTER TABLE obligarth.devices
  DROP CONSTRAINT devices_management_channel_check,
  ADD CONSTRAINT devices_management_channel_check CHECK (management_channel IN ('apple_mdm', 'amapi', 'legacy_agent')),
  DROP CONSTRAINT devices_channel_platform_check,
  ADD CONSTRAINT devices_channel_platform_check
      CHECK ((management_channel IN ('amapi', 'legacy_agent')) = (platform = 'android')),
  DROP CONSTRAINT devices_enrollment_type_check,
  ADD CONSTRAINT devices_enrollment_type_check CHECK (enrollment_type IN
      ('ade', 'ota', 'byod_account', 'configurator', 'account_device', 'migration',
       'android_qr', 'android_nfc', 'android_afw', 'android_token', 'android_zero_touch', 'android_kme',
       'android_byod_link', 'android_signin_url', 'agent_token')),
  DROP CONSTRAINT devices_management_mode_check,
  ADD CONSTRAINT devices_management_mode_check CHECK (management_mode IN ('device', 'user_enrollment', 'fully_managed',
      'dedicated', 'work_profile_corporate', 'work_profile_personal', 'device_admin')),
  DROP CONSTRAINT devices_unenroll_reason_check,
  ADD CONSTRAINT devices_unenroll_reason_check CHECK (unenroll_reason IN ('checkout', 'retired', 'transfer',
      'superseded_by_proof', 'superseded', 'apns_inactive', 'purged', 'disabled_in_edge', 'removed_by_command', 'wiped',
      'missing_in_provider', 'presumed_gone', 'agent_revoked'));

ALTER TABLE obligarth.device_apps
  DROP CONSTRAINT device_apps_source_check,
  ADD CONSTRAINT device_apps_source_check
      CHECK (source IN ('installed_list', 'managed_list', 'ddm_status', 'amapi_report', 'agent_report'));

-- 2. Enrollment tokens (§3.2) -----------------------------------------------------------
CREATE TABLE obligarth.legacy_agent_enrollment_tokens (
  id             uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id      integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  public_id      varchar(22)   NOT NULL,                     -- 16 random bytes, base64url
  secret_sha256  char(64)      NOT NULL,                     -- SHA-256 of the secret's UTF-8 text
  label          varchar(100)  NOT NULL,
  group_id       integer,                                    -- device_groups.id of the new devices (same tenant)
  max_uses       integer       NOT NULL,
  uses           integer       NOT NULL DEFAULT 0,
  expires_at     timestamptz   NOT NULL,
  revoked_at     timestamptz,
  revoked_by     integer,
  created_by     integer       NOT NULL,
  created_at     timestamptz   NOT NULL DEFAULT now(),
  last_used_at   timestamptz,
  CONSTRAINT legacy_agent_enrollment_tokens_pkey PRIMARY KEY (id),
  CONSTRAINT legacy_agent_enrollment_tokens_public_id_unique UNIQUE (public_id),
  CONSTRAINT legacy_agent_enrollment_tokens_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT legacy_agent_enrollment_tokens_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT legacy_agent_tokens_public_id CHECK (public_id ~ '^[A-Za-z0-9_-]{22}$'),
  CONSTRAINT legacy_agent_tokens_max_uses CHECK (max_uses BETWEEN 1 AND 2000),
  CONSTRAINT legacy_agent_tokens_uses CHECK (uses >= 0 AND uses <= max_uses),
  CONSTRAINT legacy_agent_tokens_ttl CHECK (expires_at <= created_at + interval '30 days'),
  CONSTRAINT legacy_agent_tokens_hash CHECK (secret_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT legacy_agent_tokens_revoked CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE INDEX legacy_agent_enrollment_tokens_tenant ON obligarth.legacy_agent_enrollment_tokens (tenant_id, created_at);
SELECT obligarth_private.rls_apply('obligarth.legacy_agent_enrollment_tokens', 'tenant');

-- 3. The satellite of an agent's device (§3.2) ------------------------------------------
CREATE TABLE obligarth.legacy_agent_devices (
  device_id           integer       NOT NULL,
  tenant_id           integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  agent_id            uuid          NOT NULL,
  public_key_spki     bytea         NOT NULL,                -- EC P-256 only (checked by the server)
  key_sha256          char(64)      NOT NULL,                -- SHA-256 of the SPKI DER
  key_storage         varchar(16)   NOT NULL,
  attestation         jsonb,                                 -- summary, optional (v1)
  token_id            uuid,                                  -- enrollment token used (never its value)
  last_seq            bigint        NOT NULL DEFAULT 0,
  agent_version_code  integer       NOT NULL,
  agent_version_name  varchar(32)   NOT NULL,
  admin_active        boolean       NOT NULL,
  knox_state          varchar(16)   NOT NULL,
  knox_info           jsonb,                                 -- { version, mdmApiLevel, error }
  api_level           integer,
  security_patch      date,
  android_id          varchar(32),
  claimed_serial      varchar(64),
  samsung_serial      varchar(64),
  imeis               text[]        NOT NULL DEFAULT '{}',
  hints               jsonb,                                 -- values declared by MobiControl macros (never trusted)
  identity_conflict   boolean       NOT NULL DEFAULT false,
  poll_seconds        integer,                               -- override; NULL = instance default
  last_poll_at        timestamptz,
  last_inventory_at   timestamptz,
  inventory_requested_at timestamptz,
  clock_offset_s      integer,                               -- server - device, last poll
  revoked_at          timestamptz,
  revoke_reason       varchar(32),
  enrolled_at         timestamptz   NOT NULL,
  created_at          timestamptz   NOT NULL DEFAULT now(),
  updated_at          timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT legacy_agent_devices_pkey PRIMARY KEY (device_id),
  CONSTRAINT legacy_agent_devices_agent_id_unique UNIQUE (agent_id),
  CONSTRAINT legacy_agent_devices_key_sha256_unique UNIQUE (key_sha256),
  CONSTRAINT legacy_agent_devices_tenant_id_device_id_unique UNIQUE (tenant_id, device_id),
  CONSTRAINT legacy_agent_devices_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT legacy_agent_devices_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT legacy_agent_devices_token_fk FOREIGN KEY (tenant_id, token_id)
    REFERENCES obligarth.legacy_agent_enrollment_tokens (tenant_id, id) ON DELETE SET NULL (token_id),
  CONSTRAINT legacy_agent_devices_key_storage_check CHECK (key_storage IN ('hardware', 'software', 'unknown')),
  CONSTRAINT legacy_agent_devices_knox_state_check CHECK (knox_state IN ('absent', 'present', 'licensed', 'license_error')),
  CONSTRAINT legacy_agent_devices_key_sha CHECK (key_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT legacy_agent_devices_last_seq CHECK (last_seq >= 0),
  CONSTRAINT legacy_agent_devices_poll_seconds CHECK (poll_seconds IS NULL OR poll_seconds BETWEEN 60 AND 3600),
  CONSTRAINT legacy_agent_devices_imeis CHECK (cardinality(imeis) <= 4),
  CONSTRAINT legacy_agent_devices_revoked CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX legacy_agent_devices_poll ON obligarth.legacy_agent_devices (tenant_id, last_poll_at) WHERE revoked_at IS NULL;
SELECT obligarth_private.rls_apply('obligarth.legacy_agent_devices', 'tenant');

-- 4. The queue of the agents (§3.2): one row per device -----------------------------------
CREATE TABLE obligarth.legacy_agent_commands (
  id                  uuid          NOT NULL,                -- command id seen by the agent
  tenant_id           integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  batch_id            uuid          NOT NULL,
  device_id           integer       NOT NULL,
  request_type        varchar(32)   NOT NULL,                -- catalogue §5.1
  params              jsonb         NOT NULL DEFAULT '{}',   -- never a secret
  origin              varchar(16)   NOT NULL,
  actor               varchar(70)   NOT NULL,                -- 'u:<id>' | 'j:<queue>' | 'i:<name>'
  requested_by        integer,
  reason              varchar(500),
  ticket              varchar(100),
  approval_id         integer,
  guard_action_uuid   uuid,
  idempotency_key     varchar(200),
  not_before          timestamptz,
  expires_at          timestamptz   NOT NULL,
  state               varchar(16)   NOT NULL DEFAULT 'pending',
  state_event_at      timestamptz   NOT NULL DEFAULT now(),
  hold_reason         varchar(24),                           -- frozen (display only)
  delivery_count      integer       NOT NULL DEFAULT 0,
  delivered_at        timestamptz,
  completed_at        timestamptz,
  cancel_requested_at timestamptz,
  result_code         varchar(48),
  result_detail       jsonb,                                 -- 4 KiB at most
  created_at          timestamptz   NOT NULL DEFAULT now(),
  updated_at          timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT legacy_agent_commands_pkey PRIMARY KEY (id),
  CONSTRAINT legacy_agent_commands_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT legacy_agent_commands_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT legacy_agent_commands_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT legacy_agent_commands_requested_by_foreign FOREIGN KEY (requested_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT legacy_agent_commands_origin_check CHECK (origin IN (${list(ORIGINS)})),
  CONSTRAINT legacy_agent_commands_state_check CHECK (state IN (${list(COMMAND_STATES)})),
  CONSTRAINT legacy_agent_commands_type_check CHECK (request_type ~ '^[a-z]+\.[a-z_]+$'),
  CONSTRAINT legacy_agent_commands_detail_size CHECK (result_detail IS NULL OR octet_length(result_detail::text) <= 4096),
  CONSTRAINT legacy_agent_commands_params_size CHECK (octet_length(params::text) <= 4096)
);
CREATE UNIQUE INDEX legacy_agent_commands_idem ON obligarth.legacy_agent_commands (tenant_id, device_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE INDEX legacy_agent_commands_open ON obligarth.legacy_agent_commands (tenant_id, device_id, state)
  WHERE state IN ('pending', 'sent');
CREATE INDEX legacy_agent_commands_created ON obligarth.legacy_agent_commands (tenant_id, created_at);
CREATE INDEX legacy_agent_commands_guard ON obligarth.legacy_agent_commands (tenant_id, guard_action_uuid)
  WHERE guard_action_uuid IS NOT NULL;
CREATE INDEX legacy_agent_commands_expiry ON obligarth.legacy_agent_commands (expires_at)
  WHERE state IN ('pending', 'sent');
SELECT obligarth_private.rls_apply('obligarth.legacy_agent_commands', 'tenant');

-- A state never goes back (rank of mdm_target_state_rank: pending 0 < sent 2 < expired, cancelled, rejected 3 <
-- acknowledged, error 4); a final state of the same rank is never replaced by another.
CREATE FUNCTION obligarth.legacy_agent_commands_guard_state() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.state IS DISTINCT FROM OLD.state
     AND (obligarth.mdm_target_state_rank(NEW.state) < obligarth.mdm_target_state_rank(OLD.state)
          OR (obligarth.mdm_target_state_rank(NEW.state) = obligarth.mdm_target_state_rank(OLD.state)
              AND obligarth.mdm_target_state_rank(OLD.state) >= 3)) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'legacy_agent_commands_state_rank',
      MESSAGE = 'legacy_agent_commands: a state never goes back';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth.legacy_agent_commands_guard_state() FROM PUBLIC;
CREATE TRIGGER legacy_agent_commands_guard_state BEFORE UPDATE OF state ON obligarth.legacy_agent_commands
  FOR EACH ROW EXECUTE FUNCTION obligarth.legacy_agent_commands_guard_state();

-- 5. Client APKs of a tenant (§3.2, PB12) -------------------------------------------------
CREATE TABLE obligarth.legacy_agent_packages (
  id             uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id      integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  package_name   varchar(255)  NOT NULL,
  version_code   bigint        NOT NULL,
  version_name   varchar(64),
  sha256         char(64)      NOT NULL,
  size_bytes     bigint        NOT NULL,
  signer_sha256  char(64),                                   -- declared; checked by the agent when present
  label          varchar(100),
  created_by     integer       NOT NULL,
  created_at     timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT legacy_agent_packages_pkey PRIMARY KEY (id),
  CONSTRAINT legacy_agent_packages_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT legacy_agent_packages_tenant_id_sha256_unique UNIQUE (tenant_id, sha256),
  CONSTRAINT legacy_agent_packages_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT legacy_agent_packages_size CHECK (size_bytes BETWEEN 1 AND 104857600),
  CONSTRAINT legacy_agent_packages_sha CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT legacy_agent_packages_signer CHECK (signer_sha256 IS NULL OR signer_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT legacy_agent_packages_name CHECK (package_name ~ '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$'),
  CONSTRAINT legacy_agent_packages_version CHECK (version_code >= 1)
);
SELECT obligarth_private.rls_apply('obligarth.legacy_agent_packages', 'tenant');

-- 6. Versions of the agent, platform-wide (§3.2) -----------------------------------------
CREATE TABLE obligarth.legacy_agent_releases (
  id             uuid          NOT NULL DEFAULT gen_random_uuid(),
  version_code   integer       NOT NULL,
  version_name   varchar(32)   NOT NULL,
  sha256         char(64)      NOT NULL,
  size_bytes     bigint        NOT NULL,
  signer_sha256  char(64)      NOT NULL,                     -- must be in LEGACY_AGENT_SIGNERS (checked by the server)
  notes          varchar(500),
  created_by     integer       NOT NULL,
  created_at     timestamptz   NOT NULL DEFAULT now(),
  withdrawn_at   timestamptz,
  CONSTRAINT legacy_agent_releases_pkey PRIMARY KEY (id),
  CONSTRAINT legacy_agent_releases_version_code_unique UNIQUE (version_code),
  CONSTRAINT legacy_agent_releases_sha256_unique UNIQUE (sha256),
  CONSTRAINT legacy_agent_releases_size CHECK (size_bytes BETWEEN 1 AND 104857600),
  CONSTRAINT legacy_agent_releases_sha CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT legacy_agent_releases_signer CHECK (signer_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT legacy_agent_releases_version CHECK (version_code >= 1)
);
SELECT obligarth_private.rls_apply('obligarth.legacy_agent_releases', 'catalog');

-- 6 bis. Settings of a tenant (§6): the Knox licence key, a reference {"$secret": "<id>"} to a tenant_secrets row
-- (sealed in the vault; the reference keeps the row out of the vault's garbage collection).
CREATE TABLE obligarth.legacy_agent_settings (
  tenant_id      integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  knox_license   jsonb,
  updated_by     integer,
  updated_at     timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT legacy_agent_settings_pkey PRIMARY KEY (tenant_id),
  CONSTRAINT legacy_agent_settings_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT legacy_agent_settings_knox_ref CHECK (knox_license IS NULL OR (jsonb_typeof(knox_license) = 'object'
    AND (knox_license->>'$secret') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'))
);
SELECT obligarth_private.rls_apply('obligarth.legacy_agent_settings', 'tenant');

-- 7. Lookups of the agent surface (§3.3), context 'none', actor i:legacy-agent only ------
CREATE FUNCTION obligarth.legacy_agent_token_lookup(p_public_id text)
  RETURNS TABLE (tenant_id integer, token_id uuid, secret_sha256 text, usable boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'i:legacy-agent' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'legacy_agent_token_lookup: the agent surface only';
  END IF;
  RETURN QUERY
    SELECT t.tenant_id, t.id, t.secret_sha256::text,
           (t.revoked_at IS NULL AND t.expires_at > now() AND t.uses < t.max_uses)
      FROM obligarth.legacy_agent_enrollment_tokens t
     WHERE t.public_id = p_public_id;
END $$;
REVOKE ALL ON FUNCTION obligarth.legacy_agent_token_lookup(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.legacy_agent_token_lookup(text) TO obligarth;

CREATE FUNCTION obligarth.legacy_agent_lookup(p_agent_id uuid)
  RETURNS TABLE (tenant_id integer, device_id integer, public_key_spki bytea, last_seq bigint, revoked boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'i:legacy-agent' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'legacy_agent_lookup: the agent surface only';
  END IF;
  RETURN QUERY
    SELECT a.tenant_id, a.device_id, a.public_key_spki, a.last_seq, (a.revoked_at IS NOT NULL)
      FROM obligarth.legacy_agent_devices a
     WHERE a.agent_id = p_agent_id;
END $$;
REVOKE ALL ON FUNCTION obligarth.legacy_agent_lookup(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.legacy_agent_lookup(uuid) TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.legacy_agent_token_lookup', 'definer', 'agent surface: tenant of an enrollment token (context none, i:legacy-agent)'),
  ('function', 'obligarth.legacy_agent_lookup', 'definer', 'agent surface: tenant and key of an agent (context none, i:legacy-agent)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('legacy_agent cannot be rolled back: restore the backup taken before the upgrade');
}
