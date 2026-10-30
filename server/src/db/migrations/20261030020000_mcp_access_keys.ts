import type { Knex } from 'knex';

// =============================================================================
// MCP server v1: personal access keys of AI agents (docs: specs mcp-server §2)
// =============================================================================
//   - access_keys            identity_self: a key of a user (sha256 of the token only), bound to the user's
//                            credential_version at creation; scopes, perimeters and IPs never change after the
//                            creation (column grants), a key is never deleted by the application, never un-revoked
//                            (trigger access_keys_no_unrevoke).
//   - access_key_targets     identity_self: the tenants, groups and devices of a key, and the tenants a tenant manager
//                            excluded from it; insert only, and only in the creating transaction except an exclusion
//                            (trigger access_key_targets_no_widen); the composite foreign key ties a row to the key's
//                            own user.
//   - mcp_authorizations     custom: the sensitive actions an agent asked, approved by the key's human with a second
//                            factor, and the approvals filed through a key; tenant policy, plus the user's own rows in
//                            every tenant (read only).
//   - mcp_ip_blocks          identity: the local blocks of /mcp (an address, or an IPv6 /64).
//   - mcp_settings           identity: singleton of the instance's settings.
//   - mcp_tenant_policies    identity: the per-tenant override of "force an IP allow-list".
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, the trigger functions
// with SET search_path and EXECUTE revoked from PUBLIC, rls_assert_clean() last, a down that raises.
// Runs as obligarth_owner (server-migrate), after legacy_agent_pulled_packages.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- MCP server: personal access keys (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'obligarth_private' AND p.proname = 'rls_apply') THEN
    RAISE EXCEPTION 'mcp_access_keys: apply the rls foundation first';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'obligarth_private' AND p.proname = 'widen_in_check') THEN
    RAISE EXCEPTION 'mcp_access_keys: obligarth_private.widen_in_check is missing';
  END IF;
  IF to_regclass('obligarth.users') IS NULL OR to_regclass('obligarth.tenants') IS NULL THEN
    RAISE EXCEPTION 'mcp_access_keys: users and tenants are missing';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'obligarth.users'::regclass
                  AND attname = 'credential_version' AND NOT attisdropped) THEN
    RAISE EXCEPTION 'mcp_access_keys: users.credential_version is missing';
  END IF;
  IF to_regclass('obligarth.legacy_agent_packages') IS NULL THEN
    RAISE EXCEPTION 'mcp_access_keys: apply the legacy_agent migrations first';
  END IF;
END $$;

-- 1. Keys ---------------------------------------------------------------------------------------
CREATE TABLE obligarth.access_keys (
  id                 uuid          NOT NULL DEFAULT gen_random_uuid(),
  public_id          text          NOT NULL,
  kind               text          NOT NULL DEFAULT 'key',
  user_id            integer       NOT NULL,
  credential_version integer       NOT NULL,                  -- users.credential_version at the creation
  name               text          NOT NULL,
  secret_sha256      text          NOT NULL,
  scopes             text[]        NOT NULL DEFAULT '{}',
  tenant_mode        text          NOT NULL,
  group_mode         text          NOT NULL,
  device_mode        text          NOT NULL,
  ip_allow           cidr[]        NOT NULL DEFAULT '{}',
  created_at         timestamptz   NOT NULL DEFAULT now(),
  expires_at         timestamptz   NOT NULL,
  created_ip         inet,
  last_used_at       timestamptz,
  last_used_ip       inet,
  revoked_at         timestamptz,
  revoked_by         integer,                                   -- a user id; NULL: the system
  revoke_reason      text,
  CONSTRAINT access_keys_pkey PRIMARY KEY (id),
  CONSTRAINT access_keys_public_id_unique UNIQUE (public_id),
  CONSTRAINT access_keys_secret_unique UNIQUE (secret_sha256),
  CONSTRAINT access_keys_id_user_unique UNIQUE (id, user_id),
  CONSTRAINT access_keys_user_id_foreign FOREIGN KEY (user_id) REFERENCES obligarth.users (id) ON DELETE CASCADE,
  CONSTRAINT access_keys_public_id_check CHECK (public_id ~ '^[a-z0-9]{12}$'),
  CONSTRAINT access_keys_kind_check CHECK (kind IN ('key')),
  CONSTRAINT access_keys_name_check CHECK (char_length(btrim(name)) BETWEEN 1 AND 80),
  CONSTRAINT access_keys_secret_check CHECK (secret_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT access_keys_scopes_check CHECK (cardinality(scopes) <= 32 AND (cardinality(scopes) = 0
    OR array_to_string(scopes, ',') ~ '^[a-z]+[.][a-z]+(,[a-z]+[.][a-z]+)*$')),
  CONSTRAINT access_keys_tenant_mode_check CHECK (tenant_mode IN ('all', 'list')),
  CONSTRAINT access_keys_group_mode_check CHECK (group_mode IN ('all', 'list')),
  CONSTRAINT access_keys_device_mode_check CHECK (device_mode IN ('all', 'list')),
  CONSTRAINT access_keys_ip_allow_check CHECK (cardinality(ip_allow) <= 32),
  CONSTRAINT access_keys_expiry_check CHECK (expires_at > created_at AND expires_at <= created_at + interval '366 days'),
  CONSTRAINT access_keys_revoke_reason_check CHECK (revoke_reason IS NULL OR revoke_reason IN
    ('user', 'admin', 'user_disabled', 'credentials_changed', 'sessions_killed', 'owner_removed'))
);
CREATE INDEX access_keys_user_active ON obligarth.access_keys (user_id) WHERE revoked_at IS NULL;
SELECT obligarth_private.rls_apply('obligarth.access_keys', 'identity_self',
  'MCP personal access keys: sha256 only, the clear secret is shown once');
-- Scopes, perimeters, IPs and credential_version never change; a key is never deleted by the application (only the
-- users cascade, an owner-level foreign key action, removes rows).
REVOKE UPDATE, DELETE ON obligarth.access_keys FROM obligarth;
GRANT UPDATE (name, last_used_at, last_used_ip, revoked_at, revoked_by, revoke_reason) ON obligarth.access_keys TO obligarth;

CREATE FUNCTION obligarth_private.access_keys_no_unrevoke() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'access_keys: a revoked key stays revoked, with its reason';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.access_keys_no_unrevoke() FROM PUBLIC;
CREATE TRIGGER access_keys_no_unrevoke BEFORE UPDATE ON obligarth.access_keys
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.access_keys_no_unrevoke();

-- 2. Perimeters of a key ------------------------------------------------------------------------
CREATE TABLE obligarth.access_key_targets (
  key_id      uuid          NOT NULL,
  user_id     integer       NOT NULL,
  kind        text          NOT NULL,
  tenant_id   integer       NOT NULL,
  ref_id      integer,                                          -- NULL for 'tenant' and 'tenant_excluded'
  created_at  timestamptz   NOT NULL DEFAULT now(),
  created_by  integer,                                          -- 'tenant_excluded': the tenant manager
  CONSTRAINT access_key_targets_key_foreign FOREIGN KEY (key_id, user_id)
    REFERENCES obligarth.access_keys (id, user_id) ON DELETE CASCADE,
  CONSTRAINT access_key_targets_tenant_id_foreign FOREIGN KEY (tenant_id) REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT access_key_targets_kind_check CHECK (kind IN ('tenant', 'group', 'device', 'tenant_excluded')),
  CONSTRAINT access_key_targets_ref_check CHECK ((kind IN ('tenant', 'tenant_excluded')) = (ref_id IS NULL))
);
CREATE UNIQUE INDEX access_key_targets_unique ON obligarth.access_key_targets (key_id, kind, tenant_id, COALESCE(ref_id, 0));
SELECT obligarth_private.rls_apply('obligarth.access_key_targets', 'identity_self',
  'MCP access keys: tenants, groups and devices of a key, tenants excluded by a tenant manager');
REVOKE UPDATE, DELETE ON obligarth.access_key_targets FROM obligarth;

-- A perimeter is written with its key only: a later row may only narrow it (a tenant excluded).
CREATE FUNCTION obligarth_private.access_key_targets_no_widen() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.kind = 'tenant_excluded' THEN
    RETURN NEW;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM obligarth.access_keys k WHERE k.id = NEW.key_id AND k.created_at = now()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'access_key_targets: the perimeter of an existing key is never widened';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.access_key_targets_no_widen() FROM PUBLIC;
CREATE TRIGGER access_key_targets_no_widen BEFORE INSERT ON obligarth.access_key_targets
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.access_key_targets_no_widen();

-- 3. Authorizations -----------------------------------------------------------------------------
CREATE TABLE obligarth.mcp_authorizations (
  id            uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id     integer       NOT NULL,
  key_id        uuid          NOT NULL,
  user_id       integer       NOT NULL,
  tool          text          NOT NULL,
  action_key    text          NOT NULL,                       -- the restriction key that asked for the human
  level         text          NOT NULL,
  summary       text          NOT NULL,                       -- built by the server, never text of the agent
  args          jsonb         NOT NULL,                       -- the validated arguments (the agent's text lives here)
  device_ids    integer[]     NOT NULL DEFAULT '{}',
  state         text          NOT NULL DEFAULT 'pending',
  created_at    timestamptz   NOT NULL DEFAULT now(),
  expires_at    timestamptz   NOT NULL,
  decided_at    timestamptz,
  step_up_via   text,
  outcome       jsonb,
  impact_digest text,
  error_code    text,
  request_id    text,
  agent_ip      inet,
  CONSTRAINT mcp_authorizations_pkey PRIMARY KEY (id),
  CONSTRAINT mcp_authorizations_tenant_id_foreign FOREIGN KEY (tenant_id) REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  -- NO ACTION (checked at the end of the statement): a key with authorizations is never deleted by the application,
  -- while a users delete, which cascades both tables in one statement, still succeeds.
  CONSTRAINT mcp_authorizations_key_id_foreign FOREIGN KEY (key_id) REFERENCES obligarth.access_keys (id) ON DELETE NO ACTION,
  CONSTRAINT mcp_authorizations_user_id_foreign FOREIGN KEY (user_id) REFERENCES obligarth.users (id) ON DELETE CASCADE,
  CONSTRAINT mcp_authorizations_tool_check CHECK (tool ~ '^[a-z_]{1,64}$'),
  CONSTRAINT mcp_authorizations_action_key_check CHECK (char_length(action_key) BETWEEN 1 AND 100),
  CONSTRAINT mcp_authorizations_level_check CHECK (level IN ('sensitive', 'restricted', 'always_human')),
  CONSTRAINT mcp_authorizations_summary_check CHECK (char_length(summary) <= 500),
  CONSTRAINT mcp_authorizations_args_check CHECK (jsonb_typeof(args) = 'object' AND octet_length(args::text) <= 16384),
  CONSTRAINT mcp_authorizations_state_check CHECK (state IN
    ('pending', 'executing', 'executed', 'failed', 'denied', 'expired', 'cancelled', 'filed', 'interrupted')),
  CONSTRAINT mcp_authorizations_step_up_check CHECK (step_up_via IS NULL OR step_up_via IN ('totp', 'obligate_totp', 'device_key')),
  CONSTRAINT mcp_authorizations_impact_digest_check CHECK (char_length(impact_digest) <= 128),
  CONSTRAINT mcp_authorizations_error_code_check CHECK (char_length(error_code) <= 64),
  CONSTRAINT mcp_authorizations_request_id_check CHECK (request_id ~ '^[A-Za-z0-9._:-]{1,64}$')
);
CREATE INDEX mcp_authorizations_user_state ON obligarth.mcp_authorizations (user_id, state, created_at DESC);
CREATE INDEX mcp_authorizations_key_state ON obligarth.mcp_authorizations (key_id, state);
CREATE INDEX mcp_authorizations_pending_expiry ON obligarth.mcp_authorizations (expires_at) WHERE state = 'pending';
CREATE INDEX mcp_authorizations_executing ON obligarth.mcp_authorizations (state, decided_at) WHERE state = 'executing';
CREATE INDEX mcp_authorizations_filed_approval ON obligarth.mcp_authorizations (tenant_id, ((outcome ->> 'approvalId')))
  WHERE state = 'filed';
SELECT obligarth_private.rls_apply('obligarth.mcp_authorizations', 'custom',
  'MCP action authorizations: approved by the key''s human with a second factor; tenant policy plus self read');
CREATE POLICY rls_tenant ON obligarth.mcp_authorizations TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant())) WITH CHECK (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_reader ON obligarth.mcp_authorizations FOR SELECT TO obligarth_reader
  USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
-- A user reads his own authorizations in every tenant (the notification centre, the agent's status polling),
-- including a platform administrator's in tenants he is not a member of. Read only.
CREATE POLICY rls_self_read ON obligarth.mcp_authorizations FOR SELECT TO obligarth
  USING (user_id = (SELECT obligarth.ctx_actor_user()));
GRANT SELECT, INSERT ON obligarth.mcp_authorizations TO obligarth;
GRANT UPDATE (state, decided_at, step_up_via, outcome, error_code) ON obligarth.mcp_authorizations TO obligarth;
GRANT SELECT ON obligarth.mcp_authorizations TO obligarth_reader;

-- 4. Local blocks of /mcp (instance) ------------------------------------------------------------
CREATE TABLE obligarth.mcp_ip_blocks (
  id                bigserial     NOT NULL,
  ip                inet          NOT NULL,
  source            text          NOT NULL,
  reason            text          NOT NULL,
  first_seen_at     timestamptz   NOT NULL DEFAULT now(),
  last_seen_at      timestamptz   NOT NULL DEFAULT now(),
  hit_count         integer       NOT NULL DEFAULT 1,
  blocked_until     timestamptz,                               -- NULL: permanent (strict mode)
  active            boolean       NOT NULL DEFAULT true,
  unblocked_at      timestamptz,
  unblocked_by      integer,
  obliguard_status  text          NOT NULL DEFAULT 'pending',
  obliguard_sent_at timestamptz,
  obliguard_error   text,
  CONSTRAINT mcp_ip_blocks_pkey PRIMARY KEY (id),
  CONSTRAINT mcp_ip_blocks_source_check CHECK (source IN ('mcp_strict', 'mcp_failures', 'mcp_prefix', 'manual')),
  CONSTRAINT mcp_ip_blocks_ip_check CHECK (masklen(ip) = CASE WHEN family(ip) = 4 THEN 32 ELSE 128 END
    OR (family(ip) = 6 AND masklen(ip) = 64 AND source = 'mcp_prefix')),
  CONSTRAINT mcp_ip_blocks_reason_check CHECK (char_length(reason) <= 300),
  CONSTRAINT mcp_ip_blocks_hits_check CHECK (hit_count >= 1),
  CONSTRAINT mcp_ip_blocks_obliguard_status_check CHECK (obliguard_status IN
    ('pending', 'sent', 'failed', 'disabled', 'withdrawn', 'skipped')),
  CONSTRAINT mcp_ip_blocks_obliguard_error_check CHECK (char_length(obliguard_error) <= 500)
);
CREATE UNIQUE INDEX mcp_ip_blocks_active_ip ON obligarth.mcp_ip_blocks (ip) WHERE active;
CREATE INDEX mcp_ip_blocks_obliguard ON obligarth.mcp_ip_blocks (obliguard_status) WHERE obliguard_status IN ('pending', 'failed');
SELECT obligarth_private.rls_apply('obligarth.mcp_ip_blocks', 'identity', 'MCP server: local blocks of /mcp (instance)');

-- 5. Settings of the instance and per-tenant policy ---------------------------------------------
CREATE TABLE obligarth.mcp_settings (
  id                       smallint      NOT NULL DEFAULT 1,
  force_ip_allowlist       boolean       NOT NULL DEFAULT false,
  min_prefix_v4            integer       NOT NULL DEFAULT 16,
  min_prefix_v6            integer       NOT NULL DEFAULT 48,
  failure_threshold        integer       NOT NULL DEFAULT 10,
  failure_window_s         integer       NOT NULL DEFAULT 900,
  block_seconds            integer       NOT NULL DEFAULT 86400,
  known_ip_days            integer       NOT NULL DEFAULT 30,
  max_new_blocks_per_min   integer       NOT NULL DEFAULT 30,
  prefix_block_threshold   integer       NOT NULL DEFAULT 4,
  key_rpm                  integer       NOT NULL DEFAULT 600,
  authorization_minutes    integer       NOT NULL DEFAULT 10,
  max_pending_per_key      integer       NOT NULL DEFAULT 5,
  max_pending_per_user     integer       NOT NULL DEFAULT 20,
  max_created_per_key_hour integer       NOT NULL DEFAULT 10,
  obliguard_enabled        boolean       NOT NULL DEFAULT false,
  obliguard_url            text,
  never_block              cidr[]        NOT NULL DEFAULT '{}',
  updated_at               timestamptz   NOT NULL DEFAULT now(),
  updated_by               integer,
  CONSTRAINT mcp_settings_pkey PRIMARY KEY (id),
  CONSTRAINT mcp_settings_singleton CHECK (id = 1),
  CONSTRAINT mcp_settings_prefix_v4_check CHECK (min_prefix_v4 BETWEEN 8 AND 32),
  CONSTRAINT mcp_settings_prefix_v6_check CHECK (min_prefix_v6 BETWEEN 32 AND 128),
  CONSTRAINT mcp_settings_threshold_check CHECK (failure_threshold BETWEEN 3 AND 100),
  CONSTRAINT mcp_settings_window_check CHECK (failure_window_s BETWEEN 60 AND 86400),
  CONSTRAINT mcp_settings_block_check CHECK (block_seconds BETWEEN 300 AND 31536000),
  CONSTRAINT mcp_settings_known_ip_check CHECK (known_ip_days BETWEEN 0 AND 365),
  CONSTRAINT mcp_settings_new_blocks_check CHECK (max_new_blocks_per_min BETWEEN 5 AND 1000),
  CONSTRAINT mcp_settings_prefix_block_check CHECK (prefix_block_threshold BETWEEN 2 AND 64),
  CONSTRAINT mcp_settings_key_rpm_check CHECK (key_rpm BETWEEN 10 AND 6000),
  CONSTRAINT mcp_settings_authorization_check CHECK (authorization_minutes BETWEEN 2 AND 60),
  CONSTRAINT mcp_settings_pending_key_check CHECK (max_pending_per_key BETWEEN 1 AND 50),
  CONSTRAINT mcp_settings_pending_user_check CHECK (max_pending_per_user BETWEEN 1 AND 200),
  CONSTRAINT mcp_settings_created_check CHECK (max_created_per_key_hour BETWEEN 1 AND 500),
  CONSTRAINT mcp_settings_obliguard_url_check CHECK (obliguard_url ~ '^https{0,1}://[^@ ]+$'),
  CONSTRAINT mcp_settings_never_block_check CHECK (cardinality(never_block) <= 256)
);
INSERT INTO obligarth.mcp_settings (id) VALUES (1) ON CONFLICT DO NOTHING;
SELECT obligarth_private.rls_apply('obligarth.mcp_settings', 'identity', 'MCP server: settings of the instance (singleton)');

CREATE TABLE obligarth.mcp_tenant_policies (
  tenant_id          integer       NOT NULL,
  force_ip_allowlist text          NOT NULL,
  updated_at         timestamptz   NOT NULL DEFAULT now(),
  updated_by         integer,
  CONSTRAINT mcp_tenant_policies_pkey PRIMARY KEY (tenant_id),
  CONSTRAINT mcp_tenant_policies_tenant_id_foreign FOREIGN KEY (tenant_id) REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT mcp_tenant_policies_force_check CHECK (force_ip_allowlist IN ('inherit', 'force', 'exempt'))
);
SELECT obligarth_private.rls_apply('obligarth.mcp_tenant_policies', 'identity',
  'MCP server: per-tenant override of the IP allow-list obligation');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
