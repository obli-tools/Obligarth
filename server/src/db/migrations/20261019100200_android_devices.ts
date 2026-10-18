import type { Knex } from 'knex';

// =============================================================================
// Android, part 3a: devices, enrollment tokens, quarantine, enrollment policies (fully managed enrollment)
// =============================================================================
//   - android_devices (class tenant): the 1-1 satellite of devices for the channel 'amapi' (the AMAPI name, the
//     ownership and the mode Google reports, the token that enrolled it, the approval of a long token, the state
//     of the device's own policy and the minimised inventory: never a hardware nor a network identifier for a
//     personal device);
//   - android_enrollment_tokens (class tenant): the AMAPI tokens the instance created, the profile frozen at the
//     creation (profile_snapshot), the sealed value by reference only (value_ref, tenant_secrets);
//   - android_quarantine (class tenant): the devices enrolled at Google that the instance did not accept (unknown
//     token, contradicted ownership or mode, API level too low): no row in devices; the operator decides;
//   - android_enrollment_policies (class tenant): the enrollment policy 'e-<profile uuid>' of an Android profile
//     (pushed version, compiled hash): a satellite rather than a column of enrollment_profiles;
//   - functions: android_project_device_count() (devices of the project, all tenants, a number only),
//     android_enrollment_due() (tenants with tokens to expire or to recover, for android.maintenance).
// New tables and functions only. The widening of the existing CHECKs (devices_enrollment_type_check,
// enrollment_profiles_*, ownership_allows, unenroll reasons; mdm_artifacts and device_artifacts for the channel
// 'amapi') is part 3b and part 5, written on the final CHECKs of lot C at the junction (AN-A2/AN-C1). Runs as
// obligarth_owner (server-migrate); ends with obligarth.rls_assert_clean(). No question mark in the SQL.

const UP = String.raw`-- =============================================================================
-- Android, part 3a: devices, enrollment tokens, quarantine, enrollment policies (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_inbox') IS NULL OR to_regclass('obligarth.enrollment_profiles') IS NULL THEN
    RAISE EXCEPTION 'android_devices: apply android_inbox and apple_enrollment first';
  END IF;
END $$;

-- ── android_enrollment_tokens ──────────────────────────────────────────────────
CREATE TABLE obligarth.android_enrollment_tokens (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),   -- carried as additionalData 'obg1:<id>'
  tenant_id           integer NOT NULL DEFAULT obligarth.ctx_tenant()
                        REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enterprise_id       integer NOT NULL,
  profile_id          uuid NOT NULL,
  profile_snapshot    jsonb NOT NULL,                 -- frozen at creation: ownership, mode, usage, group, minimumApiLevel
  requires_approval   boolean NOT NULL DEFAULT false, -- long tokens: new devices held DISABLED until approved (AN17)
  approval_forced_at  timestamptz,                    -- the hourly cap of the token forced the approval
  end_user_id         integer,
  kind                varchar(16) NOT NULL,           -- qr | byod_link | zero_touch | kme | signin
  token_name          varchar(255),                   -- enterprises/{e}/enrollmentTokens/{t}
  value_ref           uuid,                           -- tenant_secrets id (purpose android.enrollment_token)
  one_time            boolean NOT NULL,
  expires_at          timestamptz NOT NULL,
  state               varchar(12) NOT NULL DEFAULT 'creating',
  uses                integer NOT NULL DEFAULT 0,
  max_uses            integer,                        -- NULL: unlimited (long tokens)
  last_used_at        timestamptz,
  revoked_at          timestamptz,
  revoked_by          integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  created_by          integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  ended_at            timestamptz,                    -- left the state active (used, expired, revoked, failed)
  CONSTRAINT android_enrollment_tokens_kind_check CHECK (kind IN ('qr', 'byod_link', 'zero_touch', 'kme', 'signin')),
  CONSTRAINT android_enrollment_tokens_state_check
    CHECK (state IN ('creating', 'active', 'used', 'expired', 'revoked', 'failed')),
  CONSTRAINT android_enrollment_tokens_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT android_enrollment_tokens_profile_fk FOREIGN KEY (tenant_id, profile_id)
    REFERENCES obligarth.enrollment_profiles (tenant_id, id) ON DELETE RESTRICT,
  CONSTRAINT android_enrollment_tokens_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
    REFERENCES obligarth.android_enterprises (tenant_id, id),
  CONSTRAINT android_enrollment_tokens_user_fk FOREIGN KEY (tenant_id, end_user_id)
    REFERENCES obligarth.end_users (tenant_id, id) ON DELETE SET NULL (end_user_id),
  CONSTRAINT android_enrollment_tokens_one_time_rule CHECK (kind IN ('qr', 'byod_link', 'signin') OR NOT one_time),
  CONSTRAINT android_enrollment_tokens_signin_one_time CHECK (kind <> 'signin' OR one_time),
  CONSTRAINT android_enrollment_tokens_name_check
    CHECK (token_name IS NULL OR token_name ~ '^enterprises/[A-Za-z0-9_-]{1,100}/enrollmentTokens/[A-Za-z0-9_-]{1,100}$'),
  CONSTRAINT android_enrollment_tokens_active_named CHECK (state <> 'active' OR (token_name IS NOT NULL AND value_ref IS NOT NULL)),
  CONSTRAINT android_enrollment_tokens_value_only_active CHECK (value_ref IS NULL OR state = 'active'),
  CONSTRAINT android_enrollment_tokens_snapshot_object CHECK (jsonb_typeof(profile_snapshot) = 'object'),
  CONSTRAINT android_enrollment_tokens_uses_check CHECK (uses >= 0 AND (max_uses IS NULL OR max_uses >= 1))
);
CREATE INDEX android_enrollment_tokens_open ON obligarth.android_enrollment_tokens (tenant_id, state, expires_at)
  WHERE state IN ('creating', 'active');
CREATE UNIQUE INDEX android_enrollment_tokens_name ON obligarth.android_enrollment_tokens (token_name)
  WHERE token_name IS NOT NULL;
SELECT obligarth_private.rls_apply('obligarth.android_enrollment_tokens', 'tenant', 'android: enrollment tokens created by the instance');

-- ── android_devices ────────────────────────────────────────────────────────────
CREATE TABLE obligarth.android_devices (
  device_id              integer PRIMARY KEY,
  tenant_id              integer NOT NULL DEFAULT obligarth.ctx_tenant()
                           REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enterprise_id          integer NOT NULL,
  amapi_name             varchar(255) NOT NULL,          -- enterprises/{e}/devices/{d}
  amapi_management_mode  varchar(24) NOT NULL,           -- DEVICE_OWNER | PROFILE_OWNER
  amapi_ownership        varchar(24) NOT NULL,           -- COMPANY_OWNED | PERSONALLY_OWNED
  enrollment_token_id    uuid,                           -- android_enrollment_tokens.id (never the token value)
  approval_state         varchar(12) NOT NULL DEFAULT 'none',
  approved_at            timestamptz,
  approved_by            integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  policy_name            varchar(255),                   -- per-device policy the device points to (d-<uuid>)
  pushed_policy_version  bigint,                         -- Policy.version returned by the last patch
  pushed_rendered_hash   char(64),                       -- rendered_hash of that push (secrets excluded)
  pushed_at              timestamptz,
  policy_state           varchar(12) NOT NULL DEFAULT 'pending',
  policy_state_reasons   jsonb NOT NULL DEFAULT '[]',
  policy_push_failures   smallint NOT NULL DEFAULT 0,
  applied_policy_version bigint,                         -- Device.appliedPolicyVersion
  state                  varchar(32),                    -- Device.state
  applied_state          varchar(32),                    -- Device.appliedState
  security_posture       jsonb,                          -- { devicePosture, risks[] } only
  non_compliance         jsonb NOT NULL DEFAULT '[]',    -- normalised nonComplianceDetails (section 8.4)
  policy_compliant       boolean,
  api_level              integer,
  security_patch_level   date,
  last_status_report_at  timestamptz,
  last_policy_sync_at    timestamptz,
  previous_device_names  text[] NOT NULL DEFAULT '{}',
  hardware_info          jsonb,                          -- filtered by the privacy rules (section 8.2)
  software_info          jsonb,
  network_info           jsonb,
  enrolled_at            timestamptz NOT NULL,
  released_at            timestamptz,
  release_reason         varchar(24),
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT android_devices_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_devices_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
      REFERENCES obligarth.android_enterprises (tenant_id, id),
  CONSTRAINT android_devices_token_fk FOREIGN KEY (tenant_id, enrollment_token_id)
      REFERENCES obligarth.android_enrollment_tokens (tenant_id, id) ON DELETE SET NULL (enrollment_token_id),
  CONSTRAINT android_devices_mode_check CHECK (amapi_management_mode IN ('DEVICE_OWNER', 'PROFILE_OWNER')),
  CONSTRAINT android_devices_ownership_check CHECK (amapi_ownership IN ('COMPANY_OWNED', 'PERSONALLY_OWNED')),
  CONSTRAINT android_devices_name_check CHECK (amapi_name ~ '^enterprises/[A-Za-z0-9_-]{1,100}/devices/[A-Za-z0-9_-]{1,100}$'),
  CONSTRAINT android_devices_approval_check CHECK (approval_state IN ('none', 'pending', 'approved', 'rejected')),
  CONSTRAINT android_devices_policy_state_check CHECK (policy_state IN ('pending', 'delivering', 'applied', 'error')),
  CONSTRAINT android_devices_policy_reasons_array CHECK (jsonb_typeof(policy_state_reasons) = 'array'),
  CONSTRAINT android_devices_non_compliance_array CHECK (jsonb_typeof(non_compliance) = 'array'),
  CONSTRAINT android_devices_policy_name_check
    CHECK (policy_name IS NULL OR policy_name ~ '^(d|e|c)-[0-9a-f-]{1,64}$' OR policy_name = 'default'),
  CONSTRAINT android_devices_released CHECK ((released_at IS NULL) = (release_reason IS NULL)),
  -- personal: no hardware nor network identifiers (REQ-01), even if the device sent them
  CONSTRAINT android_devices_personal_no_hw CHECK (amapi_ownership = 'COMPANY_OWNED' OR (hardware_info IS NULL AND network_info IS NULL))
);
CREATE UNIQUE INDEX android_devices_amapi_name_active ON obligarth.android_devices (amapi_name) WHERE released_at IS NULL;
CREATE INDEX android_devices_policy ON obligarth.android_devices (tenant_id, policy_name);
CREATE INDEX android_devices_token ON obligarth.android_devices (tenant_id, enrollment_token_id, enrolled_at)
  WHERE enrollment_token_id IS NOT NULL;
SELECT obligarth_private.rls_apply('obligarth.android_devices', 'tenant', 'android: satellite of devices for the channel amapi');

-- ── android_quarantine ─────────────────────────────────────────────────────────
CREATE TABLE obligarth.android_quarantine (
  id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id        integer NOT NULL DEFAULT obligarth.ctx_tenant()
                     REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enterprise_id    integer NOT NULL,
  amapi_name       varchar(255) NOT NULL,
  token_id         uuid,
  reason           varchar(32) NOT NULL,          -- unknown_token | ownership_mismatch | mode_mismatch | api_too_low
  decision         varchar(12) NOT NULL,          -- quarantine | reject
  state            varchar(12) NOT NULL DEFAULT 'open',
  enrollment_time  timestamptz,
  amapi_ownership  varchar(24),
  api_level        integer,
  created_at       timestamptz NOT NULL DEFAULT now(),
  resolved_at      timestamptz,
  resolved_by      integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT android_quarantine_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT android_quarantine_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
    REFERENCES obligarth.android_enterprises (tenant_id, id),
  CONSTRAINT android_quarantine_token_fk FOREIGN KEY (tenant_id, token_id)
    REFERENCES obligarth.android_enrollment_tokens (tenant_id, id) ON DELETE SET NULL (token_id),
  CONSTRAINT android_quarantine_name_check CHECK (amapi_name ~ '^enterprises/[A-Za-z0-9_-]{1,100}/devices/[A-Za-z0-9_-]{1,100}$'),
  CONSTRAINT android_quarantine_reason_check
    CHECK (reason IN ('unknown_token', 'ownership_mismatch', 'mode_mismatch', 'api_too_low')),
  CONSTRAINT android_quarantine_decision_check CHECK (decision IN ('quarantine', 'reject')),
  CONSTRAINT android_quarantine_state_check CHECK (state IN ('open', 'rejected', 'resolved')),
  CONSTRAINT android_quarantine_resolved CHECK ((state = 'open') = (resolved_at IS NULL))
);
CREATE UNIQUE INDEX android_quarantine_open ON obligarth.android_quarantine (tenant_id, amapi_name) WHERE state = 'open';
CREATE INDEX android_quarantine_hour ON obligarth.android_quarantine (tenant_id, created_at);
SELECT obligarth_private.rls_apply('obligarth.android_quarantine', 'tenant', 'android: devices enrolled at Google and not accepted');

-- ── android_enrollment_policies ────────────────────────────────────────────────
CREATE TABLE obligarth.android_enrollment_policies (
  tenant_id        integer NOT NULL DEFAULT obligarth.ctx_tenant()
                     REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  profile_id       uuid NOT NULL,
  enterprise_id    integer NOT NULL,
  policy_id        varchar(64) NOT NULL,          -- e-<profile uuid>
  compiled_hash    char(64),
  pushed_version   bigint,
  pushed_at        timestamptz,
  state            varchar(12) NOT NULL DEFAULT 'pending',
  last_error       varchar(64),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, profile_id),
  CONSTRAINT android_enrollment_policies_profile_fk FOREIGN KEY (tenant_id, profile_id)
    REFERENCES obligarth.enrollment_profiles (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_enrollment_policies_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
    REFERENCES obligarth.android_enterprises (tenant_id, id),
  CONSTRAINT android_enrollment_policies_policy_check CHECK (policy_id ~ '^e-[0-9a-f-]{36}$'),
  CONSTRAINT android_enrollment_policies_state_check CHECK (state IN ('pending', 'pushed', 'error')),
  CONSTRAINT android_enrollment_policies_pushed CHECK (state <> 'pushed' OR (pushed_version IS NOT NULL AND compiled_hash IS NOT NULL))
);
SELECT obligarth_private.rls_apply('obligarth.android_enrollment_policies', 'tenant', 'android: enrollment policies of the Android profiles');

-- Devices of the project not released, all tenants (AN49): a number, never another datum, never returned by a
-- route of a tenant. Contexts none, platform or tenant (the gateway checks the quota in the token route, RR-7).
CREATE FUNCTION obligarth.android_project_device_count() RETURNS integer
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS NULL OR obligarth.ctx_kind() NOT IN ('none', 'platform', 'tenant') THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_project_device_count: context none, platform or tenant required';
  END IF;
  RETURN (SELECT count(*)::integer FROM obligarth.android_devices d WHERE d.released_at IS NULL);
END $$;
REVOKE ALL ON FUNCTION obligarth.android_project_device_count() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_project_device_count() TO obligarth;

-- Tenants with enrollment tokens to expire (active past their end) or to recover (creating for 15 minutes and
-- more), for android.maintenance (context 'none'; tenant ids only).
CREATE FUNCTION obligarth.android_enrollment_due() RETURNS TABLE (tenant_id integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.maintenance' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_enrollment_due: context none of the maintenance required';
  END IF;
  RETURN QUERY
  SELECT DISTINCT t.tenant_id FROM obligarth.android_enrollment_tokens t
   WHERE (t.state = 'active' AND t.expires_at <= now())
      OR (t.state = 'creating' AND t.created_at < now() - interval '15 minutes')
   ORDER BY 1;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_enrollment_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_enrollment_due() TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.android_project_device_count', 'definer', 'android quota: devices of the project (a number)'),
  ('function', 'obligarth.android_enrollment_due', 'definer', 'android maintenance: tenants with tokens to expire or recover')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
