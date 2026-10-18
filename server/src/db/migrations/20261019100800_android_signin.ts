import type { Knex } from 'knex';

// =============================================================================
// Android, part 9: sign-in URL sessions and user exits of the lost mode (lot AN-F2; android-amapi §10.1, §10.5,
// §11.2, §22.3; SEC-AN-1)
// =============================================================================
//   - android_signin_sessions (class tenant): one sign-in of a device on the device surface (signinDetails of the
//     enterprise → https://mdm.<domain>/a/<MDM key>/signin?provisioningInfo=<id>): the provisioningInfo read for the
//     tenant's enterprise reduced to mode, ownership, API level and model (never the IMEI, the MEID, the serial number
//     nor the e-mail: the e-mail only goes to Obligate as a hint), its id kept hashed (SHA-256 of
//     'oap:<tenants.uuid>:<id>', one session per provisioning), the state of the authorization request kept hashed
//     ('oas:<tenants.uuid>:<state>'), the hash of the nonce of the browser cookie that binds the answer of Obligate to
//     the device that asked (login CSRF), the profile chosen by rule, the end user authenticated by Obligate, the
//     single-use token of 15 minutes created for him, the device enrolled with it; 15 minutes at most;
//   - android_lost_mode_exits (class tenant): the last time the user of a company device left the lost mode on the
//     device (USAGE_LOGS StopLostModeUserAttemptEvent ATTEMPT_SUCCEEDED): Google refuses START_LOST_MODE for 12 hours
//     after it (USER_EXIT_LOST_MODE_RECENTLY), the bus refuses it before any call;
//   - function android_signin_due() (context none of the maintenance): the tenants with sessions to expire or purge.
// New tables and functions only: nothing existing is altered. Runs as obligarth_owner (server-migrate); ends with
// obligarth.rls_assert_clean(). No question mark in the SQL (knex.raw would bind it).

const UP = String.raw`-- =============================================================================
-- Android, part 9: sign-in sessions, lost mode exits (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_enrollment_tokens') IS NULL OR to_regclass('obligarth.enrollment_profiles') IS NULL
     OR to_regclass('obligarth.end_users') IS NULL OR to_regclass('obligarth.android_enterprises') IS NULL THEN
    RAISE EXCEPTION 'android_signin: apply apple_enrollment, android_enterprises and android_devices first';
  END IF;
END $$;

-- ── android_signin_sessions ─────────────────────────────────────────────────────
CREATE TABLE obligarth.android_signin_sessions (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          integer NOT NULL DEFAULT obligarth.ctx_tenant()
                       REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enterprise_id      integer NOT NULL,
  profile_id         uuid NOT NULL,                    -- chosen by rule from the provisioning facts
  provisioning_hash  varchar(64) NOT NULL,             -- SHA-256 (hex) of 'oap:<tenants.uuid>:<provisioningInfo id>'
  state_hash         varchar(64) NOT NULL,             -- SHA-256 (hex) of 'oas:<tenants.uuid>:<state>'
  nonce_hash         varchar(64) NOT NULL,             -- SHA-256 (hex) of the browser cookie's nonce
  management_mode    varchar(24) NOT NULL,             -- provisioningInfo: DEVICE_OWNER | PROFILE_OWNER
  ownership          varchar(24) NOT NULL,             -- provisioningInfo: COMPANY_OWNED | PERSONALLY_OWNED
  api_level          integer,
  model              varchar(64),
  state              varchar(16) NOT NULL DEFAULT 'pending',
  locale             varchar(8) NOT NULL DEFAULT 'fr',
  notice_version_id  uuid,                             -- personal device: the notice acknowledged (USR-01)
  notice_ack_id      uuid,
  acknowledged_at    timestamptz,
  end_user_id        integer,
  authenticated_at   timestamptz,
  token_id           uuid,                             -- android_enrollment_tokens.id (kind signin)
  issued_at          timestamptz,
  device_id          integer,
  used_at            timestamptz,
  failure            varchar(32),
  expires_at         timestamptz NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT android_signin_sessions_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT android_signin_sessions_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
    REFERENCES obligarth.android_enterprises (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_signin_sessions_profile_fk FOREIGN KEY (tenant_id, profile_id)
    REFERENCES obligarth.enrollment_profiles (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_signin_sessions_end_user_fk FOREIGN KEY (tenant_id, end_user_id)
    REFERENCES obligarth.end_users (tenant_id, id) ON DELETE SET NULL (end_user_id),
  CONSTRAINT android_signin_sessions_token_fk FOREIGN KEY (tenant_id, token_id)
    REFERENCES obligarth.android_enrollment_tokens (tenant_id, id) ON DELETE SET NULL (token_id),
  CONSTRAINT android_signin_sessions_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (device_id),
  CONSTRAINT android_signin_sessions_state_check
    CHECK (state IN ('notice', 'pending', 'exchanging', 'authenticated', 'issued', 'used', 'failed', 'expired')),
  CONSTRAINT android_signin_sessions_hash_check
    CHECK (provisioning_hash ~ '^[0-9a-f]{64}$' AND state_hash ~ '^[0-9a-f]{64}$' AND nonce_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT android_signin_sessions_mode_check CHECK (management_mode IN ('DEVICE_OWNER', 'PROFILE_OWNER')),
  CONSTRAINT android_signin_sessions_ownership_check CHECK (ownership IN ('COMPANY_OWNED', 'PERSONALLY_OWNED')),
  CONSTRAINT android_signin_sessions_api_check CHECK (api_level IS NULL OR api_level BETWEEN 1 AND 1000),
  CONSTRAINT android_signin_sessions_locale_check CHECK (locale IN ('fr', 'en')),
  -- 15 minutes at most (§22.3), a few seconds of tolerance for the clocks of the transaction.
  CONSTRAINT android_signin_sessions_ttl_check CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes 5 seconds'),
  -- A personal device leaves the notice only with its acknowledgement (USR-01).
  CONSTRAINT android_signin_sessions_notice_check CHECK (ownership <> 'PERSONALLY_OWNED' OR state IN ('notice', 'failed', 'expired')
    OR (notice_version_id IS NOT NULL AND acknowledged_at IS NOT NULL)),
  CONSTRAINT android_signin_sessions_ack_whole CHECK ((notice_version_id IS NULL) = (acknowledged_at IS NULL)),
  -- Nothing reaches the device before an end user of the tenant is authenticated.
  CONSTRAINT android_signin_sessions_auth_check CHECK (state NOT IN ('authenticated', 'issued', 'used')
    OR (end_user_id IS NOT NULL AND authenticated_at IS NOT NULL)),
  CONSTRAINT android_signin_sessions_issued_check CHECK (state NOT IN ('issued', 'used') OR (token_id IS NOT NULL AND issued_at IS NOT NULL)),
  CONSTRAINT android_signin_sessions_used_check CHECK ((state = 'used') = (used_at IS NOT NULL)),
  CONSTRAINT android_signin_sessions_failure_check CHECK (failure IS NULL OR failure ~ '^[a-z_]{1,32}$')
);
CREATE UNIQUE INDEX android_signin_sessions_state ON obligarth.android_signin_sessions (state_hash);
CREATE UNIQUE INDEX android_signin_sessions_provisioning ON obligarth.android_signin_sessions (tenant_id, provisioning_hash);
CREATE UNIQUE INDEX android_signin_sessions_token ON obligarth.android_signin_sessions (token_id) WHERE token_id IS NOT NULL;
CREATE INDEX android_signin_sessions_open ON obligarth.android_signin_sessions (tenant_id, state, expires_at)
  WHERE state IN ('notice', 'pending', 'exchanging', 'authenticated', 'issued');
SELECT obligarth_private.rls_apply('obligarth.android_signin_sessions', 'tenant', 'android (lot AN-F2): sign-in URL sessions of the device surface');

-- ── android_lost_mode_exits ─────────────────────────────────────────────────────
CREATE TABLE obligarth.android_lost_mode_exits (
  tenant_id    integer NOT NULL DEFAULT obligarth.ctx_tenant()
                 REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id    integer NOT NULL,
  exited_at    timestamptz NOT NULL,
  CONSTRAINT android_lost_mode_exits_pkey PRIMARY KEY (tenant_id, device_id),
  CONSTRAINT android_lost_mode_exits_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
SELECT obligarth_private.rls_apply('obligarth.android_lost_mode_exits', 'tenant', 'android (lot AN-F2): user exits of the lost mode (12 h refusal)');

-- ── android_signin_due (maintenance: tenants with sign-in sessions to expire or to purge) ──
CREATE FUNCTION obligarth.android_signin_due() RETURNS TABLE (tenant_id integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.maintenance' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_signin_due: context none of the maintenance required';
  END IF;
  RETURN QUERY
  SELECT DISTINCT s.tenant_id FROM obligarth.android_signin_sessions s
   WHERE (s.state IN ('notice', 'pending', 'exchanging', 'authenticated') AND s.expires_at <= now())
      OR (s.state IN ('failed', 'expired') AND s.created_at < now() - interval '30 days')
   ORDER BY 1;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_signin_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_signin_due() TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.android_signin_due', 'definer', 'android maintenance: tenants with sign-in sessions to expire or purge')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
