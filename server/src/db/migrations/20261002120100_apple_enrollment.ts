import type { Knex } from 'knex';

// =============================================================================
// Apple integration, part 4: enrollment profiles, tokens and sessions (docs: integration-apple-edge §4.5, §10;
// modele-donnees-mdm §13.1 step 4, §13.5)
// =============================================================================
//   - enrollment_profiles (class tenant_shared: the master's library is v1), ade_profile_bindings,
//     enrollment_tokens (links, QR codes and invitations, hashed), enrollment_sessions (= the session_ref
//     given to apple-edge);
//   - apple_ade_devices and apple_device_events, moved here from the integration's part 3, which the
//     data model's expansion (mdm_model_expand) replaces;
//   - the composite references left open by the expansion: devices.enrollment_profile_id,
//     apple_devices.enrollment_session_id, device_enrollments.enrollment_profile_id and
//     .enrollment_session_id (ON DELETE SET NULL of the column only), and those of the tokens and sessions
//     towards end_users.
// Same columns, types and names as the specification, written in SQL like the migrations of lot B1; three
// additions: enrollment_profiles_rules_check also refuses an OTA profile in corporate_personal (a COPE device
// is enrolled by ADE or Apple Configurator only: modele §4.3, barrier 1), the ownership of a session is
// checked against the profile's three values, and two indexes serve the lookups of the Authenticate rules (a session by its
// SCEP challenge, or by the fingerprint of its certificate: modele §4.5). Runs as obligarth_owner
// (server-migrate), after mdm_model_expand; ends with obligarth.rls_assert_clean(). No question mark in the
// SQL (knex.raw would bind it); kept verbatim by String.raw.

const METHODS = ['ota', 'ade', 'byod_account'];
const OWNERSHIPS = ['corporate', 'corporate_personal', 'personal'];
const TOKEN_KINDS = ['link', 'invitation'];
const SESSION_STATES = ['started', 'acknowledged', 'profile_issued', 'certificate_issued', 'authenticated',
  'enrolled', 'failed', 'expired'];

const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

const UP = String.raw`-- =============================================================================
-- Apple integration, part 4: enrollment profiles, tokens and sessions (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.tenant_apple_ade_tokens') IS NULL
     OR to_regclass('obligarth.end_users') IS NULL OR to_regclass('obligarth.device_enrollments') IS NULL THEN
    RAISE EXCEPTION 'apple_enrollment: apply the RLS migrations, apple_integrations and mdm_model_expand first';
  END IF;
END $$;

-- ── Enrollment profiles ─────────────────────────────────────────────────────────
CREATE TABLE obligarth.enrollment_profiles (
  id                  uuid          NOT NULL DEFAULT gen_random_uuid(),  -- part of the ADE URLs
  tenant_id           integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  target_tenant_ids   integer[],                           -- class tenant_shared (library: v1)
  name                varchar(200)  NOT NULL,
  platform            varchar(16)   NOT NULL DEFAULT 'apple',
  method              varchar(24)   NOT NULL,
  ownership           varchar(24)   NOT NULL,
  usage               varchar(32),                         -- ADE usage key (apple-edge §7.4)
  default_group_id    integer,
  privacy_profile_id  uuid,                                -- CNF-02: its specification adds the reference
  notice_required     boolean       NOT NULL DEFAULT true,
  locale              varchar(8)    NOT NULL DEFAULT 'fr',
  settings            jsonb         NOT NULL DEFAULT '{}', -- integration §10.1
  is_default          boolean       NOT NULL DEFAULT false, -- default ADE profile of the tenant
  enabled             boolean       NOT NULL DEFAULT true,
  version             integer       NOT NULL DEFAULT 1,
  created_by          integer,
  updated_by          integer,
  created_at          timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  archived_at         timestamptz,                         -- never deleted: tokens and devices refer to it
  CONSTRAINT enrollment_profiles_pkey PRIMARY KEY (id),
  CONSTRAINT enrollment_profiles_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT enrollment_profiles_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT enrollment_profiles_created_by_foreign FOREIGN KEY (created_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT enrollment_profiles_updated_by_foreign FOREIGN KEY (updated_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT enrollment_profiles_platform_check CHECK (platform IN ('apple')),        -- 'android' in v1
  CONSTRAINT enrollment_profiles_method_check CHECK (method IN (${list(METHODS)})),
  CONSTRAINT enrollment_profiles_ownership_check CHECK (ownership IN (${list(OWNERSHIPS)})),
  CONSTRAINT enrollment_profiles_rules_check CHECK (
        (method <> 'byod_account' OR ownership = 'personal')            -- REQ-01: personal = account only
    AND (method = 'byod_account' OR ownership <> 'personal')
    AND NOT (method = 'ota' AND ownership = 'corporate_personal')        -- COPE: ADE or Configurator (modele §4.3)
    AND ((method = 'ade') = (usage IS NOT NULL))
    AND (usage IS NULL OR usage ~ '^[a-z][a-z0-9_]{0,31}$')
    AND (notice_required OR method = 'ade')                              -- kiosks without user only
    AND (NOT is_default OR method = 'ade')
    AND (target_tenant_ids IS NULL OR tenant_id = 1)),
  CONSTRAINT enrollment_profiles_default_group_id_tenant_fk FOREIGN KEY (tenant_id, default_group_id)
    REFERENCES obligarth.device_groups (tenant_id, id) ON DELETE SET NULL (default_group_id)
);
CREATE UNIQUE INDEX enrollment_profiles_ade_usage ON obligarth.enrollment_profiles (tenant_id, usage)
  WHERE method = 'ade' AND archived_at IS NULL;
CREATE UNIQUE INDEX enrollment_profiles_ade_default ON obligarth.enrollment_profiles (tenant_id)
  WHERE method = 'ade' AND is_default AND archived_at IS NULL;
CREATE INDEX enrollment_profiles_target_tenants ON obligarth.enrollment_profiles USING gin (target_tenant_ids);
SELECT obligarth_private.rls_apply('obligarth.enrollment_profiles', 'tenant_shared');

-- ── Enrollment profile defined at Apple, per ADE server ─────────────────────────
CREATE TABLE obligarth.ade_profile_bindings (
  tenant_id        integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  profile_id       uuid          NOT NULL,
  ade_token_id     uuid          NOT NULL,
  profile_uuid     varchar(64),                            -- Apple's, returned by apple-edge
  defined_version  integer,                                -- enrollment_profiles.version defined at Apple
  defined_at       timestamptz,
  last_error_code  varchar(64),
  CONSTRAINT ade_profile_bindings_pkey PRIMARY KEY (tenant_id, profile_id, ade_token_id),
  CONSTRAINT ade_profile_bindings_profile_id_tenant_fk FOREIGN KEY (tenant_id, profile_id)
    REFERENCES obligarth.enrollment_profiles (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT ade_profile_bindings_ade_token_id_tenant_fk FOREIGN KEY (tenant_id, ade_token_id)
    REFERENCES obligarth.tenant_apple_ade_tokens (tenant_id, id) ON DELETE CASCADE
);
SELECT obligarth_private.rls_apply('obligarth.ade_profile_bindings', 'tenant');

-- ── Enrollment tokens: links, QR codes and invitations (hashed) ──────────────────
CREATE TABLE obligarth.enrollment_tokens (
  id                     uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id              integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  profile_id             uuid          NOT NULL,
  kind                   varchar(16)   NOT NULL,
  token_hash             varchar(64)   NOT NULL,           -- SHA-256 (hex) of the whole token
  prefix                 varchar(12)   NOT NULL,           -- displayable
  managed_apple_account  varchar(320),                     -- invitation: AssignedManagedAppleID
  end_user_id            integer,
  label                  varchar(200),
  expires_at             timestamptz   NOT NULL,
  max_uses               integer       NOT NULL,
  uses                   integer       NOT NULL DEFAULT 0,
  revoked_at             timestamptz,
  revoked_by             integer,
  created_by             integer,
  created_at             timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at           timestamptz,
  CONSTRAINT enrollment_tokens_pkey PRIMARY KEY (id),
  CONSTRAINT enrollment_tokens_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT enrollment_tokens_revoked_by_foreign FOREIGN KEY (revoked_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT enrollment_tokens_created_by_foreign FOREIGN KEY (created_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT enrollment_tokens_kind_check CHECK (kind IN (${list(TOKEN_KINDS)})),
  CONSTRAINT enrollment_tokens_rules_check CHECK (
        token_hash ~ '^[0-9a-f]{64}$'
    AND max_uses BETWEEN 1 AND 10000 AND uses BETWEEN 0 AND max_uses
    AND (kind <> 'invitation' OR (max_uses = 1 AND managed_apple_account IS NOT NULL))),
  CONSTRAINT enrollment_tokens_profile_id_tenant_fk FOREIGN KEY (tenant_id, profile_id)
    REFERENCES obligarth.enrollment_profiles (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT enrollment_tokens_end_user_id_tenant_fk FOREIGN KEY (tenant_id, end_user_id)
    REFERENCES obligarth.end_users (tenant_id, id) ON DELETE SET NULL (end_user_id)
);
CREATE UNIQUE INDEX enrollment_tokens_hash ON obligarth.enrollment_tokens (token_hash);
CREATE INDEX enrollment_tokens_profile ON obligarth.enrollment_tokens (tenant_id, profile_id);
SELECT obligarth_private.rls_apply('obligarth.enrollment_tokens', 'tenant');

-- ── Enrollment sessions (id = the session_ref given to apple-edge) ────────────────
CREATE TABLE obligarth.enrollment_sessions (
  id                       uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id                integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  profile_id               uuid          NOT NULL,
  token_id                 uuid,
  method                   varchar(24)   NOT NULL,
  ownership                varchar(24)   NOT NULL,
  state                    varchar(24)   NOT NULL,
  state_at                 timestamptz   NOT NULL,
  failure_code             varchar(48),
  challenge_id             uuid,                           -- apple_edge.scep_challenges.id
  machine_info_id          uuid,                           -- ADE: verified MachineInfo
  serial_number            varchar(64),                    -- ADE (from MachineInfo)
  managed_apple_account    varchar(320),                   -- BYOD
  end_user_id              integer,
  nonce_hash               varchar(64),                    -- single-use profile download (hashed)
  nonce_expires_at         timestamptz,
  access_token_hash        varchar(64),                    -- BYOD bearer (hashed), single use
  access_token_expires_at  timestamptz,
  notice_version_id        uuid,                           -- USR-01
  notice_ack_id            uuid,
  acknowledged_at          timestamptz,
  locale                   varchar(8),
  cert_sha256              varchar(64),
  device_id                integer,
  expires_at               timestamptz   NOT NULL,
  created_at               timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at               timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT enrollment_sessions_pkey PRIMARY KEY (id),
  CONSTRAINT enrollment_sessions_tenant_id_id_unique UNIQUE (tenant_id, id),  -- target of apple_devices.enrollment_session_id
  CONSTRAINT enrollment_sessions_state_check CHECK (state IN (${list(SESSION_STATES)})),
  CONSTRAINT enrollment_sessions_method_check CHECK (method IN (${list(METHODS)})),
  CONSTRAINT enrollment_sessions_ownership_check CHECK (ownership IN (${list(OWNERSHIPS)})),
  CONSTRAINT enrollment_sessions_profile_id_tenant_fk FOREIGN KEY (tenant_id, profile_id)
    REFERENCES obligarth.enrollment_profiles (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT enrollment_sessions_token_id_tenant_fk FOREIGN KEY (tenant_id, token_id)
    REFERENCES obligarth.enrollment_tokens (tenant_id, id) ON DELETE SET NULL (token_id),
  CONSTRAINT enrollment_sessions_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (device_id),
  CONSTRAINT enrollment_sessions_end_user_id_tenant_fk FOREIGN KEY (tenant_id, end_user_id)
    REFERENCES obligarth.end_users (tenant_id, id) ON DELETE SET NULL (end_user_id)
);
CREATE UNIQUE INDEX enrollment_sessions_nonce ON obligarth.enrollment_sessions (nonce_hash) WHERE nonce_hash IS NOT NULL;
CREATE UNIQUE INDEX enrollment_sessions_access ON obligarth.enrollment_sessions (access_token_hash)
  WHERE access_token_hash IS NOT NULL;
CREATE INDEX enrollment_sessions_state ON obligarth.enrollment_sessions (tenant_id, state, created_at);
CREATE INDEX enrollment_sessions_serial ON obligarth.enrollment_sessions (tenant_id, serial_number)
  WHERE serial_number IS NOT NULL;
-- Lookups of the Authenticate rules (modele §4.5): by SCEP challenge, then by certificate fingerprint.
CREATE INDEX enrollment_sessions_challenge ON obligarth.enrollment_sessions (tenant_id, challenge_id)
  WHERE challenge_id IS NOT NULL;
CREATE INDEX enrollment_sessions_cert ON obligarth.enrollment_sessions (tenant_id, cert_sha256)
  WHERE cert_sha256 IS NOT NULL;
SELECT obligarth_private.rls_apply('obligarth.enrollment_sessions', 'tenant');

-- ── Devices seen by the ADE synchronisation (from the integration's part 3) ──────
CREATE TABLE obligarth.apple_ade_devices (
  id                      bigserial     NOT NULL,
  tenant_id               integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  ade_token_id            uuid          NOT NULL,
  serial_number           varchar(64)   NOT NULL,
  model                   varchar(100),
  description             varchar(200),
  color                   varchar(50),
  device_family           varchar(32),
  os                      varchar(32),
  profile_status          varchar(16),
  profile_uuid            varchar(64),
  profile_assign_time     timestamptz,
  device_assigned_date    timestamptz,
  op_type                 varchar(16),
  op_date                 timestamptz,
  mdm_migration_deadline  timestamptz,
  hardware_ids            jsonb         NOT NULL DEFAULT '{}',  -- IMEI, MEID, EID, MAC (privacy rules)
  wanted_profile_id       uuid,                                 -- enrollment profile chosen by an operator
  device_id               integer,
  first_seen_at           timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at              timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  removed_at              timestamptz,                          -- op_type 'deleted'
  CONSTRAINT apple_ade_devices_pkey PRIMARY KEY (id),
  CONSTRAINT apple_ade_devices_tenant_id_serial_number_unique UNIQUE (tenant_id, serial_number),
  CONSTRAINT apple_ade_devices_ade_token_id_tenant_fk FOREIGN KEY (tenant_id, ade_token_id)
    REFERENCES obligarth.tenant_apple_ade_tokens (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT apple_ade_devices_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (device_id),
  CONSTRAINT apple_ade_devices_wanted_profile_id_tenant_fk FOREIGN KEY (tenant_id, wanted_profile_id)
    REFERENCES obligarth.enrollment_profiles (tenant_id, id) ON DELETE SET NULL (wanted_profile_id)
);
SELECT obligarth_private.rls_apply('obligarth.apple_ade_devices', 'tenant');

-- ── Timeline of a device (PLT-15; from the integration's part 3) ──────────────────
CREATE TABLE obligarth.apple_device_events (
  id               bigserial     NOT NULL,
  tenant_id        integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id        integer       NOT NULL,
  kind             varchar(48)   NOT NULL,                     -- integration §7.4 (column « chronologie »)
  occurred_at      timestamptz   NOT NULL,
  source_event_id  uuid,                                       -- apple_edge.outbox event_id
  details          jsonb         NOT NULL DEFAULT '{}',        -- 2 KiB at most, never an identifier of the device
  CONSTRAINT apple_device_events_pkey PRIMARY KEY (id),
  CONSTRAINT apple_device_events_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX apple_device_events_timeline ON obligarth.apple_device_events (tenant_id, device_id, occurred_at);
CREATE UNIQUE INDEX apple_device_events_dedup ON obligarth.apple_device_events (source_event_id, kind)
  WHERE source_event_id IS NOT NULL;
SELECT obligarth_private.rls_apply('obligarth.apple_device_events', 'tenant');

-- ── References left open by the data model's expansion (modele §13.1, step 4) ─────
ALTER TABLE obligarth.devices
  ADD CONSTRAINT devices_enrollment_profile_id_tenant_fk FOREIGN KEY (tenant_id, enrollment_profile_id)
    REFERENCES obligarth.enrollment_profiles (tenant_id, id) ON DELETE SET NULL (enrollment_profile_id);
ALTER TABLE obligarth.apple_devices
  ADD CONSTRAINT apple_devices_enrollment_session_id_tenant_fk FOREIGN KEY (tenant_id, enrollment_session_id)
    REFERENCES obligarth.enrollment_sessions (tenant_id, id) ON DELETE SET NULL (enrollment_session_id);
ALTER TABLE obligarth.device_enrollments
  ADD CONSTRAINT device_enrollments_enrollment_profile_id_tenant_fk FOREIGN KEY (tenant_id, enrollment_profile_id)
    REFERENCES obligarth.enrollment_profiles (tenant_id, id) ON DELETE SET NULL (enrollment_profile_id),
  ADD CONSTRAINT device_enrollments_enrollment_session_id_tenant_fk FOREIGN KEY (tenant_id, enrollment_session_id)
    REFERENCES obligarth.enrollment_sessions (tenant_id, id) ON DELETE SET NULL (enrollment_session_id);

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
