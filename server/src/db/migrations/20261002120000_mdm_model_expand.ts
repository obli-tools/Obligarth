import type { Knex } from 'knex';

// =============================================================================
// MDM data model, expand step (version N) (docs: modele-donnees-mdm §9.1, DM1 to DM26)
// =============================================================================
// Device registry and its Apple satellite, enrollment episodes, end users,
// inventory, lost-mode locations, policies and versions, assignments, apps
// catalog, effective state. The legacy RMM columns of devices stay until the
// contract step (version N+1); no code of version N reads or writes them, and
// hostname becomes optional. The command queue is created earlier, by the
// mdm_commands migration of the apple-edge integration; this migration
// replaces the integration's part 3 (apple_devices), whose apple_ade_devices
// and apple_device_events move to its part 4 (apple_enrollment).
// Same tables, columns, constraints and names as the specification, with the
// rules of the catalog since migration D (rls_audit() 11b, 12c): the two
// immutable helpers have a SQL-standard body (bound at creation), every
// function has its EXECUTE revoked from PUBLIC (trigger functions included),
// and the search_path of this transaction is pg_catalog only (every name is
// schema-qualified). One check of the specification is tightened:
// apps_store_id_check refuses an App Store or custom app without store_id
// (a NULL passed the check); one data step is added: the recommended level of
// device.change_ownership ('restricted', section 10.7) on the tenants that
// exist already (the master tenant). Runs as obligarth_owner (server-migrate), after
// the RLS migrations and mdm_commands; ends with obligarth.rls_assert_clean().
// No question mark in the SQL (knex.raw would bind it); kept verbatim by
// String.raw.

const UP = String.raw`-- =============================================================================
-- Migration mdm_model_expand: MDM device registry (devices + apple_devices),
-- enrollment episodes, end users, inventory, lost-mode locations, policies and
-- versions, assignments, apps catalog, effective state (run as obligarth_owner).
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

-- 0. Preconditions --------------------------------------------------------------
DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass,text,text)') IS NULL THEN
    RAISE EXCEPTION 'mdm_model_expand: run the row level security migrations first';
  END IF;
  IF to_regclass('obligarth.mdm_commands') IS NULL THEN
    RAISE EXCEPTION 'mdm_model_expand: run the mdm_commands migration of the apple-edge integration first';
  END IF;
  IF EXISTS (SELECT 1 FROM obligarth.devices) THEN
    RAISE EXCEPTION 'mdm_model_expand: obligarth.devices holds rows of the removed RMM agent; recreate this development database';
  END IF;
END $$;

-- 1. Helper functions (immutable, invoker rights, SQL-standard bodies) ------------
-- '17.5.1 (21F90)' -> 17005001; NULL for anything that is not a version.
CREATE FUNCTION obligarth.version_num(p_version text) RETURNS integer
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN (SELECT CASE WHEN s.v ~ '^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$' THEN
                   split_part(s.v, '.', 1)::integer * 1000000
                 + COALESCE(NULLIF(split_part(s.v, '.', 2), ''), '0')::integer * 1000
                 + COALESCE(NULLIF(split_part(s.v, '.', 3), ''), '0')::integer
                 END
            FROM (SELECT regexp_replace(COALESCE(p_version, ''), '[^0-9.].*$', '') AS v) s);

-- Ownership locks the management mode (conception 3.2, REQ-01). Mirror of
-- shared/src/mdm/ownership.ts (ownershipAllows); both change together.
CREATE FUNCTION obligarth.ownership_allows(p_ownership text, p_enrollment_type text, p_mode text)
  RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN (CASE p_ownership
    WHEN 'personal' THEN
         (p_mode = 'user_enrollment' AND p_enrollment_type = 'byod_account')
      OR (p_mode = 'work_profile_personal' AND p_enrollment_type LIKE 'android\_%')
    WHEN 'corporate_personal' THEN
         (p_mode = 'device' AND p_enrollment_type IN ('ade', 'configurator', 'migration'))
      OR (p_mode = 'work_profile_corporate' AND p_enrollment_type LIKE 'android\_%')
    WHEN 'corporate' THEN
         (p_mode = 'device' AND p_enrollment_type IN ('ade', 'configurator', 'ota', 'account_device', 'migration'))
      OR (p_mode IN ('fully_managed', 'dedicated') AND p_enrollment_type LIKE 'android\_%')
    ELSE false
  END);

-- 2. End users (PLT-28) -------------------------------------------------------------
CREATE TABLE obligarth.end_users (
  id                    serial PRIMARY KEY,
  uuid                  uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  tenant_id             integer NOT NULL DEFAULT obligarth.ctx_tenant()
                        REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  external_id           varchar(255),
  email                 varchar(320),
  display_name          varchar(200),
  managed_apple_account varchar(320),
  source                varchar(16) NOT NULL DEFAULT 'manual',
  status                varchar(16) NOT NULL DEFAULT 'active',
  departed_at           timestamptz,
  created_by            integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT end_users_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT end_users_source_check CHECK (source IN ('manual', 'csv', 'directory', 'enrollment')),
  CONSTRAINT end_users_status_check CHECK (status IN ('active', 'departed')),
  CONSTRAINT end_users_departed_coherent CHECK ((status = 'departed') = (departed_at IS NOT NULL)),
  CONSTRAINT end_users_identity_present CHECK (
    email IS NOT NULL OR managed_apple_account IS NOT NULL OR external_id IS NOT NULL)
);
CREATE UNIQUE INDEX end_users_email_uq ON obligarth.end_users (tenant_id, lower(email)) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX end_users_maa_uq ON obligarth.end_users (tenant_id, lower(managed_apple_account))
  WHERE managed_apple_account IS NOT NULL;
CREATE UNIQUE INDEX end_users_external_uq ON obligarth.end_users (tenant_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX end_users_departed ON obligarth.end_users (departed_at) WHERE departed_at IS NOT NULL;

-- 3. devices: the registry (expand) --------------------------------------------------
ALTER TABLE obligarth.devices
  ALTER COLUMN hostname DROP NOT NULL,
  ADD COLUMN platform                varchar(16) NOT NULL,
  ADD COLUMN management_channel      varchar(16) NOT NULL,
  ADD COLUMN ownership               varchar(24) NOT NULL,
  ADD COLUMN enrollment_type         varchar(32) NOT NULL,
  ADD COLUMN management_mode         varchar(32) NOT NULL,
  ADD COLUMN supervised              boolean NOT NULL DEFAULT false,
  ADD COLUMN usage                   varchar(16) NOT NULL DEFAULT 'standard',
  ADD COLUMN enrollment_state        varchar(24) NOT NULL DEFAULT 'enrolling',
  ADD COLUMN enrollment_state_at     timestamptz,
  ADD COLUMN enrolled_at             timestamptz,
  ADD COLUMN unenrolled_at           timestamptz,
  ADD COLUMN unenroll_reason         varchar(32),
  ADD COLUMN retention_until         timestamptz,
  ADD COLUMN last_checkin_at         timestamptz,
  ADD COLUMN compliance_state        varchar(16) NOT NULL DEFAULT 'unknown',
  ADD COLUMN compliance_reasons      jsonb NOT NULL DEFAULT '[]',
  ADD COLUMN compliance_evaluated_at timestamptz,
  ADD COLUMN config_state            varchar(16) NOT NULL DEFAULT 'unknown',
  ADD COLUMN lost_mode_state         varchar(16) NOT NULL DEFAULT 'off',
  ADD COLUMN lost_mode_changed_at    timestamptz,
  ADD COLUMN serial_number           varchar(64),
  ADD COLUMN model                   varchar(64),
  ADD COLUMN model_name              varchar(128),
  ADD COLUMN os_build                varchar(32),
  ADD COLUMN device_name             varchar(255),
  ADD COLUMN storage_capacity_bytes  bigint,
  ADD COLUMN storage_available_bytes bigint,
  ADD COLUMN end_user_id             integer,
  ADD COLUMN end_user_assigned_at    timestamptz,
  ADD COLUMN enrollment_profile_id   uuid;

ALTER TABLE obligarth.devices
  ADD COLUMN os_version_num integer GENERATED ALWAYS AS (obligarth.version_num(os_version)) STORED,
  ADD COLUMN label text GENERATED ALWAYS AS (COALESCE(
    NULLIF(btrim(display_name), ''), NULLIF(btrim(device_name), ''),
    model_name, model, 'device-' || left(uuid::text, 8))) STORED;

ALTER TABLE obligarth.devices
  ADD CONSTRAINT devices_platform_check
      CHECK (platform IN ('ios', 'ipados', 'macos', 'tvos', 'visionos', 'android')),
  ADD CONSTRAINT devices_management_channel_check CHECK (management_channel IN ('apple_mdm', 'amapi')),
  ADD CONSTRAINT devices_channel_platform_check CHECK ((management_channel = 'amapi') = (platform = 'android')),
  ADD CONSTRAINT devices_ownership_check CHECK (ownership IN ('corporate', 'corporate_personal', 'personal')),
  ADD CONSTRAINT devices_enrollment_type_check CHECK (enrollment_type IN
      ('ade', 'ota', 'byod_account', 'configurator', 'account_device', 'migration')),
  ADD CONSTRAINT devices_management_mode_check CHECK (management_mode IN
      ('device', 'user_enrollment', 'fully_managed', 'dedicated', 'work_profile_corporate', 'work_profile_personal')),
  ADD CONSTRAINT devices_ownership_mode_check
      CHECK (obligarth.ownership_allows(ownership, enrollment_type, management_mode)),
  ADD CONSTRAINT devices_usage_check CHECK (usage IN ('standard', 'kiosk', 'shared')),
  ADD CONSTRAINT devices_enrollment_state_check
      CHECK (enrollment_state IN ('enrolling', 'awaiting_configuration', 'enrolled', 'unenrolling', 'unenrolled')),
  ADD CONSTRAINT devices_unenrolled_coherent CHECK ((enrollment_state = 'unenrolled') = (unenrolled_at IS NOT NULL)),
  ADD CONSTRAINT devices_unenroll_reason_check CHECK (unenroll_reason IN ('checkout', 'retired', 'transfer',
      'superseded_by_proof', 'superseded', 'apns_inactive', 'purged', 'disabled_in_edge', 'removed_by_command', 'wiped')),
  ADD CONSTRAINT devices_unenroll_reason_coherent CHECK ((enrollment_state = 'unenrolled') = (unenroll_reason IS NOT NULL)),
  ADD CONSTRAINT devices_compliance_state_check
      CHECK (compliance_state IN ('unknown', 'compliant', 'non_compliant', 'exempt')),
  ADD CONSTRAINT devices_compliance_reasons_array CHECK (jsonb_typeof(compliance_reasons) = 'array'),
  ADD CONSTRAINT devices_config_state_check CHECK (config_state IN ('unknown', 'applied', 'pending', 'error')),
  ADD CONSTRAINT devices_lost_mode_state_check CHECK (lost_mode_state IN ('off', 'enabling', 'on', 'disabling')),
  ADD CONSTRAINT devices_personal_no_serial CHECK (ownership <> 'personal' OR serial_number IS NULL),
  ADD CONSTRAINT devices_personal_no_lost_mode CHECK (ownership <> 'personal' OR lost_mode_state = 'off'),
  ADD CONSTRAINT devices_end_user_tenant_fk FOREIGN KEY (tenant_id, end_user_id)
      REFERENCES obligarth.end_users (tenant_id, id) ON DELETE SET NULL (end_user_id);

CREATE UNIQUE INDEX devices_serial_uq ON obligarth.devices (tenant_id, management_channel, serial_number)
  WHERE serial_number IS NOT NULL;
CREATE INDEX devices_tenant_state ON obligarth.devices (tenant_id, enrollment_state);
CREATE INDEX devices_tenant_checkin ON obligarth.devices (tenant_id, last_checkin_at);
CREATE INDEX devices_tenant_platform_os ON obligarth.devices (tenant_id, platform, os_version_num);
CREATE INDEX devices_tenant_compliance ON obligarth.devices (tenant_id, compliance_state)
  WHERE enrollment_state <> 'unenrolled';
CREATE INDEX devices_tenant_config ON obligarth.devices (tenant_id, config_state)
  WHERE enrollment_state <> 'unenrolled';
CREATE INDEX devices_tenant_end_user ON obligarth.devices (tenant_id, end_user_id) WHERE end_user_id IS NOT NULL;
CREATE INDEX devices_retention ON obligarth.devices (retention_until) WHERE retention_until IS NOT NULL;

-- The ownership of a device changes by a new enrollment, or between corporate
-- and corporate_personal on a device-enrolled device (REQ-01: approved circuit).
CREATE FUNCTION obligarth.devices_guard_ownership() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.ownership IS DISTINCT FROM OLD.ownership
     AND NEW.enrollment_state IS DISTINCT FROM 'enrolling'
     AND NOT (OLD.ownership IN ('corporate', 'corporate_personal')
              AND NEW.ownership IN ('corporate', 'corporate_personal')
              AND NEW.management_mode = 'device') THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'devices_ownership_change',
      MESSAGE = 'devices: the ownership changes by a new enrollment, or between corporate and corporate_personal';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth.devices_guard_ownership() FROM PUBLIC;
CREATE TRIGGER devices_guard_ownership BEFORE UPDATE OF ownership ON obligarth.devices
  FOR EACH ROW EXECUTE FUNCTION obligarth.devices_guard_ownership();

-- The record of a device still under management is never deleted directly: it
-- leaves management first (ENR-17). A tenant deletion cascades (depth above 1).
CREATE FUNCTION obligarth.devices_guard_delete() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF pg_trigger_depth() = 1 AND OLD.enrollment_state <> 'unenrolled' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'devices_delete_managed',
      MESSAGE = 'devices: a device under management leaves management before its record is deleted';
  END IF;
  RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION obligarth.devices_guard_delete() FROM PUBLIC;
CREATE TRIGGER devices_guard_delete BEFORE DELETE ON obligarth.devices
  FOR EACH ROW EXECUTE FUNCTION obligarth.devices_guard_delete();

-- 4. Apple satellite (1-1) ------------------------------------------------------------
CREATE TABLE obligarth.apple_devices (
  device_id                  integer PRIMARY KEY,
  tenant_id                  integer NOT NULL DEFAULT obligarth.ctx_tenant()
                             REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enrollment_id              varchar(160) NOT NULL,
  udid                       varchar(128),
  byod_enrollment_id         varchar(128),
  nano_enroll_type           varchar(32) NOT NULL,
  topic                      varchar(255) NOT NULL,
  proof                      varchar(8) NOT NULL DEFAULT 'none',
  enrollment_session_id      uuid,
  authenticated_at           timestamptz NOT NULL,
  cert_sha256                char(64),
  cert_not_after             timestamptz,
  identity_cert_pem          text,
  identity_state             varchar(16) NOT NULL DEFAULT 'valid',
  token_update_tally         integer NOT NULL DEFAULT 0,
  token_update_at            timestamptz,
  push_state                 varchar(24) NOT NULL DEFAULT 'unknown',
  push_state_at              timestamptz,
  id_activated_at            timestamptz,
  id_released_at             timestamptz,
  id_release_reason          varchar(24),
  device_configured_at       timestamptz,
  has_unlock_token           boolean NOT NULL DEFAULT false,
  bootstrap_token_escrowed   boolean NOT NULL DEFAULT false,
  activation_lock_bypass_ref uuid,
  activation_lock_enabled    boolean,
  find_my_enabled            boolean,
  product_name               varchar(64),
  model_number               varchar(64),
  imei                       varchar(32),
  ddm_enabled                boolean NOT NULL DEFAULT false,
  ddm_enabled_at             timestamptz,
  ddm_client_capabilities    jsonb,
  device_information         jsonb,
  security_info              jsonb,
  last_device_info_at        timestamptz,
  last_security_info_at      timestamptz,
  last_apps_at               timestamptz,
  last_profiles_at           timestamptz,
  last_certificates_at       timestamptz,
  created_at                 timestamptz NOT NULL DEFAULT now(),
  updated_at                 timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT apple_devices_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT apple_devices_enrollment_id_format
      CHECK (enrollment_id ~ '^[a-km-np-z2-9]{16}_[A-Za-z0-9._-]{1,128}$'),
  CONSTRAINT apple_devices_one_identifier CHECK ((udid IS NULL) <> (byod_enrollment_id IS NULL)),
  CONSTRAINT apple_devices_nano_enroll_type_check
      CHECK (nano_enroll_type IN ('Device', 'User Enrollment (Device)')),
  CONSTRAINT apple_devices_identifier_kind CHECK ((nano_enroll_type = 'Device') = (udid IS NOT NULL)),
  CONSTRAINT apple_devices_proof_check CHECK (proof IN ('none', 'ade')),
  CONSTRAINT apple_devices_topic_check CHECK (topic LIKE 'com.apple.mgmt.%'),
  CONSTRAINT apple_devices_identity_state_check CHECK (identity_state IN ('valid', 'expired', 'revoked')),
  CONSTRAINT apple_devices_push_state_check CHECK (push_state IN
      ('unknown', 'ready', 'invalid_token', 'inactive', 'topic_error', 'disabled')),
  CONSTRAINT apple_devices_release_reason_check CHECK (id_release_reason IN
      ('checkout', 'retired', 'transfer', 'superseded_by_proof', 'superseded', 'apns_inactive', 'purged')),
  CONSTRAINT apple_devices_release_coherent CHECK ((id_released_at IS NULL) = (id_release_reason IS NULL)),
  CONSTRAINT apple_devices_cert_sha_check CHECK (cert_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX apple_devices_enrollment_id_uq ON obligarth.apple_devices (enrollment_id);
-- One active device identifier in the whole instance (conception 7.1, REQ-13):
-- a violation reveals the existence elsewhere, as intended (rls-tenant 5.6).
-- Activation mirrors apple_edge.device_ids: first TokenUpdate of the device
-- channel, so the loser of an Authenticate race never holds the identifier.
CREATE UNIQUE INDEX apple_devices_udid_active ON obligarth.apple_devices (udid)
  WHERE udid IS NOT NULL AND id_activated_at IS NOT NULL AND id_released_at IS NULL;
CREATE UNIQUE INDEX apple_devices_byod_id_active ON obligarth.apple_devices (byod_enrollment_id)
  WHERE byod_enrollment_id IS NOT NULL AND id_activated_at IS NOT NULL AND id_released_at IS NULL;
CREATE INDEX apple_devices_tenant_imei ON obligarth.apple_devices (tenant_id, imei) WHERE imei IS NOT NULL;
CREATE INDEX apple_devices_tenant_cert ON obligarth.apple_devices (tenant_id, cert_sha256) WHERE cert_sha256 IS NOT NULL;

-- 5. Enrollment episodes ---------------------------------------------------------------
CREATE TABLE obligarth.device_enrollments (
  id                    bigserial PRIMARY KEY,
  tenant_id             integer NOT NULL DEFAULT obligarth.ctx_tenant()
                        REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id             integer NOT NULL,
  channel_enrollment_id varchar(255) NOT NULL,
  enrollment_type       varchar(32) NOT NULL,
  management_mode       varchar(32) NOT NULL,
  ownership             varchar(24) NOT NULL,
  enrollment_profile_id uuid,
  enrollment_session_id uuid,
  end_user_id           integer,
  cert_sha256           char(64),
  started_at            timestamptz NOT NULL,
  enrolled_at           timestamptz,
  ended_at              timestamptz,
  end_reason            varchar(32),
  CONSTRAINT device_enrollments_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT device_enrollments_end_user_tenant_fk FOREIGN KEY (tenant_id, end_user_id)
      REFERENCES obligarth.end_users (tenant_id, id) ON DELETE SET NULL (end_user_id),
  CONSTRAINT device_enrollments_end_reason_check CHECK (end_reason IN ('checkout', 'retired', 'transfer',
      'superseded_by_proof', 'superseded', 'apns_inactive', 'purged', 'disabled_in_edge', 'removed_by_command',
      'wiped', 'replaced')),
  CONSTRAINT device_enrollments_ended_coherent CHECK ((ended_at IS NULL) = (end_reason IS NULL))
);
CREATE UNIQUE INDEX device_enrollments_one_open ON obligarth.device_enrollments (device_id) WHERE ended_at IS NULL;
CREATE INDEX device_enrollments_device ON obligarth.device_enrollments (tenant_id, device_id, started_at DESC);
CREATE INDEX device_enrollments_session ON obligarth.device_enrollments (tenant_id, enrollment_session_id)
  WHERE enrollment_session_id IS NOT NULL;

-- 6. Inventory ------------------------------------------------------------------------
CREATE TABLE obligarth.device_status_items (
  tenant_id   integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id   integer NOT NULL,
  item        varchar(128) NOT NULL,
  value       jsonb,
  value_sha256 char(64),
  error       jsonb,
  observed_at timestamptz NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, device_id, item),
  CONSTRAINT device_status_items_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT device_status_items_item_format CHECK (item ~ '^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$'),
  CONSTRAINT device_status_items_value_sha_check CHECK (value_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE TABLE obligarth.device_status_history (
  id          bigserial PRIMARY KEY,
  tenant_id   integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id   integer NOT NULL,
  item        varchar(128) NOT NULL,
  value       jsonb,
  observed_at timestamptz NOT NULL,
  CONSTRAINT device_status_history_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX device_status_history_device ON obligarth.device_status_history (tenant_id, device_id, item, observed_at DESC);
CREATE INDEX device_status_history_observed ON obligarth.device_status_history (observed_at);

CREATE TABLE obligarth.device_apps (
  id                bigserial PRIMARY KEY,
  tenant_id         integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id         integer NOT NULL,
  identifier        varchar(255) NOT NULL,
  name              varchar(255),
  version           varchar(64),
  short_version     varchar(64),
  managed           boolean NOT NULL DEFAULT false,
  management_status varchar(32),
  source            varchar(16) NOT NULL,
  bundle_size       bigint,
  dynamic_size      bigint,
  has_configuration boolean,
  is_validated      boolean,
  app_id            integer,
  first_seen_at     timestamptz NOT NULL DEFAULT now(),
  last_seen_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT device_apps_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT device_apps_uq UNIQUE (tenant_id, device_id, identifier),
  CONSTRAINT device_apps_source_check
      CHECK (source IN ('installed_list', 'managed_list', 'ddm_status', 'amapi_report'))
);
CREATE INDEX device_apps_identifier ON obligarth.device_apps (tenant_id, identifier);

CREATE TABLE obligarth.apple_device_profiles (
  id                   bigserial PRIMARY KEY,
  tenant_id            integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id            integer NOT NULL,
  payload_identifier   varchar(255) NOT NULL,
  payload_uuid         varchar(64),
  display_name         varchar(255),
  organization         varchar(255),
  is_managed           boolean,
  is_encrypted         boolean,
  removal_disallowed   boolean,
  has_removal_passcode boolean,
  payload_types        text[] NOT NULL DEFAULT '{}',
  artifact_key         varchar(200),
  first_seen_at        timestamptz NOT NULL DEFAULT now(),
  last_seen_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT apple_device_profiles_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT apple_device_profiles_uq UNIQUE (tenant_id, device_id, payload_identifier)
);

CREATE TABLE obligarth.device_certificates (
  id              bigserial PRIMARY KEY,
  tenant_id       integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id       integer NOT NULL,
  sha256          char(64) NOT NULL,
  common_name     varchar(255),
  subject         text,
  issuer          text,
  serial_hex      varchar(64),
  not_before      timestamptz,
  not_after       timestamptz,
  is_identity     boolean NOT NULL DEFAULT false,
  is_mdm_identity boolean NOT NULL DEFAULT false,
  source          varchar(16) NOT NULL,
  first_seen_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT device_certificates_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT device_certificates_uq UNIQUE (tenant_id, device_id, sha256),
  CONSTRAINT device_certificates_sha_check CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT device_certificates_source_check CHECK (source IN ('certificate_list', 'ddm_status'))
);
CREATE INDEX device_certificates_expiry ON obligarth.device_certificates (tenant_id, not_after);

-- 7. Approvals referenced by policy versions (the command queue is the integration's) ---
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'pending_approvals_tenant_id_id_unique') THEN
    ALTER TABLE obligarth.pending_approvals
      ADD CONSTRAINT pending_approvals_tenant_id_id_unique UNIQUE (tenant_id, id);
  END IF;
END $$;

-- 8. Lost-mode locations (SEC-05; never for a personal device) --------------------------
CREATE TABLE obligarth.lost_mode_locations (
  id                  bigserial PRIMARY KEY,
  tenant_id           integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id           integer NOT NULL,
  latitude            double precision NOT NULL,
  longitude           double precision NOT NULL,
  horizontal_accuracy real,
  altitude            real,
  vertical_accuracy   real,
  speed               real,
  course              real,
  observed_at         timestamptz NOT NULL,
  received_at         timestamptz NOT NULL DEFAULT now(),
  command_id          uuid,
  purge_at            timestamptz NOT NULL,
  CONSTRAINT lost_mode_locations_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT lost_mode_locations_command_tenant_fk FOREIGN KEY (tenant_id, command_id)
      REFERENCES obligarth.mdm_commands (tenant_id, id) ON DELETE SET NULL (command_id),
  CONSTRAINT lost_mode_locations_coordinates CHECK (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180),
  CONSTRAINT lost_mode_locations_purge_cap CHECK (purge_at <= received_at + interval '62 days')
);
CREATE INDEX lost_mode_locations_device ON obligarth.lost_mode_locations (tenant_id, device_id, observed_at DESC);
CREATE INDEX lost_mode_locations_purge ON obligarth.lost_mode_locations (purge_at);

CREATE FUNCTION obligarth.lost_mode_locations_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM obligarth.devices d
             WHERE d.tenant_id = NEW.tenant_id AND d.id = NEW.device_id AND d.ownership = 'personal') THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'lost_mode_locations_not_personal',
      MESSAGE = 'lost_mode_locations: no location is ever stored for a personal device';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth.lost_mode_locations_guard() FROM PUBLIC;
CREATE TRIGGER lost_mode_locations_guard BEFORE INSERT OR UPDATE OF device_id ON obligarth.lost_mode_locations
  FOR EACH ROW EXECUTE FUNCTION obligarth.lost_mode_locations_guard();

-- 9. Policies (envelope), versions (content) ------------------------------------------
CREATE TABLE obligarth.policies (
  id                 serial PRIMARY KEY,
  uuid               uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  tenant_id          integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  target_tenant_ids  integer[],
  name               varchar(200) NOT NULL,
  description        text,
  category           varchar(32) NOT NULL DEFAULT 'configuration',
  state              varchar(16) NOT NULL DEFAULT 'draft',
  sections           varchar(16)[] NOT NULL DEFAULT '{}',
  current_version_id integer,
  version_counter    integer NOT NULL DEFAULT 0,
  created_by         integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  updated_by         integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  archived_at        timestamptz,
  CONSTRAINT policies_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT policies_target_master CHECK (target_tenant_ids IS NULL OR tenant_id = 1),
  CONSTRAINT policies_state_check CHECK (state IN ('draft', 'published', 'archived')),
  CONSTRAINT policies_category_check CHECK (category ~ '^[a-z][a-z0-9_]{1,31}$'),
  CONSTRAINT policies_sections_check CHECK (sections <@ ARRAY['apple', 'android']::varchar[]),
  CONSTRAINT policies_published_has_version CHECK (state <> 'published' OR current_version_id IS NOT NULL),
  CONSTRAINT policies_archived_coherent CHECK ((state = 'archived') = (archived_at IS NOT NULL))
);
CREATE UNIQUE INDEX policies_name_uq ON obligarth.policies (tenant_id, lower(name)) WHERE state <> 'archived';
CREATE INDEX policies_target_tenants ON obligarth.policies USING gin (target_tenant_ids);

CREATE TABLE obligarth.policy_versions (
  id             serial PRIMARY KEY,
  tenant_id      integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  policy_id      integer NOT NULL,
  version        integer NOT NULL,
  state          varchar(20) NOT NULL DEFAULT 'draft',
  content        jsonb NOT NULL,
  content_sha256 char(64) NOT NULL,
  schema_release jsonb NOT NULL DEFAULT '{}',
  summary        jsonb NOT NULL DEFAULT '{}',
  change_note    text,
  impact         jsonb,
  approval_id    integer,
  created_by     integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  submitted_by   integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  submitted_at   timestamptz,
  published_by   integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  published_at   timestamptz,
  superseded_at  timestamptz,
  CONSTRAINT policy_versions_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT policy_versions_policy_tenant_fk FOREIGN KEY (tenant_id, policy_id)
      REFERENCES obligarth.policies (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT policy_versions_version_uq UNIQUE (policy_id, version),
  CONSTRAINT policy_versions_state_check
      CHECK (state IN ('draft', 'pending_approval', 'published', 'superseded', 'rejected')),
  CONSTRAINT policy_versions_sha_check CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT policy_versions_content_object CHECK (jsonb_typeof(content) = 'object'),
  CONSTRAINT policy_versions_published_coherent
      CHECK ((state IN ('published', 'superseded')) = (published_at IS NOT NULL)),
  CONSTRAINT policy_versions_approval_tenant_fk FOREIGN KEY (tenant_id, approval_id)
      REFERENCES obligarth.pending_approvals (tenant_id, id) ON DELETE SET NULL (approval_id)
);
CREATE UNIQUE INDEX policy_versions_one_open ON obligarth.policy_versions (policy_id)
  WHERE state IN ('draft', 'pending_approval');
CREATE UNIQUE INDEX policy_versions_one_published ON obligarth.policy_versions (policy_id) WHERE state = 'published';

ALTER TABLE obligarth.policies
  ADD CONSTRAINT policies_current_version_tenant_fk FOREIGN KEY (tenant_id, current_version_id)
      REFERENCES obligarth.policy_versions (tenant_id, id);

-- A submitted or published version is immutable and never deleted directly
-- (a tenant or policy deletion cascades: trigger depth above 1).
CREATE FUNCTION obligarth.policy_versions_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF pg_trigger_depth() = 1 AND OLD.state NOT IN ('draft', 'rejected') THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'policy_versions_immutable',
        MESSAGE = 'policy_versions: a submitted or published version is never deleted';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.state <> 'draft' AND (NEW.content IS DISTINCT FROM OLD.content
      OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
      OR NEW.version IS DISTINCT FROM OLD.version OR NEW.policy_id IS DISTINCT FROM OLD.policy_id) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'policy_versions_immutable',
      MESSAGE = 'policy_versions: the content of a submitted or published version is immutable';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'draft' AND NEW.state IN ('pending_approval', 'published'))
    OR (OLD.state = 'pending_approval' AND NEW.state IN ('draft', 'published', 'rejected'))
    OR (OLD.state = 'published' AND NEW.state = 'superseded')) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'policy_versions_transition',
      MESSAGE = format('policy_versions: transition %s to %s is not allowed', OLD.state, NEW.state);
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth.policy_versions_guard() FROM PUBLIC;
CREATE TRIGGER policy_versions_guard BEFORE UPDATE OR DELETE ON obligarth.policy_versions
  FOR EACH ROW EXECUTE FUNCTION obligarth.policy_versions_guard();

-- 10. Apps catalog ------------------------------------------------------------------
CREATE TABLE obligarth.apps (
  id                    serial PRIMARY KEY,
  uuid                  uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  tenant_id             integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  target_tenant_ids     integer[],
  platform_family       varchar(16) NOT NULL,
  kind                  varchar(16) NOT NULL,
  identifier            varchar(255) NOT NULL,
  store_id              varchar(32),
  name                  varchar(255) NOT NULL,
  publisher             varchar(255),
  icon_url              varchar(1024),
  supported_platforms   varchar(16)[] NOT NULL DEFAULT '{}',
  minimum_os_version    varchar(32),
  license_mode          varchar(16) NOT NULL DEFAULT 'vpp',
  metadata              jsonb NOT NULL DEFAULT '{}',
  metadata_refreshed_at timestamptz,
  created_by            integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  archived_at           timestamptz,
  CONSTRAINT apps_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT apps_target_master CHECK (target_tenant_ids IS NULL OR tenant_id = 1),
  CONSTRAINT apps_platform_family_check CHECK (platform_family IN ('apple', 'android')),
  CONSTRAINT apps_kind_check CHECK (kind IN ('app_store', 'custom', 'enterprise', 'play', 'private', 'web')),
  CONSTRAINT apps_kind_family CHECK ((platform_family = 'apple') = (kind IN ('app_store', 'custom', 'enterprise'))),
  -- An App Store or custom app has its store id (a NULL store_id is refused, not let through).
  CONSTRAINT apps_store_id_check
      CHECK (kind NOT IN ('app_store', 'custom') OR COALESCE(store_id ~ '^[0-9]{1,20}$', false)),
  CONSTRAINT apps_identifier_format CHECK (identifier ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$'),
  CONSTRAINT apps_license_mode_check CHECK (license_mode IN ('vpp', 'none')),
  CONSTRAINT apps_supported_platforms_check
      CHECK (supported_platforms <@ ARRAY['ios', 'ipados', 'macos', 'tvos', 'visionos', 'android']::varchar[])
);
CREATE UNIQUE INDEX apps_identifier_uq ON obligarth.apps (tenant_id, platform_family, identifier)
  WHERE archived_at IS NULL;
CREATE INDEX apps_target_tenants ON obligarth.apps USING gin (target_tenant_ids);

-- 11. Assignments (polymorphic resource: no foreign key, checked by trigger) ----------
CREATE TABLE obligarth.assignments (
  id                 bigserial PRIMARY KEY,
  tenant_id          integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  resource_type      varchar(16) NOT NULL,
  resource_id        integer NOT NULL,
  resource_tenant_id integer NOT NULL,
  target_scope       varchar(16) NOT NULL,
  target_id          integer,
  mode               varchar(8) NOT NULL DEFAULT 'include',
  priority           smallint NOT NULL DEFAULT 100,
  options            jsonb NOT NULL DEFAULT '{}',
  created_by         integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT assignments_resource_type_check CHECK (resource_type IN ('policy', 'app')),
  CONSTRAINT assignments_target_scope_check CHECK (target_scope IN ('tenant', 'group', 'device')),
  CONSTRAINT assignments_target_id_check CHECK ((target_scope = 'tenant') = (target_id IS NULL)),
  CONSTRAINT assignments_mode_check CHECK (mode IN ('include', 'exclude')),
  CONSTRAINT assignments_no_tenant_exclude CHECK (NOT (target_scope = 'tenant' AND mode = 'exclude')),
  CONSTRAINT assignments_priority_check CHECK (priority BETWEEN 0 AND 1000),
  CONSTRAINT assignments_resource_owner CHECK (resource_tenant_id = tenant_id OR resource_tenant_id = 1),
  CONSTRAINT assignments_options_object CHECK (jsonb_typeof(options) = 'object'),
  CONSTRAINT assignments_exclude_no_options CHECK (mode = 'include' OR options = '{}'::jsonb)
);
-- One row per (resource, target): a target is never both included and excluded (conception 7.4, rule 4)
CREATE UNIQUE INDEX assignments_target_uq ON obligarth.assignments
  (tenant_id, resource_type, resource_tenant_id, resource_id, target_scope, COALESCE(target_id, 0));
CREATE INDEX assignments_target ON obligarth.assignments (tenant_id, target_scope, target_id);
CREATE INDEX assignments_resource ON obligarth.assignments (resource_tenant_id, resource_type, resource_id);

CREATE FUNCTION obligarth.check_assignment_reference() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_ok boolean;
BEGIN
  IF NEW.resource_type = 'policy' THEN
    SELECT EXISTS (SELECT 1 FROM obligarth.policies p
                   WHERE p.id = NEW.resource_id AND p.tenant_id = NEW.resource_tenant_id AND p.state <> 'archived'
                     AND (p.tenant_id = NEW.tenant_id OR p.target_tenant_ids @> ARRAY[NEW.tenant_id])) INTO v_ok;
  ELSE
    SELECT EXISTS (SELECT 1 FROM obligarth.apps a
                   WHERE a.id = NEW.resource_id AND a.tenant_id = NEW.resource_tenant_id AND a.archived_at IS NULL
                     AND (a.tenant_id = NEW.tenant_id OR a.target_tenant_ids @> ARRAY[NEW.tenant_id])) INTO v_ok;
  END IF;
  IF NOT v_ok THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'assignments_resource_reference',
      MESSAGE = 'assignments: no such resource for the tenant of the row';
  END IF;
  IF NEW.target_scope = 'group' THEN
    PERFORM 1 FROM obligarth.device_groups g WHERE g.id = NEW.target_id AND g.tenant_id = NEW.tenant_id;
  ELSIF NEW.target_scope = 'device' THEN
    PERFORM 1 FROM obligarth.devices d WHERE d.id = NEW.target_id AND d.tenant_id = NEW.tenant_id;
  END IF;
  IF NEW.target_scope IN ('group', 'device') AND NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'assignments_target_reference',
      MESSAGE = 'assignments: no such target in the tenant of the row';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth.check_assignment_reference() FROM PUBLIC;
CREATE TRIGGER assignments_reference BEFORE INSERT OR UPDATE OF
    tenant_id, resource_type, resource_id, resource_tenant_id, target_scope, target_id
  ON obligarth.assignments FOR EACH ROW EXECUTE FUNCTION obligarth.check_assignment_reference();

CREATE FUNCTION obligarth.assignments_cleanup() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_TABLE_NAME = 'device_groups' THEN
    DELETE FROM obligarth.assignments a
     WHERE a.tenant_id = OLD.tenant_id AND a.target_scope = 'group' AND a.target_id = OLD.id;
  ELSIF TG_TABLE_NAME = 'devices' THEN
    DELETE FROM obligarth.assignments a
     WHERE a.tenant_id = OLD.tenant_id AND a.target_scope = 'device' AND a.target_id = OLD.id;
  ELSIF TG_TABLE_NAME = 'policies' THEN
    DELETE FROM obligarth.assignments a
     WHERE a.resource_type = 'policy' AND a.resource_tenant_id = OLD.tenant_id AND a.resource_id = OLD.id;
  ELSIF TG_TABLE_NAME = 'apps' THEN
    DELETE FROM obligarth.assignments a
     WHERE a.resource_type = 'app' AND a.resource_tenant_id = OLD.tenant_id AND a.resource_id = OLD.id;
  END IF;
  RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION obligarth.assignments_cleanup() FROM PUBLIC;
CREATE TRIGGER device_groups_assignments_cleanup AFTER DELETE ON obligarth.device_groups
  FOR EACH ROW EXECUTE FUNCTION obligarth.assignments_cleanup();
CREATE TRIGGER devices_assignments_cleanup AFTER DELETE ON obligarth.devices
  FOR EACH ROW EXECUTE FUNCTION obligarth.assignments_cleanup();
CREATE TRIGGER policies_assignments_cleanup AFTER DELETE ON obligarth.policies
  FOR EACH ROW EXECUTE FUNCTION obligarth.assignments_cleanup();
CREATE TRIGGER apps_assignments_cleanup AFTER DELETE ON obligarth.apps
  FOR EACH ROW EXECUTE FUNCTION obligarth.assignments_cleanup();

-- 12. Effective state: settings with provenance, compiled artifacts ---------------------
CREATE TABLE obligarth.device_effective_settings (
  tenant_id               integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id               integer NOT NULL,
  setting_key             varchar(300) NOT NULL,
  artifact_key            varchar(200),
  value_hash              char(64) NOT NULL,
  removed                 boolean NOT NULL DEFAULT false,
  source_type             varchar(8) NOT NULL,
  source_id               integer NOT NULL,
  source_tenant_id        integer NOT NULL,
  source_version_id       integer,
  source_assignment_id    bigint NOT NULL,
  source_scope            varchar(12) NOT NULL,
  source_scope_id         integer,
  source_rank             integer NOT NULL,
  availability            varchar(16) NOT NULL DEFAULT 'available',
  unavailable_reason      varchar(40),
  conflict                jsonb,
  computed_at             timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, device_id, setting_key),
  CONSTRAINT device_effective_settings_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT device_effective_settings_source_type_check CHECK (source_type IN ('policy', 'app')),
  CONSTRAINT device_effective_settings_version_coherent CHECK ((source_type = 'policy') = (source_version_id IS NOT NULL)),
  CONSTRAINT device_effective_settings_scope_check CHECK (source_scope IN ('device', 'group', 'tenant', 'library')),
  CONSTRAINT device_effective_settings_availability_check CHECK (availability IN ('available', 'not_applicable')),
  CONSTRAINT device_effective_settings_reason_coherent
      CHECK ((availability = 'not_applicable') = (unavailable_reason IS NOT NULL)),
  CONSTRAINT device_effective_settings_hash_check CHECK (value_hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX device_effective_settings_source ON obligarth.device_effective_settings (tenant_id, source_type, source_tenant_id, source_id);
CREATE INDEX device_effective_settings_conflicts ON obligarth.device_effective_settings (tenant_id, device_id)
  WHERE conflict IS NOT NULL;

CREATE TABLE obligarth.mdm_artifacts (
  tenant_id     integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  hash          char(64) NOT NULL,
  channel       varchar(12) NOT NULL,
  artifact_type varchar(128) NOT NULL,
  identifier    varchar(200) NOT NULL,
  body          jsonb NOT NULL,
  secret_refs   uuid[] NOT NULL DEFAULT '{}',
  has_variables boolean NOT NULL DEFAULT false,
  encrypt       boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, hash),
  CONSTRAINT mdm_artifacts_hash_check CHECK (hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT mdm_artifacts_channel_check CHECK (channel IN ('ddm', 'profile', 'app', 'setting')),
  CONSTRAINT mdm_artifacts_identifier_check CHECK (
       (channel = 'ddm' AND identifier ~ '^obg\.cfg\.pol-[A-Za-z0-9._-]{1,52}$')
    OR (channel = 'profile' AND identifier ~ '^tools\.obli\.obligarth\.(p|raw)\.[A-Za-z0-9._-]{1,140}$')
    OR (channel = 'app' AND identifier ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$')
    OR (channel = 'setting' AND identifier ~ '^[a-z][a-z0-9_]{0,63}$')),
  CONSTRAINT mdm_artifacts_encrypt_profile CHECK (NOT encrypt OR channel = 'profile'),
  CONSTRAINT mdm_artifacts_body_object CHECK (jsonb_typeof(body) = 'object')
);

CREATE TABLE obligarth.device_artifacts (
  tenant_id       integer NOT NULL DEFAULT obligarth.ctx_tenant() REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id       integer NOT NULL,
  artifact_key    varchar(210) NOT NULL,
  channel         varchar(12) NOT NULL,
  desired_hash    char(64),
  rendered_hash   char(64),
  sources         jsonb NOT NULL DEFAULT '[]',
  desired_at      timestamptz NOT NULL DEFAULT now(),
  delivered_hash  char(64),
  delivered_at    timestamptz,
  state           varchar(16) NOT NULL DEFAULT 'pending',
  state_reasons   jsonb NOT NULL DEFAULT '[]',
  state_at        timestamptz NOT NULL DEFAULT now(),
  last_command_id uuid,
  PRIMARY KEY (tenant_id, device_id, artifact_key),
  CONSTRAINT device_artifacts_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
      REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT device_artifacts_desired_tenant_fk FOREIGN KEY (tenant_id, desired_hash)
      REFERENCES obligarth.mdm_artifacts (tenant_id, hash),
  CONSTRAINT device_artifacts_command_tenant_fk FOREIGN KEY (tenant_id, last_command_id)
      REFERENCES obligarth.mdm_commands (tenant_id, id) ON DELETE SET NULL (last_command_id),
  CONSTRAINT device_artifacts_key_check
      CHECK (artifact_key ~ '^(ddm|profile|app|setting):[A-Za-z0-9][A-Za-z0-9._-]{0,199}$'),
  CONSTRAINT device_artifacts_channel_check CHECK (channel = split_part(artifact_key, ':', 1)),
  CONSTRAINT device_artifacts_state_check CHECK (state IN ('pending', 'delivering', 'applied', 'error',
      'not_applicable', 'removing', 'removed')),
  CONSTRAINT device_artifacts_removal_coherent
      CHECK (desired_hash IS NOT NULL OR state IN ('removing', 'removed', 'error')),
  CONSTRAINT device_artifacts_reasons_array CHECK (jsonb_typeof(state_reasons) = 'array')
);
CREATE INDEX device_artifacts_open ON obligarth.device_artifacts (tenant_id, state)
  WHERE state IN ('pending', 'delivering', 'error', 'removing');
CREATE INDEX device_artifacts_desired ON obligarth.device_artifacts (tenant_id, desired_hash);

-- Aggregate application state of devices (devices.config_state). Every writer of
-- device_artifacts calls it in the same transaction.
CREATE FUNCTION obligarth.device_config_rollup(p_device_ids integer[]) RETURNS void
  LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  UPDATE obligarth.devices d
     SET config_state = COALESCE((
           SELECT CASE WHEN bool_or(a.state = 'error') THEN 'error'
                       WHEN bool_or(a.state IN ('pending', 'delivering', 'removing')) THEN 'pending'
                       ELSE 'applied' END
             FROM obligarth.device_artifacts a
            WHERE a.tenant_id = d.tenant_id AND a.device_id = d.id AND a.state <> 'removed'), 'applied')
   WHERE d.id = ANY (p_device_ids)
$$;

-- 13. Fleet snapshots: MDM counters (the RMM ones go with the contract step) -------------
ALTER TABLE obligarth.fleet_daily_snapshot
  ADD COLUMN enrolled integer NOT NULL DEFAULT 0, ADD COLUMN enrolling integer NOT NULL DEFAULT 0,
  ADD COLUMN compliant integer NOT NULL DEFAULT 0, ADD COLUMN non_compliant integer NOT NULL DEFAULT 0,
  ADD COLUMN config_errors integer NOT NULL DEFAULT 0, ADD COLUMN stale integer NOT NULL DEFAULT 0;
ALTER TABLE obligarth.fleet_hourly_snapshot
  ADD COLUMN enrolled integer NOT NULL DEFAULT 0, ADD COLUMN enrolling integer NOT NULL DEFAULT 0,
  ADD COLUMN compliant integer NOT NULL DEFAULT 0, ADD COLUMN non_compliant integer NOT NULL DEFAULT 0,
  ADD COLUMN config_errors integer NOT NULL DEFAULT 0, ADD COLUMN stale integer NOT NULL DEFAULT 0;

-- 13 bis. The recommended level of the restriction this model adds (section 10.7: device.change_ownership,
-- 'restricted'), written on the tenants that exist already as the base seed wrote the core's on the master
-- tenant (a tenant created later gets it from tenantService.create); a level a tenant chose is kept.
UPDATE obligarth.tenants
   SET action_restrictions = COALESCE(action_restrictions, '{}'::jsonb) || '{"device.change_ownership": "restricted"}'::jsonb
 WHERE NOT jsonb_exists(COALESCE(action_restrictions, '{}'::jsonb), 'device.change_ownership');

-- 14. Row level security ---------------------------------------------------------------
SELECT obligarth_private.rls_apply(t::regclass, 'tenant') FROM unnest(ARRAY[
  'obligarth.end_users', 'obligarth.apple_devices', 'obligarth.device_enrollments',
  'obligarth.device_status_items', 'obligarth.device_status_history', 'obligarth.device_apps',
  'obligarth.apple_device_profiles', 'obligarth.device_certificates', 'obligarth.lost_mode_locations',
  'obligarth.assignments',
  'obligarth.device_effective_settings', 'obligarth.mdm_artifacts', 'obligarth.device_artifacts']) AS t;
SELECT obligarth_private.rls_apply('obligarth.policies', 'tenant_shared');
SELECT obligarth_private.rls_apply('obligarth.apps', 'tenant_shared');

SELECT obligarth_private.rls_apply('obligarth.policy_versions', 'custom',
  'versions of a policy: owner tenant, or read through the share of the parent policy');
CREATE POLICY rls_tenant ON obligarth.policy_versions TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant()))
  WITH CHECK (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_shared_read ON obligarth.policy_versions FOR SELECT TO obligarth
  USING (EXISTS (SELECT 1 FROM obligarth.policies p
                 WHERE p.id = policy_versions.policy_id
                   AND p.target_tenant_ids @> ARRAY[(SELECT obligarth.ctx_tenant())]));
CREATE POLICY rls_reader ON obligarth.policy_versions FOR SELECT TO obligarth_reader
  USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[]))
         OR EXISTS (SELECT 1 FROM obligarth.policies p
                    WHERE p.id = policy_versions.policy_id
                      AND p.target_tenant_ids && CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.policy_versions TO obligarth;
GRANT SELECT ON obligarth.policy_versions TO obligarth_reader;

REVOKE ALL ON FUNCTION obligarth.version_num(text), obligarth.ownership_allows(text, text, text),
  obligarth.device_config_rollup(integer[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.version_num(text), obligarth.ownership_allows(text, text, text)
  TO obligarth, obligarth_reader;
GRANT EXECUTE ON FUNCTION obligarth.device_config_rollup(integer[]) TO obligarth;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  // Expand/contract: going back means running image N-1 on this schema, which it tolerates.
  throw new Error('mdm_model_expand cannot be rolled back: restore the backup taken before the upgrade');
}
