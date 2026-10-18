import type { Knex } from 'knex';

// =============================================================================
// Android, part 4a: commands (section 11, AN50) and operator controls of a device (lot AN-D1)
// =============================================================================
//   - android_commands (class tenant): one Android command for one device (section 11.1: one target per command,
//     batch_id groups a request on several devices): the AMAPI Command body WITHOUT any secret (amapi_command), the
//     sealed part of RESET_PASSWORD (secret_enc, wiped in the transaction that records the operation), the AN50 mark
//     written in a committed transaction before issueCommand (amapi_submit_started_at), the operation Google returned,
//     the states of section 11.3, the hold of the submission (frozen, google_unavailable, gateway_cap) and the polling
//     schedule. A second command of the same type to a device that has one pending or sent is refused (unique index:
//     409 commandAlreadyPending, AN-RC4);
//   - android_device_controls (class tenant): the operator's disabling of a device (mdm.android_disable, AN30): a
//     policy push never reactivates a device the operator disabled (review AN-C1b, R8);
//   - function android_commands_due() (SECURITY DEFINER, context none of android.maintenance): tenants with
//     commands to submit again, to poll, to expire, held commands to resume, or reset-password secrets to sweep.
// New tables and function only. The final model (section 4.5, migration 4: mdm_commands and mdm_command_targets
// widened to the platform android, view android_operations_open) ALTERs existing tables: it is written at the
// junction AN-A2/AN-P on the final CHECKs of lot C, and these rows move there (column names kept on purpose).
// Runs as obligarth_owner (server-migrate); ends with obligarth.rls_assert_clean(). No question mark in the SQL.

const TYPES = ['LOCK', 'RESET_PASSWORD', 'REBOOT', 'START_LOST_MODE', 'STOP_LOST_MODE', 'WIPE', 'RELINQUISH_OWNERSHIP', 'CLEAR_APP_DATA'];
const STATES = ['pending', 'sent', 'acknowledged', 'error', 'cancelled', 'expired', 'rejected'];
const SUBMIT_STATES = ['pending', 'submitted', 'held', 'failed', 'cancelled'];
const HOLD_REASONS = ['frozen', 'google_unavailable', 'gateway_cap'];
const ORIGINS = ['console', 'guard', 'system'];
// coffre-secrets §4.1: v1:<DEK uuid>:<iv>:<ct>:<tag>
const SEALED_RE =
  '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$';
const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

const UP = String.raw`-- =============================================================================
-- Android, part 4a: commands and operator controls (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_devices') IS NULL OR to_regclass('obligarth.tenant_guard_settings') IS NULL THEN
    RAISE EXCEPTION 'android_commands: apply android_devices and the guard migrations first';
  END IF;
END $$;

-- ── android_commands ───────────────────────────────────────────────────────────
CREATE TABLE obligarth.android_commands (
  id                       uuid          NOT NULL,              -- v4, or jobIdFor('mdm.command', '<action>:<device>') for the engine
  tenant_id                integer       NOT NULL DEFAULT obligarth.ctx_tenant()
                             REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id                integer       NOT NULL,
  enterprise_id            integer       NOT NULL,
  enrollment_id            varchar(255)  NOT NULL,              -- AMAPI device name at the creation (channel identity)
  batch_id                 uuid          NOT NULL,
  request_type             varchar(32)   NOT NULL,
  params                   jsonb         NOT NULL DEFAULT '{}', -- validated parameters, never a secret
  amapi_command            jsonb         NOT NULL,              -- Command body without any secret
  secret_enc               text,                                -- sealed newPassword (RESET_PASSWORD), wiped once Google answered
  origin                   varchar(16)   NOT NULL,
  actor                    varchar(70)   NOT NULL,              -- 'u:<id>' | 'j:<queue>'
  requested_by             integer       REFERENCES obligarth.users (id) ON DELETE SET NULL,
  reason                   varchar(500),
  guard_action_uuid        uuid,                                -- pending_actions.uuid of a guarded action
  guard_action_key         varchar(100),
  idempotency_key          varchar(200),
  expires_at               timestamptz   NOT NULL,
  submit_state             varchar(16)   NOT NULL DEFAULT 'pending',
  hold_reason              varchar(24),
  submit_attempts          integer       NOT NULL DEFAULT 0,
  last_submit_error        varchar(64),
  amapi_submit_started_at  timestamptz,                         -- AN50: committed before issueCommand
  amapi_operation          varchar(255),                        -- enterprises/{e}/devices/{d}/operations/{o}
  amapi_error_code         varchar(32),                         -- CommandErrorCode
  state                    varchar(16)   NOT NULL DEFAULT 'pending',
  reject_code              varchar(48),
  state_event_at           timestamptz   NOT NULL DEFAULT now(),
  delivered_at             timestamptz,
  completed_at             timestamptz,
  cancel_requested_at      timestamptz,
  next_poll_at             timestamptz,
  poll_count               smallint      NOT NULL DEFAULT 0,
  created_at               timestamptz   NOT NULL DEFAULT now(),
  updated_at               timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT android_commands_pkey PRIMARY KEY (id),
  CONSTRAINT android_commands_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT android_commands_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_commands_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
    REFERENCES obligarth.android_enterprises (tenant_id, id),
  CONSTRAINT android_commands_type_check CHECK (request_type IN (${list(TYPES)})),
  CONSTRAINT android_commands_state_check CHECK (state IN (${list(STATES)})),
  CONSTRAINT android_commands_submit_state_check CHECK (submit_state IN (${list(SUBMIT_STATES)})),
  CONSTRAINT android_commands_hold_check CHECK ((submit_state = 'held') = (hold_reason IS NOT NULL)
    AND (hold_reason IS NULL OR hold_reason IN (${list(HOLD_REASONS)}))),
  CONSTRAINT android_commands_origin_check CHECK (origin IN (${list(ORIGINS)})),
  CONSTRAINT android_commands_guard_check CHECK ((origin = 'guard') = (guard_action_uuid IS NOT NULL)),
  CONSTRAINT android_commands_body_check CHECK (jsonb_typeof(amapi_command) = 'object'
    AND amapi_command->>'type' = request_type AND amapi_command->'newPassword' IS NULL),
  CONSTRAINT android_commands_params_check CHECK (jsonb_typeof(params) = 'object' AND params->'newPassword' IS NULL),
  CONSTRAINT android_commands_secret_enc_sealed CHECK (secret_enc IS NULL OR secret_enc ~ '${SEALED_RE}'),
  -- the sealed password exists only for a RESET_PASSWORD not yet answered by Google
  CONSTRAINT android_commands_secret_scope CHECK (secret_enc IS NULL
    OR (request_type = 'RESET_PASSWORD' AND state = 'pending' AND amapi_operation IS NULL)),
  CONSTRAINT android_commands_operation_check CHECK (amapi_operation IS NULL
    OR amapi_operation ~ '^enterprises/[A-Za-z0-9_-]{1,100}/devices/[A-Za-z0-9_-]{1,100}/operations/[A-Za-z0-9_-]{1,100}$'),
  CONSTRAINT android_commands_sent_check CHECK (state <> 'sent' OR (amapi_operation IS NOT NULL AND delivered_at IS NOT NULL)),
  CONSTRAINT android_commands_enrollment_check
    CHECK (enrollment_id ~ '^enterprises/[A-Za-z0-9_-]{1,100}/devices/[A-Za-z0-9_-]{1,100}$')
);
-- AN-RC4: one open command of a type per device (409 commandAlreadyPending).
CREATE UNIQUE INDEX android_commands_open_type ON obligarth.android_commands (tenant_id, device_id, request_type)
  WHERE state IN ('pending', 'sent');
CREATE UNIQUE INDEX android_commands_idempotency ON obligarth.android_commands (tenant_id, idempotency_key, device_id)
  WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX android_commands_operation ON obligarth.android_commands (amapi_operation) WHERE amapi_operation IS NOT NULL;
CREATE INDEX android_commands_device ON obligarth.android_commands (tenant_id, device_id, created_at);
CREATE INDEX android_commands_guard ON obligarth.android_commands (tenant_id, guard_action_uuid) WHERE guard_action_uuid IS NOT NULL;
CREATE INDEX android_commands_open ON obligarth.android_commands (state, next_poll_at, expires_at) WHERE state IN ('pending', 'sent');
SELECT obligarth_private.rls_apply('obligarth.android_commands', 'tenant', 'android: commands (section 11), moved to mdm_commands at the junction');

-- ── android_device_controls ────────────────────────────────────────────────────
CREATE TABLE obligarth.android_device_controls (
  device_id          integer      PRIMARY KEY,
  tenant_id          integer      NOT NULL DEFAULT obligarth.ctx_tenant()
                       REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  disabled_at        timestamptz  NOT NULL DEFAULT now(),
  disabled_by        integer      REFERENCES obligarth.users (id) ON DELETE SET NULL,
  guard_action_uuid  uuid,
  CONSTRAINT android_device_controls_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
SELECT obligarth_private.rls_apply('obligarth.android_device_controls', 'tenant', 'android: devices disabled by the operator (AN30)');

-- Tenants with command work, for android.maintenance (context 'none'; tenant ids and booleans only):
--   submit_due  pending, not held, older than 2 minutes (a lost job, or a submission interrupted after its mark);
--   poll_due    sent, next poll due;
--   expire_due  pending or sent past their expiry;
--   resume_due  held for google_unavailable for a minute, or for frozen while the tenant is no longer frozen;
--   secrets_due reset-password secrets of the vault older than 5 minutes (destroyed once no open action holds them).
CREATE FUNCTION obligarth.android_commands_due()
  RETURNS TABLE (tenant_id integer, submit_due boolean, poll_due boolean, expire_due boolean, resume_due boolean, secrets_due boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.maintenance' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_commands_due: context none of the maintenance required';
  END IF;
  RETURN QUERY
  WITH c AS (
    SELECT c.tenant_id,
           bool_or(c.state = 'pending' AND c.submit_state = 'pending' AND c.updated_at < now() - interval '2 minutes') AS submit_due,
           bool_or(c.state = 'sent' AND c.next_poll_at <= now()) AS poll_due,
           bool_or(c.state IN ('pending', 'sent') AND c.expires_at <= now()) AS expire_due,
           bool_or(c.state = 'pending' AND c.submit_state = 'held' AND (
             (c.hold_reason = 'google_unavailable' AND c.updated_at < now() - interval '1 minute')
             OR (c.hold_reason = 'frozen' AND NOT EXISTS (
                   SELECT 1 FROM obligarth.tenant_guard_settings g WHERE g.tenant_id = c.tenant_id AND g.frozen_at IS NOT NULL)))) AS resume_due
      FROM obligarth.android_commands c
     WHERE c.state IN ('pending', 'sent')
     GROUP BY c.tenant_id
  ), s AS (
    SELECT DISTINCT t.tenant_id FROM obligarth.tenant_secrets t
     WHERE t.purpose = 'android.reset_password' AND t.created_at < now() - interval '5 minutes'
  )
  SELECT coalesce(c.tenant_id, s.tenant_id),
         coalesce(c.submit_due, false), coalesce(c.poll_due, false), coalesce(c.expire_due, false), coalesce(c.resume_due, false),
         s.tenant_id IS NOT NULL
    FROM c FULL JOIN s ON s.tenant_id = c.tenant_id
   WHERE coalesce(c.submit_due, false) OR coalesce(c.poll_due, false) OR coalesce(c.expire_due, false)
      OR coalesce(c.resume_due, false) OR s.tenant_id IS NOT NULL
   ORDER BY 1;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_commands_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_commands_due() TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.android_commands_due', 'definer', 'android maintenance: tenants with commands to submit, poll, expire, resume')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
