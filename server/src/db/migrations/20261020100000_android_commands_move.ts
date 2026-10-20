import type { Knex } from 'knex';

// =============================================================================
// Android, migration 4 completed (android-amapi §4.5, §11.1, §11.3; lot AN-D): the Android commands join the queue
// =============================================================================
// android_junction (lot AN-A2) widened mdm_commands and mdm_command_targets to the platform android (amapi_command,
// sealed secret_enc, the AMAPI operation, its error code and the AN50 mark); the rows still lived in android_commands
// (part 4a, lot AN-D1). This migration ends the move:
//   - mdm_commands: an Android row is one AMAPI command (one target, push false, its body without any secret, no
//     newPassword in its params); secret_enc exists only for an Android RESET_PASSWORD; (tenant_id, id, request_type)
//     is unique so that a target can carry the type of its command (composite foreign key);
//   - mdm_command_targets: amapi_request_type (the type of an Android command, equal to its command's by the foreign
//     key: one open command of a type per device, AN-RC4, 409 commandAlreadyPending), the polling schedule of an
//     operation sent (amapi_next_poll_at, amapi_poll_count), the hold reasons of both platforms (COH-9: frozen,
//     edge_unavailable, google_unavailable, gateway_cap), the checks of a target 'sent' and of the channel identity
//     (the AMAPI device name);
//   - the view android_operations_open of §4.5;
//   - the rows of android_commands move (same ids; the idempotency key of a device is stored 'amapi:<device>:<key>',
//     the unique key of mdm_commands being per tenant and an Android request writing one command per device);
//     enterprise_id is read again from the device name (enterprises/<e>/devices/<d>) and guard_action_key from the
//     action itself; android_commands is dropped;
//   - the sealed newPassword of a RESET_PASSWORD not yet answered by Google cannot be opened here (its AAD names
//     android_commands): it waits in android_command_moved_secrets (class tenant) until the boot backfill of the vault
//     seals it again for mdm_commands.secret_enc (legacy source 'custom' of that column, modules/android.ts); the
//     submission waits for it; a seal that cannot be opened rejects the command (secret_lost), never sends it
//     without its password;
//   - android_commands_due() reads the queue.
// android_device_controls (the operator's disabling, AN30) is not a command: it stays as it is.
// Runs as obligarth_owner (server-migrate) after legacy_agent; ends with obligarth.rls_assert_clean(). No question
// mark in the SQL (knex.raw would bind it); kept verbatim by String.raw.
// =============================================================================

const TYPES = ['LOCK', 'RESET_PASSWORD', 'REBOOT', 'START_LOST_MODE', 'STOP_LOST_MODE', 'WIPE', 'RELINQUISH_OWNERSHIP', 'CLEAR_APP_DATA'];
const HOLD_REASONS = ['frozen', 'edge_unavailable', 'google_unavailable', 'gateway_cap'];
// coffre-secrets §4.1: v1:<DEK uuid>:<iv>:<ct>:<tag>
const SEALED_RE =
  '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$';
const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

const UP = String.raw`-- =============================================================================
-- Android, migration 4 completed: the commands move to the queue (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_commands') IS NULL OR to_regclass('obligarth.legacy_agent_commands') IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'obligarth.mdm_command_targets'::regclass
                     AND attname = 'amapi_operation' AND NOT attisdropped) THEN
    RAISE EXCEPTION 'android_commands_move: apply android_junction and legacy_agent first';
  END IF;
END $$;

-- ── 1. The queue ──────────────────────────────────────────────────────────────
ALTER TABLE obligarth.mdm_commands
  ADD CONSTRAINT mdm_commands_tenant_id_id_type_unique UNIQUE (tenant_id, id, request_type),
  ADD CONSTRAINT mdm_commands_android_check CHECK (platform <> 'android' OR (
        request_type IN (${list(TYPES)}) AND amapi_command->>'type' = request_type
        AND jsonb_typeof(params) = 'object' AND params->'newPassword' IS NULL AND NOT push)),
  -- the sealed password exists only for an Android RESET_PASSWORD (wiped once Google answered, or at its end)
  ADD CONSTRAINT mdm_commands_secret_scope CHECK (secret_enc IS NULL OR (platform = 'android' AND request_type = 'RESET_PASSWORD'));
CREATE INDEX mdm_commands_guard ON obligarth.mdm_commands (tenant_id, guard_action_uuid) WHERE guard_action_uuid IS NOT NULL;

ALTER TABLE obligarth.mdm_command_targets
  ADD COLUMN amapi_request_type  varchar(32),                     -- the type of an Android command (NULL for Apple)
  ADD COLUMN amapi_next_poll_at  timestamptz,                     -- next read of an operation sent
  ADD COLUMN amapi_poll_count    smallint     NOT NULL DEFAULT 0,
  ADD CONSTRAINT mdm_command_targets_hold_reason_check
    CHECK (hold_reason IS NULL OR hold_reason IN (${list(HOLD_REASONS)})),
  ADD CONSTRAINT mdm_command_targets_amapi_type_fk FOREIGN KEY (tenant_id, command_id, amapi_request_type)
    REFERENCES obligarth.mdm_commands (tenant_id, id, request_type) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT mdm_command_targets_amapi_type_check
    CHECK (amapi_request_type IS NULL OR amapi_request_type IN (${list(TYPES)})),
  -- the AMAPI columns belong to Android targets only
  ADD CONSTRAINT mdm_command_targets_amapi_check CHECK (amapi_request_type IS NOT NULL
    OR (amapi_operation IS NULL AND amapi_submit_started_at IS NULL AND amapi_error_code IS NULL AND amapi_next_poll_at IS NULL)),
  ADD CONSTRAINT mdm_command_targets_amapi_sent_check
    CHECK (amapi_request_type IS NULL OR state <> 'sent' OR (amapi_operation IS NOT NULL AND delivered_at IS NOT NULL)),
  ADD CONSTRAINT mdm_command_targets_amapi_enrollment_check CHECK (amapi_request_type IS NULL
    OR enrollment_id ~ '^enterprises/[A-Za-z0-9_-]{1,100}/devices/[A-Za-z0-9_-]{1,100}$');
-- AN-RC4: one open command of a type per Android device (409 commandAlreadyPending).
CREATE UNIQUE INDEX mdm_command_targets_amapi_open_type ON obligarth.mdm_command_targets (tenant_id, device_id, amapi_request_type)
  WHERE amapi_request_type IS NOT NULL AND state IN ('pending', 'sent');
CREATE INDEX mdm_command_targets_amapi_poll ON obligarth.mdm_command_targets (tenant_id, amapi_next_poll_at)
  WHERE amapi_request_type IS NOT NULL AND state = 'sent';

-- §4.5: the operations waiting for their end (polling, console).
CREATE VIEW obligarth.android_operations_open WITH (security_invoker = true) AS
  SELECT t.tenant_id, t.command_id, t.device_id, t.amapi_operation, t.state, t.delivered_at, c.request_type, c.expires_at
    FROM obligarth.mdm_command_targets t JOIN obligarth.mdm_commands c ON c.tenant_id = t.tenant_id AND c.id = t.command_id
   WHERE c.platform = 'android' AND t.state = 'sent';
REVOKE ALL ON obligarth.android_operations_open FROM PUBLIC;
GRANT SELECT ON obligarth.android_operations_open TO obligarth, obligarth_reader;

-- ── 2. The seals waiting for their new place ──────────────────────────────────
CREATE TABLE obligarth.android_command_moved_secrets (
  command_id  uuid         NOT NULL,
  tenant_id   integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  secret_enc  text         NOT NULL,                          -- sealed for android_commands.secret_enc (its AAD)
  moved_at    timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT android_command_moved_secrets_pkey PRIMARY KEY (command_id),
  CONSTRAINT android_command_moved_secrets_command_fk FOREIGN KEY (tenant_id, command_id)
    REFERENCES obligarth.mdm_commands (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_command_moved_secrets_sealed CHECK (secret_enc ~ '${SEALED_RE}')
);
SELECT obligarth_private.rls_apply('obligarth.android_command_moved_secrets', 'tenant',
  'android: sealed newPassword moved from android_commands, sealed again by the boot backfill of the vault');

-- ── 3. The rows ───────────────────────────────────────────────────────────────
INSERT INTO obligarth.mdm_commands (id, tenant_id, batch_id, platform, request_type, params, plist, plist_enc, plist_sha256,
    origin, actor, requested_by, reason, guard_action_uuid, idempotency_key, push, expires_at, submit_state, submit_attempts,
    last_submit_error, submitted_at, created_at, updated_at, amapi_command, secret_enc)
  SELECT a.id, a.tenant_id, a.batch_id, 'android', a.request_type, a.params, NULL, NULL, NULL,
         a.origin, a.actor, a.requested_by, a.reason, a.guard_action_uuid,
         CASE WHEN a.idempotency_key IS NULL THEN NULL ELSE left('amapi:' || a.device_id || ':' || a.idempotency_key, 200) END,
         false, a.expires_at, a.submit_state, a.submit_attempts, a.last_submit_error,
         CASE WHEN a.amapi_operation IS NOT NULL THEN a.delivered_at END, a.created_at, a.updated_at, a.amapi_command, NULL
    FROM obligarth.android_commands a;
INSERT INTO obligarth.mdm_command_targets (command_id, tenant_id, device_id, enrollment_id, state, state_event_at, hold_reason,
    reject_code, delivered_at, completed_at, cancel_requested_at, amapi_operation, amapi_error_code, amapi_submit_started_at,
    amapi_request_type, amapi_next_poll_at, amapi_poll_count)
  SELECT a.id, a.tenant_id, a.device_id, a.enrollment_id, a.state, a.state_event_at, a.hold_reason,
         a.reject_code, a.delivered_at, a.completed_at, a.cancel_requested_at, a.amapi_operation, a.amapi_error_code,
         a.amapi_submit_started_at, a.request_type, a.next_poll_at, a.poll_count
    FROM obligarth.android_commands a;
INSERT INTO obligarth.android_command_moved_secrets (command_id, tenant_id, secret_enc)
  SELECT a.id, a.tenant_id, a.secret_enc FROM obligarth.android_commands a WHERE a.secret_enc IS NOT NULL;

-- ── 4. The tenants with command work (context none of android.maintenance) ───
CREATE OR REPLACE FUNCTION obligarth.android_commands_due()
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
    SELECT t.tenant_id,
           bool_or(t.state = 'pending' AND m.submit_state = 'pending' AND m.updated_at < now() - interval '2 minutes') AS submit_due,
           bool_or(t.state = 'sent' AND t.amapi_next_poll_at <= now()) AS poll_due,
           bool_or(m.expires_at <= now()) AS expire_due,
           bool_or(t.state = 'pending' AND m.submit_state = 'held' AND (
             (t.hold_reason = 'google_unavailable' AND m.updated_at < now() - interval '1 minute')
             OR (t.hold_reason = 'frozen' AND NOT EXISTS (
                   SELECT 1 FROM obligarth.tenant_guard_settings g WHERE g.tenant_id = t.tenant_id AND g.frozen_at IS NOT NULL)))) AS resume_due
      FROM obligarth.mdm_command_targets t
      JOIN obligarth.mdm_commands m ON m.tenant_id = t.tenant_id AND m.id = t.command_id
     WHERE t.amapi_request_type IS NOT NULL AND t.state IN ('pending', 'sent')
     GROUP BY t.tenant_id
  ), s AS (
    SELECT DISTINCT x.tenant_id FROM obligarth.tenant_secrets x
     WHERE x.purpose = 'android.reset_password' AND x.created_at < now() - interval '5 minutes'
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

-- ── 5. android_commands leaves ────────────────────────────────────────────────
DROP TABLE obligarth.android_commands;
DELETE FROM obligarth_private.rls_registry WHERE object_kind = 'table' AND object_name = 'obligarth.android_commands';

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
