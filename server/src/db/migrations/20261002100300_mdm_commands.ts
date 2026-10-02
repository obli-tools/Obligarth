import type { Knex } from 'knex';

// =============================================================================
// Apple integration, part 5: the business command queue (docs: integration-apple-edge §4.6, §8;
// conception §7.2, §7.5)
// =============================================================================
//   - mdm_commands: one command, its exact plist (or its vault seal when it carries a secret), origin,
//     author, delays and submission state; id = the CommandUUID (upper case in the plist and towards
//     apple-edge, toEdgeCommandUuid; compared here by the uuid type, case-insensitive);
//   - mdm_command_targets: one row per device, nine states ordered by obligarth.mdm_target_state_rank()
//     (pending 0 < queued 1 < sent, notnow 2 < expired, cancelled, rejected 3 < acknowledged, error 4);
//   - apple_command_results_inbox: large results waiting for their ingestion;
//   - apple_setup_plans: await-configuration plans (ADE).
// Same columns, types, constraints and names as the specification, written in SQL like the migrations of
// lot A; tenant_id defaults to the context's tenant (rls-tenant §5.4, rule 5); the rank function has a
// SQL-standard body (bound at creation, rule 11b of rls_audit()). The plist check writes the '<?xml' prefix
// with chr(63): never a question mark under Knex (review INT-RC1). Runs as obligarth_owner (server-migrate),
// after apple_integrations; ends with obligarth.rls_assert_clean(). Kept verbatim by String.raw.

const ORIGINS = ['console', 'bulk', 'policy', 'ddm', 'inventory', 'enrollment', 'setup', 'system', 'approval', 'guard'];
const SUBMIT_STATES = ['pending', 'submitted', 'held', 'failed', 'cancelled'];
const TARGET_STATES = ['pending', 'queued', 'sent', 'notnow', 'expired', 'cancelled', 'rejected', 'acknowledged', 'error'];
const PUSH_OUTCOMES = ['sent', 'deferred', 'disabled', 'error', 'not_requested'];
const SETUP_STATES = ['running', 'configured', 'timed_out', 'cancelled'];
// coffre-secrets §4.1: v1:<DEK uuid>:<iv>:<ct>:<tag>
const SEALED_RE =
  '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$';

const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

const UP = String.raw`-- =============================================================================
-- Apple integration, part 5: business command queue (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.tenant_apple_edge') IS NULL THEN
    RAISE EXCEPTION 'mdm_commands: apply the RLS migrations and apple_tenants first';
  END IF;
END $$;

-- Rank of a target state (integration I2, file-durable §7.5): a later state never goes back.
CREATE FUNCTION obligarth.mdm_target_state_rank(p_state text) RETURNS smallint
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN (CASE p_state
            WHEN 'pending' THEN 0 WHEN 'queued' THEN 1 WHEN 'sent' THEN 2 WHEN 'notnow' THEN 2
            WHEN 'expired' THEN 3 WHEN 'cancelled' THEN 3 WHEN 'rejected' THEN 3
            WHEN 'acknowledged' THEN 4 WHEN 'error' THEN 4 END)::smallint;
REVOKE ALL ON FUNCTION obligarth.mdm_target_state_rank(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.mdm_target_state_rank(text) TO obligarth, obligarth_reader;

CREATE TABLE obligarth.mdm_commands (
  id                  uuid          NOT NULL,              -- = CommandUUID (upper-case in the plist)
  tenant_id           integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  batch_id            uuid,                                -- per-device commands of one request
  platform            varchar(16)   NOT NULL DEFAULT 'apple',
  request_type        varchar(64)   NOT NULL,
  params              jsonb         NOT NULL DEFAULT '{}', -- validated parameters, never a secret
  plist               text,                                -- exact UTF-8 bytes submitted (NULL when sealed)
  plist_enc           text,                                -- vault seal when the plist carries a secret
  plist_sha256        varchar(64)   NOT NULL,
  origin              varchar(16)   NOT NULL,
  actor               varchar(70)   NOT NULL,              -- 'u:<id>' | 'j:<queue>' | 'i:<name>'
  requested_by        integer,
  reason              varchar(500),
  ticket              varchar(100),
  approval_id         integer,                             -- pending_approvals.id
  guard_action_uuid   uuid,                                -- pending_actions.uuid (audit-durci §10): guarded actions only
  idempotency_key     varchar(200),
  push                boolean       NOT NULL DEFAULT true,
  not_before          timestamptz,                         -- spreading and technical postponements
  expires_at          timestamptz   NOT NULL,
  submit_state        varchar(16)   NOT NULL DEFAULT 'pending',
  submit_attempts     integer       NOT NULL DEFAULT 0,
  last_submit_error   varchar(64),
  submitted_at        timestamptz,
  created_at          timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT mdm_commands_pkey PRIMARY KEY (id),
  CONSTRAINT mdm_commands_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT mdm_commands_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT mdm_commands_requested_by_foreign FOREIGN KEY (requested_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT mdm_commands_platform_check CHECK (platform IN ('apple')),
  CONSTRAINT mdm_commands_origin_check CHECK (origin IN (${list(ORIGINS)})),
  CONSTRAINT mdm_commands_submit_state_check CHECK (submit_state IN (${list(SUBMIT_STATES)})),
  -- chr(63): never a '?' under Knex (review INT-RC1)
  CONSTRAINT mdm_commands_plist_check
    CHECK ((plist IS NULL) <> (plist_enc IS NULL) AND (plist IS NULL OR left(plist, 5) = '<' || chr(63) || 'xml')),
  CONSTRAINT mdm_commands_plist_enc_sealed CHECK (plist_enc IS NULL OR plist_enc ~ '${SEALED_RE}')
);
CREATE UNIQUE INDEX mdm_commands_idempotency ON obligarth.mdm_commands (tenant_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE INDEX mdm_commands_submit ON obligarth.mdm_commands (submit_state, not_before)
  WHERE submit_state IN ('pending', 'held');
CREATE INDEX mdm_commands_created ON obligarth.mdm_commands (tenant_id, created_at);
SELECT obligarth_private.rls_apply('obligarth.mdm_commands', 'tenant');

CREATE TABLE obligarth.mdm_command_targets (
  command_id           uuid          NOT NULL,
  tenant_id            integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id            integer       NOT NULL,
  enrollment_id        text          NOT NULL,             -- snapshot: the events carry it
  state                varchar(16)   NOT NULL DEFAULT 'pending',
  state_event_at       timestamptz   NOT NULL,
  hold_reason          varchar(24),                        -- frozen | edge_unavailable
  reject_code          varchar(48),
  last_status          varchar(24),                        -- Acknowledged | Error | CommandFormatError | NotNow
  error_chain          jsonb,                              -- 8 KiB at most
  result_summary       jsonb,                              -- 4 KiB at most
  push_outcome         varchar(16),
  pushed_at            timestamptz,
  push_count           integer       NOT NULL DEFAULT 0,
  queued_at            timestamptz,
  delivered_at         timestamptz,
  completed_at         timestamptz,
  cancel_requested_at  timestamptz,
  CONSTRAINT mdm_command_targets_pkey PRIMARY KEY (command_id, device_id),
  CONSTRAINT mdm_command_targets_state_check CHECK (state IN (${list(TARGET_STATES)})),
  CONSTRAINT mdm_command_targets_push_outcome_check CHECK (push_outcome IS NULL OR push_outcome IN (${list(PUSH_OUTCOMES)})),
  CONSTRAINT mdm_command_targets_command_id_tenant_fk FOREIGN KEY (tenant_id, command_id)
    REFERENCES obligarth.mdm_commands (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT mdm_command_targets_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX mdm_command_targets_enrollment ON obligarth.mdm_command_targets (command_id, enrollment_id);
CREATE INDEX mdm_command_targets_device ON obligarth.mdm_command_targets (tenant_id, device_id, state);
CREATE INDEX mdm_command_targets_open ON obligarth.mdm_command_targets (tenant_id, state, pushed_at)
  WHERE state IN ('pending', 'queued', 'sent', 'notnow');
SELECT obligarth_private.rls_apply('obligarth.mdm_command_targets', 'tenant');

CREATE TABLE obligarth.apple_command_results_inbox (
  event_id         uuid          NOT NULL,                 -- apple_edge.outbox event_id
  tenant_id        integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  command_id       uuid          NOT NULL,
  device_id        integer       NOT NULL,
  request_type     varchar(64)   NOT NULL,
  status           varchar(24)   NOT NULL,
  occurred_at      timestamptz   NOT NULL,
  result           jsonb         NOT NULL,                 -- personal data: deleted once ingested
  attempts         integer       NOT NULL DEFAULT 0,
  last_error_code  varchar(64),
  created_at       timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT apple_command_results_inbox_pkey PRIMARY KEY (event_id),
  CONSTRAINT apple_command_results_inbox_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
SELECT obligarth_private.rls_apply('obligarth.apple_command_results_inbox', 'tenant');

CREATE TABLE obligarth.apple_setup_plans (
  device_id                     integer       NOT NULL,
  tenant_id                     integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  state                         varchar(16)   NOT NULL,    -- running | configured | timed_out | cancelled
  command_ids                   uuid[]        NOT NULL DEFAULT '{}',
  device_configured_command_id  uuid,
  started_at                    timestamptz   NOT NULL,
  deadline_at                   timestamptz   NOT NULL,
  completed_at                  timestamptz,
  outcome_code                  varchar(32),
  CONSTRAINT apple_setup_plans_pkey PRIMARY KEY (device_id),
  CONSTRAINT apple_setup_plans_state_check CHECK (state IN (${list(SETUP_STATES)})),
  CONSTRAINT apple_setup_plans_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
SELECT obligarth_private.rls_apply('obligarth.apple_setup_plans', 'tenant');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
