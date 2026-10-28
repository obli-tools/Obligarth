import type { Knex } from 'knex';

// =============================================================================
// Remote assistance sessions (P0-15 T1, M1 of the spec; §2, §3, §4.3, §4.4; §0.1, the MSP model of the owners'
// decision of 27/10)
// =============================================================================
//   - remote_sessions (class tenant): one session of remote assistance on a device of the tenant, its whole life
//     (shared/src/mdm/remote.ts: channel, mode, states, reasons of its end; the CHECKs below copy those lists, both
//     change together). Written by server/src/remote only (the state machine, in the tenant's transaction); kept
//     remote_sessions_months after its end (the generic retention, server/src/remote/retention.ts, M3). Who asked is
//     copied at the request (requested_by_name, operator_org: told to the user of the device by its notifications,
//     kept when the account is deleted); the reason and the ticket are optional (§0.1 rule 3); step_up_via keeps how
//     the technician proved the second factor of the opening (or of the last move to the control). No user's consent
//     (§0.1 rule 1): consented_mode is the mode the agent took at /accept, never above the request; the control during
//     a session is granted by the server (escalation_state granted, released). No token in clear: the SHA-256 of the
//     viewer's token (handed once to the requester) and of the agent's one-use stream token. iOS is view only; one
//     open session per device (remote_sessions_open_per_device). The tenant, the device, the channel and who asked
//     never change: the runtime role updates the other columns only. The viewer's token is bound to the console session
//     it was handed to (viewer_session_sha256: SHA-256 of its express session id, §0.1 rule 3): another session of the
//     same account cannot attach the viewer with it.
//   - obligarth.remote_session_stream_lookup(session, agent): the attachment of the bridge agent's stream
//     (GET /agent/v1/remote/<id>/stream, server/src/remote/upgrade.ts), in the 'none' context of the agent surface
//     with the actor i:legacy-agent only (as legacy_agent_lookup): the tenant, the device, the state, the mode and the
//     stream token of the session, only when its device is the agent's (not revoked).
//   - obligarth.remote_session_consume_stream_token(session, agent, sha): same guard; the stream token used once,
//     within its lifetime, while the session is connecting (one UPDATE: no race between two attachments).
//   - legacy_agent_commands_origin_check admits 'remote' (the remote.open of a session, enqueued by
//     server/src/remote/sessions.ts only; MDM_COMMAND_ORIGINS of shared/src/mdm/commands.ts), through the S3 brick
//     widen_in_check (nothing when it is there already).
// obligarth_private.guard_destructive_device_caps() keeps its list of before P0-15: the capabilities mdm:remote_* open
// no cooldown (§0.1 rule 4, the rights of Obliance).
// The counters active_remote_sessions of fleet_daily_snapshot and fleet_hourly_snapshot are left to the contraction
// of the removed agent's columns (testbed 138): not written.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, functions with SET
// search_path = pg_catalog, pg_temp and EXECUTE revoked from PUBLIC, rls_assert_clean() last, a down that raises.
// Runs as obligarth_owner (server-migrate), after legacy_agent_bundled_release.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Remote assistance sessions (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regprocedure('obligarth_private.widen_in_check(regclass, text, text[])') IS NULL
     OR to_regclass('obligarth.legacy_agent_commands') IS NULL
     OR to_regclass('obligarth.legacy_agent_devices') IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'pending_approvals_tenant_id_id_unique')
     OR NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'legacy_agent_commands_tenant_id_id_unique') THEN
    RAISE EXCEPTION 'p015_remote_sessions: apply the RLS migrations, coordination_socle and legacy_agent first';
  END IF;
END $$;

-- 1. remote_sessions ---------------------------------------------------------------------
CREATE TABLE obligarth.remote_sessions (
  id                       uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id                integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id                integer       NOT NULL,
  channel                  varchar(16)   NOT NULL,
  mode                     varchar(8)    NOT NULL,
  state                    varchar(20)   NOT NULL,
  -- Who and why (copied by the server at the request; the reason and the ticket optional).
  requested_by             integer,
  requested_by_name        varchar(100)  NOT NULL,
  requester_side           varchar(8)    NOT NULL,
  operator_org             varchar(120)  NOT NULL,
  controller_name          varchar(200)  NOT NULL,
  approval_id              integer,
  reason                   varchar(200),
  ticket                   varchar(100),
  step_up_via              varchar(16),                             -- StepUpVia of the opening, of the last move to the control
  command_id               uuid,                                    -- legacy_agent_commands.id (remote.open)
  -- Tokens: SHA-256 only (hex).
  viewer_token_sha256      char(64)      NOT NULL,
  viewer_session_sha256    char(64),                                -- the console session the viewer's token is bound to
  stream_token_sha256      char(64),
  stream_token_expires_at  timestamptz,
  stream_token_used_at     timestamptz,
  -- Times.
  created_at               timestamptz   NOT NULL DEFAULT now(),
  delivered_at             timestamptz,
  consented_at             timestamptz,
  started_at               timestamptz,
  ended_at                 timestamptz,
  expires_at               timestamptz   NOT NULL,                  -- deadline of the current state
  max_ends_at              timestamptz,                             -- maximum duration of the session
  -- Mode taken by the agent at /accept, control granted by the server.
  consented_mode           varchar(8),
  escalated_at             timestamptz,
  escalation_state         varchar(10),
  -- End.
  end_reason               varchar(24),
  ended_by                 varchar(10),
  ended_by_user_id         integer,
  -- Measures.
  bytes_down               bigint        NOT NULL DEFAULT 0,
  bytes_up                 bigint        NOT NULL DEFAULT 0,
  input_events             integer       NOT NULL DEFAULT 0,
  agent_capabilities       jsonb,                                   -- RemoteAgentCapabilities (shared), measured at /accept
  CONSTRAINT remote_sessions_pkey PRIMARY KEY (id),
  CONSTRAINT remote_sessions_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT remote_sessions_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT remote_sessions_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT remote_sessions_requested_by_foreign FOREIGN KEY (requested_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT remote_sessions_ended_by_user_foreign FOREIGN KEY (ended_by_user_id)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT remote_sessions_approval_tenant_fk FOREIGN KEY (tenant_id, approval_id)
    REFERENCES obligarth.pending_approvals (tenant_id, id) ON DELETE SET NULL (approval_id),
  CONSTRAINT remote_sessions_command_tenant_fk FOREIGN KEY (tenant_id, command_id)
    REFERENCES obligarth.legacy_agent_commands (tenant_id, id) ON DELETE SET NULL (command_id),
  CONSTRAINT remote_sessions_channel_check CHECK (channel IN ('legacy_agent', 'android', 'apple')),
  CONSTRAINT remote_sessions_mode_check CHECK (mode IN ('view', 'control')),
  CONSTRAINT remote_sessions_state_check CHECK (state IN ('awaiting_approval', 'queued', 'awaiting_consent', 'connecting',
    'live', 'ended', 'expired', 'cancelled', 'failed')),
  CONSTRAINT remote_sessions_requester_side_check CHECK (requester_side IN ('msp', 'client')),
  CONSTRAINT remote_sessions_consented_mode_check CHECK (consented_mode IN ('view', 'control')),
  CONSTRAINT remote_sessions_escalation_state_check CHECK (escalation_state IN ('granted', 'released')),
  CONSTRAINT remote_sessions_end_reason_check CHECK (end_reason IN ('operator', 'projection_denied', 'device_timeout', 'idle',
    'max_duration', 'screen_off_timeout', 'freeze', 'revoked', 'agent_error', 'server_restart', 'approval_denied',
    'approval_expired')),
  CONSTRAINT remote_sessions_ended_by_check CHECK (ended_by IN ('operator', 'user', 'system')),
  CONSTRAINT remote_sessions_step_up_via_check CHECK (step_up_via IN ('trusted_ip', 'totp', 'obligate_totp', 'device_key', 'password')),
  -- Texts of the technician: never blank when given, no control character.
  CONSTRAINT remote_sessions_reason_check CHECK (reason IS NULL OR (btrim(reason) <> '' AND reason !~ '[[:cntrl:]]')),
  CONSTRAINT remote_sessions_ticket_check CHECK (ticket IS NULL OR (btrim(ticket) <> '' AND ticket !~ '[[:cntrl:]]')),
  CONSTRAINT remote_sessions_names_check CHECK (
        btrim(requested_by_name) <> '' AND requested_by_name !~ '[[:cntrl:]]'
    AND btrim(operator_org) <> '' AND operator_org !~ '[[:cntrl:]]'
    AND btrim(controller_name) <> '' AND controller_name !~ '[[:cntrl:]]'),
  CONSTRAINT remote_sessions_viewer_token_check CHECK (viewer_token_sha256 ~ '^[0-9a-f]{64}$'
    AND (viewer_session_sha256 IS NULL OR viewer_session_sha256 ~ '^[0-9a-f]{64}$')),
  -- A stream token has a lifetime; once used, its hash is gone (one use).
  CONSTRAINT remote_sessions_stream_token_check CHECK (
        (stream_token_sha256 IS NULL OR (stream_token_sha256 ~ '^[0-9a-f]{64}$' AND stream_token_expires_at IS NOT NULL))
    AND (stream_token_used_at IS NULL OR stream_token_sha256 IS NULL)),
  -- A final state exactly when ended_at is set; an end has its reason and its author.
  CONSTRAINT remote_sessions_final_check CHECK (
    (state IN ('ended', 'expired', 'cancelled', 'failed')) = (ended_at IS NOT NULL)),
  CONSTRAINT remote_sessions_end_check CHECK (
        (end_reason IS NULL OR ended_at IS NOT NULL)
    AND (ended_by IS NULL OR ended_at IS NOT NULL)
    AND (ended_by_user_id IS NULL OR ended_by IS NOT NULL)
    AND (ended_at IS NULL OR (end_reason IS NOT NULL AND ended_by IS NOT NULL))),
  -- iOS/iPadOS in view only (D13); the mode the agent took never exceeds the request.
  CONSTRAINT remote_sessions_apple_view CHECK (mode = 'view' OR channel <> 'apple'),
  CONSTRAINT remote_sessions_consent_bounded CHECK (consented_mode IS NULL OR mode = 'control' OR consented_mode = 'view'),
  CONSTRAINT remote_sessions_measures_check CHECK (bytes_down >= 0 AND bytes_up >= 0 AND input_events >= 0),
  CONSTRAINT remote_sessions_agent_capabilities_check CHECK (agent_capabilities IS NULL
    OR (jsonb_typeof(agent_capabilities) = 'object' AND octet_length(agent_capabilities::text) <= 2048))
);
-- One open session per device.
CREATE UNIQUE INDEX remote_sessions_open_per_device ON obligarth.remote_sessions (tenant_id, device_id) WHERE ended_at IS NULL;
-- The journal of the tenant (and the purge, M3), of a device; the sweep of the deadlines.
CREATE INDEX remote_sessions_created ON obligarth.remote_sessions (tenant_id, created_at DESC);
CREATE INDEX remote_sessions_device ON obligarth.remote_sessions (tenant_id, device_id, created_at DESC);
CREATE INDEX remote_sessions_expires ON obligarth.remote_sessions (expires_at) WHERE ended_at IS NULL;
SELECT obligarth_private.rls_apply('obligarth.remote_sessions', 'tenant',
  'remote assistance sessions (P0-15): written by server/src/remote only, no token in clear');
-- The tenant, the device, the channel and who asked never change.
REVOKE UPDATE ON obligarth.remote_sessions FROM obligarth;
GRANT UPDATE (mode, state, approval_id, command_id, viewer_token_sha256, viewer_session_sha256, stream_token_sha256, stream_token_expires_at,
  stream_token_used_at, delivered_at, consented_at, started_at, ended_at, expires_at, max_ends_at, consented_mode,
  escalated_at, escalation_state, step_up_via, end_reason, ended_by, ended_by_user_id, bytes_down, bytes_up, input_events,
  agent_capabilities) ON obligarth.remote_sessions TO obligarth;

-- 2. Lookups of the agent's stream (context none, actor i:legacy-agent) ------------------------
CREATE FUNCTION obligarth.remote_session_stream_lookup(p_session uuid, p_agent uuid)
  RETURNS TABLE (tenant_id integer, device_id integer, state text, mode text, stream_token_sha256 text,
                 stream_token_expires_at timestamptz, stream_token_used_at timestamptz)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'i:legacy-agent' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'remote_session_stream_lookup: the agent surface only';
  END IF;
  RETURN QUERY
    SELECT s.tenant_id, s.device_id, s.state::text, s.mode::text, s.stream_token_sha256::text,
           s.stream_token_expires_at, s.stream_token_used_at
      FROM obligarth.remote_sessions s
      JOIN obligarth.legacy_agent_devices a ON a.tenant_id = s.tenant_id AND a.device_id = s.device_id
     WHERE s.id = p_session AND s.channel = 'legacy_agent'
       AND a.agent_id = p_agent AND a.revoked_at IS NULL;
END $$;

CREATE FUNCTION obligarth.remote_session_consume_stream_token(p_session uuid, p_agent uuid, p_sha text)
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_ok boolean;
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'i:legacy-agent' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'remote_session_consume_stream_token: the agent surface only';
  END IF;
  IF p_sha IS NULL OR p_sha !~ '^[0-9a-f]{64}$' THEN
    RETURN false;
  END IF;
  UPDATE obligarth.remote_sessions s
     SET stream_token_used_at = now(), stream_token_sha256 = NULL
    FROM obligarth.legacy_agent_devices a
   WHERE s.id = p_session AND s.channel = 'legacy_agent' AND s.state = 'connecting'
     AND a.tenant_id = s.tenant_id AND a.device_id = s.device_id AND a.agent_id = p_agent AND a.revoked_at IS NULL
     AND s.stream_token_sha256 = p_sha AND s.stream_token_used_at IS NULL AND s.stream_token_expires_at > now()
  RETURNING true INTO v_ok;
  RETURN COALESCE(v_ok, false);
END $$;

REVOKE ALL ON FUNCTION obligarth.remote_session_stream_lookup(uuid, uuid),
  obligarth.remote_session_consume_stream_token(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.remote_session_stream_lookup(uuid, uuid),
  obligarth.remote_session_consume_stream_token(uuid, uuid, text) TO obligarth;
COMMENT ON FUNCTION obligarth.remote_session_stream_lookup(uuid, uuid) IS
  'remote assistance (P0-15): the session of an agent''s stream, its device being the agent''s (context none, i:legacy-agent)';
COMMENT ON FUNCTION obligarth.remote_session_consume_stream_token(uuid, uuid, text) IS
  'remote assistance (P0-15): the one-use stream token of a connecting session consumed (context none, i:legacy-agent)';

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.remote_session_stream_lookup', 'definer',
   'agent surface: session of a stream, device of the agent only (context none, i:legacy-agent)'),
  ('function', 'obligarth.remote_session_consume_stream_token', 'definer',
   'agent surface: one-use stream token of a connecting session (context none, i:legacy-agent)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

-- 3. Origin 'remote' of the bridge agent's queue (S3 brick) ------------------------------------
SELECT obligarth_private.widen_in_check('obligarth.legacy_agent_commands', 'legacy_agent_commands_origin_check', ARRAY['remote']);

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
