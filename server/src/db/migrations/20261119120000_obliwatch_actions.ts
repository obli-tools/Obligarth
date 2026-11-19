import type { Knex } from 'knex';

// =============================================================================
// Obliwatch integration, lot L5 (brief GTH-04, GTH-05): the action requests of Obliwatch and the push of their results
// =============================================================================
//   - obliwatch_action_requests  tenant: one request of an Obliwatch analyst on ONE device (lost mode on or off, location,
//                                sound, lock). Owner decision Q-L5a: no human approval, a valid request is executed at once
//                                (a guarded action scheduled without delay, pending_action_uuid; or a command of the queue,
//                                command_id). state: accepted → executing → done | failed | refused | expired | cancelled
//                                ('awaiting_approval' and 'approved' are admitted by the check for the brief's
//                                enumeration and never written). seq: one per transition. params never hold the phone
//                                number of the lost mode (it lives in the command and the guarded action only); result
//                                never holds a coordinate (accuracy bucket only). Purged 90 days after it closed.
//   - obliwatch_action_events    tenant: one row per transition of a request, the outbox of the push of the results
//                                (POST {obliwatch}/api/ingest/v1/action-results): push_state pending → sent | skipped |
//                                dead, attempts, next_attempt_at (the retries of 72 hours carried by the row, as
//                                device_signal_transitions of lot L3). Purged 30 days after it ended (dead: 90 days).
//   - tenant_obliwatch_settings  peer request AR-55/AR-57 (decision of the owner of Obliwatch): the nominative view of the
//                                AI apps is ON by default for a tenant that consents to be read. The tenants that consent
//                                already get it now (one UPDATE of a table of one row per tenant); nominative_ai_apps_
//                                opted_out remembers a tenant that turned it off on purpose, so that turning the read
//                                access on again does not turn it back on (integrations/obliwatch/consent.ts). A tenant
//                                whose journal shows it turned the view off on purpose before (its last
//                                obliwatch.consent.changed that changed nominativeAiApps set it to false) is marked
//                                opted out first and keeps it off; each tenant turned on gets its critical entry
//                                obliwatch.consent.changed (actor the migration, changes.nominativeAiApps false → true)
//                                in its chain (obligarth.audit_append, as the retention purge writes its own).
// Additive, re-runnable (IF NOT EXISTS, a column with a constant default: no row rewritten), safe on a live database at
// start (lock_timeout: fail fast rather than queue the writers). Nothing writes the two tables while
// OBLIWATCH_INTEGRATION is not 'on' and the tenant has not consented to the actions.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean()
// last, a down that raises. Runs as obligarth_owner (server-migrate).
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Obliwatch integration: action requests, outbox of their results, nominative AI apps by default (as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
  IF to_regclass('obligarth.devices') IS NULL OR to_regclass('obligarth.tenant_obliwatch_settings') IS NULL THEN
    RAISE EXCEPTION 'obliwatch_actions: apply the obliwatch_integration migration first';
  END IF;
END $$;

-- 1. The action requests ------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obligarth.obliwatch_action_requests (
  id                   uuid          NOT NULL,
  tenant_id            integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id            integer       NOT NULL,
  device_uuid          uuid          NOT NULL,
  action               text          NOT NULL,
  channel              text          NOT NULL,
  path                 text          NOT NULL,
  state                text          NOT NULL DEFAULT 'accepted',
  seq                  integer       NOT NULL DEFAULT 1,
  requested_by         integer       NOT NULL,
  requester_label      text,
  azp                  text          NOT NULL,
  reason               text          NOT NULL,
  incident_ref         text          NOT NULL,
  params               jsonb         NOT NULL DEFAULT '{}'::jsonb,
  pending_action_uuid  uuid,
  command_id           uuid,
  result               jsonb,
  code                 text,
  expires_at           timestamptz   NOT NULL,
  created_at           timestamptz   NOT NULL DEFAULT now(),
  updated_at           timestamptz   NOT NULL DEFAULT now(),
  closed_at            timestamptz,
  CONSTRAINT obliwatch_action_requests_pkey PRIMARY KEY (id),
  CONSTRAINT obliwatch_action_requests_tenant_id_key UNIQUE (tenant_id, id),
  CONSTRAINT obliwatch_action_requests_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT obliwatch_action_requests_action_check
    CHECK (action IN ('lost_mode_enable', 'lost_mode_disable', 'device_location', 'play_sound', 'device_lock')),
  CONSTRAINT obliwatch_action_requests_channel_check CHECK (channel IN ('apple_mdm', 'amapi', 'legacy_agent')),
  CONSTRAINT obliwatch_action_requests_path_check CHECK (path IN ('guard', 'command')),
  CONSTRAINT obliwatch_action_requests_state_check CHECK (state IN ('accepted', 'awaiting_approval', 'approved', 'executing',
    'done', 'failed', 'refused', 'expired', 'cancelled')),
  CONSTRAINT obliwatch_action_requests_seq_check CHECK (seq >= 1),
  CONSTRAINT obliwatch_action_requests_label_check CHECK (requester_label IS NULL OR length(requester_label) <= 200),
  CONSTRAINT obliwatch_action_requests_azp_check CHECK (azp ~ '^[a-z][a-z0-9_-]{0,63}$'),
  CONSTRAINT obliwatch_action_requests_reason_check CHECK (length(reason) BETWEEN 10 AND 500),
  CONSTRAINT obliwatch_action_requests_incident_check CHECK (length(incident_ref) BETWEEN 1 AND 200),
  CONSTRAINT obliwatch_action_requests_params_check CHECK (jsonb_typeof(params) = 'object' AND pg_column_size(params) <= 2048),
  CONSTRAINT obliwatch_action_requests_result_check CHECK (result IS NULL OR (jsonb_typeof(result) = 'object' AND pg_column_size(result) <= 1024)),
  CONSTRAINT obliwatch_action_requests_code_check CHECK (code IS NULL OR length(code) <= 64),
  CONSTRAINT obliwatch_action_requests_execution_check CHECK (
    (path = 'guard' AND pending_action_uuid IS NOT NULL AND command_id IS NULL)
    OR (path = 'command' AND command_id IS NOT NULL AND pending_action_uuid IS NULL)),
  CONSTRAINT obliwatch_action_requests_closed_check CHECK ((closed_at IS NOT NULL) = (state IN ('done', 'failed', 'refused', 'expired', 'cancelled')))
);
-- The open requests of a tenant (the tracking of the minute step, the caps).
CREATE INDEX IF NOT EXISTS obliwatch_action_requests_open ON obligarth.obliwatch_action_requests (tenant_id, state, expires_at)
  WHERE state IN ('accepted', 'executing');
-- The caps per window and the purge.
CREATE INDEX IF NOT EXISTS obliwatch_action_requests_created ON obligarth.obliwatch_action_requests (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS obliwatch_action_requests_requester ON obligarth.obliwatch_action_requests (tenant_id, requested_by, created_at);
COMMENT ON TABLE obligarth.obliwatch_action_requests IS
  'Obliwatch integration (GTH-04): action requests of Obliwatch analysts on one device, executed without approval (owner decision Q-L5a); never a phone number nor a coordinate; purged 90 days after they closed';
SELECT obligarth_private.rls_apply('obligarth.obliwatch_action_requests', 'tenant',
  'Obliwatch integration (L5): action requests of Obliwatch on one device');

-- 2. The transitions of the requests, outbox of the results -------------------------------------------------
CREATE TABLE IF NOT EXISTS obligarth.obliwatch_action_events (
  id               bigserial     PRIMARY KEY,
  tenant_id        integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  request_id       uuid          NOT NULL,
  seq              integer       NOT NULL,
  status           text          NOT NULL,
  at               timestamptz   NOT NULL,
  result           jsonb         NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz   NOT NULL DEFAULT now(),
  push_state       text          NOT NULL DEFAULT 'pending',
  attempts         integer       NOT NULL DEFAULT 0,
  next_attempt_at  timestamptz   NOT NULL DEFAULT now(),
  pushed_at        timestamptz,
  result_code      text,
  last_error       text,
  CONSTRAINT obliwatch_action_events_seq_key UNIQUE (tenant_id, request_id, seq),
  CONSTRAINT obliwatch_action_events_request_fk FOREIGN KEY (tenant_id, request_id)
    REFERENCES obligarth.obliwatch_action_requests (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT obliwatch_action_events_status_check CHECK (status IN ('accepted', 'awaiting_approval', 'approved', 'executing',
    'done', 'failed', 'refused', 'expired', 'cancelled')),
  CONSTRAINT obliwatch_action_events_seq_check CHECK (seq >= 1),
  CONSTRAINT obliwatch_action_events_result_check CHECK (jsonb_typeof(result) = 'object' AND pg_column_size(result) <= 1024),
  CONSTRAINT obliwatch_action_events_push_state_check CHECK (push_state IN ('pending', 'sent', 'skipped', 'dead')),
  CONSTRAINT obliwatch_action_events_result_code_check CHECK (result_code IS NULL OR length(result_code) <= 40),
  CONSTRAINT obliwatch_action_events_last_error_check CHECK (last_error IS NULL OR length(last_error) <= 300)
);
CREATE INDEX IF NOT EXISTS obliwatch_action_events_due ON obligarth.obliwatch_action_events (tenant_id, next_attempt_at, id)
  WHERE push_state = 'pending';
CREATE INDEX IF NOT EXISTS obliwatch_action_events_state_at ON obligarth.obliwatch_action_events (tenant_id, push_state, created_at);
COMMENT ON TABLE obligarth.obliwatch_action_events IS
  'Obliwatch integration (GTH-05): transitions of the action requests and the push of their results (never a coordinate); purged 30 days after they ended, 90 days for a dead one';
SELECT obligarth_private.rls_apply('obligarth.obliwatch_action_events', 'tenant',
  'Obliwatch integration (L5): results of the action requests pushed to Obliwatch');

-- 3. Nominative view of the AI apps on by default with the read access (AR-55/AR-57) ------------------------
ALTER TABLE obligarth.tenant_obliwatch_settings ADD COLUMN IF NOT EXISTS nominative_ai_apps_opted_out boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN obligarth.tenant_obliwatch_settings.nominative_ai_apps_opted_out IS
  'The tenant turned the nominative view of the AI apps off on purpose: turning the read access on again leaves it off';
-- 3a. A tenant that already turned the view off on purpose (its last obliwatch.consent.changed that changed
--     nominativeAiApps set it to false) keeps it off: its refusal remembered first.
UPDATE obligarth.tenant_obliwatch_settings s SET nominative_ai_apps_opted_out = true
 WHERE NOT s.nominative_ai_apps AND NOT s.nominative_ai_apps_opted_out
   AND (SELECT l.details #>> '{changes,nominativeAiApps,to}' FROM obligarth.audit_logs l
         WHERE l.tenant_id = s.tenant_id AND l.action = 'obliwatch.consent.changed'
           AND l.details #> '{changes,nominativeAiApps}' IS NOT NULL
         ORDER BY l.chain_seq DESC LIMIT 1) = 'false';
-- 3b. The others that consent to be read get the view, each change journaled in the tenant's chain
--     (obliwatch.consent.changed, critical, actor the migration, changes.nominativeAiApps false → true).
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN UPDATE obligarth.tenant_obliwatch_settings SET nominative_ai_apps = true
            WHERE read_enabled AND NOT nominative_ai_apps AND NOT nominative_ai_apps_opted_out
            RETURNING tenant_id
  LOOP
    PERFORM obligarth.audit_append(jsonb_build_object(
      'v', 1, 'id', gen_random_uuid(),
      'ts', to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'tenant', r.tenant_id, 'action', 'obliwatch.consent.changed', 'outcome', 'success', 'crit', 'critical',
      'actor', jsonb_build_object('type', 'job', 'ref', 'j:migration.obliwatch_actions', 'side', 'system'),
      'target', jsonb_build_object('type', 'tenant', 'id', r.tenant_id::text),
      'reason', 'Nominative view of the AI apps on by default with the read access (peer request AR-55/AR-57)',
      'details', jsonb_build_object('changes', jsonb_build_object('nominativeAiApps', jsonb_build_object('from', false, 'to', true)),
        'by', 'migration'))::text);
  END LOOP;
END $$;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
