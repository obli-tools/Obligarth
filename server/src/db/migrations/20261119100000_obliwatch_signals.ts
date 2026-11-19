import type { Knex } from 'knex';

// =============================================================================
// Obliwatch integration, lot L3 (brief GTH-01): the D-MOB-* signals pushed to Obliwatch
// =============================================================================
//   - device_signal_state        tenant: the last state of each rule of each device (active | cleared) and its
//                                transition counter: a signal is recorded on a TRANSITION only (the compare and the
//                                increment are one INSERT ... ON CONFLICT DO UPDATE ... WHERE, integrations/obliwatch/
//                                signals.ts). Filled silently from the current state when a tenant turns the push on
//                                (no burst). fingerprint: what makes a new 'active' (the severity of D-MOB-NONCOMPLIANT).
//   - device_signal_transitions  tenant: one row per transition, eventId obligarth:<device uuid>:<rule>:<seq>; its
//                                details are the brief's whitelist only (platform, ownership, managementMode,
//                                reasonCodes, posture, risks, state): never an identifier. It is the outbox of the push
//                                (push_state pending → sent | skipped | dead, attempts, next_attempt_at: the retries of
//                                72 hours are carried by the row, not by the job), purged 30 days after it ended
//                                (90 days for a dead one).
// Two new tables, nothing else touched: additive, safe on a live database at start. Nothing writes them while
// OBLIWATCH_INTEGRATION is not 'on' and the tenant has not consented to the push.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean()
// last, a down that raises. Runs as obligarth_owner (server-migrate).
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Obliwatch integration: state and transitions of the D-MOB-* signals (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.devices') IS NULL OR to_regclass('obligarth.tenant_obliwatch_settings') IS NULL THEN
    RAISE EXCEPTION 'obliwatch_signals: apply the obliwatch_integration migration first';
  END IF;
END $$;

-- 1. The state of each rule of each device -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obligarth.device_signal_state (
  tenant_id    integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id    integer       NOT NULL,
  rule_id      text          NOT NULL,
  state        text          NOT NULL,
  fingerprint  text,
  seq          integer       NOT NULL DEFAULT 0,
  changed_at   timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT device_signal_state_pkey PRIMARY KEY (tenant_id, device_id, rule_id),
  CONSTRAINT device_signal_state_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT device_signal_state_rule_check CHECK (rule_id ~ '^D-MOB-[A-Z0-9-]{2,40}$'),
  CONSTRAINT device_signal_state_state_check CHECK (state IN ('active', 'cleared')),
  CONSTRAINT device_signal_state_fingerprint_check CHECK (fingerprint IS NULL OR length(fingerprint) <= 40),
  CONSTRAINT device_signal_state_seq_check CHECK (seq >= 0)
);
COMMENT ON TABLE obligarth.device_signal_state IS
  'Obliwatch integration (GTH-01): last state of each D-MOB-* rule of a device and its transition counter (a signal on a transition only)';
SELECT obligarth_private.rls_apply('obligarth.device_signal_state', 'tenant',
  'Obliwatch integration (L3): state of the D-MOB-* rules per device');

-- 2. The transitions, outbox of the push ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obligarth.device_signal_transitions (
  id               bigserial     PRIMARY KEY,
  tenant_id        integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id        integer       NOT NULL,
  device_uuid      uuid          NOT NULL,
  rule_id          text          NOT NULL,
  seq              integer       NOT NULL,
  state            text          NOT NULL,
  severity         text          NOT NULL,
  details          jsonb         NOT NULL DEFAULT '{}'::jsonb,
  occurred_at      timestamptz   NOT NULL,
  created_at       timestamptz   NOT NULL DEFAULT now(),
  push_state       text          NOT NULL DEFAULT 'pending',
  attempts         integer       NOT NULL DEFAULT 0,
  next_attempt_at  timestamptz   NOT NULL DEFAULT now(),
  pushed_at        timestamptz,
  result_code      text,
  last_error       text,
  CONSTRAINT device_signal_transitions_event_key UNIQUE (tenant_id, device_id, rule_id, seq),
  CONSTRAINT device_signal_transitions_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT device_signal_transitions_rule_check CHECK (rule_id ~ '^D-MOB-[A-Z0-9-]{2,40}$'),
  CONSTRAINT device_signal_transitions_state_check CHECK (state IN ('active', 'cleared')),
  CONSTRAINT device_signal_transitions_severity_check CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  CONSTRAINT device_signal_transitions_push_state_check CHECK (push_state IN ('pending', 'sent', 'skipped', 'dead')),
  CONSTRAINT device_signal_transitions_seq_check CHECK (seq >= 1),
  CONSTRAINT device_signal_transitions_details_check CHECK (jsonb_typeof(details) = 'object' AND pg_column_size(details) <= 4096),
  CONSTRAINT device_signal_transitions_result_code_check CHECK (result_code IS NULL OR length(result_code) <= 40),
  CONSTRAINT device_signal_transitions_last_error_check CHECK (last_error IS NULL OR length(last_error) <= 300)
);
-- The push: the due rows of a tenant, oldest first.
CREATE INDEX IF NOT EXISTS device_signal_transitions_due ON obligarth.device_signal_transitions (tenant_id, next_attempt_at, id)
  WHERE push_state = 'pending';
-- The status of the console (dead letters, last sent) and the purge.
CREATE INDEX IF NOT EXISTS device_signal_transitions_state_at ON obligarth.device_signal_transitions (tenant_id, push_state, created_at);
COMMENT ON TABLE obligarth.device_signal_transitions IS
  'Obliwatch integration (GTH-01): transitions of the D-MOB-* rules and their push (whitelisted details, never an identifier); purged 30 days after they ended, 90 days for a dead one';
SELECT obligarth_private.rls_apply('obligarth.device_signal_transitions', 'tenant',
  'Obliwatch integration (L3): transitions of the D-MOB-* signals and their push');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
