import type { Knex } from 'knex';

// =============================================================================
// Obliwatch integration, lot L5 (brief GTH-08): Apple managed device attestation and the AMAPI security logs (SEC-13)
// =============================================================================
//   - apple_device_attestations        tenant: the verdict of the last Apple managed device attestation of a device
//                                      (DeviceInformation DevicePropertiesAttestation, integrations/obliwatch/
//                                      appleAttestation.ts): state verified | failed and its reason code, the date of
//                                      the check, and the SHA-256 of the last nonces (DeviceAttestationNonce) Obligarth
//                                      sent to the device (the freshness code of the attestation is one of them). Never
//                                      a certificate, a serial number, a UDID nor any value of the attestation.
//   - device_security_log_status       tenant: when the security logs of an AMAPI device last reached Obligarth (the
//                                      coverage securityLogs of the read API), and whether its policy was pushed with
//                                      usageLog (policy_logs_on: the sweep that turns the logs off again when the
//                                      integration or the push consent is off). Nothing else.
//   - device_security_log_windows      tenant: the aggregates of the security logs (integrations/obliwatch/
//                                      securityLogs.ts): per device, rule and fixed window, the count of the events and
//                                      whether the detection was recorded. Counts only, NEVER an event of the log (no
//                                      certificate subject, no shell command, no package). Purged eight days after the
//                                      window (the logs older than 7 days are not counted).
// Three new tables, nothing else touched: additive, re-runnable (IF NOT EXISTS), safe on a live database at start
// (lock_timeout: fail fast rather than queue the writers; the foreign keys take a SHARE ROW EXCLUSIVE lock on devices
// for an instant only, as every table of the integration). Nothing writes them while OBLIWATCH_INTEGRATION is not 'on'
// and the tenant has not consented to the push, but the clearing of policy_logs_on (the logs turned off again).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean()
// last, a down that raises. Runs as obligarth_owner (server-migrate).
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Obliwatch integration: Apple attestation, AMAPI security logs (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
  IF to_regclass('obligarth.devices') IS NULL OR to_regclass('obligarth.device_signal_state') IS NULL THEN
    RAISE EXCEPTION 'obliwatch_attestation_security_logs: apply the obliwatch_signals migration first';
  END IF;
END $$;

-- 1. The Apple managed device attestation ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obligarth.apple_device_attestations (
  tenant_id       integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id       integer       NOT NULL,
  state           text,
  reason          text,
  checked_at      timestamptz,
  nonce_hashes    text[]        NOT NULL DEFAULT '{}'::text[],
  first_nonce_at  timestamptz,
  last_nonce_at   timestamptz,
  updated_at      timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT apple_device_attestations_pkey PRIMARY KEY (tenant_id, device_id),
  CONSTRAINT apple_device_attestations_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT apple_device_attestations_state_check CHECK (state IS NULL OR state IN ('verified', 'failed')),
  CONSTRAINT apple_device_attestations_reason_check CHECK (reason IS NULL OR reason ~ '^[a-z_]{1,40}$'),
  CONSTRAINT apple_device_attestations_checked_check CHECK ((state IS NULL) = (checked_at IS NULL)),
  CONSTRAINT apple_device_attestations_nonces_check CHECK (cardinality(nonce_hashes) <= 4
    AND array_to_string(nonce_hashes, '') ~ '^([0-9a-f]{64})*$')
);
COMMENT ON TABLE obligarth.apple_device_attestations IS
  'Obliwatch integration (GTH-08): verdict of the last Apple managed device attestation of a device and the hashes of the nonces sent; never a certificate nor an identifier';
SELECT obligarth_private.rls_apply('obligarth.apple_device_attestations', 'tenant',
  'Obliwatch integration (L5): Apple managed device attestation of the devices');

-- 2. When the security logs of a device last arrived ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS obligarth.device_security_log_status (
  tenant_id         integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id         integer       NOT NULL,
  last_received_at  timestamptz,
  policy_logs_on    boolean       NOT NULL DEFAULT false,
  policy_marked_at  timestamptz,
  CONSTRAINT device_security_log_status_pkey PRIMARY KEY (tenant_id, device_id),
  CONSTRAINT device_security_log_status_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
-- The devices whose policy still carries the security logs (the sweep of integrations/obliwatch/securityLogs.ts).
CREATE INDEX IF NOT EXISTS device_security_log_status_policy ON obligarth.device_security_log_status (tenant_id, device_id)
  WHERE policy_logs_on;
COMMENT ON TABLE obligarth.device_security_log_status IS
  'Obliwatch integration (GTH-08, SEC-13): when the AMAPI security logs of a device last reached Obligarth (coverage securityLogs)';
SELECT obligarth_private.rls_apply('obligarth.device_security_log_status', 'tenant',
  'Obliwatch integration (L5): arrival of the security logs of the devices');

-- 3. The aggregates of the security logs ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obligarth.device_security_log_windows (
  tenant_id     integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id     integer       NOT NULL,
  rule_id       text          NOT NULL,
  window_start  timestamptz   NOT NULL,
  count         integer       NOT NULL DEFAULT 0,
  emitted_at    timestamptz,
  updated_at    timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT device_security_log_windows_pkey PRIMARY KEY (tenant_id, device_id, rule_id, window_start),
  CONSTRAINT device_security_log_windows_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT device_security_log_windows_rule_check CHECK (rule_id ~ '^D-MOB-SEC-[A-Z0-9-]{2,32}$'),
  CONSTRAINT device_security_log_windows_count_check CHECK (count >= 0)
);
-- The purge (windows ended eight days ago).
CREATE INDEX IF NOT EXISTS device_security_log_windows_start ON obligarth.device_security_log_windows (tenant_id, window_start);
COMMENT ON TABLE obligarth.device_security_log_windows IS
  'Obliwatch integration (GTH-08, SEC-13): counts of the security-log events per device, rule and window; never an event; purged eight days after the window';
SELECT obligarth_private.rls_apply('obligarth.device_security_log_windows', 'tenant',
  'Obliwatch integration (L5): aggregates of the security logs of the devices');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
