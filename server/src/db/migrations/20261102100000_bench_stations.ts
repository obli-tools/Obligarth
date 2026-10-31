import type { Knex } from 'knex';

// =============================================================================
// Bench stations and the bridge agent as the owner of the device (lot BANC; spec banc-spec §3.1)
// =============================================================================
//   a) management_mode 'device_owner' for the channel of the bridge agent: the CHECK devices_management_mode_check and
//      obligarth.ownership_allows widened (mirror shared/src/mdm/ownership.ts), after checking that both are still
//      what legacy_agent left them (the literals of the CHECK; the truth table of the function on every ownership,
//      method and mode, computed here from a frozen copy of the TypeScript mirror).
//   b) legacy_agent_devices: device_owner (+ since), the station and the provisioning that enrolled it, the identity
//      state of a bench enrollment, the owner declared for an agent older than 1.4.0 (exception D3), adb_enabled.
//   c) bench_stations       identity: the stations (sha256 of their token only), never readable from a tenant context
//                           nor by obligarth_reader; 'revoked' is final (trigger bench_stations_no_unrevoke).
//   c bis) bench_sessions   identity: the bench session a technician opens (8 hours at most, one open per station).
//   d) bench_station_targets tenant: the groups a station may enroll into (200 per station at most, counted across the
//                           tenants by the definer trigger bench_station_targets_cap); removed with their group
//                           (bench.target_removed group_deleted written by the group service).
//   e) bench_provisionings  tenant: one device on the bench, its transitions guarded (bench_provisionings_transition);
//                           one open provisioning per station and ADB serial, whatever the tenant.
//   f) legacy_agent_enrollment_tokens: origin console | bench; a bench token is single-use, bound to a provisioning and
//      to its station, valid 30 minutes at most. created_by and revoked_by stay users (the technician of the session).
//   g) SECURITY DEFINER functions, each with its actor guard and registered (rls_registry): the station surface runs in
//      the context 'none' as i:bench-station (lookup, registration) or i:bench-station:<id> (its own rows).
//   h) legacy_agent_releases.bench_served: the one version served to the stations, never a withdrawn one.
//   i) mdm.bench.manage and mdm.bench.operate in the permission sets that hold mdm.enrollment.manage.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, functions with
// SET search_path = pg_catalog, pg_temp and EXECUTE revoked from PUBLIC, rls_assert_clean() last, a down that raises.
// Runs as obligarth_owner (server-migrate), after legacy_agent_policies.
// =============================================================================

const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

// Frozen vocabularies (shared/src/mdm/bench.ts at the time of this migration).
const STATION_STATUSES = ['pending', 'approved', 'suspended', 'revoked'];
const IDENTITY_STATES = ['confirmed', 'unconfirmed', 'mismatch'];
const ROLE_POLICIES = ['owner_required', 'owner_preferred', 'admin_only'];
const ROLES = ['device_owner', 'device_admin'];
const PROVISIONING_STATES = ['planned', 'token_issued', 'enrolled', 'completed', 'failed', 'abandoned', 'expired'];
const PROVISIONING_KINDS = ['new', 'convert'];
const ERROR_CODES = [
  'adb_missing', 'adb_server', 'adb_conflict', 'device_unauthorized', 'device_offline', 'device_gone',
  'auto_blocker_suspected', 'adb_blocked_by_policy', 'unsupported_sdk', 'agent_foreign_signer', 'agent_downgrade',
  'agent_already_enrolled', 'install_failed', 'install_restricted', 'apk_mismatch', 'owner_blocked', 'owner_failed',
  'admin_failed', 'admin_lost', 'knox_reactivation', 'configure_failed', 'enroll_timeout', 'token_rejected',
  'identity_mismatch', 'device_outside_target', 'station_refused', 'no_session', 'server_unreachable', 'redirected',
  'target_refused', 'slot_held', 'too_many_cards', 'internal',
];

// The values the precondition expects (legacy_agent, 20261019130000).
const MODES_BEFORE = ['dedicated', 'device', 'device_admin', 'fully_managed', 'user_enrollment', 'work_profile_corporate', 'work_profile_personal'];
const OWNERSHIPS = ['corporate', 'corporate_personal', 'personal'];
const METHODS = ['ade', 'ota', 'byod_account', 'configurator', 'account_device', 'migration', 'android_qr', 'android_nfc', 'android_afw',
  'android_token', 'android_zero_touch', 'android_kme', 'android_byod_link', 'android_signin_url', 'agent_token'];
const MODES = [...MODES_BEFORE, 'device_owner'];

/** The function as legacy_agent left it (frozen copy of shared/src/mdm/ownership.ts before this lot). */
function ownershipAllowsBefore(o: string, m: string, mode: string): boolean {
  const android = m.startsWith('android_');
  switch (o) {
    case 'personal':
      return (mode === 'user_enrollment' && m === 'byod_account')
        || (mode === 'work_profile_personal' && ['android_byod_link', 'android_signin_url'].includes(m));
    case 'corporate_personal':
      return (mode === 'device' && ['ade', 'configurator', 'migration'].includes(m))
        || (mode === 'work_profile_corporate' && android && m !== 'android_byod_link' && m !== 'android_nfc');
    case 'corporate':
      return (mode === 'device' && ['ade', 'configurator', 'ota', 'account_device', 'migration'].includes(m))
        || (['fully_managed', 'dedicated'].includes(mode) && android && m !== 'android_byod_link')
        || (mode === 'device_admin' && m === 'agent_token');
    default:
      return false;
  }
}

const EXPECTED_TRUE = OWNERSHIPS.flatMap((o) => METHODS.flatMap((m) => MODES.filter((mode) => ownershipAllowsBefore(o, m, mode))
  .map((mode) => `${o}|${m}|${mode}`))).sort();
const sqlArray = (values: readonly string[]): string => `ARRAY[${values.map((v) => `'${v}'`).join(', ')}]::text[]`;

const UP = String.raw`-- =============================================================================
-- Bench stations, the agent as owner of the device (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

-- 0. Preconditions --------------------------------------------------------------------
DO $$
DECLARE v_found text[];
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.legacy_agent_devices') IS NULL OR to_regclass('obligarth.legacy_agent_enrollment_tokens') IS NULL
     OR to_regclass('obligarth.legacy_agent_releases') IS NULL OR to_regclass('obligarth.legacy_agent_policy_reports') IS NULL
     OR to_regclass('obligarth.permission_sets') IS NULL THEN
    RAISE EXCEPTION 'bench_stations: apply the RLS, legacy_agent and legacy_agent_policies migrations first';
  END IF;
  SELECT COALESCE(array_agg(DISTINCT m[1] COLLATE "C" ORDER BY m[1] COLLATE "C"), '{}'::text[]) INTO v_found
    FROM pg_constraint c CROSS JOIN LATERAL regexp_matches(pg_get_constraintdef(c.oid), '''([a-z_]+)''', 'g') AS m
   WHERE c.conrelid = 'obligarth.devices'::regclass AND c.conname = 'devices_management_mode_check';
  IF v_found IS DISTINCT FROM ${sqlArray(MODES_BEFORE)} THEN
    RAISE EXCEPTION 'bench_stations: devices_management_mode_check differs from legacy_agent (%): merge the widenings', v_found;
  END IF;
  SELECT COALESCE(array_agg((o || '|' || e || '|' || md) COLLATE "C" ORDER BY (o || '|' || e || '|' || md) COLLATE "C"), '{}'::text[]) INTO v_found
    FROM unnest(${sqlArray(OWNERSHIPS)}) AS o, unnest(${sqlArray(METHODS)}) AS e, unnest(${sqlArray(MODES)}) AS md
   WHERE obligarth.ownership_allows(o, e, md);
  IF v_found IS DISTINCT FROM ${sqlArray(EXPECTED_TRUE)} THEN
    RAISE EXCEPTION 'bench_stations: obligarth.ownership_allows differs from legacy_agent: merge the widenings of both branches';
  END IF;
END $$;

-- a) The mode of the owner of the device ---------------------------------------------
-- Mirror of shared/src/mdm/ownership.ts (ownershipAllows): both change together. The other branches are those of
-- legacy_agent, word for word.
CREATE OR REPLACE FUNCTION obligarth.ownership_allows(p_ownership text, p_enrollment_type text, p_mode text)
  RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN (CASE p_ownership
    WHEN 'personal' THEN
         (p_mode = 'user_enrollment' AND p_enrollment_type = 'byod_account')
      OR (p_mode = 'work_profile_personal' AND p_enrollment_type IN ('android_byod_link', 'android_signin_url'))
    WHEN 'corporate_personal' THEN
         (p_mode = 'device' AND p_enrollment_type IN ('ade', 'configurator', 'migration'))
      OR (p_mode = 'work_profile_corporate' AND p_enrollment_type LIKE 'android\_%'
          AND p_enrollment_type NOT IN ('android_byod_link', 'android_nfc'))
    WHEN 'corporate' THEN
         (p_mode = 'device' AND p_enrollment_type IN ('ade', 'configurator', 'ota', 'account_device', 'migration'))
      OR (p_mode IN ('fully_managed', 'dedicated') AND p_enrollment_type LIKE 'android\_%'
          AND p_enrollment_type <> 'android_byod_link')
      OR (p_mode IN ('device_admin', 'device_owner') AND p_enrollment_type = 'agent_token')
    ELSE false
  END);
REVOKE ALL ON FUNCTION obligarth.ownership_allows(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.ownership_allows(text, text, text) TO obligarth, obligarth_reader;

ALTER TABLE obligarth.devices
  DROP CONSTRAINT devices_management_mode_check,
  ADD CONSTRAINT devices_management_mode_check CHECK (management_mode IN ('device', 'user_enrollment', 'fully_managed',
      'dedicated', 'work_profile_corporate', 'work_profile_personal', 'device_admin', 'device_owner'));

-- c) Stations (platform) -----------------------------------------------------------------
CREATE TABLE obligarth.bench_stations (
  id               uuid          NOT NULL DEFAULT gen_random_uuid(),
  name             text          NOT NULL,
  hostname         text          NOT NULL,
  token_sha256     char(64)      NOT NULL,
  status           text          NOT NULL DEFAULT 'pending',
  station_version  text,
  created_at       timestamptz   NOT NULL DEFAULT now(),
  register_ip      inet,
  approved_at      timestamptz,
  approved_by      integer,
  suspended_at     timestamptz,
  suspended_by     integer,                                   -- NULL: suspended by the job (idle)
  revoked_at       timestamptz,
  revoked_by       integer,                                   -- NULL: a pending station expired (job)
  revoked_reason   text,
  allowed_cidrs    cidr[],
  last_seen_at     timestamptz,
  last_ip          inet,
  CONSTRAINT bench_stations_pkey PRIMARY KEY (id),
  CONSTRAINT bench_stations_token_unique UNIQUE (token_sha256),
  CONSTRAINT bench_stations_approved_by_foreign FOREIGN KEY (approved_by) REFERENCES obligarth.users (id),
  CONSTRAINT bench_stations_suspended_by_foreign FOREIGN KEY (suspended_by) REFERENCES obligarth.users (id),
  CONSTRAINT bench_stations_revoked_by_foreign FOREIGN KEY (revoked_by) REFERENCES obligarth.users (id),
  CONSTRAINT bench_stations_name_check CHECK (char_length(name) BETWEEN 1 AND 100 AND btrim(name) = name AND name !~ '[[:cntrl:]]'),
  CONSTRAINT bench_stations_hostname_check CHECK (char_length(hostname) <= 255 AND hostname !~ '[[:cntrl:]]'),
  CONSTRAINT bench_stations_token_check CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT bench_stations_status_check CHECK (status IN (${list(STATION_STATUSES)})),
  CONSTRAINT bench_stations_version_check CHECK (station_version IS NULL OR (char_length(station_version) <= 32
    AND station_version ~ '^[0-9A-Za-z.+_-]+$')),
  CONSTRAINT bench_stations_revoked_reason_check CHECK (revoked_reason IS NULL OR revoked_reason IN ('admin', 'pending_expired', 'idle')),
  CONSTRAINT bench_stations_cidrs_check CHECK (allowed_cidrs IS NULL OR cardinality(allowed_cidrs) <= 32),
  CONSTRAINT bench_stations_lifecycle CHECK (CASE status
    WHEN 'pending' THEN approved_at IS NULL AND approved_by IS NULL AND suspended_at IS NULL AND suspended_by IS NULL
                    AND revoked_at IS NULL AND revoked_by IS NULL AND revoked_reason IS NULL
    WHEN 'approved' THEN approved_at IS NOT NULL AND approved_by IS NOT NULL AND suspended_at IS NULL AND suspended_by IS NULL
                    AND revoked_at IS NULL AND revoked_by IS NULL AND revoked_reason IS NULL
    WHEN 'suspended' THEN approved_at IS NOT NULL AND approved_by IS NOT NULL AND suspended_at IS NOT NULL
                    AND revoked_at IS NULL AND revoked_by IS NULL AND revoked_reason IS NULL
    WHEN 'revoked' THEN revoked_at IS NOT NULL AND revoked_reason IS NOT NULL AND (revoked_reason <> 'admin' OR revoked_by IS NOT NULL)
    ELSE false END)
);
CREATE INDEX bench_stations_pending ON obligarth.bench_stations (created_at) WHERE status = 'pending';
SELECT obligarth_private.rls_apply('obligarth.bench_stations', 'identity',
  'bench stations: sha256 of their token only; platform context and the definer functions of the station surface');

CREATE FUNCTION obligarth_private.bench_stations_no_unrevoke() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.token_sha256 IS DISTINCT FROM OLD.token_sha256 THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_stations: the token of a station never changes';
  END IF;
  IF OLD.status = 'revoked' AND (NEW.status IS DISTINCT FROM OLD.status OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by OR NEW.revoked_reason IS DISTINCT FROM OLD.revoked_reason) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_stations: a revoked station stays revoked';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.bench_stations_no_unrevoke() FROM PUBLIC;
CREATE TRIGGER bench_stations_no_unrevoke BEFORE UPDATE ON obligarth.bench_stations
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.bench_stations_no_unrevoke();

-- c bis) Bench sessions (platform) -------------------------------------------------------
CREATE TABLE obligarth.bench_sessions (
  id            uuid          NOT NULL DEFAULT gen_random_uuid(),
  station_id    uuid          NOT NULL,
  user_id       integer       NOT NULL,                       -- the technician
  opened_at     timestamptz   NOT NULL DEFAULT now(),
  expires_at    timestamptz   NOT NULL,
  closed_at     timestamptz,
  closed_by     integer,                                    -- NULL: the job (expiry) or a revocation of the station
  close_reason  text,
  CONSTRAINT bench_sessions_pkey PRIMARY KEY (id),
  CONSTRAINT bench_sessions_station_foreign FOREIGN KEY (station_id) REFERENCES obligarth.bench_stations (id) ON DELETE RESTRICT,
  CONSTRAINT bench_sessions_user_foreign FOREIGN KEY (user_id) REFERENCES obligarth.users (id) ON DELETE CASCADE,
  CONSTRAINT bench_sessions_closed_by_foreign FOREIGN KEY (closed_by) REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT bench_sessions_expiry_check CHECK (expires_at > opened_at AND expires_at <= opened_at + interval '8 hours'),
  CONSTRAINT bench_sessions_closed_check CHECK ((closed_at IS NULL) = (close_reason IS NULL)),
  CONSTRAINT bench_sessions_reason_check CHECK (close_reason IS NULL OR close_reason IN
    ('user', 'admin', 'expired', 'station_revoked', 'station_suspended'))
);
CREATE UNIQUE INDEX bench_sessions_open ON obligarth.bench_sessions (station_id) WHERE closed_at IS NULL;
CREATE INDEX bench_sessions_expiry ON obligarth.bench_sessions (expires_at) WHERE closed_at IS NULL;
SELECT obligarth_private.rls_apply('obligarth.bench_sessions', 'identity',
  'bench sessions: opened by a technician (second factor, 8 hours at most); platform context and definer functions');

-- d) Targets of a station (per tenant) ---------------------------------------------------
CREATE TABLE obligarth.bench_station_targets (
  station_id          uuid          NOT NULL,
  tenant_id           integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  group_id            integer       NOT NULL,
  role_policy         text          NOT NULL DEFAULT 'owner_preferred',
  allow_legacy_owner  boolean       NOT NULL DEFAULT false,
  name_prefix         text,
  disable_dev_options boolean       NOT NULL DEFAULT true,
  suspended_at        timestamptz,
  suspended_by        integer,
  created_at          timestamptz   NOT NULL DEFAULT now(),
  created_by          integer       NOT NULL,
  CONSTRAINT bench_station_targets_pkey PRIMARY KEY (station_id, tenant_id, group_id),
  CONSTRAINT bench_station_targets_station_foreign FOREIGN KEY (station_id) REFERENCES obligarth.bench_stations (id) ON DELETE RESTRICT,
  CONSTRAINT bench_station_targets_tenant_id_foreign FOREIGN KEY (tenant_id) REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT bench_station_targets_group_foreign FOREIGN KEY (tenant_id, group_id)
    REFERENCES obligarth.device_groups (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT bench_station_targets_created_by_foreign FOREIGN KEY (created_by) REFERENCES obligarth.users (id),
  CONSTRAINT bench_station_targets_role_policy_check CHECK (role_policy IN (${list(ROLE_POLICIES)})),
  CONSTRAINT bench_station_targets_prefix_check CHECK (name_prefix IS NULL OR name_prefix ~ '^[A-Za-z0-9_-]{0,32}$'),
  CONSTRAINT bench_station_targets_suspended_check CHECK (suspended_by IS NULL OR suspended_at IS NOT NULL)
);
CREATE INDEX bench_station_targets_tenant ON obligarth.bench_station_targets (tenant_id, station_id);
SELECT obligarth_private.rls_apply('obligarth.bench_station_targets', 'tenant',
  'bench stations: the groups of a tenant a station enrolls into (added by a platform administrator)');

-- e) Provisionings (per tenant) ----------------------------------------------------------
CREATE TABLE obligarth.bench_provisionings (
  id                   uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id            integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  group_id             integer       NOT NULL,                -- the target at the creation; no foreign key (history)
  station_id           uuid          NOT NULL,
  session_id           uuid,                                  -- the session that issued the last token
  kind                 text          NOT NULL,
  state                text          NOT NULL,
  adb_serial           text          NOT NULL,
  hw_serial            text,
  model                text          NOT NULL,
  manufacturer         text          NOT NULL,
  sdk_int              integer       NOT NULL,
  os_release           text,
  one_ui               text,
  device_name          text,
  role_target          text          NOT NULL,
  role_declared        text,
  preflight            jsonb         NOT NULL DEFAULT '{}',
  steps                jsonb         NOT NULL DEFAULT '[]',
  steps_dropped        integer       NOT NULL DEFAULT 0,
  enrollment_token_id  uuid,
  device_id            integer,
  error_code           text,
  created_at           timestamptz   NOT NULL DEFAULT now(),
  updated_at           timestamptz   NOT NULL DEFAULT now(),
  outcome_at           timestamptz,
  CONSTRAINT bench_provisionings_pkey PRIMARY KEY (id),
  CONSTRAINT bench_provisionings_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT bench_provisionings_token_unique UNIQUE (enrollment_token_id),
  CONSTRAINT bench_provisionings_tenant_id_foreign FOREIGN KEY (tenant_id) REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT bench_provisionings_station_foreign FOREIGN KEY (station_id) REFERENCES obligarth.bench_stations (id) ON DELETE RESTRICT,
  CONSTRAINT bench_provisionings_session_foreign FOREIGN KEY (session_id) REFERENCES obligarth.bench_sessions (id) ON DELETE SET NULL,
  CONSTRAINT bench_provisionings_token_foreign FOREIGN KEY (tenant_id, enrollment_token_id)
    REFERENCES obligarth.legacy_agent_enrollment_tokens (tenant_id, id) ON DELETE SET NULL (enrollment_token_id),
  CONSTRAINT bench_provisionings_device_foreign FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (device_id),
  CONSTRAINT bench_provisionings_kind_check CHECK (kind IN (${list(PROVISIONING_KINDS)})),
  CONSTRAINT bench_provisionings_state_check CHECK (state IN (${list(PROVISIONING_STATES)})),
  CONSTRAINT bench_provisionings_serial_check CHECK (adb_serial ~ '^[A-Za-z0-9._:-]{1,64}$'
    AND (hw_serial IS NULL OR hw_serial ~ '^[A-Za-z0-9._:-]{1,64}$')),
  CONSTRAINT bench_provisionings_model_check CHECK (char_length(model) BETWEEN 1 AND 64 AND model !~ '[[:cntrl:]]'
    AND char_length(manufacturer) BETWEEN 1 AND 64 AND manufacturer !~ '[[:cntrl:]]'),
  CONSTRAINT bench_provisionings_sdk_check CHECK (sdk_int BETWEEN 21 AND 100),
  CONSTRAINT bench_provisionings_os_check CHECK ((os_release IS NULL OR (char_length(os_release) <= 32 AND os_release !~ '[[:cntrl:]]'))
    AND (one_ui IS NULL OR (char_length(one_ui) <= 32 AND one_ui !~ '[[:cntrl:]]'))),
  CONSTRAINT bench_provisionings_name_check CHECK (device_name IS NULL OR (char_length(device_name) BETWEEN 1 AND 100
    AND device_name !~ '[[:cntrl:]]')),
  CONSTRAINT bench_provisionings_role_check CHECK (role_target IN (${list(ROLES)}) AND (role_declared IS NULL OR role_declared IN (${list(ROLES)}))),
  CONSTRAINT bench_provisionings_preflight_check CHECK (jsonb_typeof(preflight) = 'object' AND octet_length(preflight::text) <= 4096),
  CONSTRAINT bench_provisionings_steps_check CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) <= 64
    AND octet_length(steps::text) <= 32768),
  CONSTRAINT bench_provisionings_dropped_check CHECK (steps_dropped >= 0),
  CONSTRAINT bench_provisionings_error_check CHECK (error_code IS NULL OR error_code IN (${list(ERROR_CODES)})),
  CONSTRAINT bench_provisionings_outcome_check CHECK ((state IN ('completed', 'failed', 'abandoned', 'expired')) = (outcome_at IS NOT NULL)),
  CONSTRAINT bench_provisionings_convert_check CHECK (kind = 'new' OR enrollment_token_id IS NULL)
);
CREATE UNIQUE INDEX bench_provisionings_open ON obligarth.bench_provisionings (station_id, adb_serial)
  WHERE state IN ('planned', 'token_issued', 'enrolled');
CREATE INDEX bench_provisionings_tenant ON obligarth.bench_provisionings (tenant_id, created_at DESC);
CREATE INDEX bench_provisionings_expiry ON obligarth.bench_provisionings (created_at)
  WHERE state IN ('planned', 'token_issued', 'enrolled');
SELECT obligarth_private.rls_apply('obligarth.bench_provisionings', 'tenant',
  'bench stations: one device on the bench (facts read by ADB, journal of steps without free text, outcome)');

-- Transitions: planned -> token_issued | failed | abandoned | expired; token_issued -> token_issued (a token issued
-- again) | enrolled | failed | abandoned | expired; enrolled -> completed | failed | abandoned | expired; a terminal
-- state never changes. A provisioning starts planned (kind new), or enrolled (kind convert: its device is known).
CREATE FUNCTION obligarth_private.bench_provisionings_transition() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF (NEW.state = 'planned' AND NEW.kind = 'new')
       OR (NEW.state = 'enrolled' AND NEW.kind = 'convert' AND NEW.device_id IS NOT NULL) THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_provisionings_transition',
      MESSAGE = 'bench_provisionings: a provisioning starts planned (new) or enrolled (convert, with its device)';
  END IF;
  IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.station_id IS DISTINCT FROM OLD.station_id OR NEW.adb_serial IS DISTINCT FROM OLD.adb_serial THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_provisionings_transition',
      MESSAGE = 'bench_provisionings: the kind, the station and the serial of a provisioning never change';
  END IF;
  IF NEW.state = OLD.state THEN
    RETURN NEW;
  END IF;
  IF (OLD.state = 'planned' AND NEW.state IN ('token_issued', 'failed', 'abandoned', 'expired'))
     OR (OLD.state = 'token_issued' AND NEW.state IN ('enrolled', 'failed', 'abandoned', 'expired'))
     OR (OLD.state = 'enrolled' AND NEW.state IN ('completed', 'failed', 'abandoned', 'expired')) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_provisionings_transition',
    MESSAGE = format('bench_provisionings: %s -> %s is not a transition', OLD.state, NEW.state);
END $$;
REVOKE ALL ON FUNCTION obligarth_private.bench_provisionings_transition() FROM PUBLIC;
CREATE TRIGGER bench_provisionings_transition BEFORE INSERT OR UPDATE ON obligarth.bench_provisionings
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.bench_provisionings_transition();

-- b) The satellite of an agent's device ---------------------------------------------------
ALTER TABLE obligarth.legacy_agent_devices
  ADD COLUMN device_owner          boolean     NOT NULL DEFAULT false,
  ADD COLUMN device_owner_since    timestamptz,
  ADD COLUMN enrolled_by_station_id uuid,
  ADD COLUMN bench_provisioning_id uuid,
  ADD COLUMN identity_state        text,
  ADD COLUMN bench_owner_declared  boolean     NOT NULL DEFAULT false,
  ADD COLUMN adb_enabled           boolean,
  ADD CONSTRAINT legacy_agent_devices_station_foreign FOREIGN KEY (enrolled_by_station_id)
    REFERENCES obligarth.bench_stations (id) ON DELETE RESTRICT,
  ADD CONSTRAINT legacy_agent_devices_provisioning_fk FOREIGN KEY (tenant_id, bench_provisioning_id)
    REFERENCES obligarth.bench_provisionings (tenant_id, id) ON DELETE SET NULL (bench_provisioning_id),
  ADD CONSTRAINT legacy_agent_devices_identity_state_check CHECK (identity_state IS NULL OR identity_state IN (${list(IDENTITY_STATES)})),
  ADD CONSTRAINT legacy_agent_devices_device_owner_check CHECK (device_owner = (device_owner_since IS NOT NULL));
CREATE INDEX legacy_agent_devices_station ON obligarth.legacy_agent_devices (tenant_id, enrolled_by_station_id, enrolled_at)
  WHERE enrolled_by_station_id IS NOT NULL;

-- f) Enrollment tokens: the origin ------------------------------------------------------
ALTER TABLE obligarth.legacy_agent_enrollment_tokens
  ADD COLUMN origin                text        NOT NULL DEFAULT 'console',
  ADD COLUMN bench_provisioning_id uuid,
  ADD COLUMN created_by_station    uuid,
  ADD CONSTRAINT legacy_agent_tokens_station_foreign FOREIGN KEY (created_by_station)
    REFERENCES obligarth.bench_stations (id) ON DELETE RESTRICT,
  ADD CONSTRAINT legacy_agent_tokens_origin_check CHECK (origin IN ('console', 'bench')),
  ADD CONSTRAINT legacy_agent_tokens_origin_bench CHECK (origin <> 'bench' OR (bench_provisioning_id IS NOT NULL
    AND created_by_station IS NOT NULL AND max_uses = 1 AND expires_at <= created_at + interval '30 minutes')),
  ADD CONSTRAINT legacy_agent_tokens_origin_console CHECK (origin <> 'console' OR (bench_provisioning_id IS NULL
    AND created_by_station IS NULL));
CREATE INDEX legacy_agent_tokens_station_open ON obligarth.legacy_agent_enrollment_tokens (created_by_station)
  WHERE origin = 'bench' AND revoked_at IS NULL;
-- A provisioning may issue its token again (the previous one revoked): the current one is bench_provisionings.
-- enrollment_token_id (unique); the tokens of a provisioning are indexed, not unique.
CREATE INDEX legacy_agent_tokens_bench_provisioning ON obligarth.legacy_agent_enrollment_tokens (tenant_id, bench_provisioning_id)
  WHERE bench_provisioning_id IS NOT NULL;
CREATE INDEX legacy_agent_tokens_station_created ON obligarth.legacy_agent_enrollment_tokens (created_by_station, created_at)
  WHERE origin = 'bench';

-- h) The version served to the stations ---------------------------------------------------
ALTER TABLE obligarth.legacy_agent_releases
  ADD COLUMN bench_served boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT legacy_agent_releases_bench_served_check CHECK (NOT (bench_served AND withdrawn_at IS NOT NULL));
CREATE UNIQUE INDEX legacy_agent_releases_bench_served ON obligarth.legacy_agent_releases (bench_served) WHERE bench_served;

-- g) Definer functions ------------------------------------------------------------------
-- The station's guard: its row by the sha256 of its token, and its open session (context none, i:bench-station). A
-- session whose technician's account is no longer active is not returned: the station then has no session (no token).
CREATE FUNCTION obligarth.bench_station_lookup(p_token_sha256 text)
  RETURNS TABLE (id uuid, status text, name text, allowed_cidrs cidr[], session_id uuid, session_user_id integer,
                 session_expires_at timestamptz, technician text, technician_platform_admin boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_lookup: the station surface only';
  END IF;
  RETURN QUERY
    SELECT s.id, s.status, s.name, s.allowed_cidrs, ss.sid, ss.uid, ss.expires,
           ss.label, ss.platform_admin
      FROM obligarth.bench_stations s
      LEFT JOIN LATERAL (
        SELECT x.id AS sid, x.user_id AS uid, x.expires_at AS expires,
               COALESCE(NULLIF(u.display_name::text, ''), u.username::text) AS label, (u.role = 'admin') AS platform_admin
          FROM obligarth.bench_sessions x
          JOIN obligarth.users u ON u.id = x.user_id AND u.is_active
         WHERE x.station_id = s.id AND x.closed_at IS NULL AND x.expires_at > now()) ss ON true
     WHERE s.token_sha256 = p_token_sha256;
END $$;

-- The last contact of a station: at most once a minute, unless its address or its version changed.
CREATE FUNCTION obligarth.bench_station_touch(p_id uuid, p_ip inet, p_version text) RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station:' || p_id::text THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_touch: the station itself only';
  END IF;
  UPDATE obligarth.bench_stations s
     SET last_seen_at = now(), last_ip = p_ip,
         station_version = CASE WHEN p_version ~ '^[0-9A-Za-z.+_-]{1,32}$' THEN p_version ELSE s.station_version END
   WHERE s.id = p_id
     AND (s.last_seen_at IS NULL OR s.last_seen_at < now() - interval '1 minute' OR s.last_ip IS DISTINCT FROM p_ip
          OR (p_version ~ '^[0-9A-Za-z.+_-]{1,32}$' AND s.station_version IS DISTINCT FROM p_version));
END $$;

-- The registration (public route): idempotent on the hash, never a rename; the pending stations capped (50 in all, 3
-- per address, a pending station expiring after 24 hours).
CREATE FUNCTION obligarth.bench_register_station(p_name text, p_hostname text, p_token_sha256 text, p_version text, p_ip inet)
  RETURNS TABLE (id uuid, status text, name text, created boolean, refused text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_row obligarth.bench_stations%ROWTYPE;
  v_pending integer;
  v_by_ip integer;
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_register_station: the station surface only';
  END IF;
  PERFORM pg_advisory_xact_lock(x'6f62'::integer, x'62'::integer);
  SELECT * INTO v_row FROM obligarth.bench_stations s WHERE s.token_sha256 = p_token_sha256;
  IF FOUND THEN
    RETURN QUERY SELECT v_row.id, v_row.status, v_row.name, false, NULL::text;
    RETURN;
  END IF;
  SELECT count(*) INTO v_pending FROM obligarth.bench_stations s
   WHERE s.status = 'pending' AND s.created_at > now() - interval '24 hours';
  SELECT count(*) INTO v_by_ip FROM obligarth.bench_stations s
   WHERE s.status = 'pending' AND s.created_at > now() - interval '24 hours' AND p_ip IS NOT NULL AND s.register_ip = p_ip;
  IF v_pending >= 50 OR v_by_ip >= 3 THEN
    RETURN QUERY SELECT NULL::uuid, NULL::text, NULL::text, false, 'too_many_pending'::text;
    RETURN;
  END IF;
  INSERT INTO obligarth.bench_stations (name, hostname, token_sha256, station_version, register_ip, last_seen_at, last_ip)
  VALUES (p_name, p_hostname, p_token_sha256, CASE WHEN p_version ~ '^[0-9A-Za-z.+_-]{1,32}$' THEN p_version END, p_ip, now(), p_ip)
  RETURNING * INTO v_row;
  RETURN QUERY SELECT v_row.id, v_row.status, v_row.name, true, NULL::text;
END $$;

-- The path of a group (its ancestors' names, root first).
CREATE FUNCTION obligarth_private.bench_group_path(p_tenant integer, p_group integer) RETURNS text
  LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  WITH RECURSIVE up(id, parent_id, name, depth) AS (
    SELECT g.id, g.parent_id, g.name::text, 0 FROM obligarth.device_groups g WHERE g.tenant_id = p_tenant AND g.id = p_group
    UNION ALL
    SELECT g.id, g.parent_id, g.name::text, up.depth + 1 FROM obligarth.device_groups g
      JOIN up ON g.id = up.parent_id AND g.tenant_id = p_tenant WHERE up.depth < 32)
  SELECT string_agg(name, '/' ORDER BY depth DESC) FROM up
$$;
REVOKE ALL ON FUNCTION obligarth_private.bench_group_path(integer, integer) FROM PUBLIC;

-- The targets of a station not suspended, in every tenant (GET /api/bench/v1/targets).
CREATE FUNCTION obligarth.bench_station_targets_of(p_station uuid)
  RETURNS TABLE (tenant_id integer, tenant_name text, group_id integer, group_path text, role_policy text, allow_legacy_owner boolean,
                 name_prefix text, disable_dev_options boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station:' || p_station::text THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_targets_of: the station itself only';
  END IF;
  RETURN QUERY
    SELECT t.tenant_id, te.name::text, t.group_id, obligarth_private.bench_group_path(t.tenant_id, t.group_id), t.role_policy,
           t.allow_legacy_owner, t.name_prefix, t.disable_dev_options
      FROM obligarth.bench_station_targets t
      JOIN obligarth.tenants te ON te.id = t.tenant_id
     WHERE t.station_id = p_station AND t.suspended_at IS NULL
     ORDER BY te.name, t.group_id;
END $$;

-- The tenant of a provisioning of this station, before its context is opened; NULL for any other one.
CREATE FUNCTION obligarth.bench_provisioning_tenant(p_station uuid, p_id uuid) RETURNS integer
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v integer;
BEGIN
  IF obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station:' || p_station::text THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_provisioning_tenant: the station itself only';
  END IF;
  SELECT p.tenant_id INTO v FROM obligarth.bench_provisionings p WHERE p.id = p_id AND p.station_id = p_station;
  RETURN v;
END $$;

-- The open provisioning of this station for an ADB serial, whatever its tenant.
CREATE FUNCTION obligarth.bench_open_provisioning_of(p_station uuid, p_adb_serial text) RETURNS TABLE (id uuid, tenant_id integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station:' || p_station::text THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_open_provisioning_of: the station itself only';
  END IF;
  RETURN QUERY SELECT p.id, p.tenant_id FROM obligarth.bench_provisionings p
    WHERE p.station_id = p_station AND p.adb_serial = p_adb_serial AND p.state IN ('planned', 'token_issued', 'enrolled');
END $$;

-- The enrollment tokens a station issued since a time, in every tenant (its hourly and daily quotas).
CREATE FUNCTION obligarth.bench_station_token_count(p_station uuid, p_since timestamptz) RETURNS integer
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v integer;
BEGIN
  IF obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station:' || p_station::text THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_token_count: the station itself only';
  END IF;
  SELECT count(*)::integer INTO v FROM obligarth.legacy_agent_enrollment_tokens t
   WHERE t.origin = 'bench' AND t.created_by_station = p_station AND t.created_at >= p_since;
  RETURN v;
END $$;

-- The cap of 200 targets per station, counted across the tenants by the trigger itself (a definer trigger function: it
-- cannot be called outside its trigger, so no context can count another tenant's targets).
CREATE FUNCTION obligarth_private.bench_station_targets_cap() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('bench_station_targets:' || NEW.station_id::text));
  IF (SELECT count(*) FROM obligarth.bench_station_targets t WHERE t.station_id = NEW.station_id) >= 200 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_station_targets_cap',
      MESSAGE = 'bench_station_targets: 200 targets per station at most';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.bench_station_targets_cap() FROM PUBLIC;
CREATE TRIGGER bench_station_targets_cap BEFORE INSERT ON obligarth.bench_station_targets
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.bench_station_targets_cap();

-- The revocation or the suspension of a station, in every tenant, in the caller's transaction (identity context of a
-- platform administrator): its bench tokens not consumed revoked, its open provisionings abandoned, its session closed.
CREATE FUNCTION obligarth.bench_station_revoke_cascade(p_station uuid, p_user integer, p_reason text)
  RETURNS TABLE (tenant_id integer, tokens integer, provisionings integer)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'identity' OR obligarth.ctx_actor_user() IS DISTINCT FROM p_user
     OR NOT obligarth.ctx_actor_is_platform_admin() OR p_reason NOT IN ('station_revoked', 'station_suspended') THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_revoke_cascade: a platform administrator only';
  END IF;
  UPDATE obligarth.bench_sessions ss SET closed_at = now(), closed_by = p_user, close_reason = p_reason
   WHERE ss.station_id = p_station AND ss.closed_at IS NULL;
  RETURN QUERY
    WITH tok AS (
      UPDATE obligarth.legacy_agent_enrollment_tokens t SET revoked_at = now(), revoked_by = p_user
       WHERE t.origin = 'bench' AND t.created_by_station = p_station AND t.revoked_at IS NULL AND t.uses < t.max_uses
       RETURNING t.tenant_id),
    prov AS (
      UPDATE obligarth.bench_provisionings p SET state = 'abandoned', error_code = 'station_refused', outcome_at = now(), updated_at = now()
       WHERE p.station_id = p_station AND p.state IN ('planned', 'token_issued', 'enrolled')
       RETURNING p.tenant_id),
    ids AS (SELECT tok.tenant_id FROM tok UNION SELECT prov.tenant_id FROM prov)
    SELECT ids.tenant_id,
           (SELECT count(*)::integer FROM tok WHERE tok.tenant_id = ids.tenant_id),
           (SELECT count(*)::integer FROM prov WHERE prov.tenant_id = ids.tenant_id)
      FROM ids ORDER BY ids.tenant_id;
END $$;

-- The job (j:bench-expire): open provisionings older than 120 minutes expire (their tokens expire by themselves within
-- 30 minutes: no revocation without a user), pending stations older than 24 hours are revoked, approved stations silent
-- for 90 days are suspended, past sessions closed. One row per change, for the audit.
CREATE FUNCTION obligarth.bench_expire_open()
  RETURNS TABLE (what text, tenant_id integer, ref uuid)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_actor() IS DISTINCT FROM 'j:bench-expire' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_expire_open: the job bench-expire only';
  END IF;
  RETURN QUERY
    WITH prov AS (
      UPDATE obligarth.bench_provisionings p SET state = 'expired', outcome_at = now(), updated_at = now()
       WHERE p.state IN ('planned', 'token_issued', 'enrolled') AND p.created_at < now() - interval '120 minutes'
       RETURNING p.tenant_id, p.id),
    pend AS (
      UPDATE obligarth.bench_stations s SET status = 'revoked', revoked_at = now(), revoked_reason = 'pending_expired'
       WHERE s.status = 'pending' AND s.created_at < now() - interval '24 hours'
       RETURNING s.id),
    idle AS (
      UPDATE obligarth.bench_stations s SET status = 'suspended', suspended_at = now()
       WHERE s.status = 'approved' AND COALESCE(s.last_seen_at, s.approved_at) < now() - interval '90 days'
       RETURNING s.id),
    sess AS (
      UPDATE obligarth.bench_sessions ss SET closed_at = now(), close_reason = 'expired'
       WHERE ss.closed_at IS NULL AND (ss.expires_at <= now()
             OR EXISTS (SELECT 1 FROM obligarth.bench_stations s2 WHERE s2.id = ss.station_id AND s2.status <> 'approved'))
       RETURNING ss.id)
    SELECT 'provisioning'::text, prov.tenant_id, prov.id FROM prov
    UNION ALL SELECT 'station_expired'::text, NULL::integer, pend.id FROM pend
    UNION ALL SELECT 'station_idle'::text, NULL::integer, idle.id FROM idle
    UNION ALL SELECT 'session'::text, NULL::integer, sess.id FROM sess;
END $$;

-- A serial of the bench held by a managed device of ANOTHER tenant: written to the audit of the platform only, never
-- told to the station nor to the tenant.
CREATE FUNCTION obligarth.bench_identity_conflict(p_station uuid, p_tenant integer, p_serials text[]) RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station:' || p_station::text THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_identity_conflict: the station itself only';
  END IF;
  RETURN EXISTS (SELECT 1 FROM obligarth.devices d
                  WHERE d.tenant_id <> p_tenant AND d.enrollment_state <> 'unenrolled' AND upper(d.serial_number) = ANY (p_serials))
      OR EXISTS (SELECT 1 FROM obligarth.legacy_agent_devices a
                  WHERE a.tenant_id <> p_tenant AND a.revoked_at IS NULL
                    AND (upper(a.claimed_serial) = ANY (p_serials) OR upper(a.samsung_serial) = ANY (p_serials)));
END $$;

-- The stations that target a tenant, seen from that tenant (no token, no address, no host). The technician of an open
-- session (and its user id) only when that user is a member of the tenant: never a name from another tenant.
CREATE FUNCTION obligarth.bench_tenant_stations(p_tenant integer)
  RETURNS TABLE (id uuid, name text, status text, last_seen_at timestamptz, session_id uuid, session_expires_at timestamptz, technician text,
                 session_user_id integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'tenant' OR obligarth.ctx_tenant() IS DISTINCT FROM p_tenant THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_tenant_stations: the tenant itself only';
  END IF;
  RETURN QUERY
    SELECT s.id, s.name, s.status, s.last_seen_at, ss.id, ss.expires_at, COALESCE(NULLIF(u.display_name::text, ''), u.username::text), u.id
      FROM obligarth.bench_stations s
      LEFT JOIN obligarth.bench_sessions ss ON ss.station_id = s.id AND ss.closed_at IS NULL AND ss.expires_at > now()
      LEFT JOIN obligarth.users u ON u.id = ss.user_id
            AND EXISTS (SELECT 1 FROM obligarth.user_tenants ut WHERE ut.user_id = ss.user_id AND ut.tenant_id = p_tenant)
     WHERE EXISTS (SELECT 1 FROM obligarth.bench_station_targets t WHERE t.station_id = s.id AND t.tenant_id = p_tenant)
        OR EXISTS (SELECT 1 FROM obligarth.bench_provisionings p WHERE p.station_id = s.id AND p.tenant_id = p_tenant)
     ORDER BY s.name;
END $$;

-- A station that also targets another tenant (its session, the station's, is then opened from the platform only).
CREATE FUNCTION obligarth.bench_station_shared(p_station uuid, p_tenant integer) RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'tenant' OR obligarth.ctx_tenant() IS DISTINCT FROM p_tenant THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_shared: the tenant itself only';
  END IF;
  RETURN EXISTS (SELECT 1 FROM obligarth.bench_station_targets t WHERE t.station_id = p_station AND t.tenant_id <> p_tenant);
END $$;

-- The console of the platform (identity context, a platform administrator): the targets of a station in every tenant,
-- suspended ones included, and the counts of every station (targets, devices it enrolled).
CREATE FUNCTION obligarth.bench_station_admin_targets(p_station uuid)
  RETURNS TABLE (tenant_id integer, tenant_name text, group_id integer, group_path text, role_policy text, allow_legacy_owner boolean,
                 name_prefix text, disable_dev_options boolean, suspended_at timestamptz, created_at timestamptz, created_by integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'identity' OR NOT obligarth.ctx_actor_is_platform_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_admin_targets: a platform administrator only';
  END IF;
  RETURN QUERY
    SELECT t.tenant_id, te.name::text, t.group_id, obligarth_private.bench_group_path(t.tenant_id, t.group_id), t.role_policy,
           t.allow_legacy_owner, t.name_prefix, t.disable_dev_options, t.suspended_at, t.created_at, t.created_by
      FROM obligarth.bench_station_targets t JOIN obligarth.tenants te ON te.id = t.tenant_id
     WHERE t.station_id = p_station ORDER BY te.name, t.group_id;
END $$;

CREATE FUNCTION obligarth.bench_station_admin_counts()
  RETURNS TABLE (station_id uuid, targets integer, enrolled integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'identity' OR NOT obligarth.ctx_actor_is_platform_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_admin_counts: a platform administrator only';
  END IF;
  RETURN QUERY
    SELECT s.id,
           (SELECT count(*)::integer FROM obligarth.bench_station_targets t WHERE t.station_id = s.id),
           (SELECT count(*)::integer FROM obligarth.legacy_agent_devices a WHERE a.enrolled_by_station_id = s.id)
      FROM obligarth.bench_stations s;
END $$;

REVOKE ALL ON FUNCTION obligarth.bench_station_lookup(text), obligarth.bench_station_touch(uuid, inet, text),
  obligarth.bench_register_station(text, text, text, text, inet), obligarth.bench_station_targets_of(uuid),
  obligarth.bench_provisioning_tenant(uuid, uuid), obligarth.bench_open_provisioning_of(uuid, text),
  obligarth.bench_station_shared(uuid, integer), obligarth.bench_station_revoke_cascade(uuid, integer, text),
  obligarth.bench_expire_open(), obligarth.bench_identity_conflict(uuid, integer, text[]),
  obligarth.bench_tenant_stations(integer), obligarth.bench_station_token_count(uuid, timestamptz),
  obligarth.bench_station_admin_targets(uuid), obligarth.bench_station_admin_counts() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.bench_station_lookup(text), obligarth.bench_station_touch(uuid, inet, text),
  obligarth.bench_register_station(text, text, text, text, inet), obligarth.bench_station_targets_of(uuid),
  obligarth.bench_provisioning_tenant(uuid, uuid), obligarth.bench_open_provisioning_of(uuid, text),
  obligarth.bench_station_shared(uuid, integer), obligarth.bench_station_revoke_cascade(uuid, integer, text),
  obligarth.bench_expire_open(), obligarth.bench_identity_conflict(uuid, integer, text[]),
  obligarth.bench_tenant_stations(integer), obligarth.bench_station_token_count(uuid, timestamptz),
  obligarth.bench_station_admin_targets(uuid), obligarth.bench_station_admin_counts() TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.bench_station_lookup', 'definer', 'bench station surface: the station of a token and its open session (context none, i:bench-station)'),
  ('function', 'obligarth.bench_station_touch', 'definer', 'bench station surface: last contact of a station (i:bench-station:<id>)'),
  ('function', 'obligarth.bench_register_station', 'definer', 'bench station surface: registration, capped (context none, i:bench-station)'),
  ('function', 'obligarth.bench_station_targets_of', 'definer', 'bench station surface: the targets of a station in every tenant (i:bench-station:<id>)'),
  ('function', 'obligarth.bench_provisioning_tenant', 'definer', 'bench station surface: the tenant of a provisioning of the station (i:bench-station:<id>)'),
  ('function', 'obligarth.bench_open_provisioning_of', 'definer', 'bench station surface: the open provisioning of a serial, any tenant (i:bench-station:<id>)'),
  ('function', 'obligarth.bench_station_token_count', 'definer', 'bench station surface: the tokens a station issued since a time, every tenant (i:bench-station:<id>)'),
  ('function', 'obligarth_private.bench_station_targets_cap', 'definer', 'bench stations: the cap of 200 targets per station across the tenants (its trigger only)'),
  ('function', 'obligarth.bench_station_shared', 'definer', 'bench stations: a station that also targets another tenant (boolean), from the tenant context'),
  ('function', 'obligarth.bench_station_revoke_cascade', 'definer', 'bench stations: revocation or suspension in every tenant (identity context, platform administrator)'),
  ('function', 'obligarth.bench_expire_open', 'definer', 'bench stations: expiry of provisionings, pending stations and sessions (j:bench-expire)'),
  ('function', 'obligarth.bench_identity_conflict', 'definer', 'bench stations: a serial held in another tenant, platform audit only (i:bench-station:<id>)'),
  ('function', 'obligarth.bench_tenant_stations', 'definer', 'bench stations: the stations that target a tenant or enrolled into it, from its context'),
  ('function', 'obligarth.bench_station_admin_targets', 'definer', 'bench stations: the targets of a station in every tenant (identity context, platform administrator)'),
  ('function', 'obligarth.bench_station_admin_counts', 'definer', 'bench stations: targets and enrolled devices per station (identity context, platform administrator)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

-- i) The capabilities of the permission sets that hold mdm.enrollment.manage (a tenant administrator holds every one).
UPDATE obligarth.permission_sets SET capabilities = capabilities || '["mdm.bench.manage"]'::jsonb
 WHERE capabilities @> '["mdm.enrollment.manage"]'::jsonb AND NOT capabilities @> '["mdm.bench.manage"]'::jsonb;
UPDATE obligarth.permission_sets SET capabilities = capabilities || '["mdm.bench.operate"]'::jsonb
 WHERE capabilities @> '["mdm.enrollment.manage"]'::jsonb AND NOT capabilities @> '["mdm.bench.operate"]'::jsonb;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('bench_stations cannot be rolled back: restore the backup taken before the upgrade');
}
