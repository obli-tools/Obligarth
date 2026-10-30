import type { Knex } from 'knex';

// =============================================================================
// Bridge agent 1.3.0: policies of the bridge agent (lot PONT-POL)
// =============================================================================
//   - policies_sections_check admits 'legacy_agent' (content key sections.legacyAgent).
//   - mdm_artifacts / device_artifacts admit the channel 'agent' (identifier 'policy', key agent:policy).
//   - legacy_agent_files (class tenant): the tenant's file store (deposit files, kiosk images, CAs), by content,
//     immutable but its name, note and origin; bytes on disk at <LEGACY_AGENT_FILES_DIR or customDir/agent-files>/
//     <tenant>/<sha256>.bin.
//   - legacy_agent_policy_reports (class tenant): the last compliance report of each device (one row per device).
// No new function: the download gate is an ordinary query of the tenant, and the collection of the store runs per
// tenant in its context. The vault needs nothing: its purposes are free-form (policy.kiosk_pin is new).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean()
// last, a down that raises. Runs as obligarth_owner (server-migrate), after mcp_access_keys.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Bridge agent: policies (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.legacy_agent_devices') IS NULL
     OR to_regclass('obligarth.mdm_artifacts') IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'policies_sections_check') THEN
    RAISE EXCEPTION 'legacy_agent_policies: apply the RLS, mdm_model_expand and legacy_agent migrations first';
  END IF;
END $$;

-- 1. Sections and channel ------------------------------------------------------------
ALTER TABLE obligarth.policies
  DROP CONSTRAINT policies_sections_check,
  ADD CONSTRAINT policies_sections_check CHECK (sections <@ ARRAY['apple', 'android', 'legacy_agent']::varchar[]);

ALTER TABLE obligarth.mdm_artifacts
  DROP CONSTRAINT mdm_artifacts_channel_check,
  ADD CONSTRAINT mdm_artifacts_channel_check CHECK (channel IN ('ddm', 'profile', 'app', 'setting', 'amapi', 'agent')),
  DROP CONSTRAINT mdm_artifacts_identifier_check,
  ADD CONSTRAINT mdm_artifacts_identifier_check CHECK (
       (channel = 'ddm' AND identifier ~ '^obg\.cfg\.pol-[A-Za-z0-9._-]{1,52}$')
    OR (channel = 'profile' AND identifier ~ '^tools\.obli\.obligarth\.(p|raw)\.[A-Za-z0-9._-]{1,140}$')
    OR (channel = 'app' AND identifier ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$')
    OR (channel = 'setting' AND identifier ~ '^[a-z][a-z0-9_]{0,63}$')
    OR (channel = 'amapi' AND identifier = 'policy')
    OR (channel = 'agent' AND identifier = 'policy'));

ALTER TABLE obligarth.device_artifacts
  DROP CONSTRAINT device_artifacts_key_check,
  ADD CONSTRAINT device_artifacts_key_check
      CHECK (artifact_key ~ '^(ddm|profile|app|setting|amapi|agent):[A-Za-z0-9][A-Za-z0-9._-]{0,199}$');

-- 2. File store --------------------------------------------------------------------
CREATE TABLE obligarth.legacy_agent_files (
  id            uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id     integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  sha256        char(64)      NOT NULL,
  size_bytes    bigint        NOT NULL,
  name          varchar(200)  NOT NULL,
  content_type  varchar(100)  NOT NULL,
  kind          varchar(12)   NOT NULL,                 -- file | image | certificate
  origin        varchar(12)   NOT NULL,                 -- upload | import
  note          varchar(500),
  created_by    integer,
  created_at    timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT legacy_agent_files_pkey PRIMARY KEY (id),
  CONSTRAINT legacy_agent_files_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT legacy_agent_files_tenant_sha_unique UNIQUE (tenant_id, sha256),
  CONSTRAINT legacy_agent_files_tenant_id_foreign FOREIGN KEY (tenant_id) REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT legacy_agent_files_created_by_foreign FOREIGN KEY (created_by) REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT legacy_agent_files_sha_check CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT legacy_agent_files_size_check CHECK (size_bytes BETWEEN 1 AND 67108864),
  CONSTRAINT legacy_agent_files_kind_check CHECK (kind IN ('file', 'image', 'certificate')),
  CONSTRAINT legacy_agent_files_origin_check CHECK (origin IN ('upload', 'import')),
  CONSTRAINT legacy_agent_files_image_size CHECK (kind <> 'image' OR size_bytes <= 262144),
  CONSTRAINT legacy_agent_files_image_type CHECK (kind <> 'image' OR content_type IN ('image/png', 'image/jpeg', 'image/gif', 'image/x-icon')),
  CONSTRAINT legacy_agent_files_cert_size CHECK (kind <> 'certificate' OR size_bytes <= 8192),
  CONSTRAINT legacy_agent_files_name_check CHECK (btrim(name) <> '' AND name !~ '[[:cntrl:]/\\]'),
  CONSTRAINT legacy_agent_files_type_check CHECK (content_type ~ '^[a-z0-9.+-]+/[a-z0-9.+-]+$'),
  CONSTRAINT legacy_agent_files_note_check CHECK (note IS NULL OR note !~ '[[:cntrl:]]')
);
CREATE INDEX legacy_agent_files_created ON obligarth.legacy_agent_files (tenant_id, created_at DESC);
SELECT obligarth_private.rls_apply('obligarth.legacy_agent_files', 'tenant',
  'bridge agent policies: the tenant file store (deposit files, kiosk images, CAs), by content');
-- The content, its kind and its author never change.
REVOKE UPDATE ON obligarth.legacy_agent_files FROM obligarth;
GRANT UPDATE (name, note, origin) ON obligarth.legacy_agent_files TO obligarth;

-- 3. Compliance reports -------------------------------------------------------------
CREATE TABLE obligarth.legacy_agent_policy_reports (
  tenant_id        integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id        integer      NOT NULL,
  policy_hash      char(64),                              -- NULL: the agent holds no policy
  state            varchar(10)  NOT NULL,
  knox_state       varchar(16),
  items            jsonb        NOT NULL DEFAULT '[]',
  compliant        integer      NOT NULL DEFAULT 0,
  non_compliant    integer      NOT NULL DEFAULT 0,
  pending          integer      NOT NULL DEFAULT 0,
  pending_licence  integer      NOT NULL DEFAULT 0,
  unsupported      integer      NOT NULL DEFAULT 0,
  errors           integer      NOT NULL DEFAULT 0,
  applied_at       timestamptz,                           -- the agent's clock (corrected by clock_offset_s)
  received_at      timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT legacy_agent_policy_reports_pkey PRIMARY KEY (tenant_id, device_id),
  CONSTRAINT legacy_agent_policy_reports_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT legacy_agent_policy_reports_hash_check CHECK (policy_hash IS NULL OR policy_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT legacy_agent_policy_reports_state_check CHECK (state IN ('applied', 'partial', 'pending', 'error', 'none')),
  CONSTRAINT legacy_agent_policy_reports_items_check CHECK (jsonb_typeof(items) = 'array'
    AND jsonb_array_length(items) <= 200 AND octet_length(items::text) <= 98304),
  CONSTRAINT legacy_agent_policy_reports_counts_check CHECK (compliant >= 0 AND non_compliant >= 0 AND pending >= 0
    AND pending_licence >= 0 AND unsupported >= 0 AND errors >= 0)
);
CREATE INDEX legacy_agent_policy_reports_state ON obligarth.legacy_agent_policy_reports (tenant_id, state);
SELECT obligarth_private.rls_apply('obligarth.legacy_agent_policy_reports', 'tenant',
  'bridge agent policies: last compliance report per device (never a secret: codes and short details)');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
