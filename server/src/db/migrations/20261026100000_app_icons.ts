import type { Knex } from 'knex';

// =============================================================================
// The apps of a device as a grid of icons (plan « onglet Applications », tranche T1)
// =============================================================================
//   - device_apps: is_system (a real boolean: the bridge agent's flag, AMAPI's applicationSource; the agent stored it
//     in management_status = 'system' until now, which this migration moves), launchable (an activity of category
//     LAUNCHER, agent 1.0.2), installer (the installer package), installed_at / app_updated_at (the agent's
//     firstInstallAt / lastUpdateAt), version_changed_at (kept by the server at each change of version or build:
//     the sort « recently updated »);
//   - app_icons (class tenant): the icon of an app sent by a device of the tenant (bridge agent: POST
//     /agent/v1/icons), one row per (tenant, platform family, identifier). A row 'pending' is a lease: the device
//     asked to send it (requested_device_id, requested_at), one device at a time; 'stored' holds the canonical PNG
//     (re-encoded by the server, 32 KiB at most, square, 16 to 192 px) and its SHA-256; 'none' records an app
//     without an icon. The bytes come from a device: never trusted, never served outside the tenant, never as
//     anything but image/png (no content type column: PNG only). created_device_id / created_at: the device whose
//     inventory created the row (the quota of new rows a device may create per day); failed_device_id / failed_at:
//     the last device that could not send the icon (it said so, the server refused it, or its lease expired
//     unanswered): never asked again for 30 days.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean()
// last. Runs as obligarth_owner (server-migrate), after android_commands_move.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Apps of a device: device_apps columns, app_icons (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.device_apps') IS NULL OR to_regclass('obligarth.legacy_agent_devices') IS NULL THEN
    RAISE EXCEPTION 'app_icons: apply the RLS migrations, mdm_model_expand and legacy_agent first';
  END IF;
END $$;

-- 1. device_apps ----------------------------------------------------------------------
ALTER TABLE obligarth.device_apps
  ADD COLUMN is_system          boolean,
  ADD COLUMN launchable         boolean,
  ADD COLUMN installer          varchar(255),
  ADD COLUMN installed_at       timestamptz,
  ADD COLUMN app_updated_at     timestamptz,
  ADD COLUMN version_changed_at timestamptz;

-- The agent's system flag leaves management_status (a status of the management, never a category).
UPDATE obligarth.device_apps SET is_system = true, management_status = NULL
 WHERE source = 'agent_report' AND management_status = 'system';
UPDATE obligarth.device_apps SET is_system = false WHERE source = 'agent_report' AND is_system IS NULL;

-- 2. app_icons ------------------------------------------------------------------------
CREATE TABLE obligarth.app_icons (
  tenant_id           integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  platform_family     varchar(16)   NOT NULL,
  identifier          varchar(255)  NOT NULL,
  state               varchar(8)    NOT NULL DEFAULT 'pending',   -- pending | stored | none
  source              varchar(8)    NOT NULL DEFAULT 'agent',
  version_code        bigint,                                     -- of the app when the icon was rendered
  sha256              char(64),                                   -- of the canonical PNG
  bytes               bytea,                                      -- the canonical PNG (re-encoded by the server)
  width               smallint,
  source_device_id    integer,                                    -- the device that sent it
  requested_device_id integer,                                    -- the lease: the device asked to send it
  requested_at        timestamptz,
  created_device_id   integer,                                    -- the device whose inventory created the row
  created_at          timestamptz   NOT NULL DEFAULT now(),
  failed_device_id    integer,                                    -- the last device that could not send it
  failed_at           timestamptz,
  updated_at          timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT app_icons_pkey PRIMARY KEY (tenant_id, platform_family, identifier),
  CONSTRAINT app_icons_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT app_icons_family_check CHECK (platform_family IN ('apple', 'android')),
  CONSTRAINT app_icons_identifier_check CHECK (identifier ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$'),
  CONSTRAINT app_icons_state_check CHECK (state IN ('pending', 'stored', 'none')),
  CONSTRAINT app_icons_source_check CHECK (source IN ('agent')),
  CONSTRAINT app_icons_stored_coherent CHECK ((state = 'stored') = (bytes IS NOT NULL AND sha256 IS NOT NULL)),
  CONSTRAINT app_icons_bytes_size CHECK (bytes IS NULL OR octet_length(bytes) BETWEEN 67 AND 32768),
  CONSTRAINT app_icons_sha_hex CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT app_icons_width CHECK (width IS NULL OR width BETWEEN 16 AND 192),
  CONSTRAINT app_icons_version_code CHECK (version_code IS NULL OR version_code >= 0),
  CONSTRAINT app_icons_failed_coherent CHECK (failed_device_id IS NULL OR failed_at IS NOT NULL),
  CONSTRAINT app_icons_src_dev_fk FOREIGN KEY (tenant_id, source_device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (source_device_id),
  CONSTRAINT app_icons_req_dev_fk FOREIGN KEY (tenant_id, requested_device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (requested_device_id),
  CONSTRAINT app_icons_created_dev_fk FOREIGN KEY (tenant_id, created_device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (created_device_id),
  CONSTRAINT app_icons_failed_dev_fk FOREIGN KEY (tenant_id, failed_device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (failed_device_id)
);
CREATE INDEX app_icons_sha ON obligarth.app_icons (tenant_id, sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX app_icons_updated ON obligarth.app_icons (tenant_id, updated_at);
CREATE INDEX app_icons_created ON obligarth.app_icons (tenant_id, created_device_id, created_at) WHERE created_device_id IS NOT NULL;
SELECT obligarth_private.rls_apply('obligarth.app_icons', 'tenant');

SELECT obligarth.rls_assert_clean();
`;

const DOWN = String.raw`
SET LOCAL search_path = pg_catalog, pg_temp;
DROP TABLE obligarth.app_icons;
DELETE FROM obligarth_private.rls_registry WHERE object_kind = 'table' AND object_name = 'obligarth.app_icons';
UPDATE obligarth.device_apps SET management_status = 'system'
 WHERE source = 'agent_report' AND is_system = true AND management_status IS NULL;
ALTER TABLE obligarth.device_apps
  DROP COLUMN is_system,
  DROP COLUMN launchable,
  DROP COLUMN installer,
  DROP COLUMN installed_at,
  DROP COLUMN app_updated_at,
  DROP COLUMN version_changed_at;
SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw(DOWN);
}
