import type { Knex } from 'knex';

// =============================================================================
// Sites (lot P1-SITE; spec P1-QR-SITES §2.1)
// =============================================================================
//   - sites (class tenant): the places of a tenant ("the store Exemple-Nord"): a code unique in the tenant (case-blind), a
//     name, a city, a contact, the group its devices may be filed in (gone with the group: SET NULL), and its values
//     (a JSON object key → text, the fallback of {{device.custom.<key>}} and the {{site.<key>}} of the bridge agent's
//     templates). The rules of a key and of a value (50 pairs, 500 characters, the reserved names) are the service's
//     (sites/model.ts); the table bounds the object as a whole. An archived site keeps its row (archived_at); the
//     service refuses to archive a site that still has devices. The tenant of a site never changes.
//   - devices.site_id: the site of a device (one at most), in the device's tenant (devices_site_fk on (tenant_id,
//     site_id)), NULL once the site is deleted. Its partial index (tenant_id, site_id) serves the counts of a site and
//     the filter of the list; every row is NULL when it is built (the column is new), so the build holds nothing.
//   - site_batches (class tenant): a batch of site writes an AI agent asked through the MCP server (§2.5), kept until its
//     human approves it with a second factor (one authorization per batch): its request (an import of up to 2 MiB does
//     not fit in the arguments of an authorization) and the digest of the plan approved. Consumed once; kept a day.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean() last,
// a down that raises. Runs as obligarth_owner (server-migrate), after bench_stations.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Sites (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.devices') IS NULL
     OR to_regclass('obligarth.device_groups') IS NULL THEN
    RAISE EXCEPTION 'sites: apply the RLS migrations and mdm_model_expand first';
  END IF;
END $$;

-- 1. sites -----------------------------------------------------------------------------
CREATE TABLE obligarth.sites (
  id           uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id    integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  code         varchar(32)   NOT NULL,
  name         varchar(200)  NOT NULL,
  city         varchar(100),
  group_id     integer,
  "values"     jsonb         NOT NULL DEFAULT '{}'::jsonb,   -- key → text (sites/model.ts)
  contact      varchar(200),
  archived_at  timestamptz,
  created_at   timestamptz   NOT NULL DEFAULT now(),
  updated_at   timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT sites_pkey PRIMARY KEY (id),
  CONSTRAINT sites_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT sites_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT sites_group_fk FOREIGN KEY (tenant_id, group_id)
    REFERENCES obligarth.device_groups (tenant_id, id) ON DELETE SET NULL (group_id),
  -- Texts of the console: trimmed, not blank, no control character.
  CONSTRAINT sites_code_check CHECK (code = btrim(code) AND code <> '' AND code !~ '[\x01-\x1f\x7f]'),
  CONSTRAINT sites_name_check CHECK (name = btrim(name) AND name <> '' AND name !~ '[\x01-\x1f\x7f]'),
  CONSTRAINT sites_city_check CHECK (city IS NULL OR (city = btrim(city) AND city <> '' AND city !~ '[\x01-\x1f\x7f]')),
  CONSTRAINT sites_contact_check CHECK (contact IS NULL OR (contact = btrim(contact) AND contact <> '' AND contact !~ '[\x01-\x1f\x7f]')),
  CONSTRAINT sites_values_check CHECK (COALESCE(jsonb_typeof("values") = 'object', false) AND octet_length("values"::text) <= 65536)
);
-- One code per tenant, whatever its case (the import matches the codes that way).
CREATE UNIQUE INDEX sites_code_uq ON obligarth.sites (tenant_id, lower(code));
CREATE INDEX sites_group ON obligarth.sites (tenant_id, group_id) WHERE group_id IS NOT NULL;
SELECT obligarth_private.rls_apply('obligarth.sites', 'tenant',
  'sites of a tenant (lot P1-SITE): code, name, city, contact, group of its devices, values read by the agent templates');
-- The tenant of a site never changes.
REVOKE UPDATE ON obligarth.sites FROM obligarth;
GRANT UPDATE (code, name, city, group_id, "values", contact, archived_at, updated_at) ON obligarth.sites TO obligarth;

-- 2. devices.site_id -------------------------------------------------------------------
ALTER TABLE obligarth.devices ADD COLUMN site_id uuid;
ALTER TABLE obligarth.devices ADD CONSTRAINT devices_site_fk FOREIGN KEY (tenant_id, site_id)
  REFERENCES obligarth.sites (tenant_id, id) ON DELETE SET NULL (site_id);
CREATE INDEX devices_site ON obligarth.devices (tenant_id, site_id) WHERE site_id IS NOT NULL;

-- 3. site_batches ----------------------------------------------------------------------
-- A batch of writes of the sites an AI agent asked through the MCP server (import_sites, sites_from_devices,
-- upsert_site, archive_site, set_device_site with dry_run false): its request as validated (an import's CSV text: up to
-- 2 MiB, too large for the arguments of an authorization) and the digest of the plan its human approves. Read again and
-- consumed once at the approval, which makes the plan again and refuses it when its digest changed. Kept a day.
CREATE TABLE obligarth.site_batches (
  id           uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id    integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  user_id      integer       NOT NULL,
  tool         varchar(64)   NOT NULL,
  request      jsonb         NOT NULL,
  digest       char(64)      NOT NULL,
  created_at   timestamptz   NOT NULL DEFAULT now(),
  expires_at   timestamptz   NOT NULL,
  consumed_at  timestamptz,
  CONSTRAINT site_batches_pkey PRIMARY KEY (id),
  CONSTRAINT site_batches_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT site_batches_user_id_foreign FOREIGN KEY (user_id)
    REFERENCES obligarth.users (id) ON DELETE CASCADE,
  CONSTRAINT site_batches_tool_check CHECK (tool ~ '^[a-z_]{1,64}$'),
  CONSTRAINT site_batches_digest_check CHECK (digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT site_batches_request_check CHECK (COALESCE(jsonb_typeof(request) = 'object', false) AND octet_length(request::text) <= 3145728)
);
CREATE INDEX site_batches_expiry ON obligarth.site_batches (tenant_id, expires_at);
SELECT obligarth_private.rls_apply('obligarth.site_batches', 'tenant',
  'batches of site writes asked by an AI agent (lot P1-SITE), approved by its human with a second factor');
REVOKE UPDATE ON obligarth.site_batches FROM obligarth;
GRANT UPDATE (consumed_at) ON obligarth.site_batches TO obligarth;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
