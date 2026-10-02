import type { Knex } from 'knex';

// =============================================================================
// Apple integration, part 1: tenant registry and deadlines (docs: integration-apple-edge §4.2, §6)
// =============================================================================
//   - tenants.uuid: immutable external reference of a tenant (external_ref given to apple-edge);
//     tenants.mdm_key: the opaque MDM key apple-edge generated, written once by
//     obligarth.tenant_set_mdm_key(), never changed after (trigger tenants_guard_identity). Neither column
//     joins the column UPDATE privileges of the runtime role (rls-tenant R11, A.6).
//   - obligarth.tenant_lookup_by_mdm_key(): the tenant of an MDM key (device surface, DDM relay), callable
//     in the context 'none'.
//   - tenant_apple_edge: the tenant's state in apple-edge (mirror), its CA and the cached enrollment
//     configuration (no secret).
//   - integration_deadline_items (class tenant_or_global) and the view integration_deadlines (INT-05).
// Same columns, types, constraints and names as the specification, written in SQL like the migrations of
// lot A; tenant_id of the tenant tables defaults to the context's tenant (rls-tenant §5.4, rule 5). Runs as
// obligarth_owner (server-migrate), after the RLS migrations; ends with obligarth.rls_assert_clean(). No
// question mark in the SQL (knex.raw would bind it); kept verbatim by String.raw.

const EDGE_STATES = ['unprovisioned', 'provisioning', 'active', 'suspended', 'retiring', 'retired',
  'load_failed', 'missing', 'error'];
const DEADLINE_KINDS = ['apns_certificate', 'ade_token', 'vpp_token', 'device_ca', 'mdm_tls_certificate',
  'vendor_certificate', 'mdm_domain', 'profile_signing_identity', 'vault_escrow_test', 'vault_kek_rotation',
  'vault_old_shares', 'vault_dek_destruction'];
const DEADLINE_SOURCES = ['apple-edge', 'brain', 'manual', 'vault'];

const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

const UP = String.raw`-- =============================================================================
-- Apple integration, part 1: tenant registry and deadlines (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regprocedure('obligarth.ctx_actor_is_platform_admin()') IS NULL THEN
    RAISE EXCEPTION 'Apple migrations need the RLS migrations (rls_foundation … rls_policies) first';
  END IF;
END $$;

-- ── tenants: external reference and MDM key ─────────────────────────────────
-- uuid: the tenant lifecycle specification may add it first.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_attribute
                 WHERE attrelid = 'obligarth.tenants'::regclass AND attname = 'uuid' AND NOT attisdropped) THEN
    ALTER TABLE obligarth.tenants ADD COLUMN uuid uuid NOT NULL DEFAULT gen_random_uuid();
    ALTER TABLE obligarth.tenants ADD CONSTRAINT tenants_uuid_unique UNIQUE (uuid);
  END IF;
END $$;
ALTER TABLE obligarth.tenants ADD COLUMN mdm_key varchar(16);
ALTER TABLE obligarth.tenants ADD CONSTRAINT tenants_mdm_key_unique UNIQUE (mdm_key);
ALTER TABLE obligarth.tenants ADD CONSTRAINT tenants_mdm_key_check
  CHECK (mdm_key IS NULL OR mdm_key ~ '^[a-km-np-z2-9]{16}$');

-- uuid and mdm_key never change once set (any role, migrations included).
CREATE FUNCTION obligarth.tenants_guard_identity() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.uuid IS DISTINCT FROM OLD.uuid THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenants.uuid is immutable';
  END IF;
  IF OLD.mdm_key IS NOT NULL AND NEW.mdm_key IS DISTINCT FROM OLD.mdm_key THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenants.mdm_key is immutable once set';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth.tenants_guard_identity() FROM PUBLIC;
CREATE TRIGGER tenants_guard_identity BEFORE UPDATE OF uuid, mdm_key ON obligarth.tenants
  FOR EACH ROW EXECUTE FUNCTION obligarth.tenants_guard_identity();

-- rls-tenant annex A.6: tenant of an MDM key (device surface, DDM relay), in the context 'none'.
CREATE FUNCTION obligarth.tenant_lookup_by_mdm_key(p_key text) RETURNS integer
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT t.id FROM obligarth.tenants t WHERE t.mdm_key = p_key
$$;
REVOKE ALL ON FUNCTION obligarth.tenant_lookup_by_mdm_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.tenant_lookup_by_mdm_key(text) TO obligarth;

-- Write-once MDM key: a job (provisioning, outbox) or an active platform administrator.
CREATE FUNCTION obligarth.tenant_set_mdm_key(p_tenant_id integer, p_key text) RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_current text;
BEGIN
  IF NOT (COALESCE(obligarth.ctx_actor() ~ '^j:', false) OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant_set_mdm_key: job or platform administrator required';
  END IF;
  IF p_key IS NULL OR p_key !~ '^[a-km-np-z2-9]{16}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'tenant_set_mdm_key: invalid key';
  END IF;
  SELECT t.mdm_key INTO v_current FROM obligarth.tenants t WHERE t.id = p_tenant_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'tenant_set_mdm_key: unknown tenant';
  END IF;
  IF v_current IS NULL THEN
    UPDATE obligarth.tenants SET mdm_key = p_key, updated_at = now() WHERE id = p_tenant_id;
  ELSIF v_current <> p_key THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'tenant_set_mdm_key: the tenant already has another key';
  END IF;
END $$;
REVOKE ALL ON FUNCTION obligarth.tenant_set_mdm_key(integer, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.tenant_set_mdm_key(integer, text) TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.tenant_lookup_by_mdm_key', 'definer', 'device surface, DDM relay: tenant of an MDM key'),
  ('function', 'obligarth.tenant_set_mdm_key', 'definer', 'apple-edge provisioning: write-once MDM key')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

-- ── tenant_apple_edge: mirror of the tenant in apple-edge ─────────────────────
CREATE TABLE obligarth.tenant_apple_edge (
  tenant_id             integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  edge_state            varchar(16)  NOT NULL DEFAULT 'unprovisioned',
  edge_state_at         timestamptz,                        -- occurred_at of the event (or call) that set it
  commands_frozen       boolean      NOT NULL DEFAULT false,
  ca_id                 uuid,
  ca_sha256             varchar(64),
  ca_not_after          timestamptz,
  ca_verify_only        jsonb        NOT NULL DEFAULT '[]', -- [{id, sha256, not_after}]
  enrollment_config     jsonb,                              -- GET …/enrollment-config (no secret)
  enrollment_config_at  timestamptz,
  provision_attempts    integer      NOT NULL DEFAULT 0,
  last_error_code       varchar(64),
  last_synced_at        timestamptz,
  created_at            timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at            timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT tenant_apple_edge_pkey PRIMARY KEY (tenant_id),
  CONSTRAINT tenant_apple_edge_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT tenant_apple_edge_edge_state_check CHECK (edge_state IN (${list(EDGE_STATES)})),
  CONSTRAINT tenant_apple_edge_ca_sha256_check CHECK (ca_sha256 IS NULL OR ca_sha256 ~ '^[0-9a-f]{64}$')
);
SELECT obligarth_private.rls_apply('obligarth.tenant_apple_edge', 'tenant', 'apple-edge mirror of the tenant');

-- ── integration_deadline_items: INT-05 ───────────────────────────────────────
CREATE TABLE obligarth.integration_deadline_items (
  id                      uuid         NOT NULL,           -- generated by the server
  tenant_id               integer      DEFAULT obligarth.ctx_tenant(),   -- NULL: the instance
  kind                    varchar(32)  NOT NULL,
  subject_ref             varchar(100) NOT NULL,           -- e.g. apple-edge id of the certificate or token
  label                   varchar(200) NOT NULL,           -- e.g. topic, server name; never a person
  not_after               timestamptz,
  source                  varchar(16)  NOT NULL,
  account_hint            varchar(200),                    -- Apple account used (C3), never a password
  details                 jsonb        NOT NULL DEFAULT '{}',
  last_alert_threshold    smallint,                        -- 60, 30, 14, 7, 3, 1 or 0 already alerted
  last_alerted_not_after  timestamptz,                     -- the not_after those alerts were about
  retired_at              timestamptz,                     -- subject gone; row kept 30 days
  created_at              timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at              timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT integration_deadline_items_pkey PRIMARY KEY (id),
  CONSTRAINT integration_deadline_items_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT integration_deadline_items_kind_check CHECK (kind IN (${list(DEADLINE_KINDS)})),
  CONSTRAINT integration_deadline_items_source_check CHECK (source IN (${list(DEADLINE_SOURCES)}))
);
CREATE UNIQUE INDEX integration_deadline_items_subject
  ON obligarth.integration_deadline_items ((coalesce(tenant_id, 0)), kind, subject_ref);
CREATE INDEX integration_deadline_items_due ON obligarth.integration_deadline_items (not_after)
  WHERE retired_at IS NULL;
SELECT obligarth_private.rls_apply('obligarth.integration_deadline_items', 'tenant_or_global',
  'INT-05 deadlines; tenant_id NULL: instance items, written in the identity context');

CREATE VIEW obligarth.integration_deadlines WITH (security_invoker = true) AS
SELECT i.id, i.tenant_id, i.kind, i.subject_ref, i.label, i.not_after, i.source, i.account_hint, i.details,
       i.last_alert_threshold, i.retired_at, i.updated_at,
       CASE WHEN i.not_after IS NULL THEN NULL
            ELSE floor(extract(epoch FROM (i.not_after - now())) / 86400)::integer END AS days_left,
       CASE WHEN i.retired_at IS NOT NULL THEN 'retired'
            WHEN i.not_after IS NULL THEN 'unknown'
            WHEN i.not_after <= now() THEN 'expired'
            WHEN i.not_after <= now() + interval '7 days' THEN 'critical'
            WHEN i.not_after <= now() + interval '30 days' THEN 'warning'
            ELSE 'ok' END AS level
  FROM obligarth.integration_deadline_items i;
REVOKE ALL ON obligarth.integration_deadlines FROM PUBLIC;
GRANT SELECT ON obligarth.integration_deadlines TO obligarth, obligarth_reader;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
