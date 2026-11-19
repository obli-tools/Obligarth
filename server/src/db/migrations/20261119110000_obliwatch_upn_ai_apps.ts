import type { Knex } from 'knex';

// =============================================================================
// Obliwatch integration, lot L4 (brief GTH-02, GTH-06): UPN of the end users, AI catalog, Authenticator marker
// =============================================================================
//   - end_users.upn varchar(320) NULL and end_users.entra_object_id uuid NULL: entered by hand or imported (no
//     directory synchronisation, owner decision). Case-insensitive unique per tenant (lower(upn)), like the e-mail: the
//     two partial unique indexes are built CONCURRENTLY by the next migration (end_users is written by every
//     enrollment). The suite installs no extension (no citext): lower() as for end_users_email_uq. Nullable columns
//     without a default: a change of the catalog only, no row rewritten. The shape check of the UPN is added valid, in
//     the same transaction as the ADD COLUMN, so under its ACCESS EXCLUSIVE lock (a NOT VALID / VALIDATE split would
//     gain nothing there): one scan of end_users, a small table whose new column is NULL in every row, bounded by the
//     lock_timeout of 5 s to take the lock.
//     They are not an identity of end_users_identity_present (an e-mail, a Managed Apple Account or an external id is
//     still required): the CHECK is unchanged.
//   - obliwatch_ai_catalog (catalog: read everywhere, written in the identity context of i:obliwatch): ONE row, the
//     last AI catalog fetched from Obliwatch by the daily job integrations.obliwatch.catalog-sync (the bundles section
//     of GET /api/external/v1/catalogues/ai-domains), 5 000 bundles at most. Global data, no tenant data.
//   - trigger device_apps_authenticator_marker: an inventory row of Microsoft Authenticator (com.azure.authenticator,
//     com.microsoft.azureauthenticator) inserted, deleted or whose version or managed flag changes marks its device
//     (devices.signal_updated_at), so that GET /devices?updatedSince= serves authenticatorVersion again. The WHEN of
//     each trigger compares the identifier only: any other app costs one comparison, no statement. Like the trigger of
//     devices (20261118100100), it runs whatever OBLIWATCH_INTEGRATION says (nothing reads the marker while it is
//     off); its UPDATE is in a swallowing subtransaction with NOWAIT: never the failure nor a wait of the writer.
// Additive, re-runnable (IF NOT EXISTS, guarded DO blocks, CREATE OR REPLACE, DROP TRIGGER IF EXISTS), safe on a live
// database at start (lock_timeout: fail fast rather than queue the writers of end_users and device_apps).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for the new table, the trigger function
// with SET search_path and EXECUTE revoked from PUBLIC, rls_assert_clean() last, a down that raises. Runs as
// obligarth_owner (server-migrate).
// =============================================================================

const UP = String.raw`-- =============================================================================
-- end_users.upn / entra_object_id, obliwatch_ai_catalog, Authenticator marker (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'obligarth_private' AND p.proname = 'rls_apply') THEN
    RAISE EXCEPTION 'obliwatch_upn_ai_apps: apply the rls foundation first';
  END IF;
  IF to_regclass('obligarth.end_users') IS NULL OR to_regclass('obligarth.device_apps') IS NULL THEN
    RAISE EXCEPTION 'obliwatch_upn_ai_apps: end_users and device_apps are missing';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'obligarth.devices'::regclass
                  AND attname = 'signal_updated_at' AND NOT attisdropped) THEN
    RAISE EXCEPTION 'obliwatch_upn_ai_apps: apply the devices_signal_marker migration first';
  END IF;
END $$;

-- 1. UPN and Entra object id of the end users ----------------------------------------------------------
ALTER TABLE obligarth.end_users ADD COLUMN IF NOT EXISTS upn varchar(320);
ALTER TABLE obligarth.end_users ADD COLUMN IF NOT EXISTS entra_object_id uuid;
COMMENT ON COLUMN obligarth.end_users.upn IS
  'User principal name of the client directory (entered or imported; Obliwatch GTH-02): unique per tenant, case insensitive (end_users_upn_uq)';
COMMENT ON COLUMN obligarth.end_users.entra_object_id IS
  'Object id of the person in Entra ID (entered or imported; Obliwatch GTH-02): unique per tenant (end_users_entra_uq)';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'obligarth.end_users'::regclass
                  AND conname = 'end_users_upn_shape') THEN
    ALTER TABLE obligarth.end_users ADD CONSTRAINT end_users_upn_shape
      CHECK (upn IS NULL OR (length(upn) BETWEEN 3 AND 320 AND upn ~ '^[^[:space:]@]+@[^[:space:]@]+$'));
  END IF;
END $$;

-- 2. The AI catalog of Obliwatch (one row) -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obligarth.obliwatch_ai_catalog (
  id            smallint      NOT NULL DEFAULT 1,
  version       varchar(128),
  etag          varchar(256),
  bundles       jsonb         NOT NULL DEFAULT '[]',
  bundle_count  integer       NOT NULL DEFAULT 0,
  fetched_at    timestamptz,
  checked_at    timestamptz   NOT NULL DEFAULT now(),
  last_status   varchar(40)   NOT NULL DEFAULT 'never',
  CONSTRAINT obliwatch_ai_catalog_pkey PRIMARY KEY (id),
  CONSTRAINT obliwatch_ai_catalog_single CHECK (id = 1),
  CONSTRAINT obliwatch_ai_catalog_bundles_array CHECK (jsonb_typeof(bundles) = 'array' AND jsonb_array_length(bundles) <= 5000),
  CONSTRAINT obliwatch_ai_catalog_count CHECK (bundle_count BETWEEN 0 AND 5000),
  CONSTRAINT obliwatch_ai_catalog_status_check CHECK (last_status ~ '^[a-z][a-z0-9_]{0,39}$')
);
COMMENT ON TABLE obligarth.obliwatch_ai_catalog IS
  'Obliwatch integration (GTH-06): the last AI catalog fetched from Obliwatch (bundles: [{platform, bundleId, name}], 5000 at most); one row, no tenant data';
SELECT obligarth_private.rls_apply('obligarth.obliwatch_ai_catalog', 'catalog',
  'Obliwatch integration: AI catalog of Obliwatch (bundles of AI apps), written by integrations.obliwatch.catalog-sync');

-- 3. Authenticator marker ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION obligarth_private.device_apps_authenticator_marker() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_tenant integer;
  v_device integer;
BEGIN
  IF TG_OP = 'DELETE' THEN
    v_tenant := OLD.tenant_id; v_device := OLD.device_id;
  ELSE
    v_tenant := NEW.tenant_id; v_device := NEW.device_id;
  END IF;
  -- In the writer's context (invoker): its tenant's device only; a device being deleted is simply not found.
  -- Never the failure of the writer's statement (marker.ts): a subtransaction that swallows any error, and NOWAIT on
  -- the device row, so the marker never waits behind another writer of devices (a status report locks devices then
  -- device_apps; a bulk delete of device_apps would otherwise lock in the other order and could deadlock). A row lock
  -- held by the writer itself is no wait. A device row locked elsewhere: this mark is skipped (the next change of the
  -- device marks it again; the writers of devices mark their own changes).
  BEGIN
    PERFORM 1 FROM obligarth.devices WHERE tenant_id = v_tenant AND id = v_device FOR NO KEY UPDATE NOWAIT;
    UPDATE obligarth.devices SET signal_updated_at = clock_timestamp() WHERE tenant_id = v_tenant AND id = v_device;
  EXCEPTION WHEN others THEN
    NULL;
  END;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.device_apps_authenticator_marker() FROM PUBLIC;

DROP TRIGGER IF EXISTS device_apps_authenticator_marker_ins ON obligarth.device_apps;
CREATE TRIGGER device_apps_authenticator_marker_ins AFTER INSERT ON obligarth.device_apps
  FOR EACH ROW WHEN (NEW.identifier IN ('com.azure.authenticator', 'com.microsoft.azureauthenticator'))
  EXECUTE FUNCTION obligarth_private.device_apps_authenticator_marker();

DROP TRIGGER IF EXISTS device_apps_authenticator_marker_upd ON obligarth.device_apps;
CREATE TRIGGER device_apps_authenticator_marker_upd AFTER UPDATE OF version, short_version, managed, identifier ON obligarth.device_apps
  FOR EACH ROW WHEN ((NEW.identifier IN ('com.azure.authenticator', 'com.microsoft.azureauthenticator')
                      OR OLD.identifier IN ('com.azure.authenticator', 'com.microsoft.azureauthenticator'))
                     AND (OLD.version IS DISTINCT FROM NEW.version OR OLD.short_version IS DISTINCT FROM NEW.short_version
                          OR OLD.managed IS DISTINCT FROM NEW.managed OR OLD.identifier IS DISTINCT FROM NEW.identifier))
  EXECUTE FUNCTION obligarth_private.device_apps_authenticator_marker();

DROP TRIGGER IF EXISTS device_apps_authenticator_marker_del ON obligarth.device_apps;
CREATE TRIGGER device_apps_authenticator_marker_del AFTER DELETE ON obligarth.device_apps
  FOR EACH ROW WHEN (OLD.identifier IN ('com.azure.authenticator', 'com.microsoft.azureauthenticator'))
  EXECUTE FUNCTION obligarth_private.device_apps_authenticator_marker();

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
