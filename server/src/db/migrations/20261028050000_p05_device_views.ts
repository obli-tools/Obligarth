import type { Knex } from 'knex';

// =============================================================================
// Saved views of the device list (P0-5 T2, M1 of the spec; §4.1, D6)
// =============================================================================
//   - device_views (class tenant): a view of a user in a tenant: its name, a description, private or shared in the
//     tenant, and its definition (DeviceViewDefinition of shared/src/mdm/deviceViews.ts: the filters, the advanced
//     filter, the group, the sort and the columns of the list), a JSON object of 16 KiB at most. The visibility (the
//     owner, or every member when the view is shared) and the bounds (50 private views per user, 100 shared views per
//     tenant) are the service's (mdm/views/deviceViewService.ts): RLS keeps the tenants apart. The owner and the
//     tenant of a view never change: the runtime role updates its name, description, sharing and definition only.
//   - device_view_defaults (class tenant): the default view of a user in a tenant (one at most). A default names a view
//     the user sees (device_view_defaults_visible); a view that stops being shared stops being the default of the
//     other users (device_views_unshared). Gone with the view or the user. Both triggers read the committed rows: the
//     service serialises the writes of a tenant's views and defaults (its advisory lock), so that a default set while
//     its view stops being shared waits for that change and sees it.
//   The GIN index of the tags (devices_tags_gin) is the next migration's (20261028050100, built concurrently).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, search_path fixed and
// EXECUTE revoked from PUBLIC for each function, rls_assert_clean() last. Runs as obligarth_owner (server-migrate).
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Saved views of the device list (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.devices') IS NULL
     OR to_regclass('obligarth.users') IS NULL THEN
    RAISE EXCEPTION 'p05_device_views: apply the RLS migrations and mdm_model_expand first';
  END IF;
END $$;

-- 1. device_views ----------------------------------------------------------------------
CREATE TABLE obligarth.device_views (
  id             serial       PRIMARY KEY,
  uuid           uuid         NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  tenant_id      integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  owner_user_id  integer      NOT NULL,
  name           varchar(100) NOT NULL,
  description    varchar(500),
  shared         boolean      NOT NULL DEFAULT false,
  definition     jsonb        NOT NULL,                     -- DeviceViewDefinition (shared/src/mdm/deviceViews.ts)
  created_at     timestamptz  NOT NULL DEFAULT now(),
  updated_at     timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT device_views_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT device_views_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT device_views_owner_user_id_foreign FOREIGN KEY (owner_user_id)
    REFERENCES obligarth.users (id) ON DELETE CASCADE,
  -- A name of the console: not blank, no control character.
  CONSTRAINT device_views_name_check CHECK (btrim(name) <> '' AND name !~ '[\x01-\x1f\x7f]'),
  CONSTRAINT device_views_description_check CHECK (description IS NULL OR description !~ '[\x01-\x08\x0b-\x1f\x7f]'),
  CONSTRAINT device_views_definition_check CHECK (
        COALESCE(jsonb_typeof(definition) = 'object', false)
    AND octet_length(definition::text) <= 16384)
);
-- One name per owner in a tenant (the shared views of two members may share a name).
CREATE UNIQUE INDEX device_views_name_uq ON obligarth.device_views (tenant_id, owner_user_id, lower(name));
-- The shared views of a tenant (list, bound of 100).
CREATE INDEX device_views_shared ON obligarth.device_views (tenant_id) WHERE shared;
SELECT obligarth_private.rls_apply('obligarth.device_views', 'tenant',
  'saved views of the device list (P0-5): filters, advanced filter, sort, columns; private or shared in the tenant');
-- The owner and the tenant of a view never change.
REVOKE UPDATE ON obligarth.device_views FROM obligarth;
GRANT UPDATE (name, description, shared, definition, updated_at) ON obligarth.device_views TO obligarth;

-- 2. device_view_defaults --------------------------------------------------------------
CREATE TABLE obligarth.device_view_defaults (
  tenant_id   integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  user_id     integer      NOT NULL,
  view_id     integer      NOT NULL,
  updated_at  timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT device_view_defaults_pkey PRIMARY KEY (tenant_id, user_id),
  CONSTRAINT device_view_defaults_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT device_view_defaults_user_id_foreign FOREIGN KEY (user_id)
    REFERENCES obligarth.users (id) ON DELETE CASCADE,
  CONSTRAINT device_view_defaults_view_fk FOREIGN KEY (tenant_id, view_id)
    REFERENCES obligarth.device_views (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX device_view_defaults_view ON obligarth.device_view_defaults (tenant_id, view_id);
SELECT obligarth_private.rls_apply('obligarth.device_view_defaults', 'tenant',
  'default view of the device list of a user in a tenant (P0-5)');
REVOKE UPDATE ON obligarth.device_view_defaults FROM obligarth;
GRANT UPDATE (view_id, updated_at) ON obligarth.device_view_defaults TO obligarth;

-- A default names a view of its tenant the user sees: their own, or a shared one. Read under the caller's RLS (the
-- tenant's context), as invoker. A view that is not one of the tenant's is left to device_view_defaults_view_fk.
CREATE FUNCTION obligarth_private.device_view_defaults_visible() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM obligarth.device_views v
             WHERE v.tenant_id = NEW.tenant_id AND v.id = NEW.view_id
               AND v.owner_user_id <> NEW.user_id AND NOT v.shared) THEN
    RAISE EXCEPTION USING ERRCODE = '23503', CONSTRAINT = 'device_view_defaults_visible',
      MESSAGE = 'device_view_defaults: the view is neither the user''s nor shared in the tenant';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.device_view_defaults_visible() FROM PUBLIC;
CREATE TRIGGER device_view_defaults_visible BEFORE INSERT OR UPDATE ON obligarth.device_view_defaults
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.device_view_defaults_visible();

-- A view that stops being shared stops being the default of the other users (they no longer see it).
CREATE FUNCTION obligarth_private.device_views_unshared() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  DELETE FROM obligarth.device_view_defaults d
   WHERE d.tenant_id = NEW.tenant_id AND d.view_id = NEW.id AND d.user_id <> NEW.owner_user_id;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.device_views_unshared() FROM PUBLIC;
CREATE TRIGGER device_views_unshared AFTER UPDATE OF shared ON obligarth.device_views
  FOR EACH ROW WHEN (OLD.shared AND NOT NEW.shared) EXECUTE FUNCTION obligarth_private.device_views_unshared();

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
