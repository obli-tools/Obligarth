import type { Knex } from 'knex';

// =============================================================================
// Android, part 1: enterprises of the tenants, signups, destructive counter (Android Management API, direct calls
// of the instance)
// =============================================================================
//   - android_enterprises: the Android enterprise of a tenant (one live row per tenant); enterprise_name and
//     project_id are written once by obligarth.android_enterprise_bind(), never by the runtime role (column
//     privileges and the trigger android_enterprises_guard); an enterprise name that belonged to a tenant never
//     goes to another one, whatever its state;
//   - android_signups: the signup in progress, routed back by the SHA-256 of the 256-bit callback token (the
//     token itself is never stored);
//   - android_destructive_events: sliding hour of the gateway's last-resort caps;
//   - functions: android_enterprise_lookup (pull loop, context 'none'), android_enterprise_bind,
//     android_signup_lookup (public callback route, context 'none'), android_domain_claimed (tenant context,
//     a boolean only), android_enterprise_known (project check of the maintenance, context 'none').
// New tables and functions only: nothing existing is altered. Runs as obligarth_owner (server-migrate), after the
// RLS migrations; ends with obligarth.rls_assert_clean(). No question mark in the SQL (knex.raw would bind it).

const UP = String.raw`-- =============================================================================
-- Android, part 1: enterprises, signups, destructive counter (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regprocedure('obligarth.ctx_actor_is_platform_admin()') IS NULL THEN
    RAISE EXCEPTION 'Android migrations need the RLS migrations (rls_foundation … rls_policies) first';
  END IF;
END $$;

-- ── android_enterprises ────────────────────────────────────────────────────────
CREATE TABLE obligarth.android_enterprises (
  id                     integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id              integer NOT NULL DEFAULT obligarth.ctx_tenant()
                           REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enterprise_name        varchar(128),                 -- enterprises/{id}; written once by android_enterprise_bind
  project_id             varchar(64),                  -- Google Cloud project that manages the enterprise
  state                  varchar(16) NOT NULL DEFAULT 'pending',
  enterprise_type        varchar(48),                  -- MANAGED_GOOGLE_DOMAIN | MANAGED_GOOGLE_PLAY_ACCOUNTS_ENTERPRISE
  domain_type            varchar(24),                  -- TYPE_TEAM | TYPE_DOMAIN (managedGoogleDomainType)
  admin_domain           varchar(253),                 -- domain of the signup restriction, never the e-mail
  display_name           varchar(100) NOT NULL,
  primary_color          integer,
  logo_ref               uuid,                         -- file of the tenant branding, not the URL
  terms                  jsonb NOT NULL DEFAULT '[]',  -- optional termsAndConditions shown at provisioning
  terms_acceptance       jsonb,                        -- { version, acceptedAt, userId } of the publisher-customer agreement
  signin                 jsonb NOT NULL DEFAULT '[]',  -- signinDetails as configured by Obligarth (never the Google tokens)
  mgpa_exception         boolean NOT NULL DEFAULT false,
  topic_set_at           timestamptz,
  test_message_at        timestamptz,
  linked_at              timestamptz,
  linked_by              integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  unlink_requested_at    timestamptz,
  unlinked_at            timestamptz,
  unlink_reason          varchar(32),                  -- offboarding | external | released
  last_checked_at        timestamptz,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT android_enterprises_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT android_enterprises_state_check
    CHECK (state IN ('pending', 'linked', 'unlinking', 'unlinked', 'error')),
  CONSTRAINT android_enterprises_name_check
    CHECK (enterprise_name IS NULL OR enterprise_name ~ '^enterprises/[A-Za-z0-9_-]{1,100}$'),
  CONSTRAINT android_enterprises_project_check
    CHECK (project_id IS NULL OR project_id ~ '^[a-z][a-z0-9-]{4,62}[a-z0-9]$'),
  CONSTRAINT android_enterprises_type_check CHECK (enterprise_type IS NULL OR enterprise_type IN
    ('MANAGED_GOOGLE_DOMAIN', 'MANAGED_GOOGLE_PLAY_ACCOUNTS_ENTERPRISE', 'ENTERPRISE_TYPE_UNSPECIFIED')),
  CONSTRAINT android_enterprises_linked_has_name
    CHECK (state = 'pending' OR (enterprise_name IS NOT NULL AND project_id IS NOT NULL)),
  CONSTRAINT android_enterprises_unlinked_reason CHECK ((state = 'unlinked') = (unlink_reason IS NOT NULL)),
  CONSTRAINT android_enterprises_unlink_reason_check
    CHECK (unlink_reason IS NULL OR unlink_reason IN ('offboarding', 'external', 'released'))
);
-- One live enterprise per tenant; an enterprise name belongs to one tenant of the instance.
CREATE UNIQUE INDEX android_enterprises_live_tenant ON obligarth.android_enterprises (tenant_id)
  WHERE state IN ('pending', 'linked', 'unlinking', 'error');
CREATE UNIQUE INDEX android_enterprises_name_live ON obligarth.android_enterprises (enterprise_name)
  WHERE enterprise_name IS NOT NULL AND state <> 'unlinked';
CREATE INDEX android_enterprises_name ON obligarth.android_enterprises (enterprise_name)
  WHERE enterprise_name IS NOT NULL;
CREATE INDEX android_enterprises_domain ON obligarth.android_enterprises ((lower(admin_domain)))
  WHERE admin_domain IS NOT NULL;
SELECT obligarth_private.rls_apply('obligarth.android_enterprises', 'tenant', 'android: enterprise of the tenant');

-- Column privileges: the runtime role never writes enterprise_name nor project_id (android_enterprise_bind only);
-- tenant_id stays updatable for the RLS checks (WITH CHECK keeps a row in its tenant).
REVOKE INSERT, UPDATE ON obligarth.android_enterprises FROM obligarth;
GRANT INSERT (tenant_id, state, enterprise_type, domain_type, admin_domain, display_name, primary_color, logo_ref,
              terms, terms_acceptance, signin, mgpa_exception, topic_set_at, test_message_at, linked_at, linked_by,
              unlink_requested_at, unlinked_at, unlink_reason, last_checked_at, created_at, updated_at)
  ON obligarth.android_enterprises TO obligarth;
GRANT UPDATE (tenant_id, state, enterprise_type, domain_type, admin_domain, display_name, primary_color, logo_ref, terms,
              terms_acceptance, signin, mgpa_exception, topic_set_at, test_message_at, linked_at, linked_by,
              unlink_requested_at, unlinked_at, unlink_reason, last_checked_at, updated_at)
  ON obligarth.android_enterprises TO obligarth;

-- unlinked is final (a new link is a new row); enterprise_name and project_id: written once, by the bind only.
CREATE FUNCTION obligarth.android_enterprises_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF OLD.state = 'unlinked' AND NEW.state IS DISTINCT FROM 'unlinked' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_enterprises: an unlinked enterprise stays unlinked';
  END IF;
  IF NEW.enterprise_name IS DISTINCT FROM OLD.enterprise_name OR NEW.project_id IS DISTINCT FROM OLD.project_id THEN
    IF OLD.enterprise_name IS NOT NULL OR OLD.project_id IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_enterprises: enterprise_name and project_id are written once';
    END IF;
    IF current_user <> 'obligarth_owner' THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_enterprises: enterprise_name is written by android_enterprise_bind only';
    END IF;
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_enterprises_guard() FROM PUBLIC;
CREATE TRIGGER android_enterprises_guard BEFORE UPDATE ON obligarth.android_enterprises
  FOR EACH ROW EXECUTE FUNCTION obligarth.android_enterprises_guard();

-- ── android_signups ─────────────────────────────────────────────────────────────
CREATE TABLE obligarth.android_signups (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            integer NOT NULL DEFAULT obligarth.ctx_tenant()
                         REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enterprise_id        integer NOT NULL,
  callback_token_hash  bytea NOT NULL,                -- sha256 of the 256-bit callback token (never the token)
  signup_url_name      varchar(255),                  -- signupUrls/{id} returned by Google
  state                varchar(16) NOT NULL DEFAULT 'requested',
  allowed_domain       varchar(253) NOT NULL,
  requested_by         integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  expires_at           timestamptz NOT NULL,          -- 1 h after url_issued
  consuming_at         timestamptz,
  completed_at         timestamptz,
  failure_code         varchar(48),                   -- token_missing | mgpa_refused | google_error | expired | interrupted
  created_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT android_signups_state_check
    CHECK (state IN ('requested', 'url_issued', 'consuming', 'completed', 'failed', 'expired', 'cancelled')),
  CONSTRAINT android_signups_token_hash_len CHECK (octet_length(callback_token_hash) = 32),
  CONSTRAINT android_signups_failure_check CHECK (failure_code IS NULL OR failure_code IN
    ('token_missing', 'mgpa_refused', 'google_error', 'expired', 'interrupted', 'bind_refused')),
  CONSTRAINT android_signups_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
    REFERENCES obligarth.android_enterprises (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX android_signups_token ON obligarth.android_signups (callback_token_hash);
CREATE UNIQUE INDEX android_signups_open ON obligarth.android_signups (tenant_id)
  WHERE state IN ('requested', 'url_issued', 'consuming');
CREATE INDEX android_signups_domain ON obligarth.android_signups ((lower(allowed_domain)))
  WHERE state IN ('requested', 'url_issued', 'consuming');
SELECT obligarth_private.rls_apply('obligarth.android_signups', 'tenant', 'android: signups of an enterprise');

-- ── android_destructive_events: the gateway's last-resort caps, sliding hour ────
CREATE TABLE obligarth.android_destructive_events (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     integer NOT NULL DEFAULT obligarth.ctx_tenant()
                  REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enterprise_id integer NOT NULL,
  kind          varchar(16) NOT NULL,
  at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT android_destructive_events_kind_check
    CHECK (kind IN ('wipe', 'relinquish', 'delete', 'disable', 'cleanup')),
  CONSTRAINT android_destructive_events_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
    REFERENCES obligarth.android_enterprises (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX android_destructive_events_window
  ON obligarth.android_destructive_events (tenant_id, enterprise_id, kind, at);
SELECT obligarth_private.rls_apply('obligarth.android_destructive_events', 'tenant',
  'android: sliding hour of the gateway destructive caps');

-- ── Functions ───────────────────────────────────────────────────────────────────
-- Tenant of a live enterprise (linked, unlinking, error), for the pull loop; NULL otherwise.
CREATE FUNCTION obligarth.android_enterprise_lookup(p_enterprise text) RETURNS integer
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v integer;
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.pubsub-pull' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_enterprise_lookup: context none of the pull loop required';
  END IF;
  IF p_enterprise IS NULL OR p_enterprise !~ '^enterprises/[A-Za-z0-9_-]{1,100}$' THEN
    RETURN NULL;
  END IF;
  SELECT e.tenant_id INTO v FROM obligarth.android_enterprises e
   WHERE e.enterprise_name = p_enterprise AND e.state IN ('linked', 'unlinking', 'error');
  RETURN v;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_enterprise_lookup(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_enterprise_lookup(text) TO obligarth;

-- The only writer of enterprise_name and project_id: the pending row of the tenant becomes linked. Refuses a name
-- that ever belonged to another tenant (23505, the tenant not named) and a second live enterprise.
CREATE FUNCTION obligarth.android_enterprise_bind(p_tenant integer, p_enterprise_id integer, p_enterprise text,
  p_type text, p_project text, p_domain_type text) RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_state text;
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'tenant' OR obligarth.ctx_tenant() IS DISTINCT FROM p_tenant THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_enterprise_bind: context of the tenant required';
  END IF;
  IF NOT (obligarth.ctx_actor() IN ('a:android.signup-callback', 'j:android.enterprise-adopt')
          OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_enterprise_bind: actor not allowed';
  END IF;
  IF p_enterprise IS NULL OR p_enterprise !~ '^enterprises/[A-Za-z0-9_-]{1,100}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'android_enterprise_bind: invalid enterprise name';
  END IF;
  IF p_project IS NULL OR p_project !~ '^[a-z][a-z0-9-]{4,62}[a-z0-9]$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'android_enterprise_bind: invalid project';
  END IF;
  PERFORM 1 FROM obligarth.android_enterprises e WHERE e.enterprise_name = p_enterprise AND e.tenant_id <> p_tenant;
  IF FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'android_enterprise_bind: enterprise already bound';
  END IF;
  PERFORM 1 FROM obligarth.android_enterprises e
   WHERE e.enterprise_name = p_enterprise AND e.tenant_id = p_tenant AND e.state <> 'unlinked' AND e.id <> p_enterprise_id;
  IF FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'android_enterprise_bind: enterprise already bound';
  END IF;
  SELECT e.state INTO v_state FROM obligarth.android_enterprises e
   WHERE e.id = p_enterprise_id AND e.tenant_id = p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'android_enterprise_bind: unknown enterprise row';
  END IF;
  IF v_state <> 'pending' THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'android_enterprise_bind: the row is not pending';
  END IF;
  UPDATE obligarth.android_enterprises
     SET enterprise_name = p_enterprise, project_id = p_project, enterprise_type = p_type, domain_type = p_domain_type,
         state = 'linked', linked_at = now(), updated_at = now()
   WHERE id = p_enterprise_id AND tenant_id = p_tenant;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_enterprise_bind(integer, integer, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_enterprise_bind(integer, integer, text, text, text, text) TO obligarth;

-- Tenant of an open signup (url_issued, not expired) by the hash of its callback token; NULL otherwise.
CREATE FUNCTION obligarth.android_signup_lookup(p_token_hash bytea) RETURNS integer
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v integer;
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'a:android.signup-callback' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_signup_lookup: context none of the signup callback required';
  END IF;
  IF p_token_hash IS NULL OR octet_length(p_token_hash) <> 32 THEN
    RETURN NULL;
  END IF;
  SELECT s.tenant_id INTO v FROM obligarth.android_signups s
   WHERE s.callback_token_hash = p_token_hash AND s.state = 'url_issued' AND s.expires_at > now();
  RETURN v;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_signup_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_signup_lookup(bytea) TO obligarth;

-- Whether another tenant claims this domain (open signup, or enterprise not unlinked): a boolean only.
CREATE FUNCTION obligarth.android_domain_claimed(p_domain text) RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_tenant integer := obligarth.ctx_tenant();
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'tenant' OR v_tenant IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_domain_claimed: tenant context required';
  END IF;
  RETURN EXISTS (SELECT 1 FROM obligarth.android_signups s
                  WHERE lower(s.allowed_domain) = lower(p_domain) AND s.tenant_id <> v_tenant
                    AND s.state IN ('requested', 'url_issued', 'consuming'))
      OR EXISTS (SELECT 1 FROM obligarth.android_enterprises e
                  WHERE lower(e.admin_domain) = lower(p_domain) AND e.tenant_id <> v_tenant AND e.state <> 'unlinked');
END $$;
REVOKE ALL ON FUNCTION obligarth.android_domain_claimed(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_domain_claimed(text) TO obligarth;

-- The names among p_names that ever figured in the registry (any tenant, any state): the weekly project check.
CREATE FUNCTION obligarth.android_enterprise_known(p_names text[]) RETURNS text[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.maintenance' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_enterprise_known: context none of the maintenance required';
  END IF;
  RETURN ARRAY(SELECT DISTINCT e.enterprise_name::text FROM obligarth.android_enterprises e
                WHERE e.enterprise_name = ANY (p_names) ORDER BY 1);
END $$;
REVOKE ALL ON FUNCTION obligarth.android_enterprise_known(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_enterprise_known(text[]) TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.android_enterprise_lookup', 'definer', 'android pull loop: tenant of a live enterprise'),
  ('function', 'obligarth.android_enterprise_bind', 'definer', 'android: write-once enterprise name of a tenant'),
  ('function', 'obligarth.android_signup_lookup', 'definer', 'android public callback: tenant of an open signup'),
  ('function', 'obligarth.android_domain_claimed', 'definer', 'android signup: domain claimed by another tenant (boolean)'),
  ('function', 'obligarth.android_enterprise_known', 'definer', 'android maintenance: enterprise names ever registered')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
