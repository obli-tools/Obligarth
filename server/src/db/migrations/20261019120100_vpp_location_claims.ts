import type { Knex } from 'knex';

// =============================================================================
// One tenant of the instance per location of Apple Business (decision of the owners of 19/10/2026, INT-INTC-R9
// option B). The guard against the silent takeover of a location by another tenant of this instance relied on Apple
// echoing mdmInfo.metadata (the tenant's uuid) [J1]: without the echo, a second file of the same location (another
// fingerprint) was taken over without its guard. The claim of a location (its uId) is now kept instance-wide:
//   - vpp_location_claims: location_uid → the tenant (and the token) that configured it. Class 'custom', no policy and
//     no grant for the runtime role: read and written only by the functions below (owner: obligarth_owner);
//   - obligarth.vpp_location_claim(token, uid, takeover): in the context of a tenant; true when the location is free,
//     already this tenant's, or taken over (takeover = true: the caller holds the guard of the takeover); false when
//     another tenant of the instance holds it — never which one;
//   - obligarth.vpp_location_release(token): the claim of a token removed by its tenant.
// The live tokens of the instance seed the claims (the oldest active token of each location wins).
// Runs as obligarth_owner (server-migrate), after invitation_address_attempts; ends with obligarth.rls_assert_clean().
// No question mark in the SQL (knex.raw would bind it); kept verbatim by String.raw.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Claims of the locations of Apple Business, instance-wide (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.tenant_apple_vpp_tokens') IS NULL
     OR to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL THEN
    RAISE EXCEPTION 'vpp_location_claims: apply apple_integrations and the RLS migrations first';
  END IF;
END $$;

CREATE TABLE obligarth.vpp_location_claims (
  location_uid  varchar(64)  NOT NULL,
  tenant_id     integer      NOT NULL,
  token_id      uuid         NOT NULL,
  claimed_at    timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT vpp_location_claims_pkey PRIMARY KEY (location_uid),
  CONSTRAINT vpp_location_claims_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE
);
CREATE INDEX vpp_location_claims_token ON obligarth.vpp_location_claims (token_id);
SELECT obligarth_private.rls_apply('obligarth.vpp_location_claims', 'custom',
  'Apps and Books: one tenant per location of Apple Business (INT-INTC-R9); definer functions only');
-- No row for the runtime role (no grant either): the definer functions below only.
CREATE POLICY rls_definer_only ON obligarth.vpp_location_claims TO obligarth USING (false) WITH CHECK (false);

INSERT INTO obligarth.vpp_location_claims (location_uid, tenant_id, token_id, claimed_at)
SELECT DISTINCT ON (t.location_uid) t.location_uid, t.tenant_id, t.id, t.state_at
  FROM obligarth.tenant_apple_vpp_tokens t
 WHERE t.location_uid IS NOT NULL AND t.state = 'active'
 ORDER BY t.location_uid, t.state_at, t.id;

CREATE FUNCTION obligarth.vpp_location_claim(p_token uuid, p_uid text, p_takeover boolean)
  RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_tenant integer := obligarth.ctx_tenant();
  v_holder integer;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'vpp_location_claim: the context of a tenant is required';
  END IF;
  IF p_uid IS NULL OR length(p_uid) = 0 OR length(p_uid) > 64 THEN
    RETURN true;                                   -- no location known: nothing to claim
  END IF;
  IF NOT EXISTS (SELECT 1 FROM obligarth.tenant_apple_vpp_tokens t WHERE t.tenant_id = v_tenant AND t.id = p_token) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'vpp_location_claim: not a token of the tenant';
  END IF;
  SELECT c.tenant_id INTO v_holder FROM obligarth.vpp_location_claims c WHERE c.location_uid = p_uid FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO obligarth.vpp_location_claims (location_uid, tenant_id, token_id) VALUES (p_uid, v_tenant, p_token)
      ON CONFLICT (location_uid) DO NOTHING;
    SELECT c.tenant_id INTO v_holder FROM obligarth.vpp_location_claims c WHERE c.location_uid = p_uid;
    RETURN v_holder = v_tenant;
  END IF;
  IF v_holder = v_tenant OR p_takeover THEN
    UPDATE obligarth.vpp_location_claims SET tenant_id = v_tenant, token_id = p_token,
           claimed_at = CASE WHEN tenant_id = v_tenant THEN claimed_at ELSE CURRENT_TIMESTAMP END
     WHERE location_uid = p_uid;
    RETURN true;
  END IF;
  RETURN false;
END $$;
REVOKE ALL ON FUNCTION obligarth.vpp_location_claim(uuid, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.vpp_location_claim(uuid, text, boolean) TO obligarth;

CREATE FUNCTION obligarth.vpp_location_release(p_token uuid)
  RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_tenant integer := obligarth.ctx_tenant();
  v_count integer;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'vpp_location_release: the context of a tenant is required';
  END IF;
  DELETE FROM obligarth.vpp_location_claims c WHERE c.tenant_id = v_tenant AND c.token_id = p_token;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END $$;
REVOKE ALL ON FUNCTION obligarth.vpp_location_release(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.vpp_location_release(uuid) TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.vpp_location_claim', 'definer',
   'Apps and Books: claims a location of Apple Business for the tenant of the context; says only whether another tenant holds it'),
  ('function', 'obligarth.vpp_location_release', 'definer',
   'Apps and Books: releases the claims of a token of the tenant of the context')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
