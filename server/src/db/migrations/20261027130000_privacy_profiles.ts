import type { Knex } from 'knex';

// =============================================================================
// Privacy profiles of the tenants (P0-13 T1, CNF-02; conception §10.3, §10.5; REQ-02)
// =============================================================================
//   - privacy_profile_versions (class tenant): one profile per tenant and ownership (D1), as immutable versions. The
//     current version of an ownership is the one not superseded (one at most: privacy_profile_versions_current). No
//     row: the default rules of shared/src/privacy.ts (DEFAULT_PRIVACY_PROFILE), no seed. rules holds the eight keys of
//     PrivacyProfileRules (shared) and no other (privacy_profile_versions_rules_shape); the imposed rules
//     (IMPOSED_RULES, shared) are CHECKs too: a location or a serial number of a personal device, every application
//     of a device that is not corporate (D2) are refused by the database as by the API. The runtime role reads only:
//     privacy_profile_publish is the only writer.
//   - obligarth.privacy_profile_publish(ownership, rules, justification, approval): in the tenant's context, supersedes
//     the current version and inserts the next one (one publication at a time per tenant: advisory lock, current row
//     locked). For the runtime role, an approved request of the context's actor is required: pending_approvals of the
//     tenant, type privacy_profile_change, status approved and not executed, requested by the actor, reviewed by
//     another person, payload { ownership, rules } equal to what is published; one publication per request
//     (privacy_profile_versions_approval). Without a request: the owner only (migrations, testbed).
//   - obligarth.privacy_profile_current(tenant): the current versions of a tenant (resolver of the server, cached),
//     from the tenant's own context, a read context ('member', 'platform') that covers it, or the 'none' context of
//     the jobs; never another tenant from a tenant's context.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean()
// last. Runs as obligarth_owner (server-migrate), after coordination_socle.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Privacy profiles of the tenants (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regprocedure('obligarth.ctx_read_tenants()') IS NULL
     OR to_regclass('obligarth.pending_approvals') IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'pending_approvals_tenant_id_id_unique') THEN
    RAISE EXCEPTION 'privacy_profiles: apply the RLS migrations and mdm_model_expand first';
  END IF;
END $$;

-- 1. privacy_profile_versions ---------------------------------------------------------
CREATE TABLE obligarth.privacy_profile_versions (
  tenant_id     integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  id            uuid          NOT NULL DEFAULT gen_random_uuid(),
  ownership     varchar(24)   NOT NULL,
  version       integer       NOT NULL,
  rules         jsonb         NOT NULL,                     -- PrivacyProfileRules (shared/src/privacy.ts)
  justification varchar(1000),
  approval_id   integer,                                  -- pending_approvals.id (NULL: written by the owner)
  created_by    integer,                                  -- the requester
  approved_by   integer,                                  -- the reviewer of the request
  created_at    timestamptz   NOT NULL DEFAULT now(),
  superseded_at timestamptz,
  CONSTRAINT privacy_profile_versions_pkey PRIMARY KEY (id),
  CONSTRAINT privacy_profile_versions_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT privacy_profile_versions_version_uq UNIQUE (tenant_id, ownership, version),
  CONSTRAINT privacy_profile_versions_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT privacy_profile_versions_approval_tenant_fk FOREIGN KEY (tenant_id, approval_id)
    REFERENCES obligarth.pending_approvals (tenant_id, id) ON DELETE SET NULL (approval_id),
  CONSTRAINT privacy_profile_versions_created_by_foreign FOREIGN KEY (created_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT privacy_profile_versions_approved_by_foreign FOREIGN KEY (approved_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT privacy_profile_versions_ownership_check CHECK (ownership IN ('corporate', 'corporate_personal', 'personal')),
  CONSTRAINT privacy_profile_versions_version_check CHECK (version >= 1),
  CONSTRAINT privacy_profile_versions_justification CHECK (justification IS NULL OR length(trim(justification)) >= 10),
  CONSTRAINT privacy_profile_versions_superseded_after CHECK (superseded_at IS NULL OR superseded_at >= created_at),
  -- The eight keys of PrivacyProfileRules, of their types, and no other.
  CONSTRAINT privacy_profile_versions_rules_shape CHECK (
        COALESCE(jsonb_typeof(rules) = 'object', false)
    AND COALESCE((rules - ARRAY['serialNumber', 'hardwareIds', 'deviceName', 'phoneNumber', 'network', 'lostModeLocation',
                                'installedApps', 'certificates']::text[]) = '{}'::jsonb, false)
    AND COALESCE(jsonb_typeof(rules -> 'serialNumber') = 'boolean', false)
    AND COALESCE(jsonb_typeof(rules -> 'hardwareIds') = 'boolean', false)
    AND COALESCE(jsonb_typeof(rules -> 'deviceName') = 'boolean', false)
    AND COALESCE(jsonb_typeof(rules -> 'phoneNumber') = 'boolean', false)
    AND COALESCE(jsonb_typeof(rules -> 'network') = 'boolean', false)
    AND COALESCE(jsonb_typeof(rules -> 'lostModeLocation') = 'boolean', false)
    AND COALESCE(rules -> 'installedApps' IN ('"all"'::jsonb, '"managed_only"'::jsonb), false)
    AND COALESCE(rules -> 'certificates' IN ('"all"'::jsonb, '"managed_only"'::jsonb), false)),
  -- Imposed rules (conception §10.3; IMPOSED_RULES of shared/src/privacy.ts, error privacyRuleImposed).
  CONSTRAINT privacy_profile_versions_personal_location CHECK (ownership <> 'personal'
    OR COALESCE(rules -> 'lostModeLocation' = 'false'::jsonb, false)),
  CONSTRAINT privacy_profile_versions_personal_serial CHECK (ownership <> 'personal'
    OR COALESCE(rules -> 'serialNumber' = 'false'::jsonb, false)),
  CONSTRAINT privacy_profile_versions_shared_apps CHECK (ownership = 'corporate'
    OR COALESCE(rules -> 'installedApps' = '"managed_only"'::jsonb, false))
);
CREATE UNIQUE INDEX privacy_profile_versions_current ON obligarth.privacy_profile_versions (tenant_id, ownership)
  WHERE superseded_at IS NULL;
-- An approved request publishes one version.
CREATE UNIQUE INDEX privacy_profile_versions_approval ON obligarth.privacy_profile_versions (tenant_id, approval_id)
  WHERE approval_id IS NOT NULL;
SELECT obligarth_private.rls_apply('obligarth.privacy_profile_versions', 'tenant',
  'privacy profiles (CNF-02): immutable versions, written by privacy_profile_publish only');
-- Immutable for the runtime role: read only (the supersession and the insertion go through privacy_profile_publish).
REVOKE INSERT, UPDATE, DELETE ON obligarth.privacy_profile_versions FROM obligarth;

-- 2. Publication --------------------------------------------------------------------
CREATE FUNCTION obligarth.privacy_profile_publish(p_ownership text, p_rules jsonb, p_justification text, p_approval integer)
  RETURNS TABLE (profile_id uuid, profile_version integer, previous_id uuid)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '5s' AS $$
DECLARE
  v_tenant    integer := obligarth.ctx_tenant();
  v_actor     integer := obligarth.ctx_actor_user();
  v_approver  integer;
  v_prev_id   uuid;
  v_version   integer;
  v_id        uuid;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'privacy_profile_publish: the tenant''s context is required';
  END IF;
  IF p_approval IS NULL THEN
    IF session_user = 'obligarth' THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'privacy_profile_publish: an approved request is required';
    END IF;
  ELSE
    SELECT a.reviewed_by INTO v_approver
      FROM obligarth.pending_approvals a
     WHERE a.tenant_id = v_tenant AND a.id = p_approval
       AND a.request_type = 'privacy_profile_change' AND a.status = 'approved' AND a.executed_at IS NULL
       AND a.requested_by = v_actor AND a.reviewed_by IS NOT NULL AND a.reviewed_by <> a.requested_by
       AND a.payload ->> 'ownership' = p_ownership AND a.payload -> 'rules' = p_rules;
    IF v_approver IS NULL THEN
      RAISE EXCEPTION USING ERRCODE = '42501',
        MESSAGE = 'privacy_profile_publish: no approved request of the context''s actor for these rules';
    END IF;
  END IF;

  -- One publication at a time per tenant; the current version locked.
  PERFORM pg_advisory_xact_lock(hashtext('obligarth.privacy_profile_publish'), v_tenant);
  SELECT v.id INTO v_prev_id
    FROM obligarth.privacy_profile_versions v
   WHERE v.tenant_id = v_tenant AND v.ownership = p_ownership AND v.superseded_at IS NULL
     FOR UPDATE;
  SELECT COALESCE(max(v.version), 0) + 1 INTO v_version
    FROM obligarth.privacy_profile_versions v
   WHERE v.tenant_id = v_tenant AND v.ownership = p_ownership;
  IF v_prev_id IS NOT NULL THEN
    UPDATE obligarth.privacy_profile_versions v SET superseded_at = now()
     WHERE v.tenant_id = v_tenant AND v.id = v_prev_id;
  END IF;
  INSERT INTO obligarth.privacy_profile_versions
    (tenant_id, ownership, version, rules, justification, approval_id, created_by, approved_by)
  VALUES (v_tenant, p_ownership, v_version, p_rules, NULLIF(trim(p_justification), ''), p_approval, v_actor, v_approver)
  RETURNING id INTO v_id;
  RETURN QUERY SELECT v_id, v_version, v_prev_id;
END $$;

-- 3. Current versions of a tenant ---------------------------------------------------
CREATE FUNCTION obligarth.privacy_profile_current(p_tenant integer)
  RETURNS TABLE (ownership text, profile_id uuid, version integer, rules jsonb, created_at timestamptz)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF session_user = 'obligarth' AND obligarth.ctx_kind() IS DISTINCT FROM 'none'
     AND NOT COALESCE(p_tenant = ANY (obligarth.ctx_read_tenants()), false) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'privacy_profile_current: a tenant outside the context';
  END IF;
  RETURN QUERY
    SELECT v.ownership::text, v.id, v.version, v.rules, v.created_at
      FROM obligarth.privacy_profile_versions v
     WHERE v.tenant_id = p_tenant AND v.superseded_at IS NULL
     ORDER BY v.ownership;
END $$;

REVOKE ALL ON FUNCTION obligarth.privacy_profile_publish(text, jsonb, text, integer),
  obligarth.privacy_profile_current(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.privacy_profile_publish(text, jsonb, text, integer) TO obligarth;
GRANT EXECUTE ON FUNCTION obligarth.privacy_profile_current(integer) TO obligarth, obligarth_reader;
COMMENT ON FUNCTION obligarth.privacy_profile_publish(text, jsonb, text, integer) IS
  'privacy profiles (CNF-02): next version of an ownership, in the tenant context, after an approved request';
COMMENT ON FUNCTION obligarth.privacy_profile_current(integer) IS
  'privacy profiles (CNF-02): current versions of a tenant (its context, a read context covering it, or none)';

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.privacy_profile_publish', 'definer', 'tenant context; approved request of the actor, or the owner'),
  ('function', 'obligarth.privacy_profile_current', 'definer', 'current privacy profiles of a tenant visible to the context')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
