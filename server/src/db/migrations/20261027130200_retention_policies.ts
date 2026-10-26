import type { Knex } from 'knex';

// =============================================================================
// Retention per tenant (P0-13 T4, CNF-04; conception §10.4; decisions D4, D5, D16)
// =============================================================================
//   - obligarth_private.retention_catalog(): the categories a tenant may set (default, range, unit), a copy of
//     RETENTION_CATEGORIES (shared/src/privacy.ts), written below by list() from CATEGORIES; both change together
//     (testbed 172 compares them). retention_values_valid(jsonb): an object of known categories, integer values within
//     their range (the CHECKs of the table, the checks of retention_set).
//   - tenant_retention_policies (class tenant): one row per tenant at most, none until its first change (the defaults
//     apply). "values": what the tenant set (a category absent: its default); pending_values / pending_effective_at:
//     decreases waiting for their date (D4: 7 days after the approval, cancellable meanwhile by an approved request
//     asking the value in force, D3). The runtime role reads only: retention_set is the only writer.
//   - obligarth.retention_value(tenant, category): the value in force (a decrease past its date, else the value set, else
//     the default), for the purges, the dates of purge and the notice; retention_values(tenant): every category. From
//     the tenant's own context, a read context that covers it, or the 'none' context of the jobs.
//   - obligarth.retention_set(values, justification, approval, body): in the tenant's context, after an approved
//     request of the context's actor (type privacy_retention_change, reviewed by another person, payload.values equal
//     to the values; the owner may go without one: migrations, testbed). A decrease past its date is folded into the
//     values first; then each category given: an increase (or the value in force) applies now and drops a decrease
//     waiting for it, a decrease waits 7 days (every decrease waiting then waits these 7 days). The prepared audit entry
//     privacy.retention_changed (details.values: the values) is written in the same transaction (audit_append), as
//     audit_set_retention does.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean() last.
// Runs as obligarth_owner (server-migrate), after privacy_capability.
// =============================================================================

/** RETENTION_CATEGORIES of shared/src/privacy.ts at the time of this migration (frozen here). */
const CATEGORIES: ReadonlyArray<readonly [key: string, def: number, min: number, max: number, unit: 'days' | 'months']> = [
  ['unenrolled_corporate_days', 90, 30, 365, 'days'],
  ['unenrolled_corporate_personal_days', 90, 30, 365, 'days'],
  ['unenrolled_personal_days', 30, 30, 365, 'days'],
  ['departed_end_user_days', 90, 30, 365, 'days'],
  ['lost_mode_location_days', 30, 1, 62, 'days'],
  ['technical_log_months', 6, 3, 12, 'months'],
  ['status_history_days', 90, 30, 365, 'days'],
  ['notice_ack_months', 36, 12, 72, 'months'],
];
const list = (rows: typeof CATEGORIES): string =>
  rows.map(([k, d, lo, hi, u]) => `('${k}'::text, ${d}, ${lo}, ${hi}, '${u}'::text)`).join(',\n         ');

const UP = String.raw`-- =============================================================================
-- Retention per tenant (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regprocedure('obligarth.ctx_read_tenants()') IS NULL
     OR to_regprocedure('obligarth.audit_append(text)') IS NULL
     OR to_regclass('obligarth.pending_approvals') IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'pending_approvals_tenant_id_id_unique')
     OR to_regclass('obligarth.privacy_profile_versions') IS NULL THEN
    RAISE EXCEPTION 'retention_policies: apply the RLS migrations, audit_hardening and privacy_profiles first';
  END IF;
END $$;

-- 1. Catalogue -------------------------------------------------------------------------
CREATE FUNCTION obligarth_private.retention_catalog()
  RETURNS TABLE (category text, default_value integer, min_value integer, max_value integer, unit text)
  LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT * FROM (VALUES
         ${list(CATEGORIES)}) AS c (category, default_value, min_value, max_value, unit)
$$;

-- An object of known categories whose values are integers of their range (NULL: NULL, for the CHECKs).
CREATE FUNCTION obligarth_private.retention_values_valid(p jsonb) RETURNS boolean
  LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN p IS NULL THEN NULL ELSE
    jsonb_typeof(p) = 'object'
    AND NOT EXISTS (
      SELECT 1
        FROM jsonb_each(p) e
        LEFT JOIN obligarth_private.retention_catalog() c ON c.category = e.key
       WHERE c.category IS NULL
          OR jsonb_typeof(e.value) <> 'number'
          OR (e.value)::text !~ '^[0-9]{1,6}$'
          OR ((e.value)::text)::integer NOT BETWEEN c.min_value AND c.max_value)
  END
$$;
REVOKE ALL ON FUNCTION obligarth_private.retention_catalog(), obligarth_private.retention_values_valid(jsonb) FROM PUBLIC;

-- 2. tenant_retention_policies ------------------------------------------------------------
CREATE TABLE obligarth.tenant_retention_policies (
  tenant_id            integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  "values"             jsonb         NOT NULL DEFAULT '{}'::jsonb,   -- { category: value } set by the tenant
  pending_values       jsonb,                                         -- decreases waiting for pending_effective_at
  pending_effective_at timestamptz,
  justification        varchar(1000),
  version              integer       NOT NULL DEFAULT 0,              -- changes applied (retention_set)
  approval_id          integer,                                       -- the request of the last retention_set
  updated_by           integer,
  updated_at           timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT tenant_retention_policies_pkey PRIMARY KEY (tenant_id),
  CONSTRAINT tenant_retention_policies_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT tenant_retention_policies_approval_tenant_fk FOREIGN KEY (tenant_id, approval_id)
    REFERENCES obligarth.pending_approvals (tenant_id, id) ON DELETE SET NULL (approval_id),
  CONSTRAINT tenant_retention_policies_updated_by_foreign FOREIGN KEY (updated_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT tenant_retention_policies_values_check CHECK (obligarth_private.retention_values_valid("values")),
  CONSTRAINT tenant_retention_policies_pending_check CHECK (pending_values IS NULL
    OR (obligarth_private.retention_values_valid(pending_values) AND pending_values <> '{}'::jsonb)),
  CONSTRAINT tenant_retention_policies_pending_pair CHECK ((pending_values IS NULL) = (pending_effective_at IS NULL)),
  CONSTRAINT tenant_retention_policies_version_check CHECK (version >= 0),
  CONSTRAINT tenant_retention_policies_justification CHECK (justification IS NULL OR length(trim(justification)) >= 10)
);
SELECT obligarth_private.rls_apply('obligarth.tenant_retention_policies', 'tenant',
  'retention per tenant (CNF-04): written by retention_set only');
REVOKE INSERT, UPDATE, DELETE ON obligarth.tenant_retention_policies FROM obligarth;

-- 3. Values in force ------------------------------------------------------------------------
CREATE FUNCTION obligarth.retention_value(p_tenant integer, p_category text) RETURNS integer
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_default integer;
  v_value   integer;
BEGIN
  IF session_user = 'obligarth' AND obligarth.ctx_kind() IS DISTINCT FROM 'none'
     AND NOT COALESCE(p_tenant = ANY (obligarth.ctx_read_tenants()), false) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'retention_value: a tenant outside the context';
  END IF;
  SELECT c.default_value INTO v_default FROM obligarth_private.retention_catalog() c WHERE c.category = p_category;
  IF v_default IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'retention_value: unknown category';
  END IF;
  SELECT CASE WHEN p.pending_effective_at <= now() AND (p.pending_values ->> p_category) IS NOT NULL
              THEN (p.pending_values ->> p_category)::integer
              ELSE (p."values" ->> p_category)::integer END
    INTO v_value
    FROM obligarth.tenant_retention_policies p
   WHERE p.tenant_id = p_tenant;
  RETURN COALESCE(v_value, v_default);
END $$;

CREATE FUNCTION obligarth.retention_values(p_tenant integer) RETURNS TABLE (category text, value integer)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.category, obligarth.retention_value(p_tenant, c.category) FROM obligarth_private.retention_catalog() c
$$;

-- 4. Changes --------------------------------------------------------------------------------
CREATE FUNCTION obligarth.retention_set(p_values jsonb, p_justification text, p_approval integer, p_body text)
  RETURNS TABLE (policy_version integer, lowered_categories text[], raised_categories text[], lowering_effective_at timestamptz)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '5s' AS $$
DECLARE
  v_tenant  integer := obligarth.ctx_tenant();
  v_actor   integer := obligarth.ctx_actor_user();
  b         jsonb   := p_body::jsonb;
  v_values  jsonb;
  v_pending jsonb;
  v_at      timestamptz;
  v_last    integer;
  v_version integer;
  v_lowered text[]  := ARRAY[]::text[];
  v_raised  text[]  := ARRAY[]::text[];
  e         record;
  v_cur     integer;
  v_new     integer;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'retention_set: the tenant''s context is required';
  END IF;
  IF p_values IS NULL OR p_values = '{}'::jsonb OR NOT COALESCE(obligarth_private.retention_values_valid(p_values), false) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'retention_set: values outside the catalogue or their range';
  END IF;
  IF COALESCE(length(trim(p_justification)), 0) < 10 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'retention_set: a justification is required';
  END IF;
  IF p_approval IS NULL THEN
    IF session_user = 'obligarth' THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'retention_set: an approved request is required';
    END IF;
  ELSIF NOT EXISTS (
      SELECT 1 FROM obligarth.pending_approvals a
       WHERE a.tenant_id = v_tenant AND a.id = p_approval
         AND a.request_type = 'privacy_retention_change' AND a.status = 'approved' AND a.executed_at IS NULL
         AND a.requested_by = v_actor AND a.reviewed_by IS NOT NULL AND a.reviewed_by <> a.requested_by
         AND a.payload -> 'values' = p_values) THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'retention_set: no approved request of the context''s actor for these values';
  END IF;
  IF b ->> 'action' IS DISTINCT FROM 'privacy.retention_changed' OR (b ->> 'tenant')::integer IS DISTINCT FROM v_tenant
     OR (b #> '{details,values}') IS DISTINCT FROM p_values THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'retention_set: the event does not describe this change';
  END IF;

  -- One change at a time per tenant; the row locked.
  PERFORM pg_advisory_xact_lock(hashtext('obligarth.retention_set'), v_tenant);
  INSERT INTO obligarth.tenant_retention_policies AS p (tenant_id, "values", version) VALUES (v_tenant, '{}'::jsonb, 0)
    ON CONFLICT (tenant_id) DO NOTHING;
  SELECT p."values", p.pending_values, p.pending_effective_at, p.approval_id
    INTO v_values, v_pending, v_at, v_last
    FROM obligarth.tenant_retention_policies p WHERE p.tenant_id = v_tenant
     FOR UPDATE;
  IF p_approval IS NOT NULL AND v_last IS NOT DISTINCT FROM p_approval THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'retention_set: this request was applied already';
  END IF;
  -- Decreases past their date are in force.
  IF v_at IS NOT NULL AND v_at <= now() THEN
    v_values := v_values || v_pending;
    v_pending := NULL;
    v_at := NULL;
  END IF;
  FOR e IN SELECT j.key, j.value FROM jsonb_each(p_values) j ORDER BY j.key LOOP
    v_new := ((e.value)::text)::integer;
    SELECT COALESCE((v_values ->> e.key)::integer, c.default_value) INTO v_cur
      FROM obligarth_private.retention_catalog() c WHERE c.category = e.key;
    IF v_new >= v_cur THEN
      IF v_new > v_cur THEN v_raised := v_raised || e.key; END IF;
      v_values := v_values || jsonb_build_object(e.key, v_new);
      v_pending := v_pending - e.key;
    ELSE
      v_lowered := v_lowered || e.key;
      v_pending := COALESCE(v_pending, '{}'::jsonb) || jsonb_build_object(e.key, v_new);
    END IF;
  END LOOP;
  IF v_pending = '{}'::jsonb THEN
    v_pending := NULL;
  END IF;
  IF v_pending IS NULL THEN
    v_at := NULL;
  ELSIF cardinality(v_lowered) > 0 THEN
    v_at := now() + interval '7 days';
  END IF;
  UPDATE obligarth.tenant_retention_policies p
     SET "values" = v_values, pending_values = v_pending, pending_effective_at = v_at,
         justification = trim(p_justification), version = p.version + 1, approval_id = p_approval,
         updated_by = v_actor, updated_at = now()
   WHERE p.tenant_id = v_tenant
  RETURNING p.version INTO v_version;
  PERFORM obligarth.audit_append(p_body);
  RETURN QUERY SELECT v_version, v_lowered, v_raised, CASE WHEN cardinality(v_lowered) > 0 THEN v_at END;
END $$;

REVOKE ALL ON FUNCTION obligarth.retention_value(integer, text), obligarth.retention_values(integer),
  obligarth.retention_set(jsonb, text, integer, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.retention_value(integer, text), obligarth.retention_values(integer)
  TO obligarth, obligarth_reader;
GRANT EXECUTE ON FUNCTION obligarth.retention_set(jsonb, text, integer, text) TO obligarth;
COMMENT ON FUNCTION obligarth.retention_value(integer, text) IS
  'retention (CNF-04): value in force of a category for a tenant (its context, a read context covering it, or none)';
COMMENT ON FUNCTION obligarth.retention_set(jsonb, text, integer, text) IS
  'retention (CNF-04): values of the tenant after an approved request; a decrease waits 7 days (D4)';

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.retention_value', 'definer', 'retention in force of a category for a tenant visible to the context'),
  ('function', 'obligarth.retention_values', 'definer', 'retention in force of every category for a tenant visible to the context'),
  ('function', 'obligarth.retention_set', 'definer', 'tenant context; approved request of the actor, or the owner; decrease after 7 days')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
