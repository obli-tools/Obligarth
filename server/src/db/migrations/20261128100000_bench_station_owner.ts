import type { Knex } from 'knex';

// =============================================================================
// Bench stations owned by a tenant; tenant, site and name chosen on the bench (lot BANC-T; spec banc-station-tenant
// §2, §5, §6, §9, §10)
// =============================================================================
//   a) bench_stations.owner_tenant_id: the tenant that owns the station. The owner's decision Q2 (28/11): the stations
//      of the platform BELONG TO THE MASTER TENANT (Default, id 1), which gathers every client. So the platform is
//      written 1, not NULL (the §2 draft): « owned by the platform » is then an ordinary owner, read the same way by
//      every guard (owner_tenant_id = the tenant of the context), the conversion is a change 1 -> client, and NULL keeps
//      a single meaning: the owner tenant was deleted (ON DELETE SET NULL), which the trigger turns into a revocation
//      'tenant_deleted' (never a silent return to the platform). Every existing station is the platform's (1).
//        owner_since         when a client got the station (its claim, or its assignment by the platform); NULL for 1
//        owner_assigned_by   the user who claimed it or assigned it (SET NULL with the account)
//        suspended_by_platform  a client's station suspended by the platform: the client does not lift it (Q1)
//      The owner columns are written by the definer functions only (UPDATE revoked from obligarth on them); the trigger
//      bench_stations_owner_guard admits 1 -> client (not revoked) and client -> NULL (deletion of the tenant) and
//      nothing else: never client -> 1, never client -> another client. A station is inserted as the platform's.
//   b) bench_station_targets_cap (BEFORE INSERT OR UPDATE OF station_id, tenant_id), under the same advisory lock as the
//      claim: a client's station targets ITS tenant only, a platform station is targeted by a platform administrator
//      only (check_violation bench_station_targets_owner); the cap of 200 unchanged. The trigger is the only truth,
//      serialised with the claim and the assignment by that lock.
//   c) bench_station_targets.name_template: the template of the suggested name (shared/src/mdm/bench.ts:
//      checkBenchNameTemplate; the CHECK bounds it). bench_provisionings.site_id (the site chosen on the bench, its
//      tenant's: foreign key on (tenant_id, site_id), SET NULL with the site) and legacy_owner_bench (the exception D3
//      decided AT THE BENCH, in the open session, Q3).
//   d) SECURITY DEFINER functions, each with its actor guard, registered (rls_registry):
//        bench_claim_station          tenant context of p_tenant, its user: a pending station of the platform, by its
//                                     exact name and its verification code recomputed in SQL (same digest as
//                                     stations.service.ts); one candidate exactly, else mismatch; a target in another
//                                     tenant: foreign_targets; else approved and owned by the tenant
//        bench_owned_station_set      the tenant's own station: suspend, resume (never a suspension of the platform),
//                                     revoke (reason 'owner'), rename, close its session; suspend and revoke close the session, revoke the
//                                     bench tokens not consumed and abandon the open provisionings
//        bench_tenant_owned_stations  the stations of the tenant (host and version, never an address: Q4)
//        bench_station_assign_owner   identity context, a platform administrator: a platform station (approved or
//                                     suspended) given to a client, when all its targets and open provisionings are
//                                     in that tenant (its open session closed)
//        bench_tenant_deleted_stations  the stations the deletion of a tenant just revoked (the master audit)
//        bench_station_sites          the station (i:bench-station:<id>): the sites of a tenant inside its targets
//                                     (the group of the site is a target group or below one; a site without group
//                                     belongs to the targets on a root group of its tenant only), not archived,
//                                     200 at most, by code
//        bench_station_site_devices   the station: the names used in one of those sites (its devices inside the
//                                     station's targets, open provisionings)
//        bench_station_targets_suspension_guard  (trigger) a target suspended by the platform (suspended_by_platform):
//                                     set, cleared and resumed by a platform administrator only (Q1)
//      bench_tenant_stations (+ owned; + the stations the tenant owns; a station another client owns: its id and name
//      only), bench_station_targets_of and bench_station_admin_targets (+ name_template, + suspended_by_platform) are
//      dropped and created again (their columns change).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply untouched (no new table), functions with
// SET search_path = pg_catalog, pg_temp and EXECUTE revoked from PUBLIC, rls_assert_clean() last, a down that raises.
// Runs as obligarth_owner (server-migrate), after bench_stations, bench_stations_user_fks and sites.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Bench stations owned by a tenant; site and name on the bench (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.bench_stations') IS NULL OR to_regclass('obligarth.bench_station_targets') IS NULL
     OR to_regclass('obligarth.bench_provisionings') IS NULL OR to_regclass('obligarth.sites') IS NULL
     OR to_regprocedure('obligarth.bench_tenant_stations(integer)') IS NULL THEN
    RAISE EXCEPTION 'bench_station_owner: apply the bench_stations and sites migrations first';
  END IF;
END $$;

-- a) The owner of a station ------------------------------------------------------------
ALTER TABLE obligarth.bench_stations
  ADD COLUMN owner_tenant_id       integer     DEFAULT 1,
  ADD COLUMN owner_since           timestamptz,
  ADD COLUMN owner_assigned_by     integer,
  ADD COLUMN suspended_by_platform boolean     NOT NULL DEFAULT false;
UPDATE obligarth.bench_stations SET owner_tenant_id = 1 WHERE owner_tenant_id IS NULL;
ALTER TABLE obligarth.bench_stations
  ADD CONSTRAINT bench_stations_owner_foreign FOREIGN KEY (owner_tenant_id) REFERENCES obligarth.tenants (id) ON DELETE SET NULL,
  ADD CONSTRAINT bench_stations_owner_assigned_by_foreign FOREIGN KEY (owner_assigned_by) REFERENCES obligarth.users (id) ON DELETE SET NULL,
  -- NULL only once revoked (its tenant deleted); the platform (1) has no date, a client has one.
  ADD CONSTRAINT bench_stations_owner_check CHECK (status = 'revoked'
    OR (owner_tenant_id IS NOT NULL AND (owner_tenant_id = 1) = (owner_since IS NULL))),
  ADD CONSTRAINT bench_stations_platform_suspension_check CHECK (NOT suspended_by_platform OR status = 'suspended'),
  DROP CONSTRAINT bench_stations_revoked_reason_check,
  ADD CONSTRAINT bench_stations_revoked_reason_check CHECK (revoked_reason IS NULL
    OR revoked_reason IN ('admin', 'pending_expired', 'idle', 'owner', 'tenant_deleted'));
CREATE INDEX bench_stations_owner ON obligarth.bench_stations (owner_tenant_id) WHERE owner_tenant_id <> 1;

-- The owner columns: the definer functions only.
REVOKE UPDATE ON obligarth.bench_stations FROM obligarth;
GRANT UPDATE (name, hostname, status, station_version, approved_at, approved_by, suspended_at, suspended_by, revoked_at,
  revoked_by, revoked_reason, allowed_cidrs, last_seen_at, last_ip, suspended_by_platform) ON obligarth.bench_stations TO obligarth;

-- 1 -> client (not revoked, with its date) and client -> NULL (the tenant deleted: revoked) only. A definer trigger:
-- the revocation by the deletion of a tenant closes the open session of the station in the same statement.
CREATE FUNCTION obligarth_private.bench_stations_owner_guard() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.owner_tenant_id IS DISTINCT FROM 1 OR NEW.owner_since IS NOT NULL OR NEW.suspended_by_platform THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_stations: a station starts as the platform''s (tenant 1)';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.owner_tenant_id IS NOT DISTINCT FROM OLD.owner_tenant_id THEN
    IF NEW.owner_since IS DISTINCT FROM OLD.owner_since THEN
      RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_stations: the date of the owner changes with the owner only';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.owner_tenant_id IS NULL AND OLD.owner_tenant_id IS NOT NULL THEN
    IF OLD.status <> 'revoked' THEN
      NEW.status := 'revoked';
      NEW.revoked_at := now();
      NEW.revoked_by := NULL;
      NEW.revoked_reason := 'tenant_deleted';
      NEW.suspended_by_platform := false;
      UPDATE obligarth.bench_sessions ss SET closed_at = now(), close_reason = 'station_revoked'
       WHERE ss.station_id = NEW.id AND ss.closed_at IS NULL;
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.owner_tenant_id = 1 AND NEW.owner_tenant_id <> 1 AND OLD.status <> 'revoked' AND NEW.owner_since IS NOT NULL THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION USING ERRCODE = '42501',
    MESSAGE = 'bench_stations: a station goes from the platform to a client only, never back nor to another client';
END $$;
REVOKE ALL ON FUNCTION obligarth_private.bench_stations_owner_guard() FROM PUBLIC;
CREATE TRIGGER bench_stations_owner_guard BEFORE INSERT OR UPDATE ON obligarth.bench_stations
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.bench_stations_owner_guard();

-- b) The targets confined to the owner -------------------------------------------------
CREATE OR REPLACE FUNCTION obligarth_private.bench_station_targets_cap() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_owner integer;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('bench_station_targets:' || NEW.station_id::text));
  SELECT s.owner_tenant_id INTO v_owner FROM obligarth.bench_stations s WHERE s.id = NEW.station_id;
  IF v_owner IS NULL OR (v_owner <> 1 AND NEW.tenant_id <> v_owner)
     OR (v_owner = 1 AND NOT obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_station_targets_owner',
      MESSAGE = 'bench_station_targets: a station of a client targets its tenant only; a platform station, a platform administrator only';
  END IF;
  IF TG_OP = 'INSERT' OR NEW.station_id IS DISTINCT FROM OLD.station_id THEN
    IF (SELECT count(*) FROM obligarth.bench_station_targets t WHERE t.station_id = NEW.station_id) >= 200 THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_station_targets_cap',
        MESSAGE = 'bench_station_targets: 200 targets per station at most';
    END IF;
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.bench_station_targets_cap() FROM PUBLIC;
DROP TRIGGER bench_station_targets_cap ON obligarth.bench_station_targets;
CREATE TRIGGER bench_station_targets_cap BEFORE INSERT OR UPDATE OF station_id, tenant_id ON obligarth.bench_station_targets
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.bench_station_targets_cap();

-- A target of a client's station suspended by the platform (Q1, « watch and cut »): the client does not lift it. Set
-- and cleared by a platform administrator only, and while it is set only a platform administrator resumes the target
-- (check_violation bench_station_targets_platform_suspension). The removal of such a target is refused by the route of
-- the owner (owned.routes.ts), the cascades (group, tenant) excepted.
CREATE FUNCTION obligarth_private.bench_station_targets_suspension_guard() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.suspended_by_platform AND NOT obligarth.ctx_actor_is_platform_admin() THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_station_targets_platform_suspension',
        MESSAGE = 'bench_station_targets: a suspension of the platform is set by a platform administrator only';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.suspended_by_platform IS DISTINCT FROM OLD.suspended_by_platform
      OR (OLD.suspended_by_platform AND NEW.suspended_at IS DISTINCT FROM OLD.suspended_at))
     AND NOT obligarth.ctx_actor_is_platform_admin() THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'bench_station_targets_platform_suspension',
      MESSAGE = 'bench_station_targets: the platform suspended this target: only the platform resumes it';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.bench_station_targets_suspension_guard() FROM PUBLIC;
ALTER TABLE obligarth.bench_station_targets
  ADD COLUMN suspended_by_platform boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT bench_station_targets_platform_suspension_check CHECK (NOT suspended_by_platform OR suspended_at IS NOT NULL);
CREATE TRIGGER bench_station_targets_suspension_guard BEFORE INSERT OR UPDATE OF suspended_at, suspended_by_platform
  ON obligarth.bench_station_targets FOR EACH ROW EXECUTE FUNCTION obligarth_private.bench_station_targets_suspension_guard();

-- c) The name template of a target; the site and the exception D3 of a provisioning ---------
ALTER TABLE obligarth.bench_station_targets
  ADD COLUMN name_template text,
  ADD CONSTRAINT bench_station_targets_name_template_check CHECK (name_template IS NULL OR (char_length(name_template) BETWEEN 3 AND 64
    AND name_template = btrim(name_template) AND name_template !~ '[[:cntrl:]]' AND name_template ~ '[{]n(:[0-9]+)*[}]'));

ALTER TABLE obligarth.bench_provisionings
  ADD COLUMN site_id            uuid,
  ADD COLUMN legacy_owner_bench boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT bench_provisionings_site_foreign FOREIGN KEY (tenant_id, site_id)
    REFERENCES obligarth.sites (tenant_id, id) ON DELETE SET NULL (site_id);
CREATE INDEX bench_provisionings_site_open ON obligarth.bench_provisionings (tenant_id, site_id)
  WHERE site_id IS NOT NULL AND state IN ('planned', 'token_issued', 'enrolled');

-- The group p_group is p_root or below it (tenant p_tenant).
CREATE FUNCTION obligarth_private.bench_group_within(p_tenant integer, p_group integer, p_root integer) RETURNS boolean
  LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  WITH RECURSIVE up(id, parent_id, depth) AS (
    SELECT g.id, g.parent_id, 0 FROM obligarth.device_groups g WHERE g.tenant_id = p_tenant AND g.id = p_group
    UNION ALL
    SELECT g.id, g.parent_id, up.depth + 1 FROM obligarth.device_groups g
      JOIN up ON g.id = up.parent_id AND g.tenant_id = p_tenant WHERE up.depth < 32)
  SELECT EXISTS (SELECT 1 FROM up WHERE up.id = p_root)
$$;
REVOKE ALL ON FUNCTION obligarth_private.bench_group_within(integer, integer, integer) FROM PUBLIC;

-- The verification code of a station (stations.service.ts stationVerificationCode, shared benchVerificationCode):
-- the 8 first hexadecimal characters, upper case, of sha256('obligarth-bench-verification:' || token_sha256).
CREATE FUNCTION obligarth_private.bench_verification_code(p_token_sha256 text) RETURNS text
  LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp
  RETURN upper(left(encode(sha256(convert_to('obligarth-bench-verification:' || p_token_sha256, 'UTF8')), 'hex'), 8));
REVOKE ALL ON FUNCTION obligarth_private.bench_verification_code(text) FROM PUBLIC;

-- d) Definer functions ------------------------------------------------------------------
-- The claim of a pending platform station by a tenant (POST /api/bench-stations/claim, after its limiters and a strict
-- second factor): its exact name and its code, under the lock of the registrations and then the one of its targets.
CREATE FUNCTION obligarth.bench_claim_station(p_tenant integer, p_user integer, p_name text, p_code text)
  RETURNS TABLE (outcome text, station_id uuid)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_code text := upper(regexp_replace(COALESCE(p_code, ''), '[[:space:]-]', '', 'g'));
  v_ids uuid[];
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'tenant' OR obligarth.ctx_tenant() IS DISTINCT FROM p_tenant
     OR obligarth.ctx_actor_user() IS DISTINCT FROM p_user OR p_tenant = 1 THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_claim_station: a user of a client tenant, in its context';
  END IF;
  PERFORM pg_advisory_xact_lock(x'6f62'::integer, x'62'::integer);
  SELECT array_agg(s.id ORDER BY s.id) INTO v_ids FROM obligarth.bench_stations s
   WHERE s.status = 'pending' AND s.owner_tenant_id = 1 AND s.created_at > now() - interval '24 hours'
     AND s.name = p_name AND char_length(v_code) = 8
     AND obligarth_private.bench_verification_code(btrim(s.token_sha256::text)) = v_code;
  IF v_ids IS NULL OR cardinality(v_ids) <> 1 THEN
    RETURN QUERY SELECT 'mismatch'::text, NULL::uuid;
    RETURN;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('bench_station_targets:' || v_ids[1]::text));
  PERFORM 1 FROM obligarth.bench_stations s WHERE s.id = v_ids[1] AND s.status = 'pending' AND s.owner_tenant_id = 1 FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'mismatch'::text, NULL::uuid;
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM obligarth.bench_station_targets t WHERE t.station_id = v_ids[1] AND t.tenant_id <> p_tenant) THEN
    RETURN QUERY SELECT 'foreign_targets'::text, v_ids[1];
    RETURN;
  END IF;
  UPDATE obligarth.bench_stations s
     SET status = 'approved', approved_at = now(), approved_by = p_user,
         owner_tenant_id = p_tenant, owner_since = now(), owner_assigned_by = p_user
   WHERE s.id = v_ids[1];
  RETURN QUERY SELECT 'claimed'::text, v_ids[1];
END $$;

-- A station of the tenant: suspend, resume, revoke, rename. not_found for any station the tenant does not own.
CREATE FUNCTION obligarth.bench_owned_station_set(p_station uuid, p_tenant integer, p_user integer, p_action text, p_name text)
  RETURNS TABLE (outcome text, from_status text, station_name text, tokens integer, provisionings integer)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_row obligarth.bench_stations%ROWTYPE;
  v_tok integer := 0;
  v_prov integer := 0;
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'tenant' OR obligarth.ctx_tenant() IS DISTINCT FROM p_tenant
     OR obligarth.ctx_actor_user() IS DISTINCT FROM p_user OR p_tenant = 1
     OR p_action NOT IN ('suspend', 'resume', 'revoke', 'rename', 'close_session') THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_owned_station_set: a user of the owner tenant, in its context';
  END IF;
  SELECT * INTO v_row FROM obligarth.bench_stations s WHERE s.id = p_station AND s.owner_tenant_id = p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text, 0, 0;
    RETURN;
  END IF;
  IF p_action = 'close_session' THEN
    UPDATE obligarth.bench_sessions ss SET closed_at = now(), closed_by = p_user, close_reason = 'admin'
     WHERE ss.station_id = p_station AND ss.closed_at IS NULL;
    RETURN QUERY SELECT (CASE WHEN FOUND THEN 'done' ELSE 'unchanged' END)::text, v_row.status, v_row.name, 0, 0;
    RETURN;
  END IF;
  IF p_action = 'rename' THEN
    IF v_row.status = 'revoked' THEN
      RETURN QUERY SELECT 'bad_state'::text, v_row.status, v_row.name, 0, 0;
      RETURN;
    END IF;
    IF v_row.name = p_name THEN
      RETURN QUERY SELECT 'unchanged'::text, v_row.status, v_row.name, 0, 0;
      RETURN;
    END IF;
    UPDATE obligarth.bench_stations s SET name = p_name WHERE s.id = p_station;
    RETURN QUERY SELECT 'done'::text, v_row.status, v_row.name, 0, 0;
    RETURN;
  END IF;
  IF p_action = 'resume' THEN
    IF v_row.status <> 'suspended' THEN
      RETURN QUERY SELECT 'bad_state'::text, v_row.status, v_row.name, 0, 0;
      RETURN;
    END IF;
    IF v_row.suspended_by_platform THEN
      RETURN QUERY SELECT 'platform_suspended'::text, v_row.status, v_row.name, 0, 0;
      RETURN;
    END IF;
    UPDATE obligarth.bench_stations s SET status = 'approved', suspended_at = NULL, suspended_by = NULL WHERE s.id = p_station;
    RETURN QUERY SELECT 'done'::text, v_row.status, v_row.name, 0, 0;
    RETURN;
  END IF;
  IF (p_action = 'suspend' AND v_row.status <> 'approved') OR (p_action = 'revoke' AND v_row.status = 'revoked') THEN
    RETURN QUERY SELECT 'bad_state'::text, v_row.status, v_row.name, 0, 0;
    RETURN;
  END IF;
  IF p_action = 'suspend' THEN
    UPDATE obligarth.bench_stations s SET status = 'suspended', suspended_at = now(), suspended_by = p_user,
           suspended_by_platform = false WHERE s.id = p_station;
  ELSE
    UPDATE obligarth.bench_stations s SET status = 'revoked', revoked_at = now(), revoked_by = p_user, revoked_reason = 'owner',
           suspended_at = NULL, suspended_by = NULL, suspended_by_platform = false WHERE s.id = p_station;
  END IF;
  UPDATE obligarth.bench_sessions ss SET closed_at = now(), closed_by = p_user,
         close_reason = CASE p_action WHEN 'revoke' THEN 'station_revoked' ELSE 'station_suspended' END
   WHERE ss.station_id = p_station AND ss.closed_at IS NULL;
  WITH tok AS (
    UPDATE obligarth.legacy_agent_enrollment_tokens t SET revoked_at = now(), revoked_by = p_user
     WHERE t.origin = 'bench' AND t.created_by_station = p_station AND t.revoked_at IS NULL AND t.uses < t.max_uses
     RETURNING 1),
  prov AS (
    UPDATE obligarth.bench_provisionings p SET state = 'abandoned', error_code = 'station_refused', outcome_at = now(), updated_at = now()
     WHERE p.station_id = p_station AND p.state IN ('planned', 'token_issued', 'enrolled')
     RETURNING 1)
  SELECT (SELECT count(*)::integer FROM tok), (SELECT count(*)::integer FROM prov) INTO v_tok, v_prov;
  RETURN QUERY SELECT 'done'::text, v_row.status, v_row.name, v_tok, v_prov;
END $$;

-- The stations the tenant owns, revoked ones included (no token, no address: host and version, Q4). The technician of
-- an open session named only when a member of the tenant.
CREATE FUNCTION obligarth.bench_tenant_owned_stations(p_tenant integer)
  RETURNS TABLE (id uuid, name text, hostname text, status text, station_version text, created_at timestamptz, approved_at timestamptz,
                 suspended_at timestamptz, suspended_by_platform boolean, revoked_at timestamptz, revoked_reason text,
                 last_seen_at timestamptz, owner_since timestamptz, session_id uuid, session_expires_at timestamptz, technician text,
                 session_user_id integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'tenant' OR obligarth.ctx_tenant() IS DISTINCT FROM p_tenant OR p_tenant = 1 THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_tenant_owned_stations: the tenant itself only';
  END IF;
  RETURN QUERY
    SELECT s.id, s.name, s.hostname, s.status, s.station_version, s.created_at, s.approved_at, s.suspended_at, s.suspended_by_platform,
           s.revoked_at, s.revoked_reason, s.last_seen_at, s.owner_since, ss.id, ss.expires_at,
           COALESCE(NULLIF(u.display_name::text, ''), u.username::text), u.id
      FROM obligarth.bench_stations s
      LEFT JOIN obligarth.bench_sessions ss ON ss.station_id = s.id AND ss.closed_at IS NULL AND ss.expires_at > now()
      LEFT JOIN obligarth.users u ON u.id = ss.user_id
            AND EXISTS (SELECT 1 FROM obligarth.user_tenants ut WHERE ut.user_id = ss.user_id AND ut.tenant_id = p_tenant)
     WHERE s.owner_tenant_id = p_tenant
     ORDER BY CASE s.status WHEN 'revoked' THEN 1 ELSE 0 END, s.name, s.id
     LIMIT 500;
END $$;

-- The conversion of a platform station into a client's (Q2): a platform administrator, every target and every open
-- provisioning of the station in that tenant; its open session closed. Never the other way.
CREATE FUNCTION obligarth.bench_station_assign_owner(p_station uuid, p_tenant integer, p_user integer) RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_row obligarth.bench_stations%ROWTYPE;
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'identity' OR obligarth.ctx_actor_user() IS DISTINCT FROM p_user
     OR NOT obligarth.ctx_actor_is_platform_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_assign_owner: a platform administrator only';
  END IF;
  IF p_tenant = 1 OR NOT EXISTS (SELECT 1 FROM obligarth.tenants te WHERE te.id = p_tenant) THEN
    RETURN 'bad_tenant';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('bench_station_targets:' || p_station::text));
  SELECT * INTO v_row FROM obligarth.bench_stations s WHERE s.id = p_station FOR UPDATE;
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  IF v_row.owner_tenant_id IS DISTINCT FROM 1 THEN RETURN 'already_owned'; END IF;
  IF v_row.status NOT IN ('approved', 'suspended') THEN RETURN 'bad_state'; END IF;
  IF EXISTS (SELECT 1 FROM obligarth.bench_station_targets t WHERE t.station_id = p_station AND t.tenant_id <> p_tenant)
     OR EXISTS (SELECT 1 FROM obligarth.bench_provisionings p WHERE p.station_id = p_station AND p.tenant_id <> p_tenant
                   AND p.state IN ('planned', 'token_issued', 'enrolled')) THEN
    RETURN 'foreign_targets';
  END IF;
  UPDATE obligarth.bench_sessions ss SET closed_at = now(), closed_by = p_user, close_reason = 'admin'
   WHERE ss.station_id = p_station AND ss.closed_at IS NULL;
  UPDATE obligarth.bench_stations s
     SET owner_tenant_id = p_tenant, owner_since = now(), owner_assigned_by = p_user,
         suspended_by_platform = (s.status = 'suspended' AND s.suspended_by IS NOT NULL)
   WHERE s.id = p_station;
  -- The targets the platform suspended before the conversion stay its suspensions (the client does not lift them).
  UPDATE obligarth.bench_station_targets t SET suspended_by_platform = true
   WHERE t.station_id = p_station AND t.suspended_at IS NOT NULL AND NOT t.suspended_by_platform;
  RETURN 'assigned';
END $$;

-- The stations revoked by the deletion of a tenant in this transaction (tenant.service deleteHere: the master audit).
CREATE FUNCTION obligarth.bench_tenant_deleted_stations() RETURNS TABLE (id uuid, name text)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT obligarth.ctx_actor_is_platform_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_tenant_deleted_stations: a platform administrator only';
  END IF;
  RETURN QUERY SELECT s.id, s.name FROM obligarth.bench_stations s
    WHERE s.revoked_reason = 'tenant_deleted' AND s.revoked_at = now() AND s.owner_tenant_id IS NULL ORDER BY s.id;
END $$;

-- The sites of a tenant inside the station's targets (not suspended), not archived: the group of the site is a target
-- group or below one; a site without a group belongs only to the targets on a root group of its tenant (a target on a
-- subgroup never reaches the group-less sites). The devices counted: those inside the targets. p_site: that site only (any
-- tenant of the station); p_search: in the code, the name or the city. 200 at most, by code.
CREATE FUNCTION obligarth.bench_station_sites(p_station uuid, p_tenant integer, p_site uuid, p_search text)
  RETURNS TABLE (tenant_id integer, id uuid, code text, name text, city text, group_id integer, group_path text, devices integer,
                 target_group_ids integer[])
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_pattern text;
BEGIN
  IF obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station:' || p_station::text THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_sites: the station itself only';
  END IF;
  IF p_tenant IS NULL AND p_site IS NULL THEN RETURN; END IF;
  IF p_search IS NOT NULL AND btrim(p_search) <> '' THEN
    v_pattern := '%' || replace(replace(replace(left(btrim(p_search), 100), '\', '\\'), '%', '\%'), '_', '\_') || '%';
  END IF;
  RETURN QUERY
    WITH s AS (
      SELECT si.tenant_id AS tid, si.id AS sid, si.code::text AS scode, si.name::text AS sname, si.city::text AS scity, si.group_id AS sgroup,
             ARRAY(SELECT t.group_id FROM obligarth.bench_station_targets t
                    WHERE t.station_id = p_station AND t.tenant_id = si.tenant_id AND t.suspended_at IS NULL
                      AND CASE WHEN si.group_id IS NULL
                               THEN EXISTS (SELECT 1 FROM obligarth.device_groups g
                                             WHERE g.tenant_id = si.tenant_id AND g.id = t.group_id AND g.parent_id IS NULL)
                               ELSE obligarth_private.bench_group_within(si.tenant_id, si.group_id, t.group_id) END
                    ORDER BY t.group_id) AS tgs
        FROM obligarth.sites si
       WHERE si.archived_at IS NULL
         AND (p_site IS NULL OR si.id = p_site)
         AND (p_tenant IS NULL OR si.tenant_id = p_tenant)
         AND EXISTS (SELECT 1 FROM obligarth.bench_station_targets t0
                      WHERE t0.station_id = p_station AND t0.tenant_id = si.tenant_id AND t0.suspended_at IS NULL)
         AND (v_pattern IS NULL OR si.code ILIKE v_pattern ESCAPE '\' OR si.name ILIKE v_pattern ESCAPE '\'
              OR COALESCE(si.city, '') ILIKE v_pattern ESCAPE '\'))
    SELECT s.tid, s.sid, s.scode, s.sname, s.scity, s.sgroup,
           CASE WHEN s.sgroup IS NULL THEN NULL::text ELSE obligarth_private.bench_group_path(s.tid, s.sgroup) END,
           (SELECT count(*)::integer FROM obligarth.devices d
             WHERE d.tenant_id = s.tid AND d.site_id = s.sid AND d.enrollment_state <> 'unenrolled'
               AND EXISTS (SELECT 1 FROM unnest(s.tgs) AS r(gid) WHERE obligarth_private.bench_group_within(s.tid, d.group_id, r.gid))),
           s.tgs
      FROM s WHERE cardinality(s.tgs) > 0
     ORDER BY lower(s.scode), s.sid
     LIMIT 200;
END $$;

-- The names used in a site of the station's targets: its devices under management and the open provisionings of the
-- benches (serial numbers cut to their last four characters). 1000 at most.
CREATE FUNCTION obligarth.bench_station_site_devices(p_station uuid, p_site uuid)
  RETURNS TABLE (kind text, label text, model text, serial_tail text, last_seen_at timestamptz)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_tenant integer;
  v_groups integer[];
  v_site_group integer;
BEGIN
  IF obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station:' || p_station::text THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_site_devices: the station itself only';
  END IF;
  SELECT x.tenant_id, x.target_group_ids, x.group_id INTO v_tenant, v_groups, v_site_group
    FROM obligarth.bench_station_sites(p_station, NULL, p_site, NULL) x;
  IF v_tenant IS NULL THEN RETURN; END IF;
  RETURN QUERY
    (SELECT 'device'::text, d.label, COALESCE(d.model_name, d.model)::text,
            CASE WHEN d.serial_number IS NULL OR d.serial_number = '' THEN NULL::text
                 WHEN char_length(d.serial_number) <= 4 THEN '…' || d.serial_number ELSE '…' || right(d.serial_number, 4) END,
            d.last_checkin_at
       FROM obligarth.devices d
      WHERE d.tenant_id = v_tenant AND d.site_id = p_site AND d.enrollment_state <> 'unenrolled'
        AND EXISTS (SELECT 1 FROM unnest(v_groups) AS r(gid) WHERE obligarth_private.bench_group_within(v_tenant, d.group_id, r.gid))
      ORDER BY d.label LIMIT 1000)
    UNION ALL
    (SELECT 'provisioning'::text, p.device_name, p.model::text,
            CASE WHEN char_length(p.adb_serial) <= 4 THEN '…' || p.adb_serial ELSE '…' || right(p.adb_serial, 4) END,
            NULL::timestamptz
       FROM obligarth.bench_provisionings p
      WHERE p.tenant_id = v_tenant AND p.site_id = p_site AND p.device_name IS NOT NULL AND p.device_id IS NULL
        AND p.state IN ('planned', 'token_issued', 'enrolled')
        -- In a site with a group, every provisioning lands in that group (inside the targets); in a site without one,
        -- in its target's group: only those inside the station's targets.
        AND (v_site_group IS NOT NULL
             OR EXISTS (SELECT 1 FROM unnest(v_groups) AS r(gid) WHERE obligarth_private.bench_group_within(v_tenant, p.group_id, r.gid)))
      ORDER BY p.device_name LIMIT 200);
END $$;

-- The functions whose columns change: dropped and created again.
DROP FUNCTION obligarth.bench_tenant_stations(integer);
CREATE FUNCTION obligarth.bench_tenant_stations(p_tenant integer)
  RETURNS TABLE (id uuid, name text, status text, last_seen_at timestamptz, session_id uuid, session_expires_at timestamptz, technician text,
                 session_user_id integer, owned boolean, elsewhere boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'tenant' OR obligarth.ctx_tenant() IS DISTINCT FROM p_tenant THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_tenant_stations: the tenant itself only';
  END IF;
  -- A station another client owns now (converted after it provisioned into this tenant): its id and name only, for the
  -- labels of the history (elsewhere); never its status, its last contact or its session.
  RETURN QUERY
    SELECT s.id, s.name,
           CASE WHEN v.visible THEN s.status END, CASE WHEN v.visible THEN s.last_seen_at END, ss.id, ss.expires_at,
           COALESCE(NULLIF(u.display_name::text, ''), u.username::text), u.id,
           (s.owner_tenant_id = p_tenant AND p_tenant <> 1), NOT v.visible
      FROM obligarth.bench_stations s
      CROSS JOIN LATERAL (SELECT (s.owner_tenant_id = 1 OR s.owner_tenant_id = p_tenant) IS TRUE AS visible) v
      LEFT JOIN obligarth.bench_sessions ss ON v.visible AND ss.station_id = s.id AND ss.closed_at IS NULL AND ss.expires_at > now()
      LEFT JOIN obligarth.users u ON u.id = ss.user_id
            AND EXISTS (SELECT 1 FROM obligarth.user_tenants ut WHERE ut.user_id = ss.user_id AND ut.tenant_id = p_tenant)
     WHERE EXISTS (SELECT 1 FROM obligarth.bench_station_targets t WHERE t.station_id = s.id AND t.tenant_id = p_tenant)
        OR EXISTS (SELECT 1 FROM obligarth.bench_provisionings p WHERE p.station_id = s.id AND p.tenant_id = p_tenant)
        OR (s.owner_tenant_id = p_tenant AND p_tenant <> 1)
     ORDER BY s.name;
END $$;

DROP FUNCTION obligarth.bench_station_targets_of(uuid);
CREATE FUNCTION obligarth.bench_station_targets_of(p_station uuid)
  RETURNS TABLE (tenant_id integer, tenant_name text, group_id integer, group_path text, role_policy text, allow_legacy_owner boolean,
                 name_prefix text, disable_dev_options boolean, name_template text)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_actor() IS DISTINCT FROM 'i:bench-station:' || p_station::text THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_targets_of: the station itself only';
  END IF;
  RETURN QUERY
    SELECT t.tenant_id, te.name::text, t.group_id, obligarth_private.bench_group_path(t.tenant_id, t.group_id), t.role_policy,
           t.allow_legacy_owner, t.name_prefix, t.disable_dev_options, t.name_template
      FROM obligarth.bench_station_targets t
      JOIN obligarth.tenants te ON te.id = t.tenant_id
     WHERE t.station_id = p_station AND t.suspended_at IS NULL
     ORDER BY te.name, t.group_id;
END $$;

DROP FUNCTION obligarth.bench_station_admin_targets(uuid);
CREATE FUNCTION obligarth.bench_station_admin_targets(p_station uuid)
  RETURNS TABLE (tenant_id integer, tenant_name text, group_id integer, group_path text, role_policy text, allow_legacy_owner boolean,
                 name_prefix text, disable_dev_options boolean, suspended_at timestamptz, created_at timestamptz, created_by integer,
                 name_template text, suspended_by_platform boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'identity' OR NOT obligarth.ctx_actor_is_platform_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'bench_station_admin_targets: a platform administrator only';
  END IF;
  RETURN QUERY
    SELECT t.tenant_id, te.name::text, t.group_id, obligarth_private.bench_group_path(t.tenant_id, t.group_id), t.role_policy,
           t.allow_legacy_owner, t.name_prefix, t.disable_dev_options, t.suspended_at, t.created_at, t.created_by, t.name_template,
           t.suspended_by_platform
      FROM obligarth.bench_station_targets t JOIN obligarth.tenants te ON te.id = t.tenant_id
     WHERE t.station_id = p_station ORDER BY te.name, t.group_id;
END $$;

REVOKE ALL ON FUNCTION obligarth.bench_claim_station(integer, integer, text, text),
  obligarth.bench_owned_station_set(uuid, integer, integer, text, text), obligarth.bench_tenant_owned_stations(integer),
  obligarth.bench_station_assign_owner(uuid, integer, integer), obligarth.bench_tenant_deleted_stations(),
  obligarth.bench_station_sites(uuid, integer, uuid, text), obligarth.bench_station_site_devices(uuid, uuid),
  obligarth.bench_tenant_stations(integer), obligarth.bench_station_targets_of(uuid), obligarth.bench_station_admin_targets(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.bench_claim_station(integer, integer, text, text),
  obligarth.bench_owned_station_set(uuid, integer, integer, text, text), obligarth.bench_tenant_owned_stations(integer),
  obligarth.bench_station_assign_owner(uuid, integer, integer), obligarth.bench_tenant_deleted_stations(),
  obligarth.bench_station_sites(uuid, integer, uuid, text), obligarth.bench_station_site_devices(uuid, uuid),
  obligarth.bench_tenant_stations(integer), obligarth.bench_station_targets_of(uuid), obligarth.bench_station_admin_targets(uuid) TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth_private.bench_stations_owner_guard', 'definer', 'bench stations: the owner goes 1 -> client or client -> NULL (tenant deleted: revoked, its session closed); its trigger only'),
  ('function', 'obligarth_private.bench_station_targets_suspension_guard', 'definer', 'bench stations: a target suspended by the platform is set, cleared and resumed by a platform administrator only (its trigger only)'),
  ('function', 'obligarth_private.bench_station_targets_cap', 'definer', 'bench stations: targets confined to the owner tenant and the cap of 200 per station across the tenants (its trigger only)'),
  ('function', 'obligarth.bench_claim_station', 'definer', 'bench stations: claim of a pending platform station by its name and code (tenant context, its user)'),
  ('function', 'obligarth.bench_owned_station_set', 'definer', 'bench stations: suspend, resume, revoke, rename a station the tenant owns (tenant context, its user)'),
  ('function', 'obligarth.bench_tenant_owned_stations', 'definer', 'bench stations: the stations the tenant owns, without address (tenant context)'),
  ('function', 'obligarth.bench_station_assign_owner', 'definer', 'bench stations: a platform station given to a client (identity context, platform administrator)'),
  ('function', 'obligarth.bench_tenant_deleted_stations', 'definer', 'bench stations: the stations the deletion of a tenant revoked in this transaction (platform administrator)'),
  ('function', 'obligarth.bench_station_sites', 'definer', 'bench station surface: the sites of a tenant inside the station targets (i:bench-station:<id>)'),
  ('function', 'obligarth.bench_station_site_devices', 'definer', 'bench station surface: the names used in a site of the station targets (i:bench-station:<id>)'),
  ('function', 'obligarth.bench_tenant_stations', 'definer', 'bench stations: the stations that target a tenant, enrolled into it or that it owns, from its context'),
  ('function', 'obligarth.bench_station_targets_of', 'definer', 'bench station surface: the targets of a station in every tenant (i:bench-station:<id>)'),
  ('function', 'obligarth.bench_station_admin_targets', 'definer', 'bench stations: the targets of a station in every tenant (identity context, platform administrator)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('bench_station_owner cannot be rolled back: restore the backup taken before the upgrade');
}
