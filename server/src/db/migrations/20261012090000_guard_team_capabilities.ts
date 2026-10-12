import type { Knex } from 'knex';

// Review of lot B4 (integration-apple-edge, review of lot B4, INT-B4-R4; audit-durci §10.8): the 72-hour cooldown
// of a new privilege did not cover the destructive device capabilities. The guarded MDM actions (erase, removal
// from management, lock, lost mode) ask of their requester a device capability (mdm:wipe, mdm:remove, mdm:lock,
// mdm:lost_mode), which a team gives (team_permissions.capabilities, team_memberships): neither a team row that
// gains such a capability nor an account that joins such a team recorded a privilege grant, so an account created
// a minute ago scheduled an erase, while a tenant administrator created at the same time was refused
// (privilegeCooldown). Same nature as AUD-A7-R5 (a role whose permission set holds devices.manage), closed by
// guard_integration for the roles; here for the teams, by the database, whatever the path (console, approval,
// SSO synchronisation, script):
//   - a team row that gains a destructive capability (a new row, a capability added, a row moved to another
//     team): a grant for each member of the team who did not hold that capability in the tenant already;
//   - an account that joins a team holding one it did not hold in the tenant already: a grant;
//   - an account reactivated that holds one through its teams: a grant (as for the privileged roles).
// A grant is of kind 'tenant_admin' (what the engine checks of a requester: guard_cooldown_until) with the cause
// 'capability_team' (or 'reactivated'); the job actions.privilege-watch alerts on it like on any other. A platform
// administrator passes every capability check without a team: no grant for one.
// The triggers are BEFORE ROW: each sees the rows the same statement wrote before it, so two rows giving the same
// capability in one statement record one grant, not none. « Already held » is read in the table as it is when
// the row is written: a writer that replaces the rows of a team (delete all, insert all) would make every member
// look new, hence the console writes only what changes (services/team.service.ts); a writer that does not errs
// on the safe side (a cooldown too many, never one too few).
// Not covered, stated in the specification: a scope added to a team for a capability its members already hold
// elsewhere in the tenant (more devices, same right), and a row whose level opens the writing (ro to rw).
// No table: nothing to classify. Runs as obligarth_owner (server-migrate), after guard_integration, applied last
// in every admitted order; ends with obligarth.rls_assert_clean(). The SQL holds no question mark (knex.raw would
// bind it) and no backslash; it is kept verbatim by String.raw.
const UP = String.raw`-- =============================================================================
-- Review of lot B4 (INT-B4-R4): cooldown of the destructive device capabilities given by a team.
-- Run as obligarth_owner, in one transaction.
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.record_privilege_change()') IS NULL
     OR to_regclass('obligarth.team_permissions') IS NULL OR to_regclass('obligarth.team_memberships') IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'obligarth.privilege_grants'::regclass AND attname = 'cause') THEN
    RAISE EXCEPTION 'guard_team_capabilities: apply guard_foundation and guard_integration first';
  END IF;
END $$;

-- 1. A new cause of a grant: a destructive device capability received through a team
DO $$
DECLARE
  c record;
BEGIN
  FOR c IN SELECT conname FROM pg_constraint
            WHERE conrelid = 'obligarth.privilege_grants'::regclass AND contype = 'c'
              AND pg_get_constraintdef(oid) LIKE '%capability_set%' LOOP
    EXECUTE format('ALTER TABLE obligarth.privilege_grants DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;
ALTER TABLE obligarth.privilege_grants ADD CONSTRAINT privilege_grants_cause_check
  CHECK (cause IS NULL OR cause IN ('reactivated', 'credentials_reset', 'capability_set', 'capability_team'));

-- 2. The destructive device capabilities: those a guarded action asks of its requester on each target
--    (erase, removal from management, lock, lost mode). A guarded action added later with another capability
--    extends this list by a migration (the bench compares it with the registered actions).
CREATE FUNCTION obligarth_private.guard_destructive_device_caps() RETURNS text[]
  LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT ARRAY['mdm:lock', 'mdm:lost_mode', 'mdm:remove', 'mdm:wipe']
$$;

-- The destructive capabilities among those of a team row (a jsonb array of names; anything else: none).
CREATE FUNCTION obligarth_private.guard_destructive_caps_of(p_caps jsonb) RETURNS text[]
  LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT COALESCE(array_agg(DISTINCT c.cap ORDER BY c.cap), ARRAY[]::text[])
    FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_caps) = 'array' THEN p_caps ELSE '[]'::jsonb END) AS c(cap)
   WHERE c.cap = ANY (obligarth_private.guard_destructive_device_caps())
$$;

-- 3. The grants. VOLATILE (the default): each query below sees what the calling statement wrote so far.
CREATE FUNCTION obligarth_private.record_team_capability_grant() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_caps text[];
BEGIN
  IF TG_TABLE_NAME = 'team_permissions' THEN
    -- A row that gains a destructive capability: its members who did not hold it in the tenant already (through
    -- another row of this team, or another team).
    v_caps := obligarth_private.guard_destructive_caps_of(NEW.capabilities);
    IF TG_OP = 'UPDATE' AND NEW.team_id IS NOT DISTINCT FROM OLD.team_id AND NEW.tenant_id IS NOT DISTINCT FROM OLD.tenant_id THEN
      v_caps := ARRAY(SELECT g.cap FROM unnest(v_caps) AS g(cap)
                       WHERE NOT (g.cap = ANY (obligarth_private.guard_destructive_caps_of(OLD.capabilities))));
    END IF;
    IF cardinality(v_caps) > 0 THEN
      INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source, cause)
      SELECT m.user_id, NEW.tenant_id, 'tenant_admin', 'change', 'capability_team'
        FROM obligarth.team_memberships m
        JOIN obligarth.users u ON u.id = m.user_id
       WHERE m.team_id = NEW.team_id AND m.tenant_id = NEW.tenant_id
         AND u.role IS DISTINCT FROM 'admin'
         AND EXISTS (SELECT 1 FROM unnest(v_caps) AS g(cap)
                      WHERE NOT EXISTS (SELECT 1 FROM obligarth.team_memberships m2
                                          JOIN obligarth.team_permissions p2 ON p2.team_id = m2.team_id AND p2.tenant_id = m2.tenant_id
                                         WHERE m2.tenant_id = NEW.tenant_id AND m2.user_id = m.user_id
                                           AND p2.capabilities @> jsonb_build_array(g.cap)));
    END IF;
  ELSIF TG_TABLE_NAME = 'team_memberships' THEN
    -- An account that joins a team: a destructive capability of the team it did not hold in the tenant already.
    IF (TG_OP = 'INSERT' OR NEW.team_id IS DISTINCT FROM OLD.team_id OR NEW.user_id IS DISTINCT FROM OLD.user_id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id)
       AND NOT EXISTS (SELECT 1 FROM obligarth.users u WHERE u.id = NEW.user_id AND u.role = 'admin')
       AND EXISTS (SELECT 1 FROM obligarth.team_permissions p
                    CROSS JOIN LATERAL unnest(obligarth_private.guard_destructive_caps_of(p.capabilities)) AS g(cap)
                    WHERE p.team_id = NEW.team_id AND p.tenant_id = NEW.tenant_id
                      AND NOT EXISTS (SELECT 1 FROM obligarth.team_memberships m2
                                        JOIN obligarth.team_permissions p2 ON p2.team_id = m2.team_id AND p2.tenant_id = m2.tenant_id
                                       WHERE m2.tenant_id = NEW.tenant_id AND m2.user_id = NEW.user_id
                                         AND p2.capabilities @> jsonb_build_array(g.cap))) THEN
      INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source, cause)
      VALUES (NEW.user_id, NEW.tenant_id, 'tenant_admin', 'change', 'capability_team');
    END IF;
  ELSIF TG_TABLE_NAME = 'users' THEN
    -- An account reactivated: the destructive capabilities of its teams start again, as its privileged roles do.
    IF NEW.is_active AND NOT OLD.is_active AND NEW.role IS DISTINCT FROM 'admin' THEN
      INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source, cause)
      SELECT DISTINCT NEW.id, m.tenant_id, 'tenant_admin', 'change', 'reactivated'
        FROM obligarth.team_memberships m
        JOIN obligarth.team_permissions p ON p.team_id = m.team_id AND p.tenant_id = m.tenant_id
       WHERE m.user_id = NEW.id AND cardinality(obligarth_private.guard_destructive_caps_of(p.capabilities)) > 0;
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER team_permissions_capability_grant BEFORE INSERT OR UPDATE OF capabilities, team_id, tenant_id
  ON obligarth.team_permissions FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_team_capability_grant();
CREATE TRIGGER team_memberships_capability_grant BEFORE INSERT OR UPDATE OF team_id, user_id, tenant_id
  ON obligarth.team_memberships FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_team_capability_grant();
CREATE TRIGGER users_team_capability_grant AFTER UPDATE OF is_active ON obligarth.users
  FOR EACH ROW WHEN (NEW.is_active AND NOT OLD.is_active)
  EXECUTE FUNCTION obligarth_private.record_team_capability_grant();

-- 4. Privileges and registry
REVOKE ALL ON FUNCTION obligarth_private.guard_destructive_device_caps(), obligarth_private.guard_destructive_caps_of(jsonb),
  obligarth_private.record_team_capability_grant() FROM PUBLIC;
INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth_private.record_team_capability_grant', 'definer',
   'trigger: a destructive device capability received through a team, or kept by a reactivated account (cooldown)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the migration');
}
