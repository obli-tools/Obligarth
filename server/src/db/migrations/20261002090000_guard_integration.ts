import type { Knex } from 'knex';

// Integration of lot A (audit-durci, notes of the integration of lot A): the approval of D24 (a client approver
// for a batch of the MSP) could be bypassed by the MSP alone, in three ways; each is now closed by the database,
// whatever the path (console, approval, SSO synchronisation, script).
//   I. Client permission sets (D24, D42 option 1): a set of audience 'client' held devices.manage once a
//      platform administrator added it (PUT /api/permission-sets/:id); every account of that role became a
//      requester of the client side, whose batch any approver or platform administrator approves: one MSP
//      account created such an account and approved its batch itself. A client set now holds only
//      approvals.review and audit.read (CHECK permission_sets_client_capabilities).
//  II. Privileges that start a 72-hour cooldown (review of lot A7, AUD-A7-R5; and the take-over of an
//      approver's account): besides the grants of guard_foundation, privilege_grants records (column cause)
//      the reactivation of a privileged account, a role whose set holds devices.manage (or a set that gains
//      it), and a change of the password, the second factor or the SSO identity of a designated approver or
//      of a platform administrator by another account than its holder (the MSP reset the factors of the
//      client approver, signed in in its name and approved its own batch).
// III. The loss of a client approver (review of lot A7, AUD-A7-R4). The MSP could remove the client approvers
//      of a tenant on its own (immediate revocation, deactivation of the account, change or removal of its
//      role in the tenant, deletion of the account, promotion to platform administrator), then go through
//      the fallback of D24 at once: two MSP accounts lifted a freeze set by the client, or had a batch
//      approved. Now:
//   - every loss of an active client approver (designation on the client side, active account that is not a
//     platform administrator, role of audience 'client' in the tenant) is recorded here by triggers, with
//     its cause, the actor of the context, whether it was the approver's own act (a revocation by the
//     approver themself) and the number of client approvers left;
//   - the server reads the losses of a tenant (context of that tenant): while a loss that the approver did
//     not decide is less than GUARD_FALLBACK_HOLD_DAYS old (shared/src/guard.ts), the fallback stays closed
//     (requests that need a client approver are refused, 409 approverFallbackHeld);
//   - the job actions.privilege-watch (context identity) writes guard.approver_lost in the tenant's chain and
//     alerts the tenant and the master tenant, once per loss (alerted_at), even after a stop of the server;
//   - the runtime role reads the losses of its tenant, or all of them in the context identity, and only
//     marks alerted_at (identity); it never inserts or deletes a row (triggers and the purge only);
//     guard_purge() also purges the losses after 13 months.
// Runs as obligarth_owner (server-migrate), after guard_foundation and guard_definer_review, in every admitted
// order (applied last, like any migration an order does not name: essai 121); ends with
// obligarth.rls_assert_clean(). The SQL holds no question mark (knex.raw would bind it) and no backslash;
// it is kept verbatim by String.raw.
const UP = String.raw`-- =============================================================================
-- Integration of lot A: the approval of D24 out of reach of the MSP alone (client sets, cooldown of new
-- privileges, loss of a client approver). Run as obligarth_owner, in one transaction.
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.tenant_approvers') IS NULL OR to_regprocedure('obligarth.guard_purge()') IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'obligarth.permission_sets'::regclass AND attname = 'audience') THEN
    RAISE EXCEPTION 'guard_integration: apply audit_hardening and guard_foundation first';
  END IF;
END $$;

-- I.1 A client permission set holds no operational capability (D24, D42 option 1: approver and auditor)
ALTER TABLE obligarth.permission_sets ADD CONSTRAINT permission_sets_client_capabilities
  CHECK (audience <> 'client' OR capabilities <@ '["approvals.review", "audit.read"]'::jsonb);

-- II.1 Cause of a grant: NULL for those of guard_foundation (promotion, administrator role, designation)
ALTER TABLE obligarth.privilege_grants ADD COLUMN cause varchar(24)
  CHECK (cause IS NULL OR cause IN ('reactivated', 'credentials_reset', 'capability_set'));

-- II.2 A role that grants a destructive capability (the capability the guarded actions ask of a requester;
-- 'admin' is the tenant administrator, recorded by record_privilege_grant).
CREATE FUNCTION obligarth_private.guard_destructive_role(p_role text) RETURNS boolean
  LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM obligarth.permission_sets ps
                  WHERE ps.slug = (CASE WHEN p_role = 'member' THEN 'user' ELSE p_role END)
                    AND ps.capabilities @> '["devices.manage"]'::jsonb)
$$;

CREATE FUNCTION obligarth_private.record_privilege_change() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_TABLE_NAME = 'users' THEN
    -- A privileged account reactivated: its privileges start again (AUD-A7-R5).
    IF NEW.is_active AND NOT OLD.is_active THEN
      IF NEW.role = 'admin' THEN
        INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source, cause)
        VALUES (NEW.id, NULL, 'platform_admin', 'change', 'reactivated');
      END IF;
      INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source, cause)
        SELECT NEW.id, ut.tenant_id, 'tenant_admin', 'change', 'reactivated' FROM obligarth.user_tenants ut
         WHERE ut.user_id = NEW.id AND (ut.role = 'admin' OR obligarth_private.guard_destructive_role(ut.role));
      INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source, cause)
        SELECT NEW.id, ta.tenant_id, 'approver', 'change', 'reactivated' FROM obligarth.tenant_approvers ta
         WHERE ta.user_id = NEW.id AND ta.revoked_at IS NULL;
    END IF;
    -- The password, the second factor or the SSO identity of a designated approver, or of a platform
    -- administrator, changed by another account than its holder (a vault reseal of the TOTP secret does not
    -- bump credential_version): one MSP account could otherwise sign in in the name of a second person.
    IF (NEW.password_hash IS DISTINCT FROM OLD.password_hash OR NEW.totp_enabled IS DISTINCT FROM OLD.totp_enabled
        OR NEW.foreign_source IS DISTINCT FROM OLD.foreign_source OR NEW.foreign_id IS DISTINCT FROM OLD.foreign_id
        OR (NEW.totp_secret_enc IS DISTINCT FROM OLD.totp_secret_enc
            AND NEW.credential_version IS DISTINCT FROM OLD.credential_version))
       AND obligarth.ctx_actor_user() IS DISTINCT FROM NEW.id THEN
      IF NEW.role = 'admin' THEN
        INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source, cause)
        VALUES (NEW.id, NULL, 'platform_admin', 'change', 'credentials_reset');
      END IF;
      INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source, cause)
        SELECT NEW.id, ta.tenant_id, 'approver', 'change', 'credentials_reset' FROM obligarth.tenant_approvers ta
         WHERE ta.user_id = NEW.id AND ta.revoked_at IS NULL;
    END IF;
  ELSIF TG_TABLE_NAME = 'user_tenants' THEN
    -- A role whose set holds a destructive capability, given to an account that had none in the tenant.
    IF NEW.role IS DISTINCT FROM 'admin' AND obligarth_private.guard_destructive_role(NEW.role)
       AND (TG_OP = 'INSERT' OR NOT (OLD.role = 'admin' OR obligarth_private.guard_destructive_role(OLD.role))) THEN
      INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source, cause)
      VALUES (NEW.user_id, NEW.tenant_id, 'tenant_admin', 'change', 'capability_set');
    END IF;
  ELSIF TG_TABLE_NAME = 'permission_sets' THEN
    -- A set that gains a destructive capability: every holder of that role (but the administrators).
    IF NEW.capabilities @> '["devices.manage"]'::jsonb AND NOT (OLD.capabilities @> '["devices.manage"]'::jsonb) THEN
      INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source, cause)
        SELECT ut.user_id, ut.tenant_id, 'tenant_admin', 'change', 'capability_set' FROM obligarth.user_tenants ut
         WHERE (CASE WHEN ut.role = 'member' THEN 'user' ELSE ut.role END) = NEW.slug AND ut.role IS DISTINCT FROM 'admin';
    END IF;
  END IF;
  RETURN NULL;
END $$;

CREATE TRIGGER users_privilege_change AFTER UPDATE ON obligarth.users
  FOR EACH ROW WHEN (OLD.credential_version IS DISTINCT FROM NEW.credential_version)
  EXECUTE FUNCTION obligarth_private.record_privilege_change();
CREATE TRIGGER user_tenants_privilege_change AFTER INSERT OR UPDATE OF role ON obligarth.user_tenants
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_privilege_change();
CREATE TRIGGER permission_sets_privilege_change AFTER UPDATE OF capabilities ON obligarth.permission_sets
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_privilege_change();

-- III.1 Losses of a client approver
CREATE TABLE obligarth.guard_approver_losses (
  id          bigserial    PRIMARY KEY,
  tenant_id   integer      NOT NULL REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  user_id     integer      NOT NULL,
  cause       varchar(24)  NOT NULL CHECK (cause IN ('revoked', 'deactivated', 'platform_admin', 'role_changed',
                                                     'removed', 'deleted', 'audience_changed')),
  actor       varchar(200),                    -- obligarth.ctx_actor() of the change (NULL: no context)
  self        boolean      NOT NULL,           -- the approver revoked their own designation
  remaining   integer      NOT NULL,           -- active client approvers left in the tenant
  lost_at     timestamptz  NOT NULL DEFAULT now(),
  alerted_at  timestamptz                      -- set by actions.privilege-watch (entry and alerts written)
);
CREATE INDEX guard_approver_losses_tenant ON obligarth.guard_approver_losses (tenant_id, lost_at DESC);
CREATE INDEX guard_approver_losses_unalerted ON obligarth.guard_approver_losses (lost_at) WHERE alerted_at IS NULL;

-- III.2 Detection. A role of audience 'client' (the stored slug 'member' is the set 'user').
CREATE FUNCTION obligarth_private.guard_client_role(p_role text) RETURNS boolean
  LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM obligarth.permission_sets ps
                  WHERE ps.slug = (CASE WHEN p_role = 'member' THEN 'user' ELSE p_role END) AND ps.audience = 'client')
$$;

-- Active client approvers of a tenant other than p_except (guard/people.ts activeClientApprovers).
CREATE FUNCTION obligarth_private.guard_client_approvers(p_tenant integer, p_except integer) RETURNS integer
  LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT count(DISTINCT ta.user_id)::integer
    FROM obligarth.tenant_approvers ta
    JOIN obligarth.users u ON u.id = ta.user_id
    JOIN obligarth.user_tenants ut ON ut.user_id = ta.user_id AND ut.tenant_id = ta.tenant_id
   WHERE ta.tenant_id = p_tenant AND ta.side = 'client' AND ta.revoked_at IS NULL
     AND ta.user_id IS DISTINCT FROM p_except
     AND u.is_active AND u.role IS DISTINCT FROM 'admin'
     AND obligarth_private.guard_client_role(ut.role)
$$;

-- One loss (nothing while the tenant itself is being deleted).
CREATE FUNCTION obligarth_private.guard_note_loss(p_tenant integer, p_user integer, p_cause text, p_self boolean)
  RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM obligarth.tenants t WHERE t.id = p_tenant) THEN
    RETURN;
  END IF;
  INSERT INTO obligarth.guard_approver_losses (tenant_id, user_id, cause, actor, self, remaining)
  VALUES (p_tenant, p_user, p_cause, left(obligarth.ctx_actor(), 200), COALESCE(p_self, false),
          obligarth_private.guard_client_approvers(p_tenant, p_user));
END $$;

-- The trigger: what was an active client approver before the change and is not any more.
CREATE FUNCTION obligarth_private.record_approver_loss() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r record;
BEGIN
  IF TG_TABLE_NAME = 'tenant_approvers' THEN
    -- A client designation revoked (UPDATE), or removed (DELETE: never by the runtime role, which has no
    -- DELETE; a deletion of the account is recorded before its cascade, by users_approver_loss).
    IF OLD.side = 'client' AND OLD.revoked_at IS NULL
       AND (TG_OP = 'DELETE' OR NEW.revoked_at IS NOT NULL)
       AND EXISTS (SELECT 1 FROM obligarth.users u
                     JOIN obligarth.user_tenants ut ON ut.user_id = u.id AND ut.tenant_id = OLD.tenant_id
                    WHERE u.id = OLD.user_id AND u.is_active AND u.role IS DISTINCT FROM 'admin'
                      AND obligarth_private.guard_client_role(ut.role)) THEN
      PERFORM obligarth_private.guard_note_loss(OLD.tenant_id, OLD.user_id,
        CASE WHEN TG_OP = 'DELETE' THEN 'deleted' ELSE 'revoked' END,
        TG_OP = 'UPDATE' AND NEW.revoked_by IS NOT DISTINCT FROM NEW.user_id
          AND obligarth.ctx_actor_user() IS NOT DISTINCT FROM NEW.user_id);
    END IF;
  ELSIF TG_TABLE_NAME = 'users' THEN
    IF TG_OP = 'DELETE' THEN
      -- BEFORE DELETE: memberships and designations are still there (their cascade follows).
      IF OLD.is_active AND OLD.role IS DISTINCT FROM 'admin' THEN
        FOR r IN SELECT ta.tenant_id FROM obligarth.tenant_approvers ta
                   JOIN obligarth.user_tenants ut ON ut.user_id = ta.user_id AND ut.tenant_id = ta.tenant_id
                  WHERE ta.user_id = OLD.id AND ta.side = 'client' AND ta.revoked_at IS NULL
                    AND obligarth_private.guard_client_role(ut.role) LOOP
          PERFORM obligarth_private.guard_note_loss(r.tenant_id, OLD.id, 'deleted', false);
        END LOOP;
      END IF;
      RETURN OLD;
    END IF;
    IF OLD.is_active AND OLD.role IS DISTINCT FROM 'admin'
       AND NOT (NEW.is_active AND NEW.role IS DISTINCT FROM 'admin') THEN
      FOR r IN SELECT ta.tenant_id FROM obligarth.tenant_approvers ta
                 JOIN obligarth.user_tenants ut ON ut.user_id = ta.user_id AND ut.tenant_id = ta.tenant_id
                WHERE ta.user_id = NEW.id AND ta.side = 'client' AND ta.revoked_at IS NULL
                  AND obligarth_private.guard_client_role(ut.role) LOOP
        PERFORM obligarth_private.guard_note_loss(r.tenant_id, NEW.id,
          CASE WHEN NOT NEW.is_active THEN 'deactivated' ELSE 'platform_admin' END, false);
      END LOOP;
    END IF;
  ELSIF TG_TABLE_NAME = 'user_tenants' THEN
    -- A client role changed for another one, or the membership removed (a cascade from the account or the
    -- tenant finds them gone: nothing recorded twice, nothing for a deleted tenant).
    IF obligarth_private.guard_client_role(OLD.role)
       AND (TG_OP = 'DELETE' OR NOT obligarth_private.guard_client_role(NEW.role)
            OR NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id)
       AND EXISTS (SELECT 1 FROM obligarth.tenant_approvers ta
                    WHERE ta.tenant_id = OLD.tenant_id AND ta.user_id = OLD.user_id AND ta.side = 'client'
                      AND ta.revoked_at IS NULL)
       AND EXISTS (SELECT 1 FROM obligarth.users u
                    WHERE u.id = OLD.user_id AND u.is_active AND u.role IS DISTINCT FROM 'admin') THEN
      PERFORM obligarth_private.guard_note_loss(OLD.tenant_id, OLD.user_id,
        CASE WHEN TG_OP = 'DELETE' THEN 'removed' ELSE 'role_changed' END, false);
    END IF;
  ELSIF TG_TABLE_NAME = 'permission_sets' THEN
    -- A client set that leaves the audience 'client', is renamed or deleted: its holders stop counting.
    IF OLD.audience = 'client'
       AND (TG_OP = 'DELETE' OR NEW.audience IS DISTINCT FROM 'client' OR NEW.slug IS DISTINCT FROM OLD.slug) THEN
      FOR r IN SELECT ta.tenant_id, ta.user_id FROM obligarth.tenant_approvers ta
                 JOIN obligarth.users u ON u.id = ta.user_id
                 JOIN obligarth.user_tenants ut ON ut.user_id = ta.user_id AND ut.tenant_id = ta.tenant_id
                WHERE ta.side = 'client' AND ta.revoked_at IS NULL AND u.is_active AND u.role IS DISTINCT FROM 'admin'
                  AND (CASE WHEN ut.role = 'member' THEN 'user' ELSE ut.role END) = OLD.slug LOOP
        PERFORM obligarth_private.guard_note_loss(r.tenant_id, r.user_id, 'audience_changed', false);
      END LOOP;
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER tenant_approvers_approver_loss AFTER UPDATE OF revoked_at OR DELETE ON obligarth.tenant_approvers
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_approver_loss();
CREATE TRIGGER users_approver_loss AFTER UPDATE OF is_active, role ON obligarth.users
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_approver_loss();
CREATE TRIGGER users_approver_loss_delete BEFORE DELETE ON obligarth.users
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_approver_loss();
CREATE TRIGGER user_tenants_approver_loss AFTER UPDATE OF role, user_id, tenant_id OR DELETE ON obligarth.user_tenants
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_approver_loss();
CREATE TRIGGER permission_sets_approver_loss AFTER UPDATE OF audience, slug OR DELETE ON obligarth.permission_sets
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_approver_loss();

-- III.3 Housekeeping (job actions.purge): the losses too after 13 months (counted with the grants)
CREATE OR REPLACE FUNCTION obligarth.guard_purge()
  RETURNS TABLE (actions bigint, grants bigint)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_actions bigint;
  v_grants  bigint;
  v_losses  bigint;
BEGIN
  IF session_user = 'obligarth' AND obligarth.ctx_actor() IS DISTINCT FROM 'j:actions.purge' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'guard_purge: reserved to the actions.purge job';
  END IF;
  DELETE FROM obligarth.pending_actions a
   WHERE a.state IN ('done', 'partial', 'cancelled', 'refused', 'failed', 'expired')
     AND a.updated_at < now() - interval '13 months';
  GET DIAGNOSTICS v_actions = ROW_COUNT;
  DELETE FROM obligarth.privilege_grants g WHERE g.granted_at < now() - interval '13 months';
  GET DIAGNOSTICS v_grants = ROW_COUNT;
  DELETE FROM obligarth.guard_approver_losses l WHERE l.lost_at < now() - interval '13 months';
  GET DIAGNOSTICS v_losses = ROW_COUNT;
  RETURN QUERY SELECT v_actions, v_grants + v_losses;
END $$;

-- III.4 Classification and privileges: read in the tenant's context or in identity; alerted_at marked in
-- identity; never inserted, updated otherwise or deleted by the runtime role.
SELECT obligarth_private.rls_apply('obligarth.guard_approver_losses', 'custom',
  'written by record_approver_loss only; read in the tenant''s context or identity; alerted_at marked in identity');
REVOKE ALL ON SEQUENCE obligarth.guard_approver_losses_id_seq FROM obligarth, obligarth_reader;
CREATE POLICY rls_tenant_read ON obligarth.guard_approver_losses FOR SELECT TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_identity_read ON obligarth.guard_approver_losses FOR SELECT TO obligarth
  USING ((SELECT obligarth.ctx_kind()) = 'identity');
CREATE POLICY rls_identity_mark ON obligarth.guard_approver_losses FOR UPDATE TO obligarth
  USING ((SELECT obligarth.ctx_kind()) = 'identity') WITH CHECK ((SELECT obligarth.ctx_kind()) = 'identity');
GRANT SELECT ON obligarth.guard_approver_losses TO obligarth;
GRANT UPDATE (alerted_at) ON obligarth.guard_approver_losses TO obligarth;

REVOKE ALL ON FUNCTION obligarth_private.guard_destructive_role(text), obligarth_private.record_privilege_change(),
  obligarth_private.guard_client_role(text), obligarth_private.guard_client_approvers(integer, integer),
  obligarth_private.guard_note_loss(integer, integer, text, boolean), obligarth_private.record_approver_loss() FROM PUBLIC;
INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth_private.record_approver_loss', 'definer', 'trigger: records the loss of a client approver (AUD-A7-R4)'),
  ('function', 'obligarth_private.record_privilege_change', 'definer', 'trigger: reactivation, destructive capability, approver credentials changed by another (cooldown)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;
UPDATE obligarth_private.rls_registry
   SET note = 'actions.purge job: finished actions, grants and approver losses after 13 months'
 WHERE object_kind = 'function' AND object_name = 'obligarth.guard_purge';

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the migration');
}
