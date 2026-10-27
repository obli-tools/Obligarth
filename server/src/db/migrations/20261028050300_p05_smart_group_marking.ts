import type { Knex } from 'knex';

// =============================================================================
// Marking of the dynamic groups (P0-5 T5, M2 of the spec, §3 and §4.3; D9)
// =============================================================================
// The triggers that write obligarth.smart_group_dirty: a device whose membership of the dynamic groups of its tenant is
// to be computed again, with the union of its reasons. A reason is a family of marking of the rule language
// (shared DIRTY_FAMILIES: what changed) or 'new' (a device created, or entering or leaving management: D9, every
// group computes it again). The queue mdm.groups.evaluate (server/src/mdm/groups/evaluate.ts) reads them by slices
// and computes again the groups whose families (smart_groups.rule_fields) meet the reasons. The triggers guarantee no
// device is forgotten; the server only wakes the queue (requestGroupEvaluation) and the hourly schedule empties what
// a wake missed.
//   - devices: AFTER INSERT ('new'); AFTER UPDATE OF the columns the catalog reads, the reasons by family, comparing
//     OLD and NEW:
//       facts     platform, os_version (os_version_num follows it), model, model_name, display_name and device_name
//                 (with model_name and model, the label: field name), serial_number, ownership, management_mode,
//                 management_channel, enrollment_type, supervised, usage, enrollment_state, lifecycle_status,
//                 warranty_status, storage_capacity_bytes;
//       tags      tags;  custom  custom_fields;  user  end_user_id;  group  group_id;
//       derived   compliance_state, config_state;
//       apps      ownership, management_mode, management_channel too: the key of the privacy rules of the device,
//                 which decide which applications a rule sees (P0-13, compile.ts APP_GATE_ALL_SQL);
//       new       enrollment_state entering or leaving 'unenrolled' (D9: in or out of every group).
//     Never last_checkin_at nor storage_available_bytes; the temporal fields (last_checkin, enrolled_at) are computed
//     again by the schedule, never by the marking (shared rules.ts).
//   - end_users: AFTER UPDATE OF email, external_id, status: the devices of the end user under management ('user').
//     An end user deleted sets the devices' end_user_id to NULL: marked by the devices' trigger.
//   - android_devices (api_level, security_patch_level) and legacy_agent_devices (api_level, security_patch): AFTER
//     INSERT (a value given) and AFTER UPDATE OF them ('android').
//   - device_apps: AFTER INSERT and AFTER DELETE at the statement level with their transition table, AFTER UPDATE OF
//     identifier, version, short_version, managed per row ('apps'); only while a group of the tenant reads the
//     applications.
//   - device_group_closure: AFTER INSERT and AFTER DELETE at the statement level (a static group moved in the tree):
//     the devices of the groups whose ancestry changed ('group').
// Each trigger does nothing while no dynamic group of the tenant (that is not in error) reads the reasons it would
// write: a first EXISTS on the groups the caller's RLS shows, ≤ 200 rows of the tenant. The devices out of management
// are never marked by the satellites (never members, D9). The writes are INSERT … ON CONFLICT DO UPDATE with the union
// of the reasons (nothing written when the row already holds them; queued_at kept: the oldest first). The functions
// run as invoker (the runtime role, in the tenant's context of the write: RLS applies to smart_group_dirty as to the
// row written), in obligarth_private, EXECUTE revoked from PUBLIC.
// A device deleted takes its markings with it (smart_group_dirty_device_fk ON DELETE CASCADE); the statement triggers
// of device_apps and of the closure mark only the devices that still exist (a cascade from a device deleted).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last.
// Runs as obligarth_owner (server-migrate), after p05_smart_groups.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Marking of the dynamic groups (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.smart_group_dirty') IS NULL
     OR to_regclass('obligarth.legacy_agent_devices') IS NULL
     OR to_regclass('obligarth.android_devices') IS NULL THEN
    RAISE EXCEPTION 'p05_smart_group_marking: apply p05_smart_groups, android_devices and legacy_agent first';
  END IF;
END $$;

-- 1. devices -----------------------------------------------------------------------------
CREATE FUNCTION obligarth_private.smart_group_mark_device() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_reasons text[] := '{}';
BEGIN
  IF TG_OP = 'INSERT' OR (OLD.enrollment_state = 'unenrolled') <> (NEW.enrollment_state = 'unenrolled') THEN
    v_reasons := ARRAY['new'];
  ELSE
    IF ROW(OLD.platform, OLD.os_version, OLD.model, OLD.model_name, OLD.display_name, OLD.device_name, OLD.serial_number,
           OLD.ownership, OLD.management_mode, OLD.management_channel, OLD.enrollment_type, OLD.supervised, OLD.usage,
           OLD.enrollment_state, OLD.lifecycle_status, OLD.warranty_status, OLD.storage_capacity_bytes)
       IS DISTINCT FROM
       ROW(NEW.platform, NEW.os_version, NEW.model, NEW.model_name, NEW.display_name, NEW.device_name, NEW.serial_number,
           NEW.ownership, NEW.management_mode, NEW.management_channel, NEW.enrollment_type, NEW.supervised, NEW.usage,
           NEW.enrollment_state, NEW.lifecycle_status, NEW.warranty_status, NEW.storage_capacity_bytes) THEN
      v_reasons := v_reasons || 'facts'::text;
    END IF;
    IF OLD.tags IS DISTINCT FROM NEW.tags THEN v_reasons := v_reasons || 'tags'::text; END IF;
    IF OLD.custom_fields IS DISTINCT FROM NEW.custom_fields THEN v_reasons := v_reasons || 'custom'::text; END IF;
    IF OLD.end_user_id IS DISTINCT FROM NEW.end_user_id THEN v_reasons := v_reasons || 'user'::text; END IF;
    IF OLD.group_id IS DISTINCT FROM NEW.group_id THEN v_reasons := v_reasons || 'group'::text; END IF;
    IF ROW(OLD.compliance_state, OLD.config_state) IS DISTINCT FROM ROW(NEW.compliance_state, NEW.config_state) THEN
      v_reasons := v_reasons || 'derived'::text;
    END IF;
    -- The key of the privacy rules of the device: which of its applications a rule sees.
    IF ROW(OLD.ownership, OLD.management_mode, OLD.management_channel)
       IS DISTINCT FROM ROW(NEW.ownership, NEW.management_mode, NEW.management_channel) THEN
      v_reasons := v_reasons || 'apps'::text;
    END IF;
    IF cardinality(v_reasons) = 0 THEN RETURN NULL; END IF;
  END IF;
  -- One statement: written only while a group of the tenant (not in error) reads one of the reasons.
  INSERT INTO obligarth.smart_group_dirty AS d (tenant_id, device_id, reasons)
  SELECT NEW.tenant_id, NEW.id, v_reasons
   WHERE EXISTS (SELECT 1 FROM obligarth.smart_groups g
                 WHERE g.tenant_id = NEW.tenant_id AND g.state <> 'error'
                   AND (v_reasons = ARRAY['new'] OR g.rule_fields && v_reasons))
  ON CONFLICT (tenant_id, device_id) DO UPDATE
    SET reasons = ARRAY(SELECT DISTINCT r FROM unnest(d.reasons || EXCLUDED.reasons) AS u(r) ORDER BY r)
    WHERE NOT d.reasons @> EXCLUDED.reasons;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.smart_group_mark_device() FROM PUBLIC;

CREATE TRIGGER devices_smart_group_new AFTER INSERT ON obligarth.devices
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.smart_group_mark_device();
CREATE TRIGGER devices_smart_group_mark AFTER UPDATE OF
    platform, os_version, model, model_name, display_name, device_name, serial_number, ownership, management_mode,
    management_channel, enrollment_type, supervised, usage, enrollment_state, lifecycle_status, warranty_status,
    storage_capacity_bytes, tags, custom_fields, end_user_id, group_id, compliance_state, config_state
  ON obligarth.devices
  FOR EACH ROW WHEN (
    ROW(OLD.platform, OLD.os_version, OLD.model, OLD.model_name, OLD.display_name, OLD.device_name, OLD.serial_number,
        OLD.ownership, OLD.management_mode, OLD.management_channel, OLD.enrollment_type, OLD.supervised, OLD.usage,
        OLD.enrollment_state, OLD.lifecycle_status, OLD.warranty_status, OLD.storage_capacity_bytes, OLD.tags,
        OLD.custom_fields, OLD.end_user_id, OLD.group_id, OLD.compliance_state, OLD.config_state)
    IS DISTINCT FROM
    ROW(NEW.platform, NEW.os_version, NEW.model, NEW.model_name, NEW.display_name, NEW.device_name, NEW.serial_number,
        NEW.ownership, NEW.management_mode, NEW.management_channel, NEW.enrollment_type, NEW.supervised, NEW.usage,
        NEW.enrollment_state, NEW.lifecycle_status, NEW.warranty_status, NEW.storage_capacity_bytes, NEW.tags,
        NEW.custom_fields, NEW.end_user_id, NEW.group_id, NEW.compliance_state, NEW.config_state))
  EXECUTE FUNCTION obligarth_private.smart_group_mark_device();

-- 2. end_users ---------------------------------------------------------------------------
CREATE FUNCTION obligarth_private.smart_group_mark_end_user() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM obligarth.smart_groups g
                 WHERE g.tenant_id = NEW.tenant_id AND g.state <> 'error' AND 'user' = ANY (g.rule_fields)) THEN
    RETURN NULL;
  END IF;
  INSERT INTO obligarth.smart_group_dirty AS d (tenant_id, device_id, reasons)
  SELECT dv.tenant_id, dv.id, ARRAY['user']::text[] FROM obligarth.devices dv
   WHERE dv.tenant_id = NEW.tenant_id AND dv.end_user_id = NEW.id AND dv.enrollment_state <> 'unenrolled'
  ON CONFLICT (tenant_id, device_id) DO UPDATE
    SET reasons = ARRAY(SELECT DISTINCT r FROM unnest(d.reasons || EXCLUDED.reasons) AS u(r) ORDER BY r)
    WHERE NOT d.reasons @> EXCLUDED.reasons;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.smart_group_mark_end_user() FROM PUBLIC;

CREATE TRIGGER end_users_smart_group_mark AFTER UPDATE OF email, external_id, status ON obligarth.end_users
  FOR EACH ROW WHEN (ROW(OLD.email, OLD.external_id, OLD.status) IS DISTINCT FROM ROW(NEW.email, NEW.external_id, NEW.status))
  EXECUTE FUNCTION obligarth_private.smart_group_mark_end_user();

-- 3. android_devices, legacy_agent_devices -----------------------------------------------
CREATE FUNCTION obligarth_private.smart_group_mark_android() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM obligarth.smart_groups g
                 WHERE g.tenant_id = NEW.tenant_id AND g.state <> 'error' AND 'android' = ANY (g.rule_fields)) THEN
    RETURN NULL;
  END IF;
  INSERT INTO obligarth.smart_group_dirty AS d (tenant_id, device_id, reasons)
  SELECT dv.tenant_id, dv.id, ARRAY['android']::text[] FROM obligarth.devices dv
   WHERE dv.tenant_id = NEW.tenant_id AND dv.id = NEW.device_id AND dv.enrollment_state <> 'unenrolled'
  ON CONFLICT (tenant_id, device_id) DO UPDATE
    SET reasons = ARRAY(SELECT DISTINCT r FROM unnest(d.reasons || EXCLUDED.reasons) AS u(r) ORDER BY r)
    WHERE NOT d.reasons @> EXCLUDED.reasons;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.smart_group_mark_android() FROM PUBLIC;

CREATE TRIGGER android_devices_smart_group_new AFTER INSERT ON obligarth.android_devices
  FOR EACH ROW WHEN (NEW.api_level IS NOT NULL OR NEW.security_patch_level IS NOT NULL)
  EXECUTE FUNCTION obligarth_private.smart_group_mark_android();
CREATE TRIGGER android_devices_smart_group_mark AFTER UPDATE OF api_level, security_patch_level ON obligarth.android_devices
  FOR EACH ROW WHEN (ROW(OLD.api_level, OLD.security_patch_level) IS DISTINCT FROM ROW(NEW.api_level, NEW.security_patch_level))
  EXECUTE FUNCTION obligarth_private.smart_group_mark_android();
CREATE TRIGGER legacy_agent_devices_smart_group_new AFTER INSERT ON obligarth.legacy_agent_devices
  FOR EACH ROW WHEN (NEW.api_level IS NOT NULL OR NEW.security_patch IS NOT NULL)
  EXECUTE FUNCTION obligarth_private.smart_group_mark_android();
CREATE TRIGGER legacy_agent_devices_smart_group_mark AFTER UPDATE OF api_level, security_patch ON obligarth.legacy_agent_devices
  FOR EACH ROW WHEN (ROW(OLD.api_level, OLD.security_patch) IS DISTINCT FROM ROW(NEW.api_level, NEW.security_patch))
  EXECUTE FUNCTION obligarth_private.smart_group_mark_android();

-- 4. device_apps -------------------------------------------------------------------------
-- Statement level (INSERT, DELETE: the transition table smart_group_apps), row level (UPDATE of what a rule compares).
CREATE FUNCTION obligarth_private.smart_group_mark_apps() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  -- The groups the caller sees (its tenant's): nothing to do while none reads the applications.
  IF NOT EXISTS (SELECT 1 FROM obligarth.smart_groups g WHERE g.state <> 'error' AND 'apps' = ANY (g.rule_fields)) THEN
    RETURN NULL;
  END IF;
  IF TG_LEVEL = 'ROW' THEN
    INSERT INTO obligarth.smart_group_dirty AS d (tenant_id, device_id, reasons)
    SELECT dv.tenant_id, dv.id, ARRAY['apps']::text[] FROM obligarth.devices dv
     WHERE dv.tenant_id = NEW.tenant_id AND dv.id = NEW.device_id AND dv.enrollment_state <> 'unenrolled'
       AND EXISTS (SELECT 1 FROM obligarth.smart_groups g
                   WHERE g.tenant_id = dv.tenant_id AND g.state <> 'error' AND 'apps' = ANY (g.rule_fields))
    ON CONFLICT (tenant_id, device_id) DO UPDATE
      SET reasons = ARRAY(SELECT DISTINCT r FROM unnest(d.reasons || EXCLUDED.reasons) AS u(r) ORDER BY r)
      WHERE NOT d.reasons @> EXCLUDED.reasons;
  ELSE
    INSERT INTO obligarth.smart_group_dirty AS d (tenant_id, device_id, reasons)
    SELECT dv.tenant_id, dv.id, ARRAY['apps']::text[]
      FROM (SELECT DISTINCT a.tenant_id, a.device_id FROM smart_group_apps a) c
      JOIN obligarth.devices dv ON dv.tenant_id = c.tenant_id AND dv.id = c.device_id
     WHERE dv.enrollment_state <> 'unenrolled'
       AND EXISTS (SELECT 1 FROM obligarth.smart_groups g
                   WHERE g.tenant_id = dv.tenant_id AND g.state <> 'error' AND 'apps' = ANY (g.rule_fields))
    ON CONFLICT (tenant_id, device_id) DO UPDATE
      SET reasons = ARRAY(SELECT DISTINCT r FROM unnest(d.reasons || EXCLUDED.reasons) AS u(r) ORDER BY r)
      WHERE NOT d.reasons @> EXCLUDED.reasons;
  END IF;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.smart_group_mark_apps() FROM PUBLIC;

CREATE TRIGGER device_apps_smart_group_insert AFTER INSERT ON obligarth.device_apps
  REFERENCING NEW TABLE AS smart_group_apps
  FOR EACH STATEMENT EXECUTE FUNCTION obligarth_private.smart_group_mark_apps();
CREATE TRIGGER device_apps_smart_group_delete AFTER DELETE ON obligarth.device_apps
  REFERENCING OLD TABLE AS smart_group_apps
  FOR EACH STATEMENT EXECUTE FUNCTION obligarth_private.smart_group_mark_apps();
CREATE TRIGGER device_apps_smart_group_update AFTER UPDATE OF identifier, version, short_version, managed ON obligarth.device_apps
  FOR EACH ROW WHEN (ROW(OLD.identifier, OLD.version, OLD.short_version, OLD.managed)
                     IS DISTINCT FROM ROW(NEW.identifier, NEW.version, NEW.short_version, NEW.managed))
  EXECUTE FUNCTION obligarth_private.smart_group_mark_apps();

-- 5. device_group_closure ----------------------------------------------------------------
-- A static group moved in the tree (services/group.service.ts move): the ancestry of the devices of its subtree.
CREATE FUNCTION obligarth_private.smart_group_mark_closure() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM obligarth.smart_groups g WHERE g.state <> 'error' AND 'group' = ANY (g.rule_fields)) THEN
    RETURN NULL;
  END IF;
  INSERT INTO obligarth.smart_group_dirty AS d (tenant_id, device_id, reasons)
  SELECT DISTINCT dv.tenant_id, dv.id, ARRAY['group']::text[]
    FROM (SELECT DISTINCT c.tenant_id, c.descendant_id FROM smart_group_closure c) c
    JOIN obligarth.devices dv ON dv.tenant_id = c.tenant_id AND dv.group_id = c.descendant_id
   WHERE dv.enrollment_state <> 'unenrolled'
     AND EXISTS (SELECT 1 FROM obligarth.smart_groups g
                 WHERE g.tenant_id = dv.tenant_id AND g.state <> 'error' AND 'group' = ANY (g.rule_fields))
  ON CONFLICT (tenant_id, device_id) DO UPDATE
    SET reasons = ARRAY(SELECT DISTINCT r FROM unnest(d.reasons || EXCLUDED.reasons) AS u(r) ORDER BY r)
    WHERE NOT d.reasons @> EXCLUDED.reasons;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.smart_group_mark_closure() FROM PUBLIC;

CREATE TRIGGER device_group_closure_smart_group_insert AFTER INSERT ON obligarth.device_group_closure
  REFERENCING NEW TABLE AS smart_group_closure
  FOR EACH STATEMENT EXECUTE FUNCTION obligarth_private.smart_group_mark_closure();
CREATE TRIGGER device_group_closure_smart_group_delete AFTER DELETE ON obligarth.device_group_closure
  REFERENCING OLD TABLE AS smart_group_closure
  FOR EACH STATEMENT EXECUTE FUNCTION obligarth_private.smart_group_mark_closure();

-- 6. The queue reads the oldest markings first.
CREATE INDEX smart_group_dirty_queued ON obligarth.smart_group_dirty (tenant_id, queued_at, device_id);

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
