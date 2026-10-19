import type { Knex } from 'knex';

// =============================================================================
// Android, junction AN-A2 (android-amapi §4.4 to §4.6, §15.1): the widenings of existing tables that the lots AN-C1b,
// AN-D1 and AN-E1 prepared out of the repository (forbidden on the branch android before the integration of lot C),
// written on the final CHECKs of lot C (read from a database migrated to 20261019090000: unchanged by lot C since
// they were prepared). Widenings only: no Apple row changes, every Apple branch keeps its rule word for word.
//   - part 3b: devices.enrollment_type and enrollment_profiles.method gain the Android methods; the unenroll and end
//     reasons gain missing_in_provider and presumed_gone; ownership_allows tightened for Android (a personal work
//     profile by a BYOD link or a sign-in URL only; a corporate work profile never by a BYOD link nor NFC; a fully
//     managed or dedicated device never by a BYOD link); enrollment_profiles_rules_check in two branches, Apple
//     unchanged and Android (COH-17); the mirrors in TypeScript change in the same commit (shared/src/mdm/enums.ts,
//     shared/src/mdm/ownership.ts, shared/src/mdm/enrollment.ts);
//   - part 5: mdm_artifacts and device_artifacts admit the channel amapi (identifier 'policy', key amapi:policy); the
//     package of an Android app of the catalog checked by apps_android_identifier (store_id null, license_mode none,
//     a private or web app never shared from the master tenant);
//   - migration 4 (the queue widened, section 4.5): mdm_commands admits the platform android (amapi_command, sealed
//     secret_enc, no plist), mdm_command_targets the AMAPI operation, its error code and the start of its submission.
//     The rows of android_commands stay where they are: the bus writes the common queue with the channel provider of
//     lot AN-P, which moves them (secret_enc sealed again for its new column) and drops android_commands.
// Runs as obligarth_owner (server-migrate) after the Android migrations 1 to 9; ends with
// obligarth.rls_assert_clean(). No question mark in the SQL (knex.raw would bind it); kept verbatim by String.raw.
// =============================================================================

const SEALED_RE =
  '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$';

const UP = String.raw`-- =============================================================================
-- Android, junction AN-A2: parts 3b and 5, migration 4 (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_devices') IS NULL OR to_regclass('obligarth.enrollment_profiles') IS NULL
     OR to_regclass('obligarth.mdm_commands') IS NULL OR to_regclass('obligarth.mdm_change_ledger') IS NULL THEN
    RAISE EXCEPTION 'android_junction: apply the migrations of lot C and the Android migrations first';
  END IF;
END $$;

-- ── Part 3b: registry and profiles ─────────────────────────────────────────
ALTER TABLE obligarth.devices
  DROP CONSTRAINT devices_enrollment_type_check,
  ADD CONSTRAINT devices_enrollment_type_check CHECK (enrollment_type IN
      ('ade', 'ota', 'byod_account', 'configurator', 'account_device', 'migration',
       'android_qr', 'android_nfc', 'android_afw', 'android_token', 'android_zero_touch', 'android_kme',
       'android_byod_link', 'android_signin_url')),
  DROP CONSTRAINT devices_unenroll_reason_check,
  ADD CONSTRAINT devices_unenroll_reason_check CHECK (unenroll_reason IN ('checkout', 'retired', 'transfer',
      'superseded_by_proof', 'superseded', 'apns_inactive', 'purged', 'disabled_in_edge', 'removed_by_command', 'wiped',
      'missing_in_provider', 'presumed_gone'));

ALTER TABLE obligarth.device_enrollments
  DROP CONSTRAINT device_enrollments_end_reason_check,
  ADD CONSTRAINT device_enrollments_end_reason_check CHECK (end_reason IN ('checkout', 'retired', 'transfer',
      'superseded_by_proof', 'superseded', 'apns_inactive', 'purged', 'disabled_in_edge', 'removed_by_command',
      'wiped', 'replaced', 'missing_in_provider', 'presumed_gone'));

-- ownership_allows tightened (section 4.4): work_profile_personal <=> android_byod_link or android_signin_url;
-- work_profile_corporate without android_byod_link nor android_nfc; fully_managed and dedicated never by a BYOD link.
-- The Apple branches are those of mdm_model_expand, word for word.
CREATE OR REPLACE FUNCTION obligarth.ownership_allows(p_ownership text, p_enrollment_type text, p_mode text)
  RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN (CASE p_ownership
    WHEN 'personal' THEN
         (p_mode = 'user_enrollment' AND p_enrollment_type = 'byod_account')
      OR (p_mode = 'work_profile_personal' AND p_enrollment_type IN ('android_byod_link', 'android_signin_url'))
    WHEN 'corporate_personal' THEN
         (p_mode = 'device' AND p_enrollment_type IN ('ade', 'configurator', 'migration'))
      OR (p_mode = 'work_profile_corporate' AND p_enrollment_type LIKE 'android\_%'
          AND p_enrollment_type NOT IN ('android_byod_link', 'android_nfc'))
    WHEN 'corporate' THEN
         (p_mode = 'device' AND p_enrollment_type IN ('ade', 'configurator', 'ota', 'account_device', 'migration'))
      OR (p_mode IN ('fully_managed', 'dedicated') AND p_enrollment_type LIKE 'android\_%'
          AND p_enrollment_type <> 'android_byod_link')
    ELSE false
  END);

-- enrollment_profiles_rules_check in two branches (COH-17): the Apple branch is the rule of lot C, word for word.
ALTER TABLE obligarth.enrollment_profiles
  DROP CONSTRAINT enrollment_profiles_platform_check,
  ADD CONSTRAINT enrollment_profiles_platform_check CHECK (platform IN ('apple', 'android')),
  DROP CONSTRAINT enrollment_profiles_method_check,
  ADD CONSTRAINT enrollment_profiles_method_check CHECK (method IN ('ota', 'ade', 'byod_account',
      'android_qr', 'android_nfc', 'android_afw', 'android_token', 'android_zero_touch', 'android_kme',
      'android_byod_link', 'android_signin_url')),
  DROP CONSTRAINT enrollment_profiles_rules_check,
  ADD CONSTRAINT enrollment_profiles_rules_check CHECK (
    (target_tenant_ids IS NULL OR tenant_id = 1)
    AND (
      (platform = 'apple' AND method IN ('ota', 'ade', 'byod_account')
        AND (method <> 'byod_account' OR ownership = 'personal')
        AND (method = 'byod_account' OR ownership <> 'personal')
        AND NOT (method = 'ota' AND ownership = 'corporate_personal')
        AND ((method = 'ade') = (usage IS NOT NULL))
        AND (usage IS NULL OR usage ~ '^[a-z][a-z0-9_]{0,31}$')
        AND (notice_required OR method = 'ade')
        AND (NOT is_default OR method = 'ade'))
      OR
      (platform = 'android' AND method LIKE 'android\_%'
        AND usage IS NULL AND NOT is_default
        AND ((method = 'android_byod_link') = (ownership = 'personal') OR method = 'android_signin_url')
        AND NOT (method = 'android_nfc' AND ownership = 'corporate_personal'))
    ));

-- ── Part 5: the artifacts of the channel amapi, the Android apps of the catalog ─
ALTER TABLE obligarth.mdm_artifacts
  DROP CONSTRAINT mdm_artifacts_channel_check,
  ADD CONSTRAINT mdm_artifacts_channel_check CHECK (channel IN ('ddm', 'profile', 'app', 'setting', 'amapi')),
  DROP CONSTRAINT mdm_artifacts_identifier_check,
  ADD CONSTRAINT mdm_artifacts_identifier_check CHECK (
       (channel = 'ddm' AND identifier ~ '^obg\.cfg\.pol-[A-Za-z0-9._-]{1,52}$')
    OR (channel = 'profile' AND identifier ~ '^tools\.obli\.obligarth\.(p|raw)\.[A-Za-z0-9._-]{1,140}$')
    OR (channel = 'app' AND identifier ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$')
    OR (channel = 'setting' AND identifier ~ '^[a-z][a-z0-9_]{0,63}$')
    OR (channel = 'amapi' AND identifier = 'policy'));

ALTER TABLE obligarth.device_artifacts
  DROP CONSTRAINT device_artifacts_key_check,
  ADD CONSTRAINT device_artifacts_key_check
      CHECK (artifact_key ~ '^(ddm|profile|app|setting|amapi):[A-Za-z0-9][A-Za-z0-9._-]{0,199}$');

ALTER TABLE obligarth.apps
  ADD CONSTRAINT apps_android_identifier CHECK (
    platform_family <> 'android'
    OR (identifier ~ '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$' AND length(identifier) <= 255
        AND store_id IS NULL AND license_mode = 'none'
        AND (kind = 'play' OR target_tenant_ids IS NULL))
  ) NOT VALID;
ALTER TABLE obligarth.apps VALIDATE CONSTRAINT apps_android_identifier;

-- ── Migration 4: the queue widened to the platform android ──────────────────
-- chr(63): never a question mark under Knex (review INT-RC1)
ALTER TABLE obligarth.mdm_commands
  DROP CONSTRAINT mdm_commands_platform_check,
  ADD CONSTRAINT mdm_commands_platform_check CHECK (platform IN ('apple', 'android')),
  ADD COLUMN amapi_command jsonb,
  ADD COLUMN secret_enc text,
  ALTER COLUMN plist_sha256 DROP NOT NULL,
  DROP CONSTRAINT mdm_commands_plist_check,
  ADD CONSTRAINT mdm_commands_plist_check CHECK (
       (platform = 'apple' AND (plist IS NULL) <> (plist_enc IS NULL)
          AND (plist IS NULL OR left(plist, 5) = '<' || chr(63) || 'xml') AND plist_sha256 IS NOT NULL
          AND amapi_command IS NULL AND secret_enc IS NULL)
    OR (platform = 'android' AND plist IS NULL AND plist_enc IS NULL AND amapi_command IS NOT NULL
          AND jsonb_typeof(amapi_command) = 'object' AND amapi_command->'newPassword' IS NULL)),
  ADD CONSTRAINT mdm_commands_secret_enc_sealed CHECK (secret_enc IS NULL OR secret_enc ~ '${SEALED_RE}');

ALTER TABLE obligarth.mdm_command_targets
  ADD COLUMN amapi_operation varchar(255),
  ADD COLUMN amapi_error_code varchar(32),
  ADD COLUMN amapi_submit_started_at timestamptz,
  ADD CONSTRAINT mdm_command_targets_operation_check
    CHECK (amapi_operation IS NULL OR amapi_operation ~ '^enterprises/[A-Za-z0-9_-]+/devices/[A-Za-z0-9_-]+/operations/[A-Za-z0-9_-]+$');
CREATE UNIQUE INDEX mdm_command_targets_operation ON obligarth.mdm_command_targets (amapi_operation)
  WHERE amapi_operation IS NOT NULL;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
