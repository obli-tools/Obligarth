import type { Knex } from 'knex';

// =============================================================================
// Privacy rule remoteAssistance (P0-15 T1, M2 of the spec; §4.5, D3)
// =============================================================================
//   - privacy_profile_versions_rules_shape is replaced (DROP then ADD in this transaction, lock_timeout 5s): the
//     nine keys of PrivacyProfileRules (shared/src/privacy.ts), remoteAssistance optional (absent, or a boolean). The
//     versions published before are never written again: a key absent is read at the default of the version's
//     ownership (true for corporate, false otherwise: §0.1 rule 5; server/src/privacy/profiles.ts).
//     Not a list IN: widen_in_check does not apply.
//   - Imposed rules (IMPOSED_RULES, D3): no remote assistance on a personal device
//     (privacy_profile_versions_personal_remote) nor on a COPE one (privacy_profile_versions_cope_remote): the capture
//     takes the whole screen, personal applications included. Every version published so far satisfies both (the
//     key does not exist yet).
// Precondition: the constraint replaced is still the one of privacy_profiles (P0-13), compared by the MD5 of its
// definition; another lot that changed it first stops this migration (merge both shapes here).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last, a down that raises.
// Runs as obligarth_owner (server-migrate), after p015_remote_sessions.
// =============================================================================

// md5 of pg_get_constraintdef() of privacy_profile_versions_rules_shape written by 20261027130000_privacy_profiles.
const RULES_SHAPE_MD5 = 'ec36f0229e56c686c40b562cd55b560d';

const UP = String.raw`-- =============================================================================
-- Privacy rule remoteAssistance (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '5s';

DO $$
DECLARE v_md5 text;
BEGIN
  IF to_regclass('obligarth.privacy_profile_versions') IS NULL THEN
    RAISE EXCEPTION 'p015_privacy_remote_assistance: apply privacy_profiles first';
  END IF;
  SELECT md5(pg_get_constraintdef(c.oid)) INTO v_md5
    FROM pg_constraint c
   WHERE c.conrelid = 'obligarth.privacy_profile_versions'::regclass AND c.conname = 'privacy_profile_versions_rules_shape';
  IF v_md5 IS DISTINCT FROM '${RULES_SHAPE_MD5}' THEN
    RAISE EXCEPTION 'p015_privacy_remote_assistance: privacy_profile_versions_rules_shape differs from privacy_profiles (md5 %): merge both shapes', v_md5;
  END IF;
END $$;

ALTER TABLE obligarth.privacy_profile_versions DROP CONSTRAINT privacy_profile_versions_rules_shape;
ALTER TABLE obligarth.privacy_profile_versions
  -- The nine keys of PrivacyProfileRules, of their types, and no other; remoteAssistance may be absent (P0-15).
  ADD CONSTRAINT privacy_profile_versions_rules_shape CHECK (
        COALESCE(jsonb_typeof(rules) = 'object', false)
    AND COALESCE((rules - ARRAY['serialNumber', 'hardwareIds', 'deviceName', 'phoneNumber', 'network', 'lostModeLocation',
                                'installedApps', 'certificates', 'remoteAssistance']::text[]) = '{}'::jsonb, false)
    AND COALESCE(jsonb_typeof(rules -> 'serialNumber') = 'boolean', false)
    AND COALESCE(jsonb_typeof(rules -> 'hardwareIds') = 'boolean', false)
    AND COALESCE(jsonb_typeof(rules -> 'deviceName') = 'boolean', false)
    AND COALESCE(jsonb_typeof(rules -> 'phoneNumber') = 'boolean', false)
    AND COALESCE(jsonb_typeof(rules -> 'network') = 'boolean', false)
    AND COALESCE(jsonb_typeof(rules -> 'lostModeLocation') = 'boolean', false)
    AND COALESCE(rules -> 'installedApps' IN ('"all"'::jsonb, '"managed_only"'::jsonb), false)
    AND COALESCE(rules -> 'certificates' IN ('"all"'::jsonb, '"managed_only"'::jsonb), false)
    AND (rules -> 'remoteAssistance' IS NULL OR jsonb_typeof(rules -> 'remoteAssistance') = 'boolean')),
  -- Imposed rules (D3; IMPOSED_RULES of shared/src/privacy.ts, error privacyRuleImposed).
  ADD CONSTRAINT privacy_profile_versions_personal_remote CHECK (ownership <> 'personal'
    OR COALESCE(rules -> 'remoteAssistance' = 'true'::jsonb, false) = false),
  ADD CONSTRAINT privacy_profile_versions_cope_remote CHECK (ownership <> 'corporate_personal'
    OR COALESCE(rules -> 'remoteAssistance' = 'true'::jsonb, false) = false);

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
