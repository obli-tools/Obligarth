import type { Knex } from 'knex';

// =============================================================================
// Capability mdm.privacy.manage in the admin permission set (P0-13 T2; coordination P0 §3.2 and C9)
// =============================================================================
//   - mdm.privacy.manage (shared/src/capabilities.ts, last of TENANT_CAPABILITIES): request the changes of the privacy
//     profiles and of the retention (each one approved by another person), write the settings of the notice. A tenant
//     administrator holds every capability already (requireTenantCapability); the admin set shows it in its matrix,
//     as audit.read (audit_hardening H.12b). The client sets (approver, auditor) do not get it: they read the privacy
//     pages with audit.read.
// Idempotent (a set that holds it already is left alone). The trigger permission_sets_privilege_change records a
// destructive capability only (devices.manage): nothing here.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last. Runs as
// obligarth_owner (server-migrate), after privacy_profiles.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Capability mdm.privacy.manage in the admin set (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.permission_sets') IS NULL
     OR to_regclass('obligarth.privacy_profile_versions') IS NULL THEN
    RAISE EXCEPTION 'privacy_capability: apply the base schema and privacy_profiles first';
  END IF;
END $$;

UPDATE obligarth.permission_sets SET capabilities = capabilities || '["mdm.privacy.manage"]'::jsonb
 WHERE slug = 'admin' AND NOT capabilities @> '["mdm.privacy.manage"]'::jsonb;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
