import type { Knex } from 'knex';

// =============================================================================
// The site of an enrollment token (lot P1-QR; spec P1-QR-SITES §3.2)
// =============================================================================
//   - legacy_agent_enrollment_tokens.site_id: the site a device enrolled with the token is attached to (then filed in the
//     group of the site when the token names no group: legacyAgent/enroll.ts), in the token's tenant
//     (legacy_agent_tokens_site_fk on (tenant_id, site_id)), NULL once the site is deleted (a site is archived, never
//     deleted but with its tenant).
//   - legacy_agent_enrollment_tokens.site_sheet: the token of the printable sheet of its site ("Enroll a phone"); the
//     next sheet of the site revokes the ones still active. Its partial index serves that lookup.
// Every existing row: no site, no sheet (the columns are new), so the constraints hold at once.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_assert_clean() last, a down that raises. Runs
// as obligarth_owner (server-migrate), after sites.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Site of an enrollment token (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.sites') IS NULL OR to_regclass('obligarth.legacy_agent_enrollment_tokens') IS NULL THEN
    RAISE EXCEPTION 'enrollment_token_sites: apply the sites and legacy_agent migrations first';
  END IF;
END $$;

ALTER TABLE obligarth.legacy_agent_enrollment_tokens
  ADD COLUMN site_id    uuid,
  ADD COLUMN site_sheet boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT legacy_agent_tokens_site_fk FOREIGN KEY (tenant_id, site_id)
    REFERENCES obligarth.sites (tenant_id, id) ON DELETE SET NULL (site_id),
  -- A sheet is a token of the console (a bench token is single-use, bound to its provisioning).
  ADD CONSTRAINT legacy_agent_tokens_site_sheet_origin CHECK (NOT site_sheet OR origin = 'console');
CREATE INDEX legacy_agent_tokens_site_sheet ON obligarth.legacy_agent_enrollment_tokens (tenant_id, site_id)
  WHERE site_sheet AND revoked_at IS NULL;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
