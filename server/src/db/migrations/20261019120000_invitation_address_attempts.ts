import type { Knex } from 'knex';

// =============================================================================
// Wrong codes of an invitation per address (decision of the owners of 19/10/2026 on the review of lot C2, minor
// finding "invitation", option A): five wrong codes from one address shut that address out of the invitation; the
// invitation itself is revoked only at a higher global count (enrollment_tokens.failed_attempts, counted only while
// the address is under its own cap). Whoever knows an employee's Managed Apple Account can no longer revoke the
// invitation alone with five wrong codes.
// The address is never stored: an HMAC of it (key derived from SESSION_SECRET, with the tenant's uuid), 32 hex
// characters. Tenant table under the RLS; rows deleted with their invitation or their tenant.
// Runs as obligarth_owner (server-migrate), after the Android migrations; ends with obligarth.rls_assert_clean().
// No question mark in the SQL (knex.raw would bind it); kept verbatim by String.raw.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Wrong codes of an invitation per address (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.enrollment_tokens') IS NULL
     OR to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL THEN
    RAISE EXCEPTION 'invitation_address_attempts: apply apple_enrollment and the RLS migrations first';
  END IF;
END $$;

CREATE TABLE obligarth.enrollment_invitation_address_attempts (
  tenant_id     integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  token_id      uuid         NOT NULL,
  address_hmac  char(32)     NOT NULL,
  failed        integer      NOT NULL DEFAULT 0,
  updated_at    timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT enrollment_invitation_address_attempts_pkey PRIMARY KEY (tenant_id, token_id, address_hmac),
  CONSTRAINT enrollment_invitation_address_attempts_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT enrollment_invitation_address_attempts_token_tenant_fk FOREIGN KEY (tenant_id, token_id)
    REFERENCES obligarth.enrollment_tokens (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT enrollment_invitation_address_attempts_hmac_check CHECK (address_hmac ~ '^[0-9a-f]{32}$'),
  CONSTRAINT enrollment_invitation_address_attempts_failed_check CHECK (failed BETWEEN 0 AND 1000)
);
SELECT obligarth_private.rls_apply('obligarth.enrollment_invitation_address_attempts', 'tenant');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
