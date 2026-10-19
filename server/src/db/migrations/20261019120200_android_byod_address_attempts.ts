import type { Knex } from 'knex';

// =============================================================================
// Wrong codes of the BYOD invitations of Android per address (decision of the owners of 19/10/2026 on F1R-4): the MDM
// key is public, and twenty wrong codes an hour from two addresses blocked every BYOD enrollment of the tenant. An
// address is now blocked first (ANDROID_BYOD_WRONG_CODES_PER_ADDRESS_HOUR), the tenant only at about two hundred wrong
// codes an hour (ANDROID_BYOD_WRONG_CODES_PER_HOUR, android_byod_attempts).
//   - android_byod_address_attempts (class tenant): wrong codes per tenant, hour and address. The address is never
//     stored: an HMAC of it (key derived from SESSION_SECRET, with the tenant's uuid), 32 hex characters. Rows older
//     than two days are deleted by the next wrong code of the tenant.
// Runs as obligarth_owner (server-migrate), after vpp_location_claims; ends with obligarth.rls_assert_clean(). No
// question mark in the SQL (knex.raw would bind it); kept verbatim by String.raw.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Android BYOD: wrong codes per address (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_byod_attempts') IS NULL
     OR to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL THEN
    RAISE EXCEPTION 'android_byod_address_attempts: apply android_byod and the RLS migrations first';
  END IF;
END $$;

CREATE TABLE obligarth.android_byod_address_attempts (
  tenant_id     integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  hour_start    timestamptz  NOT NULL,
  address_hmac  char(32)     NOT NULL,
  wrong_codes   integer      NOT NULL DEFAULT 0,
  CONSTRAINT android_byod_address_attempts_pkey PRIMARY KEY (tenant_id, hour_start, address_hmac),
  CONSTRAINT android_byod_address_attempts_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT android_byod_address_attempts_hmac_check CHECK (address_hmac ~ '^[0-9a-f]{32}$'),
  CONSTRAINT android_byod_address_attempts_wrong_codes_check CHECK (wrong_codes BETWEEN 0 AND 1000000)
);
SELECT obligarth_private.rls_apply('obligarth.android_byod_address_attempts', 'tenant');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
