import type { Knex } from 'knex';

// =============================================================================
// Obliwatch integration, foundations (brief GTH-01..09, plan §0 F2 and F5)
// =============================================================================
//   - integration_seen_jti        identity: the jti of every app or user token accepted by an integration router
//                                 (/api/integrations/obliwatch/v1), burned on first use; a row lives until shortly
//                                 after the token's exp (purged by the minute step of the module). No tenant data.
//   - tenant_obliwatch_settings   tenant: the consent of a tenant (read, push, actions, nominative AI apps), each off
//                                 until a manager of the tenant turns it on (audited obliwatch.consent.changed). No row:
//                                 everything off.
// Two new tables, nothing else touched: additive, safe on a live database at start (IF NOT EXISTS, rls_apply is
// re-runnable). Nothing reads them while OBLIWATCH_INTEGRATION is not 'on'.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean()
// last, a down that raises. Runs as obligarth_owner (server-migrate).
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Obliwatch integration: single-use jti, consent of the tenants (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'obligarth_private' AND p.proname = 'rls_apply') THEN
    RAISE EXCEPTION 'obliwatch_integration: apply the rls foundation first';
  END IF;
  IF to_regclass('obligarth.tenants') IS NULL OR to_regclass('obligarth.users') IS NULL THEN
    RAISE EXCEPTION 'obliwatch_integration: users and tenants are missing';
  END IF;
END $$;

-- 1. Single-use jti ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obligarth.integration_seen_jti (
  jti        uuid          NOT NULL,
  source     text          NOT NULL,
  exp        timestamptz   NOT NULL,
  seen_at    timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT integration_seen_jti_pkey PRIMARY KEY (jti),
  CONSTRAINT integration_seen_jti_source_check CHECK (source ~ '^[a-z][a-z0-9-]{1,31}$')
);
CREATE INDEX IF NOT EXISTS integration_seen_jti_exp ON obligarth.integration_seen_jti (exp);
COMMENT ON TABLE obligarth.integration_seen_jti IS
  'Obliwatch integration (F2): jti of the delegation tokens accepted by an integration router, burned on first use; purged after exp';
SELECT obligarth_private.rls_apply('obligarth.integration_seen_jti', 'identity',
  'integrations: single-use jti of the delegation tokens (no tenant data)');

-- 2. Consent of a tenant ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obligarth.tenant_obliwatch_settings (
  tenant_id          integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  read_enabled      boolean       NOT NULL DEFAULT false,
  push_enabled       boolean       NOT NULL DEFAULT false,
  actions_enabled    boolean       NOT NULL DEFAULT false,
  nominative_ai_apps boolean       NOT NULL DEFAULT false,
  changed_by         integer,
  changed_at         timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT tenant_obliwatch_settings_pkey PRIMARY KEY (tenant_id),
  CONSTRAINT tenant_obliwatch_settings_tenant_id_foreign FOREIGN KEY (tenant_id) REFERENCES obligarth.tenants (id) ON DELETE CASCADE
);
COMMENT ON TABLE obligarth.tenant_obliwatch_settings IS
  'Obliwatch integration (F5): consent of the tenant, off until a manager turns it on (audited obliwatch.consent.changed); changed_by has no foreign key (the row outlives the account)';
SELECT obligarth_private.rls_apply('obligarth.tenant_obliwatch_settings', 'tenant',
  'Obliwatch integration: consent of the tenant (read, push, actions, nominative AI apps)');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
