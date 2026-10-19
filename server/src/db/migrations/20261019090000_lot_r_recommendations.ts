import type { Knex } from 'knex';

// =============================================================================
// Recommendations of the owners of 15/10/2026 before the pilot (lot R):
//   - mdm_change_ledger: what the changes of the configuration written without a second approver touched, per
//     tenant, over the last hour (modele-donnees-mdm DM23; review of lot B5b, MDM-B5b-C7): the thresholds bear on
//     their sum (mdm/policies/changeLedger.ts). Tenant table under the RLS; rows older than the window deleted by
//     the next change of the tenant;
//   - device_enrollments_one_open on (tenant_id, device_id) instead of (device_id) (review of lot B2, MDM-B2-R8):
//     a write that named the device of another tenant answered 23505 before the RLS (an existence oracle);
//   - apple_edge_inbox_attempts from the class 'technical' (outside the RLS) to 'custom', read and written in the
//     context 'none' of a job actor only, like apple_edge_dead_letters (review of lot B1, INT-B1-R9): from the context
//     of a tenant (an SQL injection in a request), an attempt that delays the event of another tenant without end can
//     no longer be written. The consumer, the monitor of the lag and the redrive all run as jobs in the context 'none'.
// Runs as obligarth_owner (server-migrate), after enrollment_invitation_attempts; ends with
// obligarth.rls_assert_clean(). No question mark in the SQL (knex.raw would bind it); kept verbatim by String.raw.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Lot R: change ledger, open episode index per tenant, outbox attempts under the RLS (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.device_enrollments') IS NULL THEN
    RAISE EXCEPTION 'lot_r_recommendations: apply the RLS migrations and mdm_model_expand first';
  END IF;
END $$;

CREATE TABLE obligarth.mdm_change_ledger (
  id                  bigserial     NOT NULL,
  tenant_id           integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  recorded_at         timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  kind                varchar(32)   NOT NULL,
  device_ids          integer[]     NOT NULL DEFAULT '{}',
  removal_device_ids  integer[]     NOT NULL DEFAULT '{}',
  CONSTRAINT mdm_change_ledger_pkey PRIMARY KEY (id),
  CONSTRAINT mdm_change_ledger_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT mdm_change_ledger_kind_check
    CHECK (kind IN ('version', 'assignments', 'group_move', 'group_delete', 'device_move')),
  CONSTRAINT mdm_change_ledger_size_check
    CHECK (cardinality(device_ids) <= 1000 AND cardinality(removal_device_ids) <= 1000)
);
CREATE INDEX mdm_change_ledger_tenant_recorded ON obligarth.mdm_change_ledger (tenant_id, recorded_at);
SELECT obligarth_private.rls_apply('obligarth.mdm_change_ledger', 'tenant');

-- MDM-B2-R8: the uniqueness of the open episode of a device, within its tenant.
CREATE UNIQUE INDEX device_enrollments_one_open_tenant ON obligarth.device_enrollments (tenant_id, device_id) WHERE ended_at IS NULL;
DROP INDEX obligarth.device_enrollments_one_open;
ALTER INDEX obligarth.device_enrollments_one_open_tenant RENAME TO device_enrollments_one_open;

-- INT-B1-R9: the attempts of the outbox consumer, jobs only (context 'none', actor j:).
SELECT obligarth_private.rls_apply('obligarth.apple_edge_inbox_attempts', 'custom',
  'jobs (FND-04): outbox attempts, ids only; context none of a job actor (INT-B1-R9)');
CREATE POLICY rls_job ON obligarth.apple_edge_inbox_attempts TO obligarth
  USING ((SELECT obligarth.ctx_kind()) = 'none' AND (SELECT obligarth.ctx_actor()) LIKE 'j:%')
  WITH CHECK ((SELECT obligarth.ctx_kind()) = 'none' AND (SELECT obligarth.ctx_actor()) LIKE 'j:%');
GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.apple_edge_inbox_attempts TO obligarth;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}
