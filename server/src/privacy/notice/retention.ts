import type { MdmRetentionRule } from '../../mdm/inventory/retention';
import { retentionCutoff } from '../retention';

// =============================================================================
// Retention of the acknowledgements of the notice (P0-13 T5, USR-01; category notice_ack_months of the tenant, 36
// months by default, D5: to be confirmed by a lawyer), handed to the generic retention (modules/privacy.ts,
// privacy.retention-tenant), same contract as the rules of the data model: at most `limit` rows of one tenant per call,
// in the caller's transaction and the tenant's context. The versions of the notice stay (immutable, small): an
// acknowledgement purged no longer points to its version, the version keeps the text that was shown.
// =============================================================================

export const noticeRetentionRules: readonly MdmRetentionRule[] = Object.freeze([
  {
    name: 'notice_acknowledgements',
    description: 'Acknowledgements of the employee notice older than notice_ack_months',
    async purge(trx, tenantId, now, limit) {
      const cutoff = await retentionCutoff(trx, tenantId, 'notice_ack_months', now);
      const res = await trx.raw(`
        DELETE FROM notice_acknowledgements a USING (
          SELECT x.id FROM notice_acknowledgements x
           WHERE x.tenant_id = :tenantId AND x.acknowledged_at < :cutoff
           ORDER BY x.acknowledged_at
           LIMIT :limit) due
         WHERE a.tenant_id = :tenantId AND a.id = due.id`,
      { tenantId, cutoff, limit }) as { rowCount: number | null };
      return Number(res.rowCount ?? 0);
    },
  },
]);
