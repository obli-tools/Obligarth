import type { MdmRetentionRule } from '../mdm/inventory/retention';
import { retentionCutoff } from '../privacy/retention';

// =============================================================================
// Retention of the journal of the remote assistance sessions (P0-15 M3, D7; category remote_sessions_months of the
// tenant, 12 months by default, 6 to 36), handed to the generic retention (modules/privacy.ts,
// privacy.retention-tenant), same contract as the rules of the data model: at most `limit` rows of one tenant per call,
// in the caller's transaction and the tenant's context.
//   - remote_sessions: a session that ended (ended_at set: every final state) before the cutoff, created before as
//     well (the index (tenant_id, created_at)). Never an open session. The audit entries of the session keep their own
//     duration (the audit log's retention, unchanged).
// =============================================================================

export const remoteRetentionRules: readonly MdmRetentionRule[] = Object.freeze([
  {
    name: 'remote_sessions',
    description: 'Remote assistance sessions ended remote_sessions_months ago',
    async purge(trx, tenantId, now, limit) {
      const cutoff = await retentionCutoff(trx, tenantId, 'remote_sessions_months', now);
      const res = await trx.raw(`
        DELETE FROM remote_sessions s USING (
          SELECT x.id FROM remote_sessions x
           WHERE x.tenant_id = :tenantId AND x.created_at < :cutoff
             AND x.ended_at IS NOT NULL AND x.ended_at < :cutoff
           ORDER BY x.created_at
           LIMIT :limit) due
         WHERE s.tenant_id = :tenantId AND s.id = due.id`,
      { tenantId, cutoff, limit }) as { rowCount: number | null };
      return Number(res.rowCount ?? 0);
    },
  },
]);
