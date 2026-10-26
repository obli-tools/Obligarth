import type { MdmRetentionRule } from '../mdm/inventory/retention';
import { retentionCutoff } from '../privacy/retention';

// =============================================================================
// Retention of the bridge agent's queue (P0-13 T4, CNF-04; agent-pont-android §15.4), handed to the generic retention
// (modules/privacy.ts, privacy.retention-tenant), same contract as the rules of the data model: at most `limit` rows of
// one tenant per call, in the caller's transaction and the tenant's context.
//   - legacy_agent_commands: a command in a final state (acknowledged, error, rejected, expired, cancelled) that ended
//     before technical_log_months of the tenant (6 by default), created before as well. Never an open command
//     (pending, sent: the agent may still fetch it or answer it). Kept whatever its age: the last acknowledged
//     app.install of each package of a device, which tells the applications the management put there
//     (commands.ts managedPackages: device_apps.managed, the 'managed_only' rule of the privacy profile, D14).
// =============================================================================

export const legacyAgentRetentionRules: readonly MdmRetentionRule[] = Object.freeze([
  {
    name: 'legacy_agent_commands',
    description: 'Commands of the bridge agent ended technical_log_months ago (the last installation of each package kept)',
    async purge(trx, tenantId, now, limit) {
      const cutoff = await retentionCutoff(trx, tenantId, 'technical_log_months', now);
      const res = await trx.raw(`
        DELETE FROM legacy_agent_commands c USING (
          SELECT x.id FROM legacy_agent_commands x
           WHERE x.tenant_id = :tenantId AND x.created_at < :cutoff
             AND x.state IN ('acknowledged', 'error', 'rejected', 'expired', 'cancelled') AND COALESCE(x.completed_at, x.state_event_at) < :cutoff
             AND NOT (x.request_type = 'app.install' AND x.state = 'acknowledged'
                      AND NOT EXISTS (SELECT 1 FROM legacy_agent_commands y
                                       WHERE y.tenant_id = x.tenant_id AND y.device_id = x.device_id
                                         AND y.request_type = 'app.install' AND y.state = 'acknowledged'
                                         AND y.params ->> 'packageName' = x.params ->> 'packageName'
                                         AND (y.created_at, y.id) > (x.created_at, x.id)))
           ORDER BY x.created_at
           LIMIT :limit) due
         WHERE c.tenant_id = :tenantId AND c.id = due.id`,
      { tenantId, cutoff, limit }) as { rowCount: number | null };
      return Number(res.rowCount ?? 0);
    },
  },
]);
