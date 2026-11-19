import { registerJob } from '../jobs';
import { forEachTenant } from '../db/tenantContext';
import { registerLegacyAgentMinuteStep } from '../legacyAgent/jobs';
import { registerAlertDefinitions } from '../services/alertCatalog';
import { registerRestrictableActions } from '../services/restriction.service';
import { logger } from '../utils/logger';
import { obliwatchAlertDefinitions } from '../integrations/obliwatch/alerts';
import { registerObliwatchAuditActions } from '../integrations/obliwatch/audit';
import { OBLIWATCH_ACTOR, obliwatchIntegrationEnabled } from '../integrations/obliwatch/config';
import { CATALOG_QUEUE, CatalogJobPayload, runCatalogJob } from '../integrations/obliwatch/catalog';
import { purgeSeenJti } from '../integrations/obliwatch/jti';
import { PUSH_QUEUE, PushJobPayload, purgeTransitions, requestDuePushes, runPushJob } from '../integrations/obliwatch/push';
import { bindPushJob } from '../integrations/obliwatch/signals';
import {
  ACTION_RESULT_QUEUE, ActionResultJobPayload, bindActionResultJob, purgeActionRows, requestDueActionResults, runActionResultJob,
} from '../integrations/obliwatch/actionResults';
import { closeOpenRequests, trackTenant } from '../integrations/obliwatch/actionTrack';
import { purgeSecurityWindowsInTx, staleSecurityLogPoliciesInTx } from '../integrations/obliwatch/securityLogs';
import type { JobContext } from '../jobs/types';
import { db } from '../db';
import { asTenant } from '../db/context';

// =============================================================================
// OBLIWATCH INTEGRATION (brief GTH-01..09; plan §0 F6): its hooks into the core's registries, registered here and
// only here; index.ts calls registerObliwatchModule() after the MCP module, before Android. No I/O.
//   - always: the audit actions and the alert obliwatch.push_dead (the journal and the alerts keep their labels after
//     the integration is turned off);
//   - with OBLIWATCH_INTEGRATION=on only: the restrictable action of the consent, the push job
//     integrations.obliwatch.push (lot L3) and the minute step (purge of the burned jti; the tenants with due
//     transitions asked again; once an hour, the purge of the transitions ended 30 days ago, 90 for a dead one), the
//     daily job integrations.obliwatch.catalog-sync (lot L4: the AI catalog of Obliwatch); lot L5: the job
//     integrations.obliwatch.action-result (the results of the action requests pushed to Obliwatch) and, in the minute
//     step, the tracking of the open action requests (actionTrack.ts) and the results due; hourly, their purge. The
//     routes are mounted by app.ts (read API) and routes/index.ts (console), on the same switch. With the switch off,
//     the hot paths' hooks (integrations/obliwatch/signals.ts) return at once, without a statement;
//   - always (lot L5), the cleanup step 'obliwatch-cleanup': a no-op while the switch is on; off, it undoes what an
//     earlier 'on' left (open action requests, policies carrying the security logs), then stops (see above).
// =============================================================================

// ── Cleanup while the integration is OFF (lot L5) ──────────────────────────────────────────────────────────────
// Registered whatever the switch says, and a no-op while it is on (the minute step below does the work then). With the
// switch off, what an earlier 'on' left behind is undone: every open action request of Obliwatch withdrawn and closed
// ('cancelled', integration_off: nothing it would still send reaches a device; the guard engine refuses its guarded
// action anyway), and every AMAPI device whose policy still carries the security logs pushed again without them
// (securityLogs.ts, policy_logs_on). At the first minute, then every 15 minutes while something is left; once a pass
// finds nothing, it stops (no statement any more) until the switch is turned on and off again.
const CLEANUP_EVERY_MINUTES = 15;
let cleanupClean = false;
let cleanupTicks = 0;

async function runCleanupStep(ctx: JobContext<Record<string, never>>): Promise<Record<string, number>> {
  if (obliwatchIntegrationEnabled()) { cleanupClean = false; cleanupTicks = 0; return {}; }
  if (cleanupClean || cleanupTicks++ % CLEANUP_EVERY_MINUTES !== 0) return {};
  let requestsClosed = 0;
  let policiesAsked = 0;
  let left = false;
  const tenants: number[] = [];
  await forEachTenant(ctx.dbActor, async (tenantId) => { tenants.push(tenantId); });
  for (const tenantId of tenants) {
    try {
      const open = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db('obliwatch_action_requests').where({ tenant_id: tenantId })
        .whereIn('state', ['accepted', 'executing']).first('id'));
      if (open) {
        requestsClosed += await closeOpenRequests(tenantId, 'integration_off');
        left = true;
      }
      const asked = await asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction((trx) => staleSecurityLogPoliciesInTx(trx, tenantId, false)));
      policiesAsked += asked;
      if (asked > 0) left = true;
    } catch (err) {
      left = true;
      logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, tenantId }, 'obliwatch cleanup: tenant not cleaned (next pass)');
    }
  }
  if (!left) cleanupClean = true;
  return requestsClosed || policiesAsked ? { obliwatchCleanupRequestsClosed: requestsClosed, obliwatchCleanupPoliciesAsked: policiesAsked } : {};
}

export const OBLIWATCH_RESTRICTABLE_ACTIONS = [
  { key: 'obliwatch.settings_change', label: 'Change the Obliwatch consent of the tenant', category: 'Obliwatch' },
] as const;

let registered = false;
let minutes = 0;

export function registerObliwatchModule(): void {
  if (registered) return;
  registered = true;

  registerObliwatchAuditActions();
  registerAlertDefinitions('obliwatch', obliwatchAlertDefinitions());
  registerLegacyAgentMinuteStep('obliwatch-cleanup', runCleanupStep);
  if (!obliwatchIntegrationEnabled()) return;

  registerRestrictableActions(OBLIWATCH_RESTRICTABLE_ACTIONS, {}, {
    'obliwatch.settings_change': { level: 'sensitive', strictStepUp: true },
  });

  // The drain of a tenant: stately per tenant (one waiting at most, a burst of transitions is one job). The retries of
  // 72 hours are carried by the rows (push.ts); the job's own retries only cover a failure of the database.
  const push = registerJob({
    name: PUSH_QUEUE,
    scope: 'tenant',
    description: 'Send the D-MOB-* signal transitions of a tenant to Obliwatch (batches of 500, retried for 72 hours)',
    payload: PushJobPayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 30, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 600,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: 30,
    deadLetter: false,
    handler: runPushJob,
  });
  bindPushJob(push);

  // Lot L4 (GTH-06): the AI catalog of Obliwatch, once a day and once at start (catalog.ts: nothing is fetched while no
  // tenant consented to be read; Obliwatch's route not built yet is a recorded state, not a failure).
  registerJob({
    name: CATALOG_QUEUE,
    scope: 'platform',
    description: 'Every day at 03:35 UTC: fetch the AI catalog of Obliwatch (bundles of the AI apps) when a tenant consented to be read',
    payload: CatalogJobPayload,
    policy: 'exclusive',
    schedule: { cron: '35 3 * * *' },
    runAtStart: true,
    retry: { limit: 2, delaySeconds: 600, backoff: true },
    timeoutSeconds: 300,
    handler: runCatalogJob,
  });

  // Lot L5 (GTH-05): the results of the action requests, stately per tenant (the retries of 72 hours carried by the rows).
  const results = registerJob({
    name: ACTION_RESULT_QUEUE,
    scope: 'tenant',
    description: 'Send the results of the Obliwatch action requests of a tenant to Obliwatch (retried for 72 hours)',
    payload: ActionResultJobPayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 30, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 300,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: 30,
    deadLetter: false,
    handler: runActionResultJob,
  });
  bindActionResultJob(results);

  registerLegacyAgentMinuteStep('obliwatch', async (ctx) => {
    let purged = 0;
    try { purged = await purgeSeenJti(); } catch (err) { logger.warn({ err }, 'obliwatch minute step: seen jti not purged'); }
    let asked = 0;
    let transitionsPurged = 0;
    let actionsTracked = 0;
    let resultsAsked = 0;
    let actionRowsPurged = 0;
    let securityWindowsPurged = 0;
    const hourly = minutes++ % 60 === 0;
    try {
      const tenants: number[] = [];
      await forEachTenant(ctx.dbActor, async (tenantId) => { tenants.push(tenantId); });
      asked = await requestDuePushes((payload, opts) => push.send(payload, opts), tenants);
      if (hourly) for (const tenantId of tenants) transitionsPurged += await purgeTransitions(tenantId);
      // Lot L5: the open action requests brought up to date, their results due asked, the rows ended purged.
      for (const tenantId of tenants) actionsTracked += await trackTenant(tenantId);
      resultsAsked = await requestDueActionResults(tenants);
      if (hourly) for (const tenantId of tenants) actionRowsPurged += await purgeActionRows(tenantId);
      // Lot L5 (GTH-08, SEC-13): the windows of the security-log aggregates ended 8 days ago, hourly.
      if (hourly) {
        for (const tenantId of tenants) {
          securityWindowsPurged += await asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction((trx) => purgeSecurityWindowsInTx(trx, tenantId)));
          // The policies that still carry the security logs without the push consent (or for a device no longer
          // eligible): pushed again (securityLogs.ts).
          await asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction((trx) => staleSecurityLogPoliciesInTx(trx, tenantId, true)));
        }
      }
    } catch (err) {
      logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) } }, 'obliwatch minute step: push not asked');
    }
    return {
      obliwatchJtiPurged: purged, obliwatchPushAsked: asked, obliwatchTransitionsPurged: transitionsPurged,
      obliwatchActionsTracked: actionsTracked, obliwatchResultsAsked: resultsAsked, obliwatchActionRowsPurged: actionRowsPurged,
      obliwatchSecurityWindowsPurged: securityWindowsPurged,
    };
  });
}
