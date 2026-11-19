import { registerJob } from '../jobs';
import { forEachTenant } from '../db/tenantContext';
import { registerLegacyAgentMinuteStep } from '../legacyAgent/jobs';
import { registerAlertDefinitions } from '../services/alertCatalog';
import { registerRestrictableActions } from '../services/restriction.service';
import { logger } from '../utils/logger';
import { obliwatchAlertDefinitions } from '../integrations/obliwatch/alerts';
import { registerObliwatchAuditActions } from '../integrations/obliwatch/audit';
import { obliwatchIntegrationEnabled } from '../integrations/obliwatch/config';
import { purgeSeenJti } from '../integrations/obliwatch/jti';
import { PUSH_QUEUE, PushJobPayload, purgeTransitions, requestDuePushes, runPushJob } from '../integrations/obliwatch/push';
import { bindPushJob } from '../integrations/obliwatch/signals';

// =============================================================================
// OBLIWATCH INTEGRATION (brief GTH-01..09; plan §0 F6): its hooks into the core's registries, registered here and
// only here; index.ts calls registerObliwatchModule() after the MCP module, before Android. No I/O.
//   - always: the audit actions and the alert obliwatch.push_dead (the journal and the alerts keep their labels after
//     the integration is turned off);
//   - with OBLIWATCH_INTEGRATION=on only: the restrictable action of the consent, the push job
//     integrations.obliwatch.push (lot L3) and the minute step (purge of the burned jti; the tenants with due
//     transitions asked again; once an hour, the purge of the transitions ended 30 days ago, 90 for a dead one). The
//     routes are mounted by app.ts (read API) and routes/index.ts (console), on the same switch. With the switch off,
//     the hot paths' hooks (integrations/obliwatch/signals.ts) return at once, without a statement.
// =============================================================================

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

  registerLegacyAgentMinuteStep('obliwatch', async (ctx) => {
    let purged = 0;
    try { purged = await purgeSeenJti(); } catch (err) { logger.warn({ err }, 'obliwatch minute step: seen jti not purged'); }
    let asked = 0;
    let transitionsPurged = 0;
    const hourly = minutes++ % 60 === 0;
    try {
      const tenants: number[] = [];
      await forEachTenant(ctx.dbActor, async (tenantId) => { tenants.push(tenantId); });
      asked = await requestDuePushes((payload, opts) => push.send(payload, opts), tenants);
      if (hourly) for (const tenantId of tenants) transitionsPurged += await purgeTransitions(tenantId);
    } catch (err) {
      logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) } }, 'obliwatch minute step: push not asked');
    }
    return { obliwatchJtiPurged: purged, obliwatchPushAsked: asked, obliwatchTransitionsPurged: transitionsPurged };
  });
}
