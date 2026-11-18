import { registerLegacyAgentMinuteStep } from '../legacyAgent/jobs';
import { registerRestrictableActions } from '../services/restriction.service';
import { logger } from '../utils/logger';
import { registerObliwatchAuditActions } from '../integrations/obliwatch/audit';
import { obliwatchIntegrationEnabled } from '../integrations/obliwatch/config';
import { purgeSeenJti } from '../integrations/obliwatch/jti';

// =============================================================================
// OBLIWATCH INTEGRATION (brief GTH-01..09; plan §0 F6): its hooks into the core's registries, registered here and
// only here; index.ts calls registerObliwatchModule() after the MCP module, before Android. No I/O.
//   - always: the audit actions (the journal keeps their labels after the integration is turned off);
//   - with OBLIWATCH_INTEGRATION=on only: the restrictable action of the consent and the minute step (purge of the
//     burned jti). The routes are mounted by app.ts (read API) and routes/index.ts (console), on the same switch.
// =============================================================================

export const OBLIWATCH_RESTRICTABLE_ACTIONS = [
  { key: 'obliwatch.settings_change', label: 'Change the Obliwatch consent of the tenant', category: 'Obliwatch' },
] as const;

let registered = false;

export function registerObliwatchModule(): void {
  if (registered) return;
  registered = true;

  registerObliwatchAuditActions();
  if (!obliwatchIntegrationEnabled()) return;

  registerRestrictableActions(OBLIWATCH_RESTRICTABLE_ACTIONS, {}, {
    'obliwatch.settings_change': { level: 'sensitive', strictStepUp: true },
  });

  registerLegacyAgentMinuteStep('obliwatch', async () => {
    let purged = 0;
    try { purged = await purgeSeenJti(); } catch (err) { logger.warn({ err }, 'obliwatch minute step: seen jti not purged'); }
    return { obliwatchJtiPurged: purged };
  });
}
