import { registerAlertDefinitions } from '../services/alertCatalog';
import { exemptFromApiLimiter } from '../middleware/rateLimiter';
import { benchAlertDefinitions } from '../bench/alerts';
import { registerBenchAuditActions } from '../bench/audit';
import { benchExpireStep } from '../bench/jobs';
import { registerLegacyAgentMinuteStep } from '../legacyAgent/jobs';

// =============================================================================
// BENCH STATIONS (lot BANC; spec banc-spec §3): their hooks into the core's registries, registered here and only here;
// index.ts calls registerBenchModule() right after registerLegacyAgentModule() (the bench is part of the channel of the
// bridge agent: its minute job, its alerts' service), before anything starts. The surface /api/bench and the console
// routes are mounted by routes/index.ts. No I/O.
// =============================================================================

let registered = false;

export function registerBenchModule(): void {
  if (registered) return;
  registered = true;
  registerBenchAuditActions();
  registerAlertDefinitions('bench', benchAlertDefinitions());
  registerLegacyAgentMinuteStep('bench-expire', benchExpireStep);
  // The stations poll /api/bench/stations/me without a session, each behind its own limiters (guard.ts, api.routes.ts):
  // they never eat the budget of the login page.
  exemptFromApiLimiter('/api/bench/');
}
