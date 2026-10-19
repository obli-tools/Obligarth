import { guardReviewerPolicy } from '../guard/approvals';
import { registerBootTask } from '../lifecycle';
import { registerApprovalRequestType } from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { logger } from '../utils/logger';
import { findSecretRefs, registerSecretReferenceHolder } from '../vault/registry';
import { registerLegacyAgentAuditActions } from '../legacyAgent/audit';
import { signersFromEnv } from '../legacyAgent/config';
import { registerLegacyAgentGuardedActions } from '../legacyAgent/guarded';
import { registerLegacyAgentJobs } from '../legacyAgent/jobs';
import { executeLegacyAgentAction } from '../legacyAgent/routes';
import { ensureServerKey, registerServerKeySecretName } from '../legacyAgent/serverKey';

// =============================================================================
// ANDROID BRIDGE AGENT (channel legacy_agent; docs: agent-pont-android §6):
// its hooks into the core's registries, registered here and only here;
// index.ts calls registerLegacyAgentModule() right after registerAppleModule()
// (the alerts and the freeze of the Apple integration serve it), before
// anything starts. No I/O but the boot task. The surface /agent/v1 is mounted
// by app.ts, the console routes by routes/index.ts.
// =============================================================================

/** The restrictable actions of the agent (§5.4): no floor but the revocation's ('sensitive'). */
export const LEGACY_AGENT_RESTRICTABLE_ACTIONS = [
  { key: 'legacy_agent.message', label: 'Show a message on Android agent devices', category: 'Android agent' },
  { key: 'legacy_agent.restart', label: 'Restart Android agent devices', category: 'Android agent' },
  { key: 'legacy_agent.apps', label: 'Install or remove apps on Android agent devices', category: 'Android agent' },
  { key: 'legacy_agent.update', label: 'Update the Android agent', category: 'Android agent' },
  { key: 'legacy_agent.revoke', label: 'Revoke an Android agent', category: 'Android agent' },
] as const;

let registered = false;

export function registerLegacyAgentModule(): void {
  if (registered) return;
  registered = true;

  registerServerKeySecretName();
  registerLegacyAgentAuditActions();
  registerLegacyAgentJobs();
  // Guarded actions first: their keys open the category of the matrix.
  registerLegacyAgentGuardedActions();
  registerRestrictableActions(LEGACY_AGENT_RESTRICTABLE_ACTIONS, {}, { 'legacy_agent.revoke': { level: 'sensitive' } });
  // A command the matrix holds at 'restricted': a second person approves it (the guard's examination policy), with
  // a strict step-up of the reviewer, like apple_action.
  registerApprovalRequestType('legacy_agent_action', executeLegacyAgentAction, { expiryMinutes: 240, reviewerPolicy: guardReviewerPolicy, reviewerStepUp: 'strict' });
  // The Knox licence key of a tenant: a sealed tenant secret referenced by legacy_agent_settings (never collected).
  registerSecretReferenceHolder({
    table: 'legacy_agent_settings', column: 'knox_license', tenantColumn: 'tenant_id',
    refs: (v) => findSecretRefs(typeof v === 'string' ? JSON.parse(v) : v),
  });

  const { signers, invalid } = signersFromEnv();
  if (invalid > 0) logger.warn({ invalid }, 'LEGACY_AGENT_SIGNERS: entries that are not SHA-256 fingerprints are ignored');
  if (signers.length === 0) logger.info('LEGACY_AGENT_SIGNERS is empty: no version of the Android agent can be uploaded');

  // The instance key (§4.3, RS-1): loaded, or created on a fresh instance; never replaced. A failure does not stop
  // the server: the surface answers 503 until the key is back, and an alert says why.
  registerBootTask('legacy-agent.server-key', async () => {
    try {
      const r = await ensureServerKey();
      logger.info({ state: r.state }, 'legacy agent: instance key');
    } catch (err) {
      logger.error({ code: (err as { code?: unknown })?.code, message: (err as Error)?.message?.slice(0, 200) }, 'legacy agent: instance key not loaded at start');
    }
  });
}
