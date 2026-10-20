import { registerBootTask } from '../../lifecycle';
import { onTargetFinal, registerCommandResultIngestor } from '../commands/results';
import { registerOnboardStep } from '../../mdm/registry/onboard';
import { coreProvider } from './core.provider';
import { freezeDeclarationProviders, registerDeclarationProvider } from './engine';
import { registerDdmJobs, requestDeviceSync } from './jobs';
import { DDM_REQUEST_TYPE, ingestDeclarativeManagement, onSyncTargetFinal } from './sync';

// =============================================================================
// DDM engine: its hooks into the registries of the Apple integration (docs:
// integration-apple-edge §3.3, §9), called by registerAppleModule(). No I/O.
//   - the core provider (status subscriptions and its activation);
//   - the five queues apple.ddm.* (annex B);
//   - the ingestor of the result of DeclarativeManagement (§7.6) and the hook
//     of the end of a synchronisation command (§9.4);
//   - the onboarding step of a device: its first synchronisation (§8.10).
// The relay (POST /internal/apple-edge/ddm) is mounted by app.ts, the console
// API by routes/index.ts. The sender of the DeclarativeManagement command is
// registered by the command queue (registerDdmSyncSender, ddm/sync.ts).
// =============================================================================

export { registerDeclarationProvider, requestDdmRecompute } from './engine';
export type { DeclarationProvider, DeclarationSpec, DdmClientCapabilities, DdmDeviceContext, DeclarationFamily, JsonValue } from './engine';
export { registerDdmSyncSender } from './sync';
export type { DdmSyncCommand, DdmSyncSender, DdmSyncSendOutcome } from './sync';
export { registerStatusHook } from './status';
export type { StatusHook } from './status';
export type { DeclarationStatus } from './report';

let registered = false;

export function registerAppleDdm(): void {
  if (registered) return;
  registered = true;
  registerDeclarationProvider(coreProvider);
  registerDdmJobs();
  // Acknowledged: the DDM is active on the device; in error: counted, nothing sent again before the set changes.
  registerCommandResultIngestor({ requestType: DDM_REQUEST_TYPE, mode: 'inline', alsoOnError: true, apply: ingestDeclarativeManagement });
  onTargetFinal('ddm.sync', onSyncTargetFinal);
  // The onboarding of a device (apple.device-onboard, first TokenUpdate of a cycle): its set computed and announced,
  // which activates the DDM on the device. Idempotent: the queue groups the requests of a device.
  registerOnboardStep('apple_mdm', { name: 'ddm.sync', run: async ({ tenantId, deviceId }) => { await requestDeviceSync(null, tenantId, [deviceId]); } });
  // Providers are registered by the modules before the jobs start; none joins a running engine.
  registerBootTask('apple.ddm-providers', async () => { freezeDeclarationProviders(); });
}
