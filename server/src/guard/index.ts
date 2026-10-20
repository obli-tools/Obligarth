// The guard engine against mass erasure (docs: audit-durci §10, PLT-11,
// D23-D24): the only way to a destructive action. A module declares its
// guarded actions (registerGuardedAction) and the providers the engine
// reads (fleet size, ownership, the handlers of a freeze); routes and modules
// request an action through guard.request(req, input). Registration in the
// core's registries: module.ts (registerGuardModule, called by index.ts).
import { request, preview, GuardStepUpError } from './engine';
import { guardMetrics } from './metrics';

export {
  registerGuardedAction, registerGuardedActionChannel, registerFleetSizeProvider, registerOwnershipProvider, registerEdgeFreezeHandler,
  registerFreezeHandler,
  guardedActionDef, guardedActionList,
} from './catalog';
export { GuardStepUpError } from './engine';
export type { GuardedChannelImpl } from './channels';
export { registerGuardModule } from './module';
export { createGuardRouter } from './routes';
export type {
  GuardedActionDef, GuardExecutionContext, GuardTargetRefusal, GuardTargetResult, FleetSizeProvider, OwnershipProvider,
  EdgeFreezeHandler, FreezeHandler, DeviceOwnership, ManagementChannel,
} from './types';

export const guard = {
  /** The request of a guarded action (audit-durci §10.3). */
  request,
  /** Level, delay, confirmation and quota of a request, without effect. */
  preview,
  StepUpError: GuardStepUpError,
  /** Values for the observability work (FND-14). */
  metricsSnapshot: () => guardMetrics.snapshot(),
};
