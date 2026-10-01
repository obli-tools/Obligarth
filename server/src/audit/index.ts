// The hardened audit journal (docs: audit-durci.md, PLT-12): the only way the
// server writes the journal. The registration in the core's registries
// (jobs, restrictable actions, approval executors, exporter) is in
// module.ts (registerAuditModule, called by index.ts with the other modules).
//
//   audit.append(entry, ctx)             own transaction; 'critical' throws
//                                        AuditUnavailableError when not written,
//                                        the other classes spool, never throw
//   audit.appendInTx(trx, entry, ctx)    P1, in the caller's transaction, last
//                                        statement before the commit
//   audit.appendManyInTx(trx, entries)   several chains, ascending tenant order
//   audit.withIntent(entry, ctx, fn)     P2: critical intent, fn, result
//   audit.prepare(entry, ctx)            body for a SQL function that appends it
//   audit.fromRequest / fromJob / system contexts of an entry
import { forgetAuditActor, fromDbActor, fromJob, fromRequest, system } from './actor';
import { auditMetrics } from './metrics';
import { append, appendInTx, appendManyInTx, prepare, withIntent } from './writer';

export { registerAuditAction, registerAuditActions, auditActionDef, auditActionList, isDeclaredAction } from './catalog';
export { AuditUnavailableError, AuditBodyError, isAuditUnavailable } from './errors';
export { canonicalJson } from './canonical';
export { linkHash } from './chain';
export { forgetAuditActor } from './actor';
export type {
  AuditActor, AuditActionDef, AuditAppendResult, AuditEntryInput, AuditOrigin, AuditWriteContext, AuditTargets,
} from './types';

export const audit = {
  append,
  appendInTx,
  appendManyInTx,
  withIntent,
  prepare,
  fromRequest,
  fromJob,
  system,
  fromDbActor,
  forgetActor: forgetAuditActor,
  /** Values for the observability work (FND-14). */
  metricsSnapshot: () => auditMetrics.snapshot(),
};
