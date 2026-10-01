import { AsyncLocalStorage } from 'node:async_hooks';

// The approval request an executor is carrying out (approval.service.ts sets
// it around the execution): the audit entries the execution writes name it
// (audit-durci §3.1, `approvals`). No import, so that any service can read it.

const scope = new AsyncLocalStorage<{ approvalId: number }>();

export function runInApprovalScope<T>(approvalId: number, fn: () => Promise<T>): Promise<T> {
  return scope.run({ approvalId }, fn);
}

/** The approval being executed (as `approvals` of an entry), or undefined. */
export function currentApprovalIds(): number[] | undefined {
  const s = scope.getStore();
  return s ? [s.approvalId] : undefined;
}
