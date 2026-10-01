// The error of a body the writer refuses before it reaches the database (bad
// action name, undeclared action in strict mode, oversized body): a defect of
// the calling code, never retried. No import (the unit tests load body.ts
// natively).
export class AuditBodyError extends Error {
  readonly code = 'audit_body';

  constructor(message: string) {
    super(`audit: ${message}`);
    this.name = 'AuditBodyError';
  }
}
