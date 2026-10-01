import { AppError } from '../middleware/errorHandler';

/** A critical action whose audit entry could not be written is not performed
 *  (docs: audit-durci §5.4): 503, code 'auditUnavailable', Retry-After: 30
 *  (errorHandler.ts). In a durable job, a retryable error. */
export class AuditUnavailableError extends AppError {
  /** SQLSTATE or internal code of the failure (never a value). */
  readonly reason: string;

  constructor(reason = 'unavailable') {
    super(503, 'The audit log is unavailable: the action was not performed', 'auditUnavailable');
    this.name = 'AuditUnavailableError';
    this.reason = reason;
  }
}

export { AuditBodyError } from './bodyError';

export function isAuditUnavailable(err: unknown): err is AuditUnavailableError {
  return err instanceof AuditUnavailableError || (err as { code?: unknown } | null)?.code === 'auditUnavailable';
}
