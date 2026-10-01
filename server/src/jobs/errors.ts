// =============================================================================
// Errors of the jobs, and what may be kept of them
// =============================================================================
//
// pg-boss stores a job's output in clear (pgboss.job.output, kept for days and
// in the backups): an exception left to reach it would store its stack and its
// message, and a PostgreSQL message can carry values (the serial number of a
// unique key, a rejected literal). The execution envelope (wrapper.ts) stores
// only { code, message } from sanitizeError; the logs get safeErr.

/** An error a job handler raises on purpose. The message is written by the
 *  developer, in English, without personal data nor external identifier: it
 *  is the only part of an error stored in pgboss.job and job_status. */
export class JobError extends Error {
  constructor(readonly code: string, message: string, readonly retryable = true) {
    super(message);
    this.name = 'JobError';
  }
}

/** An error waiting cannot heal: straight to the dead letters, no retry
 *  spent. */
export class PermanentJobError extends JobError {
  constructor(code: string, message: string) {
    super(code, message, false);
    this.name = 'PermanentJobError';
  }
}

/** Data and programming errors never heal by waiting: straight to the dead letters. */
const PERMANENT_PG_CLASSES = ['22', '42'];                       // data exception, syntax or undefined object
const PERMANENT_PG_CODES = new Set(['23502', '23503', '23514']); // not null, foreign key, check

const SQLSTATE_RE = /^[0-9A-Z]{5}$/;

export interface SanitizedError {
  code: string;
  message: string;
  retryable: boolean;
}

/** The code and message a failed attempt may store, and whether a retry can
 *  help. */
export function sanitizeError(err: unknown): SanitizedError {
  if (err instanceof JobError) {
    return { code: err.code.slice(0, 64), message: err.message.slice(0, 200), retryable: err.retryable };
  }
  // The journal refused a critical entry (audit-durci §5.4): transient.
  if ((err as { code?: unknown } | null)?.code === 'auditUnavailable') {
    return { code: 'audit_unavailable', message: 'the audit log is unavailable', retryable: true };
  }
  const pg = err as { code?: unknown; constraint?: unknown } | null;
  if (pg && typeof pg.code === 'string' && SQLSTATE_RE.test(pg.code)) {
    const permanent = PERMANENT_PG_CODES.has(pg.code) || PERMANENT_PG_CLASSES.includes(pg.code.slice(0, 2));
    const constraint = typeof pg.constraint === 'string' && /^[a-z_][a-z0-9_]{0,62}$/.test(pg.constraint)
      ? ` (${pg.constraint})` : '';
    return { code: `pg_${pg.code}`, message: `database error${constraint}`, retryable: !permanent };
  }
  if ((err as Error | null)?.name === 'AbortError') return { code: 'aborted', message: 'attempt aborted', retryable: true };
  return { code: 'internal_error', message: 'internal error', retryable: true };
}

/** Fields of a PostgreSQL (pg) error that name things, never values. */
const PG_SAFE_FIELDS = ['code', 'severity', 'constraint', 'table', 'column', 'schema', 'routine', 'dataType'] as const;

/** An error as it may be logged: name, code, the names a PostgreSQL error
 *  gives (constraint, table, column, routine) and the stack frames; never
 *  the message nor the detail of a PostgreSQL error (they can carry values),
 *  nor the query and parameters a Knex error carries. */
export function safeErr(err: unknown): Record<string, unknown> {
  if (err === null || err === undefined) return { message: String(err) };
  if (typeof err !== 'object') return { message: String(err).slice(0, 200) };
  const e = err as Record<string, unknown> & { name?: unknown; message?: unknown; stack?: unknown };
  const name = typeof e.name === 'string' ? e.name : 'Error';
  const isPg = typeof e.code === 'string' && SQLSTATE_RE.test(e.code);
  // `name` as well as `type`: pino's error serializer rewrites `type` from
  // the constructor (here, a plain object).
  const out: Record<string, unknown> = { type: name, name };
  if (isPg) {
    for (const f of PG_SAFE_FIELDS) if (typeof e[f] === 'string') out[f] = e[f];
    out.message = 'database error';
  } else {
    if (typeof e.code === 'string' || typeof e.code === 'number') out.code = e.code;
    if (typeof e.message === 'string') out.message = e.message.slice(0, 500);
  }
  if (typeof e.stack === 'string') {
    // The stack's head repeats the message (and, for Knex, the query):
    // replaced by the name and the kept message; the frames stay.
    const at = e.stack.indexOf('\n    at ');
    const frames = at >= 0 ? e.stack.slice(at) : '';
    out.stack = `${name}: ${String(out.message ?? '')}${frames}`;
  }
  return out;
}

/** Is this the error a late completion raises once pg-boss closed its pool
 *  (stop at the end of the grace period)? Expected, logged as a warning. */
export function isPoolClosedError(err: unknown): boolean {
  const message = String((err as { message?: unknown } | null)?.message ?? '');
  return /Database not opened|Database connection is not opened|Cannot use a pool after calling end/i.test(message);
}
