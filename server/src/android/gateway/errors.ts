// Errors of the Android gateway and their correspondence (Google answer → instance error → effect in a job or a
// route). Pure: no database import, erasable TypeScript only (unit tests under node --test). Messages never carry
// a request body, a token nor a value received from Google beyond a cleaned 500-character message.

export type AndroidErrorKind =
  | 'disabled' | 'request' | 'auth' | 'access_lost' | 'ownership' | 'not_found' | 'frozen' | 'quota'
  | 'destructive_cap' | 'rate_limited' | 'unavailable';

export class AndroidError extends Error {
  readonly kind: AndroidErrorKind;
  /** May a durable job try again later? */
  readonly retryable: boolean;
  readonly details: Record<string, unknown>;
  constructor(kind: AndroidErrorKind, message: string, retryable: boolean, details: Record<string, unknown> = {}) {
    super(message);
    this.name = 'AndroidError';
    this.kind = kind;
    this.retryable = retryable;
    this.details = details;
  }
}

export class AndroidDisabledError extends AndroidError {
  constructor() { super('disabled', 'the Android integration is off', false); this.name = 'AndroidDisabledError'; }
}
export class AndroidRequestError extends AndroidError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super('request', message, false, details);
    this.name = 'AndroidRequestError';
  }
}
export class AndroidAuthError extends AndroidError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super('auth', message, true, details);
    this.name = 'AndroidAuthError';
  }
}
export class AndroidAccessLostError extends AndroidError {
  constructor(message = 'access to the enterprise lost') { super('access_lost', message, false); this.name = 'AndroidAccessLostError'; }
}
export class AndroidOwnershipError extends AndroidError {
  constructor(reason: string) { super('ownership', `ownership check refused: ${reason}`, false, { reason }); this.name = 'AndroidOwnershipError'; }
}
export class AndroidNotFoundError extends AndroidError {
  constructor(message = 'not found') { super('not_found', message, false); this.name = 'AndroidNotFoundError'; }
}
export class AndroidFrozenError extends AndroidError {
  constructor(op: string) { super('frozen', `the tenant is frozen: ${op} refused`, false, { op }); this.name = 'AndroidFrozenError'; }
}
export class AndroidQuotaError extends AndroidError {
  constructor(message = 'device quota reached') { super('quota', message, false); this.name = 'AndroidQuotaError'; }
}
export class AndroidDestructiveCapError extends AndroidError {
  constructor(kind: string, count: number, cap: number) {
    super('destructive_cap', `last-resort cap reached for ${kind}`, false, { kind, count, cap });
    this.name = 'AndroidDestructiveCapError';
  }
}
export class AndroidRateLimitedError extends AndroidError {
  readonly retryAfterSeconds: number;
  constructor(retryAfterSeconds: number) {
    super('rate_limited', 'rate limited', true, { retryAfterSeconds });
    this.name = 'AndroidRateLimitedError';
    this.retryAfterSeconds = retryAfterSeconds;
  }
}
export class AndroidUnavailableError extends AndroidError {
  constructor(message = 'Google unavailable') { super('unavailable', message, true); this.name = 'AndroidUnavailableError'; }
}

/** A response over its byte limit (a pull retries with fewer messages, never acknowledging). */
export class AndroidResponseTooLargeError extends AndroidUnavailableError {
  constructor() { super('response too large'); this.name = 'AndroidResponseTooLargeError'; }
}

export const isAndroidError = (err: unknown): err is AndroidError => err instanceof AndroidError;

/** Retry-After in seconds, bounded to [1, 600]; `dflt` when absent or unreadable. */
export function retryAfterSeconds(header: string | null | undefined, dflt = 5): number {
  if (!header) return dflt;
  const n = /^[0-9]{1,6}$/.test(header.trim()) ? Number(header.trim()) : Math.ceil((Date.parse(header) - Date.now()) / 1000);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(600, Math.max(1, n));
}

/** A Google error message, cleaned: control characters removed, 500 characters at most, no quoted value. */
export function cleanGoogleMessage(message: unknown): string {
  if (typeof message !== 'string') return '';
  return message.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/"[^"]{0,2000}"/g, '"…"').slice(0, 500);
}

/** Where the answer came from: an enterprise resource, or the project (subscription, enterprises.list, token). */
export type GoogleScope = 'enterprise' | 'project';

/**
 * The error of a non-2xx answer of Google. `read`: a GET (a 404 then means null for the caller, signalled by a null
 * return). Section 5.5 of the specification.
 */
export function googleErrorFor(status: number, body: unknown, o: { scope: GoogleScope; retryAfter?: string | null; read?: boolean }):
  AndroidError | null {
  const err = (body && typeof body === 'object' ? (body as { error?: { message?: unknown; status?: unknown; details?: unknown } }).error : undefined) ?? {};
  const message = cleanGoogleMessage(err.message);
  const gStatus = typeof err.status === 'string' ? err.status : '';
  if (status === 400) {
    const field = Array.isArray(err.details)
      ? (err.details as Array<{ fieldViolations?: Array<{ field?: unknown }> }>).flatMap((d) => d.fieldViolations ?? [])
        .map((v) => v.field).find((f) => typeof f === 'string')
      : undefined;
    return new AndroidRequestError(message || 'invalid request', typeof field === 'string' ? { field: field.slice(0, 200) } : {});
  }
  if (status === 401) return new AndroidAuthError('access token refused');
  if (status === 403) return o.scope === 'enterprise' ? new AndroidAccessLostError() : new AndroidAuthError('permission denied on the project');
  if (status === 404) return o.read ? null : new AndroidNotFoundError();
  if (status === 409) return new AndroidRequestError(message || 'conflict', { conflict: true });
  if (status === 429) {
    if (gStatus === 'RESOURCE_EXHAUSTED' && /usage limit/i.test(message)) return new AndroidQuotaError('device quota of the project reached');
    return new AndroidRateLimitedError(retryAfterSeconds(o.retryAfter ?? null, 5));
  }
  if (status >= 500) return new AndroidUnavailableError(`Google answered ${status}`);
  return new AndroidRequestError(message || `unexpected status ${status}`);
}

/** HTTP answer of a route for an Android error: [status, code]. Section 5.5, last column. */
export function routeStatusOf(err: AndroidError): { status: number; code: string } {
  switch (err.kind) {
    case 'disabled': return { status: 503, code: 'androidDisabled' };
    case 'request': return { status: 422, code: 'androidInvalidRequest' };
    case 'auth': return { status: 503, code: 'androidGoogleUnavailable' };
    case 'access_lost': return { status: 409, code: 'androidEnterpriseAccessLost' };
    case 'ownership': return { status: 404, code: 'notFound' };
    case 'not_found': return { status: 404, code: 'notFound' };
    case 'frozen': return { status: 423, code: 'tenantFrozen' };
    case 'quota': return { status: 409, code: 'androidQuotaReached' };
    case 'destructive_cap': return { status: 423, code: 'tenantFrozen' };
    case 'rate_limited': return { status: 503, code: 'androidRateLimited' };
    case 'unavailable': return { status: 503, code: 'androidGoogleUnavailable' };
    default: return { status: 500, code: 'internalError' };
  }
}

/** Effect of an Android error in a durable job (section 5.5, third column). */
export type JobEffect = 'retry' | 'dead_letter' | 'held_frozen' | 'held_cap' | 'enterprise_error' | 'hold_all';

export function jobEffectOf(err: AndroidError): JobEffect {
  switch (err.kind) {
    case 'rate_limited': case 'unavailable': return 'retry';
    case 'auth': return err.message === 'permission denied on the project' ? 'hold_all' : 'retry';
    case 'access_lost': return 'enterprise_error';
    case 'frozen': return 'held_frozen';
    case 'destructive_cap': return 'held_cap';
    default: return 'dead_letter';
  }
}
