import i18n from 'i18next';

// The server answers an error as { success: false, error, code, details? } (AppError): `error` is an English
// sentence for the logs, `code` a stable camelCase name the console translates (errors.<code>).

export interface ApiErrorBody {
  error?: string;
  code?: string;
  details?: unknown;
}

/** The body of a failed API call, when the server answered one. */
export function apiErrorBody(err: unknown): ApiErrorBody | null {
  const body = (err as { response?: { data?: unknown } } | null)?.response?.data;
  return body && typeof body === 'object' ? (body as ApiErrorBody) : null;
}

export function apiErrorCode(err: unknown): string | undefined {
  const code = apiErrorBody(err)?.code;
  return typeof code === 'string' ? code : undefined;
}

export function apiErrorStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } } | null)?.response?.status;
}

/** Where the translations of the error codes live: the common ones, then those of the command queue and of the
 *  guard engine (delivered with their lots). */
export const ERROR_NAMESPACES = ['errors', 'apple.errors', 'guard.errors'] as const;

/** The translation of an error code, or null when the console has none for it. */
export function translateErrorCode(code: string | undefined, params?: Record<string, unknown>): string | null {
  if (!code || !/^[A-Za-z][A-Za-z0-9]*$/.test(code)) return null;
  for (const ns of ERROR_NAMESPACES) {
    const key = `${ns}.${code}`;
    if (i18n.exists(key)) return i18n.t(key, params ?? {});
  }
  return null;
}

/**
 * The message to show for a failed API call: the translation of its code, else the server's sentence, else
 * `fallback` (the generic error by default). The details of the answer are offered to the translation as
 * interpolation values when they are a flat object.
 */
export function apiErrorMessage(err: unknown, fallback?: string): string {
  const body = apiErrorBody(err);
  const details = body?.details && typeof body.details === 'object' && !Array.isArray(body.details)
    ? (body.details as Record<string, unknown>) : undefined;
  return translateErrorCode(body?.code, details)
    ?? (typeof body?.error === 'string' && body.error ? body.error : null)
    ?? fallback
    ?? i18n.t('common.error', 'An error occurred');
}

/**
 * The translation of a key built from a code of the server (an open set: reasons of a device, kinds of a
 * timeline entry, status items), or `fallback` when the console has none. `t(key) || fallback` cannot do it: a
 * missing key is returned as the key itself.
 */
export function trCode(key: string, fallback: string, params?: Record<string, unknown>): string {
  return i18n.exists(key) ? i18n.t(key, params ?? {}) : fallback;
}
