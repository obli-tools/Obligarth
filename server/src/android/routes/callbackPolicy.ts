// What the public signup callback answers (AN48), pure (unit tests U-A17): fixed headers, a redirection to a fixed
// page of the console (never a URL received), and the log-safe form of its request (no query: `s` and the
// enterpriseToken never reach a log line).

export const CALLBACK_PATH = '/api/android/signup/callback';
export const CALLBACK_RETURN_PAGE = '/integrations/android/return';
export const CALLBACK_RATE_PER_MINUTE = 10;

export const CALLBACK_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  Pragma: 'no-cache',
});

/** The fixed redirection: the console's return page, 'ok' or 'error' only. */
export function callbackRedirect(result: 'ok' | 'error'): string {
  return `${CALLBACK_RETURN_PAGE}?result=${result === 'ok' ? 'ok' : 'error'}`;
}

/** A URL as it may be logged: its path only, the query removed. */
export function redactCallbackUrl(url: string): string {
  const i = url.indexOf('?');
  return i < 0 ? url : `${url.slice(0, i)}?[redacted]`;
}
