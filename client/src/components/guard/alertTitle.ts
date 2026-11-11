import type { TFunction } from 'i18next';

// The server writes the live alerts in English. Two ways to translate them:
//   - the alerts of the guard engine carry a stable key that names them
//     (audit-durci §10.10): guard:<action uuid>:<state>, guard:<uuid>:fallback,
//     guard:freeze:…, guard:unfreeze:…, guard:a3:…, guard:grant:…,
//     guard:credentials:…, guard:cooldown:…, guard:edge-freeze:…,
//     guard:approver-lost:…; the console translates the title by that key
//     (guard.alerts.<kind>);
//   - the alerts of a module's catalogue (Apple integration: integration-
//     apple-edge §12.1, I11) carry their i18n key and scalar parameters: the
//     console translates `${i18nKey}.title` and `${i18nKey}.message`;
//   - the alerts of the Android integration (server/src/android/alerts.ts) write
//     their key and parameters in the message itself, "i18n:<key> <JSON>"
//     (alerts.android.<name>): read as an i18n key and its parameters.
// The server's text is the fallback (the raw marker of an Android alert never
// is: the message is then empty).

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** An i18n key of a module's catalogue (apple.alerts.<family>.<name>). */
const I18N_KEY_RE = /^[a-z][a-z0-9]*(\.[a-z0-9_-]+){1,5}$/;

/** The kind of a guard alert (null: not one). */
export function guardAlertKind(stableKey: string | null | undefined): string | null {
  if (!stableKey || !stableKey.startsWith('guard:')) return null;
  const parts = stableKey.split(':');
  if (parts.length >= 3 && UUID_RE.test(parts[1])) return parts[parts.length - 1];
  return parts[1] || null;
}

interface TranslatableAlert {
  title: string;
  message?: string | null;
  stableKey?: string | null;
  i18nKey?: string | null;
  i18nParams?: Record<string, string | number | boolean> | null;
}

/** Scalars only. */
function scalars(params: unknown): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  if (!params || typeof params !== 'object' || Array.isArray(params)) return out;
  for (const [k, v] of Object.entries(params as Record<string, unknown>)) {
    if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') out[k] = v;
  }
  return out;
}

/** The i18n key and the parameters an Android alert writes in its message ("i18n:alerts.android.x {...}"), or null. */
export function markedMessage(message: string | null | undefined): { key: string; params: Record<string, string | number | boolean> } | null {
  const m = /^i18n:(\S+)(?:\s+([\s\S]*))?$/.exec(message ?? '');
  if (!m || !I18N_KEY_RE.test(m[1])) return null;
  let params: unknown = null;
  if (m[2]) { try { params = JSON.parse(m[2]); } catch { params = null; } }
  return { key: m[1], params: scalars(params) };
}

/** The i18n key of an alert and its parameters: the fields of a module's catalogue, else the marker of its message. */
function i18nOf(alert: TranslatableAlert): { key: string; params: Record<string, string | number | boolean> } | null {
  if (alert.i18nKey && I18N_KEY_RE.test(alert.i18nKey)) return { key: alert.i18nKey, params: scalars(alert.i18nParams) };
  return markedMessage(alert.message);
}

/** The title of a live alert, translated when it is one of the guard's or of a module's catalogue. */
export function liveAlertTitle(alert: TranslatableAlert, t: TFunction): string {
  const i18n = i18nOf(alert);
  if (i18n) return t(`${i18n.key}.title`, { ...i18n.params, defaultValue: alert.title }) || alert.title;
  const kind = guardAlertKind(alert.stableKey);
  if (!kind || !/^[a-z0-9_-]{1,40}$/.test(kind)) return alert.title;
  return t(`guard.alerts.${kind}`, alert.title) || alert.title;
}

/** The message of a live alert, translated when it is one of a module's catalogue. */
export function liveAlertMessage(alert: TranslatableAlert, t: TFunction): string {
  const marked = markedMessage(alert.message);
  const fallback = marked ? '' : (alert.message ?? '');
  const i18n = i18nOf(alert);
  if (i18n) return t(`${i18n.key}.message`, { ...i18n.params, defaultValue: fallback }) || fallback;
  return fallback;
}
