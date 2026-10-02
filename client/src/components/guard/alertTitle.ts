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
//     console translates `${i18nKey}.title` and `${i18nKey}.message`.
// The server's text is the fallback in both cases.

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

/** The parameters of a translated text: scalars only. */
function paramsOf(alert: TranslatableAlert): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(alert.i18nParams ?? {})) {
    if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') out[k] = v;
  }
  return out;
}

/** The title of a live alert, translated when it is one of the guard's or of a module's catalogue. */
export function liveAlertTitle(alert: TranslatableAlert, t: TFunction): string {
  if (alert.i18nKey && I18N_KEY_RE.test(alert.i18nKey)) {
    return t(`${alert.i18nKey}.title`, { ...paramsOf(alert), defaultValue: alert.title }) || alert.title;
  }
  const kind = guardAlertKind(alert.stableKey);
  if (!kind || !/^[a-z0-9_-]{1,40}$/.test(kind)) return alert.title;
  return t(`guard.alerts.${kind}`, alert.title) || alert.title;
}

/** The message of a live alert, translated when it is one of a module's catalogue. */
export function liveAlertMessage(alert: TranslatableAlert, t: TFunction): string {
  const fallback = alert.message ?? '';
  if (alert.i18nKey && I18N_KEY_RE.test(alert.i18nKey)) {
    return t(`${alert.i18nKey}.message`, { ...paramsOf(alert), defaultValue: fallback }) || fallback;
  }
  return fallback;
}
