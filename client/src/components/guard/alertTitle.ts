import type { TFunction } from 'i18next';

// The server writes the live alerts of the guard engine in English, with a
// stable key that names them (audit-durci §10.10): guard:<action uuid>:<state>,
// guard:<uuid>:fallback, guard:freeze:…, guard:unfreeze:…, guard:a3:…,
// guard:grant:…, guard:credentials:…, guard:cooldown:…, guard:edge-freeze:…,
// guard:approver-lost:…. The console
// translates the title by that key (guard.alerts.<kind>), the server's text
// as the fallback.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The kind of a guard alert (null: not one). */
export function guardAlertKind(stableKey: string | null | undefined): string | null {
  if (!stableKey || !stableKey.startsWith('guard:')) return null;
  const parts = stableKey.split(':');
  if (parts.length >= 3 && UUID_RE.test(parts[1])) return parts[parts.length - 1];
  return parts[1] || null;
}

/** The title of a live alert, translated when it is one of the guard's. */
export function liveAlertTitle(alert: { title: string; stableKey?: string | null }, t: TFunction): string {
  const kind = guardAlertKind(alert.stableKey);
  if (!kind || !/^[a-z0-9_-]{1,40}$/.test(kind)) return alert.title;
  return t(`guard.alerts.${kind}`, alert.title) || alert.title;
}
