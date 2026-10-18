// Alerts of the Android integration (annex E, closed catalogue): platform alerts go to the live alerts of the master
// tenant (the operator), tenant alerts to the tenant's own; deduplicated on an unread alert of the same stable key.
// Texts carry an i18n key and identifiers only (never a device datum, a name nor an e-mail). The generic alert
// catalogue opened to modules (registerAlertDefinitions) arrives with the channel generalisation; until then the
// definitions live here.
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { db } from '../db';
import { asTenant, type DbActor } from '../db/context';
import { raiseJobAlert } from '../jobs/alerts';
import { liveAlertService, type LiveAlertSeverity } from '../services/liveAlert.service';
import { logger } from '../utils/logger';
import { ANDROID_LOG_FORBIDDEN_KEYS } from './gateway/redact';

export interface AndroidAlertDefinition {
  key: string;
  scope: 'platform' | 'tenant' | 'both';
  severity: LiveAlertSeverity;
  title: string;
}

const sev = (s: 'low' | 'medium' | 'high' | 'critical'): LiveAlertSeverity =>
  (s === 'critical' ? 'critical' : s === 'high' ? 'warning' : 'info') as LiveAlertSeverity;

export const ANDROID_ALERTS: readonly AndroidAlertDefinition[] = [
  { key: 'android.google_unreachable', scope: 'platform', severity: sev('high'), title: 'Android: Google unreachable' },
  { key: 'android.google_auth_failed', scope: 'platform', severity: sev('critical'), title: 'Android: Google identity refused' },
  { key: 'android.google_key_expiring', scope: 'platform', severity: sev('high'), title: 'Android: service account key expiring' },
  { key: 'android.quota_warning', scope: 'platform', severity: sev('medium'), title: 'Android: device quota at 80 %' },
  { key: 'android.quota_exhausted', scope: 'platform', severity: sev('high'), title: 'Android: device quota reached' },
  { key: 'android.inbox_dead_letter', scope: 'platform', severity: sev('medium'), title: 'Android: notification in the dead letters' },
  { key: 'android.retention_risk', scope: 'platform', severity: sev('high'), title: 'Android: notifications at risk of expiry' },
  { key: 'android.pubsub_foreign_message', scope: 'platform', severity: sev('critical'), title: 'Android: messages of unknown enterprises' },
  { key: 'android.pubsub_test_missing', scope: 'platform', severity: sev('high'), title: 'Android: Pub/Sub test message missing' },
  { key: 'android.ownership_violation', scope: 'platform', severity: sev('critical'), title: 'Android: ownership check refused a call' },
  { key: 'android.enterprise_orphan', scope: 'platform', severity: sev('medium'), title: 'Android: enterprise of the project not in the registry' },
  { key: 'android.signup_callback_rejected', scope: 'platform', severity: sev('critical'), title: 'Android: signup callbacks rejected' },
  { key: 'android.domain_claimed', scope: 'platform', severity: sev('critical'), title: 'Android: signup for a domain claimed by another tenant' },
  { key: 'android.enterprise_unlinked_externally', scope: 'tenant', severity: sev('critical'), title: 'Android: enterprise unlinked outside Obligarth' },
  { key: 'android.signup_failed', scope: 'tenant', severity: sev('medium'), title: 'Android: enterprise signup failed' },
  { key: 'android.signup_interrupted', scope: 'tenant', severity: sev('medium'), title: 'Android: enterprise signup interrupted' },
  { key: 'android.gateway_cap_reached', scope: 'both', severity: sev('critical'), title: 'Android: last-resort cap of destructive operations reached' },
  // Enrollment, policies, inventory (lot AN-C1b). enrollment.* reuse the keys of the existing tenant alerts.
  { key: 'enrollment.unknown_session', scope: 'tenant', severity: sev('medium'), title: 'Enrollments without a token of this tenant' },
  { key: 'enrollment.ownership_mismatch', scope: 'tenant', severity: sev('high'), title: 'Ownership or mode differs from the enrollment profile' },
  { key: 'enrollment.duplicate_serial', scope: 'tenant', severity: sev('medium'), title: 'Serial number held by a device under management' },
  { key: 'android.device_api_too_low', scope: 'tenant', severity: sev('medium'), title: 'Android: device below the minimum API level of its profile' },
  { key: 'android.enrollment_spike', scope: 'tenant', severity: sev('high'), title: 'Android: enrollment spike on a long token' },
  { key: 'android.policy_push_failed', scope: 'tenant', severity: sev('high'), title: 'Android: policy refused by Google' },
  { key: 'android.integrity_compromised', scope: 'tenant', severity: sev('critical'), title: 'Android: device integrity at risk' },
  // Lot AN-H1: operation (annex E, the catalogue made complete): approvals, quarantines, silent disappearances, deadlines.
  { key: 'android.device_pending_approval', scope: 'tenant', severity: sev('medium'), title: 'Android: devices waiting for their approval' },
  { key: 'android.quarantine_cap_reached', scope: 'tenant', severity: sev('critical'), title: 'Android: cap of quarantined enrollments reached' },
  { key: 'android.device_offline_long', scope: 'tenant', severity: sev('medium'), title: 'Android: devices without contact for 240 days' },
  { key: 'android.device_presumed_gone', scope: 'tenant', severity: sev('low'), title: 'Android: devices presumed gone' },
  { key: 'android.token_expiring', scope: 'tenant', severity: sev('low'), title: 'Android: long enrollment tokens to renew' },
];

const byKey = new Map(ANDROID_ALERTS.map((a) => [a.key, a]));
const PLATFORM_ACTOR: DbActor = { type: 'job', name: 'android.alerts' };

/**
 * The parameters of an alert text, reduced to identifiers and counts (criterion 13, G-A4, I11: no datum of the
 * extended T-5 list in an alert text). Kept: a key of letters only, and a value that is either an integer of at most
 * 12 digits (an internal identifier, a count; never an IMEI) or a lowercase code (reason, kind, hash, uuid) without '@'
 * that is not a long run of digits (a serial, an IMEI, a phone number). Anything else is dropped, its key logged.
 */
export function alertParams(params: Record<string, unknown>): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  const dropped: string[] = [];
  for (const [k, v] of Object.entries(params ?? {})) {
    if (!/^[A-Za-z]{1,32}$/.test(k)) { dropped.push('?'); continue; }
    if (FORBIDDEN_KEYS.has(k.toLowerCase())) { dropped.push(k); continue; }
    if (typeof v === 'number' && Number.isSafeInteger(v) && Math.abs(v) < 1e12) { out[k] = v; continue; }
    if (typeof v === 'string' && /^obg[0-9]*:/i.test(v)) { dropped.push(k); continue; }   // additionalData of a token (enrollmentTokenData)
    if (typeof v === 'string' && /^[a-z0-9][a-z0-9_.:-]{0,63}$/.test(v) && !/[0-9]{8,}/.test(v.replace(/[-_.:]/g, ''))
      || (typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v))) { out[k] = v; continue; }
    dropped.push(k);
  }
  if (dropped.length) logger.warn({ alertParamsDropped: dropped.slice(0, 10) }, 'android: alert parameters dropped (not an identifier)');
  return out;
}

const FORBIDDEN_KEYS = new Set([...ANDROID_LOG_FORBIDDEN_KEYS, 'serial', 'phone', 'email', 'name', 'tokendata'].map((k) => k.toLowerCase()));

const suffixOf = (s: string): string => (/^[A-Za-z0-9:_-]{1,64}$/.test(s) ? s : '');

/** The text of an Android alert: the i18n key and the reduced parameters (the console translates alerts.<key>). */
export function alertMessage(key: string, params: Record<string, unknown>): string {
  return `i18n:alerts.${key} ${JSON.stringify(alertParams(params)).slice(0, 400)}`;
}

/** Raises a platform alert (master tenant); never throws. `params`: identifiers and counts only. */
export async function raiseAndroidPlatformAlert(key: string, params: Record<string, string | number> = {}, dedupSuffix = ''): Promise<void> {
  const def = byKey.get(key);
  if (!def || def.scope === 'tenant') { logger.error({ alert: key }, 'android: undeclared platform alert'); return; }
  const suffix = suffixOf(dedupSuffix);
  await raiseJobAlert(PLATFORM_ACTOR, {
    stableKey: `${key}${suffix ? `:${suffix}` : ''}`,
    severity: def.severity,
    title: def.title,
    message: alertMessage(key, params),
  });
}

/** Raises a tenant alert in `tenantId`; never throws. */
export async function raiseAndroidTenantAlert(tenantId: number, key: string, params: Record<string, string | number> = {}): Promise<void> {
  const def = byKey.get(key);
  if (!def || def.scope === 'platform') { logger.error({ alert: key }, 'android: undeclared tenant alert'); return; }
  try {
    await asTenant(tenantId, PLATFORM_ACTOR, () => liveAlertService.add(tenantId, {
      severity: def.severity, title: def.title, message: alertMessage(key, params),
      navigateTo: null, stableKey: key,
    }));
  } catch (err) {
    logger.error({ alert: key, tenantId, err: (err as Error)?.name }, 'android: tenant alert not written');
  }
}

/**
 * The definitions of the Android alerts in the shape of the alert catalogue opened to modules (registerAlertDefinitions,
 * junction AN-P): key, scope, severity, title (English), i18n key of the text. Until then they live in this module.
 */
export function androidAlertDefinitions(): Array<AndroidAlertDefinition & { i18nKey: string }> {
  return ANDROID_ALERTS.map((a) => ({ ...a, i18nKey: `alerts.${a.key}` }));
}

/** Resolves a platform alert (master tenant; the stable key with its suffix); never throws. */
export async function resolveAndroidPlatformAlert(key: string, dedupSuffix = ''): Promise<void> {
  const def = byKey.get(key);
  if (!def || def.scope === 'tenant') return;
  const suffix = suffixOf(dedupSuffix);
  try {
    await asTenant(MASTER_TENANT_ID, PLATFORM_ACTOR, () => db('live_alerts').where({ tenant_id: MASTER_TENANT_ID, stable_key: `${key}${suffix ? `:${suffix}` : ''}` })
      .whereNull('resolved_at').update({ resolved_at: db.fn.now() }));
  } catch (err) {
    logger.error({ alert: key, err: (err as Error)?.name }, 'android: platform alert not resolved');
  }
}

/** Resolves an alert of a tenant (the condition is gone: contact again, renewal…); never throws. */
export async function resolveAndroidTenantAlert(tenantId: number, key: string): Promise<void> {
  const def = byKey.get(key);
  if (!def || def.scope === 'platform') return;
  try {
    await asTenant(tenantId, PLATFORM_ACTOR, () => db('live_alerts').where({ tenant_id: tenantId, stable_key: key }).whereNull('resolved_at')
      .update({ resolved_at: db.fn.now() }));
  } catch (err) {
    logger.error({ alert: key, tenantId, err: (err as Error)?.name }, 'android: tenant alert not resolved');
  }
}
