// Alerts of the Android integration (annex E, closed catalogue): platform alerts go to the live alerts of the master
// tenant (the operator), tenant alerts to the tenant's own; deduplicated on an unread alert of the same stable key.
// Texts carry an i18n key and identifiers only (never a device datum, a name nor an e-mail). The generic alert
// catalogue opened to modules (registerAlertDefinitions) arrives with the channel generalisation; until then the
// definitions live here.
import { asTenant, type DbActor } from '../db/context';
import { raiseJobAlert } from '../jobs/alerts';
import { liveAlertService, type LiveAlertSeverity } from '../services/liveAlert.service';
import { logger } from '../utils/logger';

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
];

const byKey = new Map(ANDROID_ALERTS.map((a) => [a.key, a]));
const PLATFORM_ACTOR: DbActor = { type: 'job', name: 'android.alerts' };

/** Raises a platform alert (master tenant); never throws. `params`: identifiers and counts only. */
export async function raiseAndroidPlatformAlert(key: string, params: Record<string, string | number> = {}, dedupSuffix = ''): Promise<void> {
  const def = byKey.get(key);
  if (!def || def.scope === 'tenant') { logger.error({ alert: key }, 'android: undeclared platform alert'); return; }
  await raiseJobAlert(PLATFORM_ACTOR, {
    stableKey: `${key}${dedupSuffix ? `:${dedupSuffix}` : ''}`,
    severity: def.severity,
    title: def.title,
    message: `i18n:alerts.${key} ${JSON.stringify(params).slice(0, 400)}`,
  });
}

/** Raises a tenant alert in `tenantId`; never throws. */
export async function raiseAndroidTenantAlert(tenantId: number, key: string, params: Record<string, string | number> = {}): Promise<void> {
  const def = byKey.get(key);
  if (!def || def.scope === 'platform') { logger.error({ alert: key }, 'android: undeclared tenant alert'); return; }
  try {
    await asTenant(tenantId, PLATFORM_ACTOR, () => liveAlertService.add(tenantId, {
      severity: def.severity, title: def.title, message: `i18n:alerts.${key} ${JSON.stringify(params).slice(0, 400)}`,
      navigateTo: null, stableKey: key,
    }));
  } catch (err) {
    logger.error({ alert: key, tenantId, err: (err as Error)?.name }, 'android: tenant alert not written');
  }
}
