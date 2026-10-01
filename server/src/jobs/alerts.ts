import { MASTER_TENANT_ID } from '@obligarth/shared';
import { asTenant, type DbActor } from '../db/context';
import { liveAlertService, type LiveAlertSeverity } from '../services/liveAlert.service';
import { logger } from '../utils/logger';
import { safeErr } from './errors';

// =============================================================================
// Alerts of the jobs: live alerts of the master tenant (the MSP), deduplicated
// on an unread alert of the same stable key, and an error line in the log.
// Short English texts, no personal data nor client name. Routing to e-mail
// and ObliDesk belongs to the observability work (FND-14).
// =============================================================================

export interface JobAlert {
  stableKey: string;
  severity: LiveAlertSeverity;
  title: string;
  message: string;
}

/** Raises `alert` in the master tenant as `actor`; never throws. */
export async function raiseJobAlert(actor: DbActor, alert: JobAlert): Promise<void> {
  logger.error({ alert: alert.stableKey, severity: alert.severity }, `job alert: ${alert.title}`);
  try {
    await asTenant(MASTER_TENANT_ID, actor, () => liveAlertService.add(MASTER_TENANT_ID, {
      severity: alert.severity,
      title: alert.title.slice(0, 200),
      message: alert.message.slice(0, 500),
      navigateTo: null,
      stableKey: alert.stableKey,
    }));
  } catch (err) {
    logger.error({ err: safeErr(err), alert: alert.stableKey }, 'job alert not written');
  }
}

export const jobAlerts = {
  failing(actor: DbActor, queue: string, failures: number, code: string): Promise<void> {
    return raiseJobAlert(actor, {
      stableKey: `jobs:failing:${queue}`,
      severity: 'warning',
      title: `Background job failing: ${queue}`,
      message: `${failures} consecutive failures (last error: ${code}).`,
    });
  },
  stale(actor: DbActor, queue: string): Promise<void> {
    return raiseJobAlert(actor, {
      stableKey: `jobs:stale:${queue}`,
      severity: 'warning',
      title: `Background job not running: ${queue}`,
      message: 'No successful run for two periods and 10 minutes.',
    });
  },
  backlog(actor: DbActor, queue: string, ready: number): Promise<void> {
    return raiseJobAlert(actor, {
      stableKey: `jobs:backlog:${queue}`,
      severity: 'warning',
      title: `Background job queue behind: ${queue}`,
      message: `${ready} jobs ready and waiting at two checks in a row.`,
    });
  },
  deadLetters(actor: DbActor, count: number): Promise<void> {
    return raiseJobAlert(actor, {
      stableKey: 'jobs:dead-letters',
      severity: 'warning',
      title: 'Background jobs moved to the dead letters',
      message: `${count} new dead letter(s): see the jobs administration API.`,
    });
  },
};
