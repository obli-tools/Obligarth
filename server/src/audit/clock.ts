// The clock of the entries (docs: audit-durci §5.6): the instants come from
// the server's clock (NTP on the host); the database checks every entry
// against its own (5 minutes). At start and every minute, the drift with the
// database is measured (round trip removed): gauge, alert beyond 30 s,
// refusal to start beyond AUDIT_MAX_CLOCK_SKEW_SECONDS (240 by default).
import { config } from '../config';
import { db } from '../db';
import { asNone } from '../db/context';
import { logger } from '../utils/logger';
import { auditMetrics } from './metrics';

const ALERT_SECONDS = 30;

export class AuditClockError extends Error {
  constructor(readonly skewSeconds: number) {
    super(`The server's clock is ${skewSeconds.toFixed(1)} s away from the database's (limit ${config.audit.maxClockSkewSeconds} s): `
      + 'the audit entries would be refused. Synchronise the host clocks (NTP). Refusing to start.');
    this.name = 'AuditClockError';
  }
}

/** Database clock minus the server's, in seconds (round trip removed). */
export async function measureClockSkew(): Promise<number> {
  const t0 = Date.now();
  const res = await db.raw('SELECT clock_timestamp() AS now') as { rows: Array<{ now: Date }> };
  const t1 = Date.now();
  const skew = (new Date(res.rows[0].now).getTime() - (t0 + t1) / 2) / 1000;
  auditMetrics.set('obligarth_audit_clock_skew_seconds', Math.round(skew * 1000) / 1000);
  return skew;
}

/** Every minute (audit.spool-replay): gauge, alert beyond 30 s. */
export async function watchClock(): Promise<number> {
  const skew = await measureClockSkew();
  if (Math.abs(skew) > ALERT_SECONDS) {
    logger.warn({ code: 'AUDIT_CLOCK_SKEW', skewSeconds: skew }, 'audit: the server clock drifts from the database clock');
    const { raiseJobAlert } = await import('../jobs/alerts');
    await raiseJobAlert({ type: 'job', name: 'audit.spool-replay' }, {
      stableKey: 'audit:clock-skew', severity: 'warning',
      title: 'Server clock drifting',
      message: `The server clock is ${Math.round(skew)} s away from the database's: synchronise the host clocks (NTP).`,
    });
  }
  return skew;
}

/** At start (index.ts): refusal beyond the limit. */
export async function auditClockCheck(): Promise<number> {
  const skew = await asNone({ type: 'job', name: 'audit.clock' }, () => measureClockSkew());
  if (Math.abs(skew) > config.audit.maxClockSkewSeconds) throw new AuditClockError(skew);
  if (Math.abs(skew) > ALERT_SECONDS) logger.warn({ skewSeconds: skew }, 'audit: the server clock drifts from the database clock');
  return skew;
}
