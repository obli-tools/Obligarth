// Replay of the local spool (docs: audit-durci §5.5): job audit.spool-replay
// (every minute and at start). The files are read by date; each body is
// appended in the context of its tenant (actor j:audit.spool-replay), the
// database admitting a late body up to 7 days old. A file entirely replayed
// is removed; a transient failure stops the run (the rest waits); a body the
// database refuses (malformed, out of window, unknown tenant) goes to
// rejected/, never replayed, with an alert. At the end, audit.spool_replayed
// (count, oldest instant) in the master tenant.
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { db } from '../db';
import { asTenant, type DbActor } from '../db/context';
import { logger } from '../utils/logger';
import { fromJob } from './actor';
import { auditMetrics } from './metrics';
import { readSpoolFile, rejectEntries, rewriteSpoolFile, spoolFiles, spoolStatus, type SpoolLine } from './spool';
import { append } from './writer';

export const REPLAY_ACTOR: DbActor = { type: 'job', name: 'audit.spool-replay' };
/** Refused for good (a data exception, an integrity or an access error,
 *  classes 22, 23 and 42): kept aside, never retried — a line that can never
 *  be written must not hold back the lines after it. */
const REFUSED_RE = /^(22|23|42)/;

function codeOf(err: unknown): string {
  const c = (err as { code?: unknown } | null)?.code;
  return typeof c === 'string' && /^[0-9A-Z]{5}$/.test(c) ? c : 'error';
}

function tsOf(body: string): string | null {
  const m = /"ts":"([0-9T:.\-]+Z)"/.exec(body);
  return m ? m[1] : null;
}

export interface ReplayReport { replayed: number; rejected: number; remaining: number; oldestTs: string | null }

/** Replays the spool; never throws for a body (its fate is counted). */
export async function replaySpool(o: { requestId?: string } = {}): Promise<ReplayReport> {
  let replayed = 0;
  let rejected = 0;
  let oldestTs: string | null = null;
  let stop = false;
  for (const file of spoolFiles()) {
    if (stop) break;
    const { lines, unreadable } = readSpoolFile(file);
    if (unreadable) rejected += unreadable;
    const remaining: SpoolLine[] = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (stop) { remaining.push(line); continue; }
      try {
        await asTenant(line.tenant, REPLAY_ACTOR, () => db.raw('SELECT entry_id FROM obligarth.audit_append(?)', [line.body]));
        replayed++;
        const ts = tsOf(line.body);
        if (ts && (oldestTs === null || ts < oldestTs)) oldestTs = ts;
      } catch (err) {
        const code = codeOf(err);
        if (code === '23505') {            // already written (a replay interrupted after the commit)
          replayed++;
          continue;
        }
        if (REFUSED_RE.test(code)) {
          rejectEntries([{ ...line, firstError: `${line.firstError}; replay ${code}` }]);
          rejected++;
          continue;
        }
        logger.warn({ code: 'AUDIT_SPOOL_REPLAY_STOPPED', failure: code }, 'audit: spool replay stopped (database unavailable)');
        stop = true;
        remaining.push(line);
      }
    }
    rewriteSpoolFile(file, remaining);
  }
  const status = spoolStatus();
  if (rejected > 0) {
    auditMetrics.inc('obligarth_audit_spool_rejected_total', {}, rejected);
    const { raiseJobAlert } = await import('../jobs/alerts');
    await raiseJobAlert(REPLAY_ACTOR, {
      stableKey: 'audit:spool-rejected', severity: 'warning',
      title: 'Audit entries refused at replay',
      message: `${rejected} spooled audit entr${rejected > 1 ? 'ies were' : 'y was'} refused and kept aside (spool-import).`,
    });
  }
  if (status.entries > 0 && status.oldestSpooledAt && Date.now() - new Date(status.oldestSpooledAt).getTime() > 5 * 60_000) {
    const { raiseJobAlert } = await import('../jobs/alerts');
    await raiseJobAlert(REPLAY_ACTOR, {
      stableKey: 'audit:spool-waiting', severity: 'warning',
      title: 'Audit entries waiting in the spool',
      message: `${status.entries} audit entr${status.entries > 1 ? 'ies wait' : 'y waits'} in the local spool for more than 5 minutes: is the database reachable?`,
    });
  }
  if (replayed > 0) {
    await append({
      tenantId: MASTER_TENANT_ID, action: 'audit.spool_replayed',
      details: { count: replayed, oldestTs, rejected, remaining: status.entries },
    }, fromJob({ name: 'audit.spool-replay', requestId: o.requestId ?? 'spool-replay' }));
  }
  return { replayed, rejected, remaining: status.entries, oldestTs };
}
