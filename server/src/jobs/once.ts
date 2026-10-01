import { db } from '../db';
import { JobError } from './errors';

// =============================================================================
// job_once: a side effect done at least once, never twice (e-mail, call to a
// third party). A job runs at least once (retry after an expiry, a crash, a
// redrive): the effect is claimed under a lease, done, then marked done. A
// crash between the effect and the mark can still repeat it once the lease
// has expired: the price of at-least-once. Expired keys are purged daily
// (jobs.housekeeping).
// =============================================================================

/** Lease of a pending claim: an attempt that died holding it frees it then. */
const LEASE_MINUTES = 10;
/** Longest life of a key (90 days). */
export const ONCE_MAX_TTL_SECONDS = 90 * 86_400;
const KEY_RE = /^[A-Za-z0-9_.:/-]{1,200}$/;

type Raw = { rows: Array<Record<string, unknown>> };

export async function runOnce(
  queue: string, key: string, ttlSeconds: number, effect: () => Promise<void>,
): Promise<'done' | 'skipped'> {
  if (!KEY_RE.test(key)) throw new JobError('invalid_once_key', 'once key: identifiers only, 200 characters at most', false);
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > ONCE_MAX_TTL_SECONDS) {
    throw new JobError('invalid_once_ttl', 'once ttl: an integer from 60 seconds to 90 days', false);
  }
  // Claim: a new key, or a pending claim whose lease expired.
  const claim = await db.raw(
    `INSERT INTO job_once (key, queue, state, lease_until, expires_at)
     VALUES (?, ?, 'pending', now() + make_interval(mins => ${LEASE_MINUTES}), now() + make_interval(secs => ?))
     ON CONFLICT (key) DO UPDATE SET lease_until = EXCLUDED.lease_until
      WHERE job_once.state = 'pending' AND job_once.lease_until < now()
     RETURNING key`,
    [key, queue, ttlSeconds],
  ) as Raw;
  // No row: done already, or claimed by an attempt still running.
  if (claim.rows.length === 0) return 'skipped';
  try {
    await effect();
  } catch (err) {
    await db('job_once').where({ key, state: 'pending' }).delete().catch(() => undefined);
    throw err;
  }
  await db('job_once').where({ key }).update({ state: 'done', done_at: db.fn.now() });
  return 'done';
}

/** jobs.housekeeping: keys past their expiry. */
export async function purgeExpiredOnce(): Promise<number> {
  return db('job_once').where('expires_at', '<', db.fn.now()).delete();
}
