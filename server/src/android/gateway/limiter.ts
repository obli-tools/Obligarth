// Rate limiter of the gateway (AN23), in the database (android_rate_buckets, class technical) so that every process
// of the instance shares it: the project bucket (ANDROID_RATE_PROJECT_PER_100S per 100 s, 10 % under Google's
// 1 000) and a bucket per key k:<action>:<enterprise>:<resource> (60 per minute). Each take is one statement
// (refill and take together). Background work stops at 20 % of the project budget left; a call that would wait
// more than 10 s fails with AndroidRateLimitedError (retried by the durable queue).
import { db } from '../../db';
import { AndroidRateLimitedError } from './errors';
import type { LimiterClass } from './types';
import { androidMetrics } from '../metrics';
import { androidWait } from '../wait';

const MAX_WAIT_MS = 10_000;
const KEY_CAPACITY = 60;
const KEY_RATE_PER_S = 1;

type Rows<T> = { rows: T[] };

/**
 * Takes one token of `bucket` if at least 1 + minRemaining are available after the refill; returns null when taken,
 * else the seconds to wait for it.
 */
export async function tryTake(bucket: string, capacity: number, ratePerS: number, minRemaining = 0): Promise<number | null> {
  const r = await db.raw(
    `INSERT INTO android_rate_buckets AS b (bucket, tokens, refreshed_at) VALUES (?, ?::double precision - 1, clock_timestamp())
     ON CONFLICT (bucket) DO UPDATE
       SET tokens = LEAST(?::double precision, b.tokens + extract(epoch FROM clock_timestamp() - b.refreshed_at) * ?::double precision) - 1,
           refreshed_at = clock_timestamp()
     WHERE LEAST(?::double precision, b.tokens + extract(epoch FROM clock_timestamp() - b.refreshed_at) * ?::double precision) >= 1 + ?::double precision
     RETURNING tokens`,
    [bucket, capacity, capacity, ratePerS, capacity, ratePerS, minRemaining]) as Rows<{ tokens: number }>;
  if (r.rows.length) return null;
  const s = await db.raw(
    `SELECT LEAST(?::double precision, tokens + extract(epoch FROM clock_timestamp() - refreshed_at) * ?::double precision) AS avail
       FROM android_rate_buckets WHERE bucket = ?`, [capacity, ratePerS, bucket]) as Rows<{ avail: number }>;
  const avail = Number(s.rows[0]?.avail ?? capacity);
  return Math.max(0.05, (1 + minRemaining - avail) / ratePerS);
}


export interface LimiterSettings { projectPer100s: number }

/** Takes a token of the project bucket and of the key bucket, waiting 10 s at most. */
export async function takeTokens(settings: LimiterSettings, key: string | null, cls: LimiterClass): Promise<void> {
  const capacity = settings.projectPer100s;
  const rate = capacity / 100;
  const minRemaining = cls === 'background' ? capacity * 0.2 : 0;
  const started = Date.now();
  const buckets: Array<[string, number, number, number]> = [['project', capacity, rate, minRemaining]];
  if (key) buckets.push([key.slice(0, 255), KEY_CAPACITY, KEY_RATE_PER_S, 0]);
  for (const [bucket, cap, r, min] of buckets) {
    for (;;) {
      const wait = await tryTake(bucket, cap, r, min);
      if (wait === null) break;
      const waitMs = Math.ceil(wait * 1000);
      if (Date.now() - started + waitMs >= MAX_WAIT_MS) {
        androidMetrics.rateWait(Date.now() - started);
        throw new AndroidRateLimitedError(Math.max(1, Math.ceil(wait)));
      }
      await androidWait(waitMs);
    }
  }
  androidMetrics.rateWait(Date.now() - started);
}

/** The project bucket's level, for the health view: tokens left and capacity. */
export async function projectBudget(settings: LimiterSettings): Promise<{ tokens: number; capacity: number }> {
  const capacity = settings.projectPer100s;
  const s = await db.raw(
    `SELECT LEAST(?::double precision, tokens + extract(epoch FROM clock_timestamp() - refreshed_at) * ?::double precision) AS avail
       FROM android_rate_buckets WHERE bucket = 'project'`, [capacity, capacity / 100]) as Rows<{ avail: number }>;
  return { tokens: Number(s.rows[0]?.avail ?? capacity), capacity };
}
