import { db } from '../../db';
import { asIdentity } from '../../db/context';
import { OBLIWATCH_ACTOR } from './config';

// =============================================================================
// Single-use jti (plan §0 F2), on the model of Obliwatch's verifier: a memo in memory (the fast answer to a replay
// on this process) and the table integration_seen_jti (the answer across restarts and processes). A jti is burned
// only once the token passed the policy of the route (the caller decides when), so a refused token is not burned.
// A store failure is NOT a pass: the caller answers 503.
// =============================================================================

/** Kept past the token's exp: the verifier still accepts a token 30 s after exp (clock skew). */
const KEEP_AFTER_EXP_MS = 5 * 60_000;
const MEMO_MAX = 50_000;

const memo = new Map<string, number>();

function sweep(now: number): void {
  for (const [k, until] of memo) if (until <= now) memo.delete(k);
  if (memo.size >= MEMO_MAX) memo.clear();
}

export type JtiOutcome = 'fresh' | 'replayed';

/**
 * Burns `jti` (a UUID, already checked by the verifier) for a token of `source` expiring at `expSec` (seconds).
 * 'replayed' when it was seen before; throws when the store cannot be written (the caller answers 503).
 */
export async function consumeJti(jti: string, source: string, expSec: number): Promise<JtiOutcome> {
  const now = Date.now();
  const key = jti.toLowerCase();
  const until = expSec * 1000 + KEEP_AFTER_EXP_MS;
  const known = memo.get(key);
  if (known !== undefined && known > now) return 'replayed';
  const rows = await asIdentity(OBLIWATCH_ACTOR, () => db('integration_seen_jti')
    .insert({ jti: key, source, exp: new Date(until) })
    .onConflict('jti').ignore()
    .returning('jti')) as Array<{ jti: string }>;
  if (!memo.has(key) && memo.size >= MEMO_MAX) sweep(now);
  memo.set(key, until);
  return rows.length === 1 ? 'fresh' : 'replayed';
}

/** The minute step: rows (and memo entries) past their keeping time. */
export async function purgeSeenJti(): Promise<number> {
  sweep(Date.now());
  const n = await asIdentity(OBLIWATCH_ACTOR, () => db('integration_seen_jti').where('exp', '<', new Date()).del());
  return Number(n) || 0;
}

/** Test hook: forget the memo (the table stays). */
export function _resetJtiMemo(): void { memo.clear(); }
