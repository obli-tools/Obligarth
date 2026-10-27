// =============================================================================
// The rules of the échéancier (docs: integration-apple-edge §11.4, INT-05;
// coffre-secrets §11.5), pure: the thresholds of each kind, the threshold an
// expiry has crossed, what to do with an item now (raise, resolve, nothing).
// The unit tests load it without the server (schedule.ts runs it).
// =============================================================================

const DAY = 86_400_000;
const DEFAULT_THRESHOLDS = [60, 30, 14, 7, 3, 1, 0] as const;
/** coffre-secrets §11.5. */
const THRESHOLDS: Record<string, readonly number[]> = {
  vault_kek_rotation: [60, 30],
  vault_old_shares: [7, 0],
  vault_dek_destruction: [7, 1],
  /** Half-yearly restore drill of the backups (P0-13 T9, FND-09): J-30, 14, 7, then due. */
  backup_restore_drill: [30, 14, 7, 0],
};
/** Days added to a KEK rotation before the old escrow shares are due for destruction: the backups' retention
 *  [proposal: 30 days, FND-09 has not fixed it] and 7 days (coffre-secrets §11.5). */
export const OLD_SHARES_DAYS = 30 + 7;

export const thresholdsOf = (kind: string): readonly number[] => THRESHOLDS[kind] ?? DEFAULT_THRESHOLDS;

/** Whole days left (the view's floor); negative once expired. */
export const daysLeftOf = (notAfter: Date, now: Date): number => Math.floor((notAfter.getTime() - now.getTime()) / DAY);

/** The smallest threshold of the kind the expiry has crossed, or null. */
export function thresholdFor(kind: string, daysLeft: number): number | null {
  let crossed: number | null = null;
  for (const t of thresholdsOf(kind)) if (daysLeft <= t && (crossed === null || t < crossed)) crossed = t;
  return crossed;
}

export const severityOfThreshold = (t: number): 'warning' | 'critical' => (t >= 30 ? 'warning' : 'critical');

export interface ItemState {
  kind: string;
  not_after: Date | null;
  retired_at: Date | null;
  last_alert_threshold: number | null;
  last_alerted_not_after: Date | null;
}

export type Decision =
  | { action: 'none' }
  | { action: 'resolve' }
  | { action: 'raise'; threshold: number; daysLeft: number; resolveFirst: boolean };

/** What the échéancier does for an item now (pure: unit-tested). */
export function decide(item: ItemState, now: Date): Decision {
  const alerted = item.last_alert_threshold !== null && item.last_alert_threshold !== undefined;
  if (item.retired_at || !item.not_after) return alerted ? { action: 'resolve' } : { action: 'none' };
  const notAfter = new Date(item.not_after);
  const same = !!item.last_alerted_not_after && new Date(item.last_alerted_not_after).getTime() === notAfter.getTime();
  const renewed = alerted && !same;
  const days = daysLeftOf(notAfter, now);
  const t = thresholdFor(item.kind, days);
  const last = same ? item.last_alert_threshold : null;
  if (t !== null && (last === null || t < last)) return { action: 'raise', threshold: t, daysLeft: Math.max(0, days), resolveFirst: renewed };
  return renewed ? { action: 'resolve' } : { action: 'none' };
}

