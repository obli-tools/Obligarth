import type { Knex } from 'knex';
import {
  retentionCategoryDef, unenrolledRetentionCategory, RETENTION_CATEGORY_KEYS,
  type Ownership, type RetentionCategory,
} from '@obligarth/shared';

// =============================================================================
// Retention per tenant (P0-13 T4, CNF-04; conception §10.4): the values in force of a tenant, read in the caller's
// connection or transaction (the tenant's context, a read context that covers it, or the 'none' context of a job) from
// obligarth.retention_value (a decrease past its date, else the value the tenant set, else the default of
// RETENTION_CATEGORIES, shared/src/privacy.ts). No cache: a purge, a date of purge read once per slice or per row,
// a change of the retention applies at the next one.
// Consumers: the rules of the retention (mdm/inventory/retention.ts, apple/retention.ts, legacyAgent/retention.ts), the
// date of purge of a record out of management (mdm/registry/unenroll.ts), the date of purge of a position in lost mode
// (apple/commands/lostMode.ts, android/inventory/usageLogs.ts: lostModePurgeAt). The changes (approval, decrease after
// 7 days, cancelled by a change asking the value in force) are in privacy/retentionPolicy.ts.
// No import of the database module here: the unit tests load this file (npm run test:privacy).
// =============================================================================

type Q = Knex | Knex.Transaction;

/** The value in force of `category` for the tenant (days or months: retentionCategoryDef(category).unit). */
export async function retentionValue(q: Q, tenantId: number, category: RetentionCategory): Promise<number> {
  const r = await q.raw('SELECT obligarth.retention_value(?, ?) AS v', [tenantId, category]) as { rows: Array<{ v: number }> };
  const v = Number(r.rows[0]?.v);
  // The function always answers an integer of the range (CHECKs of the table, defaults of the catalogue).
  if (!Number.isInteger(v) || v <= 0) throw Object.assign(new Error(`retention: no value for ${category}`), { code: 'retentionUnreadable' });
  return v;
}

/** The value in force of a category counted in days. */
export async function retentionDays(q: Q, tenantId: number, category: RetentionCategory): Promise<number> {
  if (retentionCategoryDef(category).unit !== 'days') throw new Error(`retention: ${category} is not counted in days`);
  return retentionValue(q, tenantId, category);
}

/** Every category in force for the tenant. */
export async function retentionValues(q: Q, tenantId: number): Promise<Record<RetentionCategory, number>> {
  const r = await q.raw('SELECT category, value FROM obligarth.retention_values(?)', [tenantId]) as
    { rows: Array<{ category: string; value: number }> };
  const out = {} as Record<RetentionCategory, number>;
  for (const k of RETENTION_CATEGORY_KEYS) {
    const v = Number(r.rows.find((x) => x.category === k)?.value);
    if (!Number.isInteger(v) || v <= 0) throw Object.assign(new Error(`retention: no value for ${k}`), { code: 'retentionUnreadable' });
    out[k] = v;
  }
  return out;
}

/** `now` minus `months` calendar months (UTC), the day clamped to the length of the month reached
 *  (31 August minus 6 months is the last day of February, never a day of March). */
export function monthsBefore(now: Date, months: number): Date {
  const d = new Date(now.getTime());
  const day = d.getUTCDate();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() - months);
  const lastDay = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
  d.setUTCDate(Math.min(day, lastDay));
  return d;
}

/** The instant before which the data of `category` are due at `now`: `now` minus its value in force (days, or calendar
 *  months clamped to the end of the month). */
export function cutoffOf(category: RetentionCategory, value: number, now: Date): Date {
  return retentionCategoryDef(category).unit === 'months' ? monthsBefore(now, value) : new Date(now.getTime() - value * 86_400_000);
}

/** The cutoff of `category` for the tenant at `now` (its value in force). */
export async function retentionCutoff(q: Q, tenantId: number, category: RetentionCategory, now: Date): Promise<Date> {
  return cutoffOf(category, await retentionValue(q, tenantId, category), now);
}

/** The retention, in days, of the record of a device of `ownership` once out of management (unenroll.ts). */
export function unenrolledRetentionDays(q: Q, tenantId: number, ownership: Ownership | string | null): Promise<number> {
  return retentionDays(q, tenantId, unenrolledRetentionCategory(ownership));
}

/** The date of purge of a position in lost mode inserted now, as an SQL expression of the inserting statement: the
 *  transaction's now() (the received_at of the row) plus the days in force for the tenant, so that the CHECK
 *  lost_mode_locations_purge_cap (purge_at <= received_at + 62 days) holds up to the maximum of the range. */
export function lostModePurgeAt(q: Q, tenantId: number): Knex.Raw {
  return q.raw("now() + make_interval(days => obligarth.retention_value(?, 'lost_mode_location_days'))", [tenantId]);
}
