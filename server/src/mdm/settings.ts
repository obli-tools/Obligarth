import { MDM_STALE_AFTER_DAYS_DEFAULT, SETTINGS_KEYS } from '@obligarth/shared';
import { db } from '../db';

// =============================================================================
// Tenant settings of the MDM data model (docs: modele-donnees-mdm §10.9):
// mdmStaleAfterDays (global scope only, 1 to 90 days, 7 by default) fixes when
// the contact of a managed device turns 'stale' (§4.4). Read in the caller's
// database context: a tenant's own row, or every tenant's in the global view.
// =============================================================================

const clampDays = (v: unknown): number | null => {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? Number(v) : NaN;
  return Number.isInteger(n) && n >= 1 && n <= 90 ? n : null;
};

/** mdmStaleAfterDays of each tenant of `tenantIds` (the default for a tenant without a value). */
export async function staleAfterDaysOf(tenantIds: number[]): Promise<Map<number, number>> {
  const ids = [...new Set(tenantIds.filter((t) => Number.isSafeInteger(t) && t > 0))];
  const out = new Map<number, number>(ids.map((t) => [t, MDM_STALE_AFTER_DAYS_DEFAULT]));
  if (ids.length === 0) return out;
  const rows = await db('settings')
    .whereIn('tenant_id', ids)
    .where({ scope: 'global', key: SETTINGS_KEYS.MDM_STALE_AFTER_DAYS })
    .whereNull('scope_id')
    .select('tenant_id', 'value') as Array<{ tenant_id: number; value: unknown }>;
  for (const r of rows) {
    const d = clampDays(r.value);
    if (d !== null) out.set(Number(r.tenant_id), d);
  }
  return out;
}

/** mdmStaleAfterDays of one tenant. */
export async function staleAfterDays(tenantId: number): Promise<number> {
  return (await staleAfterDaysOf([tenantId])).get(tenantId) ?? MDM_STALE_AFTER_DAYS_DEFAULT;
}
