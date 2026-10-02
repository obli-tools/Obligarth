// Guard settings of a tenant (docs: audit-durci §10.6, §10.7; table
// tenant_guard_settings): hourly cap, side of the approver of mass actions,
// emergency freeze. A tenant without a row has the defaults. Read and written
// in the tenant's database context.
import type { Knex } from 'knex';
import {
  GUARD_HOURLY_CAP_MIN_DEFAULT, GUARD_HOURLY_CAP_PERCENT_DEFAULT, type GuardSettingsDto, type GuardSide,
} from '@obligarth/shared';
import { db } from '../db';

export interface GuardSettingsRow {
  tenant_id: number;
  hourly_cap_percent: number;
  hourly_cap_min: number;
  mass_approver_side: GuardSide;
  frozen_at: Date | null;
  frozen_by: number | null;
  frozen_source: 'manual' | 'anomaly' | null;
  frozen_reason: string | null;
  updated_by: number | null;
  updated_at: Date | null;
}

export function defaultSettings(tenantId: number): GuardSettingsRow {
  return {
    tenant_id: tenantId,
    hourly_cap_percent: GUARD_HOURLY_CAP_PERCENT_DEFAULT,
    hourly_cap_min: GUARD_HOURLY_CAP_MIN_DEFAULT,
    mass_approver_side: 'client',
    frozen_at: null,
    frozen_by: null,
    frozen_source: null,
    frozen_reason: null,
    updated_by: null,
    updated_at: null,
  };
}

const COLUMNS = [
  'tenant_id', 'hourly_cap_percent', 'hourly_cap_min', 'mass_approver_side', 'frozen_at', 'frozen_by',
  'frozen_source', 'frozen_reason', 'updated_by', 'updated_at',
] as const;

/** The settings of a tenant (defaults without a row). `forUpdate` in a
 *  transaction: the row is created first, then locked. */
export async function readSettings(tenantId: number, trx?: Knex.Transaction, o: { forUpdate?: boolean } = {}): Promise<GuardSettingsRow> {
  const q = trx ?? db;
  if (o.forUpdate && trx) {
    await trx('tenant_guard_settings').insert({ tenant_id: tenantId }).onConflict('tenant_id').ignore();
    const row = await trx('tenant_guard_settings').where({ tenant_id: tenantId }).forUpdate().first(COLUMNS);
    return normalise(row, tenantId);
  }
  const row = await q('tenant_guard_settings').where({ tenant_id: tenantId }).first(COLUMNS);
  return normalise(row, tenantId);
}

function normalise(row: Record<string, unknown> | undefined, tenantId: number): GuardSettingsRow {
  if (!row) return defaultSettings(tenantId);
  return {
    tenant_id: Number(row.tenant_id),
    hourly_cap_percent: Number(row.hourly_cap_percent),
    hourly_cap_min: Number(row.hourly_cap_min),
    mass_approver_side: row.mass_approver_side === 'msp' ? 'msp' : 'client',
    frozen_at: row.frozen_at ? new Date(row.frozen_at as string | Date) : null,
    frozen_by: row.frozen_by === null || row.frozen_by === undefined ? null : Number(row.frozen_by),
    frozen_source: row.frozen_source === 'manual' || row.frozen_source === 'anomaly' ? row.frozen_source : null,
    frozen_reason: typeof row.frozen_reason === 'string' ? row.frozen_reason : null,
    updated_by: row.updated_by === null || row.updated_by === undefined ? null : Number(row.updated_by),
    updated_at: row.updated_at ? new Date(row.updated_at as string | Date) : null,
  };
}

/** The settings as the console reads them; `hold`: the last loss of a client
 *  approver not decided by the approver, and the end of the fallback hold
 *  (AUD-A7-R4, guard/people.ts fallbackHold). */
export function settingsToDto(s: GuardSettingsRow, hold: { lostAt: Date; until: Date } | null = null): GuardSettingsDto {
  return {
    tenantId: s.tenant_id,
    hourlyCapPercent: s.hourly_cap_percent,
    hourlyCapMin: s.hourly_cap_min,
    massApproverSide: s.mass_approver_side,
    frozen: s.frozen_at !== null,
    frozenAt: s.frozen_at ? s.frozen_at.toISOString() : null,
    frozenBy: s.frozen_by,
    frozenSource: s.frozen_source,
    frozenReason: s.frozen_reason,
    updatedAt: s.updated_at ? s.updated_at.toISOString() : null,
    clientApproverLostAt: hold ? hold.lostAt.toISOString() : null,
    fallbackHeldUntil: hold ? hold.until.toISOString() : null,
  };
}

/** Is the tenant frozen? (No row: not frozen.) */
export async function isFrozen(tenantId: number, trx?: Knex.Transaction): Promise<boolean> {
  return (await readSettings(tenantId, trx)).frozen_at !== null;
}
