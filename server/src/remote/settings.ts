import type { Knex } from 'knex';
import { DEFAULT_REMOTE_SETTINGS, REMOTE_LIMITS, type RemoteSettings } from '@obligarth/shared';
import { z } from 'zod';

// =============================================================================
// The settings of the remote assistance of a tenant (P0-15 §4.1, §4.6, D14, D16; table remote_settings, one row per
// tenant, absent: DEFAULT_REMOTE_SETTINGS). Read in the caller's connection or transaction (the tenant's context);
// written only by the execution of an approved request (remote/approvals.ts, restriction remote.settings_change).
// =============================================================================

export const RemoteSettingsInputSchema = z.object({
  mspSessionsNeedClientApproval: z.boolean().optional(),
  maxMinutes: z.number().int().min(REMOTE_LIMITS.maxMinutesMin).max(REMOTE_LIMITS.maxMinutesMax).optional(),
  waitChannel: z.boolean().optional(),
}).strict();
export type RemoteSettingsInput = z.infer<typeof RemoteSettingsInputSchema>;

export interface RemoteSettingsRow extends RemoteSettings {
  updatedAt: Date | null;
}

/** The settings of the tenant (the defaults without a row). */
export async function readRemoteSettings(q: Knex | Knex.Transaction, tenantId: number, o: { forUpdate?: boolean } = {}): Promise<RemoteSettingsRow> {
  let sel = q('remote_settings').where({ tenant_id: tenantId });
  if (o.forUpdate) sel = sel.forUpdate();
  const r = await sel.first('msp_sessions_need_client_approval', 'max_minutes', 'wait_channel', 'updated_at') as
    { msp_sessions_need_client_approval: boolean; max_minutes: number; wait_channel: boolean; updated_at: Date } | undefined;
  if (!r) return { ...DEFAULT_REMOTE_SETTINGS, updatedAt: null };
  return {
    mspSessionsNeedClientApproval: r.msp_sessions_need_client_approval === true,
    maxMinutes: Number(r.max_minutes),
    waitChannel: r.wait_channel === true,
    updatedAt: r.updated_at ? new Date(r.updated_at) : null,
  };
}

/** The keys of `input` whose value differs from `current`, with both values. */
export function settingsChanges(current: RemoteSettings, input: RemoteSettingsInput): Record<string, { from: unknown; to: unknown }> {
  const out: Record<string, { from: unknown; to: unknown }> = {};
  for (const k of ['mspSessionsNeedClientApproval', 'maxMinutes', 'waitChannel'] as const) {
    if (input[k] !== undefined && input[k] !== current[k]) out[k] = { from: current[k], to: input[k] };
  }
  return out;
}

/** Writes the settings of the tenant (the keys of `input`, the others kept), in the caller's transaction. */
export async function writeRemoteSettings(trx: Knex.Transaction, tenantId: number, input: RemoteSettingsInput, userId: number): Promise<RemoteSettings> {
  const current = await readRemoteSettings(trx, tenantId, { forUpdate: true });
  const next: RemoteSettings = {
    mspSessionsNeedClientApproval: input.mspSessionsNeedClientApproval ?? current.mspSessionsNeedClientApproval,
    maxMinutes: input.maxMinutes ?? current.maxMinutes,
    waitChannel: input.waitChannel ?? current.waitChannel,
  };
  await trx('remote_settings').insert({
    tenant_id: tenantId, msp_sessions_need_client_approval: next.mspSessionsNeedClientApproval, max_minutes: next.maxMinutes,
    wait_channel: next.waitChannel, updated_by: userId, updated_at: new Date(),
  }).onConflict('tenant_id').merge(['msp_sessions_need_client_approval', 'max_minutes', 'wait_channel', 'updated_by', 'updated_at']);
  return next;
}
