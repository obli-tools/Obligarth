import type { Knex } from 'knex';
import { obliwatchIntegrationEnabled } from './config';

// =============================================================================
// The gate of the action requests of Obliwatch (lot L5, GTH-04), checked again when they execute, not only when they are
// made: OBLIWATCH_INTEGRATION=on and the tenant's consent actions_enabled. Read by the guard engine's executor
// (guard/executor.ts, revalidate: a guarded action of Obliwatch whose gate closed meanwhile is refused,
// obliwatchConsentOff) and by the tracking of the requests (actionTrack.ts: the open requests withdrawn). No import
// but the switch: the guard engine depends on nothing else of the integration.
// =============================================================================

/** Does a guarded action come from an action request of Obliwatch (its selection, actions.ts)? */
export function isObliwatchSelection(selection: unknown): boolean {
  return !!selection && typeof selection === 'object' && (selection as { via?: unknown }).via === 'obliwatch';
}

/** Why the requests of Obliwatch may not act now, null when they may (in the caller's transaction or context). */
export async function obliwatchActionsClosed(q: Knex | Knex.Transaction, tenantId: number): Promise<'integration_off' | 'consent_revoked' | null> {
  if (!obliwatchIntegrationEnabled()) return 'integration_off';
  const row = await q('tenant_obliwatch_settings').where({ tenant_id: tenantId }).first('actions_enabled') as { actions_enabled?: boolean } | undefined;
  return row?.actions_enabled === true ? null : 'consent_revoked';
}
