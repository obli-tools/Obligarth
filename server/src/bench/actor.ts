import type { DbActor } from '../db/context';
import type { AuditWriteContext } from '../audit';
import { audit } from '../audit';

// =============================================================================
// The actors of the bench stations (lot BANC §3.5): the station surface before a station is known (lookup,
// registration: i:bench-station), a known station (i:bench-station:<uuid>, the guard of its definer functions), the
// job of the expiries (j:bench-expire). The audit names a station by its id (the actor ref) and its name (the label),
// with the technician of the session in detail.technicianUserId.
// =============================================================================

export const BENCH_SURFACE_ACTOR: DbActor = { type: 'integration', name: 'bench-station' };
export const BENCH_JOB_ACTOR: DbActor = { type: 'job', name: 'bench-expire' };

export const stationActor = (stationId: string): DbActor => ({ type: 'integration', name: `bench-station:${stationId.toLowerCase()}` });

/** The audit context of a station's request (its name as the label of the actor). */
export async function stationAuditContext(stationId: string, stationName: string, chainTenantId: number,
  origin: { ip?: string; ua?: string; requestId?: string; route?: string } = {}): Promise<AuditWriteContext> {
  const ctx = await audit.fromDbActor(stationActor(stationId), chainTenantId, origin);
  return { ...ctx, actor: { ...ctx.actor, label: stationName.slice(0, 100) } };
}
