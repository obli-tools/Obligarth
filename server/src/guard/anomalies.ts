// Anomalies and automatic freeze (docs: audit-durci §10.9). Counted in the
// journal (entries guard.action_refused and guard.action_paused and their
// details.code): it survives restarts and keeps no state.
//   A1  second excess of the hourly cap (refusal or pause) in a tenant in
//       24 h: the tenant is frozen;
//   A2  third refusal for cooldown in a tenant in 24 h: the tenant is frozen;
//   A3  one actor requests guarded actions in 2 tenants or more in 1 hour:
//       critical alert to every platform administrator, no freeze.
//   remote.burst (P0-15 §4.6)  more than 10 remote assistance sessions asked
//       by one operator in a tenant in 1 hour: warning to the tenant and the
//       MSP, no freeze (counted by server/src/remote/routes.ts).
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { db } from '../db';
import { asTenant, type DbActor } from '../db/context';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';
import { alertTenants } from './notify';

const SYSTEM_ACTOR: DbActor = { type: 'job', name: 'guard.anomalies' };

/** Refusals and pauses of a kind in the tenant's chain in the last 24 h. */
async function countRecent(tenantId: number, codes: { refused?: string; paused?: string }): Promise<number> {
  const parts: string[] = [];
  const params: Array<string | number> = [tenantId];
  if (codes.refused) { parts.push("(action = 'guard.action_refused' AND details->>'code' = ?)"); params.push(codes.refused); }
  if (codes.paused) { parts.push("(action = 'guard.action_paused' AND details->>'code' = ?)"); params.push(codes.paused); }
  if (!parts.length) return 0;
  const res = await asTenant(tenantId, SYSTEM_ACTOR, () => db.raw(
    `SELECT count(*)::integer AS n FROM audit_logs
      WHERE tenant_id = ? AND created_at > now() - interval '24 hours' AND (${parts.join(' OR ')})`,
    params,
  )) as { rows: Array<{ n: number }> };
  return Number(res.rows[0]?.n ?? 0);
}

export type AnomalyRule = 'A1' | 'A2';

/** The rule a tenant now breaks (A1, A2), or null. Called after a refusal
 *  or a pause was written. */
export async function anomalyOf(tenantId: number): Promise<AnomalyRule | null> {
  try {
    if (await countRecent(tenantId, { refused: 'hourlyCapExceeded', paused: 'cap' }) >= 2) return 'A1';
    if (await countRecent(tenantId, { refused: 'privilegeCooldown' }) >= 3) return 'A2';
  } catch (err) {
    logger.error({ err: safeErr(err), tenantId }, 'guard: anomaly count failed');
  }
  return null;
}

/** A3: in how many tenants did the user of the current context request
 *  guarded actions of these families in the last hour
 *  (obligarth.guard_actor_recent_tenants: the actor's own requests, read
 *  across tenants by the database; nothing for another account). */
export async function actorRecentTenants(families: string[]): Promise<number> {
  const res = await db.raw('SELECT obligarth.guard_actor_recent_tenants(?::text[]) AS n', [families]) as
    { rows: Array<{ n: number }> };
  return Number(res.rows[0]?.n ?? 0);
}

/** The A3 alert (critical, master tenant: every platform administrator). */
export async function alertA3(userId: number, tenants: number): Promise<void> {
  const hour = new Date().toISOString().slice(0, 13);
  await alertTenants([MASTER_TENANT_ID], {
    severity: 'critical',
    title: 'Destructive actions requested in several tenants',
    message: `Account #${userId} requested guarded actions in ${tenants} tenants within one hour.`,
    stableKey: `guard:a3:${userId}:${hour}`,
    navigateTo: '/admin/security?tab=guard',
  });
}

/** remote.burst (P0-15 §4.6): one operator asked more than REMOTE_LIMITS.burstPerHour remote assistance sessions in
 *  a tenant within an hour. A warning to the tenant (its administrators and its client approvers) and to the master
 *  tenant (the MSP); one per operator, tenant and hour (stable key). No freeze: a session targets one device. */
export async function alertRemoteBurst(tenantId: number, userId: number, sessions: number): Promise<void> {
  const hour = new Date().toISOString().slice(0, 13);
  await alertTenants([tenantId, MASTER_TENANT_ID], {
    severity: 'warning',
    title: 'Burst of remote assistance sessions',
    message: `Account #${userId} asked ${sessions} remote assistance sessions within one hour in tenant #${tenantId}.`,
    stableKey: `remote:burst:${tenantId}:${userId}:${hour}`,
    navigateTo: '/remote-sessions',
  });
}
