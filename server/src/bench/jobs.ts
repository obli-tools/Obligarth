import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit, type AuditEntryInput } from '../audit';
import { db } from '../db';
import { asNone } from '../db/context';
import type { LegacyAgentMinuteStep } from '../legacyAgent/jobs';
import { BENCH_JOB_ACTOR } from './actor';

// =============================================================================
// The expiries of the bench (lot BANC §3.6), a step of the minute job of the bridge agent (registerLegacyAgentMinuteStep,
// no new job): bench_expire_open (j:bench-expire) expires the provisionings open for more than 120 minutes (their tokens
// expire by themselves: no revocation without a user), revokes the stations pending for more than 24 hours, suspends
// those silent for 90 days and closes the past sessions. Each change audited: a provisioning in its tenant's journal, a
// station or a session in the platform's.
// =============================================================================

export const benchExpireStep: LegacyAgentMinuteStep = async (ctx) => {
  const rows = await asNone(BENCH_JOB_ACTOR, () => db.transaction((trx) => trx.raw('SELECT * FROM obligarth.bench_expire_open()'))) as
    { rows: Array<{ what: string; tenant_id: number | null; ref: string }> };
  const out = { benchProvisioningsExpired: 0, benchStationsExpired: 0, benchStationsIdle: 0, benchSessionsClosed: 0 };
  if (rows.rows.length === 0) return out;
  const auditCtx = audit.fromJob({ name: 'bench-expire', requestId: ctx.requestId });
  const entries: AuditEntryInput[] = [];
  for (const r of rows.rows) {
    const ref = String(r.ref);
    if (r.what === 'provisioning' && r.tenant_id !== null) {
      out.benchProvisioningsExpired++;
      entries.push({ tenantId: Number(r.tenant_id), action: 'bench.provisioning_expired', target: { type: 'bench_provisioning', id: ref }, details: { provisioningId: ref } });
    } else if (r.what === 'station_expired') {
      out.benchStationsExpired++;
      entries.push({ tenantId: MASTER_TENANT_ID, action: 'bench.station_revoked', target: { type: 'bench_station', id: ref }, details: { stationId: ref, reason: 'pending_expired' } });
    } else if (r.what === 'station_idle') {
      out.benchStationsIdle++;
      entries.push({ tenantId: MASTER_TENANT_ID, action: 'bench.station_suspended', target: { type: 'bench_station', id: ref }, details: { stationId: ref, reason: 'idle' } });
    } else if (r.what === 'session') {
      out.benchSessionsClosed++;
      entries.push({ tenantId: MASTER_TENANT_ID, action: 'bench.session_closed', target: { type: 'bench_session', id: ref }, details: { sessionId: ref, reason: 'expired' } });
    }
  }
  for (const e of entries) await audit.append(e, auditCtx);
  return out;
};
