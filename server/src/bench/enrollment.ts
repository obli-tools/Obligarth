import type { Knex } from 'knex';
import { truncateSerial, type BenchIdentityState } from '@obligarth/shared';
import { audit } from '../audit';
import { raiseInTx } from '../apple/alerts/service';
import { LEGACY_AGENT_ACTOR } from '../legacyAgent/actor';

// =============================================================================
// The enrollment by a token of a bench station (lot BANC §3.4), in the enrollment's transaction (tenant context,
// i:legacy-agent), BEFORE the use of the token is consumed:
//   - the provisioning of the token locked and in token_issued, and its target (station, tenant, group) still there and
//     not suspended, else the refusal of a bad token (a target suspended or removed meanwhile closes its provisionings
//     at once, closeTargetProvisionings; this check holds even if that were missed);
//   - hints.provisioningId, when the agent sends it (1.4.0), must be that provisioning: else 403 tokenInvalid (the
//     agent waits for a new configuration, no fallback), the use not consumed, bench.provisioning_mismatch;
//   - the identity by pairs of the same nature: (ADB serial read on the bench, Build.SERIAL of the agent) and (serial of
//     the label read on the bench, ril.serialnumber of the agent); a pair is comparable when both values are known and
//     not 'unknown'. A comparable pair that differs refuses the enrollment (token revoked by the technician who issued it,
//     provisioning failed identity_mismatch, bench.identity_mismatch and an alert); at least one comparable pair and
//     none different: confirmed; none comparable (an administrator on Android 10 and later): unconfirmed.
// The reply of a refusal is always the one of a refused token (no oracle).
// =============================================================================

export interface BenchEnrollmentLink { provisioningId: string; stationId: string; identityState: BenchIdentityState }

const JUNK = new Set(['', 'unknown', '0', 'null', 'none', '0123456789abcdef']);

/** A serial that can be compared: known, not a placeholder; upper case. */
export function comparableSerial(v: string | null | undefined): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (JUNK.has(s.toLowerCase()) || !/^[A-Za-z0-9._:-]{3,64}$/.test(s)) return null;
  return s.toUpperCase();
}

/** The identity of the device against its provisioning: 'mismatch' when a comparable pair differs. */
export function benchIdentity(prov: { adbSerial: string | null; hwSerial: string | null }, agent: { serial: string | null; samsungSerial: string | null }): BenchIdentityState {
  const pairs: Array<[string | null, string | null]> = [
    [comparableSerial(prov.adbSerial), comparableSerial(agent.serial)],
    [comparableSerial(prov.hwSerial), comparableSerial(agent.samsungSerial)],
  ];
  const comparable = pairs.filter(([a, b]) => a !== null && b !== null);
  if (comparable.some(([a, b]) => a !== b)) return 'mismatch';
  return comparable.length > 0 ? 'confirmed' : 'unconfirmed';
}

/**
 * The checks of a bench token. `token`: its row (origin bench). Returns the link to write once the device is created,
 * or 'refused' (the caller answers tokenInvalid; what this function wrote commits with the transaction).
 */
export async function checkBenchEnrollment(trx: Knex.Transaction, tenantId: number, token: { id: string; bench_provisioning_id: string | null; created_by: number },
  agent: { serial: string | null; samsungSerial: string | null; provisioningId: string | null | undefined }): Promise<BenchEnrollmentLink | 'refused'> {
  if (!token.bench_provisioning_id) return 'refused';
  const p = await trx('bench_provisionings').where({ tenant_id: tenantId, id: token.bench_provisioning_id, enrollment_token_id: token.id })
    .forUpdate().first('id', 'state', 'kind', 'station_id', 'group_id', 'adb_serial', 'hw_serial') as Record<string, any> | undefined;
  if (!p || p.state !== 'token_issued' || p.kind !== 'new') return 'refused';
  const benchTarget = await trx('bench_station_targets').where({ station_id: p.station_id, tenant_id: tenantId, group_id: p.group_id })
    .whereNull('suspended_at').first('group_id');
  if (!benchTarget) return 'refused';
  const provisioningId = String(p.id).toLowerCase();
  const ctx = await audit.fromDbActor(LEGACY_AGENT_ACTOR, tenantId);
  const target = { type: 'bench_provisioning', id: provisioningId };
  if (agent.provisioningId && agent.provisioningId.toLowerCase() !== provisioningId) {
    await audit.appendInTx(trx, {
      tenantId, action: 'bench.provisioning_mismatch', target, details: { provisioningId, stationId: String(p.station_id), tokenId: token.id },
    }, ctx, { onFailure: 'spool' });
    return 'refused';
  }
  const identity = benchIdentity({ adbSerial: p.adb_serial, hwSerial: p.hw_serial ?? null }, { serial: agent.serial, samsungSerial: agent.samsungSerial });
  if (identity === 'mismatch') {
    const now = new Date();
    await trx('legacy_agent_enrollment_tokens').where({ tenant_id: tenantId, id: token.id }).whereNull('revoked_at')
      .update({ revoked_at: now, revoked_by: token.created_by });
    await trx('bench_provisionings').where({ tenant_id: tenantId, id: provisioningId })
      .update({ state: 'failed', error_code: 'identity_mismatch', outcome_at: now, updated_at: now });
    await audit.appendInTx(trx, {
      tenantId, action: 'bench.identity_mismatch', target,
      details: {
        provisioningId, stationId: String(p.station_id), tokenId: token.id, benchAdbSerial: truncateSerial(p.adb_serial),
        benchHwSerial: truncateSerial(p.hw_serial ?? null), agentSerial: truncateSerial(agent.serial), agentSamsungSerial: truncateSerial(agent.samsungSerial),
      },
    }, ctx, { onFailure: 'spool' });
    await raiseInTx(trx, tenantId, 'bench.identity_mismatch', { discriminant: provisioningId, navigateTo: '/legacy-agent' });
    return 'refused';
  }
  return { provisioningId, stationId: String(p.station_id).toLowerCase(), identityState: identity };
}

/** The provisioning enrolled, in the same transaction as the device's creation. */
export async function linkBenchEnrollment(trx: Knex.Transaction, tenantId: number, link: BenchEnrollmentLink, deviceId: number): Promise<void> {
  await trx('bench_provisionings').where({ tenant_id: tenantId, id: link.provisioningId, state: 'token_issued' })
    .update({ state: 'enrolled', device_id: deviceId, updated_at: new Date() });
}
