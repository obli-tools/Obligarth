import { MASTER_TENANT_ID } from '@obligarth/shared';
import { config } from '../config';
import { withTenantTransaction } from '../db/tenantContext';
import { edgeHealth } from '../apple/edge/health';
import { raiseInTx, resolveInTx } from '../apple/alerts/service';
import { stableKeyOf } from '../apple/alerts/catalog';
import { logger } from '../utils/logger';
import type { JobContext } from '../jobs/types';
import type { Knex } from 'knex';
import { family, single, type MetricFamily } from './metrics';
import { signingIdentityOf, signingUnusable } from './stage';

// =============================================================================
// The profile signing identity and the stage of the instance (P0-13 T11, D8, D12), as the server watches them. The
// identity is imported by the command of apple-edge (apple-edge signing-identity import, D12: never by the console);
// apple-edge announces it in its /status (edgeHealth().signingIdentity, probed every minute). Registered by
// modules/ops.ts:
//   readiness   'signing' (outside lab, APPLE_EDGE_MODE=on): an identity missing or expired makes the instance not
//               ready (code signing_identity_missing or signing_identity_expired); not heard yet: ready (the alerts of
//               apple-edge's probe tell it);
//   ops.watch   'signing' (same condition): the platform alert signing.identity_missing, critical, raised while the
//               identity is missing or expired, resolved once it is usable again. An open row of a lower severity (a
//               warning raised in lab, or by an enrollment before the stage changed) is resolved first, so that the
//               critical one is announced. The 30 days before its end are the deadline profile_signing_identity's.
//               An enrollment that finds the identity unusable outside lab raises it the same way
//               (raiseSigningCriticalInTx, apple/enrollment/flow.ts).
//   metrics     obligarth_instance_stage{stage}, obligarth_apple_signed_profiles_required and
//               obligarth_apple_signing_identity_usable (absent while unknown; the end of validity is
//               obligarth_apple_signing_identity_not_after_seconds, ops/collectors.ts).
// =============================================================================

const KIND = 'signing.identity_missing' as const;

/** The readiness check 'signing'. */
export function signingReady(): { ok: boolean; code?: string } {
  const v = signingIdentityOf(edgeHealth(), new Date());
  if (!signingUnusable(v.state)) return { ok: true };
  return { ok: false, code: v.state === 'expired' ? 'signing_identity_expired' : 'signing_identity_missing' };
}

/** The check 'signing' of ops.watch. A write that fails fails the check. */
export async function watchSigning(ctx: JobContext<unknown>): Promise<Record<string, string | number | boolean | null>> {
  const v = signingIdentityOf(edgeHealth(), new Date());
  if (v.state === 'unknown') return { state: v.state };
  const unusable = signingUnusable(v.state);
  await withTenantTransaction(MASTER_TENANT_ID, ctx.dbActor, async (trx) => {
    if (!unusable) {
      await resolveInTx(trx, MASTER_TENANT_ID, KIND);
      return;
    }
    const r = await raiseSigningCriticalInTx(trx);
    if (r.created) logger.error({ alert: KIND, state: v.state, stage: config.stage }, 'profile signing identity unusable outside the laboratory');
  });
  return { state: v.state, ...(v.daysLeft !== null ? { daysLeft: v.daysLeft } : {}) };
}

/** The critical alert signing.identity_missing of the master tenant, in the caller's transaction (its context): an
 *  open row of a lower severity (a warning raised in lab) is resolved first, so that the critical one is a new row and
 *  is announced (raiseInTx only raises the severity of an open row, without a delivery). */
export async function raiseSigningCriticalInTx(trx: Knex.Transaction): Promise<{ id: number; created: boolean }> {
  const open = await trx('live_alerts').where({ tenant_id: MASTER_TENANT_ID, stable_key: stableKeyOf(KIND) }).whereNull('resolved_at')
    .first('severity') as { severity: string } | undefined;
  if (open && open.severity !== 'critical') await resolveInTx(trx, MASTER_TENANT_ID, KIND);
  return raiseInTx(trx, MASTER_TENANT_ID, KIND, { severity: 'critical' });
}

/** The metric families of the stage and of the signing identity (collector 'stage'). */
export function stageFamilies(): MetricFamily[] {
  const apple = config.apple.mode === 'on';
  const v = signingIdentityOf(edgeHealth(), new Date());
  return [
    family('obligarth_instance_stage', 'Stage of the instance (OBLIGARTH_STAGE): 1 for the current one', 'gauge',
      [{ labels: { stage: config.stage }, value: 1 }]),
    single('obligarth_apple_signed_profiles_required', 'An unsigned enrollment profile is refused (1), served (0); absent: Apple off', 'gauge',
      apple ? (config.apple.requireSignedProfiles ? 1 : 0) : null),
    single('obligarth_apple_signing_identity_usable', 'apple-edge announces a usable profile signing identity (1), missing or expired (0); absent: unknown', 'gauge',
      apple && v.state !== 'unknown' ? (signingUnusable(v.state) ? 0 : 1) : null),
  ];
}
