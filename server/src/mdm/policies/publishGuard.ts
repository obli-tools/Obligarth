import type { Request } from 'express';
import { POLICY_PUBLISH_ACTION, PUBLISH_APPROVAL_THRESHOLDS, SocketEvents, type PolicyImpact } from '@obligarth/shared';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { refuse } from '../../services/approval.service';
import { permissionService } from '../../services/permission.service';
import { restrictionFloor, restrictionService } from '../../services/restriction.service';
import { getIO } from '../../socket';
import { impactGrew, type ImpactResult } from './impact';
import { decodeSpread, keyWithoutInstance, widerEntry } from './impactPure';

// =============================================================================
// What the guarded changes of the configuration share (docs:
// modele-donnees-mdm §7.11, §7.12, DM23): the publication of a version and a
// batch of assignment changes (publish.ts), a change of the tree of groups
// (groupTree.ts). The level a change needs, the step-up of a change below the
// thresholds, the refusal of a change whose level rose between the look that
// asked the second factor and the decision under the lock, and what the
// execution of an approved request compares with what was approved.
// =============================================================================

export type RouteOutcome = { status: number; body: unknown; headers?: Record<string, string> };

export type Level = 'none' | 'sensitive' | 'restricted';

const RANK: Record<Level, number> = { none: 0, sensitive: 1, restricted: 2 };

/** The stricter of two levels. */
export const strictest = (a: Level, b: Level): Level => (RANK[a] >= RANK[b] ? a : b);

/** POLICY_CHANGED to the tenant's room (identifiers only); never throws. */
export function emitPolicyChanged(tenantId: number, policyIds: number[]): void {
  if (!policyIds.length) return;
  try { getIO().to(`tenant:${tenantId}`).emit(SocketEvents.POLICY_CHANGED, { policyIds }); } catch { /* no Socket.io in this process */ }
}

/** The level of mdm.policy_publish in the tenant's matrix (never below its floor: a step-up). */
export async function matrixLevel(tenantId: number): Promise<Level> {
  return restrictionService.getLevelFor({ tenantId, actionKey: POLICY_PUBLISH_ACTION });
}

/** The level a publication or a batch of assignment changes needs: the tenant's matrix, raised to 'restricted'
 *  beyond the thresholds. */
export async function requiredLevel(tenantId: number, impact: PolicyImpact): Promise<Level> {
  const level = await matrixLevel(tenantId);
  return impact.approval.required ? 'restricted' : level;
}

/** The step-up of a change below the thresholds: null when proven, the refusal to send otherwise. */
export async function stepUp(req: Request, actionKey: string = POLICY_PUBLISH_ACTION): Promise<RouteOutcome | null> {
  const { checkSecondFactor } = await import('../../services/deviceKey/stepUpProof');
  const outcome = await checkSecondFactor(req, {
    actionKey, allowTrustedIp: restrictionFloor(actionKey)?.strictStepUp !== true, allowDevice: true,
  });
  if (outcome.ok) { req.stepUpVia = outcome.via; return null; }
  return { status: outcome.status, body: outcome.body, headers: outcome.headers };
}

/** The caller's visible devices (the sample of a preview, S13). */
export async function visibleDevices(req: Request): Promise<number[] | 'all'> {
  if (req.session.role === 'admin') return 'all';
  const userId = req.session.userId!;
  const tenantId = req.tenantId!;
  const ut = await db('user_tenants').where({ user_id: userId, tenant_id: tenantId }).first('role') as { role: string } | undefined;
  if (ut?.role === 'admin') return 'all';
  return permissionService.getVisibleDeviceIds(userId, false);
}

/**
 * The decision is taken under the lock of the tenant's configuration, on a preview computed there. When that
 * preview asks more than the request proved (a second factor it was not asked for: another change was written
 * meanwhile), nothing is written: the caller submits again and is asked what the change needs now.
 */
export function impactChanged(): never {
  throw new AppError(409, 'The impact of the change is no longer the one that was checked: submit it again', 'impactChanged');
}

/** What a request for approval kept of its preview (impact.ts, approvalImpact). */
export interface ApprovedImpact {
  devicesTouched: number;
  artifacts: PolicyImpact['artifacts'];
  /** Digest of the content the approval was given on. */
  digest: string;
  /** The devices each entry of that content reached, by entry name (impactPure.ts: entryName, decodeSpread). */
  spread: Record<string, number>;
}

/** The preview a request was approved with; null when the payload carries none, or none with its digest and the
 *  devices of each of its entries (a request filed before they were kept is not executed: it is filed again). */
export function approvedImpactOf(payload: { impact?: unknown }): ApprovedImpact | null {
  const i = payload.impact as (Partial<Omit<ApprovedImpact, 'spread'>> & { spread?: unknown }) | undefined;
  if (!i || typeof i !== 'object' || typeof i.devicesTouched !== 'number' || !i.artifacts
    || typeof i.artifacts.removals !== 'number' || typeof i.digest !== 'string' || !/^[0-9a-f]{64}$/.test(i.digest)) return null;
  const spread = decodeSpread(i.spread);
  return spread ? { devicesTouched: i.devicesTouched, artifacts: i.artifacts, digest: i.digest, spread } : null;
}

/**
 * Refuses the execution of an approved request whose preview, computed again under the lock, is no longer the one
 * that was approved: more devices touched or more removals than the tolerance of DM23 (impactChanged), another
 * content, whatever the number of devices (contentChanged: a policy the change depends on was published, assigned
 * or moved since the request; DM10, an approval bears on a frozen content), or the same content on the same number
 * of devices but spread otherwise (impactChanged: a key of the change reaches more devices than approved, beyond
 * the same tolerance; an exclusion or a stronger assignment that kept it away was changed since the request).
 */
export function refuseUnlessAsApproved(approved: ApprovedImpact, now: ImpactResult, again: string): void {
  if (impactGrew(approved, now.impact)) {
    refuse(`impactChanged: ${now.impact.devicesTouched} device(s) touched and ${now.impact.artifacts.removals} removal(s) now, `
      + `${approved.devicesTouched} and ${approved.artifacts.removals} approved; ${again}`);
  }
  if (now.digest !== approved.digest) {
    refuse(`contentChanged: the change no longer sets what was approved (a policy it depends on was published, assigned or `
      + `inherited otherwise since the request); ${again}`);
  }
  const wider = widerEntry(approved.spread, now.content, PUBLISH_APPROVAL_THRESHOLDS.recheckTolerance);
  if (wider) {
    // The key without the instance of its collection: the refusal is journaled with the request.
    refuse(`impactChanged: ${keyWithoutInstance(wider.entry.settingKey)} would now change on ${wider.entry.devices} device(s), `
      + `${wider.approved} approved; ${again}`);
  }
}
