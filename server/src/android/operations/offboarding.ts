// Offboarding of a client and unlink of its Android enterprise (lot AN-H1; android-amapi §6.5, AN27; criterion 15: a
// controlled final state — tokens and policies deleted, topic removed, enterprise unlinked).
//   - Request: POST /api/android/enterprise/unlink (capability of the integrations and restriction
//     android.enterprise_unlink, floor restricted: a second approver of the guard's side, reason required, strict
//     step-up of the reviewer). The request is an approval of type android_enterprise_unlink, examined by the guard's
//     policy (guardReviewerPolicy: never the requester, the side the tenant's matrix asks, the cool-down of new
//     rights); audited android.enterprise_unlink_requested (critical).
//   - Execution, once approved: the enterprise goes unlinking and the durable job android.offboard-tenant walks the
//     steps, each one idempotent and resumable (android.maintenance sends it again when a step waits or failed):
//       revoking         the sign-in URL emptied (signinDetails [], lot AN-F2), new enrollments refused
//                        (createEnrollmentToken wants linked), tokens deleted at Google and
//                        revoked (their value destroyed);
//       waiting_devices  the managed devices are never erased by the procedure: the console offers, by batch, the
//                        guarded action that fits (mdm.erase_device, mdm.remove_management; WIPE and
//                        RELINQUISH_OWNERSHIP stay admitted while unlinking, gateway/commandStates.ts); each pass reads
//                        devices.list whole and takes out the devices gone at Google (operations/gone.ts:
//                        removed_by_command or missing_in_provider, race guard of the reconciliation, which is
//                        suspended meanwhile); the job waits until none is left, or the operator forces the rest
//                        (android_enterprise_force_unlink, a separate restricted request, audited android.enterprise_force_unlinked: they keep their last policy);
//       deleting         the own policies of the devices, the enrollment policies of the profiles and 'default' are
//                        deleted (a policy still referenced by a device left by force stays: counted), the tokens no
//                        row knows are collected at Google;
//       releasing        setEnterpriseNotifications(e, false): topic and notification types removed (audited
//                        android.enterprise_released); from then on the pull loop ignores the enterprise;
//       done             the devices left leave management (offboarding), the enterprise is unlinked (released, or
//                        offboarding when the release failed for lack of access), audited android.enterprise_unlinked
//                        (critical: reason, devices left), and the console shows the client the steps in its Google
//                        admin console (ANDROID_OFFBOARDING_GUIDE).
//   - Unlink seen from outside (the client removed the link in its Google console): a 403 of the enterprise puts it in
//     error (markEnterpriseAccessLost, critical tenant alert android.enterprise_unlinked_externally), nothing deleted;
//     the operator confirms unlinked (external).
//   - Deletion of a tenant: assertTenantDeletable() refuses 409 tenantHasAndroidEnterprise while its enterprise is not
//     unlinked (hook of tenantService.delete at the junction AN-A2).
import type { Request } from 'express';
import {
  ANDROID_APPROVAL_TYPES, ANDROID_OFFBOARDING_GUIDE, type AndroidOffboardingStep, type AndroidOffboardingView,
} from '@obligarth/shared';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { guardReviewerPolicy, requiredSideFor, refuseHeldFallback } from '../../guard/approvals';
import { personFacts } from '../../guard/people';
import { AppError } from '../../middleware/errorHandler';
import {
  approvalService, registerApprovalRequestType, requireTenantCapability as requesterHolds, type ApprovalExecution, type ApprovalRequestType,
} from '../../services/approval.service';
import { logger } from '../../utils/logger';
import { raiseAndroidTenantAlert } from '../alerts';
import { endToken, recoverEnrollmentTokens } from '../enrollment/tokens';
import { clearSigninForOffboarding } from '../signin/config';
import { readEnterprise, readEnterpriseRow } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { AndroidError } from '../gateway/errors';
import { parseOwnedName, type AndroidEnterpriseRef } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { exitManagement } from './exit';
import { releaseDevicesGoneAtGoogle } from './gone';

export const OFFBOARD_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.offboard-tenant' }) as DbActor;
/** Capability of the integrations (AN41). */
export const INTEGRATIONS_CAPABILITY = 'mdm.integrations.manage' as const;
const WAIT_MINUTES = 10;
const RETRY_MINUTES = 5;

export class OffboardingError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message = code) {
    super(message);
    this.name = 'OffboardingError';
    this.status = status;
    this.code = code;
  }
}

/** android.offboard-tenant of a tenant (bound to the durable job by jobs.ts; the tests record it). */
type OffboardSender = (tenantId: number) => Promise<unknown>;
let offboardSender: OffboardSender = async () => undefined;
export function setOffboardSender(fn: OffboardSender): void { offboardSender = fn; }

const reasonOf = (raw: unknown): string => {
  const r = typeof raw === 'string' ? raw.trim() : '';
  if (r.length < 5 || r.length > 500) throw new OffboardingError(400, 'reasonRequired', 'A reason of 5 to 500 characters is required');
  return r;
};

// ── Unlink seen from outside ─────────────────────────────────────────────────

/** A 403 of the enterprise: linked → error, critical alert, nothing deleted (tenant context of the caller or given). */
export async function markEnterpriseAccessLost(tenantId: number): Promise<boolean> {
  const n = await asTenant(tenantId, OFFBOARD_ACTOR, () => db('android_enterprises').where({ tenant_id: tenantId, state: 'linked' })
    .update({ state: 'error', updated_at: db.fn.now() }));
  if (n) {
    logger.warn({ android: { enterprise: 'access_lost', tenantId } }, 'android: access to the enterprise lost (unlinked outside Obligarth?)');
    void raiseAndroidTenantAlert(tenantId, 'android.enterprise_unlinked_externally', { tenantId });
  }
  return n > 0;
}

/** The operator confirms an enterprise in error as unlinked from outside (external): its devices leave management. */
export async function confirmExternalUnlink(tenantId: number, userId: number, auditCtx: AuditWriteContext): Promise<'unlinked'> {
  return asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
    const row = await readEnterpriseRow(trx, { forUpdate: true });
    if (!row || row.state !== 'error') throw new OffboardingError(409, 'androidEnterpriseNotInError', 'the enterprise is not in error');
    const left = await releaseDevicesLeft(trx, tenantId, row.id);
    await trx('android_enterprises').where({ id: row.id }).update({ state: 'unlinked', unlink_reason: 'external', unlinked_at: trx.fn.now(), updated_at: trx.fn.now() });
    await audit.appendInTx(trx, {
      tenantId, action: 'android.enterprise_unlinked', target: { type: 'android_enterprise', id: String(row.id) },
      details: { reason: 'external', devicesLeft: left },
    }, auditCtx);
    return 'unlinked' as const;
  }));
}

/** An enterprise in error is read again at Google: reachable → linked again (rétablie). */
export async function recheckEnterpriseAccess(tenantId: number, o: { gateway?: AndroidGateway } = {}): Promise<'linked' | 'error' | 'not_in_error'> {
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, OFFBOARD_ACTOR, async () => {
    const e = await readEnterprise();
    if (!e || e.state !== 'error') return 'not_in_error';
    try {
      await gw.getEnterprise(e);
    } catch (err) {
      if (err instanceof AndroidError && (err.kind === 'access_lost' || err.kind === 'not_found')) return 'error';
      throw err;
    }
    await db('android_enterprises').where({ id: e.id, state: 'error' }).update({ state: 'linked', updated_at: db.fn.now() });
    return 'linked';
  });
}

// ── Requests (restricted) ────────────────────────────────────────────────────

async function fileRequest(req: Request | null, tenantId: number, userId: number, type: string, description: string,
  payload: Record<string, unknown>, auditCtx: AuditWriteContext, extra?: (trx: import('knex').Knex.Transaction) => Promise<void>) {
  const required = await requiredSideFor(await personFacts(userId, tenantId), tenantId);
  refuseHeldFallback(required);
  const approval = await db.transaction(async (trx) => {
    const a = await approvalService.createInTx(trx, {
      tenantId, userId, requestType: type as ApprovalRequestType, description,
      payload: { ...payload, action: type, requiredSide: required.side, approverFallback: required.fallback }, auditCtx,
    });
    if (extra) await extra(trx);
    return a;
  });
  approvalService.announceCreated(approval);
  void req;
  return approval;
}

/** POST /enterprise/unlink: a restricted request (second approver), audited android.enterprise_unlink_requested. */
export async function requestUnlink(tenantId: number, userId: number, body: { reason?: unknown }, auditCtx: AuditWriteContext, req: Request | null = null) {
  const reason = reasonOf(body?.reason);
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    const row = await readEnterpriseRow();
    if (!row || (row.state !== 'linked' && row.state !== 'error')) throw new OffboardingError(409, 'androidNotLinked', 'no linked Android enterprise');
    if (await db('android_offboardings').where({ tenant_id: tenantId }).whereNull('finished_at').first('id')) {
      throw new OffboardingError(409, 'androidOffboardingInProgress', 'an offboarding is in progress');
    }
    return fileRequest(req, tenantId, userId, ANDROID_APPROVAL_TYPES.unlink, `Unlink the Android enterprise of the tenant — reason: ${reason}`,
      { enterpriseId: row.id, reason }, auditCtx, async (trx) => {
        await audit.appendInTx(trx, {
          tenantId, action: 'android.enterprise_unlink_requested', target: { type: 'android_enterprise', id: String(row.id) }, details: { reason },
        }, auditCtx);
      });
  });
}

/** POST /enterprise/unlink/force: a separate restricted request, while the procedure waits for managed devices. */
export async function requestForceUnlink(tenantId: number, userId: number, body: { reason?: unknown }, auditCtx: AuditWriteContext, req: Request | null = null) {
  const reason = reasonOf(body?.reason);
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    const off = await db('android_offboardings').where({ tenant_id: tenantId }).whereNull('finished_at').first('id', 'step', 'forced_at') as
      { id: string; step: AndroidOffboardingStep; forced_at: Date | null } | undefined;
    if (!off || off.forced_at || (off.step !== 'waiting_devices' && off.step !== 'revoking')) {
      throw new OffboardingError(409, 'androidOffboardingNotWaiting', 'no offboarding waiting for devices');
    }
    return fileRequest(req, tenantId, userId, ANDROID_APPROVAL_TYPES.forceUnlink,
      `Force the unlink of the Android enterprise, devices left managed by Google — reason: ${reason}`, { offboardingId: off.id, reason }, auditCtx);
  });
}

/** Executor of android_enterprise_unlink: the procedure starts (unlinking, android.offboard-tenant). */
export async function executeUnlink(x: ApprovalExecution): Promise<string | void> {
  await requesterHolds(x.requesterId, x.tenantId, INTEGRATIONS_CAPABILITY);
  const reason = reasonOf((x.payload as { reason?: unknown })?.reason);
  const started = await db.transaction(async (trx) => {
    const row = await readEnterpriseRow(trx, { forUpdate: true });
    if (!row || (row.state !== 'linked' && row.state !== 'error')) throw new OffboardingError(409, 'androidNotLinked', 'no linked Android enterprise');
    if (Number((x.payload as { enterpriseId?: unknown }).enterpriseId) !== row.id) throw new OffboardingError(409, 'androidEnterpriseChanged', 'the enterprise changed');
    if (await trx('android_offboardings').where({ tenant_id: x.tenantId }).whereNull('finished_at').first('id')) return false;
    await trx('android_enterprises').where({ id: row.id }).update({ state: 'unlinking', unlink_requested_at: trx.fn.now(), updated_at: trx.fn.now() });
    await trx('android_offboardings').insert({
      tenant_id: x.tenantId, enterprise_id: row.id, approval_id: x.approvalId ?? null, requested_by: x.requesterId, reason,
    });
    return true;
  });
  if (started) await offboardSender(x.tenantId);
  return started ? undefined : 'an offboarding was already in progress';
}

/** Executor of android_enterprise_force_unlink: the procedure goes on without waiting for the devices left. */
export async function executeForceUnlink(x: ApprovalExecution): Promise<string | void> {
  await requesterHolds(x.requesterId, x.tenantId, INTEGRATIONS_CAPABILITY);
  const ctx = await audit.fromDbActor({ type: 'user', userId: x.requesterId }, x.tenantId);
  await db.transaction(async (trx) => {
    const off = await trx('android_offboardings').where({ tenant_id: x.tenantId, id: String((x.payload as { offboardingId?: unknown }).offboardingId ?? '') })
      .whereNull('finished_at').forUpdate().first('id', 'enterprise_id', 'forced_at') as { id: string; enterprise_id: number; forced_at: Date | null } | undefined;
    if (!off) throw new OffboardingError(409, 'androidOffboardingNotWaiting', 'no offboarding waiting for devices');
    if (off.forced_at) return;
    const left = await devicesLeft(trx, x.tenantId, off.enterprise_id);
    await trx('android_offboardings').where({ id: off.id }).update({ forced_at: trx.fn.now(), forced_by: x.requesterId, devices_left: left, next_run_at: trx.fn.now() });
    await audit.appendInTx(trx, {
      tenantId: x.tenantId, action: 'android.enterprise_force_unlinked', target: { type: 'android_enterprise', id: String(off.enterprise_id) },
      approvalIds: x.approvalId ? [x.approvalId] : [], details: { devicesLeft: left, offboardingId: off.id },
    }, ctx);
  });
  await offboardSender(x.tenantId);
}

// ── The procedure (android.offboard-tenant) ──────────────────────────────────

async function devicesLeft(q: import('knex').Knex | import('knex').Knex.Transaction, tenantId: number, enterpriseId: number): Promise<number> {
  const r = await q('android_devices').where({ tenant_id: tenantId, enterprise_id: enterpriseId }).whereNull('released_at').count<{ n: string }[]>('* as n');
  return Number(r[0]?.n ?? 0);
}

/** The devices of the enterprise still managed leave management (offboarding); their count. */
async function releaseDevicesLeft(trx: import('knex').Knex.Transaction, tenantId: number, enterpriseId: number): Promise<number> {
  const ids = await trx('android_devices').where({ tenant_id: tenantId, enterprise_id: enterpriseId }).whereNull('released_at').pluck('device_id') as number[];
  for (const id of ids) await exitManagement(trx, tenantId, Number(id), 'offboarding');
  return ids.length;
}

/** Google errors that mean « nothing to do there any more » during an offboarding (access lost, already gone). */
const goneAtGoogle = (err: unknown): boolean => err instanceof AndroidError && (err.kind === 'not_found' || err.kind === 'access_lost');

interface OffRow { id: string; enterprise_id: number; step: AndroidOffboardingStep; forced_at: Date | null; tokens_revoked: number;
  policies_deleted: number; policies_kept: number; release_failed: boolean }

export type OffboardOutcome = 'none' | 'waiting' | 'done' | 'retry';

export async function runOffboarding(tenantId: number, o: { gateway?: AndroidGateway } = {}): Promise<OffboardOutcome> {
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, OFFBOARD_ACTOR, async () => {
    const off = await db('android_offboardings').where({ tenant_id: tenantId }).whereNull('finished_at')
      .first('id', 'enterprise_id', 'step', 'forced_at', 'tokens_revoked', 'policies_deleted', 'policies_kept', 'release_failed') as OffRow | undefined;
    if (!off) return 'none';
    const e = await readEnterprise();
    const step = (s: AndroidOffboardingStep, patch: Record<string, unknown> = {}) =>
      db('android_offboardings').where({ id: off.id }).update({ step: s, next_run_at: db.fn.now(), attempts: 0, last_error: null, ...patch });
    try {
      if (off.step === 'revoking') {
        // The sign-in URL first (lot AN-F2, raccord): no device is sent to the surface of a client leaving.
        if (e && e.state === 'unlinking') {
          const ctx = audit.fromJob({ name: 'android.offboard-tenant', requestId: `android-offboard-${tenantId}-${off.id}` });
          try { await clearSigninForOffboarding(gw, e, tenantId, ctx); } catch (err) { if (!goneAtGoogle(err)) throw err; }
        }
        off.tokens_revoked += await revokeTokens(gw, e, tenantId, off.enterprise_id);
        await step('waiting_devices', { tokens_revoked: off.tokens_revoked });
        off.step = 'waiting_devices';
      }
      if (off.step === 'waiting_devices') {
        let left = await devicesLeft(db, tenantId, off.enterprise_id);
        // Review AN-H1 (H1R-1, §6.5 step 2): the reconciliation is suspended during an offboarding, so the devices
        // erased (or released) at Google while the procedure waits are seen here, with the same rule and race guard.
        if (left > 0 && !off.forced_at && e && e.state === 'unlinking') {
          try {
            const r = await releaseDevicesGoneAtGoogle(gw, e, tenantId);
            if (r.released) left = await devicesLeft(db, tenantId, off.enterprise_id);
          } catch (err) {
            // Access lost or enterprise gone: nothing can be checked at Google; the procedure keeps waiting (the
            // operator may force the rest). Any other error: the step is retried.
            if (!goneAtGoogle(err)) throw err;
          }
        }
        if (left > 0 && !off.forced_at) {
          await db('android_offboardings').where({ id: off.id }).update({
            devices_left: left, attempts: 0, last_error: null, next_run_at: db.raw('now() + make_interval(mins => ?)', [WAIT_MINUTES]),
          });
          return 'waiting';
        }
        await step('deleting', { devices_left: left });
        off.step = 'deleting';
      }
      if (off.step === 'deleting') {
        // Again (review AN-F2): a sign-in URL enabled by a console request that read the enterprise linked just before
        // the unlinking wrote it back after the revoking step; idempotent, nothing is sent when none is stored.
        if (e && e.state === 'unlinking') {
          const ctx = audit.fromJob({ name: 'android.offboard-tenant', requestId: `android-offboard-${tenantId}-${off.id}` });
          try { await clearSigninForOffboarding(gw, e, tenantId, ctx); } catch (err) { if (!goneAtGoogle(err)) throw err; }
        }
        const r = await deletePolicies(gw, e, tenantId, off.enterprise_id);
        if (e && e.state === 'unlinking') {
          try { await recoverEnrollmentTokens(tenantId, { gateway: gw, actor: OFFBOARD_ACTOR }); } catch (err) { if (!goneAtGoogle(err)) throw err; }
        }
        await step('releasing', { policies_deleted: off.policies_deleted + r.deleted, policies_kept: r.kept });
        off.step = 'releasing';
      }
      if (off.step === 'releasing') {
        let released = false;
        if (e && e.state === 'unlinking') {
          try {
            await gw.setEnterpriseNotifications(e, false);
            released = true;
          } catch (err) {
            if (!goneAtGoogle(err)) throw err;
          }
        }
        const ctx = audit.fromJob({ name: 'android.offboard-tenant', requestId: `android-offboard-${tenantId}-${off.id}` });
        await db.transaction(async (trx) => {
          const left = await releaseDevicesLeft(trx, tenantId, off.enterprise_id);
          await trx('android_offboardings').where({ id: off.id }).update({
            step: 'done', finished_at: trx.fn.now(), release_failed: !released, devices_left: left, last_error: null,
          });
          await trx('android_enterprises').where({ tenant_id: tenantId, id: off.enterprise_id }).whereNot('state', 'unlinked').update({
            state: 'unlinked', unlink_reason: released ? 'released' : 'offboarding', unlinked_at: trx.fn.now(), updated_at: trx.fn.now(),
          });
          await trx('android_enrollment_policies').where({ tenant_id: tenantId, enterprise_id: off.enterprise_id }).delete();
          if (released) {
            await audit.appendInTx(trx, {
              tenantId, action: 'android.enterprise_released', target: { type: 'android_enterprise', id: String(off.enterprise_id) },
              details: { enterpriseName: e?.name ?? null },
            }, ctx);
          }
          await audit.appendInTx(trx, {
            tenantId, action: 'android.enterprise_unlinked', target: { type: 'android_enterprise', id: String(off.enterprise_id) },
            details: { reason: released ? 'released' : 'offboarding', devicesLeft: left, offboardingId: off.id },
          }, ctx);
        });
        return 'done';
      }
      return 'waiting';
    } catch (err) {
      const code = err instanceof AndroidError ? err.kind : (err as { code?: string })?.code ?? 'error';
      await db('android_offboardings').where({ id: off.id }).update({
        attempts: db.raw('LEAST(attempts + 1, 32767)'), last_error: String(code).slice(0, 64),
        next_run_at: db.raw('now() + make_interval(mins => ?)', [RETRY_MINUTES]),
      });
      logger.warn({ android: { offboarding: off.step, tenantId, code } }, 'android: offboarding step failed, retried');
      return 'retry';
    }
  });
}

async function revokeTokens(gw: AndroidGateway, e: AndroidEnterpriseRef | null, tenantId: number, enterpriseId: number): Promise<number> {
  const rows = await db('android_enrollment_tokens').where({ tenant_id: tenantId, enterprise_id: enterpriseId }).whereIn('state', ['active', 'creating'])
    .select('id', 'token_name', 'value_ref', 'state') as Array<{ id: string; token_name: string | null; value_ref: string | null; state: string }>;
  let n = 0;
  for (const t of rows) {
    if (t.token_name && e && e.state === 'unlinking') {
      try {
        const p = parseOwnedName(e, t.token_name);
        if (p.kind === 'enrollmentToken') await gw.deleteEnrollmentToken(e, p.tokenId);
      } catch (err) {
        if (!goneAtGoogle(err)) throw err;
      }
    }
    await db.transaction(async (trx) => {
      const fresh = await trx('android_enrollment_tokens').where({ id: t.id }).whereIn('state', ['active', 'creating']).forUpdate().first('id', 'value_ref', 'state') as
        { id: string; value_ref: string | null; state: string } | undefined;
      if (!fresh) return;
      await endToken(trx, fresh, fresh.state === 'active' ? 'revoked' : 'failed', fresh.state === 'active' ? { revoked_at: trx.fn.now() } : {});
      n += 1;
    });
  }
  return n;
}

async function deletePolicies(gw: AndroidGateway, e: AndroidEnterpriseRef | null, tenantId: number, enterpriseId: number): Promise<{ deleted: number; kept: number }> {
  const out = { deleted: 0, kept: 0 };
  if (!e || e.state !== 'unlinking') return out;
  const devicePolicies = await db('android_devices as a').join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId, 'a.enterprise_id': enterpriseId }).select('d.uuid', 'a.released_at') as Array<{ uuid: string; released_at: Date | null }>;
  const enrollment = await db('android_enrollment_policies').where({ tenant_id: tenantId, enterprise_id: enterpriseId }).pluck('policy_id') as string[];
  const ids = [...devicePolicies.map((d) => `d-${d.uuid}`), ...enrollment, 'default'];
  for (const id of ids) {
    try {
      await gw.deletePolicy(e, id);
      out.deleted += 1;
    } catch (err) {
      if (err instanceof AndroidError && err.kind === 'not_found') continue;
      if (err instanceof AndroidError && (err.kind === 'request' || err.kind === 'access_lost')) { out.kept += 1; continue; }   // still referenced (forced)
      throw err;
    }
  }
  return out;
}

// ── Reads, guards ────────────────────────────────────────────────────────────

/** The offboarding of the tenant (the last one), for the console; null when none. */
export async function readOffboarding(tenantId: number, userId: number): Promise<AndroidOffboardingView | null> {
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    const r = await db('android_offboardings').where({ tenant_id: tenantId }).orderBy('started_at', 'desc').first() as Record<string, any> | undefined;
    if (!r) return null;
    return {
      id: String(r.id), step: r.step, startedAt: new Date(r.started_at).toISOString(), finishedAt: r.finished_at ? new Date(r.finished_at).toISOString() : null,
      devicesLeft: Number(r.devices_left), forced: r.forced_at !== null, releaseFailed: !!r.release_failed, tokensRevoked: Number(r.tokens_revoked),
      policiesDeleted: Number(r.policies_deleted), guide: r.step === 'done' ? [...ANDROID_OFFBOARDING_GUIDE] : [],
    };
  });
}

/**
 * Hook of tenantService.delete (junction AN-A2, README §5): 409 tenantHasAndroidEnterprise while the tenant's enterprise
 * is not unlinked. Runs in the tenant's context as the caller.
 */
export async function assertTenantDeletable(tenantId: number, actor: DbActor = OFFBOARD_ACTOR): Promise<void> {
  const live = await asTenant(tenantId, actor, () => db('android_enterprises').where({ tenant_id: tenantId }).whereNot('state', 'unlinked').first('id'));
  if (live) throw new AppError(409, 'The tenant still has an Android enterprise: unlink it first', 'tenantHasAndroidEnterprise');
}

let registered = false;
/** The approval request types of the unlink and of its forced end (registered by registerAndroidModule). */
export function registerAndroidOffboardingApprovals(): void {
  if (registered) return;
  registered = true;
  const options = { reviewerPolicy: guardReviewerPolicy, reviewerStepUp: 'strict' as const, expiryMinutes: 24 * 60 };
  registerApprovalRequestType(ANDROID_APPROVAL_TYPES.unlink, executeUnlink, options);
  registerApprovalRequestType(ANDROID_APPROVAL_TYPES.forceUnlink, executeForceUnlink, options);
}
