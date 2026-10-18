// Follow-up jobs of the enrollment (section 10.4; §22.2, §22.3; AN17, AN36) and the approval of a device:
//   android.device-quarantine  the device not accepted is DISABLED (neutral translated message) under its minimal
//                              policy: the enrollment policy of its token when there is one, else the reserved policy
//                              'default' of the enterprise, so that the rule of the 5 minutes does not reset it before
//                              the operator decides (attach it to a profile, or forget it under the restriction
//                              android.device_forget of lot AN-D);
//   android.device-reject      devices.delete only if every condition of the narrow window still holds when the job
//                              runs (no record, enrollmentTime < 30 min, PROVISIONING, COMPANY_OWNED, hourly cap not
//                              reached), audited android.device_reject_executed (critical); otherwise a quarantine;
//   android.device-hold        a device enrolled with a token that requires an approval: DISABLED (waiting message),
//                              its enrollment policy kept, no secret, no own policy until approved;
//   android.device-cleanup     the AMAPI resource a re-enrollment replaced (previousDeviceNames) is deleted at Google
//                              through the gateway, which reads it again before (RR-4), then its policy d-<uuid>;
//   approveAndroidDevice       POST /api/android/devices/:id/approve (mdm.enrollment.manage; devices.manage until
//                              then): approved, audited, android.device-onboard (own policy, policyName, ACTIVE).
// The gateway holds the freeze lock and the last-resort caps (a frozen tenant: state patches and deletions refused).
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { AndroidError } from '../gateway/errors';
import { parseOwnedName, type AndroidEnterpriseRef } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { decisionCap, DISABLED_MESSAGES, enrollmentTimeOf, rejectAllowed } from './methods';
import { androidSenders } from './senders';

export const DECISIONS_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.device-decisions' }) as DbActor;

const deviceIdOf = (e: AndroidEnterpriseRef, amapiName: string): string => {
  const p = parseOwnedName(e, amapiName);
  if (p.kind !== 'device') throw new Error('android: not a device name');
  return p.deviceId;
};

interface QuarantineRow { id: number; amapi_name: string; token_id: string | null; decision: string; state: string; enrollment_time: Date | null; created_at: Date }

/** The minimal policy of a quarantined device: its token's enrollment policy, else 'default'. A device not known to
 *  be COMPANY_OWNED (a personal device on a company token: review of lot AN-F1) takes the enrollment policy of a
 *  personal profile only, never the settings nor the reports of a company profile. */
async function minimalPolicyOf(tokenId: string | null, amapiOwnership: string | null): Promise<string> {
  if (!tokenId) return 'default';
  const q = db('android_enrollment_tokens as t').join('android_enrollment_policies as p', function j() {
    this.on('p.profile_id', '=', 't.profile_id').andOn('p.tenant_id', '=', 't.tenant_id');
  }).where('t.id', tokenId).where('p.state', 'pushed');
  if (amapiOwnership !== 'COMPANY_OWNED') {
    q.join('enrollment_profiles as ep', function j() { this.on('ep.id', '=', 't.profile_id').andOn('ep.tenant_id', '=', 't.tenant_id'); })
      .where('ep.ownership', 'personal');
  }
  const r = await q.first('p.policy_id') as { policy_id: string } | undefined;
  return r?.policy_id ?? 'default';
}

export async function quarantineDevice(tenantId: number, quarantineId: number, o: { gateway?: AndroidGateway; actor?: DbActor } = {}): Promise<'done' | 'gone' | 'not_open'> {
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, o.actor ?? DECISIONS_ACTOR, async () => {
    const q = await db('android_quarantine').where({ id: quarantineId }).first('id', 'amapi_name', 'token_id', 'decision', 'state', 'amapi_ownership') as
      (QuarantineRow & { amapi_ownership: string | null }) | undefined;
    if (!q || q.state !== 'open') return 'not_open';
    const e = await readEnterprise();
    if (!e) return 'not_open';
    const policyName = await minimalPolicyOf(q.token_id, q.amapi_ownership);
    try {
      await gw.patchDevice(e, deviceIdOf(e, q.amapi_name), { state: 'DISABLED', disabledReason: { ...DISABLED_MESSAGES.quarantine }, policyName });
    } catch (err) {
      if (err instanceof AndroidError && err.kind === 'not_found') return 'gone';
      throw err;
    }
    return 'done';
  });
}

export async function rejectDevice(tenantId: number, quarantineId: number, o: { gateway?: AndroidGateway; actor?: DbActor; now?: Date } = {}):
  Promise<'rejected' | 'quarantined' | 'gone' | 'not_open'> {
  const gw = o.gateway ?? androidGateway();
  const actor = o.actor ?? DECISIONS_ACTOR;
  return asTenant(tenantId, actor, async () => {
    const q = await db('android_quarantine').where({ id: quarantineId }).first('id', 'amapi_name', 'token_id', 'decision', 'state', 'enrollment_time', 'created_at') as
      QuarantineRow | undefined;
    if (!q || q.state !== 'open' || q.decision !== 'reject') return 'not_open';
    const e = await readEnterprise();
    if (!e) return 'not_open';
    const id = deviceIdOf(e, q.amapi_name);
    // The conditions of the window, checked again now (section 10.4 step 4).
    const [record, hour, devices] = await Promise.all([
      db('android_devices').where({ amapi_name: q.amapi_name }).whereNull('released_at').first('device_id'),
      db('android_quarantine').where('created_at', '>', db.raw("now() - interval '1 hour'")).where('id', '<=', quarantineId).count<{ n: string }[]>('* as n'),
      db('android_devices').whereNull('released_at').count<{ n: string }[]>('* as n'),
    ]);
    const device = await gw.getDevice(e, id);
    if (!device) {
      await db('android_quarantine').where({ id: quarantineId, state: 'open' }).update({ state: 'resolved', resolved_at: db.fn.now() });
      return 'gone';
    }
    const allowed = rejectAllowed({
      hasRecord: !!record, enrollmentTime: enrollmentTimeOf(device.enrollmentTime) ?? q.enrollment_time, state: device.state,
      ownership: device.ownership, capReached: Number(hour[0]?.n ?? 0) > decisionCap(Number(devices[0]?.n ?? 0)), now: o.now ?? new Date(),
    });
    if (!allowed) {
      await db.transaction(async (trx) => {
        await trx('android_quarantine').where({ id: quarantineId }).update({ decision: 'quarantine' });
        await androidSenders.quarantine(trx, { tenantId, quarantineId });
      });
      return 'quarantined';
    }
    await gw.deleteDevice(e, id, { purpose: 'operator' });
    const ctx = audit.fromJob({ name: 'android.device-reject', requestId: `android-reject-${tenantId}-${quarantineId}` });
    await db.transaction(async (trx) => {
      await trx('android_quarantine').where({ id: quarantineId }).update({ state: 'rejected', resolved_at: trx.fn.now() });
      await audit.appendInTx(trx, {
        tenantId, action: 'android.device_reject_executed', target: { type: 'android_quarantine', id: String(quarantineId) }, details: { quarantineId },
      }, ctx);
    });
    return 'rejected';
  });
}

export async function holdDevice(tenantId: number, deviceId: number, o: { gateway?: AndroidGateway; actor?: DbActor } = {}): Promise<'done' | 'not_pending' | 'gone'> {
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, o.actor ?? DECISIONS_ACTOR, async () => {
    const row = await db('android_devices').where({ device_id: deviceId }).whereNull('released_at').first('amapi_name', 'approval_state') as
      { amapi_name: string; approval_state: string } | undefined;
    if (!row || row.approval_state !== 'pending') return 'not_pending';
    const e = await readEnterprise();
    if (!e) return 'not_pending';
    try {
      const d = await gw.patchDevice(e, deviceIdOf(e, row.amapi_name), { state: 'DISABLED', disabledReason: { ...DISABLED_MESSAGES.approval } });
      await db('android_devices').where({ device_id: deviceId }).update({ state: typeof d?.state === 'string' ? d.state : 'DISABLED', updated_at: db.fn.now() });
    } catch (err) {
      if (err instanceof AndroidError && err.kind === 'not_found') return 'gone';
      throw err;
    }
    return 'done';
  });
}

export async function cleanupSupersededDevice(tenantId: number, deviceId: number, o: { gateway?: AndroidGateway; actor?: DbActor } = {}): Promise<'done' | 'skipped'> {
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, o.actor ?? DECISIONS_ACTOR, async () => {
    const old = await db('android_devices as a').join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .where('a.device_id', deviceId).where('a.release_reason', 'superseded').first('a.amapi_name', 'd.uuid') as { amapi_name: string; uuid: string } | undefined;
    if (!old) return 'skipped';
    const successor = await db('android_devices').whereNull('released_at').whereRaw('? = ANY (previous_device_names)', [old.amapi_name])
      .first('amapi_name') as { amapi_name: string } | undefined;
    const e = await readEnterprise();
    if (!e || !successor) return 'skipped';
    await gw.deleteDevice(e, deviceIdOf(e, old.amapi_name), { purpose: 'cleanup', supersededBy: deviceIdOf(e, successor.amapi_name) });
    try { await gw.deletePolicy(e, `d-${old.uuid}`); } catch (err) { if (!(err instanceof AndroidError && err.kind === 'not_found')) throw err; }
    return 'done';
  });
}

export class ApprovalError extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); this.name = 'ApprovalError'; }
}

/** POST /api/android/devices/:id/approve: approved (audited android.device_approved), then the onboarding. */
export async function approveAndroidDevice(tenantId: number, userId: number, deviceId: number, auditCtx: AuditWriteContext): Promise<'approved'> {
  return asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
    const row = await trx('android_devices').where({ device_id: deviceId }).whereNull('released_at').forUpdate().first('approval_state', 'enrollment_token_id') as
      { approval_state: string; enrollment_token_id: string | null } | undefined;
    if (!row) throw new ApprovalError(404, 'notFound');
    if (row.approval_state !== 'pending') throw new ApprovalError(409, 'androidNotPendingApproval');
    await trx('android_devices').where({ device_id: deviceId }).update({ approval_state: 'approved', approved_at: trx.fn.now(), approved_by: userId, updated_at: trx.fn.now() });
    await audit.appendInTx(trx, {
      tenantId, action: 'android.device_approved', target: { type: 'device', id: String(deviceId), device: deviceId },
      details: { deviceId, tokenId: row.enrollment_token_id },
    }, auditCtx);
    await androidSenders.onboard(trx, { tenantId, deviceId });
    return 'approved' as const;
  }));
}

/** Refuses a pending device (audited android.device_approval_refused); its deletion is android.device_forget (AN-D). */
export async function refuseAndroidDevice(tenantId: number, userId: number, deviceId: number, auditCtx: AuditWriteContext): Promise<'refused'> {
  return asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
    const n = await trx('android_devices').where({ device_id: deviceId, approval_state: 'pending' }).whereNull('released_at')
      .update({ approval_state: 'rejected', updated_at: trx.fn.now() });
    if (!n) throw new ApprovalError(409, 'androidNotPendingApproval');
    await audit.appendInTx(trx, {
      tenantId, action: 'android.device_approval_refused', target: { type: 'device', id: String(deviceId), device: deviceId }, details: { deviceId },
    }, auditCtx);
    return 'refused' as const;
  }));
}

