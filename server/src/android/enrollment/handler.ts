// Handler of the ENROLLMENT notifications (amapi.enrollment, section 10.4 rewritten by the final review: SEC-AN-2,
// AMAPI-R1, SEC-AN-14, COH-14; §22.2; criteria 5 and 18). The order is normative: idempotence first, then checks
// made against the state AT THE TIME OF THE ENROLLMENT (the token's profile_snapshot and the enrollmentTime), never
// against the current profile; no automatic deletion outside the narrow window of step 4.
//   1. a name already seen (a record, released or not, an episode, a quarantine in any state): nothing (a replayed ENROLLMENT, after a seek,
//      from the dead letters, after a profile changed or a token was revoked, never touches a known device: no
//      deleteDevice, no patchDevice);
//   2. enrollmentTokenData obg1:<uuid>, else no record, alert enrollment.unknown_session, quarantine;
//   3. the token of the tenant (RLS) and of the event's enterprise; enrollmentTokenName equal to its name; revoked or
//      expired before enrollmentTime: unknown token;
//   4. ownership, mode and API level against the snapshot; a contradiction: no record, quarantine by default, deletion
//      only if no record, enrollmentTime < 30 min, PROVISIONING, COMPANY_OWNED and the hourly cap of the tenant not
//      reached (5 or 10 %); beyond the cap, quarantine only and automatic freeze A1;
//   5. approval of a token that requires it (long tokens; forced by the hourly cap of the token): pending, DISABLED,
//      no own policy until approved;
//   6. the record: a released record of the same serial (company device, serial unchecked: AN45) is renewed
//      (MDM-B2-R12 option A, by the function of lot C common to the channels); a record still managed with that serial is never taken (new record, alert); a record
//      named in previousDeviceNames is superseded and its old resource deleted at Google by a cleanup job;
//   7. devices, android_devices, the episode, the token's use; 8. android.device-onboard (unless pending); 9. audit.
// No network call here (G-A3): the follow-ups are jobs sent in the event's savepoint.
import type { Knex } from 'knex';
import { autoFreeze } from '../../guard/freeze';
import { markEpisodeEnrolled, openEpisode } from '../../mdm/registry/episodes';
import { renewRecordForNewCycle } from '../../mdm/registry/renewal';
import { raiseAndroidTenantAlert } from '../alerts';
import { MissingPrerequisite, registerAndroidEventHandler, type AndroidEventContext } from '../inbox/handlers';
import { DeviceSchema } from '../inbox/schemas';
import { filterInventory } from '../inventory/privacy';
import {
  checkAgainstSnapshot, decisionCap, enrollmentTimeOf, LONG_TOKEN_HOURLY_CAP, needsApproval, rejectAllowed, SPIKE_PER_HOUR, tokenIdOf,
  tokenValidAt, type ProfileSnapshot, type SnapshotMismatch,
} from './methods';
import { readAndroidProfile, readSnapshot } from './profiles';
import { androidSenders } from './senders';
import { endToken } from './tokens';
import { invitationForEnrollment, markInvitationUsed } from '../byod/enrollmentGuard';
import { markSigninSessionUsed, signinSessionForEnrollment } from '../signin/guard';
import type { z } from 'zod';

type Device = z.infer<typeof DeviceSchema>;
type Ctx = AndroidEventContext<Device>;

interface TokenRow {
  id: string;
  enterprise_id: number;
  profile_id: string;
  profile_snapshot: unknown;
  requires_approval: boolean;
  approval_forced_at: Date | null;
  end_user_id: number | null;
  kind: string;
  token_name: string | null;
  value_ref: string | null;
  one_time: boolean;
  expires_at: Date;
  state: string;
  uses: number;
  max_uses: number | null;
  revoked_at: Date | null;
  created_at: Date;
}

export type EnrollmentOutcome =
  | { result: 'already_known' }
  | { result: 'quarantined' | 'rejected'; reason: string; quarantineId: number }
  | { result: 'enrolled'; deviceId: number; pending: boolean; renewed: boolean; superseded: number | null };

const MISMATCH_ALERT: Record<SnapshotMismatch, string> = {
  ownership_mismatch: 'enrollment.ownership_mismatch',
  mode_mismatch: 'enrollment.ownership_mismatch',
  api_too_low: 'android.device_api_too_low',
};

async function androidDeviceCount(trx: Knex.Transaction, tenantId: number): Promise<number> {
  const r = await trx('android_devices').where({ tenant_id: tenantId }).whereNull('released_at').count<{ n: string }[]>('* as n');
  return Number(r[0]?.n ?? 0);
}

/** Records a device not accepted (step 2, 3 or 4) and sends its follow-up: quarantine, or rejection in the window. */
async function notAccepted(ctx: Ctx, d: Device, reason: 'unknown_token' | SnapshotMismatch, token: TokenRow | null): Promise<EnrollmentOutcome> {
  const { trx, tenantId } = ctx;
  // Serialises the decisions of the tenant (the hourly cap is counted and compared in one place).
  await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`android.decisions:${tenantId}`]);
  const hour = await trx('android_quarantine').where({ tenant_id: tenantId }).where('created_at', '>', trx.raw("now() - interval '1 hour'"))
    .count<{ n: string }[]>('* as n');
  const count = Number(hour[0]?.n ?? 0);
  const cap = decisionCap(await androidDeviceCount(trx, tenantId));
  const capReached = count >= cap;
  const enrollmentTime = enrollmentTimeOf(d.enrollmentTime);
  const reject = reason !== 'unknown_token' && rejectAllowed({
    hasRecord: false, enrollmentTime, state: d.state, ownership: d.ownership, capReached, now: new Date(),
  });
  const [row] = await trx('android_quarantine').insert({
    tenant_id: tenantId, enterprise_id: ctx.enterpriseId, amapi_name: d.name, token_id: token?.id ?? null,
    reason, decision: reject ? 'reject' : 'quarantine', enrollment_time: enrollmentTime,
    amapi_ownership: typeof d.ownership === 'string' ? d.ownership.slice(0, 24) : null,
    api_level: typeof d.apiLevel === 'number' ? d.apiLevel : null,
  }).returning('id');
  const quarantineId = Number((row as { id: number }).id ?? row);
  if (reject) await androidSenders.reject(trx, { tenantId, quarantineId });
  else await androidSenders.quarantine(trx, { tenantId, quarantineId });
  ctx.audit({
    tenantId, action: 'android.device_quarantined', target: { type: 'android_quarantine', id: String(quarantineId) },
    details: { quarantineId, reason, decision: reject ? 'reject' : 'quarantine', tokenId: token?.id ?? null, capReached },
  });
  const alert = reason === 'unknown_token' ? 'enrollment.unknown_session' : MISMATCH_ALERT[reason];
  ctx.afterCommit(() => raiseAndroidTenantAlert(tenantId, alert, { quarantineId }));
  if (capReached) {
    // Beyond the cap: quarantine only, and the automatic freeze of the anomaly rule A1 (extended, §22.2).
    ctx.afterCommit(() => autoFreeze(tenantId, 'A1'));
  }
  return { result: reject ? 'rejected' : 'quarantined', reason, quarantineId };
}

/** Step 3: the token of the enrollment, or null when unknown. */
async function findToken(ctx: Ctx, d: Device, at: Date): Promise<TokenRow | null> {
  const id = tokenIdOf(d.enrollmentTokenData);
  if (!id) return null;
  const t = await ctx.trx('android_enrollment_tokens').where({ id, enterprise_id: ctx.enterpriseId }).first(
    'id', 'enterprise_id', 'profile_id', 'profile_snapshot', 'requires_approval', 'approval_forced_at', 'end_user_id', 'kind', 'token_name',
    'value_ref', 'one_time', 'expires_at', 'state', 'uses', 'max_uses', 'revoked_at', 'created_at') as TokenRow | undefined;
  if (!t) return null;
  // SEC-AN-14: the token Google names must be the row's (a forged additionalData on another token is unknown).
  if (d.enrollmentTokenName !== undefined && (t.token_name === null || d.enrollmentTokenName !== t.token_name)) return null;
  if (!tokenValidAt(t, at)) return null;
  // §10.3: no use beyond max_uses (review AN-C1b: a single-use token already used never enrolls a second device,
  // whatever Google does; the device of its first use is caught by the idempotence of step 1).
  if (t.max_uses !== null && Number(t.uses) >= Number(t.max_uses)) return null;
  return t;
}

export async function onEnrollment(ctx: Ctx): Promise<EnrollmentOutcome> {
  const { trx, tenantId } = ctx;
  const d = ctx.event.payload;
  // 1. Idempotence. Google never gives an AMAPI device name twice: a name the instance has already seen (a record,
  // released or not, an episode of a renewed record, a quarantine in any state) is a replay (seek, dead letter
  // redriven), never a new enrollment: no ghost record for a superseded or released resource, no new quarantine
  // feeding the hourly cap and the freeze A1 (revue AN-C1b, R2).
  const known = await trx('android_devices').where({ amapi_name: d.name }).first('device_id');
  if (known) return { result: 'already_known' };
  const episode = await trx('device_enrollments').where({ tenant_id: tenantId, channel_enrollment_id: d.name }).first('id');
  if (episode) return { result: 'already_known' };
  const quarantined = await trx('android_quarantine').where({ amapi_name: d.name }).first('id');
  if (quarantined) return { result: 'already_known' };

  const at = enrollmentTimeOf(d.enrollmentTime) ?? ctx.event.occurredAt;
  // 2 and 3. The token.
  const token = await findToken(ctx, d, at);
  if (!token) return notAccepted(ctx, d, 'unknown_token', null);
  const snapshot = readSnapshot(token.profile_snapshot);
  if (!snapshot) return notAccepted(ctx, d, 'unknown_token', token);
  // 4. The device against the snapshot.
  const mismatch = checkAgainstSnapshot(d, snapshot);
  if (mismatch) return notAccepted(ctx, d, mismatch, token);
  // Lot AN-F1: a BYOD link token enrolls a device only through an invitation issued after its notice was acknowledged
  // (not revoked, not used): otherwise an unknown enrollment, quarantined (a personal device is never deleted).
  let invitation: { id: string; noticeVersionId: string } | null = null;
  if (token.kind === 'byod_link') {
    invitation = await invitationForEnrollment(trx, tenantId, token.id);
    if (!invitation) return notAccepted(ctx, d, 'unknown_token', token);
  }
  // Lot AN-F2: a sign-in token enrolls a device only through its session of the device surface, issued after Obligate
  // authenticated an end user of the tenant (not used): otherwise an unknown enrollment, quarantined.
  let signinSession: { id: string } | null = null;
  if (token.kind === 'signin') {
    signinSession = await signinSessionForEnrollment(trx, tenantId, token.id);
    if (!signinSession) return notAccepted(ctx, d, 'unknown_token', token);
  }

  // 5. Approval (AN17), and the hourly cap of a long token that forces it.
  // A kiosk token always requires it (lot AN-G1, AN17), whatever its row says (a token written before the rule, or by
  // a path that skipped requiresApproval).
  let requires = token.requires_approval || snapshot.usage === 'kiosk';
  // Forced by the hourly cap: the list of approved serials does not apply (the serial is reported by the device,
  // unchecked: AN45; a copied long token would announce an approved one).
  let forced = token.approval_forced_at !== null;
  if (token.max_uses === null) {
    // Enrolled in the hour, or processed in the hour: a backlog applied late (instance stopped) counts too
    // (revue AN-C1b, R1).
    const hour = await trx('android_devices').where({ enrollment_token_id: token.id })
      .where((q) => q.where('enrolled_at', '>', trx.raw("now() - interval '1 hour'")).orWhere('created_at', '>', trx.raw("now() - interval '1 hour'")))
      .count<{ n: string }[]>('* as n');
    const n = Number(hour[0]?.n ?? 0) + 1;
    if (n > LONG_TOKEN_HOURLY_CAP && !token.approval_forced_at) {
      await trx('android_enrollment_tokens').where({ id: token.id }).update({ requires_approval: true, approval_forced_at: trx.fn.now() });
      requires = true;
      forced = true;
      ctx.afterCommit(() => raiseAndroidTenantAlert(tenantId, 'android.enrollment_spike', { tokenId: token.id, perHour: n }));
    } else if (n > LONG_TOKEN_HOURLY_CAP) {
      requires = true;
      forced = true;
    } else if (n === SPIKE_PER_HOUR + 1) {
      ctx.afterCommit(() => raiseAndroidTenantAlert(tenantId, 'android.enrollment_spike', { tokenId: token.id, perHour: n }));
    }
  }
  const ownership = snapshot.ownership;
  const inv = filterInventory(d as Record<string, unknown>, ownership);
  const profile = await readAndroidProfile(trx, snapshot.profileId, tenantId);
  const pending = forced || needsApproval(requires, inv.serialNumber, profile?.settings.approvedSerials ?? []);

  // 6. The record.
  const now = new Date();
  let superseded: number | null = null;
  const previous = (d.previousDeviceNames ?? []).filter((n) => typeof n === 'string' && n.startsWith(`${ctx.event.enterpriseName}/devices/`));
  if (previous.length && ownership !== 'personal') {
    const old = await trx('android_devices').whereIn('amapi_name', previous).whereNull('released_at')
      .where({ enterprise_id: ctx.enterpriseId }).first('device_id', 'amapi_name') as { device_id: number; amapi_name: string } | undefined;
    if (old) {
      superseded = Number(old.device_id);
      await trx('android_devices').where({ device_id: superseded }).update({ released_at: now, release_reason: 'superseded', updated_at: now });
      await trx('devices').where({ tenant_id: tenantId, id: superseded }).update({
        enrollment_state: 'unenrolled', enrollment_state_at: now, unenrolled_at: now, unenroll_reason: 'superseded', updated_at: now,
        // The serial follows the live device (the new record of 6b): the replaced record is out of management.
        serial_number: null,
      });
      await trx('device_enrollments').where({ tenant_id: tenantId, device_id: superseded }).whereNull('ended_at')
        .update({ ended_at: now, end_reason: 'superseded' });
      await androidSenders.cleanup(trx, { tenantId, deviceId: superseded });
    }
  }
  let deviceId: number | null = null;
  let renewed = false;
  let serial = inv.serialNumber ? inv.serialNumber.toUpperCase() : null;
  if (serial && ownership !== 'personal') {
    const holder = await trx('devices as d').leftJoin('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
      .where({ 'd.tenant_id': tenantId, 'd.management_channel': 'amapi', 'd.serial_number': serial })
      .first('d.id', 'd.enrollment_state', 'a.released_at') as { id: number; enrollment_state: string; released_at: Date | null } | undefined;
    if (holder && holder.enrollment_state === 'unenrolled' && holder.released_at !== null) {
      deviceId = Number(holder.id);
      renewed = true;
    } else if (holder) {
      // A record still under management holds this serial: never taken; a record of its own, without the serial.
      ctx.afterCommit(() => raiseAndroidTenantAlert(tenantId, 'enrollment.duplicate_serial', { deviceId: Number(holder.id) }));
      serial = null;
    }
  }

  // 7. Writes.
  const cols: Record<string, unknown> = {
    platform: 'android', management_channel: 'amapi', ownership, enrollment_type: snapshot.method, management_mode: snapshot.mode,
    supervised: false, usage: snapshot.usage, enrollment_state: 'enrolled', enrollment_state_at: at, enrolled_at: at, unenrolled_at: null,
    unenroll_reason: null, retention_until: null, enrollment_profile_id: snapshot.profileId, end_user_id: token.end_user_id,
    end_user_assigned_at: token.end_user_id ? at : null, serial_number: ownership === 'personal' ? null : serial,
    model: inv.model, model_name: inv.brand && inv.model ? `${inv.brand} ${inv.model}`.slice(0, 128) : inv.model,
    os_version: inv.osVersion, os_build: inv.osBuild,
    storage_capacity_bytes: inv.storageTotal, storage_available_bytes: inv.storageAvailable,
    compliance_state: 'unknown', compliance_reasons: '[]', config_state: 'pending', updated_at: now,
  };
  const sat: Record<string, unknown> = {
    enterprise_id: ctx.enterpriseId, amapi_name: d.name, amapi_management_mode: d.managementMode, amapi_ownership: d.ownership,
    enrollment_token_id: token.id, approval_state: pending ? 'pending' : 'none', approved_at: null, approved_by: null,
    policy_name: null, pushed_policy_version: null, pushed_rendered_hash: null, pushed_at: null, policy_state: 'pending',
    policy_state_reasons: '[]', policy_push_failures: 0, applied_policy_version: null, state: d.state ?? null, applied_state: d.appliedState ?? null,
    security_posture: null, non_compliance: '[]', policy_compliant: null, api_level: inv.apiLevel, security_patch_level: inv.securityPatchLevel,
    last_status_report_at: null, last_policy_sync_at: null, previous_device_names: (d.previousDeviceNames ?? []).slice(0, 100),
    hardware_info: inv.hardwareInfo ? JSON.stringify(inv.hardwareInfo) : null, software_info: JSON.stringify(inv.softwareInfo),
    network_info: inv.networkInfo ? JSON.stringify(inv.networkInfo) : null, enrolled_at: at, released_at: null, release_reason: null, updated_at: now,
  };
  if (deviceId !== null) {
    // Renewal (MDM-B2-R12 option A) by the function of lot C common to the channels (mdm/registry/renewal.ts): the
    // group of the profile, no direct assignment, lost mode off, no position of the previous cycle; the inventory of
    // the previous cycle goes too.
    const r = await renewRecordForNewCycle(trx, tenantId, deviceId, snapshot.defaultGroupId);
    await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update({ ...cols, ...r.columns });
    await trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId }).del();
    await trx('android_devices').where({ tenant_id: tenantId, device_id: deviceId }).update(sat);
  } else {
    const [row] = await trx('devices').insert({ tenant_id: tenantId, group_id: snapshot.defaultGroupId, ...cols }).returning('id');
    deviceId = Number((row as { id: number }).id ?? row);
    await trx('android_devices').insert({ device_id: deviceId, tenant_id: tenantId, ...sat });
  }
  await openEpisode(trx, tenantId, deviceId, {
    channelEnrollmentId: d.name, method: snapshot.method as never, mode: snapshot.mode, ownership,
    enrollmentProfileId: snapshot.profileId, enrollmentSessionId: null, endUserId: token.end_user_id, certSha256: null, startedAt: at,
  });
  await markEpisodeEnrolled(trx, tenantId, deviceId, at);
  // The token's use: a single-use token is used (its value destroyed).
  await trx('android_enrollment_tokens').where({ id: token.id }).update({ uses: trx.raw('uses + 1'), last_used_at: now });
  if (token.one_time && token.state === 'active') await endToken(trx, token, 'used');
  if (invitation) {
    await markInvitationUsed(trx, tenantId, invitation.id, deviceId);
    ctx.audit({
      tenantId, action: 'android.byod_invitation_used', target: { type: 'android_byod_invitation', id: invitation.id },
      details: { invitationId: invitation.id, deviceId, noticeVersionId: invitation.noticeVersionId },
    });
  }

  if (signinSession) {
    await markSigninSessionUsed(trx, tenantId, signinSession.id, deviceId);
    ctx.audit({
      tenantId, action: 'android.signin_session_used', target: { type: 'android_signin_session', id: signinSession.id },
      details: { sessionId: signinSession.id, deviceId },
    });
  }

  // 8. Follow-up.
  if (pending) await androidSenders.hold(trx, { tenantId, deviceId });
  else await androidSenders.onboard(trx, { tenantId, deviceId });
  // 9. Audit.
  ctx.audit({
    tenantId, action: 'device.enrolled', target: { type: 'device', id: String(deviceId), device: deviceId },
    details: { channel: 'amapi', method: snapshot.method, ownership, mode: snapshot.mode, tokenId: token.id, pending, renewed, superseded },
  });
  return { result: 'enrolled', deviceId, pending, renewed, superseded };
}

let registered = false;

export function registerEnrollmentHandler(): void {
  if (registered) return;
  registered = true;
  registerAndroidEventHandler({
    type: 'amapi.enrollment',
    payload: DeviceSchema,
    async handle(ctx) {
      if (typeof ctx.event.payload.name !== 'string') throw new MissingPrerequisite('device name');
      await onEnrollment(ctx);
    },
  });
}

export type { ProfileSnapshot };
