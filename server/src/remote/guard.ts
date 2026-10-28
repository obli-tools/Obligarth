import type { Knex } from 'knex';
import {
  REMOTE_LIMITS, type DeviceCapability, type RemoteChannel, type RemoteMode, type RemoteUnavailableReason,
} from '@obligarth/shared';
import { db } from '../db';
import { tenantFrozen } from '../guard/frozen';
import { personFacts } from '../guard/people';
import type { ManagementChannel } from '../guard/types';
import { remoteAssistanceAllowed } from '../privacy/profiles';
import { permissionService } from '../services/permission.service';
import { remoteChannel, remoteChannelOfManagement, type RemoteDeviceFacts } from './channels';

// =============================================================================
// Who may open a session on which device (P0-15 §2 « revalidation complète », §4.1, §4.5, §4.6; §0.1 of the spec, the
// MSP model of the owners' decision of 27/10): one check, checkOpenable, at the request, at the approval, at /accept,
// at each attachment of the stream and every 60 s of a live session (the relay, T5). The first condition that fails is
// the answer (its code is the console's reason of unavailability):
//   capabilityMissing   mdm:remote_view (view) or mdm:remote_control (control, which includes the view) on the device,
//                       as Obliance grants a device capability: by a team (on the device or its group), and held by the
//                       administrators of the tenant and of the platform (canUseCapability and its isAdmin shortcut,
//                       §0.1 rule 4); the write scope of the device, as every command; an active account. No cooldown,
//                       no link with mdm:wipe;
//   personalDevice      not a corporate device (personal, COPE: D3), whatever the profile says;
//   notEnrolled         the device out of management;
//   privacyDisabled     the rule remoteAssistance of the corporate profile of the tenant is not true (true by default);
//   frozen              the tenant is frozen for the channel's commands (guard/frozen.ts);
//   platformUnsupported no channel for this device (android: T10, apple: T11), iOS in control;
//   the channel's own   agentTooOld, revoked, knoxRequired, injectUnavailable, platformUnsupported (channels/*);
//   sessionOpen         another open session on the device (one per device);
//   quota               at the request only: 5 open sessions per tenant, 2 per operator, 40 on the instance.
// The strong authentication of the technician (strict step-up at each opening and each move to the control) is the
// routes' (remote/routes.ts), the revalidation of the console session the relay's (T5).
// In the caller's transaction (the tenant's context); reads only.
// =============================================================================

export type OpenablePhase = 'request' | 'approval' | 'accept' | 'attach' | 'revalidate';

export interface OpenableInput {
  tenantId: number;
  /** The requester of the session (the launcher), whose rights are read. */
  userId: number;
  deviceId: number;
  mode: RemoteMode;
  phase: OpenablePhase;
  /** The session revalidated: its own open row is not « another session ». */
  sessionId?: string;
}

export type Openable =
  | { ok: true; channel: RemoteChannel; device: RemoteDeviceFacts }
  | { ok: false; reason: RemoteUnavailableReason; details?: Record<string, unknown> };

/**
 * Does `userId` hold the remote capability of `mode` on the device of `tenantId` (§0.1 rule 4, the rights of
 * Obliance): an active account; an administrator of the tenant or of the platform holds it (canUseCapability's
 * isAdmin); otherwise a grant of a team: view by mdm:remote_view or mdm:remote_control, control by mdm:remote_control,
 * with the write scope of the device.
 */
export async function holdsRemoteCapability(userId: number, tenantId: number, deviceId: number, mode: RemoteMode): Promise<boolean> {
  if (!Number.isSafeInteger(userId) || userId <= 0) return false;
  const f = await personFacts(userId, tenantId);
  if (!f.exists || !f.active) return false;
  const isAdmin = f.platformAdmin || f.tenantRole === 'admin';
  const can = (c: DeviceCapability): Promise<boolean> => permissionService.canUseCapability(userId, deviceId, isAdmin, c);
  const held = mode === 'control' ? await can('mdm:remote_control') : (await can('mdm:remote_view')) || (await can('mdm:remote_control'));
  return held && permissionService.canWriteDevice(userId, deviceId, isAdmin);
}

/** The open sessions of the instance, all tenants (counts only: obligarth.remote_sessions_open_summary). */
export async function instanceOpenSessions(q: Knex | Knex.Transaction): Promise<number> {
  const r = await q.raw('SELECT state, sessions FROM obligarth.remote_sessions_open_summary()') as { rows: Array<{ sessions: string | number }> };
  return r.rows.reduce((n, x) => n + Number(x.sessions), 0);
}

/** The facts of the device a session needs (null: not a device of the tenant). */
async function deviceFacts(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<RemoteDeviceFacts | null> {
  const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId })
    .first('id', 'management_channel', 'ownership', 'enrollment_state', 'platform') as
    { id: number; management_channel: string; ownership: string | null; enrollment_state: string; platform: string | null } | undefined;
  if (!d) return null;
  return { deviceId: Number(d.id), managementChannel: d.management_channel, ownership: d.ownership, enrollmentState: d.enrollment_state, platform: d.platform };
}

/** May this session be opened (or go on) now? The first failing condition, in the order of the header. */
export async function checkOpenable(trx: Knex.Transaction, x: OpenableInput): Promise<Openable> {
  const device = await deviceFacts(trx, x.tenantId, x.deviceId);
  if (!device) return { ok: false, reason: 'notEnrolled' };
  const channel = remoteChannelOfManagement(device.managementChannel);
  const impl = channel ? remoteChannel(channel) : undefined;
  if (!(await holdsRemoteCapability(x.userId, x.tenantId, x.deviceId, x.mode))) return { ok: false, reason: 'capabilityMissing' };
  if (device.ownership !== 'corporate') return { ok: false, reason: 'personalDevice' };
  if (device.enrollmentState !== 'enrolled') return { ok: false, reason: 'notEnrolled' };
  if (!(await remoteAssistanceAllowed(trx, x.tenantId, device.ownership))) return { ok: false, reason: 'privacyDisabled' };
  if (await tenantFrozen(trx, x.tenantId, device.managementChannel as ManagementChannel)) return { ok: false, reason: 'frozen' };
  if (!channel || !impl || (channel === 'apple' && x.mode === 'control')) return { ok: false, reason: 'platformUnsupported' };
  const own = await impl.eligible(trx, x.tenantId, device, x.mode);
  if (!own.ok) return own;
  const other = await trx('remote_sessions').where({ tenant_id: x.tenantId, device_id: x.deviceId }).whereNull('ended_at')
    .modify((q) => { if (x.sessionId) q.whereNot('id', x.sessionId); }).first('id');
  if (other) return { ok: false, reason: 'sessionOpen' };
  if (x.phase === 'request') {
    const [{ n: tenantOpen }] = await trx('remote_sessions').where({ tenant_id: x.tenantId }).whereNull('ended_at').count<{ n: string }[]>('id as n');
    if (Number(tenantOpen) >= REMOTE_LIMITS.openPerTenant) return { ok: false, reason: 'quota', details: { scope: 'tenant', limit: REMOTE_LIMITS.openPerTenant } };
    const [{ n: mine }] = await trx('remote_sessions').where({ tenant_id: x.tenantId, requested_by: x.userId }).whereNull('ended_at')
      .count<{ n: string }[]>('id as n');
    if (Number(mine) >= REMOTE_LIMITS.openPerOperator) return { ok: false, reason: 'quota', details: { scope: 'operator', limit: REMOTE_LIMITS.openPerOperator } };
    if ((await instanceOpenSessions(trx)) >= REMOTE_LIMITS.openPerInstance) {
      return { ok: false, reason: 'quota', details: { scope: 'instance', limit: REMOTE_LIMITS.openPerInstance } };
    }
  }
  return { ok: true, channel, device };
}

/** The console's reason of unavailability of a remote action of a device for the caller (no quota: an action of the
 *  menu, not a request). */
export async function remoteAvailability(tenantId: number, userId: number, deviceId: number, mode: RemoteMode): Promise<RemoteUnavailableReason | null> {
  const r = await db.transaction((trx) => checkOpenable(trx, { tenantId, userId, deviceId, mode, phase: 'revalidate' }));
  return r.ok ? null : r.reason;
}
