import type { Knex } from 'knex';
import {
  ID_RELEASE_REASONS, methodSupervises,
  type IdReleaseReason, type ManagementMode, type NanoEnrollType, type UnenrollReason,
} from '@obligarth/shared';
import { JobError } from '../../jobs/errors';
import { jobIdFor } from '../../jobs/ids';
import { raiseInTx } from '../alerts/service';
import {
  findDeviceForAuthenticate, findSessionForAuthenticate, managementModeFor, platformFromProductName, serialOf,
  type SessionFacts,
} from '../../mdm/registry/authenticateRules';
import { closeEpisode, markEpisodeEnrolled, openEpisode } from '../../mdm/registry/episodes';
import { enrollmentReleaseJob } from '../../mdm/jobs';
import { privacyRulesFor, type PrivacyRules } from './privacy';

// =============================================================================
// Enrollment cycles of the Apple devices (docs: integration-apple-edge §7.3;
// modele-donnees-mdm §4.4, §4.5, §10.4, §13.5; DM25, DM26): the writes of an
// Authenticate, a TokenUpdate and a departure from management into the device
// registry (devices, apple_devices, device_enrollments, enrollment_sessions),
// with the rules of the data model. Called by the outbox handlers of the
// integration in the event's savepoint (ctx.trx: the tenant's context, no
// network, G-2); the handlers add the timeline, the audit (ctx.audit), the
// follow-up jobs and the realtime events (lot B3).
//   - A cycle starts with an accepted Authenticate (a new identity
//     certificate) and ends with a departure; a state never goes back, but
//     for a newer cycle (monotony by occurred_at: events arrive out of order).
//   - No record without an enrollment session (DM25): the ownership is never
//     guessed; an Authenticate whose mode the session's ownership forbids
//     (barrier 2) creates no record and asks apple-edge to release it.
//   - The identifier of the device becomes active at the first TokenUpdate
//     of the cycle (DM26), like apple_edge.device_ids: the loser of an
//     Authenticate race never holds it; a violation of the unique index there
//     is retried (missing_prerequisite) until the other tenant's release is
//     consumed.
// No column of the removed agent is read or written (hostname, status,
// approval_status, os_type: modele §13.5).
// =============================================================================

export interface AuthenticateFacts {
  enrollmentId: string;                    // '<key>_<raw id>'
  kind: 'udid' | 'enrollment_id';          // 'Device' → udid; 'User Enrollment (Device)' → enrollment_id
  rawId: string;                           // payload.device_id
  enrollmentType: NanoEnrollType;
  topic: string;
  proof: 'none' | 'ade';
  certSha256: string | null;
  certNotAfter: Date | null;
  challengeId: string | null;
  sessionRef: string | null;               // enrollment_sessions.id
  message: Record<string, unknown>;        // converted Authenticate (ProductName, Model, ModelName, OSVersion, BuildVersion, SerialNumber…)
  occurredAt: Date;
  eventId: string;
}

export type AuthenticateOutcome = 'created' | 'new_cycle' | 'duplicate' | 'stale' | 'no_session' | 'ownership_mismatch';
export type TokenUpdateOutcome = 'completed' | 'awaiting' | 'configured' | 'refreshed' | 'stale';
export type UnenrolledOutcome = 'unenrolled' | 'already' | 'stale' | 'unknown';

export interface TokenUpdateFacts {
  enrollmentId: string;
  awaitingConfiguration: boolean;
  hasUnlockToken: boolean;
  topic: string;
  tokenUpdateTally?: number;
  occurredAt: Date;
  eventId: string;
}

interface SatelliteRow {
  device_id: number;
  enrollment_session_id: string | null;
  authenticated_at: Date;
  cert_sha256: string | null;
  cert_not_after: Date | null;
  id_activated_at: Date | null;
  enrollment_state: string;
  enrollment_state_at: Date | null;
  ownership: string;
}

const str = (v: unknown, max: number): string | null => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);
const time = (v: Date | string | null | undefined): number => (v ? new Date(v).getTime() : Number.NEGATIVE_INFINITY);
const sha = (v: string | null | undefined): string | null => (v ? String(v).trim() : null);

/** The satellite of an enrollment id and its record, locked for the event (two consumers, one cycle). */
async function satelliteOf(trx: Knex.Transaction, tenantId: number, enrollmentId: string): Promise<SatelliteRow | undefined> {
  return trx('apple_devices as a')
    .join('devices as d', function joinDevice() {
      this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id');
    })
    .where({ 'a.tenant_id': tenantId, 'a.enrollment_id': enrollmentId })
    .forUpdate()
    .first('a.device_id', 'a.enrollment_session_id', 'a.authenticated_at', 'a.cert_sha256', 'a.cert_not_after',
      'a.id_activated_at', 'd.enrollment_state', 'd.enrollment_state_at', 'd.ownership') as Promise<SatelliteRow | undefined>;
}

/** Number of enrollments without a session waiting for an operator (the count of the aggregated alert). */
async function raiseUnknownSession(trx: Knex.Transaction, tenantId: number): Promise<void> {
  const open = await trx('live_alerts')
    .where({ tenant_id: tenantId, stable_key: 'apple:enrollment.unknown_session' })
    .whereNull('resolved_at')
    .orderBy('id', 'desc')
    .first('i18n_params') as { i18n_params: Record<string, unknown> | null } | undefined;
  const count = Number(open?.i18n_params?.count ?? 0);
  await raiseInTx(trx, tenantId, 'enrollment.unknown_session', { params: { count: (Number.isFinite(count) ? count : 0) + 1 } });
}

/** The columns of the record a new cycle writes (§4.5 rule 3, §10.4): from the session and the message. */
function cycleColumns(f: AuthenticateFacts, s: SessionFacts, mode: ManagementMode, rules: PrivacyRules,
  current: { platform: string | null; isNew: boolean }) {
  const msg = f.message ?? {};
  const productName = str(msg.ProductName, 64);
  const personal = s.ownership === 'personal';
  const serial = !personal && rules.storeSerialNumber ? (serialOf(f) ?? (s.serialNumber && /^[A-Za-z0-9]{4,64}$/.test(s.serialNumber) ? s.serialNumber.toUpperCase() : null)) : null;
  const cols: Record<string, unknown> = {
    management_channel: 'apple_mdm',
    ownership: s.ownership,
    enrollment_type: s.method,
    management_mode: mode,
    supervised: methodSupervises(s.method),
    usage: s.usage,
    enrollment_state: 'enrolling',
    enrollment_state_at: f.occurredAt,
    enrolled_at: null,
    unenrolled_at: null,
    unenroll_reason: null,
    retention_until: null,
    enrollment_profile_id: s.profileId,
    end_user_id: s.endUserId,
    end_user_assigned_at: s.endUserId ? f.occurredAt : null,
    updated_at: new Date(),
  };
  const platform = platformFromProductName(productName);
  if (platform || current.isNew) cols.platform = platform ?? current.platform ?? 'ios';
  if (productName) cols.model = productName;
  const modelName = str(msg.ModelName, 128);
  if (modelName) cols.model_name = modelName;
  const osVersion = str(msg.OSVersion, 200);
  if (osVersion) cols.os_version = osVersion;
  const osBuild = str(msg.BuildVersion, 32);
  if (osBuild) cols.os_build = osBuild;
  // What the privacy rules of the new ownership do not keep is cleared, never carried over (§5.2).
  if (personal || !rules.storeSerialNumber) cols.serial_number = null;
  else if (serial) cols.serial_number = serial;
  if (!rules.storeDeviceName) cols.device_name = null;
  else if (str(msg.DeviceName, 255)) cols.device_name = str(msg.DeviceName, 255);
  if (personal) cols.lost_mode_state = 'off';
  return cols;
}

/** The satellite's columns of a new cycle: the identity, a fresh activation, push and DDM state. */
function satelliteColumns(f: AuthenticateFacts, s: SessionFacts) {
  const msg = f.message ?? {};
  return {
    enrollment_id: f.enrollmentId,
    udid: f.kind === 'udid' ? f.rawId : null,
    byod_enrollment_id: f.kind === 'enrollment_id' ? f.rawId : null,
    nano_enroll_type: f.enrollmentType,
    topic: f.topic,
    proof: f.proof,
    enrollment_session_id: s.sessionId,
    authenticated_at: f.occurredAt,
    cert_sha256: f.certSha256,
    cert_not_after: f.certNotAfter,
    identity_cert_pem: null,
    identity_state: 'valid',
    token_update_tally: 0,
    token_update_at: null,
    push_state: 'unknown',
    push_state_at: null,
    id_activated_at: null,
    id_released_at: null,
    id_release_reason: null,
    device_configured_at: null,
    has_unlock_token: false,
    ddm_enabled: false,
    ddm_enabled_at: null,
    ddm_client_capabilities: null,
    product_name: str(msg.ProductName, 64),
    model_number: str(msg.Model, 64) ?? str(msg.ModelNumber, 64),
    updated_at: new Date(),
  };
}

/**
 * mdm.authenticate (§7.3, modele §4.5): the record created or found, a new cycle opened. 'duplicate': the
 * same certificate again; 'stale': older than the current cycle or than the record's last state; no write
 * for 'no_session' (alert enrollment.unknown_session) nor 'ownership_mismatch' (alert
 * enrollment.ownership_mismatch, job mdm.enrollment-release; the handler writes the audit entry).
 */
export async function onAuthenticate(trx: Knex.Transaction, tenantId: number, f: AuthenticateFacts):
  Promise<{ deviceId: number | null; outcome: AuthenticateOutcome }> {
  const sat = await satelliteOf(trx, tenantId, f.enrollmentId);
  if (sat) {
    if (f.certSha256 && sha(sat.cert_sha256) === f.certSha256) {
      if (!sat.cert_not_after && f.certNotAfter) {
        await trx('apple_devices').where({ tenant_id: tenantId, device_id: sat.device_id }).update({ cert_not_after: f.certNotAfter });
      }
      return { deviceId: Number(sat.device_id), outcome: 'duplicate' };
    }
    if (f.occurredAt.getTime() <= time(sat.authenticated_at) || f.occurredAt.getTime() < time(sat.enrollment_state_at)) {
      return { deviceId: Number(sat.device_id), outcome: 'stale' };
    }
  }

  // Rule 1: the session (DM25). Rule 2: barrier 2.
  const session = await findSessionForAuthenticate(trx, tenantId, f);
  if (!session) {
    await raiseUnknownSession(trx, tenantId);
    return { deviceId: null, outcome: 'no_session' };
  }
  const mode = managementModeFor(f, session);
  if (!mode) {
    await raiseInTx(trx, tenantId, 'enrollment.ownership_mismatch', {});
    await enrollmentReleaseJob().sendInTx(trx, { tenantId, eventId: f.eventId },
      { id: jobIdFor('mdm.enrollment-release', f.eventId), tenantId });
    return { deviceId: null, outcome: 'ownership_mismatch' };
  }
  const rules = await privacyRulesFor(trx, tenantId, session.ownership, f.enrollmentType);

  // Rule 3: the existing record (the satellite of the enrollment id, else the serial number).
  let deviceId: number;
  let created = false;
  const found = sat ? { deviceId: Number(sat.device_id), enrollmentId: f.enrollmentId } : await findDeviceForAuthenticate(trx, tenantId, f, rules);
  if (found) {
    deviceId = found.deviceId;
    const current = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).forUpdate()
      .first('group_id', 'platform', 'enrollment_state_at') as { group_id: number | null; platform: string; enrollment_state_at: Date | null } | undefined;
    if (!current) throw new JobError('missing_prerequisite', 'record of the device not found');
    if (!sat && f.occurredAt.getTime() < time(current.enrollment_state_at)) return { deviceId, outcome: 'stale' };
    const cols = cycleColumns(f, session, mode, rules, { platform: current.platform, isNew: false });
    // The group changes only when the profile asks for it (§4.5 rule 3).
    if (session.resetGroupOnReenroll) cols.group_id = session.groupId;
    await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update(cols);
    const satCols = satelliteColumns(f, session);
    const updated = await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update(satCols);
    if (!updated) await trx('apple_devices').insert({ device_id: deviceId, tenant_id: tenantId, ...satCols });
    // The erased device lost its declarations: the set is to be synchronised again (§7.3, step 4).
    await trx('apple_declaration_sets').where({ tenant_id: tenantId, device_id: deviceId })
      .update({ sent_token: null, fetched_token: null, sync_command_id: null });
  } else {
    const cols = cycleColumns(f, session, mode, rules, { platform: null, isNew: true });
    const [row] = await trx('devices').insert({ tenant_id: tenantId, group_id: session.groupId, ...cols }).returning('id');
    deviceId = Number((row as { id: number }).id ?? row);
    created = true;
    await trx('apple_devices').insert({ device_id: deviceId, tenant_id: tenantId, ...satelliteColumns(f, session) });
  }

  // Rule 4: the episode of the cycle (the open one, if any, is replaced).
  await openEpisode(trx, tenantId, deviceId, {
    channelEnrollmentId: f.enrollmentId, method: session.method, mode, ownership: session.ownership,
    enrollmentProfileId: session.profileId, enrollmentSessionId: session.sessionId, endUserId: session.endUserId,
    certSha256: f.certSha256, startedAt: f.occurredAt,
  });
  // The session: authenticated (unless further), its device and certificate; the ADE device of the serial.
  await trx('enrollment_sessions').where({ tenant_id: tenantId, id: session.sessionId })
    .whereNotIn('state', ['authenticated', 'enrolled'])
    .update({ state: 'authenticated', state_at: f.occurredAt, updated_at: new Date() });
  await trx('enrollment_sessions').where({ tenant_id: tenantId, id: session.sessionId })
    .update({ device_id: deviceId, cert_sha256: trx.raw('COALESCE(cert_sha256, ?)', [f.certSha256]), updated_at: new Date() });
  const adeSerial = session.serialNumber ?? serialOf(f);
  if (adeSerial) {
    await trx('apple_ade_devices').where({ tenant_id: tenantId, serial_number: adeSerial }).update({ device_id: deviceId, updated_at: new Date() });
  }
  return { deviceId, outcome: created ? 'created' : 'new_cycle' };
}

/**
 * mdm.token_update of the device channel (§7.3, modele §4.4, DM26): null without a record (the handler
 * raises missing_prerequisite). The first token of the cycle activates the identifier and ends the
 * enrollment ('completed', or 'awaiting' the configuration of an ADE device); a token after DeviceConfigured
 * completes it ('configured'); any other is a refresh. A violation of the unique index of the active
 * identifiers (still active in another tenant's record) is retried: JobError('missing_prerequisite').
 */
export async function onTokenUpdate(trx: Knex.Transaction, tenantId: number, f: TokenUpdateFacts):
  Promise<{ deviceId: number; outcome: TokenUpdateOutcome } | null> {
  const sat = await satelliteOf(trx, tenantId, f.enrollmentId);
  if (!sat) return null;
  const deviceId = Number(sat.device_id);
  if (f.occurredAt.getTime() < time(sat.authenticated_at) || sat.enrollment_state === 'unenrolled') {
    return { deviceId, outcome: 'stale' };
  }
  const satUpdate: Record<string, unknown> = {
    token_update_at: trx.raw('GREATEST(token_update_at, ?::timestamptz)', [f.occurredAt]),
    has_unlock_token: trx.raw('has_unlock_token OR ?::boolean', [f.hasUnlockToken]),
    push_state: trx.raw("CASE WHEN push_state_at IS NULL OR push_state_at < ?::timestamptz THEN 'ready' ELSE push_state END", [f.occurredAt]),
    push_state_at: trx.raw('GREATEST(push_state_at, ?::timestamptz)', [f.occurredAt]),
    updated_at: new Date(),
  };
  if (Number.isInteger(f.tokenUpdateTally)) satUpdate.token_update_tally = trx.raw('GREATEST(token_update_tally, ?::int)', [f.tokenUpdateTally as number]);
  if (f.topic && /^com\.apple\.mgmt\./.test(f.topic)) satUpdate.topic = f.topic.slice(0, 255);

  let outcome: TokenUpdateOutcome = 'refreshed';
  let newState: string | null = null;
  if (sat.enrollment_state === 'enrolling') {
    outcome = f.awaitingConfiguration ? 'awaiting' : 'completed';
    newState = f.awaitingConfiguration ? 'awaiting_configuration' : 'enrolled';
  } else if (sat.enrollment_state === 'awaiting_configuration' && !f.awaitingConfiguration
    && f.occurredAt.getTime() > time(sat.enrollment_state_at)) {
    outcome = 'configured';
    newState = 'enrolled';
  }
  const activates = outcome === 'awaiting' || outcome === 'completed';
  if (activates && !sat.id_activated_at) satUpdate.id_activated_at = f.occurredAt;
  try {
    await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update(satUpdate);
  } catch (err) {
    const e = err as { code?: string; constraint?: string };
    if (e.code === '23505' && (e.constraint === 'apple_devices_udid_active' || e.constraint === 'apple_devices_byod_id_active')) {
      // The identifier is still active in another tenant's record: its release (written before by apple-edge,
      // in the same transaction) is not consumed yet. Retried (file-durable §7.4), dead letters at the end.
      throw new JobError('missing_prerequisite', 'device identifier still active in another record');
    }
    throw err;
  }
  if (newState) {
    const deviceUpdate: Record<string, unknown> = { enrollment_state: newState, enrollment_state_at: f.occurredAt, updated_at: new Date() };
    if (activates) deviceUpdate.enrolled_at = f.occurredAt;
    await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update(deviceUpdate);
  }
  if (activates) {
    await markEpisodeEnrolled(trx, tenantId, deviceId, f.occurredAt);
    if (sat.enrollment_session_id) {
      await trx('enrollment_sessions').where({ tenant_id: tenantId, id: sat.enrollment_session_id }).whereNot('state', 'enrolled')
        .update({ state: 'enrolled', state_at: f.occurredAt, updated_at: new Date() });
    }
  }
  return { deviceId, outcome };
}

const RELEASE_REASONS = new Set<string>(ID_RELEASE_REASONS);

/**
 * A device leaves management (§7.3 onUnenrolled, modele §4.4): mdm.checkout ('checkout'), device.id_released
 * (apple-edge's reason), a retirement noted ('retired', 'removed_by_command', 'wiped'), the reconciliation
 * ('disabled_in_edge'), the purge ('purged'). The record goes 'unenrolled', the push is disabled, an
 * identifier released by apple-edge leaves the unique index, the episode is closed, the open targets of
 * commands are cancelled and a configuration plan in progress too. 'unknown' without a record; 'stale' for
 * an event of a previous cycle; 'already' when the record already left.
 */
export async function onUnenrolled(trx: Knex.Transaction, tenantId: number, enrollmentId: string,
  reason: UnenrollReason, occurredAt: Date, _eventId: string):
  Promise<{ deviceId: number | null; outcome: UnenrolledOutcome }> {
  const sat = await satelliteOf(trx, tenantId, enrollmentId);
  if (!sat) return { deviceId: null, outcome: 'unknown' };
  const deviceId = Number(sat.device_id);
  if (occurredAt.getTime() < time(sat.authenticated_at)) return { deviceId, outcome: 'stale' };
  if (sat.enrollment_state === 'unenrolled') return { deviceId, outcome: 'already' };
  await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update({
    enrollment_state: 'unenrolled', enrollment_state_at: occurredAt, unenrolled_at: occurredAt, unenroll_reason: reason,
    updated_at: new Date(),
  });
  const satUpdate: Record<string, unknown> = { push_state: 'disabled', push_state_at: occurredAt, updated_at: new Date() };
  if (RELEASE_REASONS.has(reason)) {
    satUpdate.id_released_at = occurredAt;
    satUpdate.id_release_reason = reason as IdReleaseReason;
  }
  await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update(satUpdate);
  await closeEpisode(trx, tenantId, deviceId, reason, occurredAt);
  // Open targets of the device's commands: cancelled (rank 3 over pending 0, queued 1, sent and notnow 2).
  await trx('mdm_command_targets')
    .where({ tenant_id: tenantId, device_id: deviceId })
    .whereIn('state', ['pending', 'queued', 'sent', 'notnow'])
    .update({ state: 'cancelled', reject_code: 'unenrolled', state_event_at: occurredAt });
  await trx('apple_setup_plans').where({ tenant_id: tenantId, device_id: deviceId, state: 'running' })
    .update({ state: 'cancelled', completed_at: occurredAt, outcome_code: 'unenrolled' });
  return { deviceId, outcome: 'unenrolled' };
}
