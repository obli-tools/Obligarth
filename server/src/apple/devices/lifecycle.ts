import type { Knex } from 'knex';
import {
  ID_RELEASE_REASONS, methodSupervises,
  type IdReleaseReason, type ManagementMode, type NanoEnrollType, type UnenrollReason,
} from '@obligarth/shared';
import { JobError } from '../../jobs/errors';
import { jobIdFor } from '../../jobs/ids';
import { raiseCountedInTx, raiseInTx } from '../alerts/service';
import {
  findDeviceForAuthenticate, findSessionForAuthenticate, managementModeFor, platformFromProductName, serialClaimOf,
  serialHolderOf, type DeviceMatch, type SessionFacts,
} from '../../mdm/registry/authenticateRules';
import { closeEpisode, markEpisodeEnrolled, openEpisode } from '../../mdm/registry/episodes';
import { applyCollectionRules } from '../../mdm/inventory/ingestors';
import { enrollmentReleaseJob } from '../../mdm/jobs';
import { afterCommit, cancelOpenTargetsOfDevice } from '../commands/targets';
import { realtime } from '../realtime';
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
//   - The serial number of the message is device data (S10): only an ADE
//     enrollment verifies it (apple-edge, against the session's MachineInfo).
//     Unverified, it finds a record that left management only, whose
//     identifier is released, and renews it (decision MDM-B2-R12, option A:
//     the profile's group, no direct assignment, lost mode off, no position);
//     held by any other record, it is never taken: the device gets a record
//     of its own, without a serial number, and an alert is raised.
//   - The kind of the identifier (UDID or EnrollmentID) of an enrollment id
//     never changes on a record (MDM-B2-R13); a record of the other kind out
//     of management, or under management against an ADE proof, gives its
//     enrollment id up (INT-B3-R3, options A and B: its satellite detached).
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

export type AuthenticateOutcome = 'created' | 'new_cycle' | 'duplicate' | 'stale' | 'no_session' | 'ownership_mismatch'
  | 'identity_mismatch';
export type TokenUpdateOutcome = 'completed' | 'awaiting' | 'configured' | 'refreshed' | 'stale';
export type UnenrolledOutcome = 'unenrolled' | 'already' | 'stale' | 'unknown';

export interface AuthenticateResult {
  deviceId: number | null;
  outcome: AuthenticateOutcome;
  /** The serial number presented is held by this other record (a device still under management, or any other
   *  record when the device was found by its enrollment id), which keeps it: the device was recorded without it
   *  and the alert security.identity_mismatch raised (the handler audits it). */
  serialHeldBy?: number;
  /** The record of the other kind of identifier that held this enrollment id gave it up (INT-B3-R3): out of management
   *  (superseded: false), or under management and superseded by the ADE proof of this Authenticate (superseded: true:
   *  it left management, 'superseded_by_proof', and the alert security.identity_mismatch was raised). Its satellite
   *  is deleted: the record keeps its history, the enrollment id is the new device's. */
  detached?: { recordId: number; superseded: boolean };
  /** Found by an unverified serial number (a record out of management whose identifier is released): renewed
   *  (MDM-B2-R12, option A): the group of the session's profile, its direct assignments, lost mode and positions
   *  removed. */
  renewed?: { assignments: number; locations: number };
  /** A new cycle without ADE proof on a record still under management and activated (MDM-B2-R13, option A): the
   *  alert enrollment.reenrolled_without_proof was raised. */
  reenrolledWithoutProof?: boolean;
  /** identity_mismatch: what the Authenticate contradicts. Absent: the serial number of the session's MachineInfo;
   *  'udid': the kind of the identifier of the record of this enrollment id (a UDID presented as an EnrollmentID, or
   *  the reverse), whose record (recordId) is not written (review of lot B2, MDM-B2-R13); the enrollment is released
   *  in both cases. */
  mismatch?: { field: 'udid'; recordId: number };
}

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
  nano_enroll_type: string;
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
      'a.id_activated_at', 'd.enrollment_state', 'd.enrollment_state_at', 'd.ownership', 'a.nano_enroll_type') as Promise<SatelliteRow | undefined>;
}

/** Number of enrollments without a session waiting for an operator (the count of the aggregated alert): one per
 *  Authenticate, counted once whatever the replays of its event (review of lot B2, MDM-B2-R7: the occurrence is
 *  ordered by the event's time and id, raiseCountedInTx). */
async function raiseUnknownSession(trx: Knex.Transaction, tenantId: number, f: AuthenticateFacts): Promise<void> {
  await raiseCountedInTx(trx, tenantId, 'enrollment.unknown_session', { at: f.occurredAt, eventId: f.eventId });
}

/** The columns of the record a new cycle writes (§4.5 rule 3, §10.4): from the session and the message. The
 *  serial number is not among them: onAuthenticate decides it. */
function cycleColumns(f: AuthenticateFacts, s: SessionFacts, mode: ManagementMode, rules: PrivacyRules,
  current: { platform: string | null; isNew: boolean }) {
  const msg = f.message ?? {};
  const productName = str(msg.ProductName, 64);
  const personal = s.ownership === 'personal';
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
 * for 'no_session' (alert enrollment.unknown_session), 'ownership_mismatch' (alert
 * enrollment.ownership_mismatch, job mdm.enrollment-release) nor 'identity_mismatch' (the message's serial
 * number contradicts the session's verified one, or, with `mismatch`, the kind of the identifier differs from
 * the record's of this enrollment id: alert security.identity_mismatch, job mdm.enrollment-release); the
 * handler writes the audit entries. The record is found by its enrollment id, else by its serial number
 * (findDeviceForAuthenticate): an unverified serial number never takes a record still under management
 * ('created' with serialHeldBy: a record of its own, without that serial number, and an alert).
 */
export async function onAuthenticate(trx: Knex.Transaction, tenantId: number, f: AuthenticateFacts):
  Promise<AuthenticateResult> {
  let sat = await satelliteOf(trx, tenantId, f.enrollmentId);
  let detached: AuthenticateResult['detached'];
  if (sat && sat.nano_enroll_type !== f.enrollmentType && f.occurredAt.getTime() > time(sat.authenticated_at)
    && (sat.enrollment_state === 'unenrolled' || f.proof === 'ade')) {
    // INT-B3-R3 (decided on 15/10/2026, options A and B): the record of the other kind gives the enrollment id up when
    // it is out of management (its identifier is free at apple-edge, which accepted this Authenticate), or when this
    // Authenticate carries the ADE proof (apple-edge released the other kind: an ADE device of the tenant prevails
    // over an EnrollmentID announced as its UDID). Before anything else: whatever this Authenticate becomes, the
    // enrollment id now answers to this device, never to that record (its next TokenUpdate would read as a refresh).
    const recordId = Number(sat.device_id);
    const superseded = sat.enrollment_state !== 'unenrolled';
    if (superseded) {
      await onUnenrolled(trx, tenantId, f.enrollmentId, 'superseded_by_proof', f.occurredAt, f.eventId);
      await raiseInTx(trx, tenantId, 'security.identity_mismatch', { params: { field: 'udid' } });
    }
    await trx('apple_devices').where({ tenant_id: tenantId, device_id: recordId }).del();
    detached = { recordId, superseded };
    sat = undefined;
  }
  if (sat) {
    // The kind of the identifier never changes under one enrollment id (review of lot B2, MDM-B2-R13): apple-edge
    // shares '<key>_<id>' between a UDID and an EnrollmentID, so a User Enrollment whose EnrollmentID is the UDID of
    // a device of the tenant (or the reverse) would take its record (a company device turned personal). Nothing is
    // written on the record and the alert is raised. apple-edge accepted that Authenticate: the enrollment id now
    // answers to the other device (NanoMDM bound it to the new certificate, the record's own device is refused
    // from then on), and its next TokenUpdate would read as a refresh of this record, whose commands and profiles
    // it would receive. As every refused Authenticate, the enrollment is released (mdm.enrollment-release, which
    // releases it only while apple-edge still holds it under the refused certificate): device.id_released then
    // takes the record out of management, and the device it belongs to enrolls again. An event older than the
    // record's cycle (consumed late, replayed after a new cycle) is stale: nothing raised nor released. Since lot C0,
    // apple-edge refuses such an Authenticate itself (403, security.device_id_conflict 'refused_other_kind') while the
    // record's identifier is active there: this branch remains for a record under management whose identifier is not
    // active at apple-edge (not yet activated, or released and not yet consumed), without an ADE proof (above).
    if (sat.nano_enroll_type !== f.enrollmentType) {
      if (f.occurredAt.getTime() <= time(sat.authenticated_at)) return { deviceId: Number(sat.device_id), outcome: 'stale' };
      await raiseInTx(trx, tenantId, 'security.identity_mismatch', { discriminant: Number(sat.device_id), params: { field: 'udid' } });
      await enrollmentReleaseJob().sendInTx(trx, { tenantId, eventId: f.eventId },
        { id: jobIdFor('mdm.enrollment-release', f.eventId), tenantId });
      return { deviceId: null, outcome: 'identity_mismatch', mismatch: { field: 'udid', recordId: Number(sat.device_id) } };
    }
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
    await raiseUnknownSession(trx, tenantId, f);
    return detached ? { deviceId: null, outcome: 'no_session', detached } : { deviceId: null, outcome: 'no_session' };
  }
  const mode = managementModeFor(f, session);
  if (!mode) {
    await raiseInTx(trx, tenantId, 'enrollment.ownership_mismatch', {});
    await enrollmentReleaseJob().sendInTx(trx, { tenantId, eventId: f.eventId },
      { id: jobIdFor('mdm.enrollment-release', f.eventId), tenantId });
    return detached ? { deviceId: null, outcome: 'ownership_mismatch', detached } : { deviceId: null, outcome: 'ownership_mismatch' };
  }
  // The serial number and its trust (S10): a message that contradicts the session's MachineInfo creates nothing
  // (apple-edge refuses such an Authenticate first; the enrollment is released if one got through).
  const claim = serialClaimOf(f, session);
  if (claim.contradicted) {
    await raiseInTx(trx, tenantId, 'security.identity_mismatch', { params: { field: 'serial' } });
    await enrollmentReleaseJob().sendInTx(trx, { tenantId, eventId: f.eventId },
      { id: jobIdFor('mdm.enrollment-release', f.eventId), tenantId });
    return detached ? { deviceId: null, outcome: 'identity_mismatch', detached } : { deviceId: null, outcome: 'identity_mismatch' };
  }
  const rules = await privacyRulesFor(trx, tenantId, session.ownership, f.enrollmentType);
  const keepsSerial = session.ownership !== 'personal' && rules.storeSerialNumber;

  // Rule 3: the existing record (the satellite of the enrollment id, else the serial number).
  let deviceId: number;
  let created = false;
  let serialHeldBy: number | undefined;
  let renewed: AuthenticateResult['renewed'];
  let reenrolledWithoutProof = false;
  const lookup = sat ? { deviceId: Number(sat.device_id), enrollmentId: f.enrollmentId, by: 'enrollment_id' as const }
    : await findDeviceForAuthenticate(trx, tenantId, f, rules, session);
  if (lookup && 'serialHeldBy' in lookup) serialHeldBy = lookup.serialHeldBy;
  const found: DeviceMatch | null = lookup && 'deviceId' in lookup ? lookup : null;
  if (found) {
    deviceId = found.deviceId;
    const current = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).forUpdate()
      .first('group_id', 'platform', 'enrollment_state_at', 'serial_number') as
      { group_id: number | null; platform: string; enrollment_state_at: Date | null; serial_number: string | null } | undefined;
    if (!current) throw new JobError('missing_prerequisite', 'record of the device not found');
    if (!sat && f.occurredAt.getTime() < time(current.enrollment_state_at)) {
      return detached ? { deviceId, outcome: 'stale', detached } : { deviceId, outcome: 'stale' };
    }
    const cols = cycleColumns(f, session, mode, rules, { platform: current.platform, isNew: false });
    // The serial number: cleared when the rules of the new cycle do not keep it (§5.2). A record found by its
    // enrollment id keeps a known serial number (a different one only raises an alert, as at the ingestion,
    // §5.3) and takes the presented one only if no other record holds it. Found by its serial number: unchanged.
    if (!keepsSerial) cols.serial_number = null;
    else if (found.by === 'enrollment_id' && claim.serial && claim.serial !== (current.serial_number ?? '').toUpperCase()) {
      if (current.serial_number) {
        await raiseInTx(trx, tenantId, 'device.serial_changed', { discriminant: deviceId });
      } else {
        const holder = await serialHolderOf(trx, tenantId, claim.serial, deviceId);
        if (holder !== null) serialHeldBy = holder;
        else cols.serial_number = claim.serial;
      }
    }
    // The group changes only when the profile asks for it (§4.5 rule 3), or when an unverified serial number found
    // the record (MDM-B2-R12, option A, decided on 15/10/2026): a device that only announced the serial number of a
    // retired record takes nothing of its configuration: the group of its own profile, no direct assignment (policies
    // and apps), lost mode off and no position of the previous cycle.
    if (session.resetGroupOnReenroll || found.by === 'serial') cols.group_id = session.groupId;
    if (found.by === 'serial') {
      cols.lost_mode_state = 'off';
      cols.lost_mode_changed_at = null;
      const assignments = await trx('assignments').where({ tenant_id: tenantId, target_scope: 'device', target_id: deviceId }).del();
      const locations = await trx('lost_mode_locations').where({ tenant_id: tenantId, device_id: deviceId }).del();
      renewed = { assignments: Number(assignments), locations: Number(locations) };
    } else if (sat && sat.enrollment_state !== 'unenrolled' && sat.id_activated_at && f.proof !== 'ade') {
      // MDM-B2-R13, option A: a new cycle of a record under management without the ADE proof (an OTA enrollment that
      // announces the UDID of an enrolled device, or the device itself installing a profile again): the operator checks.
      await raiseInTx(trx, tenantId, 'enrollment.reenrolled_without_proof', { discriminant: deviceId, navigateTo: `/devices/${deviceId}` });
      reenrolledWithoutProof = true;
    }
    await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update(cols);
    const satCols = satelliteColumns(f, session);
    const updated = await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).update(satCols);
    if (!updated) await trx('apple_devices').insert({ device_id: deviceId, tenant_id: tenantId, ...satCols });
    // What the rules of the new cycle do not collect leaves the inventory of the previous one (§5.2, criterion 7:
    // a device enrolled again under a narrower ownership, corporate → COPE, keeps no unmanaged app).
    await applyCollectionRules(trx, tenantId, deviceId, rules);
    // The commands requested before this Authenticate died with the previous cycle (apple-edge empties the queue of
    // an enrollment that authenticates again): their open targets are closed, the hooks of the final states run
    // (review of lot B3, INT-B3-R4). A command requested since belongs to the new cycle and stays.
    const closed = await cancelOpenTargetsOfDevice(trx, tenantId, deviceId, 'unenrolled', f.occurredAt, f.occurredAt);
    if (closed.length > 0) afterCommit(trx, () => realtime.commandChanged(tenantId, closed.slice(0, 500), [deviceId]));
    // The erased device lost its declarations: the set is to be synchronised again (§7.3, step 4).
    await trx('apple_declaration_sets').where({ tenant_id: tenantId, device_id: deviceId })
      .update({ sent_token: null, fetched_token: null, sync_command_id: null });
  } else {
    const cols = cycleColumns(f, session, mode, rules, { platform: null, isNew: true });
    // A serial number held by a record still under management is never written over it (devices_serial_uq):
    // the device gets a record of its own, without it (review of lot B2, MDM-B2-R1).
    cols.serial_number = keepsSerial && serialHeldBy === undefined ? claim.serial : null;
    const [row] = await trx('devices').insert({ tenant_id: tenantId, group_id: session.groupId, ...cols }).returning('id');
    deviceId = Number((row as { id: number }).id ?? row);
    created = true;
    await trx('apple_devices').insert({ device_id: deviceId, tenant_id: tenantId, ...satelliteColumns(f, session) });
  }
  if (serialHeldBy !== undefined) {
    // Another enrollment announced the serial number of a device under management (a forged message, or a
    // logic board replaced while the previous record still runs): the operator decides; that record is untouched.
    await raiseInTx(trx, tenantId, 'security.identity_mismatch', { discriminant: serialHeldBy, params: { field: 'serial' } });
  }

  // Rule 4: the episode of the cycle (the open one, if any, is replaced).
  await openEpisode(trx, tenantId, deviceId, {
    channelEnrollmentId: f.enrollmentId, method: session.method, mode, ownership: session.ownership,
    enrollmentProfileId: session.profileId, enrollmentSessionId: session.sessionId, endUserId: session.endUserId,
    certSha256: f.certSha256, startedAt: f.occurredAt,
  });
  // The session: authenticated (unless further), its device and certificate.
  await trx('enrollment_sessions').where({ tenant_id: tenantId, id: session.sessionId })
    .whereNotIn('state', ['authenticated', 'enrolled'])
    .update({ state: 'authenticated', state_at: f.occurredAt, updated_at: new Date() });
  await trx('enrollment_sessions').where({ tenant_id: tenantId, id: session.sessionId })
    .update({ device_id: deviceId, cert_sha256: trx.raw('COALESCE(cert_sha256, ?)', [f.certSha256]), updated_at: new Date() });
  // The device of Apple Business of the serial number: by the verified serial number only (an ADE enrollment),
  // never by the message's nor for a personal device (§7.3 step 6, review of lot B2).
  if (claim.verified && claim.serial && session.ownership !== 'personal') {
    await trx('apple_ade_devices').where({ tenant_id: tenantId, serial_number: claim.serial }).update({ device_id: deviceId, updated_at: new Date() });
  }
  const result: AuthenticateResult = { deviceId, outcome: created ? 'created' : 'new_cycle' };
  if (serialHeldBy !== undefined) result.serialHeldBy = serialHeldBy;
  if (detached) result.detached = detached;
  if (renewed) result.renewed = renewed;
  if (reenrolledWithoutProof) result.reenrolledWithoutProof = true;
  return result;
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
 * device.id_released for a record already out of management (§7.3, modele §4.5, DM26): apple-edge released the
 * identifier later than the departure (a departure without release: 'wiped', 'removed_by_command',
 * 'disabled_in_edge'), or the release of a departure already recorded. The identifier of the current cycle
 * leaves the unique index of the active identifiers when it is still in it (id_released_at, the reason of
 * apple-edge); an event of a previous cycle changes nothing. Returns true when it released the identifier.
 */
export async function releaseIdentifier(trx: Knex.Transaction, tenantId: number, enrollmentId: string,
  reason: IdReleaseReason, occurredAt: Date): Promise<boolean> {
  if (!RELEASE_REASONS.has(reason)) return false;
  const n = await trx('apple_devices')
    .where({ tenant_id: tenantId, enrollment_id: enrollmentId })
    .whereNull('id_released_at')
    .where('authenticated_at', '<=', occurredAt)
    // A record out of management only: the release of a managed one is onUnenrolled's.
    .whereIn('device_id', (q) => q.select('id').from('devices').where({ tenant_id: tenantId, enrollment_state: 'unenrolled' }))
    .update({ id_released_at: occurredAt, id_release_reason: reason, push_state: 'disabled', push_state_at: occurredAt, updated_at: new Date() });
  return Number(n) > 0;
}

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
  // A setup plan in progress ends first (its hook would otherwise release a device that is gone).
  await trx('apple_setup_plans').where({ tenant_id: tenantId, device_id: deviceId, state: 'running' })
    .update({ state: 'cancelled', completed_at: occurredAt, outcome_code: 'unenrolled' });
  // Open targets of the device's commands: cancelled (rank 3 over pending 0, queued 1, sent and notnow 2), through
  // the writer of the target states: the hooks of the final states run (setup plan, DDM, policies), and the console
  // is told once the event is committed (review of lot B3, INT-B3-R4).
  const closed = await cancelOpenTargetsOfDevice(trx, tenantId, deviceId, 'unenrolled', occurredAt);
  if (closed.length > 0) afterCommit(trx, () => realtime.commandChanged(tenantId, closed.slice(0, 500), [deviceId]));
  return { deviceId, outcome: 'unenrolled' };
}
