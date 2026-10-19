import type { Knex } from 'knex';
import { config } from '../../config';
import { JobError, PermanentJobError, jobIdFor, registerOutboxHandler, type OutboxHandlerContext } from '../../jobs';
import { checkEnrollmentSpike, raiseInTx } from '../alerts/service';
import { applyTargetState, expireTargets, isFinalTargetState, type TargetState } from '../commands/targets';
import { ingestCommandResult, summarizeResult } from '../commands/results';
import { deviceEvents } from '../devices/events';
import { deviceJobs, sendUnenrollCleanup } from '../devices/jobs';
import { onAuthenticate, onTokenUpdate, onUnenrolled, type AuthenticateFacts } from '../devices/lifecycle';
import { appleMetrics } from '../metrics';
import { realtime } from '../realtime';
import { firstTimeFor } from './once';
import { P, type PayloadOf } from './schemas';

// =============================================================================
// Handlers of the enrollment, command and SCEP events of apple-edge (docs:
// integration-apple-edge §7.3, §7.4, §7.6, §8.2; rules G-1 to G-9 of §7.2):
//   mdm.authenticate        onAuthenticate (DM25: no record without a session;
//                           barrier 2; cycles); timeline enrollment_started;
//                           audits of the refused enrollments
//   mdm.token_update        onTokenUpdate (DM26: activation at the first token
//                           of the cycle); apple.device-onboard and
//                           apple.await-configuration; device.enrolled;
//                           timeline; enrollment.spike
//   mdm.checkout            onUnenrolled('checkout'); devices.unenroll-cleanup;
//                           device.checked_out (company devices)
//   mdm.command_delivered   target 'sent', delivered_at = the earliest delivery
//   mdm.command_result      target by status (§8.2), ingestion (§7.6), hooks
//                           of the final states, command.failed, audit of the
//                           guarded commands
//   mdm.command_expired     targets 'expired' (one statement)
//   mdm.seen_batch          devices.last_checkin_at = maximum (one statement)
//   scep.certificate_issued the session of the challenge: certificate_issued
// Writes through ctx.trx only (the event's tenant context, set by the
// consumer), no network call; follow-up work as jobs (sendInTx: they exist only
// if the event is consumed, a replay adds none), Socket.io after the commit
// (ctx.afterCommit), audit entries at the end of the batch (ctx.audit). A
// state of a record or a target never goes back (monotony by occurred_at,
// cycles, ranks): an event replayed or consumed late changes nothing, and its
// one-time effects (timeline entry, audit, alert count) are written once.
// The payload is never logged; an identifier of a device never leaves the
// database (logs, alerts, job payloads, realtime: internal ids only).
// =============================================================================

type Ctx<K extends keyof typeof P> = OutboxHandlerContext<PayloadOf<K>>;

/** An enrollment id of apple-edge: '<key>_<raw id>' (ids.go alphabet). */
const ENROLLMENT_ID_RE = /^[a-km-np-z2-9]{16}_[A-Za-z0-9._-]{1,128}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** error_chain kept in a target (§8.2): 8 KiB at most. */
const MAX_ERROR_CHAIN_BYTES = 8192;

const deviceTarget = (deviceId: number) => ({ type: 'device', id: String(deviceId), device: deviceId });

function ignored(ctx: OutboxHandlerContext<unknown>, why: string): void {
  appleMetrics.eventIgnored(ctx.event.type);
  ctx.log.debug({ why }, 'outbox event without effect');
}

/** The enrollment session of the device's current cycle (for the realtime event of the session). */
async function sessionOfDevice(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<string | null> {
  const r = await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).first('enrollment_session_id') as
    { enrollment_session_id: string | null } | undefined;
  return r?.enrollment_session_id ?? null;
}

/** The identifier of the departure of a record (its device and unenrolled_at): one cleanup job per departure. */
async function departureOf(trx: Knex.Transaction, tenantId: number, deviceId: number):
  Promise<{ unenrolledAt: Date | null; reason: string | null; ownership: string | null }> {
  const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).first('unenrolled_at', 'unenroll_reason', 'ownership') as
    { unenrolled_at: Date | null; unenroll_reason: string | null; ownership: string | null } | undefined;
  return { unenrolledAt: d?.unenrolled_at ? new Date(d.unenrolled_at) : null, reason: d?.unenroll_reason ?? null, ownership: d?.ownership ?? null };
}

// ── mdm.authenticate ────────────────────────────────────────────────────────────

async function handleAuthenticate(ctx: Ctx<'mdm.authenticate'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  // The device channel only: apple-edge refuses an Authenticate on a user channel.
  if (p.enrollment_type !== 'Device' && p.enrollment_type !== 'User Enrollment (Device)') {
    ignored(ctx, 'not_device_channel');
    return;
  }
  // G-1 (the consumer) checked the prefix; the enrollment must also be the device's own '<key>_<device_id>' (review
  // of lot B2, MDM-B2-R5): an event that says otherwise is refused (dead letter), never written.
  const enrollmentId = event.enrollmentId ?? '';
  if (!ENROLLMENT_ID_RE.test(enrollmentId) || enrollmentId !== `${event.tenantKey}_${p.device_id}`) {
    throw new PermanentJobError('enrollment_mismatch', 'the enrollment of the event is not the device\'s');
  }
  const facts: AuthenticateFacts = {
    enrollmentId,
    kind: p.enrollment_type === 'Device' ? 'udid' : 'enrollment_id',
    rawId: p.device_id,
    enrollmentType: p.enrollment_type,
    topic: p.topic,
    proof: p.proof,
    certSha256: p.identity.cert_sha256 ?? null,
    certNotAfter: p.identity.not_after ? new Date(p.identity.not_after) : null,
    challengeId: p.identity.challenge_id ?? null,
    sessionRef: p.identity.session_ref ?? null,
    message: p.message,
    occurredAt: event.occurredAt,
    eventId: event.eventId,
  };
  const r = await onAuthenticate(trx, tenantId, facts);
  if (r.detached?.superseded) {
    // INT-B3-R3, option A: the record of the other kind (a User Enrollment whose EnrollmentID was this ADE device's
    // UDID, or the reverse) left management, superseded by the ADE proof; its satellite is detached. Its departure
    // as for device.id_released ('superseded_by_proof'), written once per event.
    const recordId = r.detached.recordId;
    if (await deviceEvents.add(trx, tenantId, recordId, 'released', event.occurredAt, event.eventId, { reason: 'superseded_by_proof' })) {
      const departure = await departureOf(trx, tenantId, recordId);
      await sendUnenrollCleanup(trx, tenantId, recordId, departure.unenrolledAt);
      const otherKind = facts.kind === 'udid' ? 'enrollment_id' : 'udid';
      ctx.audit({ tenantId, action: 'device.id_released', target: deviceTarget(recordId), details: { reason: 'superseded_by_proof', idKind: otherKind } });
      ctx.audit({ tenantId, action: 'security.identity_mismatch', outcome: 'denied', target: deviceTarget(recordId),
        details: { field: 'udid', stage: 'authenticate', nanoType: p.enrollment_type, outcome: 'superseded_by_proof' } });
      await raiseInTx(trx, tenantId, 'device.superseded', { discriminant: recordId, navigateTo: `/devices/${recordId}` });
      ctx.afterCommit(() => realtime.deviceChanged(tenantId, recordId));
    }
  }
  switch (r.outcome) {
    case 'created':
    case 'new_cycle': {
      const deviceId = r.deviceId as number;
      await deviceEvents.add(trx, tenantId, deviceId, 'enrollment_started', event.occurredAt, event.eventId, {
        cycle: r.outcome === 'created' ? 'first' : 'new', proof: p.proof,
        ...(r.renewed ? { renewed: true } : {}), ...(r.reenrolledWithoutProof ? { withoutProof: true } : {}),
      });
      if (r.serialHeldBy !== undefined) {
        // Another enrollment announced the serial number of a device under management: that record keeps it (review
        // of lot B2, MDM-B2-R1). The alert is raised by the lifecycle; the entry targets the record it protects.
        ctx.audit({ tenantId, action: 'security.identity_mismatch', outcome: 'denied', target: deviceTarget(r.serialHeldBy),
          details: { field: 'serial', stage: 'authenticate', recordedAs: deviceId } });
      }
      const sessionId = await sessionOfDevice(trx, tenantId, deviceId);
      ctx.afterCommit(() => {
        realtime.deviceChanged(tenantId, deviceId, r.serialHeldBy);
        realtime.sessionChanged(tenantId, sessionId);
      });
      return;
    }
    case 'ownership_mismatch':
      // Barrier 2 (modele §4.3): no record, alert and release by the lifecycle; the audit here, once per event.
      if (await firstTimeFor(trx, event.eventId, 'audit')) {
        ctx.audit({ tenantId, action: 'enrollment.ownership_mismatch', outcome: 'denied',
          details: { nanoType: p.enrollment_type, proof: p.proof } });
      }
      return;
    case 'identity_mismatch':
      // The serial number of the message contradicts the session's MachineInfo (no record), or the kind of the
      // identifier is not the record's of this enrollment id (the record not written, MDM-B2-R13): alert and
      // release by the lifecycle, the audit here, once per event.
      if (await firstTimeFor(trx, event.eventId, 'audit')) {
        ctx.audit({ tenantId, action: 'security.identity_mismatch', outcome: 'denied',
          ...(r.mismatch ? { target: deviceTarget(r.mismatch.recordId) } : {}),
          details: { field: r.mismatch?.field ?? 'serial', stage: 'authenticate', nanoType: p.enrollment_type } });
      }
      return;
    case 'no_session':                                  // DM25: alert counted by the lifecycle
    case 'duplicate':
    case 'stale':
    default:
      return;
  }
}

// ── mdm.token_update ────────────────────────────────────────────────────────────

async function handleTokenUpdate(ctx: Ctx<'mdm.token_update'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  if (p.channel !== 'device') {                         // user channel: macOS, v1
    ignored(ctx, 'user_channel');
    return;
  }
  if (!event.enrollmentId) {
    ignored(ctx, 'no_enrollment');
    return;
  }
  const r = await onTokenUpdate(trx, tenantId, {
    enrollmentId: event.enrollmentId, awaitingConfiguration: p.awaiting_configuration, hasUnlockToken: p.has_unlock_token,
    topic: p.topic ?? '', tokenUpdateTally: p.token_update_tally, occurredAt: event.occurredAt, eventId: event.eventId,
  });
  if (r === null) throw new JobError('missing_prerequisite', 'TokenUpdate before its Authenticate');
  const deviceId = r.deviceId;
  if (r.outcome === 'stale') {
    const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).first('enrollment_state') as { enrollment_state: string } | undefined;
    if (d?.enrollment_state === 'unenrolled') appleMetrics.tokenUpdateAfterUnenroll();
    return;
  }
  if (r.outcome === 'completed' || r.outcome === 'awaiting') {
    // The first token of the cycle (I3, DM26): the device opens to management.
    await deviceJobs.onboard().sendInTx(trx, { tenantId, deviceId }, { id: jobIdFor('apple.device-onboard', event.eventId), tenantId });
    if (r.outcome === 'awaiting') {
      await deviceJobs.awaitConfiguration().sendInTx(trx, { tenantId, deviceId }, { singletonKey: `d:${deviceId}`, tenantId });
    }
    const kind = r.outcome === 'awaiting' ? 'awaiting_configuration' : 'enrolled';
    await deviceEvents.add(trx, tenantId, deviceId, kind, event.occurredAt, event.eventId);
    ctx.audit({ tenantId, action: 'device.enrolled', target: deviceTarget(deviceId), details: { awaiting: r.outcome === 'awaiting' } });
    await checkEnrollmentSpike(trx, tenantId, event.occurredAt, config.apple.enrollmentSpikeCount);
    const sessionId = await sessionOfDevice(trx, tenantId, deviceId);
    ctx.afterCommit(() => {
      realtime.deviceChanged(tenantId, deviceId);
      realtime.sessionChanged(tenantId, sessionId);
    });
    return;
  }
  if (r.outcome === 'configured') {
    // The token after DeviceConfigured: the device left the setup assistant.
    await deviceEvents.add(trx, tenantId, deviceId, 'configured', event.occurredAt, event.eventId);
  }
  ctx.afterCommit(() => realtime.deviceChanged(tenantId, deviceId));
}

// ── mdm.checkout ────────────────────────────────────────────────────────────────

async function handleCheckout(ctx: Ctx<'mdm.checkout'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const enrollmentId = event.enrollmentId ?? '';
  if (!enrollmentId || enrollmentId.includes(':')) {   // a user channel (macOS, v1): the device channel stays
    ignored(ctx, 'user_channel');
    return;
  }
  const r = await onUnenrolled(trx, tenantId, enrollmentId, 'checkout', event.occurredAt, event.eventId);
  if (r.outcome === 'unknown') {
    ignored(ctx, 'no_record');
    return;
  }
  if (r.outcome === 'stale') return;
  const deviceId = r.deviceId as number;
  const departure = await departureOf(trx, tenantId, deviceId);
  // 'already': the release of the same departure (device.id_released, reason checkout) may have been consumed first;
  // the checkout's own effects are then written now, once per cycle (a device repeats a CheckOut whose answer it
  // lost). Another departure (retired, wiped…) gets none.
  if (r.outcome === 'already' && (departure.reason !== 'checkout' || await deviceEvents.inCurrentCycle(trx, tenantId, deviceId, 'checked_out'))) return;
  // The timeline entry is written once per event: a replay writes neither it nor what goes with it.
  if (!(await deviceEvents.add(trx, tenantId, deviceId, 'checked_out', event.occurredAt, event.eventId))) return;
  await sendUnenrollCleanup(trx, tenantId, deviceId, departure.unenrolledAt);
  ctx.audit({ tenantId, action: 'device.checked_out', target: deviceTarget(deviceId) });
  if (departure.ownership === 'corporate' || departure.ownership === 'corporate_personal') {
    await raiseInTx(trx, tenantId, 'device.checked_out', { discriminant: deviceId, navigateTo: `/devices/${deviceId}` });
  }
  ctx.afterCommit(() => realtime.deviceChanged(tenantId, deviceId));
}

// ── Commands ────────────────────────────────────────────────────────────────────

/** The error chain of a result, 8 KiB at most (its first entries). */
export function boundedErrorChain(chain: unknown): string | null {
  if (chain === undefined || chain === null) return null;
  let value: unknown = chain;
  let json = JSON.stringify(value);
  if (Buffer.byteLength(json) <= MAX_ERROR_CHAIN_BYTES) return json;
  if (Array.isArray(chain)) {
    const kept: unknown[] = [];
    for (const e of chain) {
      const next = JSON.stringify([...kept, e]);
      if (Buffer.byteLength(next) > MAX_ERROR_CHAIN_BYTES - 32) break;
      kept.push(e);
    }
    value = kept;
    json = JSON.stringify(value);
    if (Buffer.byteLength(json) <= MAX_ERROR_CHAIN_BYTES) return json;
  }
  return JSON.stringify({ truncated: true });
}

async function handleCommandDelivered(ctx: Ctx<'mdm.command_delivered'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const commandId = event.commandUuid ?? '';
  const enrollmentId = event.enrollmentId ?? '';
  if (!UUID_RE.test(commandId) || !enrollmentId) {
    ignored(ctx, 'no_command');
    return;
  }
  const r = await applyTargetState(trx, { tenantId, commandId, enrollmentId, to: 'sent', at: event.occurredAt });
  if (!r.found) {
    ignored(ctx, 'unknown_target');                     // a command the brain did not create, or another enrollment
    return;
  }
  // The earliest delivery, whatever the state (a result may have been consumed first).
  await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId, enrollment_id: enrollmentId })
    .update({ delivered_at: trx.raw('LEAST(COALESCE(delivered_at, ?::timestamptz), ?::timestamptz)', [event.occurredAt, event.occurredAt]) });
  if (r.applied) ctx.afterCommit(() => realtime.commandChanged(tenantId, [commandId], [r.deviceId as number]));
}

const RESULT_STATE: Record<PayloadOf<'mdm.command_result'>['status'], TargetState> = {
  NotNow: 'notnow', Acknowledged: 'acknowledged', Error: 'error', CommandFormatError: 'error',
};

async function handleCommandResult(ctx: Ctx<'mdm.command_result'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  const commandId = event.commandUuid ?? '';
  const enrollmentId = event.enrollmentId ?? '';
  if (!UUID_RE.test(commandId) || !enrollmentId) {
    ignored(ctx, 'no_command');
    return;
  }
  const to = RESULT_STATE[p.status];
  const set: Record<string, unknown> = { last_status: p.status };
  if (to === 'acknowledged' || to === 'error') set.completed_at = event.occurredAt;
  if (to === 'error') set.error_chain = boundedErrorChain(p.error_chain);
  const r = await applyTargetState(trx, { tenantId, commandId, enrollmentId, to, at: event.occurredAt, set });
  if (!r.found) {
    ignored(ctx, 'unknown_target');
    return;
  }
  if (!r.applied) {
    // A final result after a final result (the device repeats a status, 05 §5.3): the first one stays.
    if (r.previous && targetIsFinalResult(r.previous) && isFinalTargetState(to)) appleMetrics.duplicateResult();
    return;
  }
  const deviceId = r.deviceId as number;
  const requestType = r.requestType ?? p.request_type;
  if (to === 'acknowledged' || to === 'error') {
    // The ingestion of §7.6 (inline in this savepoint, or deferred to its job), then the summary of the target.
    await ingestCommandResult(trx, { tenantId, deviceId, commandId, status: p.status, result: p.result, occurredAt: event.occurredAt,
      requestType, eventId: event.eventId });
    if (to === 'acknowledged') {
      const summary = summarizeResult(requestType, p.result);
      if (summary) {
        await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId, device_id: deviceId })
          .update({ result_summary: JSON.stringify(summary) });
      }
    }
    if (r.guardActionUuid) {
      // A command of a guarded action (audit-durci §10.12): its end in the journal, with the action's link.
      ctx.audit({ tenantId, action: to === 'acknowledged' ? 'mdm.command_acknowledged' : 'mdm.command_failed',
        outcome: to === 'acknowledged' ? 'success' : 'failure', target: deviceTarget(deviceId),
        details: { commandId: commandId.toLowerCase(), requestType, status: p.status }, links: { action: r.guardActionUuid } });
    }
    if (to === 'error' && r.byUser) {
      // command.failed: the failed targets of a user's command, counted (idempotent).
      const n = await trx('mdm_command_targets').where({ tenant_id: tenantId, command_id: commandId, state: 'error' })
        .count('* as n').first() as { n: string | number } | undefined;
      await raiseInTx(trx, tenantId, 'command.failed', { discriminant: commandId.toLowerCase(), params: { requestType, count: Number(n?.n ?? 1) } });
    }
  }
  ctx.afterCommit(() => realtime.commandChanged(tenantId, [commandId], [deviceId]));
}

const targetIsFinalResult = (state: string): boolean => state === 'acknowledged' || state === 'error';

async function handleCommandExpired(ctx: Ctx<'mdm.command_expired'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const commandId = event.commandUuid ?? '';
  if (!UUID_RE.test(commandId)) {
    ignored(ctx, 'no_command');
    return;
  }
  // T-3: the targets of the event are enrollments of the event's tenant only (the consumer checked no prefix: the
  // event names no enrollment of its own).
  const prefix = `${event.tenantKey}_`;
  const targets = [...new Set(event.payload.targets)].filter((t) => t.startsWith(prefix) && t.length > prefix.length);
  if (targets.length < event.payload.targets.length) ctx.log.warn({ dropped: event.payload.targets.length - targets.length }, 'expired targets outside the tenant ignored');
  const devices = await expireTargets(trx, tenantId, commandId, targets, event.occurredAt);
  if (devices.length === 0) {
    ignored(ctx, 'no_open_target');
    return;
  }
  ctx.afterCommit(() => realtime.commandChanged(tenantId, [commandId], devices));
}

// ── mdm.seen_batch ──────────────────────────────────────────────────────────────

async function handleSeenBatch(ctx: Ctx<'mdm.seen_batch'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const prefix = `${event.tenantKey}_`;
  const ids: string[] = [];
  const seen: string[] = [];
  for (const e of event.payload.enrollments) {
    // The device channel of the tenant's enrollments only (a user channel carries ':<user>').
    if (!e.enrollment_id.startsWith(prefix) || e.enrollment_id.includes(':') || !ENROLLMENT_ID_RE.test(e.enrollment_id)) continue;
    ids.push(e.enrollment_id);
    seen.push(new Date(e.last_seen_at).toISOString());
  }
  if (ids.length === 0) return;
  // One statement (§7.4): the latest contact of each device, never an older one. The rows are locked first, in
  // ascending order (MDM-B5c-R13: the resolution of a tenant locks its slices in that order; an UPDATE alone locks
  // them in the order of its plan), and only those whose contact moves forward.
  await trx.raw(`
    WITH s AS (SELECT a.device_id, max(u.seen) AS seen
                 FROM unnest(?::text[], ?::timestamptz[]) AS u(enrollment_id, seen)
                 JOIN obligarth.apple_devices a ON a.enrollment_id = u.enrollment_id AND a.tenant_id = ?
                GROUP BY a.device_id),
         l AS (SELECT d.id, s.seen
                 FROM obligarth.devices d JOIN s ON s.device_id = d.id
                WHERE d.tenant_id = ? AND (d.last_checkin_at IS NULL OR d.last_checkin_at < s.seen)
                ORDER BY d.id
                  FOR NO KEY UPDATE OF d)
    UPDATE obligarth.devices d
       SET last_checkin_at = l.seen
      FROM l
     WHERE d.id = l.id AND d.tenant_id = ?
       AND (d.last_checkin_at IS NULL OR d.last_checkin_at < l.seen)`, [ids, seen, tenantId, tenantId, tenantId]);
}

// ── scep.certificate_issued ─────────────────────────────────────────────────────

/** States of a session before its identity is issued (the issuance moves them to certificate_issued). */
const BEFORE_ISSUANCE = ['started', 'acknowledged', 'profile_issued', 'certificate_issued'];

async function handleCertificateIssued(ctx: Ctx<'scep.certificate_issued'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  // The session by its reference (the session_ref given with the challenge), else by the challenge.
  type SessionRow = { id: string; state: string; state_at: Date | null; challenge_id: string | null };
  const find = (where: Record<string, string>) => trx('enrollment_sessions').where({ tenant_id: tenantId, ...where }).forUpdate()
    .first('id', 'state', 'state_at', 'challenge_id') as Promise<SessionRow | undefined>;
  const byRef = p.session_ref && UUID_RE.test(p.session_ref) ? await find({ id: p.session_ref.toLowerCase() }) : undefined;
  const session = byRef ?? await find({ challenge_id: p.challenge_id.toLowerCase() });
  if (!session) {
    ignored(ctx, 'no_session');
    return;
  }
  // State of the session (monotone): an issuance moves a session that has not authenticated yet; the certificate of
  // the last issuance is the one the device presents (an Authenticate finds the session by it).
  if (!BEFORE_ISSUANCE.includes(session.state)) return;
  if (session.state_at && new Date(session.state_at).getTime() > event.occurredAt.getTime() && session.state === 'certificate_issued') return;
  await trx('enrollment_sessions').where({ tenant_id: tenantId, id: session.id }).update({
    state: 'certificate_issued', state_at: event.occurredAt, cert_sha256: p.cert_sha256,
    challenge_id: session.challenge_id ?? p.challenge_id.toLowerCase(), updated_at: new Date(),
  });
  ctx.afterCommit(() => realtime.sessionChanged(tenantId, session.id));
}

let registered = false;

export function registerMdmHandlers(): void {
  if (registered) return;
  registered = true;
  const t = (type: keyof typeof P, handle: (ctx: any) => Promise<void>) => registerOutboxHandler({
    type, scope: 'tenant', module: 'apple', payload: P[type], handle,
  });
  t('mdm.authenticate', handleAuthenticate);
  t('mdm.token_update', handleTokenUpdate);
  t('mdm.checkout', handleCheckout);
  t('mdm.command_delivered', handleCommandDelivered);
  t('mdm.command_result', handleCommandResult);
  t('mdm.command_expired', handleCommandExpired);
  t('mdm.seen_batch', handleSeenBatch);
  t('scep.certificate_issued', handleCertificateIssued);
}
