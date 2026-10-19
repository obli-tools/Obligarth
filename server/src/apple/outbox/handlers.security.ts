import type { Knex } from 'knex';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { applyTenantContext } from '../../db/tenantContext';
import { registerOutboxHandler, type OutboxHandlerContext } from '../../jobs';
import { raiseCountedInTx, raiseInTx, type RaiseOptions } from '../alerts/service';
import type { AppleAlertKind } from '../alerts/catalog';
import { deviceEvents } from '../devices/events';
import { sendUnenrollCleanup } from '../devices/jobs';
import { onUnenrolled, releaseIdentifier } from '../devices/lifecycle';
import { appleMetrics } from '../metrics';
import { realtime } from '../realtime';
import { firstTimeFor } from './once';
import { P, type PayloadOf } from './schemas';

// =============================================================================
// Handlers of the security and device events of apple-edge (docs:
// integration-apple-edge §7.4; rules G-1 to G-9 of §7.2):
//   security.topic_mismatch        apns.no_certificate (no push certificate) or
//                                  security.topic_mismatch (counted); audit once
//                                  per alert raised (a refused check-in repeats)
//   security.identity_expired      the record of the current certificate:
//                                  identity 'expired'; devices.identity_expired
//                                  (count of the records); audit; timeline
//   security.identity_revoked      the record: 'revoked'; security.identity_revoked
//                                  (counted); audit; timeline
//   security.identity_mismatch     the session of the enrollment 'failed' when
//                                  the event names it; alert; audit
//   security.device_id_conflict    tenant: alert without the other tenant, audit;
//                                  platform: platform.device_id_conflict and the
//                                  audit in the master tenant (names of both)
//   security.foreign_certificate   platform: platform.foreign_certificate (master)
//   device.id_released             onUnenrolled(reason) or the release of the
//                                  identifier of a departure; cleanup job;
//                                  device.superseded, devices.apns_inactive_released
//   device.transfer_completed      tenant: audit (direction), timeline; platform:
//                                  audit in the master tenant
// An alert raised from an event that changes no record is counted by the
// event's time (raiseCountedInTx: a replay counts nothing); its audit entry is
// written once per event (job_once marker, ./once.ts). A platform event writes
// in the master tenant after applyTenantContext(ctx.trx, 1) (G-6) and never in
// another tenant's chain. Texts and details never hold a device identifier,
// a serial number nor another tenant's key: names of tenants in the master
// tenant only (platform administrators).
// =============================================================================

type Ctx<K extends keyof typeof P> = OutboxHandlerContext<PayloadOf<K>>;

const deviceTarget = (deviceId: number) => ({ type: 'device', id: String(deviceId), device: deviceId });
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function ignored(ctx: OutboxHandlerContext<unknown>, why: string): void {
  appleMetrics.eventIgnored(ctx.event.type);
  ctx.log.debug({ why }, 'outbox event without effect');
}

/** A counted alert of an event (its time and id): an event applied again adds nothing. */
function raiseForEvent(ctx: OutboxHandlerContext<unknown>, tenantId: number, kind: AppleAlertKind, opts: RaiseOptions = {}) {
  return raiseCountedInTx(ctx.trx, tenantId, kind, { at: ctx.event.occurredAt, eventId: ctx.event.eventId }, opts);
}

/** The record whose CURRENT identity certificate is `sha` (a record re-enrolled since has another one). */
async function recordOfCertificate(trx: Knex.Transaction, tenantId: number, sha: string): Promise<{ deviceId: number; state: string } | null> {
  const r = await trx('apple_devices').where({ tenant_id: tenantId, cert_sha256: sha }).first('device_id', 'identity_state') as
    { device_id: number; identity_state: string } | undefined;
  return r ? { deviceId: Number(r.device_id), state: r.identity_state } : null;
}

/** Names of tenants by MDM key, read in the consumer's context 'none' (the registry is readable there). */
async function tenantsByKey(trx: Knex.Transaction, keys: string[]): Promise<Map<string, { id: number; name: string }>> {
  const valid = keys.filter((k) => /^[a-km-np-z2-9]{16}$/.test(k));
  const out = new Map<string, { id: number; name: string }>();
  if (valid.length === 0) return out;
  const rows = await trx('tenants').whereIn('mdm_key', valid).select('id', 'name', 'mdm_key') as Array<{ id: number; name: string; mdm_key: string }>;
  for (const r of rows) out.set(r.mdm_key, { id: Number(r.id), name: r.name });
  return out;
}

/** fn in the master tenant's context (G-6), then the consumer's context 'none' again. When fn fails, the consumer
 *  rolls the event's savepoint back and sets its own context (EventScope.failed): no statement here, which would
 *  fail in the aborted transaction and hide the error of fn (its code decides the retry). */
async function inMaster<T>(ctx: OutboxHandlerContext<unknown>, fn: () => Promise<T>): Promise<T> {
  await applyTenantContext(ctx.trx, MASTER_TENANT_ID, ctx.actor);
  const out = await fn();
  await applyTenantContext(ctx.trx, null, ctx.actor);
  return out;
}

// ── security.* (tenant) ─────────────────────────────────────────────────────────

async function handleTopicMismatch(ctx: Ctx<'security.topic_mismatch'>): Promise<void> {
  const tenantId = ctx.tenantId as number;
  const p = ctx.event.payload;
  // No push certificate at all: the tenant's problem (§12.1); another topic: a device of another configuration.
  const r = p.reason === 'no_push_certificate'
    ? await raiseForEvent(ctx, tenantId, 'apns.no_certificate')
    : await raiseForEvent(ctx, tenantId, 'security.topic_mismatch');
  // A device whose topic is refused repeats its check-ins: one entry per alert raised, not per refused request.
  if (r.created) {
    ctx.audit({ tenantId, action: 'security.topic_mismatch', outcome: 'denied', details: { reason: p.reason } });
    ctx.afterCommit(() => realtime.integrationChanged(tenantId, 'push'));
  }
}

async function handleIdentityExpired(ctx: Ctx<'security.identity_expired'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const rec = await recordOfCertificate(trx, tenantId, event.payload.cert_sha256);
  if (!rec) {
    ignored(ctx, 'no_record');                          // no record, or re-enrolled with another certificate
    return;
  }
  // valid → expired (a revoked identity stays revoked).
  const n = await trx('apple_devices').where({ tenant_id: tenantId, device_id: rec.deviceId, cert_sha256: event.payload.cert_sha256, identity_state: 'valid' })
    .update({ identity_state: 'expired', updated_at: new Date() });
  if (!Number(n)) return;
  await deviceEvents.add(trx, tenantId, rec.deviceId, 'identity_expired', event.occurredAt, event.eventId);
  ctx.audit({ tenantId, action: 'security.identity_expired', outcome: 'denied', target: deviceTarget(rec.deviceId) });
  // Aggregated (§12.1): the devices under management whose identity expired, counted from the records.
  const c = await trx('apple_devices as a')
    .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId, 'a.identity_state': 'expired' }).whereNot('d.enrollment_state', 'unenrolled')
    .count('* as n').first() as { n: string | number } | undefined;
  await raiseInTx(trx, tenantId, 'devices.identity_expired', { params: { count: Number(c?.n ?? 1) } });
  ctx.afterCommit(() => realtime.deviceChanged(tenantId, rec.deviceId));
}

async function handleIdentityRevoked(ctx: Ctx<'security.identity_revoked'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  // A revoked identity presented is a security event of the tenant (attack A19), recorded or not (a device
  // retired, purged): the alert counts the refused connections, the journal keeps each event once.
  await raiseForEvent(ctx, tenantId, 'security.identity_revoked');
  const rec = await recordOfCertificate(trx, tenantId, event.payload.cert_sha256);
  if (await firstTimeFor(trx, event.eventId, 'audit')) {
    ctx.audit({ tenantId, action: 'security.identity_revoked', outcome: 'denied', ...(rec ? { target: deviceTarget(rec.deviceId) } : {}),
      details: { recorded: rec !== null } });
  }
  if (!rec) {
    ignored(ctx, 'no_record');
    return;
  }
  const n = await trx('apple_devices').where({ tenant_id: tenantId, device_id: rec.deviceId, cert_sha256: event.payload.cert_sha256 })
    .whereNot('identity_state', 'revoked').update({ identity_state: 'revoked', updated_at: new Date() });
  if (!Number(n)) return;
  await deviceEvents.add(trx, tenantId, rec.deviceId, 'identity_revoked', event.occurredAt, event.eventId);
  ctx.afterCommit(() => realtime.deviceChanged(tenantId, rec.deviceId));
}

async function handleIdentityMismatch(ctx: Ctx<'security.identity_mismatch'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  // Once per event: the same alert as the lifecycle's (a contradicted serial number, its params the field only), and
  // the journal's entry; an event applied again raises nothing (a read alert stays read).
  if (await firstTimeFor(trx, event.eventId, 'audit')) {
    await raiseInTx(trx, tenantId, 'security.identity_mismatch', { params: { field: p.field } });
    ctx.audit({ tenantId, action: 'security.identity_mismatch', outcome: 'denied', details: { field: p.field, stage: 'apple-edge' } });
  }
  // The session of the refused enrollment: apple-edge names it in no field today (session_ref, read when it comes).
  // A reference that is not a UUID designates no session (compared as a uuid, it would fail the event and take the
  // alert and the journal's entry above with its savepoint).
  const ref = p.session_ref && UUID_RE.test(p.session_ref) ? p.session_ref.toLowerCase() : null;
  if (!ref) return;
  const n = await trx('enrollment_sessions').where({ tenant_id: tenantId, id: ref }).whereNotIn('state', ['enrolled', 'failed'])
    .update({ state: 'failed', failure_code: 'identity_mismatch', state_at: event.occurredAt, updated_at: new Date() });
  if (Number(n)) ctx.afterCommit(() => realtime.sessionChanged(tenantId, ref));
}

async function handleDeviceIdConflict(ctx: Ctx<'security.device_id_conflict'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  // The record, when the event names its enrollment (the conflicts within a tenant do; the serial number of the payload
  // is device data and designates nothing).
  const sat = event.enrollmentId
    ? await trx('apple_devices').where({ tenant_id: tenantId, enrollment_id: event.enrollmentId }).first('device_id') as { device_id: number } | undefined
    : undefined;
  if (p.outcome === REENROLL_REFUSED && sat) {
    // A re-enrollment without proof of a record under management, refused by apple-edge (decision of the owners of
    // 19/10/2026 on AE-C0-R2bis): the alert of the record proposes « Allow the re-enrollment ».
    await raiseInTx(trx, tenantId, 'enrollment.reenroll_refused', { discriminant: Number(sat.device_id), navigateTo: `/devices/${sat.device_id}` });
  } else {
    // Never the other tenant (S-11): its outcome for this tenant only.
    await raiseForEvent(ctx, tenantId, 'security.device_id_conflict', { params: { outcome: p.outcome } });
  }
  if (await firstTimeFor(trx, event.eventId, 'audit')) {
    ctx.audit({ tenantId, action: 'security.device_id_conflict', outcome: 'denied', ...(sat ? { target: deviceTarget(Number(sat.device_id)) } : {}),
      details: { idKind: p.id_kind, outcome: p.outcome } });
  }
  if (sat) await deviceEvents.add(trx, tenantId, Number(sat.device_id), 'id_conflict', event.occurredAt, event.eventId, { outcome: p.outcome });
}

/** The outcome apple-edge gives a re-enrollment without proof of an active identifier (AE-C0-R2bis). */
const REENROLL_REFUSED = 'refused_reenroll_without_proof';

// ── security.* (platform) ───────────────────────────────────────────────────────

async function handlePlatformDeviceIdConflict(ctx: Ctx<'security.device_id_conflict#platform'>): Promise<void> {
  const { trx, event } = ctx;
  const p = event.payload;
  const names = await tenantsByKey(trx, [p.tenants.holder, p.tenants.requester]);
  const holder = names.get(p.tenants.holder);
  const requester = names.get(p.tenants.requester);
  await inMaster(ctx, async () => {
    await raiseCountedInTx(trx, MASTER_TENANT_ID, 'platform.device_id_conflict', { at: event.occurredAt, eventId: event.eventId }, {
      params: { holder: holder?.name ?? p.tenants.holder, requester: requester?.name ?? p.tenants.requester, policy: p.policy },
    });
    if (await firstTimeFor(trx, event.eventId, 'audit')) {
      ctx.audit({ tenantId: MASTER_TENANT_ID, action: 'security.device_id_conflict', outcome: 'denied',
        details: { idKind: p.id_kind, outcome: p.outcome, policy: p.policy, holderTenantId: holder?.id ?? null, requesterTenantId: requester?.id ?? null } });
    }
  });
}

async function handleForeignCertificate(ctx: Ctx<'security.foreign_certificate'>): Promise<void> {
  const { trx, event } = ctx;
  const p = event.payload;
  const names = await tenantsByKey(trx, [p.url_tenant, p.issuer_tenant ?? '']);
  const url = names.get(p.url_tenant);
  const issuer = p.issuer_tenant ? names.get(p.issuer_tenant) : undefined;
  await inMaster(ctx, async () => {
    await raiseCountedInTx(trx, MASTER_TENANT_ID, 'platform.foreign_certificate', { at: event.occurredAt, eventId: event.eventId }, {
      params: { urlTenant: url?.name ?? p.url_tenant, issuerTenant: issuer?.name ?? p.issuer_tenant ?? '?' },
    });
    if (await firstTimeFor(trx, event.eventId, 'audit')) {
      ctx.audit({ tenantId: MASTER_TENANT_ID, action: 'security.foreign_certificate', outcome: 'denied',
        details: { urlTenantId: url?.id ?? null, issuerTenantId: issuer?.id ?? null } });
    }
  });
}

// ── device.* ────────────────────────────────────────────────────────────────────

async function handleIdReleased(ctx: Ctx<'device.id_released'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  const enrollmentId = event.enrollmentId ?? '';
  if (!enrollmentId || enrollmentId.includes(':')) {
    ignored(ctx, 'no_enrollment');
    return;
  }
  const r = await onUnenrolled(trx, tenantId, enrollmentId, p.reason, event.occurredAt, event.eventId);
  if (r.outcome === 'unknown') {
    ignored(ctx, 'no_record');
    return;
  }
  if (r.outcome === 'stale') return;
  const deviceId = r.deviceId as number;
  if (r.outcome === 'already') {
    // The record left before: a departure without release (wiped, removed by command, disabled at apple-edge)
    // releases its identifier now (DM26); the release of a departure recorded by another event of the same
    // departure (mdm.checkout) is recorded once; any other departure changes nothing.
    const released = await releaseIdentifier(trx, tenantId, enrollmentId, p.reason, event.occurredAt);
    if (!released) {
      const sat = await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).first('id_release_reason') as
        { id_release_reason: string | null } | undefined;
      if (sat?.id_release_reason !== p.reason || await deviceEvents.inCurrentCycle(trx, tenantId, deviceId, 'released')) return;
    }
  }
  if (!(await deviceEvents.add(trx, tenantId, deviceId, 'released', event.occurredAt, event.eventId, { reason: p.reason }))) return;
  const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).first('unenrolled_at') as { unenrolled_at: Date | null } | undefined;
  await sendUnenrollCleanup(trx, tenantId, deviceId, d?.unenrolled_at ? new Date(d.unenrolled_at) : null);
  ctx.audit({ tenantId, action: 'device.id_released', target: deviceTarget(deviceId), details: { reason: p.reason, idKind: p.id_kind } });
  if (p.reason === 'superseded_by_proof' || p.reason === 'superseded') {
    await raiseInTx(trx, tenantId, 'device.superseded', { discriminant: deviceId, navigateTo: `/devices/${deviceId}` });
  } else if (p.reason === 'apns_inactive') {
    // Aggregated per day (§12.1): the devices released for inactivity that day, counted from the records.
    const day = event.occurredAt.toISOString().slice(0, 10);
    const from = new Date(`${day}T00:00:00.000Z`);
    const c = await trx('apple_devices').where({ tenant_id: tenantId, id_release_reason: 'apns_inactive' })
      .where('id_released_at', '>=', from).where('id_released_at', '<', new Date(from.getTime() + 86_400_000))
      .count('* as n').first() as { n: string | number } | undefined;
    await raiseInTx(trx, tenantId, 'devices.apns_inactive_released', { discriminant: day, params: { count: Number(c?.n ?? 1) } });
  }
  ctx.afterCommit(() => realtime.deviceChanged(tenantId, deviceId));
}

async function handleTransferCompleted(ctx: Ctx<'device.transfer_completed'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  // 'out': the release follows (device.id_released, transfer); 'in': the Authenticate follows. The record of the
  // enrollment, when the brain has one (the source device), gets the timeline entry, which marks the event done.
  const sat = event.enrollmentId
    ? await trx('apple_devices').where({ tenant_id: tenantId, enrollment_id: event.enrollmentId }).first('device_id') as { device_id: number } | undefined
    : undefined;
  const deviceId = sat ? Number(sat.device_id) : null;
  const first = deviceId !== null
    ? await deviceEvents.add(trx, tenantId, deviceId, 'transferred', event.occurredAt, event.eventId, { direction: p.direction })
    : await firstTimeFor(trx, event.eventId, 'audit');
  if (!first) return;
  ctx.audit({ tenantId, action: 'device.transfer_completed', ...(deviceId !== null ? { target: deviceTarget(deviceId) } : {}),
    details: { direction: p.direction, approvalRef: p.approval_ref } });
  if (deviceId !== null) ctx.afterCommit(() => realtime.deviceChanged(tenantId, deviceId));
}

async function handlePlatformTransferCompleted(ctx: Ctx<'device.transfer_completed#platform'>): Promise<void> {
  const { trx, event } = ctx;
  const p = event.payload;
  const names = await tenantsByKey(trx, [p.from, p.to]);
  await inMaster(ctx, async () => {
    if (!(await firstTimeFor(trx, event.eventId, 'audit'))) return;
    ctx.audit({ tenantId: MASTER_TENANT_ID, action: 'device.transfer_completed',
      details: { direction: 'platform', approvalRef: p.approval_ref, fromTenantId: names.get(p.from)?.id ?? null, toTenantId: names.get(p.to)?.id ?? null } });
  });
}

let registered = false;

export function registerSecurityHandlers(): void {
  if (registered) return;
  registered = true;
  const t = (type: keyof typeof P, handle: (ctx: any) => Promise<void>) => registerOutboxHandler({
    type, scope: 'tenant', module: 'apple', payload: P[type], handle,
  });
  const platform = (type: string, schema: keyof typeof P, handle: (ctx: any) => Promise<void>) => registerOutboxHandler({
    type, scope: 'platform', module: 'apple', payload: P[schema], handle,
  });
  t('security.topic_mismatch', handleTopicMismatch);
  t('security.identity_expired', handleIdentityExpired);
  t('security.identity_revoked', handleIdentityRevoked);
  t('security.identity_mismatch', handleIdentityMismatch);
  t('security.device_id_conflict', handleDeviceIdConflict);
  platform('security.device_id_conflict', 'security.device_id_conflict#platform', handlePlatformDeviceIdConflict);
  platform('security.foreign_certificate', 'security.foreign_certificate', handleForeignCertificate);
  t('device.id_released', handleIdReleased);
  t('device.transfer_completed', handleTransferCompleted);
  platform('device.transfer_completed', 'device.transfer_completed#platform', handlePlatformTransferCompleted);
}
