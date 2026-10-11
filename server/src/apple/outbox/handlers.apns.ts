import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import { registerOutboxHandler, type OutboxHandlerContext } from '../../jobs';
import { raiseCountedInTx, raiseInTx, resolveInTx } from '../alerts/service';
import { deviceEvents } from '../devices/events';
import { recordDeadline } from '../integrations/deadlines';
import { appleMetrics } from '../metrics';
import { realtime } from '../realtime';
import { upsertMirror } from '../tenants/registry';
import { firstTimeFor } from './once';
import { P, type PayloadOf } from './schemas';

// =============================================================================
// Handlers of the push (APNs) events of apple-edge (docs: integration-apple-
// edge §7.4, §11.1, §11.4, §12.1; rules G-1 to G-9 of §7.2):
//   apns.push_failed             BadDeviceToken: push 'invalid_token'; a topic
//                                refused: push 'topic_error' and apns.topic_config;
//                                403 with the circuit open: apns.circuit_open and
//                                the audit apns.push_refused
//   apns.token_inactive          push 'inactive' (410 Unregistered)
//   apns.throttled               counter, apns.throttled (counted)
//   apns.certificate_expiring    the apns_certificate deadline (the échéancier
//                                alerts at its thresholds, lot C3)
//   apns.certificate_activated   the row of tenant_apple_push 'active' (by
//                                certificate, else the request of its topic),
//                                the previous one superseded (legacy for a change
//                                of topic); enrollment configuration invalidated;
//                                push alerts resolved; deadline; audit
//   apns.certificate_expired     the active row 'expired'; apns.certificate_expired
// The device's push state is monotone by push_state_at (onTokenUpdate sets
// 'ready' at a newer token). No device record: the device effects are skipped
// (« Sans fiche » : ignore), the tenant's alerts stand.
// =============================================================================

type Ctx<K extends keyof typeof P> = OutboxHandlerContext<PayloadOf<K>>;

/** APNs reasons of a topic problem (§7.4): the tenant's push configuration. */
const TOPIC_REASONS = new Set(['DeviceTokenNotForTopic', 'TopicDisallowed', 'BadTopic']);

function ignored(ctx: OutboxHandlerContext<unknown>, why: string): void {
  appleMetrics.eventIgnored(ctx.event.type);
  ctx.log.debug({ why }, 'outbox event without effect');
}

/** The record of the event's enrollment (its device channel), or null. */
async function recordOf(trx: Knex.Transaction, tenantId: number, enrollmentId: string | null): Promise<number | null> {
  if (!enrollmentId || enrollmentId.includes(':')) return null;
  const sat = await trx('apple_devices').where({ tenant_id: tenantId, enrollment_id: enrollmentId }).first('device_id') as
    { device_id: number } | undefined;
  return sat ? Number(sat.device_id) : null;
}

/** The push state of a record, when the event is newer than the state it holds (a device out of management stays
 *  'disabled'). True when changed. */
async function setPushState(trx: Knex.Transaction, tenantId: number, deviceId: number, state: string, at: Date): Promise<boolean> {
  const n = await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId })
    .whereNot('push_state', 'disabled')
    .andWhere((q) => q.whereNull('push_state_at').orWhere('push_state_at', '<', at))
    .update({ push_state: state, push_state_at: at, updated_at: new Date() });
  return Number(n) > 0;
}

async function handlePushFailed(ctx: Ctx<'apns.push_failed'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  const reason = (p.reason ?? '').slice(0, 64);
  if (p.circuit_open) {
    // Apple refuses the tenant's pushes (403): the circuit of apple-edge is open for the topic.
    await raiseCountedInTx(trx, tenantId, 'apns.circuit_open', { at: event.occurredAt, eventId: event.eventId },
      { params: { httpStatus: p.http_status } });
    if (p.http_status === 403 && await firstTimeFor(trx, event.eventId, 'audit')) {
      ctx.audit({ tenantId, action: 'apns.push_refused', outcome: 'failure', details: { httpStatus: p.http_status, reason } });
    }
    ctx.afterCommit(() => realtime.integrationChanged(tenantId, 'push'));
  }
  if (TOPIC_REASONS.has(reason)) {
    await raiseCountedInTx(trx, tenantId, 'apns.topic_config', { at: event.occurredAt, eventId: event.eventId }, { params: { reason } });
  }
  const deviceId = await recordOf(trx, tenantId, event.enrollmentId);
  if (deviceId === null) {
    ignored(ctx, 'no_record');
    return;
  }
  // BadDeviceToken: the device's token; a topic refused: the device's channel; any other failure: the timeline only.
  const state = reason === 'BadDeviceToken' ? 'invalid_token' : TOPIC_REASONS.has(reason) ? 'topic_error' : null;
  const changed = state !== null && await setPushState(trx, tenantId, deviceId, state, event.occurredAt);
  await deviceEvents.add(trx, tenantId, deviceId, 'push_failed', event.occurredAt, event.eventId, { httpStatus: p.http_status, reason });
  if (changed) ctx.afterCommit(() => realtime.deviceChanged(tenantId, deviceId));
}

async function handleTokenInactive(ctx: Ctx<'apns.token_inactive'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const deviceId = await recordOf(trx, tenantId, event.enrollmentId);
  if (deviceId === null) {
    ignored(ctx, 'no_record');
    return;
  }
  const changed = await setPushState(trx, tenantId, deviceId, 'inactive', event.occurredAt);
  await deviceEvents.add(trx, tenantId, deviceId, 'push_inactive', event.occurredAt, event.eventId,
    { reason: (event.payload.reason ?? 'Unregistered').slice(0, 64) });
  if (changed) ctx.afterCommit(() => realtime.deviceChanged(tenantId, deviceId));
}

async function handleThrottled(ctx: Ctx<'apns.throttled'>): Promise<void> {
  const tenantId = ctx.tenantId as number;
  const p = ctx.event.payload;
  const r = await raiseCountedInTx(ctx.trx, tenantId, 'apns.throttled', { at: ctx.event.occurredAt, eventId: ctx.event.eventId, increment: p.count });
  if (r.counted) appleMetrics.apnsThrottled(p.count);
}

async function handleCertificateExpiring(ctx: Ctx<'apns.certificate_expiring'>): Promise<void> {
  const tenantId = ctx.tenantId as number;
  const p = ctx.event.payload;
  await recordDeadline(ctx.trx, tenantId, { kind: 'apns_certificate', subjectRef: p.topic, label: p.topic, notAfter: new Date(p.not_after) });
  ctx.afterCommit(() => realtime.integrationChanged(tenantId, 'deadlines'));
}

interface PushRow {
  id: string;
  state: string;
  state_at: Date;
  topic: string | null;
  cert_sha256: string | null;
}

/** States of a request still waiting for its certificate. */
const OPEN_REQUEST = ['vendor_signature_pending', 'apple_upload_pending'];

async function handleCertificateActivated(ctx: Ctx<'apns.certificate_activated'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  const at = event.occurredAt;
  const rows = await trx('tenant_apple_push').where({ tenant_id: tenantId }).forUpdate()
    .select('id', 'state', 'state_at', 'topic', 'cert_sha256') as PushRow[];
  const sha = p.cert_sha256 ?? null;
  // The row of this certificate (imported by the console), else the open request of its topic, else any open request.
  const target = (sha ? rows.find((r) => r.cert_sha256 === sha) : undefined)
    ?? rows.find((r) => OPEN_REQUEST.includes(r.state) && r.topic === p.topic)
    ?? rows.find((r) => OPEN_REQUEST.includes(r.state));
  const current = rows.find((r) => r.state === 'active');
  if (target && target === current) return;                          // already active (a replay)
  // Monotony (occurred_at): the row already reflects this event or a newer one (expired since, superseded…).
  if (target && new Date(target.state_at).getTime() >= at.getTime()) return;
  if (current && new Date(current.state_at).getTime() > at.getTime()) {
    // A newer certificate is active: this activation is older (consumed late), superseded since.
    if (target && OPEN_REQUEST.includes(target.state)) {
      await trx('tenant_apple_push').where({ tenant_id: tenantId, id: target.id })
        .update({ state: 'superseded', state_at: at, topic: p.topic, cert_sha256: sha, not_after: new Date(p.not_after), closed_at: at, updated_at: new Date() });
    }
    return;
  }
  if (current) {
    // A renewal at the same topic supersedes; a change of topic keeps the previous certificate for the devices
    // enrolled under it (legacy).
    await trx('tenant_apple_push').where({ tenant_id: tenantId, id: current.id })
      .update({ state: current.topic && current.topic !== p.topic ? 'legacy' : 'superseded', state_at: at, closed_at: at, updated_at: new Date() });
  }
  const cols = { state: 'active', state_at: at, activated_at: at, topic: p.topic, cert_sha256: sha, not_after: new Date(p.not_after), updated_at: new Date() };
  if (target) {
    await trx('tenant_apple_push').where({ tenant_id: tenantId, id: target.id }).update(cols);
  } else {
    // Activated without a request of the console (an import of the laboratory, a restore): mirrored as an import.
    await trx('tenant_apple_push').insert({ id: randomUUID(), tenant_id: tenantId, purpose: 'import', ...cols });
  }
  await upsertMirror(trx, tenantId, { enrollment_config: null });    // the enrollment configuration names the topic
  for (const kind of ['apns.no_certificate', 'apns.circuit_open', 'apns.certificate_expired', 'apns.topic_config'] as const) {
    await resolveInTx(trx, tenantId, kind);
  }
  await recordDeadline(trx, tenantId, { kind: 'apns_certificate', subjectRef: p.topic, label: p.topic, notAfter: new Date(p.not_after) });
  ctx.audit({ tenantId, action: 'integration.push_certificate_activated', target: { type: 'tenant', id: String(tenantId) },
    details: { topic: p.topic, notAfter: new Date(p.not_after).toISOString(), renewal: current?.topic === p.topic } });
  ctx.afterCommit(() => realtime.integrationChanged(tenantId, 'push', 'deadlines'));
}

async function handleCertificateExpired(ctx: Ctx<'apns.certificate_expired'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  const rows = await trx('tenant_apple_push').where({ tenant_id: tenantId, topic: p.topic }).whereIn('state', ['active', 'legacy'])
    .forUpdate().select('id', 'state', 'state_at', 'not_after') as Array<PushRow & { not_after: Date | null }>;
  const notAfter = new Date(p.not_after).getTime();
  const row = rows.find((r) => r.not_after && new Date(r.not_after).getTime() === notAfter) ?? rows.find((r) => r.state === 'active');
  if (!row || new Date(row.state_at).getTime() > event.occurredAt.getTime()) {
    ignored(ctx, 'no_certificate_row');
    return;
  }
  await trx('tenant_apple_push').where({ tenant_id: tenantId, id: row.id })
    .update({ state: 'expired', state_at: event.occurredAt, closed_at: event.occurredAt, updated_at: new Date() });
  await upsertMirror(trx, tenantId, { enrollment_config: null });
  // The active certificate expired: pushes are disabled until a renewal (critical); a legacy one (a previous
  // topic) only ends the reach of the devices still enrolled under it.
  if (row.state === 'active') await raiseInTx(trx, tenantId, 'apns.certificate_expired', { params: { topic: p.topic } });
  ctx.afterCommit(() => realtime.integrationChanged(tenantId, 'push', 'deadlines'));
}

let registered = false;

export function registerApnsHandlers(): void {
  if (registered) return;
  registered = true;
  const t = (type: keyof typeof P, handle: (ctx: any) => Promise<void>) => registerOutboxHandler({
    type, scope: 'tenant', module: 'apple', payload: P[type], handle,
  });
  t('apns.push_failed', handlePushFailed);
  t('apns.token_inactive', handleTokenInactive);
  t('apns.throttled', handleThrottled);
  t('apns.certificate_expiring', handleCertificateExpiring);
  t('apns.certificate_activated', handleCertificateActivated);
  t('apns.certificate_expired', handleCertificateExpired);
}
