import type { Knex } from 'knex';
import { registerOutboxHandler, type OutboxHandlerContext } from '../../jobs';
import { raiseCountedInTx, raiseInTx, resolveInTx } from '../alerts/service';
import { privacyRulesFor } from '../devices/privacy';
import { recordDeadline } from '../integrations/deadlines';
import { appleMetrics } from '../metrics';
import { realtime } from '../realtime';
import { P, type PayloadOf } from './schemas';

// =============================================================================
// Handlers of the Apple Business (ADE) events of apple-edge (docs: integration-
// apple-edge §7.4, §11.2, §10.7, §12.1; rules G-1 to G-9 of §7.2). The ADE
// servers are mirrored in tenant_apple_ade_tokens (rows created by the console
// with the token at apple-edge, lot C3): an event of a server the brain does
// not mirror changes nothing (counted). The mirror is monotone by state_at:
//   ade.token_activated     mirror 'active' (name, UUID, expiry), errors reset;
//                           ade_token deadline; ADE alerts resolved; audit
//   ade.devices             apple_ade_devices in one statement (the latest
//                           op_date wins; 'deleted' → removed_at); hardware
//                           identifiers kept per the privacy rules; the mirror's
//                           last synchronisation; a server in error or with terms
//                           to accept is back to 'active' (apple-edge says it
//                           with no event)
//   ade.profile_assignment  profile_status of the serials assigned; failures:
//                           ade.assignment_failed (counted)
//   ade.sync_error          mirror (code, consecutive errors; 'error' for a token
//                           refused); ade.token_error (critical when unauthorized)
//   ade.terms_not_signed    mirror 'terms_not_signed'; alert (critical)
//   ade.token_expiring      ade_token deadline; token_expired: mirror 'expired',
//                           ade.token_expired (critical)
// Serial numbers of Apple Business are the inventory of the client's
// organisation (Apple's data, not the device's word): kept in
// apple_ade_devices, never in a log, an alert nor a job payload.
// =============================================================================

type Ctx<K extends keyof typeof P> = OutboxHandlerContext<PayloadOf<K>>;

interface Mirror {
  id: string;
  label: string;
  state: string;
  state_at: Date;
  server_name: string | null;
  consecutive_errors: number;
  last_error_code: string | null;
  last_sync_at: Date | null;
  last_fetch_at: Date | null;
}

function ignored(ctx: OutboxHandlerContext<unknown>, why: string): void {
  appleMetrics.eventIgnored(ctx.event.type);
  ctx.log.debug({ why }, 'outbox event without effect');
}

/** The mirror of the ADE server of the event (locked: the events of one server are serialised), or null. */
async function mirrorOf(trx: Knex.Transaction, tenantId: number, tokenId: string): Promise<Mirror | null> {
  const r = await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id: tokenId }).whereNot('state', 'removed').forUpdate()
    .first('id', 'label', 'state', 'state_at', 'server_name', 'consecutive_errors', 'last_error_code', 'last_sync_at', 'last_fetch_at') as Mirror | undefined;
  return r ?? null;
}

const serverNameOf = (m: Mirror): string => (m.server_name || m.label || 'ADE').slice(0, 200);
const newer = (m: Mirror, at: Date): boolean => !m.state_at || new Date(m.state_at).getTime() < at.getTime();
/** A page of devices of the server (a synchronisation that succeeded) later than `at`: an error of `at` consumed
 *  after it is past (events of one server out of order: a retry), and neither blocks the mirror nor alerts. */
const succeededSince = (m: Mirror, at: Date): boolean => [m.last_sync_at, m.last_fetch_at]
  .some((v) => v !== null && v !== undefined && new Date(v).getTime() > at.getTime());

async function handleTokenActivated(ctx: Ctx<'ade.token_activated'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  const m = await mirrorOf(trx, tenantId, p.token_id);
  if (!m) {
    ignored(ctx, 'unknown_ade_server');
    return;
  }
  if (!newer(m, event.occurredAt)) return;                         // an older event consumed late, or a replay
  const notAfter = p.not_after ? new Date(p.not_after) : null;
  await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id: m.id }).update({
    state: 'active', state_at: event.occurredAt, server_name: p.server_name ?? m.server_name, server_uuid: p.server_uuid ?? null,
    not_after: notAfter, consecutive_errors: 0, last_error_code: null, updated_at: new Date(),
  });
  const serverName = (p.server_name || m.label || 'ADE').slice(0, 200);
  if (notAfter) await recordDeadline(trx, tenantId, { kind: 'ade_token', subjectRef: m.id, label: serverName, notAfter });
  for (const kind of ['ade.token_error', 'ade.terms_not_signed', 'ade.token_expired'] as const) await resolveInTx(trx, tenantId, kind, m.id);
  ctx.audit({ tenantId, action: 'integration.ade_token_activated', target: { type: 'ade_token', id: m.id }, details: { renewed: m.state !== 'awaiting_token' } });
  ctx.afterCommit(() => realtime.integrationChanged(tenantId, 'ade', 'deadlines'));
}

/** The hardware identifiers of a device of Apple Business, when the privacy rules keep them. */
function hardwareIds(d: PayloadOf<'ade.devices'>['devices'][number], keep: boolean): Record<string, unknown> {
  if (!keep) return {};
  const out: Record<string, unknown> = {};
  const list = (v: string[] | undefined) => (v ?? []).filter((x) => typeof x === 'string' && x.length <= 64).slice(0, 4);
  if (d.imei?.length) out.imei = list(d.imei);
  if (d.meid?.length) out.meid = list(d.meid);
  if (d.eid && d.eid.length <= 64) out.eid = d.eid;
  if (d.wifi_mac_address && d.wifi_mac_address.length <= 32) out.wifiMac = d.wifi_mac_address;
  if (d.bluetooth_mac_address && d.bluetooth_mac_address.length <= 32) out.bluetoothMac = d.bluetooth_mac_address;
  if (d.ethernet_mac_address && d.ethernet_mac_address.length <= 32) out.ethernetMac = d.ethernet_mac_address;
  return out;
}

const time = (v: string | undefined): number => (v ? Date.parse(v) : Number.NEGATIVE_INFINITY);

async function handleDevices(ctx: Ctx<'ade.devices'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  const m = await mirrorOf(trx, tenantId, p.token_id);
  if (!m) {
    ignored(ctx, 'unknown_ade_server');
    return;
  }
  // The ownership of a device of Apple Business is known at its enrollment only (its profile): the strictest one
  // ADE allows (company-owned, personally enabled) decides what is kept before (§10.7, T-6).
  const rules = await privacyRulesFor(trx, tenantId, 'corporate_personal', 'Device');
  // One row per serial number in the statement (ON CONFLICT cannot touch a row twice): the latest operation.
  const bySerial = new Map<string, PayloadOf<'ade.devices'>['devices'][number]>();
  for (const d of p.devices) {
    const serial = d.serial_number.trim().toUpperCase();
    if (!/^[A-Z0-9]{4,64}$/.test(serial)) continue;
    const prev = bySerial.get(serial);
    if (!prev || time(d.op_date) >= time(prev.op_date)) bySerial.set(serial, d);
  }
  const rows = [...bySerial.entries()].map(([serial, d]) => ({
    serial_number: serial, model: d.model ?? null, description: d.description ?? null, color: d.color ?? null,
    device_family: d.device_family ?? null, os: d.os ?? null, profile_status: d.profile_status ?? null, profile_uuid: d.profile_uuid ?? null,
    profile_assign_time: d.profile_assign_time ?? null, device_assigned_date: d.device_assigned_date ?? null,
    op_type: d.op_type ? d.op_type.toLowerCase() : null, op_date: d.op_date ?? null, mdm_migration_deadline: d.mdm_migration_deadline ?? null,
    hardware_ids: hardwareIds(d, rules.storeHardwareIds),
  }));
  if (rows.length > 0) {
    // One statement (§7.4): the latest operation of Apple wins (op_date); an operation without date applies.
    await trx.raw(`
      INSERT INTO obligarth.apple_ade_devices AS a
        (tenant_id, ade_token_id, serial_number, model, description, color, device_family, os, profile_status, profile_uuid,
         profile_assign_time, device_assigned_date, op_type, op_date, mdm_migration_deadline, hardware_ids, removed_at, updated_at)
      SELECT ?, ?::uuid, r.serial_number, left(r.model, 100), left(r.description, 200), left(r.color, 50), left(r.device_family, 32),
             left(r.os, 32), left(r.profile_status, 16), left(r.profile_uuid, 64), r.profile_assign_time, r.device_assigned_date,
             left(r.op_type, 16), r.op_date, r.mdm_migration_deadline, COALESCE(r.hardware_ids, '{}'::jsonb),
             CASE WHEN r.op_type = 'deleted' THEN COALESCE(r.op_date, ?::timestamptz) END, now()
        FROM jsonb_to_recordset(?::jsonb) AS r(serial_number text, model text, description text, color text, device_family text,
             os text, profile_status text, profile_uuid text, profile_assign_time timestamptz, device_assigned_date timestamptz,
             op_type text, op_date timestamptz, mdm_migration_deadline timestamptz, hardware_ids jsonb)
      ON CONFLICT (tenant_id, serial_number) DO UPDATE SET
        ade_token_id = EXCLUDED.ade_token_id,
        model = COALESCE(EXCLUDED.model, a.model), description = COALESCE(EXCLUDED.description, a.description),
        color = COALESCE(EXCLUDED.color, a.color), device_family = COALESCE(EXCLUDED.device_family, a.device_family),
        os = COALESCE(EXCLUDED.os, a.os), profile_status = COALESCE(EXCLUDED.profile_status, a.profile_status),
        profile_uuid = COALESCE(EXCLUDED.profile_uuid, a.profile_uuid),
        profile_assign_time = COALESCE(EXCLUDED.profile_assign_time, a.profile_assign_time),
        device_assigned_date = COALESCE(EXCLUDED.device_assigned_date, a.device_assigned_date),
        op_type = EXCLUDED.op_type, op_date = COALESCE(EXCLUDED.op_date, a.op_date),
        mdm_migration_deadline = COALESCE(EXCLUDED.mdm_migration_deadline, a.mdm_migration_deadline),
        hardware_ids = EXCLUDED.hardware_ids, removed_at = EXCLUDED.removed_at, updated_at = now()
       WHERE a.op_date IS NULL OR EXCLUDED.op_date IS NULL OR EXCLUDED.op_date >= a.op_date`,
    [tenantId, m.id, event.occurredAt, JSON.stringify(rows)]);
  }
  // The mirror's last synchronisation; apple-edge is back to 'active' after errors or the terms, without an event.
  const last = p.phase === 'fetch'
    ? { last_fetch_at: trx.raw('GREATEST(last_fetch_at, ?::timestamptz)', [event.occurredAt]) }
    : { last_sync_at: trx.raw('GREATEST(last_sync_at, ?::timestamptz)', [event.occurredAt]) };
  await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id: m.id }).update({ ...last, updated_at: new Date() });
  // A page of devices is a synchronisation that succeeded: newer than the mirror's last error, it ends it. A server
  // blocked (terms to accept, token refused) is active again; one that stayed active through passing errors (its
  // alert ade.token_error raised at the third in a row) loses its error count: the alerts of the server are resolved
  // in both cases (§12.1: « synchronisation réussie »). An older page consumed late changes nothing.
  const blocked = m.state === 'terms_not_signed' || m.state === 'error';
  const inError = m.state === 'active' && (Number(m.consecutive_errors) > 0 || m.last_error_code !== null);
  if ((blocked || inError) && newer(m, event.occurredAt)) {
    await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id: m.id })
      .update({ state: 'active', state_at: event.occurredAt, consecutive_errors: 0, last_error_code: null, updated_at: new Date() });
    await resolveInTx(trx, tenantId, 'ade.terms_not_signed', m.id);
    await resolveInTx(trx, tenantId, 'ade.token_error', m.id);
    ctx.afterCommit(() => realtime.integrationChanged(tenantId, 'ade'));
  }
}

async function handleProfileAssignment(ctx: Ctx<'ade.profile_assignment'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  const m = await mirrorOf(trx, tenantId, p.token_id);
  if (!m) {
    ignored(ctx, 'unknown_ade_server');
    return;
  }
  const assigned: string[] = [];
  let failed = 0;
  for (const [serial, status] of Object.entries(p.results)) {
    const s = serial.trim().toUpperCase();
    if (!/^[A-Z0-9]{4,64}$/.test(s)) continue;
    if (status === 'SUCCESS') assigned.push(s);
    else failed += 1;
  }
  if (assigned.length > 0) {
    // The latest result wins (§7.4): an assignment consumed after a later one (or after the synchronisation that
    // reports a later assignment of Apple) changes nothing; the same event applied again writes the same values.
    await trx('apple_ade_devices').where({ tenant_id: tenantId, ade_token_id: m.id }).whereIn('serial_number', assigned)
      .andWhere((q) => q.whereNull('profile_assign_time').orWhere('profile_assign_time', '<=', event.occurredAt))
      .update({ profile_status: 'assigned', profile_uuid: p.profile_uuid.slice(0, 64), profile_assign_time: event.occurredAt, updated_at: new Date() });
  }
  if (failed > 0) {
    await raiseCountedInTx(trx, tenantId, 'ade.assignment_failed', { at: event.occurredAt, eventId: event.eventId, increment: failed },
      { discriminant: m.id });
  }
}

/** Codes of a token Apple refuses (apple-edge sets its token in error): the mirror too. */
const REFUSED = new Set(['unauthorized', 'access_denied']);

async function handleSyncError(ctx: Ctx<'ade.sync_error'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  const m = await mirrorOf(trx, tenantId, p.token_id);
  if (!m) {
    ignored(ctx, 'unknown_ade_server');
    return;
  }
  if (!newer(m, event.occurredAt) || succeededSince(m, event.occurredAt)) return;
  await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id: m.id }).update({
    ...(REFUSED.has(p.code) ? { state: 'error' } : {}), state_at: event.occurredAt, last_error_code: p.code,
    consecutive_errors: trx.raw('consecutive_errors + 1'), updated_at: new Date(),
  });
  await raiseInTx(trx, tenantId, 'ade.token_error', {
    discriminant: m.id, params: { serverName: serverNameOf(m), code: p.code }, severity: p.code === 'unauthorized' ? 'critical' : undefined,
  });
  ctx.afterCommit(() => realtime.integrationChanged(tenantId, 'ade'));
}

async function handleTermsNotSigned(ctx: Ctx<'ade.terms_not_signed'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const m = await mirrorOf(trx, tenantId, event.payload.token_id);
  if (!m) {
    ignored(ctx, 'unknown_ade_server');
    return;
  }
  if (!newer(m, event.occurredAt) || succeededSince(m, event.occurredAt)) return;
  await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id: m.id })
    .update({ state: 'terms_not_signed', state_at: event.occurredAt, last_error_code: event.payload.code, updated_at: new Date() });
  await raiseInTx(trx, tenantId, 'ade.terms_not_signed', { discriminant: m.id, params: { serverName: serverNameOf(m) } });
  ctx.afterCommit(() => realtime.integrationChanged(tenantId, 'ade'));
}

async function handleTokenExpiring(ctx: Ctx<'ade.token_expiring'>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  const m = await mirrorOf(trx, tenantId, p.token_id);
  if (!m) {
    ignored(ctx, 'unknown_ade_server');
    return;
  }
  await recordDeadline(trx, tenantId, { kind: 'ade_token', subjectRef: m.id, label: serverNameOf(m), notAfter: new Date(p.not_after) });
  if (p.code === 'token_expired' && newer(m, event.occurredAt)) {
    await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id: m.id })
      .update({ state: 'expired', state_at: event.occurredAt, updated_at: new Date() });
    await raiseInTx(trx, tenantId, 'ade.token_expired', { discriminant: m.id, params: { serverName: serverNameOf(m) } });
  }
  ctx.afterCommit(() => realtime.integrationChanged(tenantId, 'ade', 'deadlines'));
}

let registered = false;

export function registerAdeHandlers(): void {
  if (registered) return;
  registered = true;
  const t = (type: keyof typeof P, handle: (ctx: any) => Promise<void>) => registerOutboxHandler({
    type, scope: 'tenant', module: 'apple', payload: P[type], handle,
  });
  t('ade.token_activated', handleTokenActivated);
  t('ade.devices', handleDevices);
  t('ade.profile_assignment', handleProfileAssignment);
  t('ade.sync_error', handleSyncError);
  t('ade.terms_not_signed', handleTermsNotSigned);
  t('ade.token_expiring', handleTokenExpiring);
}
