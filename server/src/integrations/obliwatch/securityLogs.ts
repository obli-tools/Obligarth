import type { Knex } from 'knex';
import { androidSenders } from '../../android/enrollment/senders';
import { logger } from '../../utils/logger';
import { obliwatchIntegrationEnabled } from './config';
import { touchSignalInTx } from './marker';
import { RULES, type RuleState } from './rules';
import { pushActiveInTx, recordSignalsInTx } from './signals';

// =============================================================================
// SEC-13 (brief GTH-08; lot L5): the AMAPI security logs as AGGREGATED detections D-MOB-SEC-*, never raw logs.
//   Collection   the compiled AMAPI policy (mdm/android/compile.ts, ctx.securityLogs) carries
//                usageLog {enabledLogTypes: [SECURITY_LOGS], uploadOnCellularAllowed: [SECURITY_LOGS]} only for a
//                company-owned fully managed device (ownership corporate, management mode fully_managed: Google
//                supports the security logs on fully managed devices; Policy.usageLog, UsageLog.LogType) of a tenant
//                with OBLIWATCH_INTEGRATION=on and the push consent (read in the database at each push, never a
//                cache). The device shows the user that logging is on (Google). The change of the push consent asks
//                the push of the policies of those devices (requestSecurityLogPoliciesInTx, in the consent's
//                transaction), so the logs follow the consent both ways.
//   Reception    Google sends them with the USAGE_LOGS notifications (UsageLogEvent, eventType and one event field),
//                handled by android/inventory/usageLogs.ts, which calls recordSecurityLogsInTx in its transaction:
//                each event is classified, COUNTED in a fixed window per device and rule (device_security_log_windows),
//                then forgotten. Nothing of an event is stored or sent (no certificate subject, no shell command, no
//                package nor uid): the counts, the windows, and the time the logs last arrived
//                (device_security_log_status: coverage securityLogs of the read API). The inbox never holds more either:
//                the batch is reduced before it is written (android/inbox/schemas.ts, reduceUsageLogs: the lost mode's
//                events whole, the events read here as type, time and one boolean, any other event as a count).
//   Rules        (UsageLogEvent types; one transition per device, rule and window at most, details.count and
//                details.windowMinutes; event rules, never cleared):
//                  D-MOB-SEC-USER-CA          CERT_AUTHORITY_INSTALLED with success      medium  window 60 min
//                  D-MOB-SEC-ADB              ADB_SHELL_COMMAND, ADB_SHELL_INTERACTIVE    medium  window 60 min
//                  D-MOB-SEC-UNLOCK-BURST     KEYGUARD_DISMISS_AUTH_ATTEMPT not success,  medium  5 failures within a
//                                             as a burst                                          window of 15 min
//                                                                                                 (or it and the one
//                                                                                                 before: 30 min)
//                  D-MOB-SEC-KEY-INTEGRITY    KEY_INTEGRITY_VIOLATION                     high    window 60 min
//                  D-MOB-SEC-LOGGING-STOPPED  LOGGING_STOPPED                             medium  window 60 min
//                The count sent is the count known when the detection is recorded (the first events of the window);
//                later events of the same window are counted, not sent again. Events older than 7 days are not
//                counted (their window would be purged already: no second detection of an old window).
//   Off          nothing is counted while the integration is off or without the push consent. The policies follow:
//                device_security_log_status.policy_logs_on marks a device whose policy was pushed with usageLog (set
//                in the push's transaction, before the policy can carry it; cleared once a policy without it was
//                delivered, android/policies/push.ts). The withdrawal of the push consent asks the push at once; the
//                sweep (staleSecurityLogPoliciesInTx) asks it again for any device still marked that should not carry
//                the logs: hourly while the integration is on (no push consent, device no longer company-owned fully
//                managed), and at start then every 15 minutes while the integration is OFF (every marked device), until
//                none is left (modules/obliwatch.ts). A device released or no longer enrolled loses its mark.
// Everything under a savepoint, every error swallowed and logged: the usage logs handler never fails because of it.
// =============================================================================

export type SecurityRuleId = 'D-MOB-SEC-USER-CA' | 'D-MOB-SEC-ADB' | 'D-MOB-SEC-UNLOCK-BURST' | 'D-MOB-SEC-KEY-INTEGRITY' | 'D-MOB-SEC-LOGGING-STOPPED';

/** Window of each rule (minutes). */
export const SECURITY_WINDOWS: Readonly<Record<SecurityRuleId, number>> = {
  'D-MOB-SEC-USER-CA': 60, 'D-MOB-SEC-ADB': 60, 'D-MOB-SEC-UNLOCK-BURST': 15, 'D-MOB-SEC-KEY-INTEGRITY': 60, 'D-MOB-SEC-LOGGING-STOPPED': 60,
};
/** Failed unlock attempts that make a burst (in a window of 15 minutes, or in it and the one before). */
export const UNLOCK_BURST_THRESHOLD = 5;
/** Logs older than this are not counted. */
const MAX_AGE_MS = 7 * 86_400_000;
/** The coverage securityLogs: logs received within this time. */
export const SECURITY_LOGS_FRESH_MS = 7 * 86_400_000;
const MAX_EVENTS = 5_000;

/** The lost mode events of the USAGE_LOGS notifications (usageLogs.ts): not security logs. */
const LOST_MODE_TYPES = new Set(['LOST_MODE_LOCATION', 'STOP_LOST_MODE_USER_ATTEMPT', 'LOST_MODE_OUTGOING_PHONE_CALL']);

/** A device whose security logs are collected: AMAPI, company-owned, fully managed. */
export function securityLogsEligible(d: { channel?: string | null; ownership: string | null; mode: string | null }): boolean {
  return (d.channel === undefined || d.channel === 'amapi') && d.ownership === 'corporate' && d.mode === 'fully_managed';
}

/** Does the policy of this device carry the security logs (the push of its policy, android/policies/push.ts)? The
 *  consent read in the database (never the 30-second cache: a push right after the change follows it). Never throws. */
export async function securityLogsWantedInTx(trx: Knex.Transaction, tenantId: number, d: { ownership: string; mode: string }): Promise<boolean> {
  if (!obliwatchIntegrationEnabled() || !securityLogsEligible(d)) return false;
  try {
    const row = await trx.transaction(async (sp) => sp('tenant_obliwatch_settings').where({ tenant_id: tenantId }).first('push_enabled')) as
      { push_enabled?: boolean } | undefined;
    return row?.push_enabled === true;
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) } }, 'obliwatch security logs: consent not read (logs left off)');
    return false;
  }
}

/** The push consent changed (consent.ts, in its transaction): the policies of the eligible devices pushed again (the
 *  usageLog follows the consent). The number of devices asked. */
export async function requestSecurityLogPoliciesInTx(trx: Knex.Transaction, tenantId: number): Promise<number> {
  const ids = await trx('devices as d')
    .join('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where({ 'd.tenant_id': tenantId, 'd.management_channel': 'amapi', 'd.ownership': 'corporate', 'd.management_mode': 'fully_managed', 'd.enrollment_state': 'enrolled' })
    .whereNull('a.released_at').orderBy('d.id').pluck('d.id') as Array<number | string>;
  for (const id of ids) await androidSenders.push(trx, { tenantId, deviceId: Number(id) });
  return ids.length;
}

// ── The policies that carry the security logs ─────────────────────────────────────────────────────────────

/** The policy of this device is about to carry usageLog (the push's transaction, before the policy is sent). */
export async function markSecurityLogPolicyInTx(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<void> {
  await trx('device_security_log_status').insert({ tenant_id: tenantId, device_id: deviceId, policy_logs_on: true, policy_marked_at: trx.fn.now() })
    .onConflict(['tenant_id', 'device_id']).merge({ policy_logs_on: true, policy_marked_at: trx.fn.now() });
}

/** A policy without usageLog was delivered to this device (or it already held one): its mark cleared. Own
 *  transaction, never throws (the push never fails because of it). Runs whatever the switch says: it is the way the
 *  logs are turned off. */
export async function clearSecurityLogPolicy(q: Knex, tenantId: number, deviceId: number): Promise<void> {
  try {
    await q.transaction((trx) => trx('device_security_log_status').where({ tenant_id: tenantId, device_id: deviceId, policy_logs_on: true })
      .update({ policy_logs_on: false, policy_marked_at: trx.fn.now() }));
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, deviceId }, 'obliwatch security logs: policy mark not cleared (the sweep asks again)');
  }
}

/**
 * The devices of a tenant whose policy still carries the security logs while it should not (see the header): their
 * push asked again (the push clears the mark once delivered); a device released or no longer enrolled under AMAPI
 * loses its mark (no policy is pushed to it any more). Integration on: only the devices of a tenant without the push
 * consent, or no longer company-owned fully managed. Returns the number of pushes asked.
 */
export async function staleSecurityLogPoliciesInTx(trx: Knex.Transaction, tenantId: number, integrationOn: boolean): Promise<number> {
  const rows = await trx('device_security_log_status as s')
    .join('devices as d', function j() { this.on('d.id', '=', 's.device_id').andOn('d.tenant_id', '=', 's.tenant_id'); })
    .leftJoin('android_devices as a', function j() { this.on('a.device_id', '=', 's.device_id').andOn('a.tenant_id', '=', 's.tenant_id'); })
    .where({ 's.tenant_id': tenantId, 's.policy_logs_on': true })
    .orderBy('s.device_id').limit(1000)
    .select('s.device_id', 'd.management_channel', 'd.enrollment_state', 'd.ownership', 'd.management_mode', 'a.device_id as amapi_device', 'a.released_at') as
    Array<{ device_id: number; management_channel: string; enrollment_state: string; ownership: string; management_mode: string; amapi_device: number | null; released_at: Date | null }>;
  if (!rows.length) return 0;
  let consent = false;
  if (integrationOn) {
    const t = await trx('tenant_obliwatch_settings').where({ tenant_id: tenantId }).first('push_enabled') as { push_enabled?: boolean } | undefined;
    consent = t?.push_enabled === true;
  }
  const gone: number[] = [];
  let asked = 0;
  for (const r of rows) {
    const managed = r.management_channel === 'amapi' && r.enrollment_state === 'enrolled' && r.amapi_device !== null && r.released_at === null;
    if (!managed) { gone.push(Number(r.device_id)); continue; }
    if (integrationOn && consent && securityLogsEligible({ ownership: r.ownership, mode: r.management_mode })) continue;
    await androidSenders.push(trx, { tenantId, deviceId: Number(r.device_id) });
    asked++;
  }
  if (gone.length) {
    await trx('device_security_log_status').where({ tenant_id: tenantId }).whereIn('device_id', gone).update({ policy_logs_on: false, policy_marked_at: trx.fn.now() });
  }
  return asked;
}

// ── Classification and aggregation ───────────────────────────────────────────────────────────────────────

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});

/** The rule of one event of the security logs, or null (another event). Reads the type and one boolean only. */
export function securityRuleOf(e: Record<string, unknown>): SecurityRuleId | null {
  switch (e.eventType) {
    case 'CERT_AUTHORITY_INSTALLED': return obj(e.certAuthorityInstalledEvent).success === true ? 'D-MOB-SEC-USER-CA' : null;
    case 'ADB_SHELL_COMMAND':
    case 'ADB_SHELL_INTERACTIVE': return 'D-MOB-SEC-ADB';
    // proto3 JSON leaves out a false boolean: an attempt without success: true failed.
    case 'KEYGUARD_DISMISS_AUTH_ATTEMPT': return obj(e.keyguardDismissAuthAttemptEvent).success === true ? null : 'D-MOB-SEC-UNLOCK-BURST';
    case 'KEY_INTEGRITY_VIOLATION': return 'D-MOB-SEC-KEY-INTEGRITY';
    case 'LOGGING_STOPPED': return 'D-MOB-SEC-LOGGING-STOPPED';
    default: return null;
  }
}

export interface SecurityAggregate {
  /** Events of the security logs in the batch (any type but the lost mode's). */
  securityEvents: number;
  /** Per rule and window start (epoch ms): the count, and the earliest event of the window in the batch. */
  windows: Map<SecurityRuleId, Map<number, { count: number; first: number }>>;
}

/** The aggregate of a batch of usage logs, pure. */
export function aggregateSecurityEvents(events: unknown, receivedAt: Date, otherEvents = 0): SecurityAggregate {
  // otherEvents: the events of the batch only counted at intake (android/inbox/schemas.ts, reduceUsageLogs).
  const out: SecurityAggregate = { securityEvents: Number.isSafeInteger(otherEvents) && otherEvents > 0 ? otherEvents : 0, windows: new Map() };
  const recv = receivedAt.getTime();
  for (const raw of (Array.isArray(events) ? events : []).slice(0, MAX_EVENTS)) {
    const e = obj(raw);
    if (typeof e.eventType !== 'string' || LOST_MODE_TYPES.has(e.eventType)) continue;
    out.securityEvents++;
    const rule = securityRuleOf(e);
    if (!rule) continue;
    const t = typeof e.eventTime === 'string' ? Date.parse(e.eventTime) : NaN;
    // A time in the future (the device's clock) counts as the reception; an old log is not counted.
    const at = Number.isFinite(t) && t <= recv + 300_000 ? t : recv;
    if (recv - at > MAX_AGE_MS) continue;
    const size = SECURITY_WINDOWS[rule] * 60_000;
    const start = Math.floor(at / size) * size;
    let byWindow = out.windows.get(rule);
    if (!byWindow) { byWindow = new Map(); out.windows.set(rule, byWindow); }
    const w = byWindow.get(start) ?? { count: 0, first: at };
    w.count++;
    w.first = Math.min(w.first, at);
    byWindow.set(start, w);
  }
  return out;
}

async function guarded<T>(trx: Knex.Transaction, what: string, fn: (sp: Knex.Transaction) => Promise<T>): Promise<T | null> {
  try {
    return await trx.transaction(async (sp) => fn(sp));
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, what }, 'obliwatch security logs: not recorded (the caller goes on)');
    return null;
  }
}

/** The window counted (added to), its count and whether a detection was recorded for it. */
const ADD_SQL = String.raw`
INSERT INTO obligarth.device_security_log_windows AS w (tenant_id, device_id, rule_id, window_start, count, updated_at)
VALUES (?::int, ?::int, ?::text, ?::timestamptz, ?::int, now())
ON CONFLICT (tenant_id, device_id, rule_id, window_start) DO UPDATE SET count = w.count + EXCLUDED.count, updated_at = now()
RETURNING w.count, w.emitted_at`;

/** The detection of a window recorded once (the first caller wins). */
const EMIT_SQL = String.raw`
UPDATE obligarth.device_security_log_windows SET emitted_at = now()
 WHERE tenant_id = ?::int AND device_id = ?::int AND rule_id = ?::text AND window_start = ANY (?::timestamptz[]) AND emitted_at IS NULL
RETURNING window_start`;

export interface SecurityLogsOutcome { securityEvents: number; detections: number }

/**
 * A batch of usage logs of an AMAPI device (android/inventory/usageLogs.ts, in its transaction): the security logs
 * counted, the detections recorded (D-MOB-SEC-*, through signals.ts), the arrival of the logs dated. Nothing while the
 * integration is off, without the push consent, or for a device that is not company-owned and fully managed. Never
 * throws.
 */
export async function recordSecurityLogsInTx(trx: Knex.Transaction, tenantId: number,
  device: { id: number; ownership: string; mode: string }, events: unknown, receivedAt: Date, otherEvents = 0): Promise<SecurityLogsOutcome | null> {
  if (!obliwatchIntegrationEnabled() || !securityLogsEligible(device)) return null;
  const agg = aggregateSecurityEvents(events, receivedAt, otherEvents);
  if (agg.securityEvents === 0) return null;
  if (!(await pushActiveInTx(trx, tenantId))) return null;
  const found = await guarded(trx, 'aggregate', async (sp) => {
    // 1. When the logs last arrived (the coverage); a first arrival, or one after a gap, marks the device for the read API.
    const before = await sp('device_security_log_status').where({ tenant_id: tenantId, device_id: device.id }).first('last_received_at') as
      { last_received_at: Date } | undefined;
    await sp('device_security_log_status').insert({ tenant_id: tenantId, device_id: device.id, last_received_at: receivedAt })
      .onConflict(['tenant_id', 'device_id'])
      .merge({ last_received_at: sp.raw('GREATEST(device_security_log_status.last_received_at, EXCLUDED.last_received_at)') });
    if (!before || receivedAt.getTime() - new Date(before.last_received_at).getTime() > SECURITY_LOGS_FRESH_MS) {
      await touchSignalInTx(sp, tenantId, [device.id]);
    }
    // 2. The windows counted, the detections decided.
    const detections: Array<{ rule: SecurityRuleId; count: number; windowMinutes: number; at: number }> = [];
    for (const [rule, byWindow] of agg.windows) {
      const minutes = SECURITY_WINDOWS[rule];
      const size = minutes * 60_000;
      for (const [start, w] of [...byWindow.entries()].sort((a, b) => a[0] - b[0])) {
        const added = (await sp.raw(ADD_SQL, [tenantId, device.id, rule, new Date(start), w.count]) as
          { rows: Array<{ count: number; emitted_at: Date | null }> }).rows[0];
        if (!added || added.emitted_at) continue;
        let count = Number(added.count);
        const windows = [new Date(start)];
        if (rule === 'D-MOB-SEC-UNLOCK-BURST') {
          const prev = await sp('device_security_log_windows')
            .where({ tenant_id: tenantId, device_id: device.id, rule_id: rule, window_start: new Date(start - size) })
            .first('count', 'emitted_at') as { count: number; emitted_at: Date | null } | undefined;
          if (count < UNLOCK_BURST_THRESHOLD && prev && !prev.emitted_at && count + Number(prev.count) >= UNLOCK_BURST_THRESHOLD) {
            count += Number(prev.count);
            windows.push(new Date(start - size));
          }
          if (count < UNLOCK_BURST_THRESHOLD) continue;
        }
        const won = (await sp.raw(EMIT_SQL, [tenantId, device.id, rule, windows]) as { rows: unknown[] }).rows;
        if (won.length === 0) continue;
        detections.push({ rule, count, windowMinutes: minutes * windows.length, at: w.first });
      }
    }
    return detections;
  });
  if (!found) return { securityEvents: agg.securityEvents, detections: 0 };
  let n = 0;
  for (const d of found) {
    const event: RuleState = {
      deviceId: device.id, ruleId: d.rule, state: 'active', severity: RULES[d.rule].severity, fingerprint: null,
      reasonCodes: [d.rule.slice('D-MOB-SEC-'.length).toLowerCase().replace(/-/g, '_')], count: d.count, windowMinutes: d.windowMinutes,
    };
    n += await recordSignalsInTx(trx, tenantId, [], { events: [event], occurredAt: new Date(d.at) });
  }
  return { securityEvents: agg.securityEvents, detections: n };
}

/** The windows ended more than 8 days ago removed (the minute step, hourly). */
export async function purgeSecurityWindowsInTx(trx: Knex.Transaction, tenantId: number, now = Date.now()): Promise<number> {
  return Number(await trx('device_security_log_windows').where({ tenant_id: tenantId })
    .where('window_start', '<', new Date(now - 8 * 86_400_000)).delete());
}
