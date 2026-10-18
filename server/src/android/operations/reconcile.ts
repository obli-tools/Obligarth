// android.reconcile-tenant (lot AN-H1; android-amapi §13.1, §22.5, AN36, AN49): the daily reconciliation of a tenant
// (spread over the day by tenant), and on demand (the operator's button, an absence of the instance of more than 5
// days, a restore of the base). In order:
//   1. devices.list paginated (class background of the limiter: the reconciliations of an instance stay under 5 % of
//      the budget of the project); a list cut short (pages bound reached) marks nothing missing;
//   2. each device the instance manages: absent at Google → it leaves management (removed_by_command when a WIPE or a
//      RELINQUISH_OWNERSHIP of the instance was sent to it, otherwise missing_in_provider); a newer report at Google →
//      written to the inbox as a status report and applied by the report handler (android.inbox-drain), the same code as
//      the notifications; the same report but another state → the state columns only; a policyName other than its own
//      policy → its push again;
//   3. silent disappearances (Google signals neither the reset of a device nor the removal of a work profile): no
//      report for mdmStaleAfterDays (30 by default) → presumed gone, shown and proposed to the forget; a report again →
//      the mark is cleared; 270 days → the automatic forget (forget.ts), spread;
//   4. devices Google lists that the instance never knew (no record, no quarantine): counted, alert
//      enrollment.unknown_session, never a record by default (DM25);
//   5. the own policies of the devices released since the last run are deleted (d-*); the tokens no row knows are
//      collected (AN50 recovery and garbage collection of enrollment/tokens.ts);
//   6. the counts: the devices Google lists without those silent for 270 days (google_count) feed the weekly recount
//      of the quota (quota.ts); the next run at the tenant's slot tomorrow.
// A 403 of the enterprise (access lost: the client removed the link in its Google console) puts the enterprise in error
// with the critical alert android.enterprise_unlinked_externally (offboarding.ts), nothing deleted.
// No device datum in a log, an alert or a job payload (G-A4): identifiers and counts only.
import { createHash } from 'node:crypto';
import type { AmapiDevice } from '@obligarth/shared/dist/android/amapi';
import {
  ANDROID_FORGET_AFTER_DAYS, ANDROID_FORGET_PER_RUN, ANDROID_OFFLINE_ALERT_DAYS, ANDROID_STALE_DAYS, ANDROID_STALE_DEFAULT_DAYS,
  type AndroidReconcileResult, type AndroidReconcileTrigger,
} from '@obligarth/shared/dist/android/operations.js';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { logger } from '../../utils/logger';
import { raiseAndroidTenantAlert, resolveAndroidTenantAlert } from '../alerts';
import { recoverEnrollmentTokens } from '../enrollment/tokens';
import { androidSenders } from '../enrollment/senders';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { AndroidError } from '../gateway/errors';
import type { AndroidEnterpriseRef } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { sendDrainInTx } from '../link/pull';
import { exitManagement } from './exit';
import { automaticForgetEnabled, deleteDevicePolicy, forgetPresumedGone } from './forget';
import { tenantDeadlineAlerts } from './deadlines';
import { markEnterpriseAccessLost } from './offboarding';

export const RECONCILE_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.reconcile-tenant' }) as DbActor;
const DAY_MS = 86_400_000;
/** 200 pages of 100 devices: 20 000 devices per enterprise at most in one run. */
const MAX_PAGES = 200;

/** mdmStaleAfterDays of a tenant for an ownership (the tenant setting at the junction; 30 days by default). */
type StaleDaysSource = (tenantId: number, ownership: string) => Promise<number | null>;
let staleDaysOf: StaleDaysSource = async () => null;
export function setStaleDaysSource(fn: StaleDaysSource): void { staleDaysOf = fn; }

/** The minute of the day of a tenant's daily pass: spread by a hash of its id (stable, no tenant datum). */
export function slotMinuteOf(tenantId: number): number {
  return createHash('sha256').update(`android-reconcile:${tenantId}`).digest().readUInt32BE(0) % 1440;
}

/** The next run of the daily pass after `now`: tomorrow at the tenant's slot (UTC). */
export function nextSlot(now: Date, slotMinute: number): Date {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, slotMinute));
  while (d.getTime() <= now.getTime() + 6 * 3_600_000) d.setTime(d.getTime() + DAY_MS);
  return d;
}

/** Silence of a device: presumed gone, forget due, or not silent. Pure (unit tests). */
export function silenceOf(lastSeen: Date, now: Date, staleDays: number): 'active' | 'presumed_gone' | 'forget' {
  const age = now.getTime() - lastSeen.getTime();
  if (age >= ANDROID_FORGET_AFTER_DAYS * DAY_MS) return 'forget';
  if (age >= staleDays * DAY_MS) return 'presumed_gone';
  return 'active';
}

const clampStale = (n: number | null): number => {
  if (n === null || !Number.isInteger(n)) return ANDROID_STALE_DEFAULT_DAYS;
  return Math.min(ANDROID_STALE_DAYS.max, Math.max(ANDROID_STALE_DAYS.min, n));
};
const time = (v: unknown): Date | null => (typeof v === 'string' && Number.isFinite(Date.parse(v)) ? new Date(v) : null);
const lastSegment = (name: unknown): string | null => (typeof name === 'string' ? name.split('/').pop() ?? null : null);

interface KnownDevice {
  device_id: number; amapi_name: string; state: string | null; applied_state: string | null; policy_name: string | null; policy_state: string;
  approval_state: string; last_status_report_at: Date | null; enrolled_at: Date; created_at: Date; ownership: string; uuid: string;
}

/** Asks an extra reconciliation of a tenant (operator, absence of the instance, restore); picked up within the minute. */
export async function requestReconcile(tenantId: number, trigger: Exclude<AndroidReconcileTrigger, 'daily'>, actor: DbActor = RECONCILE_ACTOR): Promise<boolean> {
  return asTenant(tenantId, actor, async () => {
    const e = await readEnterprise();
    if (!e || e.state !== 'linked') return false;
    await db('android_reconcile_state').insert({
      tenant_id: tenantId, enterprise_id: e.id, slot_minute: slotMinuteOf(tenantId), requested_at: db.fn.now(), request_trigger: trigger,
    }).onConflict(['tenant_id', 'enterprise_id']).merge({ requested_at: db.fn.now(), request_trigger: trigger, updated_at: db.fn.now() });
    return true;
  });
}

/** Lists every device of the enterprise at Google (bounded); `complete` false when the bound cut the list. */
async function listAll(gw: AndroidGateway, e: AndroidEnterpriseRef): Promise<{ devices: AmapiDevice[]; complete: boolean }> {
  const devices: AmapiDevice[] = [];
  let token: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const r = await gw.listDevices(e, token);
    devices.push(...r.items);
    token = r.nextPageToken;
    if (!token) return { devices, complete: true };
  }
  return { devices, complete: false };
}

export async function reconcileTenant(tenantId: number, o: { gateway?: AndroidGateway; now?: Date; trigger?: AndroidReconcileTrigger } = {}):
  Promise<AndroidReconcileResult | 'no_enterprise' | 'offboarding' | 'access_lost'> {
  const gw = o.gateway ?? androidGateway();
  const now = o.now ?? new Date();
  return asTenant(tenantId, RECONCILE_ACTOR, async () => {
    if (await db('android_offboardings').where({ tenant_id: tenantId }).whereNull('finished_at').first('id')) return 'offboarding';
    const e = await readEnterprise();
    if (!e || e.state !== 'linked') return 'no_enterprise';
    const slot = slotMinuteOf(tenantId);
    const prev = await db('android_reconcile_state').where({ tenant_id: tenantId, enterprise_id: e.id }).first('requested_at', 'request_trigger', 'last_started_at') as
      { requested_at: Date | null; request_trigger: string | null; last_started_at: Date | null } | undefined;
    const trigger: AndroidReconcileTrigger = o.trigger ?? ((prev?.request_trigger as AndroidReconcileTrigger | null) ?? 'daily');
    await db('android_reconcile_state').insert({ tenant_id: tenantId, enterprise_id: e.id, slot_minute: slot, last_started_at: now, last_trigger: trigger })
      .onConflict(['tenant_id', 'enterprise_id']).merge({ slot_minute: slot, last_started_at: now, last_trigger: trigger, updated_at: db.fn.now() });

    const out: AndroidReconcileResult = {
      listed: 0, refreshed: 0, statePatched: 0, policyRepushed: 0, missing: 0, unknown: 0, presumedGone: 0, cleared: 0, forgotten: 0,
      forgetDeferred: 0, policiesDeleted: 0, tokensCollected: 0, googleCount: 0, googleStale: 0, complete: true,
    };
    let listed: { devices: AmapiDevice[]; complete: boolean };
    // Review AN-H1 (R1): a device enrolled (or renewed) while devices.list is read is absent from the list yet known by
    // the base when both are compared; only a record created (or enrolled again) before the listing may be missing.
    const listStartedAt = Date.now() - 1000;
    try {
      listed = await listAll(gw, e);
    } catch (err) {
      if (err instanceof AndroidError && err.kind === 'access_lost') {
        await markEnterpriseAccessLost(tenantId);
        await db('android_reconcile_state').where({ tenant_id: tenantId, enterprise_id: e.id }).update({ last_error: 'access_lost', updated_at: db.fn.now() });
        return 'access_lost';
      }
      await db('android_reconcile_state').where({ tenant_id: tenantId, enterprise_id: e.id })
        .update({ last_error: err instanceof AndroidError ? err.kind : 'error', updated_at: db.fn.now() });
      throw err;
    }
    out.listed = listed.devices.length;
    out.complete = listed.complete;
    const atGoogle = new Map(listed.devices.map((d) => [d.name, d]));

    const known = await db('android_devices as a').join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .where({ 'a.tenant_id': tenantId, 'a.enterprise_id': e.id }).whereNull('a.released_at')
      .select('a.device_id', 'a.amapi_name', 'a.state', 'a.applied_state', 'a.policy_name', 'a.policy_state', 'a.approval_state',
        'a.last_status_report_at', 'a.enrolled_at', 'a.created_at', 'd.ownership', 'd.uuid') as KnownDevice[];
    const staleByOwnership = new Map<string, number>();
    const staleDays = async (ownership: string) => {
      if (!staleByOwnership.has(ownership)) staleByOwnership.set(ownership, clampStale(await staleDaysOf(tenantId, ownership)));
      return staleByOwnership.get(ownership)!;
    };
    let offlineLong = 0;
    for (const k of known) {
      const g = atGoogle.get(k.amapi_name);
      const deviceId = Number(k.device_id);
      if (!g) {
        if (!listed.complete) continue;
        if ([k.created_at, k.enrolled_at].some((t) => t && new Date(t).getTime() >= listStartedAt)) continue;   // written during the listing
        const removed = await db('android_commands').where({ tenant_id: tenantId, device_id: deviceId })
          .whereIn('request_type', ['WIPE', 'RELINQUISH_OWNERSHIP']).whereIn('state', ['sent', 'acknowledged']).first('id');
        const left = await db.transaction((trx) => exitManagement(trx, tenantId, deviceId, removed ? 'removed_by_command' : 'missing_in_provider'));
        if (left) out.missing += 1;
        continue;
      }
      const report = time(g.lastStatusReportTime);
      const stored = k.last_status_report_at ? new Date(k.last_status_report_at) : null;
      if (report && (!stored || report.getTime() > stored.getTime())) {
        await db.transaction(async (trx) => {
          const payload = JSON.stringify(g);
          const r = await trx('android_inbox').insert({
            tenant_id: tenantId, message_id: `rc-${deviceId}-${report.getTime()}`, event_type: 'amapi.status_report', enterprise_name: e.name,
            resource_name: g.name, published_at: now, occurred_at: report, payload: trx.raw('?::jsonb', [payload]), payload_bytes: Buffer.byteLength(payload),
          }).onConflict(['tenant_id', 'message_id']).ignore().returning('id');
          if (r.length) { out.refreshed += 1; await sendDrainInTx(trx, tenantId); }
        });
      } else if ((typeof g.state === 'string' && g.state !== k.state) || (typeof g.appliedState === 'string' && g.appliedState !== k.applied_state)) {
        await db('android_devices').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('released_at').update({
          state: typeof g.state === 'string' ? g.state.slice(0, 32) : k.state, applied_state: typeof g.appliedState === 'string' ? g.appliedState.slice(0, 32) : k.applied_state,
          updated_at: db.fn.now(),
        });
        out.statePatched += 1;
      }
      const pointed = lastSegment(g.policyName);
      if (k.policy_name && k.policy_name.startsWith('d-') && k.approval_state !== 'pending' && k.policy_state !== 'pending' && pointed && pointed !== k.policy_name) {
        await db.transaction((trx) => androidSenders.push(trx, { tenantId, deviceId }));
        out.policyRepushed += 1;
      }
      // Silent disappearances.
      const seen = [report, stored].filter((x): x is Date => !!x).sort((a, b) => b.getTime() - a.getTime())[0] ?? new Date(k.enrolled_at);
      if (now.getTime() - seen.getTime() >= ANDROID_OFFLINE_ALERT_DAYS * DAY_MS) offlineLong += 1;
      const silence = silenceOf(seen, now, await staleDays(k.ownership));
      if (silence === 'active') {
        const n = await db('android_presumed_gone').where({ tenant_id: tenantId, device_id: deviceId, state: 'open' })
          .update({ state: 'cleared', ended_at: db.fn.now() });
        out.cleared += n;
      } else {
        const forgetDue = new Date(seen.getTime() + ANDROID_FORGET_AFTER_DAYS * DAY_MS);
        const open = await db('android_presumed_gone').where({ tenant_id: tenantId, device_id: deviceId, state: 'open' }).first('id', 'last_report_at');
        if (!open) {
          try {
            await db('android_presumed_gone').insert({ tenant_id: tenantId, device_id: deviceId, since: now, last_report_at: seen, forget_due_at: forgetDue });
            out.presumedGone += 1;
          } catch (err) {
            if ((err as { code?: string })?.code !== '23505') throw err;   // marked by a concurrent run
          }
        } else if (!open.last_report_at || new Date(open.last_report_at).getTime() < seen.getTime()) {
          // A newer report that still leaves the device silent: the forget moves with it.
          await db('android_presumed_gone').where({ id: open.id }).update({ last_report_at: seen, forget_due_at: forgetDue });
        }
      }
    }
    // Devices Google lists that this instance never knew (no record in any state, no quarantine).
    if (listed.devices.length) {
      const names = listed.devices.map((d) => d.name);
      const seenNames = new Set<string>();
      for (let i = 0; i < names.length; i += 1000) {
        const chunk = names.slice(i, i + 1000);
        const a = await db('android_devices').where({ tenant_id: tenantId }).whereIn('amapi_name', chunk).pluck('amapi_name') as string[];
        const q = await db('android_quarantine').where({ tenant_id: tenantId }).whereIn('amapi_name', chunk).pluck('amapi_name') as string[];
        for (const n of [...a, ...q]) seenNames.add(n);
      }
      out.unknown = names.filter((n) => !seenNames.has(n)).length;
    }
    for (const g of listed.devices) {
      const report = time(g.lastStatusReportTime) ?? time(g.enrollmentTime);
      if (report && now.getTime() - report.getTime() > ANDROID_FORGET_AFTER_DAYS * DAY_MS) out.googleStale += 1;
      else out.googleCount += 1;
    }
    // The automatic forget at 270 days, spread (RR-4 control in the gateway, RR-11).
    if (automaticForgetEnabled()) {
      const due = await db('android_presumed_gone').where({ tenant_id: tenantId, state: 'open' }).where('forget_due_at', '<=', now)
        .where((q) => q.whereNull('next_forget_at').orWhere('next_forget_at', '<=', now)).orderBy('forget_due_at')
        .limit(ANDROID_FORGET_PER_RUN).pluck('device_id') as number[];
      for (const deviceId of due) {
        const r = await forgetPresumedGone(tenantId, Number(deviceId), { gateway: gw });
        if (r === 'forgotten') out.forgotten += 1;
        else if (r !== 'not_open') out.forgetDeferred += 1;
      }
    }
    // Own policies of the devices released since the last run (or the last 3 days on a first run).
    const since = prev?.last_started_at ? new Date(new Date(prev.last_started_at).getTime() - 3_600_000) : new Date(now.getTime() - 3 * DAY_MS);
    const released = await db('android_devices as a').join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .where({ 'a.tenant_id': tenantId, 'a.enterprise_id': e.id }).whereNotNull('a.released_at').where('a.released_at', '>=', since)
      .limit(500).pluck('d.uuid') as string[];
    for (const uuid of released) if (await deleteDevicePolicy(gw, e, uuid)) out.policiesDeleted += 1;
    // Tokens no row knows (AN50 recovery, garbage collection; RR-9: creations in progress kept).
    try {
      out.tokensCollected = (await recoverEnrollmentTokens(tenantId, { gateway: gw, actor: RECONCILE_ACTOR })).collected;
    } catch (err) {
      logger.warn({ android: { reconcile: 'tokens', tenantId, kind: (err as AndroidError)?.kind ?? 'error' } }, 'android: token collection skipped');
    }
    await db('android_reconcile_state').where({ tenant_id: tenantId, enterprise_id: e.id }).update({
      last_finished_at: db.fn.now(), last_result: JSON.stringify(out), last_error: null, google_count: out.googleCount, google_stale: out.googleStale,
      counted_at: listed.complete ? db.fn.now() : null, next_due_at: nextSlot(now, slot), requested_at: null, request_trigger: null, updated_at: db.fn.now(),
    });
    // Alerts: identifiers and counts only.
    if (out.unknown) void raiseAndroidTenantAlert(tenantId, 'enrollment.unknown_session', { count: out.unknown, source: 'reconcile' });
    const open = await db('android_presumed_gone').where({ tenant_id: tenantId, state: 'open' }).count<{ n: string }[]>('* as n');
    const openCount = Number(open[0]?.n ?? 0);
    if (out.presumedGone) void raiseAndroidTenantAlert(tenantId, 'android.device_presumed_gone', { count: openCount });
    else if (!openCount) void resolveAndroidTenantAlert(tenantId, 'android.device_presumed_gone');
    if (offlineLong) void raiseAndroidTenantAlert(tenantId, 'android.device_offline_long', { count: offlineLong });
    else void resolveAndroidTenantAlert(tenantId, 'android.device_offline_long');
    // Deadlines of the long tokens (daily, with the pass of the tenant).
    await tenantDeadlineAlerts(tenantId, RECONCILE_ACTOR, now).catch(() => 0);
    logger.info({ android: { reconcile: trigger, tenantId, listed: out.listed, missing: out.missing, presumedGone: out.presumedGone, forgotten: out.forgotten } },
      'android: tenant reconciled');
    return out;
  });
}
