import type { Knex } from 'knex';
import type { ObliwatchRuleId } from '@obligarth/shared';
import { defaultRuntime } from '../../jobs';
import type { JobHandle } from '../../jobs/types';
import { logger } from '../../utils/logger';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { OBLIWATCH_ACTOR, obliwatchIntegrationEnabled } from './config';
import {
  ALERT_EVENT_RULES, RULES, complianceRuleStates, postureRuleStates, reasonCodesOf, type ComplianceInput, type PostureInput, type RuleState,
} from './rules';

// =============================================================================
// The recording of the D-MOB-* signals (brief GTH-01; plan L3), called by the hot paths of the fleet (AMAPI status
// reports, compliance evaluation, Apple check-ins and inventory, bridge agent poll) INSIDE their own transaction:
//   1. pushActiveInTx: OBLIWATCH_INTEGRATION=on and the push consent of the tenant, read at most once per 30 s and per
//      tenant and process (a savepoint on the caller's transaction on a miss; nothing at all while the switch is off).
//      Off: the caller's work and its SQL load are unchanged.
//   2. one INSERT ... ON CONFLICT DO UPDATE ... WHERE on device_signal_state: the compare with the last state AND the
//      increment of the per (device, rule) sequence, atomic under the row lock; only the rows that changed come back
//      (a first 'cleared' of a rule never seen is stored, never sent);
//   3. one INSERT ... SELECT of the transitions (whitelisted details: platform, ownership, managementMode from the
//      device, reasonCodes, posture, risks, state), then the drain job of the tenant integrations.obliwatch.push in the
//      same transaction (stately per tenant: a burst of transitions is one job; absorbed by a waiting job, it is sent
//      again after the commit, and the minute step picks up anything left).
// Everything under a SAVEPOINT, every error swallowed and logged: recording a signal NEVER fails the caller's
// transaction (as integrations/obliwatch/marker.ts).
// =============================================================================

const CONSENT_TTL_MS = 30_000;
const consentCache = new Map<number, { push: boolean; at: number }>();

/** Forgets the cached push consent of a tenant (the consent changed in this process). */
export function invalidatePushConsent(tenantId?: number): void {
  if (tenantId === undefined) consentCache.clear();
  else consentCache.delete(tenantId);
}

async function guarded<T>(trx: Knex.Transaction, what: string, fn: (sp: Knex.Transaction) => Promise<T>): Promise<T | null> {
  try {
    return await trx.transaction(async (sp) => fn(sp));
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, what }, 'obliwatch signals: not recorded (the caller goes on)');
    return null;
  }
}

/** Is the push on for `tenantId` (switch of the instance and consent of the tenant)? Never throws. */
export async function pushActiveInTx(trx: Knex.Transaction, tenantId: number): Promise<boolean> {
  if (!obliwatchIntegrationEnabled()) return false;
  if (!Number.isSafeInteger(tenantId) || tenantId <= 0) return false;
  const now = Date.now();
  const c = consentCache.get(tenantId);
  if (c && now - c.at < CONSENT_TTL_MS) return c.push;
  const row = await guarded(trx, 'consent', (sp) => sp('tenant_obliwatch_settings').where({ tenant_id: tenantId }).first('push_enabled'));
  const push = (row as { push_enabled?: boolean } | null | undefined)?.push_enabled === true;
  if (consentCache.size > 10_000) consentCache.clear();
  consentCache.set(tenantId, { push, at: now });
  return push;
}

// ── The drain job (bound by the module) ─────────────────────────────────────────────────────────────────────

export interface PushPayload { tenantId: number; reconcile?: boolean }
let pushJob: JobHandle<PushPayload> | null = null;

/** The handle of integrations.obliwatch.push (modules/obliwatch.ts). */
export function bindPushJob(job: JobHandle<PushPayload>): void {
  pushJob = job;
}

export const pushSingletonKey = (tenantId: number): string => `obliwatch-push:t:${tenantId}`;

type Nested = Knex.Transaction & { parentTransaction?: Knex.Transaction; executionPromise?: Promise<unknown> };

async function requestPushInTx(sp: Knex.Transaction, tenantId: number): Promise<void> {
  const job = pushJob;
  if (!job) return;
  if (!defaultRuntime.isStarted()) return;   // a process without jobs (a tool, a test): the minute step sends it
  const opts = { singletonKey: pushSingletonKey(tenantId), tenantId };
  // In a savepoint of its own: a send that fails never takes the transitions with it (the minute step sends it).
  const id = await guarded(sp, 'job', (j) => job.sendInTx(j, { tenantId }, opts));
  if (id !== null) return;
  // Absorbed by a job already waiting, which may run before this commits: sent again once the outermost transaction
  // committed (the minute step is the last net).
  let outer = sp as Nested;
  for (let depth = 0; depth < 16 && outer.parentTransaction; depth++) outer = outer.parentTransaction as Nested;
  outer.executionPromise?.then(() => job.send({ tenantId }, opts), () => undefined)
    .catch((err) => logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) } }, 'obliwatch push: not requested again after the commit'));
}

/** The drain job of the tenant asked once `trx` committed (the dead letters requeued from the console). */
export function requestPushAfterCommit(trx: Knex.Transaction, tenantId: number): void {
  const job = pushJob;
  if (!job) return;
  let outer = trx as Nested;
  for (let depth = 0; depth < 16 && outer.parentTransaction; depth++) outer = outer.parentTransaction as Nested;
  outer.executionPromise?.then(() => job.send({ tenantId }, { singletonKey: pushSingletonKey(tenantId), tenantId }), () => undefined)
    .catch((err) => logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) } }, 'obliwatch push: not requested after the commit'));
}

// ── Recording ────────────────────────────────────────────────────────────────────────────────────────────

/** device_signal_state, a state rule: the compare and the increment in one statement; the rows that changed (or were
 *  created). */
const STATE_SQL = String.raw`
INSERT INTO obligarth.device_signal_state AS s (tenant_id, device_id, rule_id, state, fingerprint, seq, changed_at)
SELECT ?::int, u.device_id, u.rule_id, u.state, u.fp, CASE WHEN u.state = 'active' THEN 1 ELSE 0 END, clock_timestamp()
  FROM unnest(?::int[], ?::text[], ?::text[], ?::text[]) AS u(device_id, rule_id, state, fp)
ON CONFLICT (tenant_id, device_id, rule_id) DO UPDATE
   SET state = EXCLUDED.state, fingerprint = EXCLUDED.fingerprint, seq = s.seq + 1, changed_at = EXCLUDED.changed_at
 WHERE s.state <> EXCLUDED.state
    OR (EXCLUDED.state = 'active' AND s.fingerprint IS DISTINCT FROM EXCLUDED.fingerprint)
RETURNING s.device_id, s.rule_id, s.state, s.seq, (xmax = 0) AS inserted`;

/** device_signal_state, an event: each occurrence a new transition (active, the sequence incremented). */
const EVENT_SQL = String.raw`
INSERT INTO obligarth.device_signal_state AS s (tenant_id, device_id, rule_id, state, fingerprint, seq, changed_at)
SELECT ?::int, u.device_id, u.rule_id, 'active', u.fp, 1, clock_timestamp()
  FROM unnest(?::int[], ?::text[], ?::text[]) AS u(device_id, rule_id, fp)
ON CONFLICT (tenant_id, device_id, rule_id) DO UPDATE
   SET state = 'active', fingerprint = EXCLUDED.fingerprint, seq = s.seq + 1, changed_at = EXCLUDED.changed_at
RETURNING s.device_id, s.rule_id, s.state, s.seq, (xmax = 0) AS inserted`;

/** The transitions, their details completed from the device (platform, ownership, managementMode). */
const TRANSITIONS_SQL = String.raw`
INSERT INTO obligarth.device_signal_transitions
  (tenant_id, device_id, device_uuid, rule_id, seq, state, severity, details, occurred_at, push_state, next_attempt_at)
SELECT d.tenant_id, d.id, d.uuid, u.rule_id, u.seq, u.state, u.severity,
       jsonb_build_object('platform', d.platform, 'ownership', d.ownership, 'managementMode', d.management_mode, 'state', u.state)
         || u.extra::jsonb,
       ?::timestamptz, 'pending', now()
  FROM unnest(?::int[], ?::text[], ?::int[], ?::text[], ?::text[], ?::text[]) AS u(device_id, rule_id, seq, state, severity, extra)
  JOIN obligarth.devices d ON d.tenant_id = ?::int AND d.id = u.device_id
ON CONFLICT (tenant_id, device_id, rule_id, seq) DO NOTHING
RETURNING id`;

interface Wanted extends RuleState { force: boolean }

const extraOf = (w: RuleState): string => {
  const o: Record<string, unknown> = { reasonCodes: w.reasonCodes.slice(0, 20) };
  if (w.posture !== undefined) o.posture = w.posture ?? null;
  if (w.risks !== undefined) o.risks = w.risks ?? null;
  // An aggregated detection (SEC-13): counts only, never an event of the log.
  if (Number.isSafeInteger(w.count) && (w.count as number) > 0) o.count = Math.min(w.count as number, 1_000_000);
  if (Number.isSafeInteger(w.windowMinutes) && (w.windowMinutes as number) > 0) o.windowMinutes = Math.min(w.windowMinutes as number, 10_080);
  return JSON.stringify(o);
};

/** Records the wanted states (and events) in `sp`; the number of transitions written. */
async function recordInSp(sp: Knex.Transaction, tenantId: number, wanted: Wanted[], occurredAt: Date): Promise<number> {
  // One wanted state per (device, rule): an INSERT ... ON CONFLICT cannot touch a row twice (the last one wins).
  const byKey = new Map<string, Wanted>();
  for (const w of wanted) if (Number.isSafeInteger(w.deviceId) && w.deviceId > 0 && RULES[w.ruleId]) byKey.set(`${w.deviceId}|${w.ruleId}`, w);
  const list = [...byKey.values()];
  if (list.length === 0) return 0;
  type Changed = { device_id: number; rule_id: string; state: string; seq: number; inserted: boolean };
  const states = list.filter((w) => !w.force);
  const events = list.filter((w) => w.force);
  const changed: Changed[] = [];
  if (states.length) {
    changed.push(...(await sp.raw(STATE_SQL, [
      tenantId, states.map((w) => w.deviceId), states.map((w) => w.ruleId), states.map((w) => w.state), states.map((w) => w.fingerprint),
    ] as any[]) as { rows: Changed[] }).rows);
  }
  if (events.length) {
    changed.push(...(await sp.raw(EVENT_SQL, [
      tenantId, events.map((w) => w.deviceId), events.map((w) => w.ruleId), events.map((w) => w.fingerprint),
    ] as any[]) as { rows: Changed[] }).rows);
  }
  // A rule seen for the first time in its normal state is only stored: nothing to close at Obliwatch.
  const sent = changed.filter((r) => !(r.inserted && r.state === 'cleared'));
  if (sent.length === 0) return 0;
  const of = (r: { device_id: number; rule_id: string }) => byKey.get(`${Number(r.device_id)}|${r.rule_id}`)!;
  const ins = (await sp.raw(TRANSITIONS_SQL, [
    occurredAt, sent.map((r) => Number(r.device_id)), sent.map((r) => r.rule_id), sent.map((r) => Number(r.seq)), sent.map((r) => r.state),
    sent.map((r) => of(r).severity), sent.map((r) => extraOf(of(r))), tenantId,
  ] as any[]) as { rows: unknown[] }).rows;
  if (ins.length > 0) await requestPushInTx(sp, tenantId);
  return ins.length;
}

/** Records wanted states and events of devices of `tenantId` in the caller's transaction (tenant context). Never throws. */
export async function recordSignalsInTx(trx: Knex.Transaction, tenantId: number, states: RuleState[],
  o: { events?: RuleState[]; occurredAt?: Date } = {}): Promise<number> {
  const events = o.events ?? [];
  if (states.length === 0 && events.length === 0) return 0;
  if (!(await pushActiveInTx(trx, tenantId))) return 0;
  const wanted: Wanted[] = [...states.map((s) => ({ ...s, force: false })), ...events.map((e) => ({ ...e, state: 'active' as const, force: true }))];
  const n = await guarded(trx, 'record', (sp) => recordInSp(sp, tenantId, wanted, o.occurredAt ?? new Date()));
  return n ?? 0;
}

/** An event of a rule on a device (each occurrence a new transition): ID-MISMATCH, MGMT-REMOVED of a departure,
 *  LOST-EXIT. Never throws. */
export async function recordEventSignalInTx(trx: Knex.Transaction, tenantId: number, deviceId: number, ruleId: ObliwatchRuleId,
  reasonCodes: string[], o: { occurredAt?: Date; companyOnly?: boolean; notDuringOffboarding?: boolean } = {}): Promise<number> {
  if (!(await pushActiveInTx(trx, tenantId))) return 0;
  if (o.companyOnly || o.notDuringOffboarding) {
    const ok = await guarded(trx, 'facts', async (sp) => {
      if (o.companyOnly) {
        const d = await sp('devices').where({ tenant_id: tenantId, id: deviceId }).first('ownership') as { ownership?: string } | undefined;
        if (!d || d.ownership === 'personal') return false;
      }
      // The offboarding of the tenant (operator-approved) releases the devices gone at Google: departures Obligarth
      // decided, never signals.
      if (o.notDuringOffboarding && await sp('android_offboardings').where({ tenant_id: tenantId }).whereNull('finished_at').first('id')) return false;
      return true;
    });
    if (!ok) return 0;
  }
  const event: RuleState = { deviceId, ruleId, state: 'active', severity: RULES[ruleId].severity, fingerprint: null, reasonCodes };
  return recordSignalsInTx(trx, tenantId, [], { events: [event], occurredAt: o.occurredAt });
}

/** A state of one rule of a device (the bridge agent's MGMT-REMOVED cleared when its administrator or its owner role
 *  is back). Never throws. */
export async function recordStateSignalInTx(trx: Knex.Transaction, tenantId: number, deviceId: number, ruleId: ObliwatchRuleId,
  state: 'active' | 'cleared', reasonCodes: string[] = []): Promise<number> {
  return recordSignalsInTx(trx, tenantId, [{ deviceId, ruleId, state, severity: RULES[ruleId].severity, fingerprint: null, reasonCodes }]);
}

/**
 * An AMAPI device (alias a: android_devices) DISABLED by Obligarth itself: an approval hold, the operator's control
 * recorded, or an mdm.android_disable of the tenant that targets it still executing (android/commands/guarded.ts
 * executeState patches the device at Google BEFORE it records the control, in another transaction: a status report in
 * between, or a recording that failed and is retried, must not read as a user-side disable), or ended within the hour.
 */
const OPERATOR_DISABLED_SQL = String.raw`(a.approval_state = 'pending'
  OR EXISTS (SELECT 1 FROM obligarth.android_device_controls c WHERE c.tenant_id = a.tenant_id AND c.device_id = a.device_id)
  OR EXISTS (SELECT 1 FROM obligarth.pending_actions p
              WHERE p.tenant_id = a.tenant_id AND p.action_key = 'mdm.android_disable' AND a.device_id = ANY (p.target_device_ids)
                AND (p.state = 'executing' OR (p.state IN ('partial', 'failed') AND p.updated_at > now() - interval '1 hour'))))`;

/**
 * The compliance of devices changed (the evaluators' differentials: Apple and bridge agent in mdm/compliance/evaluate.ts,
 * AMAPI in android/inventory/compliance.ts): NONCOMPLIANT, STALE, OS-OUTDATED and, for AMAPI, MGMT-REMOVED. Only the
 * devices whose verdict changed are given. Never throws; nothing at all while the push is off.
 */
export async function recordComplianceSignalsInTx(trx: Knex.Transaction, tenantId: number, changed: ComplianceInput[]): Promise<number> {
  if (changed.length === 0) return 0;
  if (!(await pushActiveInTx(trx, tenantId))) return 0;
  // A device DISABLED by Obligarth (an operator's disable, an approval hold) is told apart from a user-side disable,
  // and the ownership of an AMAPI device read, only for the devices concerned.
  const disabled = changed.filter((c) => c.channel === 'amapi' && c.codes.includes('management_disabled')).map((c) => c.deviceId);
  const amapi = changed.filter((c) => c.channel === 'amapi').map((c) => c.deviceId);
  let operator = new Set<number>();
  let personal = new Set<number>();
  if (amapi.length) {
    const facts = await guarded(trx, 'facts', async (sp) => {
      const own = await sp('devices').where({ tenant_id: tenantId, ownership: 'personal' }).whereIn('id', amapi).pluck('id');
      const ctl = disabled.length
        ? await sp('android_devices as a')
          .where('a.tenant_id', tenantId).whereIn('a.device_id', disabled)
          .whereRaw(OPERATOR_DISABLED_SQL)
          .pluck('a.device_id')
        : [];
      return { own: (own as Array<number | string>).map(Number), ctl: (ctl as Array<number | string>).map(Number) };
    });
    if (!facts) return 0;
    personal = new Set(facts.own);
    operator = new Set(facts.ctl);
  }
  const states = changed.flatMap((c) => complianceRuleStates({ ...c, operatorDisabled: operator.has(c.deviceId), personal: personal.has(c.deviceId) }));
  return recordSignalsInTx(trx, tenantId, states);
}

/** The Play Integrity posture of an AMAPI device changed (status report). Never throws. */
export async function recordPostureSignalsInTx(trx: Knex.Transaction, tenantId: number, deviceId: number, posture: PostureInput | null): Promise<number> {
  const states = postureRuleStates(deviceId, posture);
  if (states.length === 0) return 0;
  return recordSignalsInTx(trx, tenantId, states);
}

/** An alert of the catalogue was just created for a device (apple/alerts/service.ts raiseInTx): the event of its rule,
 *  if it is one (rules.ts ALERT_EVENT_RULES). Never throws. */
export async function recordAlertSignalInTx(trx: Knex.Transaction, tenantId: number, kind: string, deviceId: unknown): Promise<number> {
  const rule = ALERT_EVENT_RULES[kind];
  if (!rule || typeof deviceId !== 'number' || !Number.isSafeInteger(deviceId) || deviceId <= 0) return 0;
  if (!obliwatchIntegrationEnabled()) return 0;
  return recordEventSignalInTx(trx, tenantId, deviceId, rule[0], [rule[1]], { companyOnly: rule[0] === 'D-MOB-MGMT-REMOVED' });
}

// ── Silent bootstrap ─────────────────────────────────────────────────────────────────────────────────────

/**
 * The current data of the managed devices of the tenant, reduced to the wanted states of the state rules by the SAME
 * functions as the hot paths (rules.ts complianceRuleStates, postureRuleStates: an AMAPI device non-compliant only
 * because Obligarth disabled it decides nothing, as live). One statement.
 */
const CURRENT_SQL = String.raw`
SELECT d.id, d.management_channel AS channel, d.ownership, d.compliance_state AS cs, d.compliance_reasons AS reasons,
       CASE WHEN d.management_channel = 'amapi' THEN a.security_posture END AS posture,
       COALESCE(a.device_id IS NOT NULL AND ${OPERATOR_DISABLED_SQL}, false) AS operator
  FROM obligarth.devices d
  LEFT JOIN obligarth.android_devices a ON a.tenant_id = d.tenant_id AND a.device_id = d.id AND a.released_at IS NULL
 WHERE d.tenant_id = ?::int AND d.enrollment_state IN ('enrolled', 'awaiting_configuration')`;

const json = (v: unknown): unknown => {
  if (typeof v !== 'string') return v;
  try { return JSON.parse(v); } catch { return null; }
};

function postureOf(v: unknown): PostureInput | null {
  const p = json(v);
  if (!p || typeof p !== 'object') return null;
  const o = p as { devicePosture?: unknown; risks?: unknown };
  if (typeof o.devicePosture !== 'string' || !o.devicePosture) return null;
  return { devicePosture: o.devicePosture, risks: Array.isArray(o.risks) ? o.risks.filter((r): r is string => typeof r === 'string') : [] };
}

async function currentStatesOf(q: Knex.Transaction, tenantId: number): Promise<RuleState[]> {
  const rows = (await q.raw(CURRENT_SQL, [tenantId]) as { rows: Array<Record<string, unknown>> }).rows;
  const out: RuleState[] = [];
  for (const r of rows) {
    const deviceId = Number(r.id);
    out.push(...complianceRuleStates({
      deviceId, channel: String(r.channel ?? ''), state: String(r.cs ?? ''), codes: reasonCodesOf(json(r.reasons)),
      operatorDisabled: r.operator === true, personal: r.ownership === 'personal',
    }));
    if (r.channel === 'amapi') out.push(...postureRuleStates(deviceId, postureOf(r.posture)));
  }
  // Lot L5 (GTH-08): the last verdict of the Apple managed device attestation (appleAttestation.ts), a state rule.
  const attested = await q('apple_device_attestations as x')
    .join('devices as d', function j() { this.on('d.id', '=', 'x.device_id').andOn('d.tenant_id', '=', 'x.tenant_id'); })
    .where({ 'x.tenant_id': tenantId, 'd.management_channel': 'apple_mdm' }).whereIn('d.enrollment_state', ['enrolled', 'awaiting_configuration'])
    .whereNotNull('x.state').select('x.device_id', 'x.state', 'x.reason') as Array<{ device_id: number; state: string; reason: string | null }>;
  for (const a of attested) {
    const failed = a.state === 'failed';
    out.push({
      deviceId: Number(a.device_id), ruleId: 'D-MOB-ATTEST-FAILED', state: failed ? 'active' : 'cleared', severity: RULES['D-MOB-ATTEST-FAILED'].severity,
      fingerprint: null, reasonCodes: failed ? ['attestation_failed', ...(a.reason ? [a.reason] : [])] : [],
    });
  }
  return out;
}

/** device_signal_state written silently: no transition, the sequences already there kept (an eventId is never reused). */
const SILENT_SQL = String.raw`
INSERT INTO obligarth.device_signal_state AS s (tenant_id, device_id, rule_id, state, fingerprint, seq, changed_at)
SELECT ?::int, u.device_id, u.rule_id, u.state, u.fp, 0, clock_timestamp()
  FROM unnest(?::int[], ?::text[], ?::text[], ?::text[]) AS u(device_id, rule_id, state, fp)
ON CONFLICT (tenant_id, device_id, rule_id) DO UPDATE SET state = EXCLUDED.state, fingerprint = EXCLUDED.fingerprint, changed_at = EXCLUDED.changed_at
 WHERE s.state IS DISTINCT FROM EXCLUDED.state OR s.fingerprint IS DISTINCT FROM EXCLUDED.fingerprint`;

/**
 * The silent bootstrap of a tenant (consent.ts, when the push turns on, in its transaction): the state of every rule
 * of every managed device from its current data, WITHOUT any transition nor push (no burst of signals that are not
 * transitions). What still waited from an earlier period of consent is skipped (consent_reset): the state it carried
 * is replaced by the current one, never sent after it. Throws: the consent change is then refused.
 */
export async function bootstrapSignalStateInTx(trx: Knex.Transaction, tenantId: number): Promise<number> {
  await trx('device_signal_transitions').where({ tenant_id: tenantId, push_state: 'pending' })
    .update({ push_state: 'skipped', result_code: 'consent_reset' });
  const byKey = new Map<string, RuleState>();
  for (const w of await currentStatesOf(trx, tenantId)) byKey.set(`${w.deviceId}|${w.ruleId}`, w);
  const list = [...byKey.values()];
  if (list.length === 0) return 0;
  const r = await trx.raw(SILENT_SQL, [
    tenantId, list.map((w) => w.deviceId), list.map((w) => w.ruleId), list.map((w) => w.state), list.map((w) => w.fingerprint),
  ] as any[]) as { rowCount?: number };
  return Number(r.rowCount ?? 0);
}

/** Two minutes: longer than the consent cache of every process (30 s) and than a transaction of the hot paths. */
export const RECONCILE_AFTER_S = 120;
export const reconcileSingletonKey = (tenantId: number): string => `obliwatch-reconcile:t:${tenantId}`;

/**
 * The second pass after the push turned on, asked in the consent transaction (startAfter two minutes; its own
 * singleton key). The bootstrap read a snapshot: a hot path in flight, or in a process whose cache still said "off",
 * may have changed a device without recording it. Never throws (the consent change goes on without it: logged).
 */
export async function requestReconcileInTx(trx: Knex.Transaction, tenantId: number): Promise<void> {
  const job = pushJob;
  if (!job || !defaultRuntime.isStarted()) return;
  await guarded(trx, 'reconcile', (j) => job.sendInTx(j, { tenantId, reconcile: true },
    { singletonKey: reconcileSingletonKey(tenantId), tenantId, startAfter: RECONCILE_AFTER_S }));
}

/**
 * The reconciliation of a tenant whose push is on (the job of requestReconcileInTx; the tests call it directly): the
 * current data compared with device_signal_state through the normal recording (the same statements as the hot paths),
 * so what changed since the bootstrap is a transition and pushed; a rule seen for the first time in its normal state is
 * stored only. Nothing when the push is off. The number of transitions written.
 */
export async function reconcileSignalState(tenantId: number): Promise<number> {
  if (!obliwatchIntegrationEnabled()) return 0;
  return asTenant(tenantId, OBLIWATCH_ACTOR, () => db.transaction(async (trx) => {
    const c = await trx('tenant_obliwatch_settings').where({ tenant_id: tenantId }).first('push_enabled') as { push_enabled?: boolean } | undefined;
    if (c?.push_enabled !== true) return 0;
    const wanted: Wanted[] = (await currentStatesOf(trx, tenantId)).map((s) => ({ ...s, force: false }));
    const n = await guarded(trx, 'reconcile', (sp) => recordInSp(sp, tenantId, wanted, new Date()));
    return n ?? 0;
  }));
}
