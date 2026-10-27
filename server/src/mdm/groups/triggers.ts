import type { Knex } from 'knex';
import { RULE_FIELDS, ruleFieldsOf, validateRule, type Ownership, type RuleNode } from '@obligarth/shared';
import { db } from '../../db';
import { defaultRuntime } from '../../jobs';
import { logger } from '../../utils/logger';
import { evaluateGroupsJob } from './jobs';

// =============================================================================
// Wakes of the incremental computation of the dynamic groups (P0-5 T5, §4.3). The marking triggers of the base
// (migration p05_smart_group_marking) guarantee no device is forgotten: requestGroupEvaluation only wakes the queue
// mdm.groups.evaluate of the tenant, sent in the caller's transaction like requestDeviceResolution (the job exists if
// and only if the transaction commits), next to every request of the resolution of the inventory, the registry and
// the end users: the ingestors of Apple, Android and the bridge agent, the DDM status channel, the ownership, the
// group of a device, the end users (assignment, profile, departure, purge), the PATCH of a device, the onboarding, the
// departure from management, a static group moved or deleted. It sends nothing while nothing is marked (the devices
// given, or the tenant), nor in a process without the MDM module; outside a server that runs the job runtime (a CLI,
// a test that does not start it), a wake is logged and dropped: the hourly schedule empties what is left.
// A publication of a privacy profile (P0-13) changes what a rule sees of the devices of its ownership (their serial
// number, their applications): onPrivacyProfilePublished marks them, for the groups that read it.
// =============================================================================

const pgIntArray = (ids: readonly number[]): string => `{${ids.map(Number).filter((n) => Number.isSafeInteger(n)).join(',')}}`;

/** The promise of the outermost transaction of `trx` (a nested transaction ends before its outer one commits). */
function outermostExecution(trx: Knex.Transaction): Promise<unknown> | null {
  type Nested = Knex.Transaction & { parentTransaction?: Knex.Transaction };
  let t = trx as Nested;
  for (let depth = 0; depth < 16 && t.parentTransaction; depth++) t = t.parentTransaction as Nested;
  return t.executionPromise ?? null;
}

/**
 * A wake sent in a transaction and absorbed by a job already queued is sent again once the transaction is committed
 * (never when it rolls back): the queued job may start before this transaction commits and miss its markings.
 */
function resendAfterCommit(trx: Knex.Transaction, send: () => Promise<unknown>, tenantId: number): void {
  const committed = outermostExecution(trx);
  if (!committed) return;
  void committed.then(() => send(), () => undefined)
    .catch((err) => logger.warn({ tenantId, err: { message: (err as Error)?.message } }, 'dynamic groups not woken again after the commit'));
}

/**
 * Wakes the incremental computation of the tenant's dynamic groups when something is marked: one of `deviceIds`
 * when given, any device of the tenant otherwise. Returns the job's id, or null (nothing marked, absorbed, no runtime).
 */
export async function requestGroupEvaluation(trx: Knex.Transaction | null, tenantId: number, deviceIds?: readonly number[]): Promise<string | null> {
  const job = evaluateGroupsJob();
  if (!job) return null;
  const marked = (trx ?? db)('smart_group_dirty').where({ tenant_id: tenantId });
  if (deviceIds) {
    const ids = [...new Set(deviceIds.filter((n) => Number.isSafeInteger(n) && n > 0))];
    if (!ids.length) return null;
    marked.whereRaw('device_id = ANY(?::integer[])', [pgIntArray(ids)]);
  }
  if (!(await marked.first('device_id'))) return null;
  if (!defaultRuntime.isStarted()) {
    logger.warn({ tenantId }, 'dynamic groups not woken: the job runtime is not started');
    return null;
  }
  const opts = { singletonKey: `t:${tenantId}`, tenantId };
  if (!trx) return job.send({ tenantId }, opts);
  const id = await job.sendInTx(trx, { tenantId }, opts);
  if (id === null) resendAfterCommit(trx, () => job.send({ tenantId }, opts), tenantId);
  return id;
}

/**
 * A privacy profile published (P0-13, in the transaction of its publication): the devices of the tenant under
 * management with this ownership are marked for the groups whose rule compares what the profile decides (the serial
 * number: 'facts'; the applications: 'apps'), and the queue is woken. Returns the devices marked.
 */
export async function onPrivacyProfilePublished(trx: Knex.Transaction, p: { tenantId: number; ownership: Ownership }): Promise<number> {
  const groups = await trx('smart_groups').where({ tenant_id: p.tenantId }).whereNot('state', 'error').select('rule') as Array<{ rule: unknown }>;
  const reasons = new Set<string>();
  for (const g of groups) {
    const rule = (typeof g.rule === 'string' ? JSON.parse(g.rule) : g.rule) as RuleNode;
    if (validateRule(rule).length > 0) continue;
    for (const k of ruleFieldsOf(rule)) if (RULE_FIELDS[k].privacy !== undefined) reasons.add(RULE_FIELDS[k].family);
  }
  if (reasons.size === 0) return 0;
  const res = await trx.raw(`
    INSERT INTO smart_group_dirty AS d (tenant_id, device_id, reasons)
    SELECT dv.tenant_id, dv.id, ?::text[] FROM devices dv
     WHERE dv.tenant_id = ?::integer AND dv.ownership = ?::text AND dv.enrollment_state <> 'unenrolled'
    ON CONFLICT (tenant_id, device_id) DO UPDATE
      SET reasons = ARRAY(SELECT DISTINCT r FROM unnest(d.reasons || EXCLUDED.reasons) AS u(r) ORDER BY r)
      WHERE NOT d.reasons @> EXCLUDED.reasons`,
  [`{${[...reasons].sort().join(',')}}`, p.tenantId, p.ownership]) as { rowCount?: number };
  await requestGroupEvaluation(trx, p.tenantId);
  return Number(res.rowCount ?? 0);
}
