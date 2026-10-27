import type { Knex } from 'knex';
import { db } from '../db';
import { asNone, asTenant } from '../db/context';
import { forEachTenant } from '../db/tenantContext';
import { tenantFrozen } from '../guard/frozen';
import { JobError, type JobContext, type JobResult } from '../jobs';
import { restrictionFloor, restrictionService } from '../services/restriction.service';
import { legacyAgentCommands } from './commands';
import { instanceSettings } from './config';

// =============================================================================
// Automatic update of the bridge agents (lot AGENT-RU T1): the job
// legacy-agent.auto-update (every 10 minutes) puts an agent.update in the
// queue of the enrolled agents older than the latest version embedded in the
// server image and not withdrawn (origin 'bundled': the owners chose it by
// running the update of the instance; an uploaded version is only ever pushed
// by a command of the console), in batches, at the pace of the instance
// settings (autoUpdate, on by default; autoUpdatePerHour, 500 by default, 1 to
// 5 000; turning it on or raising the pace asks for a strict second factor):
//   pace       at most autoUpdatePerHour commands of this job over the last
//              hour (counted in the queue, every tenant), at most a sixth of
//              it per run;
//   who        an agent of the tenant, enrolled, not revoked, of a lower
//              versionCode, that interrogated in the last 24 hours (a silent
//              agent is left for when it comes back); none with an open
//              agent.update (a withdrawn version's excepted: it is never
//              delivered), none whose update to this very version was queued
//              in the last 24 hours (a refusal, a failure or an expiry is
//              taken up again the next day, not every run);
//   order      the agents that install silently first (device administrator
//              active and Knox licensed: AndroidActions.install goes through
//              Knox ApplicationPolicy.updateApplication, no prompt; else the
//              installer of the system asks the user), then by the most recent
//              interrogation, every tenant together;
//   guards     a frozen tenant gets nothing (no row held by the freeze); the
//              restrictions matrix of the tenant: a level above 'none' on
//              legacy_agent.update (a person would be asked: a second factor
//              or an approval) sets the device aside, in the query itself
//              (before its limit: the devices set aside never hide the others
//              from a run; same scope as restrictionService.getLevelFor);
//   queue      legacyAgentCommands.enqueue, origin 'system', actor
//              j:legacy-agent.auto-update: one batch per tenant and run, its
//              audit entry legacy_agent.command_queued in the transaction.
// The agent checks the version again (higher than its own, signer pinned,
// SHA-256) before installing (§8.6).
// =============================================================================

export const AUTO_UPDATE_JOB = 'legacy-agent.auto-update';
export const AUTO_UPDATE_ACTOR = `j:${AUTO_UPDATE_JOB}`;
export const AUTO_UPDATE_RUNS_PER_HOUR = 6;
const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
const RESTRICTION_KEY = 'legacy_agent.update';

export type AutoUpdateOutput = {
  state: 'off' | 'noRelease' | 'budgetSpent' | 'done';
  versionCode: number | null;
  releaseId: string | null;
  /** The commands this run could queue. */
  budget: number;
  queued: number;
  /** Of which on agents that install silently. */
  silentInstall: number;
  /** Tenants with agents to update, frozen. */
  frozenTenants: number;
  /** Agents to update set aside by the restrictions matrix. */
  restrictedDevices: number;
};

interface Release { id: string; version_code: number; version_name: string; sha256: string; size_bytes: number }
interface Candidate { tenantId: number; deviceId: number; silent: boolean; lastPoll: number }

/** The target of the automatic update: the latest version embedded in the server image and not withdrawn (the catalog
 *  is readable in every context). An uploaded version is never a target. */
export async function latestBundledRelease(q: Knex | Knex.Transaction = db): Promise<Release | undefined> {
  return q('legacy_agent_releases').where('origin', 'bundled').whereNull('withdrawn_at').orderBy('version_code', 'desc')
    .first('id', 'version_code', 'version_name', 'sha256', 'size_bytes') as Promise<Release | undefined>;
}

/** What the restrictions matrix of a tenant holds for legacy_agent.update: nothing, every device (a floor, or an
 *  entry on the whole tenant), or the devices of a scope (include: those listed; exclude: the others). */
type Scope = { kind: 'scope'; mode: 'include' | 'exclude'; deviceIds: number[]; groupIds: number[] };
type Gate = { kind: 'none' } | { kind: 'all' } | Scope;

async function gateOf(tenantId: number): Promise<Gate> {
  if (restrictionFloor(RESTRICTION_KEY)) return { kind: 'all' };
  const entry = (await restrictionService.getMap(tenantId))[RESTRICTION_KEY];
  if (!entry) return { kind: 'none' };
  if (entry.scope.mode === 'all') return { kind: 'all' };
  return { kind: 'scope', mode: entry.scope.mode, deviceIds: entry.scope.deviceIds ?? [], groupIds: entry.scope.groupIds ?? [] };
}

/** Keeps the devices the scope holds (`held` true) or lets through (false). A device is listed by its id, or by its
 *  group or an ancestor of it (device_group_closure), as restrictionService.getLevelFor decides it for one device. */
function gated(qb: Knex.QueryBuilder, scope: Scope, held: boolean): void {
  const listed = function listed(this: Knex.QueryBuilder): void {
    this.whereIn('d.id', scope.deviceIds).orWhereExists(function viaGroup() {
      this.select(db.raw('1')).from('device_group_closure as gc').whereRaw('gc.descendant_id = d.group_id').whereIn('gc.ancestor_id', scope.groupIds);
    });
  };
  if ((scope.mode === 'include') === held) qb.where(listed); else qb.whereNot(listed);
}

/** The agents of a tenant to bring to `target`: enrolled, older, interrogated in the last 24 hours, no open update,
 *  none to this version queued in the last 24 hours. */
function candidatesQuery(tenantId: number, target: Release): Knex.QueryBuilder {
  const now = Date.now();
  return db('legacy_agent_devices as a')
    .join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where('a.tenant_id', tenantId).whereNull('a.revoked_at').where('d.enrollment_state', 'enrolled').where('d.management_channel', 'legacy_agent')
    .where('a.agent_version_code', '<', Number(target.version_code))
    .where('a.last_poll_at', '>=', new Date(now - DAY_MS))
    .whereNotExists(function open() {
      this.select(db.raw('1')).from('legacy_agent_commands as c')
        .whereRaw('c.tenant_id = a.tenant_id AND c.device_id = a.device_id').where('c.request_type', 'agent.update').whereIn('c.state', ['pending', 'sent'])
        .whereNotExists(function withdrawn() {
          this.select(db.raw('1')).from('legacy_agent_releases as r').whereRaw("r.id::text = c.params->>'releaseId'").whereNotNull('r.withdrawn_at');
        });
    })
    .whereNotExists(function recent() {
      this.select(db.raw('1')).from('legacy_agent_commands as c')
        .whereRaw('c.tenant_id = a.tenant_id AND c.device_id = a.device_id').where('c.request_type', 'agent.update')
        .whereRaw("(c.params->>'versionCode')::bigint = ?", [Number(target.version_code)]).where('c.created_at', '>', new Date(now - DAY_MS));
    });
}

/** The candidates the matrix lets through, silent installers first, then by the most recent interrogation. */
async function candidatesOf(tenantId: number, target: Release, limit: number, gate: Gate): Promise<Candidate[]> {
  if (gate.kind === 'all') return [];
  const q = candidatesQuery(tenantId, target);
  if (gate.kind === 'scope') gated(q, gate, false);
  const rows = await q
    .orderByRaw("(a.admin_active AND a.knox_state = 'licensed') DESC, a.last_poll_at DESC, d.id")
    .limit(limit)
    .select('d.id', 'a.last_poll_at', db.raw("(a.admin_active AND a.knox_state = 'licensed') AS silent")) as
    Array<{ id: number; last_poll_at: Date; silent: boolean }>;
  return rows.map((r) => ({ tenantId, deviceId: Number(r.id), silent: r.silent === true, lastPoll: new Date(r.last_poll_at).getTime() }));
}

/** The commands of this job queued in the tenant over the last hour. */
async function queuedLastHour(tenantId: number): Promise<number> {
  const row = await db('legacy_agent_commands').where({ tenant_id: tenantId, request_type: 'agent.update', origin: 'system', actor: AUTO_UPDATE_ACTOR })
    .where('created_at', '>', new Date(Date.now() - HOUR_MS)).count<{ n: string }[]>('* as n').first();
  return Number(row?.n ?? 0);
}

/** The candidates the matrix holds (a person would be asked), counted for the output. */
async function heldCount(tenantId: number, target: Release, gate: Gate): Promise<number> {
  if (gate.kind === 'none') return 0;
  const q = candidatesQuery(tenantId, target);
  if (gate.kind === 'scope') gated(q, gate, true);
  const row = await q.count<{ n: string }[]>('* as n').first();
  return Number(row?.n ?? 0);
}

const bySilentThenRecent = (a: Candidate, b: Candidate): number =>
  Number(b.silent) - Number(a.silent) || b.lastPoll - a.lastPoll || a.tenantId - b.tenantId || a.deviceId - b.deviceId;

export async function autoUpdate(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  const out: AutoUpdateOutput = {
    state: 'done', versionCode: null, releaseId: null, budget: 0, queued: 0, silentInstall: 0, frozenTenants: 0, restrictedDevices: 0,
  };
  const settings = await instanceSettings(true);
  if (!settings.autoUpdate) return { output: { ...out, state: 'off' } };
  const target = await asNone(ctx.dbActor, () => latestBundledRelease());
  if (!target) return { output: { ...out, state: 'noRelease' } };
  out.versionCode = Number(target.version_code);
  out.releaseId = String(target.id);
  const perRun = Math.ceil(settings.autoUpdatePerHour / AUTO_UPDATE_RUNS_PER_HOUR);
  // Read more than a run takes: the other tenants compete for the same budget.
  const fetch = perRun * 2 + 50;

  let lastHour = 0;
  const found: Candidate[] = [];
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    lastHour += await queuedLastHour(tenantId);
    const gate = await gateOf(tenantId);
    const list = await candidatesOf(tenantId, target, fetch, gate);
    const held = await heldCount(tenantId, target, gate);
    if (list.length === 0 && held === 0) return;
    if (await tenantFrozen(null, tenantId, 'legacy_agent')) { out.frozenTenants++; return; }
    out.restrictedDevices += held;
    found.push(...list);
  });

  out.budget = Math.max(0, Math.min(perRun, settings.autoUpdatePerHour - lastHour));
  if (out.budget === 0) out.state = 'budgetSpent';
  const chosen = found.sort(bySilentThenRecent).slice(0, out.budget);
  // One batch per tenant, in the order of the first agent each brings (the most urgent batch is queued first).
  const batches = new Map<number, Candidate[]>();
  for (const c of chosen) batches.set(c.tenantId, [...(batches.get(c.tenantId) ?? []), c]);
  const params = { releaseId: String(target.id), versionCode: Number(target.version_code), sha256: String(target.sha256), size: Number(target.size_bytes) };
  let enqueueFailed = 0;
  for (const [tenantId, list] of batches) {
    ctx.throwIfAborted();
    try {
      const o = await asTenant(tenantId, ctx.dbActor, () => db.transaction((trx) => legacyAgentCommands.enqueue(trx, {
        tenantId, requestType: 'agent.update', deviceIds: list.map((c) => c.deviceId), params, origin: 'system', actor: AUTO_UPDATE_ACTOR,
        reason: `Automatic update of the agent to ${target.version_name}`,
      })));
      const refused = new Set(o.refused.map((r) => r.deviceId));
      out.queued += o.targets;
      out.silentInstall += list.filter((c) => c.silent && !refused.has(c.deviceId)).length;
    } catch (err) {
      enqueueFailed++;
      ctx.log.warn({ tenantId, message: (err as Error)?.message?.slice(0, 200) }, 'legacy agent: automatic update not queued in a tenant');
    }
  }
  if (failed + enqueueFailed > 0) {
    ctx.log.warn({ ...out }, 'legacy agent: automatic update partly done');
    throw new JobError('partial_failure', `${failed + enqueueFailed} tenant(s) failed`);
  }
  return { output: { ...out } };
}
