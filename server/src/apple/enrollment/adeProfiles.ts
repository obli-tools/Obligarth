import type { Knex } from 'knex';
import { z } from 'zod';
import type { AdeDevicePage, AdeDeviceView, EnrollmentAdeBindingView } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { forEachTenant } from '../../db/tenantContext';
import { JobError, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { AppError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { edgeActorOf } from '../actors';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import { appleTenants } from '../tenants/registry';
import { adeProfileBody, type AdeProfileRow } from './adeRules';

// =============================================================================
// The ADE profiles at Apple (docs: integration-apple-edge §10.6, §11.2; apple-edge §7.4), lot C2:
//   - enrollment.ade-profiles-sync (tenant, key t:<id>, 5 retries): for each active ADE server of the tenant and
//     each ADE enrollment profile not archived whose binding (ade_profile_bindings) is missing or of another
//     version, appleEdge.defineAdeProfile(key, server, usage, { profile, default }) outside any transaction, then
//     the binding (Apple's profile UUID, version, date, error). Then the assignments an operator chose
//     (apple_ade_devices.wanted_profile_id): a device whose Apple profile is not the binding of its wanted profile
//     on its server is assigned it (grouped by server and usage, 1 000 serial numbers a call); a device without
//     choice whose Apple profile is another of ours (a choice withdrawn, its profile archived) gets the default
//     profile back. The other devices receive the default profile from apple-edge itself. Sent by the saving
//     or the archiving of an ADE profile, the choice of a device's profile, ade.token_activated, and every day
//     (enrollment.ade-profiles-sync-all). An archived profile is not removed at Apple (no deletion there).
//   - the console's view of the ADE devices and the choice of their enrollment profile.
// Serial numbers of Apple Business stay in the database: never in a log, a job payload nor an alert.
// =============================================================================

const TenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();
type Tenant = z.infer<typeof TenantPayload>;
let syncJob: JobHandle<Tenant> | null = null;

/** Serial numbers of one assignment call (apple-edge's MaxSerials). */
const ASSIGN_CHUNK = 1_000;
/** Rounds of one run: a profile saved during a run is defined by the next round. */
const MAX_ROUNDS = 3;
const DEVICE_PAGE = 200;

/** Asks a synchronisation of the tenant's ADE profiles (after the caller's commit). Never throws. */
export async function requestAdeProfilesSync(tenantId: number): Promise<void> {
  if (!syncJob || config.apple.mode !== 'on') return;
  try {
    await syncJob.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
  } catch (err) {
    logger.warn({ tenantId, code: (err as { code?: unknown })?.code ?? null }, 'enrollment.ade-profiles-sync not sent');
  }
}

/** The same, inside the caller's transaction (an outbox handler: ade.token_activated). */
export async function sendAdeProfilesSyncInTx(trx: Knex.Transaction, tenantId: number): Promise<void> {
  if (!syncJob || config.apple.mode !== 'on') return;
  await syncJob.sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
}

interface Binding { profile_id: string; ade_token_id: string; profile_uuid: string | null; defined_version: number | null }

async function readState(trx: Knex.Transaction, tenantId: number) {
  const tokens = (await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, state: 'active' }).whereNull('removed_at')
    .orderBy('created_at').pluck('id') as string[]).map(String);
  const profiles = await trx('enrollment_profiles').where({ tenant_id: tenantId, method: 'ade' }).whereNull('archived_at')
    .orderBy('created_at').select('id', 'name', 'usage', 'version', 'is_default', 'ownership', 'settings') as AdeProfileRow[];
  const bindings = await trx('ade_profile_bindings').where({ tenant_id: tenantId })
    .select('profile_id', 'ade_token_id', 'profile_uuid', 'defined_version') as Binding[];
  const t = await trx('tenants').where({ id: tenantId }).first('uuid') as { uuid: string };
  return { tokens, profiles, bindings, tenantUuid: String(t.uuid) };
}

async function recordBinding(ctx: JobContext<Tenant>, tenantId: number, profileId: string, tokenId: string,
  ok: { profileUuid: string; version: number } | { error: string }): Promise<void> {
  await ctx.withTenant(async (trx) => {
    const base = { tenant_id: tenantId, profile_id: profileId, ade_token_id: tokenId };
    if ('error' in ok) {
      await trx('ade_profile_bindings').insert({ ...base, last_error_code: ok.error.slice(0, 64) })
        .onConflict(['tenant_id', 'profile_id', 'ade_token_id']).merge({ last_error_code: ok.error.slice(0, 64) });
      return;
    }
    const cols = { profile_uuid: ok.profileUuid.slice(0, 64), defined_version: ok.version, defined_at: new Date(), last_error_code: null };
    await trx('ade_profile_bindings').insert({ ...base, ...cols }).onConflict(['tenant_id', 'profile_id', 'ade_token_id']).merge(cols);
  });
}

/** enrollment.ade-profiles-sync. */
async function syncTenant(ctx: JobContext<Tenant>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const base = config.apple.mdmPublicBase;
  if (config.apple.mode !== 'on' || !base) return { output: { skipped: 'integration_off' } };
  const key = await ctx.withTenant((trx) => appleTenants.keyOrNull(tenantId, trx));
  if (!key) return { output: { skipped: 'not_provisioned' } };
  const edge = { actor: edgeActorOf(ctx.dbActor) };
  let defined = 0;
  let failed = 0;
  let transient = 0;
  const tried = new Set<string>();
  for (let round = 0; round < MAX_ROUNDS; round++) {
    ctx.throwIfAborted();
    const st = await ctx.withTenant((trx) => readState(trx, tenantId));
    const todo: Array<{ token: string; p: AdeProfileRow }> = [];
    for (const token of st.tokens) {
      for (const p of st.profiles) {
        const b = st.bindings.find((x) => x.profile_id === p.id && x.ade_token_id === token);
        if (b && b.profile_uuid && Number(b.defined_version) === Number(p.version)) continue;
        const k = `${token}:${p.id}:${p.version}`;
        if (tried.has(k)) continue;
        tried.add(k);
        todo.push({ token, p });
      }
    }
    if (todo.length === 0) break;
    for (const { token, p } of todo) {
      ctx.throwIfAborted();
      try {
        const r = await appleEdge.defineAdeProfile(key, token, p.usage, { profile: adeProfileBody(base, key, st.tenantUuid, p), default: p.is_default === true }, edge);
        await recordBinding(ctx, tenantId, p.id, token, { profileUuid: String(r.profile_uuid), version: Number(p.version) });
        defined++;
      } catch (err) {
        if (!isAppleEdgeError(err)) throw err;
        await recordBinding(ctx, tenantId, p.id, token, { error: String(err.code) });
        if (err.retryable) transient++; else failed++;
        logger.warn({ tenantId, code: err.code, status: err.status }, 'ADE profile not defined at Apple');
      }
    }
  }
  const assigned = await assignWanted(ctx, tenantId, key, edge);
  transient += assigned.transient;
  failed += assigned.failed;
  if (transient > 0) throw new JobError('ade_unavailable', `${transient} call(s) to apple-edge to retry`);
  return { output: { defined, assigned: assigned.serials, failed } };
}

/** The assignments the operators chose (§10.6), grouped by server and usage. */
async function assignWanted(ctx: JobContext<Tenant>, tenantId: number, key: string, edge: { actor: string }):
  Promise<{ serials: number; failed: number; transient: number }> {
  const groups = await ctx.withTenant(async (trx) => {
    const st = await readState(trx, tenantId);
    const byId = new Map(st.profiles.map((p) => [p.id, p]));
    const def = st.profiles.find((p) => p.is_default);
    const uuidOf = (profileId: string, token: string): string | null =>
      st.bindings.find((b) => b.profile_id === profileId && b.ade_token_id === token)?.profile_uuid ?? null;
    const ours = new Map<string, Set<string>>();
    for (const b of st.bindings) if (b.profile_uuid) (ours.get(b.ade_token_id) ?? ours.set(b.ade_token_id, new Set()).get(b.ade_token_id)!).add(b.profile_uuid);
    const devices = await trx('apple_ade_devices').where({ tenant_id: tenantId }).whereNull('removed_at')
      .whereIn('ade_token_id', st.tokens).orderBy('id')
      .select('serial_number', 'ade_token_id', 'profile_uuid', 'wanted_profile_id') as
      Array<{ serial_number: string; ade_token_id: string; profile_uuid: string | null; wanted_profile_id: string | null }>;
    const out = new Map<string, { token: string; usage: string; serials: string[] }>();
    const add = (token: string, usage: string, serial: string) => {
      const k = `${token}:${usage}`;
      (out.get(k) ?? out.set(k, { token, usage, serials: [] }).get(k)!).serials.push(serial);
    };
    for (const d of devices) {
      const token = String(d.ade_token_id);
      const wanted = d.wanted_profile_id ? byId.get(String(d.wanted_profile_id)) : undefined;
      if (wanted) {
        const u = uuidOf(wanted.id, token);
        if (u && d.profile_uuid !== u) add(token, wanted.usage, d.serial_number);
        continue;
      }
      // No choice (or its profile archived): back to the default profile when Apple holds another of ours.
      if (!def) continue;
      const u = uuidOf(def.id, token);
      if (u && d.profile_uuid && d.profile_uuid !== u && ours.get(token)?.has(d.profile_uuid)) add(token, def.usage, d.serial_number);
    }
    return [...out.values()];
  });
  let serials = 0;
  let failed = 0;
  let transient = 0;
  for (const g of groups) {
    for (let i = 0; i < g.serials.length; i += ASSIGN_CHUNK) {
      ctx.throwIfAborted();
      const chunk = g.serials.slice(i, i + ASSIGN_CHUNK);
      try {
        await appleEdge.assignAdeProfile(key, g.token, { usage: g.usage, serials: chunk }, edge);
        serials += chunk.length;
      } catch (err) {
        if (!isAppleEdgeError(err)) throw err;
        if (err.retryable) transient++; else failed++;
        logger.warn({ tenantId, code: err.code, status: err.status, count: chunk.length }, 'ADE profile not assigned');
      }
    }
  }
  return { serials, failed, transient };
}

/** enrollment.ade-profiles-sync-all: the daily pass, one job per tenant that has an active ADE server. */
async function syncAll(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let tenants = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const any = await db('tenant_apple_ade_tokens').where({ tenant_id: tenantId, state: 'active' }).whereNull('removed_at').first('id');
    if (!any) return;
    await (syncJob as JobHandle<Tenant>).send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
    tenants++;
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { tenants } };
}

let registered = false;

export function registerAdeProfileJobs(): void {
  if (registered) return;
  registered = true;
  syncJob = registerJob({
    name: 'enrollment.ade-profiles-sync',
    scope: 'tenant',
    description: 'Define the ADE enrollment profiles of a tenant at Apple, and assign the profiles its operators chose',
    payload: TenantPayload,
    // stately (not exclusive): a profile saved while a run is active queues the next run instead of being dropped.
    policy: 'stately',
    retry: { limit: 5, delaySeconds: 60, backoff: true, maxDelaySeconds: 3600 },
    timeoutSeconds: 600,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: 60,
    handler: syncTenant,
  });
  registerJob({
    name: 'enrollment.ade-profiles-sync-all',
    scope: 'platform',
    description: 'Daily: the tenants whose ADE profiles are defined at Apple again when they changed',
    payload: z.object({}).strict(),
    policy: 'exclusive',
    // APPLE_EDGE_MODE=off: no ADE server, the daily pass is not scheduled.
    ...(config.apple.mode === 'on' ? { schedule: { cron: '40 3 * * *' } } : {}),
    retry: { limit: 2, delaySeconds: 300, backoff: true, maxDelaySeconds: 3600 },
    timeoutSeconds: 600,
    pollSeconds: 300,
    deadLetter: false, trackStatus: 'queue', manualRun: true, keepFinishedSeconds: 172_800, keepPendingSeconds: 86_400,
    handler: syncAll,
  });
}

// ── Console: bindings, ADE devices, choice of a device's profile ──────────────────

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);

/** The bindings of ADE profiles on the active servers of the tenant, by profile. */
export async function bindingsByProfile(q: Knex | Knex.Transaction, tenantId: number): Promise<Map<string, EnrollmentAdeBindingView[]>> {
  const rows = await q('tenant_apple_ade_tokens as k')
    .join('enrollment_profiles as p', 'p.tenant_id', 'k.tenant_id')
    .leftJoin('ade_profile_bindings as b', function joinBinding() {
      this.on('b.tenant_id', '=', 'k.tenant_id').andOn('b.ade_token_id', '=', 'k.id').andOn('b.profile_id', '=', 'p.id');
    })
    .where({ 'k.tenant_id': tenantId, 'p.tenant_id': tenantId, 'p.method': 'ade', 'k.state': 'active' }).whereNull('k.removed_at')
    .orderBy(['k.created_at', 'k.id'])
    .select('p.id as profile_id', 'p.version', 'k.id as token_id', 'k.label', 'k.server_name', 'b.profile_uuid', 'b.defined_version', 'b.defined_at',
      'b.last_error_code') as Array<Record<string, any>>;
  const out = new Map<string, EnrollmentAdeBindingView[]>();
  for (const r of rows) {
    const list = out.get(String(r.profile_id)) ?? [];
    list.push({
      adeTokenId: String(r.token_id), serverName: String(r.server_name || r.label || 'ADE'), profileUuid: r.profile_uuid ?? null,
      definedVersion: r.defined_version === null || r.defined_version === undefined ? null : Number(r.defined_version),
      definedAt: iso(r.defined_at), lastErrorCode: r.last_error_code ?? null,
      upToDate: !!r.profile_uuid && Number(r.defined_version) === Number(r.version),
    });
    out.set(String(r.profile_id), list);
  }
  return out;
}

/** The ADE devices of the tenant, newest first; `q`: a part of the serial number; `cursor`: the last id seen. */
export async function listAdeDevices(q: Knex | Knex.Transaction, tenantId: number, f: { q?: string; cursor?: number; removed?: boolean }):
  Promise<AdeDevicePage> {
  let qb = q('apple_ade_devices as d')
    .join('tenant_apple_ade_tokens as k', function joinToken() { this.on('k.id', '=', 'd.ade_token_id').andOn('k.tenant_id', '=', 'd.tenant_id'); })
    .leftJoin('enrollment_profiles as w', function joinWanted() { this.on('w.id', '=', 'd.wanted_profile_id').andOn('w.tenant_id', '=', 'd.tenant_id'); })
    .leftJoin('ade_profile_bindings as b', function joinApplied() {
      this.on('b.tenant_id', '=', 'd.tenant_id').andOn('b.ade_token_id', '=', 'd.ade_token_id').andOn('b.profile_uuid', '=', 'd.profile_uuid');
    })
    .leftJoin('enrollment_profiles as a', function joinAppliedProfile() { this.on('a.id', '=', 'b.profile_id').andOn('a.tenant_id', '=', 'b.tenant_id'); })
    .where('d.tenant_id', tenantId);
  if (!f.removed) qb = qb.whereNull('d.removed_at');
  if (f.q) qb = qb.whereRaw('d.serial_number LIKE ?', [`%${f.q.toUpperCase().replace(/[^A-Z0-9]/g, '')}%`]);
  if (f.cursor) qb = qb.where('d.id', '<', f.cursor);
  const rows = await qb.orderBy('d.id', 'desc').limit(DEVICE_PAGE + 1)
    .select('d.id', 'd.ade_token_id', 'k.label', 'k.server_name', 'd.serial_number', 'd.model', 'd.description', 'd.device_family', 'd.os',
      'd.profile_status', 'd.profile_assign_time', 'd.wanted_profile_id', 'w.name as wanted_name', 'a.id as applied_id', 'a.name as applied_name',
      'd.device_id', 'd.first_seen_at', 'd.removed_at') as Array<Record<string, any>>;
  const page = rows.slice(0, DEVICE_PAGE);
  const items: AdeDeviceView[] = page.map((r) => ({
    id: Number(r.id), adeTokenId: String(r.ade_token_id), serverName: String(r.server_name || r.label || 'ADE'), serialNumber: String(r.serial_number),
    model: r.model ?? null, description: r.description ?? null, deviceFamily: r.device_family ?? null, os: r.os ?? null,
    profileStatus: r.profile_status ?? null, profileAssignTime: iso(r.profile_assign_time),
    appliedProfileId: r.applied_id ? String(r.applied_id) : null, appliedProfileName: r.applied_name ?? null,
    wantedProfileId: r.wanted_profile_id ? String(r.wanted_profile_id) : null, wantedProfileName: r.wanted_name ?? null,
    deviceId: r.device_id === null || r.device_id === undefined ? null : Number(r.device_id),
    firstSeenAt: iso(r.first_seen_at) ?? new Date(0).toISOString(), removedAt: iso(r.removed_at),
  }));
  return { items, nextCursor: rows.length > DEVICE_PAGE && page.length ? String(page[page.length - 1].id) : null };
}

/** The enrollment profile an operator chooses for an ADE device (null: the default one). The facts of the audit
 *  entry. */
export async function setWantedProfile(trx: Knex.Transaction, tenantId: number, id: number, profileId: string | null):
  Promise<{ previous: string | null; adeTokenId: string }> {
  const d = await trx('apple_ade_devices').where({ tenant_id: tenantId, id }).whereNull('removed_at').forUpdate()
    .first('wanted_profile_id', 'ade_token_id') as { wanted_profile_id: string | null; ade_token_id: string } | undefined;
  if (!d) throw new AppError(404, 'ADE device not found', 'adeDeviceNotFound');
  if (profileId !== null) {
    const p = await trx('enrollment_profiles').where({ tenant_id: tenantId, id: profileId, method: 'ade' }).whereNull('archived_at').first('id');
    if (!p) throw new AppError(404, 'Enrollment profile not found', 'enrollmentProfileNotFound');
  }
  await trx('apple_ade_devices').where({ tenant_id: tenantId, id }).update({ wanted_profile_id: profileId, updated_at: new Date() });
  return { previous: d.wanted_profile_id ? String(d.wanted_profile_id) : null, adeTokenId: String(d.ade_token_id) };
}
