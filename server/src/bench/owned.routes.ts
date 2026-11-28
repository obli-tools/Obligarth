import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { MASTER_TENANT_ID, isMasterTenant, type BenchOwnedStationView, type BenchOwnedTargetView } from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { switchToNone } from '../db/context';
import { raiseAlert } from '../apple/alerts/service';
import { AppError } from '../middleware/errorHandler';
import { requireTenantCapability } from '../middleware/rbac';
import { checkSecondFactor, sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { WindowLimiter } from '../legacyAgent/limits';
import { BENCH_SURFACE_ACTOR, stationActor } from './actor';
import { cleanLabel } from './stations.service';
import { TargetFields, TargetPatch, assertGroup, insertTarget, patchTarget, removeTarget } from './targets.service';

// =============================================================================
// The stations a client tenant owns (lot BANC-T §3, §5, §6), mounted at /api/bench-stations in the tenant router:
// mdm.bench.manage, 404 in the master tenant (its stations are the platform's: /api/admin/bench-stations).
//   POST   /claim                       { name, verificationCode }: a pending station of the platform claimed by the name
//                                       and the code its screen shows. Order: the limiters FIRST (5 failures an hour per
//                                       user, 20 attempts a day per tenant: 429), THEN a strict second factor (a new
//                                       TOTP step), THEN the definer (bench_claim_station). 201 the station; one 422
//                                       claim_mismatch for every refusal (unknown, wrong code, wrong name, not pending,
//                                       several candidates); 409 claim_conflict when the station targets another tenant
//   GET    /                            the stations of the tenant, their targets and open session
//   PATCH  /:id                         { name }: rename (standard)
//   POST   /:id/suspend                 no second factor (protective): its tokens, provisionings and session closed
//   POST   /:id/resume                  strict second factor; 409 suspendedByPlatform when the platform suspended it
//   POST   /:id/revoke                  simple second factor (protective, final)
//   POST   /:id/targets                 { groupId, rolePolicy, namePrefix, nameTemplate, disableDevOptions }: strict;
//                                       the tenant is the request's, never the body's
//   PATCH  /:id/targets/:groupId        { suspended } alone: no second factor; anything else strict (a resumption is
//                                       allowed here: the exception to D4 of a station the tenant owns; never of a
//                                       target the platform suspended: 409 suspendedByPlatform, Q1)
//   DELETE /:id/targets/:groupId        simple second factor (409 suspendedByPlatform for a target the platform suspended)
//   POST   /:id/sessions/close          the open session of the station closed (protective)
// The sessions open by POST /api/bench-sessions (sessions.routes.ts), as for any station that serves this tenant only.
// The server never reads bench_stations from the tenant's context: every read and every change goes through a definer
// function bounded to the tenant's own stations (not_found for any other).
// =============================================================================

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function body<S extends z.ZodTypeAny>(schema: S, req: Request): z.infer<S> {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  return parsed.data;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);

function stationIdOf(req: Request): string {
  const id = String(req.params.id ?? '').toLowerCase();
  if (!UUID_RE.test(id)) throw new AppError(404, 'Station not found');
  return id;
}

/** The limiters of the claim (in memory: one instance of the server; §6). */
export const claimLimits = {
  failuresPerUser: new WindowLimiter(5, 3_600_000),
  attemptsPerTenant: new WindowLimiter(20, 86_400_000),
  /** Refusals per tenant in 24 hours (times): the platform is alerted at the third, and at each conflict. */
  refusalsPerTenant: new Map<number, number[]>(),
  reset(): void { this.failuresPerUser.reset(); this.attemptsPerTenant.reset(); this.refusalsPerTenant.clear(); },
};

/** Records a refusal of the tenant; the count of its refusals within 24 hours. */
function countRefusal(tenantId: number, now = Date.now()): number {
  const list = (claimLimits.refusalsPerTenant.get(tenantId) ?? []).filter((t) => t > now - 86_400_000);
  list.push(now);
  if (claimLimits.refusalsPerTenant.size > 10_000) claimLimits.refusalsPerTenant.clear();
  claimLimits.refusalsPerTenant.set(tenantId, list);
  return list.length;
}
const REFUSALS_ALERT_AT = 3;

const ClaimBody = z.object({ name: z.string().max(200), verificationCode: z.string().max(20) }).strict();
const RenameBody = z.object({ name: z.string().max(200) }).strict();
const OwnedTargetBody = z.object({ groupId: z.number().int().positive(), ...TargetFields }).strict();

/** The groups of the tenant by id, with their path (root first). */
async function groupPaths(tenantId: number): Promise<Map<number, string>> {
  const rows = await db('device_groups').where({ tenant_id: tenantId }).select('id', 'parent_id', 'name') as Array<{ id: number; parent_id: number | null; name: string }>;
  const byId = new Map(rows.map((r) => [Number(r.id), r]));
  const out = new Map<number, string>();
  for (const r of rows) {
    const names: string[] = [];
    let cur: typeof r | undefined = r;
    for (let i = 0; cur && i < 32; i++) { names.unshift(cur.name); cur = cur.parent_id === null ? undefined : byId.get(Number(cur.parent_id)); }
    out.set(Number(r.id), names.join('/'));
  }
  return out;
}

/** The stations the tenant owns (its definer function), their targets (tenant context) and their session. */
export async function ownedStations(tenantId: number, userId: number, only?: string): Promise<BenchOwnedStationView[]> {
  const r = await db.raw('SELECT * FROM obligarth.bench_tenant_owned_stations(?)', [tenantId]) as { rows: Array<Record<string, any>> };
  const rows = only ? r.rows.filter((s) => String(s.id) === only) : r.rows;
  if (rows.length === 0) return [];
  const targets = await db('bench_station_targets').where({ tenant_id: tenantId }).whereIn('station_id', rows.map((s) => String(s.id)))
    .orderBy('group_id').select('*') as Array<Record<string, any>>;
  const paths = await groupPaths(tenantId);
  const targetView = (t: Record<string, any>): BenchOwnedTargetView => ({
    groupId: Number(t.group_id), groupPath: paths.get(Number(t.group_id)) ?? String(t.group_id), rolePolicy: t.role_policy,
    allowLegacyOwner: t.allow_legacy_owner === true, namePrefix: t.name_prefix ?? null, nameTemplate: t.name_template ?? null,
    disableDevOptions: t.disable_dev_options === true, suspendedAt: iso(t.suspended_at), suspendedByPlatform: t.suspended_by_platform === true,
    createdAt: iso(t.created_at) as string,
  });
  return rows.map((s) => ({
    id: String(s.id), name: s.name, hostname: s.hostname, status: s.status, stationVersion: s.station_version ?? null,
    createdAt: iso(s.created_at) as string, approvedAt: iso(s.approved_at), suspendedAt: iso(s.suspended_at),
    suspendedByPlatform: s.suspended_by_platform === true, revokedAt: iso(s.revoked_at), revokedReason: s.revoked_reason ?? null,
    lastSeenAt: iso(s.last_seen_at), ownerSince: iso(s.owner_since),
    targets: targets.filter((t) => String(t.station_id) === String(s.id)).map(targetView),
    session: s.session_id ? {
      id: String(s.session_id), technician: s.technician ?? null, expiresAt: iso(s.session_expires_at) as string,
      mine: s.session_user_id !== null && s.session_user_id !== undefined && Number(s.session_user_id) === userId,
    } : null,
  }));
}

/** The tenant's own station (404 otherwise): its view. */
async function ownedOne(tenantId: number, userId: number, id: string): Promise<BenchOwnedStationView> {
  const [s] = await ownedStations(tenantId, userId, id);
  if (!s) throw new AppError(404, 'Station not found');
  return s;
}

type SetAction = 'suspend' | 'resume' | 'revoke' | 'rename' | 'close_session';
interface SetOutcome { outcome: string; from_status: string | null; station_name: string | null; tokens: number; provisionings: number }

/** One change of an owned station by its definer function, in the caller's transaction (tenant context). */
async function setOwned(trx: import('knex').Knex.Transaction, tenantId: number, userId: number, id: string, action: SetAction, name: string | null = null): Promise<SetOutcome> {
  const r = await trx.raw('SELECT * FROM obligarth.bench_owned_station_set(?::uuid, ?, ?, ?, ?)', [id, tenantId, userId, action, name]) as { rows: SetOutcome[] };
  const o = r.rows[0];
  if (!o || o.outcome === 'not_found') throw new AppError(404, 'Station not found');
  if (o.outcome === 'platform_suspended') throw new AppError(409, 'The platform suspended this station: only the platform resumes it', 'suspendedByPlatform');
  if (o.outcome === 'bad_state') throw new AppError(409, 'The station cannot do this in its state', 'bad_state');
  return { ...o, tokens: Number(o.tokens ?? 0), provisionings: Number(o.provisionings ?? 0) };
}

/** A refusal of the claim: the tenant's chain (never the code nor the name typed), the platform alerted beyond 3 a day
 *  and at each conflict (with the station, in the master's chain). */
async function claimRefused(req: Request, tenantId: number, reason: 'mismatch' | 'foreign_targets', stationId: string | null): Promise<void> {
  const ctx = await audit.fromRequest(req, tenantId);
  await audit.append({
    tenantId, action: 'bench.station_claim_refused', target: { type: 'bench_station', id: 'claim' }, details: { reason },
  }, ctx);
  const count = countRefusal(tenantId);
  if (reason === 'foreign_targets' || count === REFUSALS_ALERT_AT) {
    if (stationId) {
      const master = await audit.fromRequest(req, MASTER_TENANT_ID);
      await switchToNone(() => audit.append({
        tenantId: MASTER_TENANT_ID, action: 'bench.station_claim_refused', target: { type: 'bench_station', id: stationId },
        details: { reason, stationId, claimTenantId: tenantId },
      }, master, { criticality: 'protective' })).catch(() => { /* protective: spooled by the writer */ });
    }
    await switchToNone(() => raiseAlert(stationId ? stationActor(stationId) : BENCH_SURFACE_ACTOR, MASTER_TENANT_ID, 'bench.claim_refused', {
      discriminant: `tenant:${tenantId}`, params: { count, reason, tenantId }, navigateTo: '/manage/bench-stations',
    }));
  }
}

export function createBenchOwnedRouter(): Router {
  const router = Router();
  router.use((req, _res, next) => { next(isMasterTenant(req.tenantId) ? new AppError(404, 'Not found') : undefined); });
  router.use(requireTenantCapability('mdm.bench.manage'));

  router.post('/claim', wrap(async (req, res) => {
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    // 1. The limiters, before anything else (no second factor spent on a refused attempt).
    const wait = Math.max(claimLimits.failuresPerUser.peek(String(userId)), claimLimits.attemptsPerTenant.peek(String(tenantId)));
    if (wait) { res.setHeader('Retry-After', String(wait)); throw new AppError(429, 'Too many claims: try again later', 'rate_limited'); }
    const b = body(ClaimBody, req);
    const name = cleanLabel(b.name, 100);
    // 2. A strict second factor: a new TOTP step for every attempt (32 bits x 50 candidates x one step each, §6).
    const step = await checkSecondFactor(req, { actionKey: 'bench.station_claim', allowTrustedIp: false, allowDevice: true, requireNewStep: true });
    if (!step.ok) { sendStepUpFailure(res, step); return; }
    const again = claimLimits.attemptsPerTenant.hit(String(tenantId));
    if (again) { res.setHeader('Retry-After', String(again)); throw new AppError(429, 'Too many claims: try again later', 'rate_limited'); }
    // 3. The definer: the comparison of the code happens in SQL, never before the second factor.
    const ctx = await audit.fromRequest(req, tenantId);
    const out = name ? await db.transaction(async (trx) => {
      const r = await trx.raw('SELECT * FROM obligarth.bench_claim_station(?, ?, ?, ?)', [tenantId, userId, name, b.verificationCode]) as
        { rows: Array<{ outcome: string; station_id: string | null }> };
      const o = r.rows[0] ?? { outcome: 'mismatch', station_id: null };
      if (o.outcome === 'claimed') {
        // Critical, in the claim's transaction (a failure gives no station).
        await audit.appendInTx(trx, {
          tenantId, action: 'bench.station_claimed', target: { type: 'bench_station', id: String(o.station_id) },
          details: { stationId: String(o.station_id), name, ownerTenantId: tenantId },
        }, ctx);
      }
      return o;
    }) : { outcome: 'mismatch', station_id: null };
    if (out.outcome === 'mismatch') {
      claimLimits.failuresPerUser.hit(String(userId));
      await claimRefused(req, tenantId, 'mismatch', null);
      throw new AppError(422, 'No pending station has this name and this code', 'claim_mismatch');
    }
    if (out.outcome === 'foreign_targets') {
      await claimRefused(req, tenantId, 'foreign_targets', String(out.station_id));
      throw new AppError(409, 'This station already serves another tenant: ask the platform', 'claim_conflict');
    }
    const stationId = String(out.station_id);
    // The copy of the master's chain (the platform watches the stations of its clients): its own transaction.
    const master = await audit.fromRequest(req, MASTER_TENANT_ID);
    await switchToNone(() => audit.append({
      tenantId: MASTER_TENANT_ID, action: 'bench.station_claimed', target: { type: 'bench_station', id: stationId },
      details: { stationId, name, ownerTenantId: tenantId, claimedBy: userId },
    }, master, { criticality: 'protective' })).catch(() => { /* written in the tenant's chain already */ });
    res.status(201).json({ success: true, data: await ownedOne(tenantId, userId, stationId) });
  }));

  router.get('/', wrap(async (req, res) => {
    res.json({ success: true, data: await ownedStations(req.tenantId!, req.session.userId!) });
  }));

  router.patch('/:id', wrap(async (req, res) => {
    const id = stationIdOf(req);
    const name = cleanLabel(body(RenameBody, req).name, 100);
    if (!name) throw new AppError(400, 'A name is required', 'invalidRequest');
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    const ctx = await audit.fromRequest(req, tenantId);
    await db.transaction(async (trx) => {
      const o = await setOwned(trx, tenantId, userId, id, 'rename', name);
      if (o.outcome === 'done') {
        await audit.appendInTx(trx, { tenantId, action: 'bench.station_renamed', target: { type: 'bench_station', id },
          details: { stationId: id, from: o.station_name, to: name, ownerTenantId: tenantId } }, ctx);
      }
    });
    res.json({ success: true, data: await ownedOne(tenantId, userId, id) });
  }));

  async function changeStatus(req: Request, res: Response, action: 'suspend' | 'resume' | 'revoke'): Promise<void> {
    const id = stationIdOf(req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    if (action !== 'suspend') {
      const step = await checkSecondFactor(req, { actionKey: `bench.station_${action}`, allowTrustedIp: action === 'revoke', allowDevice: true });
      if (!step.ok) { sendStepUpFailure(res, step); return; }
    }
    const auditAction = action === 'resume' ? 'bench.station_resumed' : action === 'suspend' ? 'bench.station_suspended' : 'bench.station_revoked';
    const ctx = await audit.fromRequest(req, tenantId);
    const protective = action !== 'resume';
    let name: string | null = null;
    await db.transaction(async (trx) => {
      if (!protective) {
        // Critical, before the change: read the station first (404 / 409 from the definer itself otherwise).
        await ownedOne(tenantId, userId, id);
        await audit.appendInTx(trx, { tenantId, action: auditAction, target: { type: 'bench_station', id }, details: { stationId: id, ownerTenantId: tenantId } }, ctx);
      }
      const o = await setOwned(trx, tenantId, userId, id, action);
      name = o.station_name;
      if (protective) {
        await audit.appendInTx(trx, {
          tenantId, action: auditAction, target: { type: 'bench_station', id },
          details: { stationId: id, name: o.station_name, from: o.from_status, ownerTenantId: tenantId, enrollmentsRevoked: o.tokens, provisioningsAbandoned: o.provisionings },
        }, ctx, { onFailure: 'spool' });
      }
    });
    // The platform reads the suspensions and revocations of its clients' stations in its own chain (§5).
    if (protective) {
      const master = await audit.fromRequest(req, MASTER_TENANT_ID);
      await switchToNone(() => audit.append({
        tenantId: MASTER_TENANT_ID, action: auditAction, target: { type: 'bench_station', id },
        details: { stationId: id, name, ownerTenantId: tenantId, byOwner: true },
      }, master, { criticality: 'protective' })).catch(() => { /* spooled */ });
    }
    res.json({ success: true, data: await ownedOne(tenantId, userId, id) });
  }

  router.post('/:id/suspend', wrap((req, res) => changeStatus(req, res, 'suspend')));
  router.post('/:id/resume', wrap((req, res) => changeStatus(req, res, 'resume')));
  router.post('/:id/revoke', wrap((req, res) => changeStatus(req, res, 'revoke')));

  router.post('/:id/targets', wrap(async (req, res) => {
    const id = stationIdOf(req);
    const b = body(OwnedTargetBody, req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    const s = await ownedOne(tenantId, userId, id);
    if (s.status === 'revoked') throw new AppError(409, 'The station is revoked', 'bad_state');
    await assertGroup(tenantId, b.groupId, userId);
    const step = await checkSecondFactor(req, { actionKey: 'bench.target_add', allowTrustedIp: false, allowDevice: true });
    if (!step.ok) { sendStepUpFailure(res, step); return; }
    await insertTarget(req, id, s.name, tenantId, b);
    res.status(201).json({ success: true, data: await ownedOne(tenantId, userId, id) });
  }));

  function groupIdOf(req: Request): number {
    const groupId = Number(req.params.groupId);
    if (!Number.isSafeInteger(groupId) || groupId <= 0) throw new AppError(404, 'Target not found');
    return groupId;
  }

  router.patch('/:id/targets/:groupId', wrap(async (req, res) => {
    const id = stationIdOf(req);
    const groupId = groupIdOf(req);
    const b = body(TargetPatch, req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    await ownedOne(tenantId, userId, id);
    if (!(await patchTarget(req, res, id, tenantId, groupId, b, { platform: false, ownedStation: true }))) return;
    res.json({ success: true, data: await ownedOne(tenantId, userId, id) });
  }));

  router.delete('/:id/targets/:groupId', wrap(async (req, res) => {
    const id = stationIdOf(req);
    const groupId = groupIdOf(req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    await ownedOne(tenantId, userId, id);
    const step = await checkSecondFactor(req, { actionKey: 'bench.target_remove', allowTrustedIp: true, allowDevice: true });
    if (!step.ok) { sendStepUpFailure(res, step); return; }
    await removeTarget(req, id, tenantId, groupId, 'tenant');
    res.json({ success: true, data: await ownedOne(tenantId, userId, id) });
  }));

  router.post('/:id/sessions/close', wrap(async (req, res) => {
    const id = stationIdOf(req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    const ctx = await audit.fromRequest(req, tenantId);
    await db.transaction(async (trx) => {
      const o = await setOwned(trx, tenantId, userId, id, 'close_session');
      if (o.outcome === 'done') {
        await audit.appendInTx(trx, { tenantId, action: 'bench.session_closed', target: { type: 'bench_station', id },
          details: { stationId: id, reason: 'owner', ownerTenantId: tenantId } }, ctx, { onFailure: 'spool' });
      }
    });
    res.json({ success: true, data: await ownedOne(tenantId, userId, id) });
  }));

  return router;
}
