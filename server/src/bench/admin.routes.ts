import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import {
  MASTER_TENANT_ID, isMasterTenant, normaliseBenchVerificationCode,
  type BenchStationDetail, type BenchStationView, type BenchTargetView,
} from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { asTenant, switchToIdentity, userActor } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { checkSecondFactor, sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { signersFromEnv } from '../legacyAgent/config';
import { releaseView } from '../legacyAgent/routes';
import { installerState, servedRelease } from './apk.service';
import { cleanLabel, planStationTransition, stationVerificationCode, type StationAction } from './stations.service';
import { TargetFields, TargetPatch, assertGroup, insertTarget, patchTarget, removeTarget } from './targets.service';

// =============================================================================
// The bench stations in the console of the platform (lot BANC §3.3, §3.7, §3.12), mounted at /api/admin/bench-stations:
// the master tenant (404 elsewhere), a platform administrator (403 otherwise).
//   GET    /                                   the stations (pending first), their targets and enrolled devices counted
//   GET    /:id                                one station and its targets in every tenant
//   PATCH  /:id                                { name }: rename (standard)
//   POST   /:id/approve                        { verificationCode }: the code read on the station's screen (the console
//                                              never shows it), checked by the server (422 verification_mismatch), then
//                                              a strict second factor
//   POST   /:id/suspend                        no second factor (protective): its tokens and provisionings closed
//   POST   /:id/resume                         strict second factor
//   POST   /:id/revoke                         simple second factor (protective, final): the same cascade
//   POST   /:id/targets                        { tenantId, groupId, rolePolicy, namePrefix, disableDevOptions }: strict
//   PATCH  /:id/targets/:tenantId/:groupId     { suspended } alone: no second factor; anything else strict
//                                              (allowLegacyOwner: the exception D3, audited apart)
//   DELETE /:id/targets/:tenantId/:groupId     simple second factor
//   POST   /:id/owner                          { tenantId }: the platform station given to a client (lot BANC-T, Q2): strict
//                                              second factor; every target (and open provisioning) in that tenant (409
//                                              foreignTargets); never the other way
// A station of a client (lot BANC-T, Q1): the platform reads it, suspends it (the client does not lift that suspension;
// a station the client suspended already becomes the platform's suspension), resumes its own suspension, revokes it,
// suspends one of its targets (same rule: suspended_by_platform on the target) and resumes its own suspension of one;
// anything else (rename, targets) is 409 stationOwned.
// No bench session since 28/11/2026: an approved station acts within its targets by itself (no route of sessions).
//   GET    /release, PUT /release              the version of the agent served to the stations ({ releaseId | null }:
//                                              strict second factor)
//   GET    /installer                          the installer of the station in the image
// =============================================================================

function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!isMasterTenant(req.tenantId)) { next(new AppError(404, 'Not found')); return; }
  if (req.session?.role !== 'admin') { next(new AppError(403, 'Insufficient permissions')); return; }
  next();
}

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function body<S extends z.ZodTypeAny>(schema: S, req: Request): z.infer<S> {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  return parsed.data;
}

/** strict: never the trusted address shortcut; simple: the trusted address admitted (a protective action). */
async function stepUp(req: Request, res: Response, actionKey: string, mode: 'strict' | 'simple'): Promise<boolean> {
  const step = await checkSecondFactor(req, { actionKey, allowTrustedIp: mode === 'simple', allowDevice: true });
  if (!step.ok) { sendStepUpFailure(res, step); return false; }
  return true;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);

function stationId(req: Request): string {
  const id = String(req.params.id ?? '').toLowerCase();
  if (!UUID_RE.test(id)) throw new AppError(404, 'Station not found');
  return id;
}

function stationView(r: Record<string, any>, counts: Map<string, { targets: number; enrolled: number }>,
  tenantNames: Map<number, string>): BenchStationView {
  const id = String(r.id);
  const c = counts.get(id) ?? { targets: 0, enrolled: 0 };
  const owner = r.owner_tenant_id === null || r.owner_tenant_id === undefined ? null : Number(r.owner_tenant_id);
  return {
    id, name: r.name, hostname: r.hostname, status: r.status, stationVersion: r.station_version ?? null,
    createdAt: iso(r.created_at) as string, approvedAt: iso(r.approved_at), suspendedAt: iso(r.suspended_at), revokedAt: iso(r.revoked_at),
    revokedReason: r.revoked_reason ?? null, lastSeenAt: iso(r.last_seen_at), lastIp: r.last_ip ?? null, registerIp: r.register_ip ?? null,
    targetCount: c.targets, enrolledCount: c.enrolled,
    ownerTenantId: owner, ownerTenantName: owner === null ? null : tenantNames.get(owner) ?? null, ownerSince: iso(r.owner_since),
    suspendedByPlatform: r.suspended_by_platform === true,
  };
}

/** The names of the owner tenants of these rows. */
async function ownerNames(rows: Array<Record<string, any>>): Promise<Map<number, string>> {
  const ids = [...new Set(rows.map((r) => r.owner_tenant_id).filter((v) => v !== null && v !== undefined).map(Number))];
  if (ids.length === 0) return new Map();
  const t = await db('tenants').whereIn('id', ids).select('id', 'name') as Array<{ id: number; name: string }>;
  return new Map(t.map((x) => [Number(x.id), x.name]));
}

/** A station of a client (lot BANC-T): the platform watches and cuts, nothing else (Q1). */
const isOwned = (r: Record<string, any>): boolean =>
  r.owner_tenant_id !== null && r.owner_tenant_id !== undefined && Number(r.owner_tenant_id) !== MASTER_TENANT_ID;
function refuseOwned(r: Record<string, any>): void {
  if (isOwned(r)) throw new AppError(409, 'This station belongs to a client: the platform only suspends or revokes it', 'stationOwned');
}

async function countsOf(): Promise<Map<string, { targets: number; enrolled: number }>> {
  const r = await db.raw('SELECT * FROM obligarth.bench_station_admin_counts()') as { rows: Array<{ station_id: string; targets: number; enrolled: number }> };
  return new Map(r.rows.map((x) => [String(x.station_id), { targets: Number(x.targets), enrolled: Number(x.enrolled) }]));
}

async function targetsOf(id: string): Promise<BenchTargetView[]> {
  const r = await db.raw('SELECT * FROM obligarth.bench_station_admin_targets(?::uuid)', [id]) as { rows: Array<Record<string, any>> };
  return r.rows.map((t) => ({
    tenantId: Number(t.tenant_id), tenantName: t.tenant_name, groupId: Number(t.group_id), groupPath: t.group_path ?? '',
    rolePolicy: t.role_policy, allowLegacyOwner: t.allow_legacy_owner === true, namePrefix: t.name_prefix ?? null, nameTemplate: t.name_template ?? null,
    disableDevOptions: t.disable_dev_options === true, suspendedAt: iso(t.suspended_at), suspendedByPlatform: t.suspended_by_platform === true,
    createdAt: iso(t.created_at) as string,
  }));
}

async function stationRow(id: string): Promise<Record<string, any>> {
  const r = await db('bench_stations').where({ id }).first('*') as Record<string, any> | undefined;
  if (!r) throw new AppError(404, 'Station not found');
  return r;
}

async function detailOf(id: string): Promise<BenchStationDetail> {
  return switchToIdentity(async () => {
    const r = await stationRow(id);
    return { ...stationView(r, await countsOf(), await ownerNames([r])), targets: await targetsOf(id) };
  });
}

const ApproveBody = z.object({ verificationCode: z.string().max(20) }).strict();
const RenameBody = z.object({ name: z.string().max(200) }).strict();
const TargetBody = z.object({ tenantId: z.number().int().positive(), groupId: z.number().int().positive(), ...TargetFields }).strict();
const OwnerBody = z.object({ tenantId: z.number().int().positive() }).strict();
const ReleaseBody = z.object({ releaseId: z.string().regex(UUID_RE).nullable() }).strict();

/** A status change (compare-and-set on the status read) and its cascade, in one transaction of the identity context. */
async function changeStatus(req: Request, id: string, action: StationAction): Promise<BenchStationDetail> {
  const userId = req.session.userId!;
  const ctx = await audit.fromRequest(req, MASTER_TENANT_ID);
  await switchToIdentity(() => db.transaction(async (trx) => {
    const r = await trx('bench_stations').where({ id }).forUpdate().first('status', 'name', 'owner_tenant_id', 'suspended_by_platform') as
      { status: any; name: string; owner_tenant_id: number | null; suspended_by_platform: boolean } | undefined;
    if (!r) throw new AppError(404, 'Station not found');
    // A client's station: the platform resumes its own suspension only (the client's is the client's).
    if (action === 'resume' && isOwned(r) && !r.suspended_by_platform) {
      throw new AppError(409, 'This station was suspended by its owner: the client resumes it', 'stationOwned');
    }
    // A client's station the client suspended already: the platform makes that suspension its own (Q1: the client then
    // no longer lifts it), the status unchanged and the cascade run again (idempotent).
    const takeOver = action === 'suspend' && isOwned(r) && r.status === 'suspended' && !r.suspended_by_platform;
    const to = takeOver ? 'suspended' : planStationTransition(r.status, action);
    if (!to) throw new AppError(409, `The station cannot be ${action === 'approve' ? 'approved' : `${action}d`} in its state`, 'bad_state');
    const now = new Date();
    const set: Record<string, unknown> = { status: to };
    if (action === 'approve') Object.assign(set, { approved_at: now, approved_by: userId });
    if (action === 'suspend') Object.assign(set, { suspended_at: now, suspended_by: userId, suspended_by_platform: isOwned(r) });
    if (action === 'resume') Object.assign(set, { suspended_at: null, suspended_by: null, suspended_by_platform: false });
    if (action === 'revoke') {
      Object.assign(set, { revoked_at: now, revoked_by: userId, revoked_reason: 'admin', suspended_at: null, suspended_by: null, suspended_by_platform: false });
    }
    const auditAction = action === 'approve' ? 'bench.station_approved' : action === 'resume' ? 'bench.station_resumed'
      : action === 'suspend' ? 'bench.station_suspended' : 'bench.station_revoked';
    const protective = action === 'suspend' || action === 'revoke';
    let cascade: Array<{ tenant_id: number; tokens: number; provisionings: number }> = [];
    // The critical actions are written before the change; the protective ones never wait for the journal.
    if (!protective) {
      await audit.appendInTx(trx, { tenantId: MASTER_TENANT_ID, action: auditAction, target: { type: 'bench_station', id },
        details: { stationId: id, name: r.name, from: r.status, ...(isOwned(r) ? { ownerTenantId: Number(r.owner_tenant_id) } : {}) } }, ctx);
    }
    await trx('bench_stations').where({ id, status: r.status }).update(set);
    if (protective) {
      const out = await trx.raw('SELECT * FROM obligarth.bench_station_revoke_cascade(?::uuid, ?, ?)',
        [id, userId, action === 'revoke' ? 'station_revoked' : 'station_suspended']) as { rows: typeof cascade };
      cascade = out.rows.map((x) => ({ tenant_id: Number(x.tenant_id), tokens: Number(x.tokens), provisionings: Number(x.provisionings) }));
      await audit.appendManyInTx(trx, [
        { tenantId: MASTER_TENANT_ID, action: auditAction, target: { type: 'bench_station', id }, details: { stationId: id, name: r.name, from: r.status, tenants: cascade.length,
          enrollmentsRevoked: cascade.reduce((n, c) => n + c.tokens, 0), provisioningsAbandoned: cascade.reduce((n, c) => n + c.provisionings, 0),
          ...(isOwned(r) ? { ownerTenantId: Number(r.owner_tenant_id) } : {}), ...(takeOver ? { tookOver: true } : {}) } },
        // Each tenant the cascade touched reads it in its own journal; the owner of a client's station always does.
        ...[...new Set([...cascade.map((c) => c.tenant_id), ...(isOwned(r) ? [Number(r.owner_tenant_id)] : [])])]
          .filter((t) => t !== MASTER_TENANT_ID).map((t) => {
            const c = cascade.find((x) => x.tenant_id === t);
            return {
              tenantId: t, action: auditAction, target: { type: 'bench_station', id },
              details: { stationId: id, name: r.name, enrollmentsRevoked: c?.tokens ?? 0, provisioningsAbandoned: c?.provisionings ?? 0,
                ...(isOwned(r) ? { ownerTenantId: Number(r.owner_tenant_id), byPlatform: true } : {}), ...(takeOver ? { tookOver: true } : {}) },
            };
          }),
      ], ctx, { onFailure: 'spool' });
    }
  }));
  return detailOf(id);
}

export function createBenchAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  router.get('/', wrap(async (_req, res) => {
    const data = await switchToIdentity(async () => {
      const rows = await db('bench_stations').orderByRaw("CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 WHEN 'suspended' THEN 2 ELSE 3 END")
        .orderBy('created_at', 'desc').limit(1000).select('*') as Array<Record<string, any>>;
      const counts = await countsOf();
      const names = await ownerNames(rows);
      return rows.map((r) => stationView(r, counts, names));
    });
    res.json({ success: true, data });
  }));

  router.get('/release', wrap(async (_req, res) => {
    const served = await servedRelease();
    const rows = await db('legacy_agent_releases').whereNull('withdrawn_at').orderBy('version_code', 'desc').limit(100).select('*');
    const { signers } = signersFromEnv();
    res.json({
      success: true,
      data: {
        served: served ? { releaseId: served.releaseId, versionCode: served.versionCode, versionName: served.versionName, sha256: served.sha256,
          deviceOwnerCapable: served.deviceOwnerCapable, signerAdmitted: signers.includes(served.signerSha256) } : null,
        releases: rows.map(releaseView),
      },
    });
  }));

  router.put('/release', wrap(async (req, res) => {
    const b = body(ReleaseBody, req);
    if (b.releaseId) {
      const r = await db('legacy_agent_releases').where({ id: b.releaseId }).first('id', 'withdrawn_at', 'signer_sha256') as Record<string, any> | undefined;
      if (!r) throw new AppError(404, 'Release not found');
      if (r.withdrawn_at) throw new AppError(409, 'This version is withdrawn', 'releaseWithdrawn');
      if (!signersFromEnv().signers.includes(String(r.signer_sha256).trim())) throw new AppError(422, 'This signer is not admitted (LEGACY_AGENT_SIGNERS)', 'signerNotAdmitted');
    }
    if (!(await stepUp(req, res, 'bench.release_set', 'strict'))) return;
    const ctx = await audit.fromRequest(req, MASTER_TENANT_ID);
    await switchToIdentity(() => db.transaction(async (trx) => {
      const before = await trx('legacy_agent_releases').where({ bench_served: true }).first('id', 'version_code') as Record<string, any> | undefined;
      const after = b.releaseId ? await trx('legacy_agent_releases').where({ id: b.releaseId }).first('version_code') as Record<string, any> | undefined : undefined;
      await audit.appendInTx(trx, {
        tenantId: MASTER_TENANT_ID, action: 'legacy_agent.bench_release_set', target: { type: 'legacy_agent_release', id: b.releaseId ?? 'none' },
        details: { before: before ? Number(before.version_code) : null, after: after ? Number(after.version_code) : null },
      }, ctx);
      await trx('legacy_agent_releases').where({ bench_served: true }).update({ bench_served: false });
      if (b.releaseId) await trx('legacy_agent_releases').where({ id: b.releaseId }).whereNull('withdrawn_at').update({ bench_served: true });
    }));
    const served = await servedRelease();
    res.json({ success: true, data: { served: served ? { releaseId: served.releaseId, versionCode: served.versionCode, versionName: served.versionName } : null } });
  }));

  router.get('/installer', wrap(async (_req, res) => {
    const s = await installerState();
    res.json({ success: true, data: { version: s.version, available: s.available, sha256: s.sha256, size: s.size, file: 'obligarth-bench.msi' } });
  }));

  // The tenants and the groups of a tenant a target may name (the dialog of a new target).
  router.get('/tenants', wrap(async (_req, res) => {
    const rows = await db('tenants').orderBy('name').select('id', 'name') as Array<{ id: number; name: string }>;
    res.json({ success: true, data: rows.map((r) => ({ id: Number(r.id), name: r.name })) });
  }));

  router.get('/tenants/:tenantId/groups', wrap(async (req, res) => {
    const tenantId = Number(req.params.tenantId);
    if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new AppError(404, 'Tenant not found');
    const rows = await asTenant(tenantId, userActor(req.session.userId!), () => db('device_groups').where({ tenant_id: tenantId })
      .select('id', 'parent_id', 'name')) as Array<{ id: number; parent_id: number | null; name: string }>;
    const byId = new Map(rows.map((r) => [Number(r.id), r]));
    const pathOf = (id: number): string => {
      const names: string[] = [];
      let cur = byId.get(id);
      for (let i = 0; cur && i < 32; i++) { names.unshift(cur.name); cur = cur.parent_id === null ? undefined : byId.get(Number(cur.parent_id)); }
      return names.join('/');
    };
    const data = rows.map((r) => ({ id: Number(r.id), path: pathOf(Number(r.id)) })).sort((a, b) => a.path.localeCompare(b.path));
    res.json({ success: true, data });
  }));

  router.get('/:id', wrap(async (req, res) => {
    res.json({ success: true, data: await detailOf(stationId(req)) });
  }));

  router.patch('/:id', wrap(async (req, res) => {
    const id = stationId(req);
    const name = cleanLabel(body(RenameBody, req).name, 100);
    if (!name) throw new AppError(400, 'A name is required', 'invalidRequest');
    const ctx = await audit.fromRequest(req, MASTER_TENANT_ID);
    await switchToIdentity(() => db.transaction(async (trx) => {
      const r = await trx('bench_stations').where({ id }).forUpdate().first('name', 'status', 'owner_tenant_id') as Record<string, any> | undefined;
      if (!r) throw new AppError(404, 'Station not found');
      refuseOwned(r);
      if (r.name === name) return;
      await trx('bench_stations').where({ id }).update({ name });
      await audit.appendInTx(trx, { tenantId: MASTER_TENANT_ID, action: 'bench.station_renamed', target: { type: 'bench_station', id }, details: { from: r.name, to: name } }, ctx);
    }));
    res.json({ success: true, data: await detailOf(id) });
  }));

  router.post('/:id/approve', wrap(async (req, res) => {
    const id = stationId(req);
    const b = body(ApproveBody, req);
    const r = await switchToIdentity(() => stationRow(id));
    if (normaliseBenchVerificationCode(b.verificationCode) !== normaliseBenchVerificationCode(stationVerificationCode(String(r.token_sha256).trim()))) {
      throw new AppError(422, 'The verification code does not match the station', 'verification_mismatch');
    }
    if (r.status !== 'pending') throw new AppError(409, 'The station is not pending', 'bad_state');
    if (!(await stepUp(req, res, 'bench.station_approve', 'strict'))) return;
    res.json({ success: true, data: await changeStatus(req, id, 'approve') });
  }));

  router.post('/:id/suspend', wrap(async (req, res) => {
    res.json({ success: true, data: await changeStatus(req, stationId(req), 'suspend') });
  }));

  router.post('/:id/resume', wrap(async (req, res) => {
    const id = stationId(req);
    if (!(await stepUp(req, res, 'bench.station_resume', 'strict'))) return;
    res.json({ success: true, data: await changeStatus(req, id, 'resume') });
  }));

  router.post('/:id/revoke', wrap(async (req, res) => {
    const id = stationId(req);
    if (!(await stepUp(req, res, 'bench.station_revoke', 'simple'))) return;
    res.json({ success: true, data: await changeStatus(req, id, 'revoke') });
  }));

  router.post('/:id/targets', wrap(async (req, res) => {
    const id = stationId(req);
    const b = body(TargetBody, req);
    const r = await switchToIdentity(() => stationRow(id));
    refuseOwned(r);
    if (r.status === 'revoked') throw new AppError(409, 'The station is revoked', 'bad_state');
    await assertGroup(b.tenantId, b.groupId, req.session.userId!);
    if (!(await stepUp(req, res, 'bench.target_add', 'strict'))) return;
    await insertTarget(req, id, r.name, b.tenantId, b);
    res.status(201).json({ success: true, data: await detailOf(id) });
  }));

  router.patch('/:id/targets/:tenantId/:groupId', wrap(async (req, res) => {
    const id = stationId(req);
    const tenantId = Number(req.params.tenantId);
    const groupId = Number(req.params.groupId);
    if (!Number.isSafeInteger(tenantId) || tenantId <= 0 || !Number.isSafeInteger(groupId) || groupId <= 0) throw new AppError(404, 'Target not found');
    const b = body(TargetPatch, req);
    // A client's station: the platform only suspends one of its targets (protective) and resumes its own suspension of
    // one (Q1; patchTarget refuses to resume a suspension of the client: 409 stationOwned).
    const onlySuspension = Object.keys(b).length === 1 && typeof b.suspended === 'boolean';
    const r = await switchToIdentity(() => stationRow(id));
    if (!onlySuspension) refuseOwned(r);
    if (!(await patchTarget(req, res, id, tenantId, groupId, b, { platform: true, ownedStation: isOwned(r) }))) return;
    res.json({ success: true, data: await detailOf(id) });
  }));

  router.delete('/:id/targets/:tenantId/:groupId', wrap(async (req, res) => {
    const id = stationId(req);
    const tenantId = Number(req.params.tenantId);
    const groupId = Number(req.params.groupId);
    if (!Number.isSafeInteger(tenantId) || tenantId <= 0 || !Number.isSafeInteger(groupId) || groupId <= 0) throw new AppError(404, 'Target not found');
    refuseOwned(await switchToIdentity(() => stationRow(id)));
    if (!(await stepUp(req, res, 'bench.target_remove', 'simple'))) return;
    await removeTarget(req, id, tenantId, groupId, 'admin');
    res.json({ success: true, data: await detailOf(id) });
  }));

  // Lot BANC-T, Q2: a platform station given to a client (never the other way).
  router.post('/:id/owner', wrap(async (req, res) => {
    const id = stationId(req);
    const b = body(OwnerBody, req);
    if (isMasterTenant(b.tenantId)) throw new AppError(409, 'A station of a client never goes back to the platform', 'bad_state');
    const r = await switchToIdentity(() => stationRow(id));
    refuseOwned(r);
    if (!['approved', 'suspended'].includes(r.status)) throw new AppError(409, 'Only an approved or suspended station is given to a client', 'bad_state');
    if (!(await stepUp(req, res, 'bench.station_owner_assign', 'strict'))) return;
    const userId = req.session.userId!;
    const ctx = await audit.fromRequest(req, MASTER_TENANT_ID);
    await switchToIdentity(() => db.transaction(async (trx) => {
      const out = await trx.raw('SELECT obligarth.bench_station_assign_owner(?::uuid, ?, ?) AS o', [id, b.tenantId, userId]) as { rows: Array<{ o: string }> };
      const outcome = out.rows[0]?.o;
      if (outcome === 'bad_tenant') throw new AppError(404, 'Tenant not found');
      if (outcome === 'not_found') throw new AppError(404, 'Station not found');
      if (outcome === 'already_owned') throw new AppError(409, 'This station belongs to a client already', 'stationOwned');
      if (outcome === 'foreign_targets') throw new AppError(409, 'The station targets or provisions another tenant: remove those targets first', 'foreignTargets');
      if (outcome !== 'assigned') throw new AppError(409, 'The station cannot be given in its state', 'bad_state');
      // Critical, in the change's transaction: the master's chain and the new owner's.
      await audit.appendManyInTx(trx, [
        { tenantId: MASTER_TENANT_ID, action: 'bench.station_owner_assigned', target: { type: 'bench_station', id }, details: { stationId: id, name: r.name, ownerTenantId: b.tenantId } },
        { tenantId: b.tenantId, action: 'bench.station_owner_assigned', target: { type: 'bench_station', id }, details: { stationId: id, name: r.name, ownerTenantId: b.tenantId } },
      ], ctx);
    }));
    res.json({ success: true, data: await detailOf(id) });
  }));

  return router;
}
