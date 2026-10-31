import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import {
  BENCH_LIMITS, BENCH_ROLE_POLICIES, MASTER_TENANT_ID, isMasterTenant, normaliseBenchVerificationCode,
  type BenchSessionView, type BenchStationDetail, type BenchStationView, type BenchTargetView,
} from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { asTenant, switchToIdentity, userActor } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { checkSecondFactor, sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { signersFromEnv } from '../legacyAgent/config';
import { releaseView } from '../legacyAgent/routes';
import { installerState, servedRelease } from './apk.service';
import { closeTargetProvisionings } from './provisioning.service';
import { cleanLabel, planStationTransition, stationVerificationCode, type StationAction } from './stations.service';

// =============================================================================
// The bench stations in the console of the platform (lot BANC §3.3, §3.7, §3.12), mounted at /api/admin/bench-stations:
// the master tenant (404 elsewhere), a platform administrator (403 otherwise).
//   GET    /                                   the stations (pending first), their targets and enrolled devices counted
//   GET    /:id                                one station and its targets in every tenant
//   PATCH  /:id                                { name }: rename (standard)
//   POST   /:id/approve                        { verificationCode }: the code read on the station's screen (the console
//                                              never shows it), checked by the server (422 verification_mismatch), then
//                                              a strict second factor
//   POST   /:id/suspend                        no second factor (protective): its tokens, provisionings and session closed
//   POST   /:id/resume                         strict second factor
//   POST   /:id/revoke                         simple second factor (protective, final): the same cascade
//   POST   /:id/targets                        { tenantId, groupId, rolePolicy, namePrefix, disableDevOptions }: strict
//   PATCH  /:id/targets/:tenantId/:groupId     { suspended } alone: no second factor; anything else strict
//                                              (allowLegacyOwner: the exception D3, audited apart)
//   DELETE /:id/targets/:tenantId/:groupId     simple second factor
//   POST   /:id/sessions                       { minutes }: a bench session of the administrator, strict second factor
//   POST   /:id/sessions/close                 the open session closed
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

export function sessionView(r: Record<string, any> | undefined | null): BenchSessionView | null {
  if (!r?.id) return null;
  return {
    id: String(r.id), stationId: String(r.station_id), userId: Number(r.user_id), technician: r.technician ?? null,
    openedAt: iso(r.opened_at) as string, expiresAt: iso(r.expires_at) as string, closedAt: iso(r.closed_at),
  };
}

function stationView(r: Record<string, any>, counts: Map<string, { targets: number; enrolled: number }>, session: BenchSessionView | null): BenchStationView {
  const id = String(r.id);
  const c = counts.get(id) ?? { targets: 0, enrolled: 0 };
  return {
    id, name: r.name, hostname: r.hostname, status: r.status, stationVersion: r.station_version ?? null,
    createdAt: iso(r.created_at) as string, approvedAt: iso(r.approved_at), suspendedAt: iso(r.suspended_at), revokedAt: iso(r.revoked_at),
    revokedReason: r.revoked_reason ?? null, lastSeenAt: iso(r.last_seen_at), lastIp: r.last_ip ?? null, registerIp: r.register_ip ?? null,
    targetCount: c.targets, enrolledCount: c.enrolled, session,
  };
}

/** The open sessions, with their technician's label (identity context). */
async function openSessions(stationIds: string[] | null): Promise<Map<string, BenchSessionView>> {
  let q = db('bench_sessions as s').leftJoin('users as u', 'u.id', 's.user_id').whereNull('s.closed_at').where('s.expires_at', '>', new Date());
  if (stationIds) q = q.whereIn('s.station_id', stationIds);
  const rows = await q.select('s.*', db.raw("COALESCE(NULLIF(u.display_name, ''), u.username) AS technician")) as Array<Record<string, any>>;
  return new Map(rows.map((r) => [String(r.station_id), sessionView(r)!]));
}

async function countsOf(): Promise<Map<string, { targets: number; enrolled: number }>> {
  const r = await db.raw('SELECT * FROM obligarth.bench_station_admin_counts()') as { rows: Array<{ station_id: string; targets: number; enrolled: number }> };
  return new Map(r.rows.map((x) => [String(x.station_id), { targets: Number(x.targets), enrolled: Number(x.enrolled) }]));
}

async function targetsOf(id: string): Promise<BenchTargetView[]> {
  const r = await db.raw('SELECT * FROM obligarth.bench_station_admin_targets(?::uuid)', [id]) as { rows: Array<Record<string, any>> };
  return r.rows.map((t) => ({
    tenantId: Number(t.tenant_id), tenantName: t.tenant_name, groupId: Number(t.group_id), groupPath: t.group_path ?? '',
    rolePolicy: t.role_policy, allowLegacyOwner: t.allow_legacy_owner === true, namePrefix: t.name_prefix ?? null,
    disableDevOptions: t.disable_dev_options === true, suspendedAt: iso(t.suspended_at), createdAt: iso(t.created_at) as string,
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
    const sessions = await openSessions([id]);
    return { ...stationView(r, await countsOf(), sessions.get(id) ?? null), targets: await targetsOf(id) };
  });
}

const ApproveBody = z.object({ verificationCode: z.string().max(20) }).strict();
const RenameBody = z.object({ name: z.string().max(200) }).strict();
const TargetBody = z.object({
  tenantId: z.number().int().positive(), groupId: z.number().int().positive(),
  rolePolicy: z.enum(BENCH_ROLE_POLICIES).optional(), namePrefix: z.string().regex(/^[A-Za-z0-9_-]{0,32}$/).nullable().optional(),
  disableDevOptions: z.boolean().optional(),
}).strict();
const TargetPatch = z.object({
  rolePolicy: z.enum(BENCH_ROLE_POLICIES).optional(), namePrefix: z.string().regex(/^[A-Za-z0-9_-]{0,32}$/).nullable().optional(),
  disableDevOptions: z.boolean().optional(), allowLegacyOwner: z.boolean().optional(), suspended: z.boolean().optional(),
}).strict();
const SessionBody = z.object({ minutes: z.number().int().min(15).max(BENCH_LIMITS.sessionMaxHours * 60).optional() }).strict();
const ReleaseBody = z.object({ releaseId: z.string().regex(UUID_RE).nullable() }).strict();

/** A status change (compare-and-set on the status read) and its cascade, in one transaction of the identity context. */
async function changeStatus(req: Request, id: string, action: StationAction): Promise<BenchStationDetail> {
  const userId = req.session.userId!;
  const ctx = await audit.fromRequest(req, MASTER_TENANT_ID);
  await switchToIdentity(() => db.transaction(async (trx) => {
    const r = await trx('bench_stations').where({ id }).forUpdate().first('status', 'name') as { status: any; name: string } | undefined;
    if (!r) throw new AppError(404, 'Station not found');
    const to = planStationTransition(r.status, action);
    if (!to) throw new AppError(409, `The station cannot be ${action === 'approve' ? 'approved' : `${action}d`} in its state`, 'bad_state');
    const now = new Date();
    const set: Record<string, unknown> = { status: to };
    if (action === 'approve') Object.assign(set, { approved_at: now, approved_by: userId });
    if (action === 'suspend') Object.assign(set, { suspended_at: now, suspended_by: userId });
    if (action === 'resume') Object.assign(set, { suspended_at: null, suspended_by: null });
    if (action === 'revoke') Object.assign(set, { revoked_at: now, revoked_by: userId, revoked_reason: 'admin', suspended_at: null, suspended_by: null });
    const auditAction = action === 'approve' ? 'bench.station_approved' : action === 'resume' ? 'bench.station_resumed'
      : action === 'suspend' ? 'bench.station_suspended' : 'bench.station_revoked';
    const protective = action === 'suspend' || action === 'revoke';
    let cascade: Array<{ tenant_id: number; tokens: number; provisionings: number }> = [];
    // The critical actions are written before the change; the protective ones never wait for the journal.
    if (!protective) {
      await audit.appendInTx(trx, { tenantId: MASTER_TENANT_ID, action: auditAction, target: { type: 'bench_station', id }, details: { stationId: id, name: r.name, from: r.status } }, ctx);
    }
    await trx('bench_stations').where({ id, status: r.status }).update(set);
    if (protective) {
      const out = await trx.raw('SELECT * FROM obligarth.bench_station_revoke_cascade(?::uuid, ?, ?)',
        [id, userId, action === 'revoke' ? 'station_revoked' : 'station_suspended']) as { rows: typeof cascade };
      cascade = out.rows.map((x) => ({ tenant_id: Number(x.tenant_id), tokens: Number(x.tokens), provisionings: Number(x.provisionings) }));
      await audit.appendManyInTx(trx, [
        { tenantId: MASTER_TENANT_ID, action: auditAction, target: { type: 'bench_station', id }, details: { stationId: id, name: r.name, from: r.status, tenants: cascade.length,
          enrollmentsRevoked: cascade.reduce((n, c) => n + c.tokens, 0), provisioningsAbandoned: cascade.reduce((n, c) => n + c.provisionings, 0) } },
        // Each tenant the cascade touched reads it in its own journal.
        ...cascade.filter((c) => c.tenant_id !== MASTER_TENANT_ID).map((c) => ({
          tenantId: c.tenant_id, action: auditAction, target: { type: 'bench_station', id },
          details: { stationId: id, name: r.name, enrollmentsRevoked: c.tokens, provisioningsAbandoned: c.provisionings },
        })),
      ], ctx, { onFailure: 'spool' });
    }
  }));
  return detailOf(id);
}

/** The group of a target, in its tenant (404 otherwise). */
async function assertGroup(tenantId: number, groupId: number, userId: number): Promise<void> {
  const ok = await asTenant(tenantId, userActor(userId), () => db('device_groups').where({ tenant_id: tenantId, id: groupId }).first('id'));
  if (!ok) throw new AppError(404, 'Group not found');
}

export function createBenchAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  router.get('/', wrap(async (_req, res) => {
    const data = await switchToIdentity(async () => {
      const rows = await db('bench_stations').orderByRaw("CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 WHEN 'suspended' THEN 2 ELSE 3 END")
        .orderBy('created_at', 'desc').limit(1000).select('*') as Array<Record<string, any>>;
      const counts = await countsOf();
      const sessions = await openSessions(null);
      return rows.map((r) => stationView(r, counts, sessions.get(String(r.id)) ?? null));
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
      const r = await trx('bench_stations').where({ id }).forUpdate().first('name', 'status') as Record<string, any> | undefined;
      if (!r) throw new AppError(404, 'Station not found');
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
    if (r.status === 'revoked') throw new AppError(409, 'The station is revoked', 'bad_state');
    const userId = req.session.userId!;
    await assertGroup(b.tenantId, b.groupId, userId);
    if (!(await stepUp(req, res, 'bench.target_add', 'strict'))) return;
    const ctx = await audit.fromRequest(req, b.tenantId);
    await asTenant(b.tenantId, userActor(userId), () => db.transaction(async (trx) => {
      if (await trx('bench_station_targets').where({ station_id: id, tenant_id: b.tenantId, group_id: b.groupId }).first('group_id')) {
        throw new AppError(409, 'This group is a target of the station already', 'targetExists');
      }
      await audit.appendInTx(trx, {
        tenantId: b.tenantId, action: 'bench.target_added', target: { type: 'bench_station', id },
        details: { stationId: id, name: r.name, groupId: b.groupId, rolePolicy: b.rolePolicy ?? 'owner_preferred', disableDevOptions: b.disableDevOptions ?? true },
      }, ctx);
      await trx('bench_station_targets').insert({
        station_id: id, tenant_id: b.tenantId, group_id: b.groupId, role_policy: b.rolePolicy ?? 'owner_preferred', name_prefix: b.namePrefix || null,
        disable_dev_options: b.disableDevOptions ?? true, created_by: userId,
      });
    })).catch((err) => {
      if ((err as { constraint?: string })?.constraint === 'bench_station_targets_cap') throw new AppError(422, '200 targets per station at most', 'tooManyTargets');
      throw err;
    });
    res.status(201).json({ success: true, data: await detailOf(id) });
  }));

  router.patch('/:id/targets/:tenantId/:groupId', wrap(async (req, res) => {
    const id = stationId(req);
    const tenantId = Number(req.params.tenantId);
    const groupId = Number(req.params.groupId);
    if (!Number.isSafeInteger(tenantId) || tenantId <= 0 || !Number.isSafeInteger(groupId) || groupId <= 0) throw new AppError(404, 'Target not found');
    const b = body(TargetPatch, req);
    const keys = Object.keys(b);
    if (keys.length === 0) throw new AppError(400, 'Nothing to change', 'invalidRequest');
    const onlySuspend = keys.length === 1 && b.suspended === true;
    if (!onlySuspend && !(await stepUp(req, res, b.allowLegacyOwner ? 'bench.legacy_owner_allow' : 'bench.target_change', 'strict'))) return;
    const userId = req.session.userId!;
    const ctx = await audit.fromRequest(req, tenantId);
    await asTenant(tenantId, userActor(userId), () => db.transaction(async (trx) => {
      const t = await trx('bench_station_targets').where({ station_id: id, tenant_id: tenantId, group_id: groupId }).forUpdate().first('*') as Record<string, any> | undefined;
      if (!t) throw new AppError(404, 'Target not found');
      const set: Record<string, unknown> = {};
      if (b.rolePolicy !== undefined) set.role_policy = b.rolePolicy;
      if (b.namePrefix !== undefined) set.name_prefix = b.namePrefix || null;
      if (b.disableDevOptions !== undefined) set.disable_dev_options = b.disableDevOptions;
      if (b.allowLegacyOwner !== undefined) set.allow_legacy_owner = b.allowLegacyOwner;
      if (b.suspended === true && !t.suspended_at) Object.assign(set, { suspended_at: new Date(), suspended_by: userId });
      if (b.suspended === false && t.suspended_at) Object.assign(set, { suspended_at: null, suspended_by: null });
      if (Object.keys(set).length === 0) return;
      // A suspension closes at once what the target had open: its provisionings abandoned, their tokens revoked.
      const closed = b.suspended === true && !t.suspended_at ? await closeTargetProvisionings(trx, tenantId, id, groupId, userId) : null;
      const entries = [];
      if (b.allowLegacyOwner === true && t.allow_legacy_owner !== true) {
        entries.push({ tenantId, action: 'bench.legacy_owner_allowed', target: { type: 'bench_station', id }, details: { stationId: id, groupId } });
      }
      if (closed) entries.push({ tenantId, action: 'bench.target_suspended', target: { type: 'bench_station', id }, details: { stationId: id, groupId, ...closed } });
      if (b.suspended === false && t.suspended_at) entries.push({ tenantId, action: 'bench.target_resumed', target: { type: 'bench_station', id }, details: { stationId: id, groupId } });
      const changed = Object.keys(set).filter((k) => !['suspended_at', 'suspended_by'].includes(k));
      if (changed.length > 0) {
        entries.push({ tenantId, action: 'bench.target_changed', target: { type: 'bench_station', id }, details: { stationId: id, groupId, changed: Object.fromEntries(changed.map((k) => [k, set[k]])) } });
      }
      if (entries.length) await audit.appendManyInTx(trx, entries, ctx, onlySuspend ? { onFailure: 'spool' } : {});
      await trx('bench_station_targets').where({ station_id: id, tenant_id: tenantId, group_id: groupId }).update(set);
    }));
    res.json({ success: true, data: await detailOf(id) });
  }));

  router.delete('/:id/targets/:tenantId/:groupId', wrap(async (req, res) => {
    const id = stationId(req);
    const tenantId = Number(req.params.tenantId);
    const groupId = Number(req.params.groupId);
    if (!Number.isSafeInteger(tenantId) || tenantId <= 0 || !Number.isSafeInteger(groupId) || groupId <= 0) throw new AppError(404, 'Target not found');
    if (!(await stepUp(req, res, 'bench.target_remove', 'simple'))) return;
    const userId = req.session.userId!;
    const ctx = await audit.fromRequest(req, tenantId);
    await asTenant(tenantId, userActor(userId), () => db.transaction(async (trx) => {
      const n = await trx('bench_station_targets').where({ station_id: id, tenant_id: tenantId, group_id: groupId }).delete();
      if (n === 0) throw new AppError(404, 'Target not found');
      const closed = await closeTargetProvisionings(trx, tenantId, id, groupId, userId);
      await audit.appendInTx(trx, { tenantId, action: 'bench.target_removed', target: { type: 'bench_station', id }, details: { stationId: id, groupId, reason: 'admin', ...closed } },
        ctx, { onFailure: 'spool' });
    }));
    res.json({ success: true, data: await detailOf(id) });
  }));

  router.post('/:id/sessions', wrap(async (req, res) => {
    const id = stationId(req);
    const b = body(SessionBody, req);
    const r = await switchToIdentity(() => stationRow(id));
    if (r.status !== 'approved') throw new AppError(409, 'The station is not approved', 'bad_state');
    if (!(await stepUp(req, res, 'bench.session_open', 'strict'))) return;
    await openBenchSession(req, id, r.name, b.minutes ?? BENCH_LIMITS.sessionMaxHours * 60, MASTER_TENANT_ID);
    res.status(201).json({ success: true, data: await detailOf(id) });
  }));

  router.post('/:id/sessions/close', wrap(async (req, res) => {
    const id = stationId(req);
    await closeBenchSession(req, { stationId: id }, MASTER_TENANT_ID, 'admin');
    res.json({ success: true, data: await detailOf(id) });
  }));

  return router;
}

/** Opens the session of the request's user on a station (identity context): the station locked and still approved, the
 *  expired leftovers closed first, one open session per station (409 sessionOpen, also when a concurrent opening won the
 *  unique index). The audit entry (critical) goes to the chain of `chainTenantId`. */
export async function openBenchSession(req: Request, id: string, stationName: string, minutes: number, chainTenantId: number): Promise<BenchSessionView> {
  const userId = req.session.userId!;
  const ctx = await audit.fromRequest(req, chainTenantId);
  const m = Math.max(15, Math.min(BENCH_LIMITS.sessionMaxHours * 60, Math.floor(minutes)));
  return switchToIdentity(() => db.transaction(async (trx) => {
    const st = await trx('bench_stations').where({ id }).forUpdate().first('status') as { status: string } | undefined;
    if (!st) throw new AppError(404, 'Station not found');
    if (st.status !== 'approved') throw new AppError(409, 'The station is not approved', 'bad_state');
    await trx('bench_sessions').where({ station_id: id }).whereNull('closed_at').where('expires_at', '<=', new Date())
      .update({ closed_at: new Date(), close_reason: 'expired' });
    if (await trx('bench_sessions').where({ station_id: id }).whereNull('closed_at').first('id')) {
      throw new AppError(409, 'A bench session is open on this station already', 'sessionOpen');
    }
    const [row] = await trx('bench_sessions').insert({
      station_id: id, user_id: userId, expires_at: trx.raw('now() + make_interval(mins => ?)', [m]),
    }).returning('*') as Array<Record<string, any>>;
    await audit.appendInTx(trx, {
      tenantId: chainTenantId, action: 'bench.session_opened', target: { type: 'bench_station', id },
      details: { stationId: id, name: stationName, sessionId: String(row.id), minutes: m, technicianUserId: userId },
    }, ctx);
    return sessionView({ ...row, technician: req.session.username ?? null })!;
  })).catch((err) => {
    if ((err as { code?: string })?.code === '23505' && /bench_sessions_open/.test(String((err as { constraint?: string }).constraint ?? ''))) {
      throw new AppError(409, 'A bench session is open on this station already', 'sessionOpen');
    }
    throw err;
  });
}

/** Closes the open session of a station (by the station, or by its id): protective. */
export async function closeBenchSession(req: Request, which: { stationId?: string; sessionId?: string }, chainTenantId: number,
  reason: 'user' | 'admin', mustOwn = false): Promise<boolean> {
  const userId = req.session.userId!;
  const ctx = await audit.fromRequest(req, chainTenantId);
  return switchToIdentity(() => db.transaction(async (trx) => {
    let q = trx('bench_sessions').whereNull('closed_at');
    if (which.stationId) q = q.where({ station_id: which.stationId });
    if (which.sessionId) q = q.where({ id: which.sessionId });
    const s = await q.forUpdate().first('id', 'station_id', 'user_id') as Record<string, any> | undefined;
    if (!s) return false;
    if (mustOwn && Number(s.user_id) !== userId) throw new AppError(404, 'Session not found');
    await trx('bench_sessions').where({ id: s.id }).update({ closed_at: new Date(), closed_by: userId, close_reason: reason });
    await audit.appendInTx(trx, {
      tenantId: chainTenantId, action: 'bench.session_closed', target: { type: 'bench_station', id: String(s.station_id) },
      details: { stationId: String(s.station_id), sessionId: String(s.id), technicianUserId: Number(s.user_id), reason },
    }, ctx, { onFailure: 'spool' });
    return true;
  }));
}
