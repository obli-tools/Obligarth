import { Router, type NextFunction, type Request, type Response } from 'express';
import {
  BENCH_PROVISIONING_STATES, truncateSerial,
  type BenchProvisioningView, type BenchStepEntry, type BenchTenantStationView,
} from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { requireTenantCapability } from '../middleware/rbac';
import { checkSecondFactor, sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { permissionService } from '../services/permission.service';
import { closeTargetProvisionings } from './provisioning.service';

// =============================================================================
// The bench seen from a tenant (lot BANC §3.7, §3.12), mounted at /api/bench-provisionings in the tenant router, all
// behind mdm.bench.manage:
//   GET    /                                   the provisionings of the tenant (500 at most; ?stationId=&state=&deviceId=):
//                                              serial numbers in clear with devices.manage, cut to 4 characters otherwise
//   GET    /stations                           the stations that target the tenant or enrolled into it (no token, no
//                                              address, no host), with the tenant's targets
//   POST   /targets/:stationId/:groupId/suspend   no second factor (protective): its open provisionings abandoned and
//                                                 their tokens revoked
//   DELETE /targets/:stationId/:groupId           second factor: the same
// Only a platform administrator adds a target (D4), and so resumes one (§3.3, §3.7): the tenant suspends and removes.
// =============================================================================

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);

function targetParams(req: Request): { stationId: string; groupId: number } {
  const stationId = String(req.params.stationId ?? '').toLowerCase();
  const groupId = Number(req.params.groupId);
  if (!UUID_RE.test(stationId) || !Number.isSafeInteger(groupId) || groupId <= 0) throw new AppError(404, 'Target not found');
  return { stationId, groupId };
}

/** The stations of the tenant. The technician of an open session is named only when that user is a member of this
 *  tenant (bench_tenant_stations); `mine`: the session of the requesting user. */
async function stationsOf(tenantId: number, userId: number): Promise<BenchTenantStationView[]> {
  const r = await db.raw('SELECT * FROM obligarth.bench_tenant_stations(?)', [tenantId]) as { rows: Array<Record<string, any>> };
  const targets = await db('bench_station_targets as t').leftJoin('device_groups as g', function j() { this.on('g.id', '=', 't.group_id').andOn('g.tenant_id', '=', 't.tenant_id'); })
    .where('t.tenant_id', tenantId).select('t.station_id', 't.group_id', 't.role_policy', 't.suspended_at', 'g.name as group_name') as Array<Record<string, any>>;
  return r.rows.map((s) => ({
    id: String(s.id), name: s.name, status: s.status, lastSeenAt: iso(s.last_seen_at),
    targets: targets.filter((t) => String(t.station_id) === String(s.id)).map((t) => ({
      groupId: Number(t.group_id), groupPath: t.group_name ?? String(t.group_id), rolePolicy: t.role_policy, suspendedAt: iso(t.suspended_at),
    })),
    session: s.session_id ? {
      id: String(s.session_id), technician: s.technician ?? null, expiresAt: iso(s.session_expires_at) as string,
      mine: s.session_user_id !== null && s.session_user_id !== undefined && Number(s.session_user_id) === userId,
    } : null,
  }));
}

export function createBenchHistoryRouter(): Router {
  const router = Router();
  router.use(requireTenantCapability('mdm.bench.manage'));

  router.get('/', wrap(async (req, res) => {
    const tenantId = req.tenantId!;
    const clear = req.session.role === 'admin' || await permissionService.userHasTenantCapability(req.session.userId!, tenantId, 'devices.manage');
    let q = db('bench_provisionings as p')
      .leftJoin('devices as d', function j() { this.on('d.id', '=', 'p.device_id').andOn('d.tenant_id', '=', 'p.tenant_id'); })
      .leftJoin('legacy_agent_devices as a', function j() { this.on('a.device_id', '=', 'p.device_id').andOn('a.tenant_id', '=', 'p.tenant_id'); })
      .leftJoin('legacy_agent_enrollment_tokens as k', function j() { this.on('k.id', '=', 'p.enrollment_token_id').andOn('k.tenant_id', '=', 'p.tenant_id'); })
      .where('p.tenant_id', tenantId);
    if (typeof req.query.stationId === 'string' && UUID_RE.test(req.query.stationId)) q = q.where('p.station_id', req.query.stationId.toLowerCase());
    if (typeof req.query.state === 'string' && (BENCH_PROVISIONING_STATES as readonly string[]).includes(req.query.state)) q = q.where('p.state', req.query.state);
    const deviceId = Number(req.query.deviceId);
    if (Number.isSafeInteger(deviceId) && deviceId > 0) q = q.where('p.device_id', deviceId);
    const rows = await q.orderBy('p.created_at', 'desc').limit(500)
      .select('p.*', 'd.uuid as device_uuid', 'd.management_mode', 'a.identity_state', 'k.created_by as technician_id') as Array<Record<string, any>>;
    const names = new Map((await stationsOf(tenantId, req.session.userId!)).map((s) => [s.id, s.name]));
    const ids = [...new Set(rows.map((r) => Number(r.technician_id)).filter((n) => Number.isSafeInteger(n) && n > 0))];
    const labels = ids.length === 0 ? new Map<number, string>()
      : new Map(((await db.raw('SELECT id, username, display_name FROM obligarth.user_labels(?::int[])', [ids])) as { rows: Array<Record<string, any>> }).rows
        .map((u) => [Number(u.id), String(u.display_name || u.username)]));
    const cut = (s: string | null): string | null => (s === null ? null : clear ? s : truncateSerial(s));
    const data: BenchProvisioningView[] = rows.map((r) => ({
      id: String(r.id), stationId: String(r.station_id), stationName: names.get(String(r.station_id)) ?? null, groupId: Number(r.group_id),
      kind: r.kind, state: r.state, adbSerial: cut(r.adb_serial) as string, hwSerial: cut(r.hw_serial ?? null), model: r.model,
      manufacturer: r.manufacturer, sdkInt: Number(r.sdk_int), osRelease: r.os_release ?? null, oneUi: r.one_ui ?? null,
      deviceName: r.device_name ?? null, roleTarget: r.role_target, roleDeclared: r.role_declared ?? null, managementMode: r.management_mode ?? null,
      identityState: r.identity_state ?? null, deviceId: r.device_id === null ? null : Number(r.device_id), deviceUuid: r.device_uuid ? String(r.device_uuid) : null,
      errorCode: r.error_code ?? null, steps: (Array.isArray(r.steps) ? r.steps : []) as BenchStepEntry[], stepsDropped: Number(r.steps_dropped ?? 0),
      technician: r.technician_id ? labels.get(Number(r.technician_id)) ?? null : null,
      createdAt: iso(r.created_at) as string, updatedAt: iso(r.updated_at) as string, outcomeAt: iso(r.outcome_at),
    }));
    res.json({ success: true, data });
  }));

  router.get('/stations', wrap(async (req, res) => {
    res.json({ success: true, data: await stationsOf(req.tenantId!, req.session.userId!) });
  }));

  async function setTarget(req: Request, res: Response, change: 'suspend' | 'remove'): Promise<void> {
    const { stationId, groupId } = targetParams(req);
    const tenantId = req.tenantId!;
    if (change === 'remove') {
      const step = await checkSecondFactor(req, { actionKey: 'bench.target_remove', allowTrustedIp: true, allowDevice: true });
      if (!step.ok) { sendStepUpFailure(res, step); return; }
    }
    const userId = req.session.userId!;
    const ctx = await audit.fromRequest(req, tenantId);
    await db.transaction(async (trx) => {
      const t = await trx('bench_station_targets').where({ station_id: stationId, tenant_id: tenantId, group_id: groupId }).forUpdate().first('suspended_at') as
        { suspended_at: Date | null } | undefined;
      if (!t) throw new AppError(404, 'Target not found');
      const target = { type: 'bench_station', id: stationId };
      if (change === 'remove') {
        await trx('bench_station_targets').where({ station_id: stationId, tenant_id: tenantId, group_id: groupId }).delete();
        const closed = await closeTargetProvisionings(trx, tenantId, stationId, groupId, userId);
        await audit.appendInTx(trx, { tenantId, action: 'bench.target_removed', target, details: { stationId, groupId, reason: 'tenant', ...closed } }, ctx, { onFailure: 'spool' });
      } else if (!t.suspended_at) {
        await trx('bench_station_targets').where({ station_id: stationId, tenant_id: tenantId, group_id: groupId }).update({ suspended_at: new Date(), suspended_by: userId });
        const closed = await closeTargetProvisionings(trx, tenantId, stationId, groupId, userId);
        await audit.appendInTx(trx, { tenantId, action: 'bench.target_suspended', target, details: { stationId, groupId, ...closed } }, ctx, { onFailure: 'spool' });
      }
    });
    res.json({ success: true, data: await stationsOf(tenantId, userId) });
  }

  router.post('/targets/:stationId/:groupId/suspend', wrap((req, res) => setTarget(req, res, 'suspend')));
  router.delete('/targets/:stationId/:groupId', wrap((req, res) => setTarget(req, res, 'remove')));

  return router;
}
