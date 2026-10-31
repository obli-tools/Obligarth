import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { BENCH_LIMITS } from '@obligarth/shared';
import { db } from '../db';
import { switchToIdentity } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { requireTenantCapability } from '../middleware/rbac';
import { checkSecondFactor, sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { closeBenchSession, openBenchSession } from './admin.routes';

// =============================================================================
// Bench sessions from a tenant (lot BANC §3.3 bis), mounted at /api/bench-sessions in the tenant router:
//   POST /              { stationId, minutes }: mdm.bench.operate in the session's tenant, a station approved that
//                       targets this tenant (a target not suspended) and no other tenant: a session is the station's,
//                       so a station shared between tenants opens its session from the console of the platform only
//                       (409 stationShared); second factor (strict); 8 hours at most
//   POST /:id/close     the user's own session (a platform administrator: any)
// The technician has no account on the station: it only shows the session its GET /me reads. The capability is checked
// again in the tenant of each target at every token the station asks for (provisioning.service.ts).
// =============================================================================

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OpenBody = z.object({
  stationId: z.string().regex(UUID_RE),
  minutes: z.number().int().min(15).max(BENCH_LIMITS.sessionMaxHours * 60).optional(),
}).strict();

export function createBenchSessionsRouter(): Router {
  const router = Router();

  router.post('/', requireTenantCapability('mdm.bench.operate'), wrap(async (req, res) => {
    const parsed = OpenBody.safeParse(req.body ?? {});
    if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
    const b = parsed.data;
    const id = b.stationId.toLowerCase();
    const tenantId = req.tenantId!;
    const target = await db('bench_station_targets').where({ station_id: id, tenant_id: tenantId }).whereNull('suspended_at').first('group_id');
    if (!target) throw new AppError(404, 'Station not found');
    const shared = await db.raw('SELECT obligarth.bench_station_shared(?::uuid, ?) AS s', [id, tenantId]) as { rows: Array<{ s: boolean }> };
    if (shared.rows[0]?.s === true) {
      throw new AppError(409, 'This station also serves other tenants: its session is opened from the console of the platform', 'stationShared');
    }
    const station = await switchToIdentity(() => db('bench_stations').where({ id }).first('status', 'name')) as { status: string; name: string } | undefined;
    if (!station) throw new AppError(404, 'Station not found');
    if (station.status !== 'approved') throw new AppError(409, 'The station is not approved', 'bad_state');
    const step = await checkSecondFactor(req, { actionKey: 'bench.session_open', allowTrustedIp: false, allowDevice: true });
    if (!step.ok) { sendStepUpFailure(res, step); return; }
    const session = await openBenchSession(req, id, station.name, b.minutes ?? BENCH_LIMITS.sessionMaxHours * 60, tenantId);
    res.status(201).json({ success: true, data: session });
  }));

  router.post('/:id/close', wrap(async (req, res) => {
    const id = String(req.params.id ?? '').toLowerCase();
    if (!UUID_RE.test(id)) throw new AppError(404, 'Session not found');
    const done = await closeBenchSession(req, { sessionId: id }, req.tenantId!, 'user', req.session.role !== 'admin');
    if (!done) throw new AppError(404, 'Session not found');
    res.json({ success: true, data: { closed: true } });
  }));

  return router;
}
