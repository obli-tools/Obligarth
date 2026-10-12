import { Router, type NextFunction, type Request, type Response } from 'express';
import type {
  DdmDeclarationStatusView, DdmSyncRequestOutcome, DeviceCapability, DeviceDeclarationsView, DeviceStatusHistoryEntry, DeviceStatusItemView,
} from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { defaultRuntime } from '../../jobs';
import { asTargetTenant, globalViewRead, globalViewScope } from '../../middleware/dbContext';
import { AppError } from '../../middleware/errorHandler';
import { parseRequestDeviceId, resolveRequestDevice } from '../../services/deviceScope.service';
import { permissionService } from '../../services/permission.service';
import { isFinalTargetState } from '../commands/targets';
import type { SetItem } from './engine';
import { ddmJobs } from './jobs';

// =============================================================================
// Console API of the DDM engine (docs: integration-apple-edge §9.9), mounted
// at /api/apple in the tenant of the session (requireTenant):
//   GET  /devices/:id/declarations  the set served, the status the device
//                                   reported of each declaration, the tokens
//   GET  /devices/:id/status-items  the last value of each status item;
//                                   ?item=<name>&history=1: the history of one
//   POST /devices/:id/ddm-sync      202: a synchronisation now, announced even
//                                   when the tokens did not change (one per
//                                   device and per minute)
// A device out of reach answers like an unknown one (404), whatever the state
// of the integration. Reads accept the master tenant's global view. Never the
// payload of a declaration: its identifier, type and tokens. With
// APPLE_EDGE_MODE=off, a device the caller reaches answers 503
// appleIntegrationDisabled.
// =============================================================================

const router = Router();

/** The capability a team needs to force a synchronisation (§8.11: profiles, settings, forced DDM synchronisation). */
const SYNC_CAPABILITY = 'mdm:profiles' as DeviceCapability;
const ITEM_RE = /^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/;
const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);

declare module 'express-serve-static-core' {
  interface Request {
    /** The device of an /api/apple/devices/:id route of the DDM engine, once resolved (its own tenant). */
    ddmDevice?: { id: number; tenantId: number };
  }
}

function requireIntegration(_req: Request, _res: Response, next: NextFunction): void {
  if (config.apple.mode !== 'on') next(new AppError(503, 'The Apple integration is turned off', 'appleIntegrationDisabled'));
  else next();
}

/** The device of the route, with the REST tenant rule: the session's tenant, any tenant for the global view,
 *  through a team of the caller for a non-administrator; 404 out of reach. */
function resolveDevice(opts: { capability?: DeviceCapability; write?: boolean } = {}) {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const id = parseRequestDeviceId(req.params.id);
      if (id === null) { next(new AppError(404, 'Device not found')); return; }
      const outcome = await globalViewRead(req, () => resolveRequestDevice(req, id, opts.capability ? { capability: opts.capability } : {}));
      if (!outcome.ok) { next(new AppError(outcome.status, outcome.error)); return; }
      if (opts.write && !outcome.isAdmin && !(await permissionService.canWriteDevice(req.session.userId!, id, false))) {
        next(new AppError(403, 'Insufficient permissions'));
        return;
      }
      req.ddmDevice = { id, tenantId: Number(outcome.device.tenant_id) };
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** GET declarations: read in the caller's context. */
export async function deviceDeclarations(tenantId: number, deviceId: number): Promise<DeviceDeclarationsView | null> {
  const sat = await db('apple_devices').where({ tenant_id: tenantId, device_id: deviceId })
    .first('ddm_enabled', 'ddm_enabled_at', 'ddm_client_capabilities') as
    { ddm_enabled: boolean; ddm_enabled_at: Date | null; ddm_client_capabilities: unknown } | undefined;
  if (!sat) return null;
  const set = await db('apple_declaration_sets').where({ tenant_id: tenantId, device_id: deviceId })
    .first('declarations_token', 'items', 'computed_at', 'sent_token', 'sync_command_id', 'fetched_token', 'fetched_at') as
    { declarations_token: string; items: SetItem[] | null; computed_at: Date; sent_token: string | null; sync_command_id: string | null;
      fetched_token: string | null; fetched_at: Date | null } | undefined;
  const statuses = await db('apple_declaration_status').where({ tenant_id: tenantId, device_id: deviceId }).orderBy('identifier')
    .select('identifier', 'family', 'server_token', 'active', 'valid', 'reasons', 'observed_at') as Array<Record<string, any>>;
  let syncOpen = false;
  if (set?.sync_command_id) {
    const target = await db('mdm_command_targets').where({ tenant_id: tenantId, command_id: set.sync_command_id, device_id: deviceId })
      .first('state') as { state: string } | undefined;
    syncOpen = !!target && !isFinalTargetState(target.state);
  }
  const items = Array.isArray(set?.items) ? set.items : [];
  const byIdentifier = new Map(statuses.map((s) => [String(s.identifier), s]));
  const view = (s: Record<string, any>, served: string | null): DdmDeclarationStatusView => ({
    active: s.active ?? null, valid: s.valid ?? null, serverToken: s.server_token ?? null,
    current: served !== null && s.server_token === served, reasons: Array.isArray(s.reasons) ? s.reasons : null, observedAt: iso(s.observed_at)!,
  });
  const cited = new Set(items.map((i) => i.identifier));
  return {
    ddmEnabled: !!sat.ddm_enabled,
    ddmEnabledAt: iso(sat.ddm_enabled_at),
    capabilitiesKnown: sat.ddm_client_capabilities !== null && sat.ddm_client_capabilities !== undefined,
    declarationsToken: set?.declarations_token ?? null,
    computedAt: iso(set?.computed_at),
    sentToken: set?.sent_token ?? null,
    syncOpen,
    fetchedToken: set?.fetched_token ?? null,
    fetchedAt: iso(set?.fetched_at),
    declarations: items.map((i) => {
      const s = byIdentifier.get(i.identifier);
      return { family: i.family, identifier: i.identifier, type: i.type, serverToken: i.server_token, status: s ? view(s, i.server_token) : null };
    }),
    reportedOnly: statuses.filter((s) => !cited.has(String(s.identifier)))
      .map((s) => ({ family: s.family, identifier: String(s.identifier), status: view(s, null) })),
  };
}

// GET /api/apple/devices/:id/declarations
router.get('/devices/:id/declarations', globalViewScope('console.devices'), resolveDevice({ capability: 'monitor' }), requireIntegration,
  async (req, res, next) => {
    try {
      const data = await deviceDeclarations(req.ddmDevice!.tenantId, req.ddmDevice!.id);
      if (!data) throw new AppError(404, 'Device not found');
      res.json({ data });
    } catch (err) { next(err); }
  });

// GET /api/apple/devices/:id/status-items[?item=<name>&history=1]
router.get('/devices/:id/status-items', globalViewScope('console.devices'), resolveDevice({ capability: 'monitor' }), requireIntegration,
  async (req, res, next) => {
    try {
      const { id, tenantId } = req.ddmDevice!;
      const item = typeof req.query.item === 'string' ? req.query.item : null;
      if (item !== null && (!ITEM_RE.test(item) || item.length > 128)) throw new AppError(400, 'Invalid status item', 'invalidRequest');
      if (item !== null && (req.query.history === '1' || req.query.history === 'true')) {
        const rows = await db('device_status_history').where({ tenant_id: tenantId, device_id: id, item }).orderBy('observed_at', 'desc').limit(200)
          .select('item', 'value', 'observed_at') as Array<Record<string, any>>;
        const data: DeviceStatusHistoryEntry[] = rows.map((r) => ({ item: r.item, value: r.value ?? null, observedAt: iso(r.observed_at)! }));
        res.json({ data });
        return;
      }
      const q = db('device_status_items').where({ tenant_id: tenantId, device_id: id }).orderBy('item');
      if (item !== null) q.where({ item });
      const rows = await q.select('item', 'value', 'error', 'observed_at') as Array<Record<string, any>>;
      const data: DeviceStatusItemView[] = rows.map((r) => ({
        item: r.item, value: r.value ?? null, error: r.error ?? null, observedAt: iso(r.observed_at)!, i18nKey: `apple.status.${r.item}`,
      }));
      res.json({ data });
    } catch (err) { next(err); }
  });

// POST /api/apple/devices/:id/ddm-sync
router.post('/devices/:id/ddm-sync', resolveDevice({ capability: SYNC_CAPABILITY, write: true }), requireIntegration, async (req, res, next) => {
  try {
    const { id, tenantId } = req.ddmDevice!;
    const job = ddmJobs.deviceSync();
    if (!job || !defaultRuntime.isStarted()) throw new AppError(503, 'Background jobs are not running', 'jobsUnavailable');
    const requested = await asTargetTenant(req, tenantId, () => db.transaction(async (trx) => {
      const d = await trx('devices').where({ tenant_id: tenantId, id }).first('enrollment_state') as { enrollment_state: string } | undefined;
      if (!d || (d.enrollment_state !== 'enrolled' && d.enrollment_state !== 'awaiting_configuration')) {
        throw new AppError(409, 'This device is not under management', 'deviceNotManaged');
      }
      // One forced synchronisation per device and per minute (its own key: the engine's requests are not throttled).
      const sent = await job.sendInTx(trx, { tenantId, deviceId: id }, { singletonKey: `d:${id}:console`, tenantId, throttleSeconds: 60, priority: 10 });
      if (!sent) return false;
      // Forced: the current tokens are announced again, unless a command already waits for the device (it will read them).
      await trx.raw(`
        UPDATE obligarth.apple_declaration_sets s SET sent_token = NULL
         WHERE s.tenant_id = ? AND s.device_id = ?
           AND NOT EXISTS (SELECT 1 FROM obligarth.mdm_command_targets t
                            WHERE t.tenant_id = s.tenant_id AND t.command_id = s.sync_command_id AND t.device_id = s.device_id
                              AND t.state IN ('pending', 'queued', 'sent', 'notnow'))`, [tenantId, id]);
      return true;
    }));
    const data: DdmSyncRequestOutcome = { requested };
    res.status(202).json({ data });
  } catch (err) { next(err); }
});

/** The console API of the DDM engine, mounted at /api/apple (routes/index.ts), after requireTenant. */
export function createAppleDdmRouter(): Router {
  return router;
}
