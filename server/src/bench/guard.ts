import { BlockList, isIP } from 'node:net';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { clientIp } from '../utils/clientIp';
import { WindowLimiter } from '../legacyAgent/limits';
import { lookupStation, parseBenchAuthorization, stationAccessVerdict, touchStation, type BenchScope, type StationLookup } from './stations.service';

// =============================================================================
// The guard of the station routes (lot BANC §3.3): the station's row read again at EVERY request, no cache (a
// revocation or a suspension is seen at once). Only this guard answers 401 and 403 on these routes: the station reads
// them as « this computer is refused »; every other refusal is a 400, 404, 409, 422 or 429.
//   requireBenchStationSelf      GET /stations/me: pending, approved and suspended read their state; revoked is 403
//   requireApprovedBenchStation  /v1/*: approved only
// The address restriction of a station (allowed_cidrs) is applied when it is set (station_ip_refused).
// A station acts 600 times a minute at most (429).
// =============================================================================

declare global {
  namespace Express {
    interface Request {
      /** The station of a request of the bench surface, set by its guard. */
      benchStation?: StationLookup;
    }
  }
}

const actLimiter = new WindowLimiter(600, 60_000);

function refuse(res: Response, status: number, code: string, error: string, headers: Record<string, string> = {}): void {
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.status(status).json({ success: false, error, code });
}

/** The address of the station is inside one of its allowed ranges (none set: any address). */
export function addressAllowed(cidrs: string[] | null, ip: string): boolean {
  if (!cidrs || cidrs.length === 0) return true;
  const kind = isIP(ip);
  if (!kind) return false;
  const list = new BlockList();
  for (const c of cidrs) {
    const [net, bits] = c.split('/');
    const family = isIP(net) === 6 ? 'ipv6' : 'ipv4';
    try { list.addSubnet(net, Number(bits ?? (family === 'ipv6' ? 128 : 32)), family); } catch { /* an unreadable range allows nothing */ }
  }
  return list.check(ip, kind === 6 ? 'ipv6' : 'ipv4');
}

export function createBenchStationGuard(scope: BenchScope): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    void (async () => {
      const auth = parseBenchAuthorization(req.get('authorization'));
      if (!auth.ok) { refuse(res, 401, 'unknown_station', 'Station authentication required'); return; }
      const station = await lookupStation(auth.token);
      const verdict = stationAccessVerdict(station?.status ?? null, scope);
      if (!verdict.ok) { refuse(res, verdict.status, verdict.code, verdict.error); return; }
      const ip = clientIp(req) || '';
      if (!addressAllowed(station!.allowedCidrs, ip)) { refuse(res, 403, 'station_ip_refused', 'This address is not allowed for the station'); return; }
      if (scope === 'act') {
        const wait = actLimiter.hit(station!.id);
        if (wait) { refuse(res, 429, 'rate_limited', 'Too many requests', { 'Retry-After': String(wait) }); return; }
      }
      const version = typeof req.get('x-bench-version') === 'string' ? String(req.get('x-bench-version')).slice(0, 32) : null;
      await touchStation(station!.id, isIP(ip) ? ip : null, version);
      req.benchStation = station!;
      next();
    })().catch(next);
  };
}

export const requireBenchStationSelf = createBenchStationGuard('self');
export const requireApprovedBenchStation = createBenchStationGuard('act');

/** Called again by each controller of /v1/*: the guard ran and the station is approved. */
export function assertApprovedBenchStation(req: Request): StationLookup {
  const s = req.benchStation;
  if (!s || s.status !== 'approved') throw new Error('bench: a /v1 controller without the guard of an approved station');
  return s;
}
